package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/hashicorp/yamux"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var VERSION string = "HEAD"

const ENV_VARS = "TERM"
const TLS_KEY = "key.pem"
const TLS_CERT = "cert.pem"
const BINARY_NAME = "ssrv"
const UNIX_SOCKET = "unix:@ssrv"

var CPIDS_DIR = fmt.Sprint("/tmp/ssrv", syscall.Geteuid())

const USAGE_PREAMBLE = `Server usage: %[1]s -srv [-tls-key key.pem] [-tls-cert cert.pem] [-sock tcp:1337] [-env all]
Client usage: %[1]s [-tls-cert cert.pem] [options] [ COMMAND [ arguments... ] ]

If COMMAND is not passed, spawn a $SHELL on the server side.

Accepted options:
`

const USAGE_FOOTER = `
--

Environment variables:
    SSRV_PTY=1                      Same as -pty argument
    SSRV_NO_PTY=1                   Same as -no-pty argument
    SSRV_ENV="MY_VAR,MY_VAR1"       Same as -env argument
    SSRV_UENV="MY_VAR,MY_VAR1"      Same as -uenv argument
    SSRV_SOCK="tcp:1337"            Same as -sock argument
    SSRV_TLS_KEY="/path/key.pem"    Same as -tls-key argument
    SSRV_TLS_CERT="/path/cert.pem"  Same as -tls-cert argument
    SSRV_CPIDS_DIR=/path/dir        Same as -cpids-dir argument
    SSRV_NOSEP_CPIDS=1              Same as -nosep-cpids argument
    SSRV_PID_FILE=/path/ssrv.pid    Same as -pid-file argument
    SSRV_CWD=/path/dir              Same as -cwd argument
    SHELL="/bin/bash"               Assigns a default shell (on the server side)

--

If none of the pty arguments are passed in the client, a pseudo-terminal is allocated by default, unless it is
known that the command behaves incorrectly when attached to the pty or the client is not running in the terminal`

var pty_blocklist = map[string]bool{
	"gio":       true,
	"podman":    true,
	"kde-open":  true,
	"kde-open5": true,
	"xdg-open":  true,
}

var is_srv = flag.Bool(
	"srv", false,
	"Run as server",
)
var socket_addr = flag.String(
	"sock", UNIX_SOCKET,
	"Socket address listen/connect (unix,tcp,tcp4,tcp6)",
)
var env_vars = flag.String(
	"env", ENV_VARS,
	"Comma separated list of environment variables for pass to the server side process.",
)
var uenv_vars = flag.String(
	"uenv", "",
	"Comma separated list of environment variables for unset on the server side process.",
)
var is_version = flag.Bool(
	"v", false,
	"Show this program's version",
)
var is_pty = flag.Bool(
	"pty", false,
	"Force allocate a pseudo-terminal for the server side process",
)
var is_no_pty = flag.Bool(
	"no-pty", false,
	"Do not allocate a pseudo-terminal for the server side process",
)
var tls_cert = flag.String(
	"tls-cert", TLS_CERT,
	"TLS cert file for server and client",
)
var tls_key = flag.String(
	"tls-key", TLS_KEY,
	"TLS key file for server",
)
var cpids_dir = flag.String(
	"cpids-dir", CPIDS_DIR,
	"A directory on the server side for storing a list of client PIDs.",
)
var nosep_cpids = flag.Bool(
	"nosep-cpids", false,
	"Don't create a separate dir for the server socket to store the list of client PIDs.",
)
var pid_file = flag.String(
	"pid-file", "",
	"The file for storing the server's PID.",
)
var cwd = flag.String(
	"cwd", "",
	"Change the current working directory of the process/command.",
)

type win_size struct {
	ws_row    uint16
	ws_col    uint16
	ws_xpixel uint16
	ws_ypixel uint16
}

func set_term_size(f *os.File, rows, cols int) error {
	ws := win_size{ws_row: uint16(rows), ws_col: uint16(cols)}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return syscall.Errno(errno)
	}
	return nil
}

func get_socket(addr []string) string {
	var socket string
	if addr[0] == "unix" {
		socket = addr[1]
	} else if len(addr) > 2 {
		socket = addr[1] + ":" + addr[2]
	} else {
		socket = ":" + addr[1]
	}
	return socket
}

func touch_file(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
	} else {
		currentTime := time.Now().Local()
		err = os.Chtimes(path, currentTime, currentTime)
		if err != nil {
			return err
		}
	}
	return nil
}

func is_dir_exists(dir string) bool {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

func is_file_exists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func is_valid_proto(proto string) bool {
	switch proto {
	case "unix", "tcp", "tcp4", "tcp6":
		return true
	}
	return false
}

func get_shell() string {
	shell := os.Getenv("SHELL")
	if is_file_exists(shell) {
		return shell
	} else if zsh, err := exec.LookPath("zsh"); err == nil {
		return zsh
	} else if fish, err := exec.LookPath("fish"); err == nil {
		return fish
	} else if bash, err := exec.LookPath("bash"); err == nil {
		return bash
	}
	return "sh"
}

func is_env_var_eq(var_name, var_value string) bool {
	value, exists := os.LookupEnv(var_name)
	return exists && value == var_value
}

func flag_parse() []string {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, USAGE_PREAMBLE, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, USAGE_FOOTER)
		os.Exit(0)
	}

	flag.Parse()

	if *is_version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	return flag.Args()
}

func ssrv_env_vars_unset() {
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		key := pair[0]
		if strings.HasPrefix(key, "SSRV_") {
			os.Unsetenv(key)
		}
	}
}

func ssrv_env_vars_parse() {
	if is_env_var_eq("SSRV_PTY", "1") &&
		!*is_pty {
		flag.Set("pty", "true")
	}
	if is_env_var_eq("SSRV_NO_PTY", "1") &&
		!*is_no_pty {
		flag.Set("no-pty", "true")
	}
	if is_env_var_eq("SSRV_NOSEP_CPIDS", "1") &&
		!*nosep_cpids {
		flag.Set("nosep-cpids", "true")
	}
	if ssrv_env, ok := os.LookupEnv("SSRV_ENV"); ok &&
		*env_vars == ENV_VARS {
		flag.Set("env", ssrv_env)
	}
	if ssrv_socket, ok := os.LookupEnv("SSRV_SOCK"); ok &&
		*socket_addr == UNIX_SOCKET {
		flag.Set("sock", ssrv_socket)
	}
	if ssrv_cpids_dir, ok := os.LookupEnv("SSRV_CPIDS_DIR"); ok &&
		*cpids_dir == CPIDS_DIR {
		flag.Set("cpids-dir", ssrv_cpids_dir)
	}
	if ssrv_uenv, ok := os.LookupEnv("SSRV_UENV"); ok &&
		*uenv_vars == "" {
		flag.Set("uenv", ssrv_uenv)
	}
	if ssrv_pid_file, ok := os.LookupEnv("SSRV_PID_FILE"); ok &&
		*pid_file == "" {
		flag.Set("pid-file", ssrv_pid_file)
	}
	if ssrv_cwd, ok := os.LookupEnv("SSRV_CWD"); ok &&
		*cwd == "" {
		flag.Set("cwd", ssrv_cwd)
	}
	if ssrv_tls_key, ok := os.LookupEnv("SSRV_TLS_KEY"); ok &&
		*tls_key == TLS_KEY && is_file_exists(ssrv_tls_key) {
		flag.Set("tls-key", ssrv_tls_key)
	}
	if ssrv_tls_cert, ok := os.LookupEnv("SSRV_TLS_CERT"); ok &&
		*tls_cert == TLS_CERT && is_file_exists(ssrv_tls_cert) {
		flag.Set("tls-cert", ssrv_tls_cert)
	}
}

func child_pids_walk(pid int, wg *sync.WaitGroup, child_pids *[]int) {
	defer wg.Done()
	proc, _ := process.NewProcess(int32(pid))
	proc_child, _ := proc.Children()
	for _, child := range proc_child {
		*child_pids = append(*child_pids, int(child.Pid))
		wg.Add(1)
		go child_pids_walk(int(child.Pid), wg, child_pids)
	}
}

func get_child_pids(pid int) []int {
	var wg sync.WaitGroup
	var child_pids []int
	wg.Add(1)
	child_pids_walk(int(pid), &wg, &child_pids)
	wg.Wait()
	sort.Slice(child_pids, func(i, j int) bool {
		return child_pids[i] < child_pids[j]
	})
	return child_pids
}

func is_pid_exist(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.SIGCONT)
	return err == nil
}

func get_cert_sha256(cert string) ([]byte, error) {
	cert_bytes, err := os.ReadFile(cert)
	if err != nil {
		return []byte(""), err
	}
	cert_str := string(cert_bytes)
	cert_str = strings.Replace(cert_str, "-----BEGIN CERTIFICATE-----", "-----CERT_SHA256-----", -1)
	cert_str = strings.Replace(cert_str, "-----END CERTIFICATE-----", "-----CERT_SHA256-----", -1)
	cert_sha256 := sha256.Sum256([]byte(cert_str))
	return cert_sha256[:], nil
}

func get_cert_hash(cert string) (string, error) {
	cert_sha256, err := get_cert_sha256(cert)
	if err != nil {
		return "", err
	}
	hash_bytes, err := bcrypt.GenerateFromPassword(cert_sha256, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash_bytes), nil
}

func verify_cert_hash(provided_cert_hash, cert string) (bool, error) {
	cert_sha256, err := get_cert_sha256(cert)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(provided_cert_hash), cert_sha256)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func srv_handle(conn net.Conn, self_cpids_dir string) {
	var wg sync.WaitGroup
	disconnect := func(session *yamux.Session, remote string) {
		session.Close()
		log.Printf("[%s] [  DISCONNECT  ]", remote)
	}

	defer conn.Close()
	remote := conn.RemoteAddr().String()

	if is_file_exists(*tls_cert) {
		hash_buf := make([]byte, 60)
		n, err := conn.Read(hash_buf)
		if err != nil {
			log.Printf("[%s] error reading cert hash: %v", remote, err)
			return
		}
		provided_cert_hash := string(hash_buf[:n])
		is_valid_cert_hash, err := verify_cert_hash(provided_cert_hash, *tls_cert)
		if err != nil || !is_valid_cert_hash {
			log.Printf("[%s] invalid cert!", remote)
			conn.Write([]byte("error\r"))
			return
		}
		conn.Write([]byte("\r"))
	}

	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("[%s] session error: %v", remote, err)
		return
	}
	defer disconnect(session, remote)
	log.Printf("[%s] [    CONNECT   ]", remote)

	envs_channel, err := session.Accept()
	if err != nil {
		log.Printf("[%s] environment channel accept error: %v", remote, err)
		return
	}
	envs_reader := bufio.NewReader(envs_channel)
	envs_str, err := envs_reader.ReadString('\r')
	if err != nil {
		log.Printf("[%s] error reading environment variables: %v", remote, err)
		return
	}
	envs_str = envs_str[:len(envs_str)-1]
	envs := strings.Split(envs_str, "\n")
	last_env_num := len(envs) - 1

	is_alloc_pty := true
	var stdin_channel net.Conn
	var stderr_channel net.Conn
	if envs[last_env_num] == "_NO_PTY_" {
		is_alloc_pty = false
		envs = envs[:last_env_num]

		stdin_channel, err = session.Accept()
		if err != nil {
			log.Printf("[%s] stdin channel accept error: %v", remote, err)
			return
		}
		stderr_channel, err = session.Accept()
		if err != nil {
			log.Printf("[%s] stderr channel accept error: %v", remote, err)
			return
		}
	} else {
		is_alloc_pty = true
	}

	data_channel, err := session.Accept()
	if err != nil {
		log.Printf("[%s] data channel accept error: %v", remote, err)
		return
	}

	command_channel, err := session.Accept()
	if err != nil {
		log.Printf("[%s] command channel accept error: %v", remote, err)
		return
	}
	cmd_reader := bufio.NewReader(command_channel)
	cmd_str, err := cmd_reader.ReadString('\r')
	if err != nil {
		log.Printf("[%s] error reading command: %v", remote, err)
		return
	}
	cmd_str = cmd_str[:len(cmd_str)-1]
	if len(cmd_str) == 0 {
		cmd_str = get_shell()
	}
	cmd := strings.Split(cmd_str, "\n")
	exec_cmd := exec.Command(cmd[0], cmd[1:]...)

	var cwd string
	last_env_num -= 1
	exec_cmd_envs := os.Environ()
	if strings.HasPrefix(envs[last_env_num], "_SSRV_CWD=") {
		cwd = strings.Replace(envs[last_env_num], "_SSRV_CWD=", "", 1)
		envs = envs[:last_env_num]
		last_env_num -= 1
	}
	if strings.HasPrefix(envs[last_env_num], "_SSRV_UENV=") {
		uenv_vars := strings.Replace(envs[last_env_num], "_SSRV_UENV=", "", 1)
		if uenv_vars == "all" {
			exec_cmd_envs = nil
		} else if strings.HasPrefix(uenv_vars, "all-:") {
			var exec_cmd_no_uenv []string
			no_uenv_vars := strings.Split(strings.Replace(uenv_vars, "all-:", "", 1), ",")
			for _, env := range exec_cmd_envs {
				pair := strings.SplitN(env, "=", 2)
				for _, no_uenv := range no_uenv_vars {
					if pair[0] == no_uenv {
						exec_cmd_no_uenv = append(exec_cmd_no_uenv, env)
					}
				}
			}
			exec_cmd_envs = exec_cmd_no_uenv
		} else {
			for _, uenv := range strings.Split(uenv_vars, ",") {
				for num, env := range exec_cmd_envs {
					pair := strings.SplitN(env, "=", 2)
					if pair[0] == uenv {
						exec_cmd_envs = append(exec_cmd_envs[:num], exec_cmd_envs[num+1:]...)
					}
				}
			}
		}
		envs = envs[:last_env_num]
		last_env_num -= 1
	}
	exec_cmd.Env = exec_cmd_envs
	exec_cmd.Env = append(exec_cmd.Env, envs...)
	if len(cwd) != 0 && is_dir_exists(cwd) {
		exec_cmd.Dir = cwd
	} else {
		for _, env := range envs {
			pair := strings.SplitN(env, "=", 2)
			var value string
			if len(pair) == 2 {
				key := pair[0]
				value = pair[1]
				if strings.HasPrefix(key, "PWD") &&
					is_dir_exists(value) {
					exec_cmd.Dir = value
				}
			}
		}
	}

	var cmd_ptmx *os.File
	var cmd_stdout, cmd_stderr io.ReadCloser
	if is_alloc_pty {
		cmd_ptmx, err = pty.Start(exec_cmd)
	} else {
		exec_cmd.Stdin = stdin_channel
		cmd_stdout, _ = exec_cmd.StdoutPipe()
		cmd_stderr, _ = exec_cmd.StderrPipe()
		exec_cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		err = exec_cmd.Start()
	}
	if err != nil {
		log.Printf("[%s] cmd error: %v", remote, err)
		_, err = command_channel.Write([]byte(fmt.Sprint("cmd error: " + err.Error() + "\r\n")))
		if err != nil {
			log.Printf("[%s] failed to send cmd error: %v", remote, err)
		}
		return
	}

	cmd_pid := exec_cmd.Process.Pid
	cmd_pgid, _ := syscall.Getpgid(cmd_pid)
	log.Printf("[%s] PID: %d -> EXEC: %s", remote, cmd_pid, cmd)

	cpid := fmt.Sprint(self_cpids_dir, "/", cmd_pid)
	if is_dir_exists(self_cpids_dir) {
		proc_pid := fmt.Sprint("/proc/", cmd_pid)
		if is_dir_exists(proc_pid) {
			if err := os.Symlink(proc_pid, cpid); err != nil {
				log.Printf("[%s] PID: %d -> symlink error: %v", remote, cmd_pid, err)
				return
			}
		} else {
			touch_file(cpid)
		}
	}
	defer os.Remove(cpid)

	cp := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
	}

	control_channel, err := session.Accept()
	if err != nil {
		log.Printf("[%s] PID: %d -> control channel accept error: %v", remote, cmd_pid, err)
		return
	}
	if is_alloc_pty {
		go func() {
			decoder := gob.NewDecoder(control_channel)
			for {
				var win struct {
					Rows, Cols int
				}
				if err := decoder.Decode(&win); err != nil {
					break
				}
				if err := set_term_size(cmd_ptmx, win.Rows, win.Cols); err != nil {
					log.Printf("[%s] PID: %d -> set term size error: %v", remote, cmd_pid, err)
					break
				}
				if err := syscall.Kill(exec_cmd.Process.Pid, syscall.SIGWINCH); err != nil {
					log.Printf("[%s] PID: %d -> sigwinch error: %v", remote, cmd_pid, err)
					break
				}
			}
		}()
		wg.Add(2)
		go cp(data_channel, cmd_ptmx)
		go cp(cmd_ptmx, data_channel)
	} else {
		go func() {
			exec_cmd_kill := func(sig syscall.Signal) {
				child_pids := []int{cmd_pid}
				child_pids = append(child_pids, get_child_pids(cmd_pid)...)

				syscall.Kill(-cmd_pgid, sig)
				pgid_wait := time.Second
				for {
					if is_pid_exist(-cmd_pgid) && pgid_wait != 0 {
						pgid_wait -= 10 * time.Millisecond
						time.Sleep(10 * time.Millisecond)
					} else {
						break
					}
				}

				for _, pid := range child_pids {
					syscall.Kill(pid, sig)
					if is_pid_exist(pid) &&
						sig != syscall.SIGHUP &&
						sig != syscall.SIGUSR1 &&
						sig != syscall.SIGUSR2 {
						syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			}
			reader := bufio.NewReader(control_channel)
			sig, err := reader.ReadString('\r')
			if err != nil && err != io.EOF {
				log.Printf("[%s] PID: %d -> control channel reader error: %v", remote, cmd_pid, err)
			}
			switch sig {
			case "SIGINT\r":
				exec_cmd_kill(syscall.SIGINT)
			case "SIGTERM\r":
				exec_cmd_kill(syscall.SIGTERM)
			case "SIGQUIT\r":
				exec_cmd_kill(syscall.SIGQUIT)
			case "SIGHUP\r":
				exec_cmd_kill(syscall.SIGHUP)
			case "SIGUSR1\r":
				exec_cmd_kill(syscall.SIGUSR1)
			case "SIGUSR2\r":
				exec_cmd_kill(syscall.SIGUSR2)
			}
		}()
		wg.Add(2)
		go cp(data_channel, cmd_stdout)
		go cp(stderr_channel, cmd_stderr)
	}

	state, err := exec_cmd.Process.Wait()
	if err != nil {
		log.Printf("[%s] PID: %d -> error getting exit code: %v", remote, cmd_pid, err)
		return
	}
	exit_code := strconv.Itoa(state.ExitCode())
	log.Printf("[%s] PID: %d -> EXIT: %s", remote, cmd_pid, exit_code)

	_, err = command_channel.Write([]byte(fmt.Sprint(exit_code + "\r\n")))
	if err != nil {
		log.Printf("[%s] PID: %d -> error sending exit code: %v", remote, cmd_pid, err)
		return
	}

	if is_alloc_pty {
		session.Close()
	}

	wg.Wait()
}

func server(proto, socket string) {
	ssrv_pid := fmt.Sprintf("%d", os.Getpid())
	if *pid_file != "" {
		err := os.WriteFile(*pid_file, []byte(ssrv_pid), 0644)
		if err != nil {
			log.Fatalf("error writing PID file: %v\n", err)
		}
	}

	var err error
	var listener net.Listener
	if is_file_exists(*tls_cert) && is_file_exists(*tls_key) {
		*tls_key, _ = filepath.Abs(*tls_key)
		*tls_cert, _ = filepath.Abs(*tls_cert)
		cert, err := tls.LoadX509KeyPair(*tls_cert, *tls_key)
		if err != nil {
			log.Fatal(err)
		}
		tls_config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			Certificates:       []tls.Certificate{cert},
		}
		listener, err = tls.Listen(proto, socket, tls_config)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("TLS encryption enabled")
	} else {
		listener, err = net.Listen(proto, socket)
		if err != nil {
			log.Fatal(err)
		}
	}

	if proto == "unix" && is_file_exists(socket) {
		err = os.Chmod(socket, 0700)
		if err != nil {
			log.Fatalln("unix socket:", err)
		}
	}
	listener_addr := listener.Addr().String()
	log.Printf("listening on %s %s", listener.Addr().Network(), listener_addr)

	var self_cpids_dir string
	if *nosep_cpids {
		self_cpids_dir = *cpids_dir
	} else {
		listener_addr = strings.TrimLeft(listener_addr, "/")
		listener_addr = strings.Replace(listener_addr, "/", "-", -1)
		self_cpids_dir = fmt.Sprint(*cpids_dir, "/", listener_addr)
	}
	self_cpids_dir, _ = filepath.Abs(self_cpids_dir)

	err = os.MkdirAll(self_cpids_dir, 0700)
	if err != nil {
		fmt.Println("creating directory error:", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		if proto == "unix" && is_file_exists(socket) {
			os.Remove(socket)
		}
		if is_file_exists(*pid_file) {
			os.Remove(*pid_file)
		}
		os.RemoveAll(self_cpids_dir)
		os.Remove(*cpids_dir)
		os.Exit(1)
	}()

	if *env_vars == "all" {
		for _, uenv := range strings.Split(*uenv_vars, ",") {
			os.Unsetenv(uenv)
		}
	} else if strings.HasPrefix(*env_vars, "all-:") {
		for _, uenv := range strings.Split(strings.Replace(*env_vars, "all-:", "", 1), ",") {
			os.Unsetenv(uenv)
		}
	} else if strings.HasPrefix(*uenv_vars, "all-:") {
		no_uenv_vars := strings.Split(strings.Replace(*uenv_vars, "all-:", "", 1), ",")
		for _, env := range os.Environ() {
			pair := strings.SplitN(env, "=", 2)
			key := pair[0]
			is_unset_env := true
			for _, no_uenv := range no_uenv_vars {
				if key == no_uenv {
					is_unset_env = false
					break
				}
			}
			if is_unset_env {
				os.Unsetenv(key)
			}
		}
	} else {
		env_vars_pass := strings.Split(*env_vars, ",")
		uenv_vars_pass := strings.Split(*uenv_vars, ",")
		for _, env := range os.Environ() {
			pair := strings.SplitN(env, "=", 2)
			key := pair[0]
			is_unset_env := true
			if *uenv_vars != "all" {
				env_vars_pass = append(env_vars_pass,
					"PATH", "SHELL", "HOME", "MAIL", "USER", "LOGNAME",
					"DISPLAY", "WAYLAND_DISPLAY", "LANG", "LANGUAGE",
					"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
					"XDG_SESSION_CLASS", "XDG_SESSION_TYPE",
					"XDG_DATA_DIRS", "XDG_CONFIG_DIRS",
					"XDG_SESSION_DESKTOP", "XDG_CURRENT_DESKTOP",
					"KDE_FULL_SESSION", "KDE_SESSION_VERSION",
				)
			}
			for _, env_pass := range env_vars_pass {
				if key == env_pass {
					is_unset_env = false
					break
				}
			}
			if *uenv_vars != "all" && !is_unset_env {
				for _, uenv_pass := range uenv_vars_pass {
					if key == uenv_pass {
						is_unset_env = true
						break
					}
				}
			}
			if is_unset_env {
				os.Unsetenv(key)
			}
		}
	}

	if len(*cwd) != 0 {
		err := os.Chdir(*cwd)
		if err != nil {
			log.Fatalf("cwd path error: %v\n", err)
		}
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[%s] accept error: %v", conn.RemoteAddr().String(), err)
			continue
		}
		go srv_handle(conn, self_cpids_dir)
	}
}

func client(proto, socket string, exec_args []string) int {
	var err error
	var wg sync.WaitGroup

	is_alloc_pty := true
	if len(exec_args) != 0 {
		is_alloc_pty = !pty_blocklist[exec_args[0]]
	}
	if *is_pty {
		is_alloc_pty = true
	} else if *is_no_pty {
		is_alloc_pty = false
	}

	var conn net.Conn
	if is_file_exists(*tls_cert) {
		tls_config := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}
		conn, err = tls.Dial(proto, socket, tls_config)
		if err != nil {
			log.Fatalf("TLS connection error: %v", err)
		}
		cert_hash, err := get_cert_hash(*tls_cert)
		if err != nil {
			log.Fatalf("failed to get cert hash: %v", err)
		}
		_, err = conn.Write([]byte(cert_hash))
		if err != nil {
			log.Fatalf("failed to send cert hash: %v", err)
		}
		status_reader := bufio.NewReader(conn)
		status, err := status_reader.ReadString('\r')
		if err != nil {
			log.Fatalf("error reading hash status: %v", err)
		}
		if status == "error\r" {
			log.Fatalf("invalid cert!")
		}
	} else {
		conn, err = net.Dial(proto, socket)
		if err != nil {
			log.Fatalf("connection error: %v", err)
		}
	}
	defer conn.Close()

	yamux_config := yamux.DefaultConfig()
	yamux_config.StreamOpenTimeout = 0
	session, err := yamux.Client(conn, yamux_config)
	if err != nil {
		log.Fatalf("session error: %v", err)
	}
	defer session.Close()

	_, err = session.Ping()
	if err != nil {
		log.Fatalf("ping error: %v", err)
	}

	stdin := int(os.Stdin.Fd())
	is_stdin_term := false
	if term.IsTerminal(stdin) {
		is_stdin_term = true
	}
	stdout := int(os.Stdout.Fd())
	is_stdout_term := false
	if term.IsTerminal(stdout) {
		is_stdout_term = true
	}
	stderr := int(os.Stderr.Fd())
	is_stderr_term := false
	if term.IsTerminal(stderr) {
		is_stderr_term = true
	}

	pid := os.Getpid()
	pgid, err := unix.Getpgid(pid)
	if err != nil {
		log.Fatalf("error getting process group ID: %v", err)
	}
	is_foreground := true
	tpgid, err := unix.IoctlGetInt(unix.Stdin, unix.TIOCGPGRP)
	if err == nil && pgid != tpgid {
		is_foreground = false
	}

	var term_old_state *term.State
	if (is_stdin_term && is_stderr_term && is_stdout_term && is_foreground) ||
		(*is_pty && is_stdin_term) {
		if is_alloc_pty && is_stdin_term {
			is_foreground = true
			term_old_state, err = term.MakeRaw(stdin)
			if err != nil {
				log.Fatalf("unable to make terminal raw: %v", err)
			}
			defer term.Restore(stdin, term_old_state)
		}
	} else {
		is_alloc_pty = false
	}

	var envs string
	if *env_vars == "all" {
		for _, env := range os.Environ() {
			envs += env + "\n"
		}
	} else if strings.HasPrefix(*env_vars, "all-:") {
		unset_env_vars := strings.Split(strings.Replace(*env_vars, "all-:", "", 1), ",")
		for _, env := range os.Environ() {
			pair := strings.SplitN(env, "=", 2)
			key := pair[0]
			is_add_env := true
			for _, unset_env := range unset_env_vars {
				if key == unset_env {
					is_add_env = false
					break
				}
			}
			if is_add_env {
				envs += env + "\n"
			}
		}
	} else {
		if *env_vars != "TERM" {
			*env_vars = fmt.Sprintf("TERM," + *env_vars)
		}
		for _, env := range strings.Split(*env_vars, ",") {
			if value, ok := os.LookupEnv(env); ok {
				envs += env + "=" + value + "\n"
			}
		}
	}
	if len(*uenv_vars) != 0 {
		envs += fmt.Sprintf("_SSRV_UENV=%s\n", *uenv_vars)
	}
	if len(*cwd) != 0 {
		envs += fmt.Sprintf("_SSRV_CWD=%s\n", *cwd)
	}
	if !is_alloc_pty {
		envs += "_NO_PTY_"
	}
	envs += "\r\n"
	envs_channel, err := session.Open()
	if err != nil {
		log.Fatalf("environment channel open error: %v", err)
	}
	_, err = envs_channel.Write([]byte(envs))
	if err != nil {
		log.Fatalf("failed to send environment variables: %v", err)
	}

	var stdin_channel net.Conn
	var stderr_channel net.Conn
	if !is_alloc_pty {
		stdin_channel, err = session.Open()
		if err != nil {
			log.Fatalf("stdin channel open error: %v", err)
		}
		stderr_channel, err = session.Open()
		if err != nil {
			log.Fatalf("stderr channel open error: %v", err)
		}
	}

	data_channel, err := session.Open()
	if err != nil {
		log.Fatalf("data channel open error: %v", err)
	}

	command_channel, err := session.Open()
	if err != nil {
		log.Fatalf("command channel open error: %v", err)
	}
	command := strings.Join(exec_args, "\n") + "\r\n"
	_, err = command_channel.Write([]byte(command))
	if err != nil {
		log.Fatalf("failed to send command: %v", err)
	}

	pipe_stdin := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		stdin_channel.Close()
	}
	cp := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
	}

	control_channel, err := session.Open()
	if err != nil {
		log.Fatalf("control channel open error: %v", err)
	}
	if is_alloc_pty {
		go func() {
			encoder := gob.NewEncoder(control_channel)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGWINCH)
			for {
				cols, rows, err := term.GetSize(stdin)
				if err != nil {
					log.Printf("get term size error: %v", err)
					break
				}
				win := struct {
					Rows, Cols int
				}{Rows: rows, Cols: cols}
				if err := encoder.Encode(win); err != nil {
					break
				}
				<-sig
			}
		}()
	} else {
		sig_chan := make(chan os.Signal, 1)
		signal.Notify(sig_chan, os.Interrupt,
			syscall.SIGINT, syscall.SIGTERM,
			syscall.SIGHUP, syscall.SIGQUIT,
			syscall.SIGUSR1, syscall.SIGUSR2,
		)
		go func() {
			sig := <-sig_chan
			switch sig {
			case syscall.SIGINT:
				control_channel.Write([]byte("SIGINT\r"))
			case syscall.SIGTERM:
				control_channel.Write([]byte("SIGTERM\r"))
			case syscall.SIGQUIT:
				control_channel.Write([]byte("SIGQUIT\r"))
			case syscall.SIGHUP:
				control_channel.Write([]byte("SIGHUP\r"))
			case syscall.SIGUSR1:
				control_channel.Write([]byte("SIGUSR1\r"))
			case syscall.SIGUSR2:
				control_channel.Write([]byte("SIGUSR2\r"))
			}
		}()
	}

	if is_foreground {
		if !is_stdin_term {
			wg.Add(1)
			go pipe_stdin(stdin_channel, os.Stdin)
		} else {
			wg.Add(1)
			go cp(data_channel, os.Stdin)
		}
	}
	if !is_alloc_pty {
		wg.Add(1)
		go cp(os.Stderr, stderr_channel)
	}
	wg.Add(1)
	go cp(os.Stdout, data_channel)

	var exit_code = 1
	exit_reader := bufio.NewReader(command_channel)
	exit_code_str, err := exit_reader.ReadString('\r')
	if strings.Contains(exit_code_str, "cmd error:") {
		log.Println(exit_code_str)
	} else if err == nil {
		exit_code, err = strconv.Atoi(exit_code_str[:len(exit_code_str)-1])
		if err != nil {
			log.Printf("failed to parse exit code: %v", err)
		}
	} else if err != io.EOF {
		log.Printf("error reading from command channel: %v", err)
	}

	if term_old_state != nil {
		term.Restore(stdin, term_old_state)
		if is_foreground {
			wg.Done()
		}
	}
	if is_foreground && is_stdin_term && ((!*is_pty && !*is_no_pty) ||
		(*is_no_pty && (!is_stdout_term || !is_stderr_term)) || *is_no_pty) {
		if !is_stderr_term || !is_alloc_pty {
			wg.Done()
		}
	}

	wg.Wait()
	return exit_code
}

func main() {
	var exec_args []string
	self_basename := path.Base(os.Args[0])
	if self_basename != BINARY_NAME {
		exec_args = append([]string{self_basename}, os.Args[1:]...)
	} else {
		exec_args = flag_parse()
	}

	ssrv_env_vars_parse()
	ssrv_env_vars_unset()

	address := strings.Split(*socket_addr, ":")
	if len(address) > 1 && is_valid_proto(address[0]) {
		proto := address[0]
		socket := get_socket(address)
		if *is_srv {
			server(proto, socket)
		} else {
			os.Exit(client(proto, socket, exec_args))
		}
	} else {
		log.Fatal("socket format is not recognized!")
	}
}
