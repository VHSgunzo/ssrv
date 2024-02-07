package main

import (
	"bufio"
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
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/hashicorp/yamux"
	"golang.org/x/term"
)

var VERSION string = "HEAD"

const BINARY_NAME = "shellsrv"
const UNIX_SOCKET = "unix:@shellsrv"

const USAGE_PREAMBLE = `Server usage: %[1]s -server [-socket tcp:1337]
Client usage: %[1]s [options] [ COMMAND [ arguments... ] ]

If COMMAND is not passed, spawn a $SHELL on the server side.

Accepted options:
`

const USAGE_FOOTER = `
--

Environment variables:
    SSRV_ALLOC_PTY=1                Same as -pty argument
    SSRV_NO_ALLOC_PTY=1             Same as -no-pty argument
    SSRV_ENV="MY_VAR,MY_VAR1"       Same as -env argument
    SSRV_SOCKET="tcp:1337"          Same as -socket argument
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
	"server", false,
	"Run as server",
)
var socket_addr = flag.String(
	"socket", UNIX_SOCKET,
	"Socket address listen/connect (unix,tcp,tcp4,tcp6)",
)
var env_vars = flag.String(
	"env", "TERM",
	"Comma separated list of environment variables to pass to the server side process.",
)
var is_version = flag.Bool(
	"version", false,
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

func ssrv_env_vars_parse() {
	if is_env_var_eq("SSRV_ALLOC_PTY", "1") {
		flag.Set("pty", "true")
	}
	if is_env_var_eq("SSRV_NO_ALLOC_PTY", "1") {
		flag.Set("no-pty", "true")
	}
	if ssrv_socket, ok := os.LookupEnv("SSRV_SOCKET"); ok {
		flag.Set("socket", ssrv_socket)
	}
	if ssrv_envs, ok := os.LookupEnv("SSRV_ENV"); ok {
		flag.Set("env", ssrv_envs)
	}
}

func srv_handle(conn net.Conn) {
	disconnect := func(session *yamux.Session, remote string) {
		session.Close()
		log.Printf("[%s] [  DISCONNECTED  ]", remote)
	}

	remote := conn.RemoteAddr().String()
	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("[%s] session error: %v", remote, err)
		return
	}
	defer disconnect(session, remote)
	log.Printf("[%s] [ NEW CONNECTION ]", remote)

	done := make(chan struct{})

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
	if envs[last_env_num] == "is_alloc_pty := false" {
		is_alloc_pty = false
		envs = envs[:last_env_num]
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
	log.Printf("[%s] exec: %s", remote, cmd)
	exec_cmd := exec.Command(cmd[0], cmd[1:]...)

	exec_cmd.Env = os.Environ()
	exec_cmd.Env = append(exec_cmd.Env, envs...)

	var cmd_ptmx *os.File
	var cmd_stdout, cmd_stderr io.ReadCloser
	if is_alloc_pty {
		cmd_ptmx, err = pty.Start(exec_cmd)
	} else {
		cmd_stdout, _ = exec_cmd.StdoutPipe()
		cmd_stderr, _ = exec_cmd.StderrPipe()
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
	defer cmd_ptmx.Close()

	cmd_pid := strconv.Itoa(exec_cmd.Process.Pid)
	log.Printf("[%s] pid: %s", remote, cmd_pid)

	if is_alloc_pty {
		control_channel, err := session.Accept()
		if err != nil {
			log.Printf("[%s] control channel accept error: %v", remote, err)
			return
		}
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
					log.Printf("[%s] set term size error: %v", remote, err)
					break
				}
				if err := syscall.Kill(exec_cmd.Process.Pid, syscall.SIGWINCH); err != nil {
					log.Printf("[%s] sigwinch error: %v", remote, err)
					break
				}
			}
			done <- struct{}{}
		}()
	}

	data_channel, err := session.Accept()
	if err != nil {
		log.Printf("[%s] data channel accept error: %v", remote, err)
		return
	}
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}

	if is_alloc_pty {
		go cp(data_channel, cmd_ptmx)
		go cp(cmd_ptmx, data_channel)
	} else {
		go cp(data_channel, cmd_stdout)
		go cp(data_channel, cmd_stderr)
	}

	<-done

	state, err := exec_cmd.Process.Wait()
	if err != nil {
		log.Printf("[%s] error getting exit code: %v", remote, err)
		return
	}
	exit_code := strconv.Itoa(state.ExitCode())
	log.Printf("[%s] exit: %s", remote, exit_code)

	_, err = command_channel.Write([]byte(fmt.Sprint(exit_code + "\r\n")))
	if err != nil {
		log.Printf("[%s] error sending exit code: %v", remote, err)
	}
}

func server(proto, socket string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		if proto == "unix" && is_file_exists(socket) {
			os.Remove(socket)
		}
		os.Exit(1)
	}()

	listen, err := net.Listen(proto, socket)
	if err != nil {
		log.Fatal(err)
	}
	if proto == "unix" && is_file_exists(socket) {
		err = os.Chmod(socket, 0700)
		if err != nil {
			log.Fatalln("unix socket:", err)
		}
	}
	log.Printf("listening on %s %s", listen.Addr().Network(), listen.Addr().String())

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("[%s] accept error: %v", conn.RemoteAddr().String(), err)
			continue
		}
		go srv_handle(conn)
	}
}

func client(proto, socket string, exec_args []string) int {
	is_alloc_pty := true
	if len(exec_args) != 0 {
		is_alloc_pty = !pty_blocklist[exec_args[0]]
	}
	if *is_pty {
		is_alloc_pty = true
	} else if *is_no_pty {
		is_alloc_pty = false
	}

	conn, err := net.Dial(proto, socket)
	if err != nil {
		log.Fatalf("connection error: %v", err)
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Fatalf("session error: %v", err)
	}
	defer session.Close()

	var old_state *term.State
	stdin := int(os.Stdin.Fd())
	if term.IsTerminal(stdin) {
		if is_alloc_pty {
			old_state, err = term.MakeRaw(stdin)
			if err != nil {
				log.Fatalf("unable to make terminal raw: %v", err)
			}
			defer term.Restore(stdin, old_state)
		}
	} else {
		is_alloc_pty = false
	}

	done := make(chan struct{})

	env_vars_pass := strings.Split(*env_vars, ",")
	var envs string
	for _, env := range env_vars_pass {
		if value, ok := os.LookupEnv(env); ok {
			envs += env + "=" + value + "\n"
		}
	}
	if !is_alloc_pty {
		envs += "is_alloc_pty := false"
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

	command_channel, err := session.Open()
	if err != nil {
		log.Fatalf("command channel open error: %v", err)
	}
	command := strings.Join(exec_args, "\n") + "\r\n"
	_, err = command_channel.Write([]byte(command))
	if err != nil {
		log.Fatalf("failed to send command: %v", err)
	}

	if is_alloc_pty {
		control_channel, err := session.Open()
		if err != nil {
			log.Fatalf("control channel open error: %v", err)
		}
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
			done <- struct{}{}
		}()
	}

	data_channel, err := session.Open()
	if err != nil {
		log.Fatalf("data channel open error: %v", err)
	}
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(data_channel, os.Stdin)
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
	} else {
		log.Printf("error reading from command channel: %v", err)
	}

	<-done
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
