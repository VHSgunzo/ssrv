# shellsrv
`shellsrv` is a versatile networking tool designed to enable efficient command execution across different systems. It operates as both a server and a client, facilitating remote shell access and command execution. With a focus on flexibility and control, users can specify environment variables, choose whether to allocate a pseudo-terminal, and define the socket for communication.

Key features include:

- **Multiplexed Connections**: Allows handling multiple clients simultaneously, ensuring robustness and scalability.
- **Customizable Environment Variables**: Users can pass a comma-separated list of environment variables to the server side process, providing fine-grained control over the session environment.
- **Pseudo-Terminal Allocation**: Offers options to force or avoid allocating a pseudo-terminal, accommodating various command behaviors and client requirements.
- **Command Execution**: When no command is passed, the default behavior is to spawn a shell on the server side, offering full shell functionality to the client. The remote command exit code is also returned to the client.
- **Shims for the server side binaries**: If there's a process that you always want to execute on the server side system, you can
create a symlink to it somewhere in your `$PATH` and it'll always be executed through `shellsrv`.
- **Stdin Pipe**: Sends data to the command's standard input using a pipe.

`shellsrv` is ideal for system administrators and developers who require a solution for executing commands remotely or locally with  listening on unix sockets. By default, the server and the client communicate via an abstract unix socket `@shellsrv`. Its configurability and support for multiple concurrent sessions make it suitable for complex network operations and management tasks.

## To get started:
* **Install the latest revision**
```
go install github.com/VHSgunzo/shellsrv@latest
```
* Or take an already precompiled binary file from the [releases](https://github.com/VHSgunzo/shellsrv/releases)


## **Usage**:
```
┌──[user@linux]─[~] - Server:
└──╼ $ shellsrv -server [-socket tcp:1337] [-env all]
┌──[user@linux]─[~] - Client:
└──╼ $ shellsrv [options] [ COMMAND [ arguments... ] ]

If COMMAND is not passed, spawn a $SHELL on the server side.

Accepted options:
    -cpids-dir string
        A directory on the server side for storing a list of client PIDs. (default "/tmp/ssrv$EUID")
    -cwd string
        Change the current working directory of the process/command.
    -env string
        Comma separated list of environment variables to pass to the server side process. (default "TERM")
    -no-pty
        Do not allocate a pseudo-terminal for the server side process
    -nosep-cpids
        Don't create a separate dir for the server socket to store the list of client PIDs.
    -pid-file string
        The file for storing the server's PID.
    -pty
        Force allocate a pseudo-terminal for the server side process
    -server
        Run as server
    -socket string
        Socket address listen/connect (unix,tcp,tcp4,tcp6) (default "unix:@shellsrv")
    -uenv string
        Comma separated list of environment variables for unset on the server side process.
    -version
        Show this program's version

--

Environment variables:
    SSRV_ALLOC_PTY=1                Same as -pty argument
    SSRV_NO_ALLOC_PTY=1             Same as -no-pty argument
    SSRV_ENV="MY_VAR,MY_VAR1"       Same as -env argument
    SSRV_UENV="MY_VAR,MY_VAR1"      Same as -uenv argument
    SSRV_SOCKET="tcp:1337"          Same as -socket argument
    SSRV_CPIDS_DIR=/path/dir        Same as -cpids-dir argument
    SSRV_NOSEP_CPIDS=1              Same as -nosep-cpids argument
    SSRV_PID_FILE=/path/ssrv.pid    Same as -pid-file argument
    SSRV_CWD=/path/dir              Same as -cwd argument
    SHELL="/bin/bash"               Assigns a default shell (on the server side)

--

If none of the pty arguments are passed in the client, a pseudo-terminal is allocated by default, unless it is
known that the command behaves incorrectly when attached to the pty or the client is not running in the terminal
```

Example of creating a shim for the `flatpak` command:

```
# Inside your container:

$ flatpak --version
zsh: command not found: flatpak

# Have shellsrv handle any flatpak command
$ ln -s /usr/local/bin/shellsrv /usr/local/bin/flatpak

# Now flatpak will always be executed on the server side
$ flatpak --version
Flatpak 1.12.7
```
**Note:** you will want to store the symlink in a location visible only to the container, to avoid an infinite loop. If you are using toolbox/distrobox, this means anywhere outside your home directory. I recommend `/usr/local/bin`.

Example of file transfer to server:

```
# one file:
shellsrv sh -c 'cat>/server/path/some_file.tar.zst' </client/path/some_file.tar.zst

# directory with zstd compression:
tar -I 'zstd -T0 -1' -c /client/path/some_dir|shellsrv tar --zstd -xf - -C /server/path/some_dir
```

Example of file transfer from server:

```
# one file:
shellsrv cat /server/path/some_file.tar.zst > /client/path/some_file.tar.zst

# directory with zstd compression:
shellsrv tar -I 'zstd -T0 -1' -c /server/path/some_dir|tar --zstd -xf - -C /client/path/some_dir
# or dir to archive:
shellsrv tar -I 'zstd -T0 -1' -c /server/path/some_dir > /client/path/some_dir.tar.zst
```
