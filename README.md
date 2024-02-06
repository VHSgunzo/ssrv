# shellsrv
`shellsrv` is a versatile networking tool designed to enable efficient command execution across different systems. It operates as both a server and a client, facilitating remote shell access and command execution. With a focus on flexibility and control, users can specify environment variables, choose whether to allocate a pseudo-terminal, and define the socket for communication.

Key features include:

- **Multiplexed Connections**: Allows handling multiple clients simultaneously, ensuring robustness and scalability.
- **Customizable Environment Variables**: Users can pass a comma-separated list of environment variables to the server side process, providing fine-grained control over the session environment.
- **Pseudo-Terminal Allocation**: Offers options to force or avoid allocating a pseudo-terminal, accommodating various command behaviors and client requirements.
- **Command Execution**: When no command is passed, the default behavior is to spawn a shell on the server side, offering full shell functionality to the client. The remote command exit code is also returned to the client.
- **Shims for the server side binaries**: If there's a process that you always want to execute on the server side system, you can
create a symlink to it somewhere in your `$PATH` and it'll always be executed through `shellsrv`.

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
└──╼ $ shellsrv -server [-socket tcp:1337]
┌──[user@linux]─[~] - Client:
└──╼ $ shellsrv [options] [ COMMAND [ arguments... ] ]

If COMMAND is not passed, spawn a $SHELL on the server side.

Accepted options:
    -env string
        Comma separated list of environment variables to pass to the server side process. (default "TERM")
    -no-pty
        Do not allocate a pseudo-terminal for the server side process
    -pty
        Force allocate a pseudo-terminal for the server side process
    -server
        Run as server
    -socket string
        Socket address listen/connect (unix,tcp,tcp4,tcp6) (default "unix:@shellsrv")
    -version
        Show this program's version

--

Environment variables:
    SSRV_ALLOC_PTY=1                Same as -pty argument
    SSRV_NO_ALLOC_PTY=1             Same as -no-pty argument
    SSRV_ENVS="MY_VAR,MY_VAR1"      Same as -env argument
    SSRV_SOCKET="tcp:1337"          Same as -socket argument
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
