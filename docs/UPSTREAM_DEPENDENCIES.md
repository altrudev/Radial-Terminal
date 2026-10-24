# Upstream dependency strategy

Radial Terminal is not intended to wholesale-copy the ConnectBot application.

The preferred boundary is to consume maintained upstream components and keep
Radial-specific operator assurance in this repository.

## Confirmed upstream components

### Terminal

Repository: `connectbot/termlib`

Published coordinate:

```text
org.connectbot:termlib
```

The component is a Jetpack Compose terminal backed by libvterm/JNI.

### SSH

Repository: `connectbot/cbssh`

Published coordinate:

```text
org.connectbot.sshlib:sshlib
```

The library provides SSH client transport, authentication, interactive PTY
sessions, SFTP, forwarding, and modern SSH algorithms.

## Integration order

1. Build and verify the Android operator shell.
2. Add termlib behind a small `TerminalSurface` abstraction.
3. Add cbssh behind `SshTransport`.
4. Bind terminal keyboard output to the command gate only at complete-command
   boundaries.
5. Bind SSH output directly into the terminal emulator.
6. Add host-key verification and Android credential storage.
7. Add optional DDC Radial provider.
8. Add local receipt persistence and export.

## Important representation boundary

Interactive shells do not naturally expose a reliable "complete command"
event. A newline typed by the user is not sufficient evidence that the remote
shell will execute exactly the visible text: shell editing, bracketed paste,
multiline input, aliases, expansion, shell functions, terminal control
sequences, and nested programs can alter behavior.

Therefore Radial Terminal must not intercept raw SSH byte streams and claim
that each line is a semantically complete command.

The v0.2 UI exercises an explicit preflight path. Interactive interception will
only be enabled after a command-boundary mechanism is designed and tested.
