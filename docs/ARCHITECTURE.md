# Radial Terminal Architecture

## Product invariant

Radial Terminal is a terminal first and an assurance client second.

A user must eventually be able to connect to a standard SSH server and use the terminal without DDC, DDCRE, DSR, Agent Replay, an account, telemetry, or a remote control plane.

## State-transition boundary

Preflight permission and actual execution are different transitions:

requested command
-> preflight request validation
-> local classifier
-> optional external assurance
-> monotonic combination
-> ALLOW / REVIEW / BLOCK
-> Proceed / Confirm / Stop
-> explicit execution boundary
-> execute
-> observe
-> receipt

Proceed means the preflight gate permits continuing. It does not mean an action has already executed.

## Monotonic assurance rule

External assurance can never reduce the severity of the local baseline.

Severity ordering:

ALLOW < REVIEW < BLOCK

Assured mode takes the maximum severity across local and external decisions. Provider failure, absence, invalidity, or staleness is REVIEW.

## Representation boundary

Raw terminal bytes are not authoritative command semantics. Aliases, shell functions, multiline editing, expansion, subshells, bracketed paste, and nested interactive programs can change behavior.

Therefore the project does not infer authoritative executed-command identity from a newline in an interactive PTY.

## Target identity

Display hostname is not proof of target identity. Before live SSH execution, the assurance and receipt boundary must bind to verified SSH host-key identity, hostname, and port.

## Modules

### terminal-core
Terminal rendering, input, escape handling, session lifecycle.

### ssh-provider
Standard SSH transport behind a narrow interface.

### assurance-core
Standalone local-first risk classifier and common decision model.

### assurance-ddc
Optional asynchronous external assurance adapter.

### receipt-store
Local receipt persistence. Export is explicit.

### executor-ddcre
Optional governed remote execution adapter.

### evidence-dsr
Optional independently observed evidence transport.

### replay-export
Optional Agent Replay/session export.

## Privacy

Default:
- no telemetry
- no cloud account
- no command upload
- local history
- local receipts

Any external assurance adapter is opt-in and visibly configured per host or profile.
