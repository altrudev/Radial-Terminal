# Radial Terminal Architecture

## Product invariant

Radial Terminal is a terminal first and an assurance client second.

A user must be able to connect to a standard SSH server and use the terminal
without DDC, DDCRE, DSR, Agent Replay, an account, telemetry, or a remote
control plane.

## Execution pipeline

```text
input
  |
  v
command parser
  |
  +---- non-mutating / low-risk ----> execute
  |
  v
assurance preflight
  |
  +---- ALLOW ----------------------> execute
  +---- REVIEW ---> explicit user confirmation ---> execute/cancel
  +---- BLOCK ----------------------> stop
  |
  v
observation
  |
  v
local action receipt
```

## Modules

### terminal-core
Terminal rendering, input, escape handling, session lifecycle.

### ssh-provider
Standard SSH transport. Preferred implementation strategy is to consume
maintained upstream libraries rather than copy application code where
practical.

### assurance-core
Standalone deterministic risk classifier and common assurance data model.
It must be local-first and must not require network access.

### assurance-ddc
Optional adapter. Sends the normalized preflight envelope to a configured
DDC Radial endpoint/runtime and maps the response into the common
disposition model.

### executor-ddcre
Optional governed execution adapter.

### evidence-dsr
Optional independently observed evidence transport.

### replay-export
Exports an incident/session bundle consumable by Agent Replay or another
compatible reconstruction system.

### receipt-store
Local receipt storage. Export is explicit.

## Common decision model

```text
ALLOW   - operation may proceed without additional assurance interaction
REVIEW  - explicit operator confirmation required
BLOCK   - operation must not execute through the guarded path
```

A provider may attach findings without changing the three-state contract.

## Trust boundary

The terminal must never silently promote an external adapter's result.
Adapter identity, policy version, and evidence freshness are part of the
decision envelope.

## Privacy

Default:
- no telemetry
- no cloud account
- no command upload
- local history
- local receipts

Any external assurance adapter is opt-in and visibly configured per host or
profile.
