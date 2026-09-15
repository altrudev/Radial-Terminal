# Radial Terminal v0.1 Product Specification

## User promise

**Know what a remote command is likely to affect before running it, and keep
a verifiable local record of what was requested and what the terminal
observed afterward.**

## Modes

### Direct
Normal SSH terminal behavior.

### Guarded
Locally classify state-changing commands. REVIEW and BLOCK are surfaced
before dispatch.

### Assured
Use a configured external assurance provider and create an evidence-rich
receipt around execution.

## v0.1 scope

- SSH host profiles
- interactive terminal sessions
- Direct / Guarded / Assured session modes
- deterministic local command classifier
- per-command disposition
- explicit confirmation for REVIEW
- hard stop for BLOCK unless policy explicitly defines a separate override
  workflow
- local JSON receipts
- session export
- assurance provider interface
- DDC Radial adapter contract
- no mandatory account
- no telemetry

## Explicit non-goals

- replacing the remote shell
- pretending to perfectly parse every shell dialect
- autonomous command execution
- silently intercepting commands without user-visible mode state
- requiring Altru.dev infrastructure
- uploading terminal history by default
