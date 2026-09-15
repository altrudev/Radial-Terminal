# Radial Terminal v0.2 Product Specification

## User promise

Evaluate a remote command before execution, make assurance bypasses visible, and preserve enough provenance to reconstruct what was requested, permitted, executed, and observed.

## Modes

### Direct

Bypasses assurance intentionally. The bypass itself is recorded as provenance. Direct mode must never masquerade as an assurance decision.

### Guarded

Runs the local conservative classifier. Only explicitly recognized low-risk command families receive ALLOW. Unknown or opaque commands receive REVIEW.

### Assured

Runs the local Guarded baseline plus an optional external assurance provider. External assurance may preserve or increase severity; it may never downgrade the local result.

Examples:

ALLOW + REVIEW -> REVIEW
REVIEW + ALLOW -> REVIEW
BLOCK + ALLOW -> BLOCK
ALLOW + BLOCK -> BLOCK

Unavailable, failed, malformed, or stale external assurance degrades to REVIEW.

## v0.2 scope

- Android Compose operator shell
- Direct / Guarded / Assured session modes
- deterministic local classifier
- conservative unknown-command handling
- bounded command input
- explicit preflight result: ALLOW / REVIEW / BLOCK
- monotonic local + external assurance composition
- decision freshness field
- structured receipt schema
- no mandatory account
- no telemetry
- no command upload by default

## Not yet implemented

- live SSH transport
- verified SSH host-key binding
- terminal emulator integration
- local receipt persistence
- external DDC transport implementation
- independent post-execution observation
- Agent Replay export

The UI must clearly identify these missing capabilities and must not imply that commands have executed.

## Explicit non-goals

- pretending textual classification is shell semantic proof
- silently intercepting arbitrary terminal bytes and claiming command identity
- autonomous privileged command execution
- allowing an external provider to weaken a local BLOCK
- requiring Altru.dev infrastructure
- uploading terminal history by default
