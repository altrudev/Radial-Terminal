# Radial Terminal

**Assurance-aware SSH and remote execution for Android.**

Radial Terminal is a standalone terminal client designed to preserve ordinary SSH usability while adding an optional assurance layer for commands that can alter remote state.

The product is being developed by **Valentyn Rukhaylo / Altru.dev**.

> Status: v0.2 Android operator shell under verification.

## Product boundary

Radial Terminal must remain useful without DDC, DDCRE, DSR, Agent Replay, a cloud account, or telemetry.

Optional adapters may add deeper assurance:

- DDC Radial — multi-dimensional preflight analysis
- DDCRE — governed remote execution
- DSR — independently observed execution evidence
- Agent Replay — incident reconstruction

## Current milestone

v0.2 now establishes:

- Android Compose application shell
- Direct / Guarded / Assured session modes
- explicit Direct-mode bypass provenance
- conservative local command preflight
- unknown commands default to REVIEW
- monotonic local + external assurance composition
- fail-closed external provider handling
- stale-decision handling
- structured action-receipt schema
- Java 17 compatibility across Android and assurance core
- dependency-first integration plan for ConnectBot termlib and cbssh

The current UI is a preflight demo only. It does not yet connect to SSH or execute commands, and it labels that limitation explicitly.

## Assurance rule

```text
ALLOW < REVIEW < BLOCK
```

Assured mode may never reduce the local Guarded result.

## Design principle

```text
request -> preflight -> proceed/confirm/stop -> execute -> observe -> receipt
```

Preflight permission is not the same thing as execution.

## Upstream strategy

Radial Terminal is intended to consume Apache-2.0-licensed ConnectBot components while preserving all required upstream notices and attribution. A dependency-first approach is preferred over wholesale application copying.

## License

Apache License 2.0.

Copyright 2026 Valentyn Rukhaylo / Altru.dev.
