# Radial Terminal

**Assurance-aware SSH and remote execution for Android.**

Radial Terminal is a standalone terminal client designed to preserve ordinary SSH usability while adding an optional assurance layer for commands that can alter remote state.

The product is being developed by **Valentyn Rukhaylo / Altru.dev**.

> Status: early architecture and implementation.

## Product boundary

Radial Terminal must remain useful without DDC, DDCRE, DSR, or any other Altru.dev infrastructure.

Optional adapters may add deeper assurance:

- DDC Radial — multi-dimensional preflight analysis
- DDCRE — governed remote execution
- DSR — independently observed execution evidence
- Agent Replay — incident reconstruction

The core terminal, SSH connectivity, host management, command history, local receipts, and built-in static risk classification remain standalone.

## Design principle

```text
request -> preflight -> execute -> observe -> receipt
```

Ordinary read-only terminal use should remain low-friction. Potentially destructive or authority-changing operations can be classified, inspected, confirmed, and recorded.

## Upstream strategy

Radial Terminal is intended to use or derive from Apache-2.0-licensed ConnectBot components while preserving all required upstream notices and attribution. Any incorporated upstream source must retain its applicable copyright and license notices.

A dependency-first approach is preferred where practical: use maintained ConnectBot libraries such as its terminal and SSH components rather than copying application code unnecessarily.

## License

Apache License 2.0 is planned for the open-source core. See the repository license and notices as they are added.

Copyright 2026 Valentyn Rukhaylo / Altru.dev.
