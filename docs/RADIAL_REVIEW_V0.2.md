# DDC Radial Review — Android Shell v0.2

## Reviewed transition

```text
v0.1 assurance core
    ->
Android operator shell
    ->
future terminal + SSH transport
```

## Findings

### Runtime compatibility

The v0.1 core targeted Java 21. Android and the selected upstream SSH/terminal
stack target Java 17. Keeping a Java 21 core would create an avoidable runtime
and build boundary.

**Disposition:** corrected. Core and Android shell now target Java 17.

### Mode ambiguity

A terminal that displays "guarded" while silently bypassing classification
would create a false assurance signal.

**Disposition:** mode behavior is centralized in `CommandGate`.

- DIRECT bypasses assurance intentionally.
- GUARDED uses local classification.
- ASSURED requires an external provider or degrades to REVIEW.

### External-provider failure

Network errors, malformed responses, unavailable adapters, and provider
exceptions must not become ALLOW.

**Disposition:** ASSURED provider absence/failure degrades to REVIEW.

### Interactive-shell representation

Raw terminal bytes do not provide a reliable command boundary. Intercepting
every newline and claiming the resulting string is the executed shell command
would overstate assurance.

**Disposition:** v0.2 uses an explicit command-preflight surface. SSH/terminal
wiring is postponed until a trustworthy boundary contract is implemented.

### Target binding

The current demo host identifier is UI-only and must not be treated as a
cryptographic host identity.

**Disposition:** acceptable for the shell milestone. Real SSH integration must
bind receipts and decisions to verified host-key identity.

### Privacy

The shell adds no telemetry, analytics, account, or remote assurance call.

**Disposition:** PASS.

## Radial disposition

**ALLOW FOR v0.2 SHELL, REVIEW BEFORE SSH INTERCEPTION**

The architecture remains valid if the next implementation preserves:
1. verified host-key binding;
2. explicit command-boundary semantics;
3. fail-closed assured-mode behavior;
4. local-first receipt storage;
5. visible mode state;
6. upstream licensing/attribution.
