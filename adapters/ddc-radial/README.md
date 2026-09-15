# DDC Radial Adapter

This adapter is optional.

Radial Terminal must function as a standard SSH client when this adapter is
absent, disabled, unreachable, or unsupported.

## Input contract

The adapter receives a normalized preflight envelope containing at minimum:

- session identifier
- target/host identifier
- requested command
- request timestamp
- local classifier findings
- optional observed host state
- explicit adapter policy/profile identifier

## Output contract

The adapter maps the external result into:

- `ALLOW`
- `REVIEW`
- `BLOCK`

and preserves:

- provider identity
- provider version
- policy/version identifiers
- findings/contradictions
- decision timestamp
- freshness or expiry information when supplied
- evidence references when supplied

## Failure behavior

An external adapter failure must never silently become `ALLOW`.

Recommended policy:

- Direct mode: adapter is not called.
- Guarded mode: local classifier remains authoritative for the local gate.
- Assured mode: unavailable/invalid external assurance returns REVIEW or BLOCK
  according to the host profile.

## Data boundary

No command, terminal history, host state, or credential material may leave
the device merely because the adapter exists. The operator must explicitly
enable the adapter for the relevant profile.

Credentials and private SSH keys are never part of the assurance request.
