# DDC Radial Adapter

This adapter is optional. Radial Terminal must remain usable without DDC.

## Execution model

The adapter is asynchronous. It receives a normalized preflight envelope only after the operator has explicitly enabled Assured mode for the relevant profile.

The local Guarded classifier always runs first. The DDC result is then combined monotonically:

ALLOW < REVIEW < BLOCK

The external provider may preserve or increase severity. It may never downgrade the local result.

Examples:

- local BLOCK + DDC ALLOW -> BLOCK
- local REVIEW + DDC ALLOW -> REVIEW
- local ALLOW + DDC REVIEW -> REVIEW
- local ALLOW + DDC BLOCK -> BLOCK

## Input contract

The adapter receives at minimum:

- session identifier
- target identity
- requested command
- request timestamp
- local classifier decision/findings
- optional observed host state
- explicit policy/profile identifier

Credentials and private SSH keys are never part of the request.

## Output contract

The adapter returns:

- ALLOW / REVIEW / BLOCK
- provider identity and version
- policy/version identifiers when applicable
- structured findings/contradictions
- decision timestamp
- freshness/expiry when applicable
- evidence references when applicable

## Failure behavior

Unavailable, failed, malformed, or stale external assurance becomes REVIEW. It never becomes ALLOW.

## Data boundary

No command, terminal history, host state, or credential material leaves the device merely because the adapter exists. External assurance is opt-in per host/profile.
