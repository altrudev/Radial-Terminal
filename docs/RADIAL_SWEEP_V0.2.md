# DDC Radial Full-Repository Sweep — v0.2

## Scope

Reviewed the complete current repository and PR #2 across:

- representation
- authority
- target identity
- temporal freshness
- contradiction handling
- consequence
- reversibility
- provenance
- privacy
- build reproducibility
- licensing
- product-boundary drift

## Findings fixed in this sweep

### Monotonic assurance

Assured mode previously allowed the external provider to replace the local result.

Corrected invariant:

ALLOW < REVIEW < BLOCK

External assurance may preserve or increase severity; it may never reduce the local baseline.

### Unknown-command handling

Absence of a dangerous regex match no longer implies ALLOW.

Only explicitly recognized low-risk command shapes receive ALLOW. Unknown or opaque commands receive REVIEW.

### Direct-mode provenance

Direct mode no longer returns a null decision. It produces an explicit direct-bypass decision with assuranceBypassed=true.

### Preflight vs execution representation

GateResult.Execute was renamed to GateResult.Proceed.

Proceed means the gate permits moving to a future execution boundary. It does not claim execution occurred.

### Async external assurance

AssuranceProvider.evaluate is now suspendable so future DDC/network providers do not need to block the Android UI thread.

Provider failures degrade to REVIEW. Coroutine cancellation is preserved rather than converted into an assurance result.

### Freshness

AssuranceDecision now supports validUntil. Expired external decisions degrade to REVIEW.

### Classifier hardening

Added:
- request validation
- command-size bound
- filesystem formatting detection
- raw-device write detection
- infrastructure destroy detection
- system power-state detection
- command-family-specific forced Git push detection
- conservative shell-control handling
- expanded tests for destructive and ambiguous commands

### Receipt provenance

Receipt schema v0.2 now represents:
- receipt ID and nonce
- session/mode
- verified host identity boundary
- requested vs executed command hashes
- provider/policy provenance
- explicit bypass state
- structured findings
- decision freshness
- structured observations
- evidence references

### Licensing

Replaced the abbreviated LICENSE with the complete canonical Apache License 2.0 text while retaining project NOTICE attribution.

### UI truthfulness

The v0.2 UI now explicitly says:
- DEMO TARGET / NOT VERIFIED
- transport is not connected
- NO COMMANDS EXECUTE

The button says Evaluate preflight rather than Run.

## Verification completed

- v0.1 core previously passed the Gradle test suite on the VPS.
- Hardened v0.2 main assurance sources were independently compiled with Kotlin/JVM after this sweep.
- A direct smoke run verified representative ALLOW / REVIEW / BLOCK behavior and proved that external ALLOW cannot downgrade a local BLOCK.

## Remaining gates before merge

1. Generate and commit the Gradle 9.7.0 wrapper using scripts/bootstrap_gradle_wrapper.sh.
2. Re-run the full core test suite from the branch.
3. Complete :app:assembleDebug with Android SDK 37 available.
4. Re-run this radial sweep against the exact merge candidate.
5. Merge only after all four gates pass.

## Post-merge v0.3 boundary

Do not add live SSH command interception until:
- host-key identity is verified and bound to receipts;
- terminal/SSH components are integrated behind narrow interfaces;
- command-boundary semantics are explicit;
- receipt persistence is implemented;
- arbitrary PTY newlines are not treated as authoritative command identity.
