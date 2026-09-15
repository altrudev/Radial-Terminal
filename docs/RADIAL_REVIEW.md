# DDC Radial Design Review — v0.1

This review is the design gate for the initial Radial Terminal architecture.

## Object under review

An Android SSH terminal that optionally evaluates state-changing commands
before execution and records post-execution evidence.

## Radial dimensions

### 1. Representation
**Risk:** shell text is not equivalent to shell behavior. Aliases, quoting,
expansion, pipes, redirection, subshells, remote shell type, and locale can
change meaning.

**Constraint:** never claim semantic certainty from raw command text alone.
The built-in classifier produces risk indicators, not a proof of effect.

### 2. Authority
**Risk:** an authenticated SSH user may still lack authority for the intended
administrative action, while sudo, su, containers, or remote tools can expand
authority.

**Constraint:** distinguish connection identity from effective execution
authority. Elevated commands are REVIEW by default.

### 3. Target
**Risk:** the operator can run the right command against the wrong host,
container, namespace, account, branch, or environment.

**Constraint:** every guarded decision binds host identity and session ID.
Adapters may add stronger target-state bindings.

### 4. Temporal state
**Risk:** preflight state can become stale before execution.

**Constraint:** decisions carry timestamps and optional freshness limits.
High-consequence external decisions must fail closed when their freshness
contract is exceeded.

### 5. Contradiction
**Risk:** command intent, host policy, observed state, and operator request
may conflict.

**Constraint:** contradictory high-confidence findings cannot be collapsed
into ALLOW. They produce REVIEW or BLOCK.

### 6. Consequence
**Risk:** destructive filesystem, package, service, database, firewall,
identity, storage, and cluster operations can cause disproportionate damage.

**Constraint:** consequence is evaluated independently from command
familiarity. Common commands can still be high consequence.

### 7. Reversibility
**Risk:** backups, snapshots, reflogs, transaction logs, or replicas may not
exist when a UI labels an action reversible.

**Constraint:** built-in logic does not claim reversibility merely because a
command usually has a recovery technique.

### 8. Provenance
**Risk:** a decision cannot be audited if we cannot identify which classifier,
policy, adapter, and target produced it.

**Constraint:** receipts bind provider, provider version, host/session IDs,
normalized command hash, disposition, findings, and execution result.

## Initial disposition

**REVIEW / PROCEED WITH CONSTRAINTS**

The architecture is acceptable if:
1. Core SSH remains independent of DDC.
2. Built-in analysis is described as heuristic/deterministic classification,
   not semantic proof.
3. Guard bypass is visible and configurable.
4. No command leaves the device unless an external adapter is explicitly
   enabled.
5. Upstream attribution is preserved.
6. Execution receipts distinguish requested command from observed outcome.

## Self-check

The review itself can be wrong in two important ways:
- textual classification can under-estimate shell semantics;
- post-execution observation can mistake exit status for actual state change.

Therefore v0.1 must not label either mechanism as complete proof. Stronger
claims require independent observation or an assurance adapter.
