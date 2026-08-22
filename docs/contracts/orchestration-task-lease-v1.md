# Orchestration task lease v1

## Boundary

This additive boundary gives one registered worker runtime short-lived coordination
ownership of one exact `ready` validation task. A lease is not a dispatch, task-running
transition, policy decision, capability, approval, grant, or network permission. Every
lease document fixes `authority` to `none` and `execution_enabled` to false.

Acquisition binds the active assessment and signed policy, plan/task revisions, agent,
ready-bound v2 capability manifest, ready-bound v2 budget reservation, approval
consumption when required, worker registry identity/version, recovery generation,
purpose, and bounded lifetime. Worker identity and eligibility come only from the
durable trusted runtime registry; command bodies cannot assert runtime or containment
properties.

## Lifecycle and fencing

Migration 0042 stores one active lease per task revision, immutable lease identities,
monotonic per-task lease generations and fencing tokens, and immutable lifecycle
events. Acquisition, renewal, and release use immediate transactions and exact revision
fences. A raw bearer token is returned once at acquisition; only its SHA-256 digest is
stored. Acquisition replay therefore denies instead of reproducing the token.

Renewal and release require the current worker, runtime version, token, lease version,
lease generation, fencing token, and recovery generation. A stale or different holder
cannot affect a newer lease. Lifetimes are bounded by the lease maximum and the earliest
policy, assessment, manifest, budget, or approval expiry.

Startup recovery invalidates every active lease and increments its task recovery fence.
It never renews, reconstructs, reassigns, resumes, dispatches, or creates authority.
Each lifecycle change produces bounded metadata-only hash-chained audit and outbox
linkage.

## Default deny, compatibility, privacy, and rollback

Malformed or unsupported contracts; v1 or mixed readiness prerequisites; stale policy,
plan, task, worker, lease, or recovery versions; invalid safety state; cancellation;
expiry; token mismatch; cross-scope binding; duplicate acquisition; and concurrent or
tampered state deny with stable `ORCHESTRATION_LEASE_*` codes.

The contracts, service, and migration are additive. Existing workflow leases are a
separate Phase 1 coordination boundary and are unchanged. Application rollback disables
new lease operations while retaining immutable security history; reversing migration
0042 is unsupported. Stored data is limited to identifiers, hashes, versions, state,
and timestamps. Raw tokens, credentials, secrets, evidence, prompts, provider payloads,
and targets are not persisted or audited.

Worker dispatch/contact, the `ready` to `running` transition, checkpoints, retries,
completion consumption, Master Orchestrator runtime, provider/plugin execution, UI, and
effect-specific authorization remain deferred.
