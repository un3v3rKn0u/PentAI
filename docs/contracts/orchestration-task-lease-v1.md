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

Acquisition and state v2 are additive and bind one exact retry-ready attempt-two task to
its TaskCapabilityManifest v3, task-budget reservation v3, retry activation, immutable
attempt, and consumed retry-unit provenance. V1 remains closed to v2 manifest and budget
records. Original-attempt manifests, reservations, leases, worker ownership, and fencing
state cannot satisfy v2. The same durable worker registry remains the sole source of
worker identity and eligibility.

Acquisition and state v3 are separately versioned for the closed attempt-three lineage.
They accept only TaskCapabilityManifest v4, task-budget reservation v4, retry activation
v2, and attempt three under retry policy v2. Migration 0067 uses a separate immutable
table because the earlier lease table is closed to older manifest and reservation
versions. V3 shares the existing per-task fence, so lease generations and fencing tokens
remain monotonic across all attempts. V1 and v2 rows cannot satisfy v3.

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

V3 preserves one-time bearer handling: trusted core returns the raw token once, persists
only its SHA-256 digest, and denies acquisition replay rather than re-exposing secret
material. Recovery invalidates active v3 leases and advances the shared fence without
reconstructing tokens, changing task state, or contacting a worker. Renewal, consumption,
and the attempt-three `ready` to `running` transition were originally deferred from
acquisition and remain separate contracts.

Consumption v3 additively accepts only one exact current lease-v3 holder proof and the
same activation-v2, attempt-three, manifest-v4, reservation-v4, policy, approval, worker,
budget-account, fencing, and recovery lineage. Migration 0068 stores an immutable
version-exact receipt and permits only its exact `ready` to `running` coordination edge.
V1/v2 consumers and rows remain unchanged and cannot satisfy v3. The raw token is
verified transiently and is absent from the receipt, database, audit, and outbox.
Consumed acquisition rows remain immutable history; the unique consumption receipt is
the spent-lease projection and prevents recovery or reuse.

Migration 0054 adds nullable immutable retry-lineage fields and exact storage guards.
Existing v1 rows require no conversion. Application rollback disables v2 acquisition,
renewal, and release while retaining immutable history; migration reversal is unsupported.

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

Worker dispatch/contact, checkpoints, retries, completion consumption, Master
Orchestrator runtime, provider/plugin execution, UI, and effect-specific authorization
remain deferred.

Consumption v2 additively accepts only a current retry-bound v2 lease and exact v3
manifest/budget, activation, attempt-two, consumed-retry-unit, policy, worker, fencing,
and recovery lineage. V1 and mixed-version records remain incompatible. Migration 0055
adds nullable immutable consumption provenance and replaces the storage transition guard
with version-exact v1/v2 predicates; existing v1 rows require no conversion.

## Dedicated consumption

An additive consumption v1 command may atomically exchange one exact current lease for
the task's durable `running` coordination state. It revalidates every acquisition
binding, the one-time holder proof, lease-state digest, worker registry version, safety
state, and recovery fence. The immutable receipt and lease release are committed in the
same transaction as the plan/task revision change. The general transition service and
direct storage updates cannot perform `ready` to `running`.

Consumption is still non-executing: it does not contact or dispatch the registered
worker, debit provider usage, invoke a model or plugin, evaluate an ActionIntent, mint a
grant, create a gateway request, or contact a target. Checkpoints, retries, dispatch,
completion consumption, and runtime enforcement remain deferred.

The v3 path has the same non-executing separation. `running` is coordination state only;
worker contact/dispatch, checkpoints, failure/completion, provider/plugin calls, network
access, and effects remain later independently reviewed boundaries.

The v2 path provides the same atomic receipt, lease release, plan/task revision update,
and metadata-only audit/outbox guarantees for attempt two. The raw holder token is
verified transiently and is absent from receipts, storage, audit, and outbox payloads.
Rollback disables v2 consumption while retaining immutable history; migration reversal
is unsupported. Later retry checkpoints, failure/completion consumption, worker
dispatch/contact, and runtime execution remain deferred.
