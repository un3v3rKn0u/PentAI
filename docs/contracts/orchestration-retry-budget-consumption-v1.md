# Orchestration retry-budget consumption v1

This additive trusted-core boundary consumes exactly one already-reserved integer retry
unit for the exact eligible decision produced by the deterministic retry-policy service.
It is accounting only. The command cannot supply retryability, units, remaining capacity,
backoff, failure classification, or authority.

Consumption revalidates the immutable eligibility decision and its complete failed-
attempt, typed-failure, checkpoint, lease-consumption, worker, manifest, approval, active-
policy, retry-policy, safety, cancellation, budget, and recovery lineage. It accepts only
an `eligible` v1 decision after its deterministic earliest-retry time and before expiry.
Denied, stale, malformed, mixed-version, cross-bound, tampered, released, exhausted, or
version-fenced state denies with stable machine-readable codes.

Migration 0048 adds an immutable consumption sub-ledger. An immediate transaction checks
the caller's exact current assessment-budget account version, derives prior consumption
from ledger rows, appends one one-unit receipt, and advances the account version. Unique
decision, attempt, and task/next-attempt constraints prevent forks. Byte-equivalent replay
returns the existing result only while the resulting account version and all security
bindings remain current; changed replay or concurrent consumption denies.

The original reservation amount remains immutable. Consumed units are non-refundable and
cannot be transferred, restored, or interpreted as authority. Recovery can fence later use
but cannot invent, duplicate, replay, refund, activate, or silently consume a unit.

Commands and receipts fix `authority` to `none` and `execution_enabled` to false. This
boundary does not create attempt two, reopen or transition a task, acquire a lease, assign
or contact a worker, schedule or dispatch work, invoke a provider or plugin, create an
`ActionIntent`, approve policy, mint a grant, create a gateway request, contact a target,
or perform an external effect.

The contracts and migration are additive. Application rollback disables consumption while
retaining immutable history; migration reversal and refunds are unsupported. Stored data
is limited to bounded identifiers, hashes, closed values, integer counters/versions, and
timestamps. Secrets, evidence, prompts, diagnostics, URLs, paths, commands, provider/plugin
payloads, target content, and raw tokens are excluded. Scheduling, activation, task
reopening, later leases, dispatch, completion, and runtime execution remain deferred.

An additive dedicated contract can now register immutable, non-activating attempt-two
identity from one exact current consumption receipt. Registration does not refund or
consume another unit, schedule work, change task state, acquire a lease, or grant authority.
Scheduling and activation remain deferred.

## Version 2 attempt-three accounting

The additive v2 command accepts only an exact current eligible retry-decision v2 for
failed attempt two. It derives capacity exclusively from the original v1 consumption
receipt and its immutable reservation, while separately preserving the retry-bound v3
reservation as execution-resource lineage. A refreshed reservation cannot replenish or
reinterpret retry capacity.

Migration 0061 adds a separate immutable v2 sub-ledger. One immediate transaction
revalidates the complete v2 attempt, failure, checkpoint, lease, worker, approval,
manifest, policy, safety, cancellation, and recovery lineage; sums v1 and v2 consumption
against the original integer reservation; consumes exactly one remaining unit; and
advances the existing assessment budget-account version. Unique decision, attempt,
prior-consumption, and task/attempt constraints reject forks and duplicate consumption.

V1 contracts and rows remain unchanged. Application rollback disables v2 consumption
while retaining immutable non-refundable history. V2 creates no attempt three, schedule,
activation, task transition, manifest, reservation, lease, dispatch, network authority,
or external effect. Every command and receipt remains fixed to `authority: none` and
`execution_enabled: false`.
