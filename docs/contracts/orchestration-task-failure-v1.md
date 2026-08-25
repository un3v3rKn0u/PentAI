# Orchestration task failure v1 and v2

This additive boundary consumes one closed failure classification for an exact current
`running` validation task. The command binds the active policy, plan/task revisions,
ready-bound manifest and budget, approval when applicable, lease-consumption receipt,
trusted worker identity, lease/fencing/recovery generations, and the exact current
checkpoint head (or the explicit absence of checkpoints).

Only `checkpoint_stalled`, `coordination_timeout`, `runtime_unavailable`, and
`worker_process_failed` are accepted. Free-form diagnostics, exceptions, stack traces,
provider or target responses, evidence, paths, URLs, commands, flags, secrets, and raw
lease tokens are excluded. The closed class is historical input to a future trusted
retry policy; it does not assert or imply retry eligibility.

The trusted core atomically stores an immutable receipt, advances only
`running` to `failed`, increments exact plan/task revisions, and appends metadata-only
audit/outbox linkage. The general transition service and direct storage writes cannot
perform this edge. Startup recovery uses a separate immutable recovery-failure marker
so it remains fail-closed without fabricating a worker-reported failure receipt.

Every record fixes `authority` to `none` and `execution_enabled` to false. Failure
consumption cannot reopen a task, schedule or consume a retry, create an attempt,
acquire a lease, dispatch/contact a worker, invoke a provider/plugin, create an
`ActionIntent`, approve policy, mint a grant, or perform an external effect.

Migration 0045 is additive and retains immutable history. Application rollback disables
new failure consumption; it must not restore the former general `running` to `failed`
edge. Migration reversal is unsupported. Typed attempt identity, deterministic retry
eligibility, retry-budget consumption, retry scheduling/activation, completion
consumption, dispatch, and runtime execution remain deferred.

## Retry-bound v2 compatibility

Failure command and receipt v2 extend the same closed semantics to the exact running
attempt-two lineage. The trusted core additionally binds retry activation and attempt
digests, the consumed retry unit, TaskCapabilityManifest v3 and its digest, task-budget
reservation v3 and its request digest, lease-consumption v2, and either the exact
checkpoint-v2 head or the explicit all-null absence tuple. V1 records remain valid for
original-attempt tasks but cannot satisfy v2; mixed versions deny.

Migration 0057 adds nullable retry-lineage columns and exact v2 insertion predicates to
the existing immutable ledger. Existing rows require no conversion. Rollback disables
v2 production while retaining its historical rows; reversing the migration is
unsupported. Attempt-two failure remains non-authoritative and does not evaluate a
further retry, consume retry capacity, create attempt three, reopen work, dispatch, or
perform an external effect.
