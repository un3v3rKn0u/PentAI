# Orchestration task completion v3

This additive boundary consumes successful completion of the exact current running
attempt-three validation task. One trusted-core operation validates the closed command,
stores an immutable receipt, transitions only the bound task to `succeeded`, recomputes
dependent readiness, and derives plan state in one immediate transaction.

The command binds the exact attempt-three activation, schedule, attempt, both retry
consumptions, capability manifest v4, task-budget reservation v4, approval when
required, worker/runtime, lease v3 and lease-consumption v3, policy, account version,
fencing token, recovery generation, and either the exact checkpoint-v3 head or the
complete explicit absence tuple. Attempt one, attempt two, attempt four, mixed versions,
partial checkpoint tuples, authority-shaped fields, and arbitrary result data are not
representable.

The trusted consumer derives and atomically revalidates every security field. Migration
0078 replaces the deny-all producer with an exact current-lineage predicate, and a
separate task trigger requires that immutable receipt for attempt-three
`running → succeeded`. The general plan-graph transition remains compatible for earlier
attempts but denies attempt three. Success follows existing graph semantics: successors
become ready or awaiting approval only when all required predecessors succeed, and the
plan becomes completed only when every task succeeds.

The contracts contain no output, artifact, evidence, diagnostic, prompt, provider or
plugin response, target, command, path, URL, secret, token, or arbitrary payload. They
remain fixed to `authority: none` and `execution_enabled: false`. Completion does not
authorize execution, provider usage, dispatch, retry, queueing, notification, or an
external effect.

Migrations 0077 and 0078 are additive and preserve every existing table, record, and
reader. Earlier-attempt success behavior remains unchanged. Exact cross-version attempt
binding is enforced by trusted core and the storage predicate rather than an unsafe
SQLite parent-key foreign key. Application rollback disables new consumption while
retaining immutable receipts and the storage success fence; destructive downgrade is
unsupported.

Provider-usage reconciliation, budget finalization, worker dispatch, runtime
composition, evidence/findings/reporting, queue processing, operator workflows,
providers/plugins, UI, and Phase 2 exit demonstrations remain deferred.
