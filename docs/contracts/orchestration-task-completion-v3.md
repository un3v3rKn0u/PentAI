# Orchestration task completion v3 prerequisite

This additive boundary reserves a closed command and receipt shape for successful
completion of the exact current running attempt-three validation task. It also adds an
immutable completion ledger whose producer is storage-denied. No service can create a
completion receipt in this slice and no task or plan state changes.

The command binds the exact attempt-three activation, schedule, attempt, both retry
consumptions, capability manifest v4, task-budget reservation v4, approval when
required, worker/runtime, lease v3 and lease-consumption v3, policy, account version,
fencing token, recovery generation, and either the exact checkpoint-v3 head or the
complete explicit absence tuple. Attempt one, attempt two, attempt four, mixed versions,
partial checkpoint tuples, authority-shaped fields, and arbitrary result data are not
representable.

The future trusted consumer must derive and atomically revalidate every security field,
then store one immutable receipt before a version-exact storage predicate permits the
bound `running` to `succeeded` coordination transition. It must also define dependent
readiness and plan-state composition. The existing general plan-graph transition is
legacy coordination behavior and is not completion-v3 evidence.

The contracts contain no output, artifact, evidence, diagnostic, prompt, provider or
plugin response, target, command, path, URL, secret, token, or arbitrary payload. They
remain fixed to `authority: none` and `execution_enabled: false`. Completion does not
authorize execution, provider usage, dispatch, retry, queueing, notification, or an
external effect.

Migration 0077 is additive and preserves every existing table, record, transition, and
reader. Its deny-all producer trigger must remain until a later separately reviewed
consumer replaces it atomically with an exact completion-v3 predicate. Application
rollback disables the new contracts while leaving the empty inert table. Destructive
downgrade is unsupported. The inert table deliberately does not add a foreign key to
the versioned attempt table: exact cross-version attempt binding belongs in that future
consumer predicate, avoiding a SQLite parent-key compatibility regression.

Successful-completion production and consumption, `running → succeeded`, dependent
readiness, plan completion, provider-usage reconciliation, budget finalization, worker
dispatch, runtime composition, queue processing, operator workflows, providers/plugins,
UI, and Phase 2 exit demonstrations remain deferred.
