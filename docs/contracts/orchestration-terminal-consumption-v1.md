# Orchestration terminal consumption v1 prerequisite

This additive prerequisite defines the closed command and receipt contracts and the
immutable persistence boundary needed by a later trusted-core consumer of an exact
attempt-three terminal-disposition v1 decision. The storage guard accepts only the
matching current `failed` task revision and the decision's digest-verified
`dead_letter_eligible` / `retry_ceiling_exhausted` result.

The table has an explicit deny-all insert trigger: no caller, including one that can
construct a contract-valid row, can turn the prerequisite into a consumption result.
The existing `orchestration_tasks.state` SQLite constraint does not contain
`dead_letter`. Safely widening it would require reconstruction of a table referenced by
many immutable security-lineage tables. The current migration policy and runner do not
define or verify that reconstruction. This slice therefore does not insert consumption
rows, revise a task, or claim that the `failed → dead_letter` transition exists.

The receipt contract fixes queue and operator-review behavior to false and fixes
`authority: none` and `execution_enabled: false`. A future slice must either establish a
reviewed, data/trigger/foreign-key-preserving task-table migration protocol or adopt an
equally authoritative versioned task-state representation, then implement the atomic
consumer, audit/outbox linkage, replay validation, and exact storage-enforced state
change. Queue insertion, notification, dispatch, provider/plugin use, and every external
effect remain out of scope.

Compatibility is additive: existing plan/task v1 contracts, task rows, transitions, and
historical retry/failure/terminal records are unchanged. Rollback before use removes
only the empty additive table and contracts; migration downgrade after data exists is
unsupported.
