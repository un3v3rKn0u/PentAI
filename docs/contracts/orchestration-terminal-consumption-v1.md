# Orchestration terminal consumption v1 prerequisite

This additive prerequisite defines the closed command and receipt contracts and the
immutable persistence boundary needed by a later trusted-core consumer of an exact
attempt-three terminal-disposition v1 decision. The storage guard accepts only the
matching current `failed` task revision and the decision's digest-verified
`dead_letter_eligible` / `retry_ceiling_exhausted` result.

The table has an explicit deny-all insert trigger: no caller, including one that can
construct a contract-valid row, can turn the prerequisite into a consumption result.
Migration 0074 now adds `dead_letter` to the authoritative
`orchestration_tasks.state` SQLite constraint through ADR 0006's verified reconstruction
protocol. It also denies direct `dead_letter` inserts, while the unchanged version fence
continues to deny `failed → dead_letter`. The plan-graph v1 contract remains unchanged:
it is the immutable creation/current-snapshot contract, and no reachable runtime row can
yet contain the new state. Before a trusted consumer makes the state reachable, the
runtime read boundary uses the additive task-snapshot v2 contract rather than silently
widening v1. This prerequisite still cannot insert consumption rows, revise a task, or
claim that the transition exists.

The receipt contract fixes queue and operator-review behavior to false and fixes
`authority: none` and `execution_enabled: false`. Task-snapshot v2 now provides the
additive runtime read contract. A future slice must implement the atomic consumer,
audit/outbox linkage, replay validation, and exact storage-enforced state change. Queue insertion,
notification, dispatch, provider/plugin use, and every external effect remain out of
scope.

Compatibility is additive: existing plan/task v1 contracts, task rows, transitions, and
historical retry/failure/terminal records are unchanged. Older readers remain compatible
because guards keep `dead_letter` unreachable. Migration downgrade is unsupported after
a later consumer creates such rows; application rollback before that point remains safe.
