# Orchestration terminal consumption v1

This boundary defines the closed command and receipt contracts and the dedicated
trusted-core consumer of an exact attempt-three terminal-disposition v1 decision. The
storage guard accepts only the matching current `failed` task revision and the decision's digest-verified
`dead_letter_eligible` / `retry_ceiling_exhausted` result.

Migration 0074 now adds `dead_letter` to the authoritative
`orchestration_tasks.state` SQLite constraint through ADR 0006's verified reconstruction
protocol. Migration 0075 replaces only the deny-all consumption producer and task
version fence. A contract-valid, current receipt must be inserted before the exact
`failed → dead_letter` revision change can pass. Direct insertion of a dead-letter task,
the general transition service, and an unbacked update remain denied.

The consumer revalidates the complete current failure-v3 security lineage, inserts one
immutable receipt, advances only the task state/revision, and appends metadata-only
audit/outbox linkage in one immediate transaction. Plan state and revision remain
unchanged. Byte-equivalent replay validates the current security state and returns the
same receipt; changed or stale replay denies.

The receipt fixes queue and operator-review behavior to false and fixes
`authority: none` and `execution_enabled: false`. Task snapshot v2 is the version-safe
read boundary. Plan-graph v1 remains unchanged and fails closed when asked to serialize
a reachable dead-letter task. Queue insertion, notification, dispatch, provider/plugin
use, and every external effect remain out of scope.

Compatibility is additive for producers and historical v1/v2/v3 lineage. Older
plan-graph readers do not misinterpret the new state; they deny and must migrate to task
snapshot v2. Migration downgrade is unsupported after a dead-letter row exists because
the prior task constraint cannot represent it losslessly. Application rollback is safe
only before first consumption or after restoring a compatible application version.
