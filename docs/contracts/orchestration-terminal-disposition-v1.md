# Orchestration terminal disposition v1

This additive boundary records one immutable terminal disposition for the exact current
failed-attempt v3 receipt at the retry-policy-v2 ceiling of three attempts. Trusted core
revalidates the complete attempt-three failure, checkpoint, lease, worker, readiness,
retry-consumption, policy, cancellation, safety, budget-account, fencing, and recovery
lineage before deriving `dead_letter_eligible` with reason
`retry_ceiling_exhausted`.

The result means only that a later independently reviewed boundary may consider the
failed task for dead-letter transition. It does not change plan or task state, insert or
consume a queue item, create operator-review work, notify anyone, retry, dispatch, or
perform an effect. Transition, queue, and operator-review flags are fixed to false;
`authority` is `none` and `execution_enabled` is false.

The repository currently defines no authoritative operator-review mapping for terminal
or security failures. Failure v3 accepts only four closed coordination/runtime classes;
cancellation, safety, policy, authorization, privacy, secret-access, integrity, worker-
revocation, and recovery-fenced states cannot be substituted into this decision. No
caller may select the disposition, reason, queue, review behavior, or authority.

Migration 0072 adds a separate immutable one-to-one ledger. Existing retry-decision and
failed-attempt v1/v2 contracts remain unchanged and cannot satisfy this boundary.
Application rollback disables new decisions while retaining history; destructive
migration reversal is unsupported. A dead-letter state transition, durable queue, and
operator workflow remain separately reviewed deferred capabilities.
