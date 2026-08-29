# Orchestration task attempt v1 and v2

This additive boundary registers immutable identity for the initial failed execution
attempt of one exact validation task. Registration accepts only a current, digest-
verified typed failure receipt created by the dedicated failure-consumption boundary.
Startup-recovery failure markers cannot satisfy this contract.

Attempt v1 is deliberately closed to `attempt_number: 1` and `attempt_state: failed`.
The receipt binds the assessment, plan/task revisions, agent, ready-bound manifest and
budget reservation, approval when applicable, lease consumption, worker identity,
lease/fencing/recovery generations, exact checkpoint head, typed failure identity and
digest, policy, and immutable attempt digest. One failure can produce only one attempt,
and one task can have only one v1 initial attempt. Atomic unique storage rejects forks;
byte-equivalent replay returns the existing receipt only while plan/task state remains
current.

The record fixes `authority` to `none` and `execution_enabled` to false. Registration
does not determine retry eligibility, consume retry capacity, create a later attempt,
reopen or transition a task, acquire a lease, assign/contact a worker, dispatch work,
invoke a provider/plugin, create an `ActionIntent`, approve policy, mint a grant, or
perform an external effect.

Migration 0046 is additive and immutable. Application rollback disables new attempt
registration while retaining history; migration reversal is unsupported. Scheduling,
activation, completion, dispatch, and runtime execution remain deferred.

A separate additive retry-attempt contract can now register immutable attempt number two
only after exact eligibility and retry-budget consumption. It does not change this initial
failed-attempt contract or create scheduling, task state, leasing, dispatch, or authority.

## Retry-bound failed-attempt v2

The additive v2 command registers the already-existing immutable attempt-two identity
as failed after exact typed failure consumption v2. It binds the retry activation,
attempt digest, consumed retry unit, v3 manifest and reservation, v2 lease consumption,
optional checkpoint-v2 head, closed failure class, worker, policy, fencing, and recovery
lineage. It cannot mutate the original retry-attempt receipt or allocate attempt three.

Migration 0058 introduces a separate immutable one-to-one failure-linkage table because
the attempt-two creation record is intentionally immutable in `registered` state. V1
original-attempt registration remains unchanged; mixed versions cannot satisfy v2.
Application rollback disables v2 production while retaining immutable history, and
migration reversal is unsupported. Further retry evaluation, scheduling, activation,
task reopening, completion, dispatch, and runtime execution remain deferred.

## Terminal failed-attempt v3

The additive v3 command links the already-existing attempt-three identity to the exact
current typed failure-consumption v3 receipt. Trusted core derives the closed failure
class and complete activation, schedule, retry-consumption, manifest-v4, reservation-v4,
approval, worker, lease-consumption-v3, checkpoint-v3, policy, fencing, and recovery
lineage from durable records. The task is already failed; registration performs no plan
or task transition.

Migration 0071 stores a separate immutable one-to-one projection because attempt-three's
creation receipt remains permanently `registered`. V1/v2 contracts and rows are unchanged
and cannot satisfy v3. The receipt records the retry-policy-v2 ceiling of three but does
not evaluate retryability, create attempt four, dead-letter work, mutate budget, dispatch,
or grant authority. Rollback disables new v3 registration while retaining history;
destructive migration reversal is unsupported.
