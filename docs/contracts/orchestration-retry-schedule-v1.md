# Orchestration retry schedule v1

This additive boundary registers immutable timing metadata for the exact non-activating
attempt-two identity. Scheduling is an inert coordination record: it does not reopen the
failed task, activate the attempt, create runnable work, or grant authority.

The trusted-core command accepts only an exact digest-verified retry-attempt v1 receipt.
Registration revalidates its complete prior-attempt, typed-failure, checkpoint,
lease-consumption, worker, capability-manifest, approval, active-policy, retry-policy,
eligibility, retry-budget, safety, cancellation, and recovery lineage. The service derives
`scheduled_for` exclusively from the immutable attempt's `earliest_retry_at`; callers cannot
supply backoff, delay, wake time, priority, retryability, failure classification, task or
schedule state, worker assignment, budget, privilege, or authority.

Schedule v1 is closed to attempt number two, schedule revision one, and state `registered`.
The attempt must already be registered and the command cannot precede its registration or
deterministic earliest retry time. Unique attempt, retry-consumption, and task/revision
constraints reject duplicate schedules, forks, and competing branches. Byte-equivalent
replay returns the stored receipt only while every current security binding remains valid.

The receipt fixes `authority` to `none` and `execution_enabled` to false. Scheduling does
not transition the task or attempt, issue a manifest or reservation, acquire a lease,
assign/contact/dispatch a worker, invoke a provider or plugin, create or evaluate an
`ActionIntent`, mint an `ActionGrant`, create a gateway request, contact a target, create
network authority, or perform an external effect. Worker fields are failed-attempt lineage
only and do not assign the later attempt.

Migration 0050 is additive and makes schedule records immutable. Application rollback
disables registration while retaining history; migration reversal is unsupported. Stored
data is limited to bounded identifiers, hashes, closed enums, integer revisions, and
timestamps. Secrets, credentials, evidence, prompts, diagnostics, URLs, paths, commands,
provider/plugin payloads, target content, and raw tokens are excluded. Activation, task
reopening, later manifests/reservations/leases, dispatch, completion, and runtime execution
remain deferred.
