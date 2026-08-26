# Orchestration retry attempt v1

This additive boundary registers immutable historical identity for attempt two after an
exact eligible retry decision has consumed one reserved retry unit. It is deliberately
separate from the initial failed-attempt contract, which remains closed to attempt number
one and the typed-failure lineage.

The trusted-core command accepts only the exact immutable retry-budget consumption receipt
and derives attempt number two as prior attempt number plus one. Registration revalidates
the current failed task and complete prior-attempt, failure, checkpoint, lease-consumption,
worker, manifest, approval, active-policy, retry-policy, eligibility, budget, safety,
cancellation, and recovery lineage. The consumption receipt must prove one consumed unit
for proposed attempt two, and registration cannot precede either consumption or the
deterministic earliest-retry time.

Attempt v1 is closed to `attempt_number: 2` and `attempt_state: registered`. Callers cannot
provide state, retryability, backoff, schedule time, priority, worker assignment, budget
amounts, or authority. Unique prior-attempt, consumption-receipt, and task/attempt-number
constraints reject gaps, forks, competing registrations, and reuse. Byte-equivalent replay
returns the stored record only while every security binding remains current.

The receipt fixes `authority` to `none` and `execution_enabled` to false. Registration does
not reopen or transition the task, schedule or activate the attempt, acquire a lease,
assign/contact a worker, dispatch work, invoke a provider/plugin, create an `ActionIntent`,
approve policy, mint a grant, create a gateway request, contact a target, or perform an
external effect. The copied worker and execution-lineage identifiers describe the failed
prior attempt only and are not an assignment for attempt two.

Migration 0049 is additive and makes retry-attempt records immutable. Application rollback
disables registration while retaining history; migration reversal is unsupported. Stored
data is bounded identifiers, hashes, closed enums, integer versions/numbers, and timestamps.
Secrets, evidence, prompts, diagnostics, URLs, paths, commands, provider/plugin payloads,
target content, and raw tokens are excluded. Scheduling, activation, task reopening, later
leases, dispatch, completion, and runtime execution remain deferred.

An additive retry-schedule v1 boundary can now register immutable timing metadata for this
exact attempt by deriving `scheduled_for` from its stored earliest-retry value. The schedule
remains inert and cannot reopen the task, activate the attempt, issue prerequisites, acquire
a lease, dispatch work, or create authority.

## Version 2 attempt-three identity

The additive v2 command accepts only the exact current retry-budget-consumption v2
receipt for failed attempt two. Trusted core revalidates the complete assessment,
policy, retry-policy, plan/task, failure, checkpoint, lease, worker, approval, manifest,
budget, safety, cancellation, fencing, and recovery lineage before deriving attempt
number three. The command cannot select identity, numbering, state, capacity, timing,
worker ownership, privilege, or authority.

Migration 0062 uses a separate immutable table so v1 remains closed to attempt two.
Unique predecessor, consumption, and task/attempt constraints plus an exact storage
predicate prevent gaps, rollback, duplicate numbering, forks, cross-scope reuse, and
direct insertion. Exact replay returns the existing receipt only while all current
security bindings remain valid.

Attempt three is `registered`, `authority: none`, and `execution_enabled: false`. It is
the identity at the retry-policy v2 ceiling of three total attempts; this contract cannot
create attempt four. Registration changes no task or budget state and creates no
schedule, activation, manifest, reservation, lease, checkpoint, worker assignment,
dispatch, provider/plugin call, network authority, or external effect. Application
rollback disables v2 registration while retaining immutable history; migration reversal
is unsupported. Scheduling, activation, refreshed readiness prerequisites, later
leasing, terminal/dead-letter behavior, completion, dispatch, and runtime composition
remain deferred.
