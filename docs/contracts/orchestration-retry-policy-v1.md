# Orchestration retry policy and eligibility v1

This additive boundary lets trusted core issue one closed retry policy for an exact
assessment and active policy bundle, then derive an immutable eligibility decision for
the initial failed orchestration attempt. The policy fixes the supported validation task,
attempt and failure contract versions, three-attempt ceiling, closed transient failure
classes, and integer-second backoff schedule. Callers cannot supply or expand those
semantics.

Evaluation accepts only the current digest-verified failed-attempt receipt and revalidates
its typed-failure, checkpoint, lease-consumption, worker, manifest, budget, approval,
policy, safety, cancellation, and recovery lineage. Eligibility and earliest retry time
are derived deterministically. Unknown fields, mixed versions, stale or cross-scope
bindings, changed replay, concurrent forks, replaced policy, ineligible failure classes,
or unavailable retry capacity deny with stable codes.

The policy and decision fix `authority` to `none` and `execution_enabled` to false. A
decision does not consume retry capacity, create attempt two, reopen or transition a
task, acquire a lease, assign or contact a worker, dispatch work, invoke a provider or
plugin, create an `ActionIntent`, approve policy, mint a grant, or perform an external
effect. Existing Phase 1 authorization remains unchanged.

Migration 0047 is additive and makes policy and decision rows immutable. Exact replay
returns the stored decision only while its security bindings remain current. Application
rollback disables issuance and evaluation while retaining immutable audit history;
migration reversal is unsupported. Stored values are bounded identifiers, hashes,
closed enums, integer counters/backoff, versions, and timestamps—never diagnostics,
evidence, prompts, URLs, paths, credentials, secrets, raw lease tokens, provider/plugin
payloads, or target content.

An additive dedicated boundary can now consume exactly one reserved retry unit for an
exact current eligible decision using an immutable sub-ledger and assessment-account
version fence. Consumption remains non-activating and non-authoritative. Later-attempt
identity, scheduling/activation, task reopening, leases for a later attempt, dispatch,
completion, and runtime execution remain deferred.

## Retry-bound policy v2 prerequisite

Retry policy v1 is intentionally closed to failure and attempt contract v1 and cannot
govern the failed attempt-two receipt. An additive policy v2 contract therefore binds
the same trusted-core three-attempt ceiling, closed transient failure classes, and
integer backoff schedule to failure and attempt contract v2. V1 issuance and stored
rows remain unchanged.

Policy v2 issuance performs no eligibility evaluation, capacity read or mutation,
attempt creation, scheduling, task transition, lease operation, worker contact,
provider/plugin invocation, or external effect. Migration 0059 stores v2 policies in
a separate immutable table. Application rollback disables v2 issuance while retaining
history; migration reversal is unsupported. Attempt-two eligibility remains deferred
to a separately reviewed version-exact evaluation boundary.

That version-exact evaluation boundary now accepts only the immutable failed-attempt
v2 receipt and retry policy v2. It derives attempt two to proposed attempt three,
applies the second deterministic backoff, and checks remaining capacity only through
the immutable prior consumption receipt. The decision is metadata-only, immutable,
and non-authoritative. It consumes no capacity and creates, schedules, activates, or
transitions no work.

Migration 0060 adds a separate immutable v2 decision table because v1 decisions remain
closed to attempt one to two. Existing policy and decision rows require no conversion.
Application rollback disables v2 evaluation while retaining history; migration reversal
is unsupported. Retry-budget consumption for attempt three and terminal dead-letter
state changes remain separately reviewed deferred boundaries.
