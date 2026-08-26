# Orchestration retry capability manifest v3

TaskCapabilityManifest v3 is an additive trusted-core-issued readiness prerequisite for
the exact attempt-two activation lineage. It binds one current `ready` validation task and
active plan revision to the immutable retry activation, attempt, and consumed retry-budget
identities that produced that readiness.

Issuance revalidates the activation receipt and its complete schedule, failure, checkpoint,
lease, worker, approval, policy, retry-policy, budget, safety, cancellation, and recovery
lineage in the same immediate transaction. The manifest expires no later than the active
policy or source retry schedule. A unique activation binding and immutable provenance
columns reject duplicate, forked, cross-attempt, or cross-task issuance. Byte-equivalent
replay succeeds only while every current security binding remains valid.

V1 and v2 manifests remain compatible and cannot claim v3 retry provenance. V3 is fixed to
`task_state: ready`, `authority: none`, `execution_enabled: false`, no delegation, one
validation agent, and the existing bounded HTTP GET proposal ceiling. Existing ActionIntent
conversion accepts only running-state manifests and therefore rejects v3; readiness cannot
be interpreted as permission to propose or perform an action.

Migration 0052 adds nullable retry-provenance columns to the existing immutable manifest
table. Existing rows remain unchanged. Application rollback disables v3 issuance while
retaining history; migration reversal is unsupported. No secret, credential, evidence,
prompt, provider/plugin data, target content, command, URL, path, raw token, network route,
worker assignment, or external effect is represented.

Retry-bound budget reservation, later lease acquisition and consumption, worker dispatch,
provider/plugin execution, completion, Master Orchestrator runtime integration, agents, and
UI remain deferred.

## Version 4 attempt-three readiness manifest

TaskCapabilityManifest v4 is a separate additive contract and table for the exact
attempt-three activation-v2 lineage. Trusted core accepts only a current activation v2
receipt, derives its schedule-v2, attempt-three, retry-policy, consumed-capacity,
approval, worker, fencing, and recovery bindings, and requires the resulting plan/task
revisions to remain exactly active/ready. V1–V3 rows and semantics are unchanged and
cannot satisfy v4 consumers.

The exact prior approval-consumption receipt may remain part of the bounded task-purpose
lineage only while current and unexpired; v4 issuance does not refresh or reinterpret
approval. Attempt-one and attempt-two manifests remain immutable history and cannot be
reused for attempt three.

V4 retains the existing closed validation proposal ceiling, `authority: none`,
`execution_enabled: false`, and no delegation. It is stored outside the running-manifest
lookup, so ready-state ActionIntent conversion denies. Migration 0065 is additive;
application rollback disables v4 issuance while retaining inert immutable history, and
migration reversal is unsupported. Budget reservation, leasing, transitions, dispatch,
provider/plugin execution, and external effects remain deferred.
