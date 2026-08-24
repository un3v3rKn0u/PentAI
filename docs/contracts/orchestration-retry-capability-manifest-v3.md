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
