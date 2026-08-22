# Task capability manifest v1

## Boundary and ownership

`TaskCapabilityManifest v1` is an immutable, non-authoritative permission ceiling
issued only by the trusted core for one current Validation Agent task. It binds one
assessment, active signed policy, plan and revision, running task and revision, agent
identity, purpose, typed ActionIntent capability, limits, and short validity window.
Agents, models, plugins, workers, plans, tasks, and user interfaces cannot submit,
activate, edit, delegate, or broaden a manifest.

The initial manifest supports only `propose_supervised_http_validation` and
`network.http.get`. Wildcards, inheritance, delegation, commands, free-form flags,
secret or raw-evidence access, provider credentials, plugin permissions, and direct
network authority are unrepresentable. `authority` is `none` and
`execution_enabled` is false.

Version 2 adds an exact `task_state` binding and permits trusted-core issuance while a
validation task is `ready` or `running`. A ready-bound manifest is preparation metadata
for later budget and lease composition only; agent-to-ActionIntent conversion continues
to require a current running task and a running-bound manifest.

## Validation and cancellation composition

Issuance revalidates current assessment/global safety, the active signed policy, and
the exact active plan and running validation task in an immediate transaction. The
manifest cannot outlive the signed policy and has a maximum fifteen-minute lifetime.
Exact replay returns the same manifest; changed limit reuse of the deterministic
identity denies. First issuance appends a metadata-only hash-chained audit event and
outbox record; exact replay does not duplicate either record.

`AgentActionIntentRequest v2` references the exact manifest and revision. Conversion
again checks all assessment, policy, plan, task, agent, purpose, capability, limit,
revision, and expiry bindings. Plan/task cancellation, terminal state, recovery
fencing, policy replacement, or safety pause therefore denies new use immediately.
A pending ActionIntent remains non-authoritative and still requires fresh deterministic
policy evaluation, approval when required, budget enforcement, and ActionGrant minting.

## Compatibility, migration, rollback, privacy, and residual risk

Migration 0037 adds the immutable manifest table and nullable manifest provenance to
historical agent-intent links. Stored v1 links remain readable, but new conversion of
request v1 denies with `AGENT_INTENT_CAPABILITY_MANIFEST_REQUIRED`. Other ActionIntent
producers and ActionIntent v1 are unchanged. Application rollback disables new
issuance/conversion and retains immutable history; migration 0037 is not reversed.
Migration 0041 adds and immutably backfills `task_state=running`; rollback disables v2
issuance and retains the state binding. V1 remains running-only compatible.

Only bounded action metadata and opaque identifiers/digests are stored. No prompt,
secret, credential, evidence content, provider payload, or external effect is accepted.
Transport authentication of the agent and Master Orchestrator, generalized task types,
approval/budget runtime composition, leases, dispatch, and execution remain deferred.
