# Agent action-intent request v1 and v2

## Boundary

This contract converts one untrusted Validation Agent proposal for a bounded HTTP GET
into the existing immutable `ActionIntent v1`. The result is pending deterministic
policy evaluation. Conversion does not evaluate, approve, grant, dispatch, connect, or
execute anything.

Request v2 additionally requires a trusted-core-issued `TaskCapabilityManifest v1`
and binds one assessment, active signed policy, plan and revision, running
validation task and revision, exact agent identity, purpose, input digest, action
digest, and five-minute validity window. The action is a closed typed object: GET only,
no body, no redirects, bounded deadline and response size, and a canonical target.
Arbitrary commands, free-form flags, delegation, secret values, provider credentials,
raw evidence, caller authority, and unsupported operations are unrepresentable.

## Validation, provenance, and authority

The trusted core verifies the action digest and canonical target, then revalidates the
current signed policy, assessment/global safety, assessment expiry, active plan, exact
revisions, running task, and the exact immutable capability manifest in one
immediate transaction before persistence. Plans, task state, agent assertions, and
model content cannot broaden the request.

Migrations 0036 and 0037 immutably link the request digest, manifest identity, and
all plan/task/agent/policy provenance to the ActionIntent. Exact replay returns the
same intent only while every safety and revision binding remains current; changed
identity reuse denies. The transaction also appends a hash-chained
audit event and outbox record containing metadata only. `authority` is `none` and
`execution_enabled` is false. No `PolicyDecision` or `ActionGrant` is created.

## Compatibility, migration, rollback, privacy, and residual risk

Request v1 is retained as a historical contract but new conversion fails closed with
`AGENT_INTENT_CAPABILITY_MANIFEST_REQUIRED`; v2 is the supported conversion contract.
`ActionIntent v1` and existing human/service producers remain compatible. Application
rollback disables conversion while retaining immutable intent, provenance, and audit
history; migrations 0036 and 0037 are not reversed.

Only typed action metadata and opaque digests/references are stored. Input content,
secrets, evidence, prompts, credentials, and provider payloads are neither accepted nor
logged. The input digest is provenance supplied by a future context builder; this
slice cannot attest the absent source artifact.

Agent runtime authentication, Master Orchestrator authorship, generalized capability
manifests, human approval, budget composition, provider/model execution,
and end-to-end intent evaluation remain deferred. The broader action-plan requirement
remains open.
