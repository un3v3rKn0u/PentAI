# Phase 2 slice security reviews

## 2026-08-23 — Deterministic orchestration retry policy and eligibility v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed policy, evaluation-command, and decision contracts;
migration 0047; deterministic trusted-core service; immutable audit/outbox linkage; and
synthetic positive, malformed, closed-class, replay, concurrency, policy-expiry,
cross-binding, safety, worker, budget, recovery, storage-tampering, integer-boundary,
and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core alone fixes retry
semantics and revalidates the exact immutable attempt/failure/checkpoint/lease, policy,
safety, manifest, budget, approval, worker, and recovery lineage. No provider, plugin,
worker, gateway, target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Caller-controlled retryability, backoff, or next-attempt
fields; wildcard or altered policy; mixed versions; stale/cross-scope lineage; digest
substitution; changed replay; concurrent decisions; cancellation/safety pause;
policy/worker/budget/recovery replacement; authority-shaped input; and storage mutation
deny with stable codes. Security and unlisted failure classes cannot be relabeled as
transient.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable tables leave Phase 1 and existing orchestration consumers unchanged. Rollback
disables new issuance/evaluation and retains history; migration reversal is unsupported.
Stored data is bounded identifiers, hashes, enums, integer counters/backoff, versions,
and timestamps—never diagnostics, evidence, prompts, paths, URLs, commands, credentials,
secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Eligibility checks existing retry capacity but does
not consume it. It cannot create attempt two, reopen tasks, acquire leases, schedule or
dispatch work, contact workers, or execute providers/plugins. Retry-budget consumption,
activation, later-attempt lifecycle, completion, Master Orchestrator/UI integration, and
effect-specific authorization remain deferred. Non-independent review reduces governance
assurance and is accepted only for this non-executing slice.

## 2026-08-23 — Immutable orchestration failed-attempt identity v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0046, deterministic
attempt-registration service, immutable audit/outbox linkage, and synthetic positive,
malformed, numbering, replay, concurrency, failure/checkpoint binding, cross-scope,
safety, worker, budget, recovery-marker, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates the exact
typed failure receipt and current policy, safety, failed task, manifest, budget,
approval, lease consumption, worker, fencing/recovery, and checkpoint lineage. No
provider, plugin, worker, gateway, target, secret, evidence, or network boundary is
crossed.

**Threat/default-deny review:** Missing typed failure, recovery-marker substitution,
unknown/free-form fields, attempt numbers other than one, stale/cross-scope bindings,
failure/checkpoint digest substitution, changed replay, concurrent forks, safety pause,
policy/worker/budget/recovery replacement, authority-shaped input, and storage mutation
deny with stable codes. Attempt identity cannot assert retryability or create authority.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table; existing Phase 1 workflow attempts and orchestration state are
unchanged. Rollback disables production and retains history; migration reversal is
unsupported. Stored data is bounded identifiers, hashes, closed state, integer attempt
number, versions, and timestamps—never diagnostics, evidence, prompts, paths, URLs,
commands, credentials, secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** This slice registers only the initial failed attempt.
It does not define retry policy, decide eligibility, consume retry capacity, create or
activate a later attempt, reopen tasks, acquire leases, dispatch/contact workers, or
execute providers/plugins. Those boundaries and Master Orchestrator/UI integration
remain deferred. Non-independent review reduces governance assurance and is accepted
only for this non-executing slice.

## 2026-08-22 — Dedicated typed orchestration failure consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0045, deterministic
failure-consumption service, dedicated storage predicate, immutable recovery markers,
audit/outbox linkage, and synthetic positive, malformed, closed-class, replay,
concurrency, checkpoint-lineage, cross-binding, safety, recovery, immutability, and
non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates current
policy, safety, running task, manifest, budget, approval, lease consumption, worker,
fence, recovery generation, and checkpoint head. No provider, plugin, worker, gateway,
target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Unknown or free-form failure data, malformed input,
stale/cross-scope bindings, ambiguous or stale checkpoint lineage, changed replay,
concurrent consumption, cancellation, safety pause, policy/worker/recovery replacement,
direct storage mutation, and general transition attempts deny with stable codes. A
failure class cannot assert retryability or create authority.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable tables; migration 0045 intentionally closes general `running` to `failed`
while preserving explicit startup recovery through immutable recovery markers.
Rollback disables production and retains history; it must not reopen the closed edge,
and migration reversal is unsupported. Stored data is bounded identifiers, hashes,
closed classes, versions, and timestamps—never diagnostics, evidence, prompts, paths,
URLs, commands, credentials, secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Failure consumption does not create immutable attempt
identity, determine retry eligibility, consume retry budget, schedule/activate retries,
reopen tasks, complete tasks, dispatch/contact workers, or execute providers/plugins.
Those boundaries and Master Orchestrator/UI integration remain deferred. The
non-independent review reduces governance assurance and is accepted only for this
non-executing slice.

## 2026-08-22 — Durable metadata-only orchestration checkpoints v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, Execution Safety Lead, and Security Reviewer. This does not satisfy
independent review or dual control.

**Scope and evidence:** Closed command/receipt contracts, migration 0044, deterministic
checkpoint service, immutable audit/outbox linkage, and synthetic positive, malformed,
replay, conflict, sequence, predecessor, progress rollback, concurrency, cross-worker,
safety, recovery-fencing, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-DATA-005`, and `INV-REL-001` through `INV-REL-003`. Trusted core
revalidates durable policy, safety, running task, prerequisite, consumption, worker, and
fencing records without contacting any external component.

**Threat/default-deny review:** Unknown/malformed, stale, cross-scope, expired,
authority-shaped, sequence-gapped, forked, predecessor-mismatched, progress-decreasing,
concurrent, worker-revoked, safety-paused, cancelled/terminal, and recovery-stale input
denies with stable codes. Checkpoints cannot alter state or authorize an effect.

**Compatibility, privacy, migration, and rollback:** Additive schemas/service/table;
Phase 1 workflow checkpoints remain unchanged. Rollback disables production and retains
immutable history; migration reversal is unsupported. Only bounded identifiers, hashes,
integer progress, closed status, and timestamps are stored. Artifact references, raw
evidence, prompts, paths, URLs, commands, credentials, secrets, tokens, provider/plugin
content, and targets are excluded.

**Limitations and residual risk:** Artifact references, retries, completion, resume,
dispatch, worker contact, Master Orchestrator runtime, UI, provider/plugin execution,
and effect-specific authorization remain deferred. Non-independent review reduces
governance assurance and is accepted only for this non-executing slice.

## 2026-08-22 — Dedicated orchestration lease consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Closed command/receipt contracts, migration 0043, atomic
lease-consumption service, storage-gated readiness transition, closure of the general
transition edge, immutable receipt/audit/outbox linkage, and synthetic positive,
malformed, token, digest, cross-binding, replay, concurrency, direct-storage,
cancellation, safety, worker-fencing, expiry, recovery, and non-authority tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core consumes an existing
lease after revalidating its exact assessment, policy, plan/task, manifest, budget,
approval, worker, token digest, lease state, and recovery bindings. No provider, model,
plugin, worker, gateway, target, secret, or network boundary is crossed.

**Threat/default-deny review:** General or direct-storage starts, malformed and unknown
contracts, wrong token, tampered state digest, cross-scope substitution, stale plan,
task, worker, lease, fence, or recovery versions, expired/released/recovered leases,
safety pause, cancellation, conflicting replay, concurrent consumption, delegation,
inheritance, wildcard, and authority-shaped input deny with stable codes. Exact replay
returns only the immutable receipt and never repeats the transition or exposes a token.

**Compatibility, privacy, migration, and rollback:** Migration 0043 additively stores
immutable receipts and replaces the transition trigger with the previous rules plus one
exact receipt-backed predicate. Existing running and terminal history remains readable;
general new starts are intentionally closed. Application rollback cannot reopen the
storage edge and retains security history; migration reversal is unsupported. Stored
data is bounded metadata and hashes—never raw tokens, credentials, secrets, evidence,
prompts, provider payloads, targets, or assessment content.

**Limitations and residual risk:** `running` remains coordination state only. Worker
dispatch/contact, checkpoints, retries, completion consumption, Master Orchestrator
runtime, UI, provider/plugin execution, and effect-specific authorization remain
deferred. Non-independent review reduces governance assurance and is accepted only for
this non-executing slice.

## 2026-08-22 — Durable orchestration task leases and worker fencing v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Four closed lease contracts, migration 0042, deterministic
acquire/renew/release/recovery service, one-time raw-token handling, monotonic task
generations/fencing tokens, immutable lifecycle/audit/outbox records, and synthetic
positive, malformed, replay, token, revision, concurrency, worker-revocation, safety,
recovery, storage-tampering, and non-authority tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core reads an existing
durable worker-registry identity and exact current readiness prerequisites. It does not
contact or launch that runtime. Models, agents, workers, plugins, UI, retrieved content,
and request bodies cannot assert eligibility, inherit authority, or alter fencing.

**Threat/default-deny review:** Unsupported versions, v1/mixed prerequisites, malformed
or duplicate commands, cross-scope bindings, expired or replaced policy/prerequisites,
cancelled or non-ready tasks, safety pause, worker ineligibility, token mismatch, stale
revision/generation/fence, conflicting replay, concurrent acquisition, and recovery-
stale state deny with stable codes. Only a token digest is persisted; the raw token is
returned once and is absent from audit/outbox data.

**Compatibility, privacy, migration, and rollback:** The contracts, service, and
migration are additive and do not alter the separate Phase 1 workflow lease. Application
rollback disables orchestration lease operations while retaining immutable history;
migration reversal is unsupported. Stored data is bounded metadata, hashes, versions,
state, and timestamps—never credentials, secrets, evidence, prompts, targets, provider
payloads, or raw lease tokens.

**Limitations and residual risk:** A registered `running` worker is used only as durable
identity; no live liveness proof or contact occurs. Dispatch, task-running transition,
checkpoints, retries, completion, Master Orchestrator runtime, UI, provider/plugin
execution, and effect-specific authorization remain deferred. Non-independent review
reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-22 — Orchestration readiness-bound manifest and budget v2

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Closed v2 capability-manifest and budget request/receipt schemas,
migration 0041 immutable task-state bindings, deterministic ready-state validation,
v1 compatibility, and synthetic positive, malformed, unsupported-state, state mismatch,
replay, concurrency, recovery, cancellation, tampering, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-GRANT-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and
`INV-REL-001`. Trusted core may issue preparation metadata for an exact ready task.
Agents, models, plugins, workers, UI, retrieved content, and request bodies cannot alter
state, issue authority, or use a ready-bound manifest to create an ActionIntent.

**Threat/default-deny review:** Missing/unknown versions or task state, blocked or
terminal state, revision mismatch, state-changing replay, policy/safety/manifest/account
expiry, cross-scope identity, changed request reuse, oversubscription, malformed integer
units, tampered receipts, cancellation, and recovery-stale state deny with stable codes.
No lease, dispatch, worker assignment, grant, provider call, gateway request, or network
effect is introduced.

**Compatibility, privacy, migration, and rollback:** V1 remains running-only. Migration
0041 additively backfills immutable `task_state=running` for historical manifests and
reservations. Application rollback disables v2 production while retaining security
history; reversing the migration is unsupported. Only bounded identifiers, hashes,
integer amounts, timestamps, and state are stored—no secrets, evidence, prompts,
credentials, provider payloads, targets, or raw lease tokens.

**Limitations and residual risk:** Durable leases and worker fencing remain blocked on
this prerequisite’s merge. Checkpoints, retries, dispatch, Master Orchestrator runtime,
UI, provider/plugin execution, and effect-specific authorization remain deferred.
Non-independent review reduces governance assurance and is accepted only for this
local-development, non-executing slice.

## 2026-08-22 — Authenticated orchestration approval consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy independent review or dual control.

**Scope and evidence:** Closed receipt schema, migration 0040, dedicated authenticated
API/service operation, exact storage predicate, atomic state/receipt/audit/outbox writes,
and synthetic positive, malformed, legacy-version, digest, signature, actor/session,
expiry, replay, concurrency, immutability, direct-transition, cancellation, and
recovery-stale tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-AUTH-005`, `INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`,
`INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`. The authenticated local principal
and process session cross into trusted core; only verified v2 request/decision records
can satisfy the exact readiness predicate. No model, agent, plugin, worker, gateway,
target, secret, or network boundary is trusted or crossed.

**Threat/default-deny review:** Missing authentication, v1/mixed versions, rejection,
invalid signatures or digests, caller identity, cross-scope/principal/session reuse,
expiry, cancellation, safety pause, policy or revision replacement, conflicting replay,
direct general transitions, direct storage writes without a receipt, and stale recovery
deny. Consumption changes coordination readiness only and creates no policy decision,
grant, dispatch, budget debit, network route, or external effect.

**Compatibility, privacy, migration, and rollback:** The schema, route, service method,
and receipt table are additive. Migration 0040 replaces the task transition trigger with
its prior rules plus one exact receipt-backed predicate. Rollback disables the route and
retains immutable receipts and state history; migration reversal is unsupported. Stored
data is bounded identity, provenance, hashes, revisions, and timestamps; credentials,
prompts, evidence, secrets, providers, and targets are absent.

**Limitations and residual risk:** One local desktop principal remains the identity
model. Leases, checkpoints, dispatch, UI, provider/plugin execution, and effect-specific
policy approval remain deferred. Non-independent review reduces governance assurance and
is accepted only for this local-development, non-executing slice.

## 2026-08-21 — Authenticated orchestration approval API v2

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, Desktop Maintainer, and Security Reviewer. The `GIT_WORKFLOW.md` exception
is used and does not satisfy independent review or dual control.

**Scope and evidence:** Additive closed request/decision v2 schemas, two narrowly typed
authenticated local-core routes, server-derived principal and per-process session
composition, v1/v2 replay
separation, synthetic authenticated/unauthenticated/forged-identity/confirmation/
changed-principal/stale-state tests, compatibility documentation, complete diff,
quality checks, and repository scans. No migration is required.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-AUTH-005`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, and `INV-REL-001`; the existing bearer middleware authenticates before
body parsing, installs the local human principal, and the route passes only that
server-derived identity into the approval service. No caller identity, model, agent,
plugin, worker, tool, gateway, target, secret, or network boundary is trusted.

**Threat/default-deny review:** Missing or malformed credentials deny uniformly before
routing. Closed bodies reject actor, requester, role, authentication-context,
delegation, proxy, wildcard, and batch claims. Missing/false confirmation, changed
principal or session, v1/v2 mixing, malformed or unsupported data, stale policy/plan/task state,
expiry, cancellation, terminal state, changed replay, signature/content tampering, and
signer failure deny with stable codes. Approval remains non-authoritative and cannot
move a task out of `awaiting_human`.

**Compatibility, privacy, migration, and rollback:** V2 schemas and routes are
additive; v1 records remain readable and trusted-internal v1 production remains
compatible, while mixed-version use denies. Existing tables already store immutable
canonical documents, so no database migration is needed. Only the fixed local actor,
random per-process session UUID, and bounded approval metadata are added; credentials, prompts, evidence,
targets, secrets, and provider payloads are absent. Rollback removes the routes and v2
production while preserving immutable history.

**Limitations and residual risk:** The current launch credential maps to one local
desktop actor rather than multiple human accounts or OS-backed user identity; process
sessions are separately fenced.
Approval consumption, UI, leases, checkpoints, dispatch, provider execution, and
effect-specific policy approval remain deferred. Non-independent review reduces
governance assurance and is accepted only for this local-development, non-executing
slice.

## 2026-08-21 — Orchestration task approval v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy independent review or dual control.

**Scope and evidence:** Closed request/decision schemas, migration 0039, deterministic
request and signed-decision service, immutable persistence, audit/outbox linkage, and
synthetic positive, malformed, confirmation, replay, conflict, concurrency, expiry,
cancellation, signer, transition, and recovery-fencing tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and
`INV-REL-001`; trusted core creates the request, then its asserted human actor identifier
crosses into an immutable signed non-authoritative decision. Authentication remains a
documented prerequisite rather than a claim made by this slice. No provider, model,
plugin, worker, tool, gateway, target, secret, or network boundary is crossed.

**Threat/default-deny review:** Missing confirmation, malformed identity, unsupported
decision, stale policy/plan/task revisions, cross-scope substitution, changed replay,
expiry, cancellation, terminal state, signature/content tampering, and signer
unavailability deny with stable codes. Approval cannot alter task state, scope, policy,
capability, budget, privacy, or authority. Rejection can only use the pre-existing
`awaiting_human -> cancelled` transition.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
migration; no existing ActionIntent, approval, grant, or orchestration contract changes.
Only bounded metadata, identities, hashes, timestamps, decision reason, and signature
are stored. No prompts, evidence, targets, credentials, or secret references are stored.
Rollback disables the service and retains security history; migration 0039 is not
reversed.

**Limitations and residual risk:** Authenticated API/UI composition and a dedicated
approval-consuming readiness transition are deferred, as are leases, checkpoints,
dispatch, provider execution, and effect-specific policy approval. Non-independent
review reduces governance assurance and is accepted only for this local-development,
non-executing slice.

## 2026-08-21 — Durable orchestration task budget v1

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used and does
not satisfy independent review or dual control.

**Scope and evidence:** Closed request/reservation schemas, migration 0038, durable
account activation, atomic reservation and recovery service, immutable identity,
hash-chained audit/outbox linkage, synthetic positive/default-deny/replay/concurrency/
expiry/cancellation/recovery/tampering tests, documentation, complete diff, quality
checks, and repository scans.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`,
`INV-REL-001`, and `INV-REL-002`; validated provider ceilings cross into a trusted
assessment account, then an untrusted request crosses deterministic current-state and
atomic accounting checks into a non-authoritative reservation. No provider, model,
secret broker, worker, tool, gateway, target, or network boundary is crossed.

**Threat/default-deny review:** Missing/unknown fields, floating-point or empty values,
overflow boundaries, authority-shaped input, stale account/policy/plan/task/manifest
versions, cross-scope or cross-agent substitution, manifest tampering, changed replay,
concurrent oversubscription, expiry, cancellation, terminal state, recovery ambiguity,
and persisted identity mutation deny with stable codes. Exact replay cannot bypass
fresh current-state checks. No material finding is accepted.

**Compatibility, privacy, migration, and rollback:** Additive contracts/service and
migration; existing AI and gateway ledgers and ActionIntent producers are unchanged.
Only identifiers, hashes, timestamps, states, and integer ceilings/amounts are stored;
no prompts, evidence, targets, credentials, secret references, or provider payloads.
Rollback disables the service and retains security history; migration 0038 is not
reversed.

**Limitations and residual risk:** Trusted account activation is not yet reached
through an authenticated Master Orchestrator. Provider usage reconciliation,
committed debit, per-action budget composition, leases, checkpoints, approvals,
dispatch, and execution remain deferred. Non-independent review reduces governance
assurance and is accepted only for this local-development non-executing slice.

## 2026-08-21 — Task capability manifest v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy an independent-review requirement.

**Scope and evidence:** Closed manifest and request-v2 schemas, migration 0037,
trusted-core issuance and conversion composition, immutable provenance, synthetic
positive/default-deny/replay/tampering/expiry/limit/cancellation/recovery tests,
contract and action-plan documentation, complete diff, quality checks, and repository
scans.

**Invariants and trust boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`; trusted core issues
a non-authoritative ceiling after current-state validation, then treats each agent
proposal as untrusted input and revalidates every binding before creating only a
pending ActionIntent. No provider, model, plugin, worker, tool, gateway, target, or
network boundary is crossed.

**Threat/default-deny review:** Wildcards, caller issuance, delegation, privilege
inheritance, unsupported operations, secret/credential/raw-evidence fields, malformed
or unknown data, stale policy/plan/task/manifest revisions, cross-scope or cross-agent
substitution, changed replay, expiry, limit expansion, cancellation, terminal state,
safety pause, and recovery reuse deny with stable codes. Exact replay is idempotent
only while current security bindings remain valid. No material finding is accepted.

**Compatibility, privacy, migration, and rollback:** Request v2 is additive; request
v1 is retained for stored-document compatibility but denied for new conversion.
ActionIntent v1 and other producers are unchanged. Migration 0037 preserves old rows
with nullable linkage and adds immutable manifest records. Only bounded metadata and
opaque digests are stored; no secrets or content. Rollback disables issuance and new
v2 conversion while retaining immutable history; the migration is not reversed.

**Limitations and residual risk:** Agent transport authentication, authenticated Master
Orchestrator authorship, generalized capability issuance, approvals, budget charging,
leases, dispatch, and execution remain deferred. Non-independent review reduces
governance assurance and is accepted only for this local-development non-executing
slice.

## 2026-08-21 — Agent request to pending ActionIntent v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer,
Execution Safety Lead, Data Protection Lead, and Security Reviewer. The
`GIT_WORKFLOW.md` exception is used. This review is not independent.

**Scope and evidence:** Closed request schema, migration 0036, deterministic conversion
service, immutable provenance/audit linkage, synthetic positive/default-deny/replay/
concurrency/tampering tests, migration checks, documentation, complete diff, quality
checks, and repository scans.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`; untrusted agent
proposal to trusted deterministic validation, then immutable pending intent,
provenance, audit, and outbox persistence. No evaluation, approval, grant, provider,
plugin, worker, tool, gateway, target, or network boundary is crossed.

**Threat/default-deny review:** Unknown fields, raw-secret/command-shaped input,
delegation, unsupported agent/capability/method, action-digest or canonical-target
tampering, stale/expired input, cross-assessment/policy/plan/task substitution, stale
revisions, cancelled/terminal/non-validation tasks, paused safety, replay conflict,
concurrency, and database mutation deny. Exact replay is idempotent. No material
finding is accepted.

**Compatibility, privacy, migration, and rollback:** Additive schema/table/service;
ActionIntent v1 and prior producers are unchanged. Metadata and opaque digests only;
no content or secrets. Rollback disables conversion and retains immutable records;
migration 0036 is not reversed.

**Limitations and residual risk:** Agent/runtime identity is structurally bound but not
transport-authenticated. The input digest has no source artifact in this slice. Master
Orchestrator authorship, general capability manifests, approval, budgets, cancellation,
provider/model/runtime integration, and end-to-end evaluation remain deferred.
Non-independent review reduces governance assurance; the sole maintainer accepts that
risk only for this local-development non-executing slice.

## 2026-08-21 — Durable orchestration plan graph v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Plan-graph and transition schemas, migration 0035, deterministic
service, synthetic graph/transition/concurrency/recovery tests, migration tests,
contract and action-plan documentation, complete diff, quality checks, and repository
scans. Exact validation results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and `INV-REL-002`; untrusted graph and
command documents to deterministic validation, validated coordination state to SQLite,
and interrupted state to fail-closed recovery. No provider, secret, evidence-content,
agent, worker, plugin, tool, gateway, target, or network boundary is crossed.

**Threat and abuse cases:** malformed/oversized graphs, duplicate or conflicting
identity, missing/cross-plan references, self/cyclic/duplicate edges, unsupported task
or dependency type, privilege inheritance, stale plan/task revision, cross-assessment
substitution, changed command replay, invalid or terminal transition, concurrent
mutation, database tampering/deletion, and restart attempts to resume interrupted work.

**Default-deny findings:** Closed contracts precede semantic checks. Exact assessment,
plan, task, revision, command identity, transition, and request time are bound. Graph
creation derives readiness rather than trusting caller state. Database constraints and
triggers retain non-authority, immutable identity/history, and monotonic revisions.
Recovery only fails interrupted tasks. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts and
migration; existing workflow and authorization records are unchanged. Only bounded
metadata and opaque references are stored. Raw secrets/evidence/model content are
absent. Application rollback disables the new service and retains immutable records;
the migration is not reversed.

**Limitations and residual risk:** Plan authorship and activation are not authenticated;
human approval, audit/outbox linkage, cancellation propagation, leases, checkpoints,
retries, budgets, retention, Master Orchestrator logic, agents, tool-to-`ActionIntent`
conversion, and execution are deferred. No task is dispatched. Non-independent review
reduces governance assurance; the sole maintainer accepts that risk only for this
local-development non-executing slice.

## 2026-08-20 — AI provider configuration contract v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, Core Maintainer, Contract Maintainer, and Security Reviewer.
The `GIT_WORKFLOW.md` sole-maintainer exception is used. This review is not independent
and does not satisfy any external independence or dual-control requirement.

**Scope reviewed:** The complete provider configuration schema, deterministic validator,
synthetic tests, compatibility documentation, Phase 2 dependency ordering, and the
unchanged Phase 1 authorization/network boundary.

**Invariants and trust boundaries:** `INV-AUTH-003`, `INV-AGENT-001`,
`INV-AGENT-004`, and `INV-DATA-001`; untrusted configuration/model producers to the
trusted core policy; core to a future secret broker; core to future local and remote
provider adapters. No provider, broker, adapter, model, evidence, or network boundary
is crossed by this slice.

**Threat and abuse cases examined:** provider/model substitution, provider-type
confusion, configuration expiry and future dating, remote use without dual opt-in,
raw credential fields, cross-provider secret references, secret or restricted raw
evidence routing, unknown properties, disabled execution mutation, zero/unbounded and
over-ceiling budgets, and configuration data attempting to expand the trusted
allowlist.

**Default-deny findings:** Schema validation precedes semantic validation. Exact
provider/model allowlists are supplied by trusted code. Missing, malformed, stale,
ambiguous, conflicting, unsupported, privacy-violating, or over-budget inputs deny with
stable codes. No configuration value can enable execution or create authorization.

**Compatibility, migration, privacy, secrets, and rollback:** The v1 contract is
additive and has no legacy consumers. No migration or persistence is introduced.
Remote routing is explicit and deny-by-default; secret and restricted raw evidence are
forbidden. Only opaque, provider-bound secret references are representable. Rollback
removes the additive files without data conversion or authority recovery.

**Evidence examined:** Targeted and full Python tests, JSON contract validation, Ruff,
mypy, complete branch diff, staged-path review, and scans for credentials, real targets,
databases, caches, generated output, and merge markers. Exact command results are
recorded in the pull request.

**Findings:** No material finding accepted. The local-runtime cost value is configured
but not reserved or charged; all budget enforcement beyond validation remains deferred.

**Limitations and residual risk:** Provider adapters, real secret storage/resolution,
context assembly, runtime budget accounting, prompt-injection defenses, structured
output, persistence/audit, UI, and provider availability are absent. The slice must not
be described as completing either provider-adapter or full allowlist/budget action-plan
items. Governance assurance is reduced because review is non-independent; the sole
maintainer accepts that governance risk only for this local-development contract slice.

## 2026-08-20 — Trusted AI provider registry v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete registry schema/compiler, configuration-policy
composition change, synthetic tests, contract documentation, action-plan note, complete
diff, contract validation, Python unit and pytest suites, Ruff, mypy, and repository
scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, `INV-AGENT-004`, and
`INV-DATA-001`; untrusted registry documents to trusted deterministic compilation, and
compiled policy to provider-configuration validation. No provider, secret broker,
evidence store, model, target, or network boundary is crossed.

**Threat and abuse cases:** malformed/missing registry data, provider/model
substitution, duplicate identity ambiguity, order-dependent disabled entries, stale or
future policy, configuration outliving policy, expired-policy reuse, empty/degraded
allowlists, forbidden data routing, invalid budgets, execution-enable mutation, and
source-document mutation after compilation.

**Default deny and findings:** Schema validation precedes semantic compilation.
Malformed, stale, ambiguous, privacy-unsafe, and empty-enabled registries deny with
stable codes. Compiled maps are immutable snapshots with registry revision and expiry.
Configuration cannot outlive or reuse expired registry policy. No material finding is
accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive registry v1;
configuration v1 remains compatible. Secret and restricted raw evidence routing denies,
and the registry stores no secret references or values. There is no persistence or
migration. Rollback removes the additive registry boundary without data conversion or
authority recovery.

**Limitations and residual risk:** Registry origin authentication, signatures,
rollback protection, durable activation/revocation, audit, UI, adapters, context
construction, secret brokerage, and runtime budget accounting are deferred. Execution
remains disabled. Non-independent review reduces governance assurance; the sole
maintainer accepts that risk only for this local-development non-executing slice.

## 2026-08-20 — Non-resolving AI secret reference v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete secret-reference schema/validator, provider
configuration and registry composition, synthetic tests, contract documentation,
action-plan note, complete diff, contract validation, Python unit and pytest suites,
Ruff, mypy, and repository scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, `INV-AGENT-004`, and
`INV-DATA-001`; untrusted descriptor to deterministic validation, configuration to
opaque reference binding, and future core to secret broker. No credential store,
provider, model, evidence, target, or network boundary is crossed.

**Threat and abuse cases:** raw-secret fields, malformed reference identity,
cross-provider confusion, configuration reuse/replay, purpose confusion, future/stale/
overlong lifetime, incomplete configuration coverage, revocation bypass, local-runtime
secret attachment, attempted resolution enablement, and invalid underlying registry or
configuration authority.

**Default deny and findings:** Schema validation rejects unknown/raw-value-shaped and
resolution-enabled documents. Exact configuration, provider, URI, purpose, lifecycle,
and time binding is required. Revoked, local, stale, mismatched, or reused descriptors
deny with stable codes. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive descriptor v1;
provider configuration/registry v1 stay compatible. No secret value or store locator is
represented, resolved, logged, or exposed. There is no persistence or migration.
Rollback removes the additive descriptor boundary without data conversion or authority
recovery.

**Limitations and residual risk:** Credential-store custody, broker authentication,
just-in-time and single-use resolution, rotation, durable revocation, audit, recovery,
redaction scans, UI, adapters, and runtime execution remain deferred. Non-independent
review reduces governance assurance; the sole maintainer accepts that risk only for
this local-development non-resolving slice.

## 2026-08-21 — Deterministic AI budget reservation v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete reservation-request and receipt schemas, deterministic
in-memory ledger, synthetic tests, contract documentation, action-plan note, complete
diff, contract validation, Python unit and pytest suites, Ruff, mypy, and repository
scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, and `INV-NET-005`;
untrusted reservation request to deterministic accounting, trusted configuration and
registry revision to a fenced ledger, and recovered receipts to fail-closed state. No
provider, secret broker, model, evidence, target, gateway, or network boundary is
crossed, and no execution authority is created.

**Threat and abuse cases:** malformed or empty amounts, integer boundary violations,
cumulative and concurrent oversubscription, duplicate and conflicting replay, stale
ledger versions, configuration/registry substitution, stale requests, overlong or
expired reservations, invalid lifecycle transitions, tampered recovery records,
duplicate recovered identity/version, and recovery of oversubscribed state.

**Default deny and findings:** Contract validation precedes semantic accounting.
Atomic compare-and-reserve, exact idempotency, monotonic version fencing, bounded
lifetime, immutable snapshots, and strict recovery validation deny unsafe state with
stable codes. Expired reservations cannot commit and are released during recovery. No
material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
provider configuration, registry, and secret-reference v1 remain compatible. Only
counts and opaque identifiers are accepted; no prompt, evidence, secret value, or
secret resolution is present. There is no persistence or migration. Rollback removes
the additive ledger boundary without data conversion or authority recovery.

**Limitations and residual risk:** Durable crash-atomic storage, audit linkage,
per-task and per-assessment aggregation, cancellation, pricing/version provenance,
provider usage reconciliation, and runtime deadline enforcement are deferred. Provider
execution remains disabled. Non-independent review reduces governance assurance; the
sole maintainer accepts that risk only for this local-development non-executing slice.

## 2026-08-21 — Assessment retrieval metadata and ACL v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Retrieval policy, request, and result schemas; immutable policy
compiler; metadata-only assessment catalog; envelope revalidation; ACL, version,
lifetime, replay, and deterministic ordering logic; synthetic positive, negative,
tampering, expiry, injection, and concurrency tests; contract/compatibility docs;
action-plan note; complete diff; contract validation; Python unit and pytest suites;
Ruff; mypy; and repository scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; trusted-core policy injection to immutable ACLs,
untrusted request to exact subject/purpose filtering, validated envelopes to bounded
metadata, and instruction-like content to inert annotations. No acquisition, content
return, index, model context, provider, secret broker, evidence store, plugin, target,
tool, gateway, agent, or network boundary is crossed, and no execution authority is
created.

**Threat and abuse cases:** malformed/future/stale/overlong policy, duplicate subject,
untrusted policy substitution, unknown or child subject, cross-purpose reuse, requested
origin/classification/limit expansion, secret/raw classification, cross-assessment
request or envelope, stale policy/catalog/request, invalid envelope provenance/digest/
metadata/lifetime, duplicate identity/provenance, result ambiguity, exact/conflicting/
concurrent replay, and prompt-injection attempts to mutate filters or authority.

**Default deny and findings:** Closed contracts precede semantic checks. Policy,
catalog, subject, purpose, query digest, filter subsets, result ceiling, and time are
exactly bound. Every envelope is revalidated before selection, any invalid member
denies the entire request, ordering is deterministic, and content is omitted. Request
identity consumption is locked. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
existing AI boundaries remain compatible. Secret and restricted-raw classifications
are unrepresentable, and results expose only bounded provenance metadata rather than
content. No secret resolution, content logging, persistence, or migration exists.
Rollback removes the additive boundary without conversion or authority recovery.

**Limitations and residual risk:** Policy injection is trusted but not authenticated;
ACL/catalog/request state and replay fencing are process-local. Durable policy
activation, indexing, acquisition, persistent ACLs, idempotent recovery, audit,
retention/deletion, content retrieval, query matching, embeddings, context construction,
provider routing, and agent integration are deferred. Provider execution remains
disabled. Non-independent review reduces governance assurance; the sole maintainer
accepts that risk only for this local-development non-executing slice.

## 2026-08-21 — Strict AI structured output v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Candidate-observation, repair-request, and parse-result schemas;
strict parser and one-repair session boundary; synthetic negative and concurrency tests;
contract and compatibility documentation; action-plan note; complete diff; contract
validation; Python unit and pytest suites; Ruff; mypy; and repository scans. Exact
results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; raw untrusted bytes to deterministic parsing,
initial failure to bounded repair metadata, and parsed candidate to a non-authoritative
result. No provider, model context, secret broker, evidence, target, gateway, agent, or
network boundary is crossed, and no execution authority is created.

**Threat and abuse cases:** invalid encoding, empty or oversized bytes, duplicate JSON
keys, trailing content, non-finite numbers, type coercion, non-object roots, missing or
unknown fields, unsupported versions/types/operations, excessive nesting or
collections, altered limits, digest/failure substitution, future/stale repair,
unexpected repair, replay, concurrent consumption, and repair exhaustion.

**Default deny and findings:** Byte limits precede decoding; strict UTF-8/JSON and
contract validation precede acceptance. Repair eligibility is narrow, short-lived,
digest-bound, fixed-limit, and atomically one-use. All results retain execution disabled
and accepted content remains candidate data. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
the existing provider, registry, secret-reference, and budget contracts remain
compatible. There are no dedicated prompt, evidence, assessment-data, credential,
secret-value, or reference fields, and the parser neither logs nor routes content.
Bounded descriptive strings remain untrusted and require later classification at every
consumer. There is no persistence or migration. Rollback removes the additive boundary
without data conversion or authority recovery.

**Limitations and residual risk:** Repair replay state is process-local; provider calls,
actual repair prompting, durable state/audit, broader typed outputs, untrusted-content
envelopes, prompt-injection evaluation, context routing, and agent consumers are
deferred. Provider execution remains disabled. Non-independent review reduces
governance assurance; the sole maintainer accepts that risk only for this local-
development non-executing slice.

## 2026-08-21 — Untrusted content envelope v1 and injection corpus

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Envelope schema; deterministic builder, validator, indicator
metadata, and process-local replay registry; eleven-family synthetic prompt-injection
corpus; positive, negative, boundary, tampering, replay, and concurrency tests; contract
and compatibility documentation; action-plan note; complete diff; contract validation;
Python unit and pytest suites; Ruff; mypy; and repository scans. Exact results are
recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; untrusted origin text to an inert assessment-
scoped envelope, provenance and digest metadata to deterministic validation, and
instruction-like text to non-authoritative annotations. No acquisition, provider,
model context, secret broker, evidence store, plugin, target, tool, gateway, agent, or
network boundary is crossed, and no execution authority is created.

**Threat and abuse cases:** unknown or forbidden origin/classification, secret or raw-
evidence classification, oversized UTF-8, cross-assessment substitution, origin/
provenance mismatch, content-digest and injection-metadata tampering, future/expired/
overlong lifetime, envelope identity conflict, provenance reuse, exact and concurrent
replay, authority-shaped unknown fields, and direct, indirect, encoded, obfuscated,
delimiter-breaking, role-confusion, authority-claim, secret-exfiltration, tool-call,
policy-mutation, and data-poisoning content.

**Default deny and findings:** Closed schema validation precedes semantic checks. Exact
scope, origin/provenance namespace, UTF-8 byte ceiling, digest, recomputed metadata, and
bounded lifetime are mandatory. Registry mutation is locked and rejects replay or
ambiguous identity/provenance. Detection never changes authority or serves as an
authorization control. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contract;
existing AI boundaries remain compatible. Secret and restricted-raw classifications
are unrepresentable, and no credential/reference field, resolution, logging, or routing
exists. Arbitrary text can still be misclassified or contain sensitive material, so
future consumers must authenticate classification. There is no persistence or
migration. Rollback removes the additive boundary without conversion or authority
recovery.

**Limitations and residual risk:** Replay and provenance state are process-local;
source authentication, live acquisition, retrieval ACLs, classification assurance,
secret scanning, active-content stripping, context construction, provider routing,
canary traces, live model evaluation, and agent integration are deferred. Provider
execution remains disabled. Non-independent review reduces governance assurance; the
sole maintainer accepts that risk only for this local-development non-executing slice.
