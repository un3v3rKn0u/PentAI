# Phase 2 slice security reviews

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
