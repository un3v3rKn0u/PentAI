# PentAI Versioned Technical Contracts

The Phase 0 contracts are stored under `schemas/v1/` and use JSON Schema Draft 2020-12.

## Contracts

- `ai-provider-configuration-v1.schema.json` — non-executing exact provider/model,
  secret-reference, privacy-routing, opt-in, expiry, and budget configuration.
- `ai-provider-registry-v1.schema.json` — trusted, revisioned provider/model allowlist,
  privacy-route, state, validity, and global budget-ceiling source.
- `ai-secret-reference-v1.schema.json` — non-resolving opaque provider-secret metadata
  bound to one exact provider configuration, purpose, lifecycle, and validity window.
- `ai-budget-reservation-request-v1.schema.json` — version-fenced, idempotent request
  to reserve bounded AI token, request, integer-cost, and runtime capacity.
- `ai-budget-reservation-v1.schema.json` — immutable non-executing reservation,
  commit, or release receipt with exact configuration and registry provenance.
- `ai-candidate-observation-v1.schema.json` — bounded non-authoritative candidate data
  accepted from strict model-output parsing.
- `ai-output-repair-request-v1.schema.json` — short-lived, digest-bound, one-repair
  request with fixed parser limits and execution disabled.
- `ai-structured-output-result-v1.schema.json` — deterministic direct, repaired, or
  denied parse result linked to the exact output bytes.
- `untrusted-content-envelope-v1.schema.json` — assessment-scoped inert text with
  origin-bound provenance, digest, classification, lifetime, and injection metadata.
- `prompt-injection-corpus-v1.schema.json` — bounded synthetic adversarial cases for
  the eleven initial instruction-like content categories.
- `ai-retrieval-policy-v1.schema.json` — exact assessment, subject, purpose, origin,
  classification, result-limit, revision, and validity access rules.
- `ai-retrieval-request-v1.schema.json` — short-lived policy- and catalog-fenced
  metadata retrieval request with query digest and requested ACL subsets.
- `ai-retrieval-result-v1.schema.json` — deterministic bounded provenance metadata
  with content omitted and authority disabled.
- `orchestration-plan-graph-v1.schema.json` — durable assessment-scoped task DAG with
  typed dependencies, deterministic readiness, revision fencing, and no authority.
- `orchestration-task-transition-v1.schema.json` — short-lived idempotent task-state
  command with exact assessment, plan, task, and revision bindings.
- `orchestration-task-budget-request-v1.schema.json` — version-fenced integer budget
  request bound to one current task, capability manifest, policy, and assessment account.
- `orchestration-task-budget-reservation-v1.schema.json` — durable non-authoritative
  reservation/release receipt with exact provenance and cancellation recovery state.
- `agent-action-intent-request-v1.schema.json` — non-authoritative Validation Agent
  proposal retained for compatibility and denied for new conversion without a manifest.
- `agent-action-intent-request-v2.schema.json` — manifest-bound, non-authoritative
  Validation Agent proposal converted into a provenance-bound pending ActionIntent.
- `task-capability-manifest-v1.schema.json` — trusted-core-issued immutable ceiling for
  one exact assessment, plan, task, agent, policy, purpose, capability, and limit set.
- `engagement-manifest-v2.schema.json` — normalized human-reviewed engagement data.
- `policy-ir-v1.schema.json` — deterministic compiled authorization policy.
- `action-intent-v1.schema.json` — immutable request for an external effect.
- `policy-decision-v1.schema.json` — deterministic decision and rule references.
- `approval-v1.schema.json` — typed human approval that satisfies policy conditions.
  Version 1.2 uses Ed25519 over the canonical document; v1.1 transactional
  attestations remain historical and cannot activate newly signed policy.
- `action-grant-v1.schema.json` — short-lived, signed, single-use execution authority.
- `network-attestation-v1.schema.json` — measured route and source identity bound to
  one active policy.
- `network-profile-proposal-v1.schema.json` — expiring, non-authoritative host route
  and resolver discovery result that requires human confirmation.
- `network-profile-v1.schema.json` — durable human-confirmed route, resolver mode,
  and registered source identity with explicit revocation state.
- `destination-decision-v1.schema.json` — immutable, non-executing DNS and destination
  reauthorization result.
- `gateway-session-v1.schema.json` — atomically budgeted, durable, non-executing
  gateway session preparation.
- `gateway-request-start-v1.schema.json` — irreversible, deadline-bounded, still
  non-executing request-start commitment.
- `gateway-request-result-v1.schema.json` — immutable request outcome, deadline, and
  bounded response-byte accounting linked to committed authority.
- `gateway-fixture-execution-claim-v1.schema.json` — historical unsigned one-use
  execution authority for the exact owned TEST-NET fixture.
- `gateway-fixture-execution-claim-v2.schema.json` — signed one-use execution authority
  bound to a committed start and live containment; the active fixture requires v2.
- `gateway-runtime-instance-v1.schema.json` — durable identity and fail-closed state
  for a non-target-facing gateway fixture runtime.
- `worker-containment-attestation-v1.schema.json` — short-lived runtime measurements
  retained for the historical gateway-to-fixture containment boundary.
- `worker-containment-attestation-v2.schema.json` — worker-specific measurements with
  an explicit gateway-only network role required before a worker launch may be planned.
- `worker-launch-spec-v1.schema.json` — immutable, digest-pinned, non-executing worker
  launch plan with fixed isolation controls.
- `assessment-workflow-v1.schema.json` — durable, version-fenced lifecycle for a
  human-supervised assessment; it never grants execution authority.
- `workflow-task-v1.schema.json` — idempotent, persistent task intent with dispatch
  and external effects explicitly disabled.
- `workflow-task-lifecycle-v1.schema.json` — version-fenced task attempts, retry,
  terminal, and dead-letter state without execution authority.
- `workflow-task-lease-v1.schema.json` — short-lived coordination lease whose token
  cannot grant worker launch, gateway access, or an external effect.
- `workflow-task-checkpoint-v1.schema.json` — immutable monotonic progress metadata
  containing references rather than evidence payloads.
- `audit-event-v1.schema.json` — validated append-only hash-chain event for privileged
  decisions, lifecycle changes, and effects.
- `execution-trace-v1.schema.json` — immutable owned-fixture execution linkage from
  intent and evaluated policy rules through grant, runtime version, result, and audit.
- `evidence-original-v1.schema.json` — immutable encrypted evidence metadata bound to
  one supervised workflow, exact policy, and optional matching execution trace.
- `evidence-custody-event-v1.schema.json` — append-only per-object evidence custody
  chain for storage and access events.
- `evidence-redaction-v1.schema.json` — immutable server-generated text redaction
  derivative with exact source digest and selected-range provenance.
- `evidence-preview-v1.schema.json` — bounded derivative-only inactive plain-text
  preview response that cannot request original content.
- `evidence-derivative-event-v1.schema.json` — append-only per-derivative custody
  chain for redaction storage and preview access.
- `evidence-deletion-v1.schema.json` — policy-deadline-bound, human-confirmed,
  crash-recoverable content deletion with explicit erasure limitations.
- `finding-v1.schema.json` — policy/evidence-bound supervised finding with deterministic
  CVSS validation, affected assets, duplicate review, validation state, and immutable
  version history.
- `report-draft-v1.schema.json` — immutable human-requested report draft metadata with
  exact finding-version references and digested Markdown, HTML, JSON, and PDF artifacts.
- `assessment-coverage-v1.schema.json` — immutable human-recorded testing coverage for
  an exact policy asset/capability pair, with evidence and explicit limitations.
- `no-findings-report-draft-v1.schema.json` — coverage-complete immutable report draft
  that snapshots exact coverage and evidence references without granting export authority.
- `report-export-approval-v1.schema.json` — explicit immutable human approval binding
  one exact draft hash and all artifact digests to export-ready status.
- `report-file-export-v1.schema.json` — one immutable local export receipt binding an
  approved artifact digest to a server-generated filename without submission authority.
- `canonical-types-v1.schema.json` — reusable canonical target value objects.

## Ownership and review

| Schema | Owning role | Compatibility and versioning | Required reviewers |
|---|---|---|---|
| AIProviderConfiguration v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| AIProviderRegistry v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| AISecretReference v1 | Data Protection Lead | Contract Maintainer | AI/Agent Lead, Security Reviewer |
| AIBudgetReservationRequest v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| AIBudgetReservation v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| AICandidateObservation v1 | AI/Agent Lead | Contract Maintainer | Security Reviewer |
| AIOutputRepairRequest v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| AIStructuredOutputResult v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| UntrustedContentEnvelope v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| PromptInjectionCorpus v1 | AI/Agent Lead | Contract Maintainer | Security Reviewer |
| AIRetrievalPolicy v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| AIRetrievalRequest v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| AIRetrievalResult v1 | AI/Agent Lead | Contract Maintainer | Data Protection Lead, Security Reviewer |
| OrchestrationPlanGraph v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskTransition v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetRequest v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetReservation v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| AgentActionIntentRequest v1 | AI/Agent Lead | Contract Maintainer | Execution Safety Lead, Security Reviewer |
| Engagement Manifest v2 | Product Safety Lead | Contract Maintainer | Product Owner, Policy Maintainer, Security Reviewer |
| Policy IR v1 | Policy Maintainer | Contract Maintainer | Core Maintainer, independent Security Reviewer |
| ActionIntent v1 | Execution Safety Lead | Contract Maintainer | Policy Maintainer, independent Security Reviewer |
| PolicyDecision v1 | Policy Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| Approval v1.1 | Core Security Maintainer | Contract Maintainer | Product Safety Lead, independent Security Reviewer |
| ActionGrant v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| NetworkAttestation v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| NetworkProfileProposal v1 | Gateway Maintainer | Contract Maintainer | Product Safety Lead, Security Reviewer |
| NetworkProfile v1 | Gateway Maintainer | Contract Maintainer | Product Safety Lead, Security Reviewer |
| DestinationDecision v1 | Gateway Maintainer | Contract Maintainer | Policy Maintainer, independent Security Reviewer |
| GatewaySession v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| GatewayRequestStart v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| GatewayRequestResult v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| GatewayFixtureExecutionClaim v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| GatewayFixtureExecutionClaim v2 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| GatewayRuntimeInstance v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| WorkerContainmentAttestation v1 | Systems Engineer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| WorkerContainmentAttestation v2 | Systems Engineer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| WorkerLaunchSpec v1 | Execution Safety Lead | Contract Maintainer | Systems Engineer, independent Security Reviewer |
| AssessmentWorkflow v1 | Core Maintainer | Contract Maintainer | Product Safety Lead, Security Reviewer |
| WorkflowTask v1 | Core Maintainer | Contract Maintainer | Execution Safety Lead, Security Reviewer |
| WorkflowTaskLifecycle v1 | Core Maintainer | Contract Maintainer | Execution Safety Lead, Security Reviewer |
| WorkflowTaskLease v1 | Core Maintainer | Contract Maintainer | Execution Safety Lead, Security Reviewer |
| WorkflowTaskCheckpoint v1 | Core Maintainer | Contract Maintainer | Product Safety Lead, Security Reviewer |
| AuditEvent v1 | Core Security Maintainer | Contract Maintainer | Product Safety Lead, Security Reviewer |
| ExecutionTrace v1 | Execution Safety Lead | Contract Maintainer | Gateway Maintainer, Security Reviewer |
| EvidenceOriginal v1 | Evidence Maintainer | Contract Maintainer | Core Maintainer, Security Reviewer |
| EvidenceCustodyEvent v1 | Evidence Maintainer | Contract Maintainer | Core Security Maintainer, Security Reviewer |
| EvidenceRedaction v1 | Evidence Maintainer | Contract Maintainer | Core Security Maintainer, Security Reviewer |
| EvidencePreview v1 | Evidence Maintainer | Contract Maintainer | UI Maintainer, Security Reviewer |
| EvidenceDerivativeEvent v1 | Evidence Maintainer | Contract Maintainer | Core Security Maintainer, Security Reviewer |
| EvidenceDeletion v1 | Evidence Maintainer | Contract Maintainer | Core Security Maintainer, Security Reviewer |
| Finding v1 | Evidence and Reporting Lead | Contract Maintainer | Product Safety Lead, Security Reviewer |
| ReportFileExport v1 | Evidence and Reporting Lead | Contract Maintainer | Product Safety Lead, Security Reviewer |
| BackupRestoreReport v1 | Core Maintainer | Contract Maintainer | Evidence Maintainer, Security Reviewer |
| BackupRestoreReport v2 | Core Maintainer | Contract Maintainer | Evidence Maintainer, Security Reviewer |
| BackupInventory v1 | Core Maintainer | Contract Maintainer | Evidence Maintainer, Security Reviewer |
| BackupRotationPlan v1 | Core Maintainer | Contract Maintainer | Evidence Maintainer, Security Reviewer |
| BackupPurge v1 | Core Maintainer | Contract Maintainer | Evidence Maintainer, Security Reviewer |
| Canonical Types v1 | Policy Maintainer | Contract Maintainer | Gateway Maintainer, independent Security Reviewer |

The owning role is accountable for semantics and consumers. The Contract Maintainer is
accountable for compatibility analysis, schema release notes, and version changes.
Security-critical changes also require the heightened review policy in
`GIT_WORKFLOW.md`. While PentAI has only one maintainer, the documented
sole-maintainer exception may replace independence for internal project approval, but
the review must be recorded as non-independent and cannot satisfy an external
independent-review requirement.

## Compatibility

- `$id` is the stable contract identity.
- Additive optional fields require a minor contract release.
- New required fields, changed semantics, or removed values require a new major contract.
- Producers include `schema_version`; consumers reject unsupported major versions.
- Unknown fields are rejected in authorization-critical objects.
- Persisted contracts are immutable and content-addressed after approval or decision.

## Authority

The manifest is reviewed input. Policy IR is compiled output. An `Approval` can satisfy only a condition already declared by Policy IR. Only the policy decision service may create a `PolicyDecision`, and only the execution broker may mint an `ActionGrant`.
