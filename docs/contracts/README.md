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
- `orchestration-task-approval-request-v1.schema.json` — trusted-core-created,
  short-lived readiness condition bound to one approval-gated task and active policy.
- `orchestration-task-approval-decision-v1.schema.json` — signed immutable human
  decision that grants no authority and leaves approval consumption deferred.
- `orchestration-task-approval-request-v2.schema.json` — authenticated local-core
  request binding its server-derived human principal without accepting caller identity.
- `orchestration-task-approval-decision-v2.schema.json` — authenticated-session
  decision bound to the same requesting principal and still granting no authority.
- `orchestration-task-approval-consumption-v1.schema.json` — immutable authenticated
  receipt for the exact storage-gated readiness-only transition.
- `orchestration-task-budget-request-v1.schema.json` — version-fenced integer budget
  request bound to one current task, capability manifest, policy, and assessment account.
- `orchestration-task-budget-reservation-v1.schema.json` — durable non-authoritative
  reservation/release receipt with exact provenance and cancellation recovery state.
- `orchestration-task-budget-request-v2.schema.json` — v1-compatible request with an
  exact ready/running task-state binding for pre-lease reservation ordering.
- `orchestration-task-budget-reservation-v2.schema.json` — immutable task-state-bound
  reservation/release receipt that grants no execution authority.
- `orchestration-task-budget-request-v3.schema.json` — retry-activation and v3-manifest
  bound request for one exact ready attempt-two lineage.
- `orchestration-task-budget-reservation-v3.schema.json` — immutable retry-bound
  reservation/release receipt with no task-transition or execution authority.
- `orchestration-task-lease-acquire-v1.schema.json` — exact ready-task lease acquisition
  request bound to trusted worker identity and current orchestration prerequisites.
- `orchestration-task-lease-acquire-v2.schema.json` — retry-bound acquisition request
  for one exact ready attempt-two manifest and budget lineage.
- `orchestration-task-lease-acquire-v3.schema.json` — attempt-three-only acquisition
  request bound to manifest v4, reservation v4, activation v2, and trusted worker state.
- `orchestration-task-lease-mutation-v1.schema.json` — token- and revision-fenced lease
  renewal or release command.
- `orchestration-task-lease-state-v1.schema.json` — non-authoritative durable lease state.
- `orchestration-task-lease-state-v2.schema.json` — immutable retry-lineage-bound lease
  state that retains non-authoritative coordination semantics.
- `orchestration-task-lease-state-v3.schema.json` — immutable attempt-three lease state
  with shared monotonic task fencing and no execution authority.
- `orchestration-task-lease-event-v1.schema.json` — immutable lease lifecycle receipt.
- `orchestration-task-lease-consumption-v1.schema.json` — exact holder-proof command
  for the dedicated readiness-to-running coordination transition.
- `orchestration-task-lease-consumption-receipt-v1.schema.json` — immutable,
  non-authoritative receipt binding the consumed lease and resulting revisions.
- `orchestration-task-lease-consumption-v2.schema.json` — retry-bound holder-proof
  command for one exact attempt-two readiness transition.
- `orchestration-task-lease-consumption-receipt-v2.schema.json` — immutable retry-lineage
  receipt for the attempt-two readiness transition.
- `orchestration-task-lease-consumption-v3.schema.json` — exact attempt-three holder-proof
  command bound to lease v3 and its v4 readiness lineage.
- `orchestration-task-lease-consumption-receipt-v3.schema.json` — immutable,
  non-authoritative receipt for the attempt-three readiness transition.
- `orchestration-task-checkpoint-command-v1.schema.json` — exact running-task command
  carrying only bounded progress metadata.
- `orchestration-task-checkpoint-receipt-v1.schema.json` — immutable monotonic
  checkpoint receipt linked by predecessor digest.
- `orchestration-task-checkpoint-command-v2.schema.json` — exact attempt-two command
  bound to retry activation, v3 readiness records, and lease-consumption v2.
- `orchestration-task-checkpoint-receipt-v2.schema.json` — immutable retry-lineage
  checkpoint receipt with metadata-only coordination semantics.
- `orchestration-task-checkpoint-command-v3.schema.json` — exact attempt-three command
  bound to lease-consumption v3 and the v4 readiness lineage.
- `orchestration-task-checkpoint-receipt-v3.schema.json` — immutable, predecessor-chained
  metadata-only checkpoint for the running attempt-three task.
- `orchestration-task-failure-command-v1.schema.json` — closed original-attempt failure
  command bound to the current lease/checkpoint lineage.
- `orchestration-task-failure-receipt-v1.schema.json` — immutable original-attempt
  failure receipt with no retry or execution authority.
- `orchestration-task-failure-command-v2.schema.json` — closed attempt-two failure
  command bound to retry activation, v3 readiness records, and checkpoint v2.
- `orchestration-task-failure-receipt-v2.schema.json` — immutable retry-lineage failure
  receipt for the storage-enforced coordination-only failed transition.
- `orchestration-task-attempt-command-v2.schema.json` — exact attempt-two failure-link
  command bound to the immutable retry failure receipt.
- `orchestration-task-attempt-receipt-v2.schema.json` — immutable failed attempt-two
  receipt that preserves the existing attempt identity without activation or authority.
- `orchestration-retry-policy-v1.schema.json` — trusted-core closed retry semantics,
  integer attempt/backoff ceilings, exact policy binding, and no authority.
- `orchestration-retry-policy-v2.schema.json` — additive trusted-core policy for
  retry-bound failure/attempt v2 lineage with the same closed three-attempt ceiling.
- `orchestration-retry-evaluation-command-v2.schema.json` — version-exact evaluation
  request for one immutable failed attempt-two receipt and retry policy v2.
- `orchestration-retry-decision-v2.schema.json` — immutable non-activating attempt
  two to proposed attempt three eligibility or terminal-denial result.
- `orchestration-retry-evaluation-command-v1.schema.json` — short-lived evaluation
  request bound to one immutable failed attempt and active retry policy.
- `orchestration-retry-decision-v1.schema.json` — immutable non-activating eligibility
  result with deterministic reason and earliest retry time.
- `orchestration-retry-budget-consumption-command-v1.schema.json` — version-fenced
  one-unit accounting command bound to an exact eligible retry decision.
- `orchestration-retry-budget-consumption-receipt-v1.schema.json` — immutable,
  non-refundable retry sub-ledger receipt that grants no authority.
- `orchestration-retry-attempt-command-v1.schema.json` — exact consumption-bound
  registration command for non-activating attempt-two identity.
- `orchestration-retry-attempt-receipt-v1.schema.json` — immutable registered attempt
  two identity bound to the first retry-consumption receipt, with no scheduling,
  task-state, lease, dispatch, or execution authority.
- `orchestration-retry-attempt-command-v2.schema.json` — version-exact registration
  request for inert attempt three, bound to the second retry-consumption receipt.
- `orchestration-retry-attempt-receipt-v2.schema.json` — immutable, fork-free attempt
  three identity at the closed retry-policy ceiling.
- `orchestration-retry-schedule-command-v1.schema.json` — exact attempt-two-bound
  registration command with no caller-controlled timing or activation fields.
- `orchestration-retry-schedule-receipt-v1.schema.json` — immutable inert scheduling
  metadata derived from trusted retry lineage with no runnable or execution authority.
- `orchestration-retry-schedule-command-v2.schema.json` — version-exact inert schedule
  registration for attempt three after its deterministic policy backoff.
- `orchestration-retry-schedule-receipt-v2.schema.json` — immutable attempt-three
  timing metadata with no activation, task-state, lease, dispatch, or effect authority.
- `orchestration-retry-activation-command-v1.schema.json` — exact schedule-consumption
  command for the dedicated failed-task readiness transition.
- `orchestration-retry-activation-receipt-v1.schema.json` — immutable non-authoritative
  receipt for one storage-fenced retry readiness activation.
- `orchestration-retry-activation-command-v2.schema.json` — version-exact schedule-v2
  consumption command for attempt-three readiness.
- `orchestration-retry-activation-receipt-v2.schema.json` — immutable non-authoritative
  receipt for the storage-fenced attempt-three failed-to-ready transition.
- `agent-action-intent-request-v1.schema.json` — non-authoritative Validation Agent
  proposal retained for compatibility and denied for new conversion without a manifest.
- `agent-action-intent-request-v2.schema.json` — manifest-bound, non-authoritative
  Validation Agent proposal converted into a provenance-bound pending ActionIntent.
- `task-capability-manifest-v1.schema.json` — trusted-core-issued immutable ceiling for
  one exact assessment, plan, task, agent, policy, purpose, capability, and limit set.
- `task-capability-manifest-v2.schema.json` — v1-compatible manifest with an exact
  ready/running task-state binding; ready manifests cannot produce ActionIntents.
- `task-capability-manifest-v3.schema.json` — retry-activation- and attempt-bound ready
  manifest that remains non-authoritative and cannot produce an ActionIntent.
- `task-capability-manifest-request-v4.schema.json` — closed trusted-core request for
  one exact attempt-three activation-v2 ready lineage.
- `task-capability-manifest-v4.schema.json` — immutable attempt-three ready manifest
  bound to the exact activation-v2 lineage without execution authority.
- `orchestration-task-budget-request-v4.schema.json` — attempt-three ready-state,
  manifest-v4-bound integer resource reservation request with zero retry capacity.
- `orchestration-task-budget-reservation-v4.schema.json` — immutable attempt-three
  reservation receipt that preserves both consumed retry units and grants no authority.
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
| OrchestrationTaskApprovalConsumption v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetRequest v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetReservation v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetRequest v2 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskBudgetReservation v2 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Security Reviewer |
| OrchestrationTaskLease v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationTaskLeaseConsumption v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationTaskCheckpoint v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Data Protection Lead, Security Reviewer |
| OrchestrationTaskFailure v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationTaskAttempt v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationRetryPolicy v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationRetryDecision v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationRetryBudgetConsumption v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationRetryBudgetConsumption v2 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| OrchestrationRetryAttempt v1 | AI/Agent Lead | Contract Maintainer | Core Maintainer, Execution Safety Lead, Security Reviewer |
| TaskCapabilityManifest v2 | AI/Agent Lead | Contract Maintainer | Execution Safety Lead, Security Reviewer |
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
