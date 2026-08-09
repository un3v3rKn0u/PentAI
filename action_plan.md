# PentAI Implementation Action Plan

**Status:** Execution baseline<br>
**Version:** 1.0<br>
**Date:** 2026-08-05<br>
**Architecture baseline:** `PentAI_Software_Architecture.md`<br>
**Intake source of truth:** `design_intake_workflow.md`

## 1. Purpose

This plan converts the PentAI architecture into an implementable, testable delivery program. It prioritizes enforceable authorization, deterministic policy, network containment, auditability, and recovery before autonomous agents or broad tool coverage.

The plan assumes a cross-functional team of six to nine people. A smaller team should retain the same safety gates and reduce feature breadth.

The governing delivery rule is:

> PentAI must not execute a target-facing action until deterministic policy enforcement, controlled egress, audit traceability, and emergency stop have passed their release gates.

## 2. Target Outcome

At the end of the plan, PentAI will be a signed cross-platform desktop application that can:

- Collect and version complete bug-bounty program information.
- Compile approved Rules of Engagement into deterministic policies.
- Create and supervise bounded assessment plans.
- Execute approved actions only through a controlled network path.
- Recover safely from crashes and infrastructure failures.
- Capture encrypted, traceable evidence.
- Validate and manage findings.
- Generate professional finding and “No Findings” reports.
- Load signed, capability-scoped tool plugins.
- Orchestrate specialized AI agents without granting them enforcement authority.

## 3. Delivery Principles

1. **Safety before autonomy.** Manual and supervised workflows must work before agent-driven execution.
2. **Default deny.** Ambiguous, missing, stale, conflicting, or unverifiable authorization blocks execution.
3. **One enforcement path.** All external traffic must traverse the PentAI gateway.
4. **Typed boundaries.** Agents, plugins, tools, and services communicate through versioned schemas.
5. **Durability by design.** Committed work survives process and machine failure.
6. **Trace everything privileged.** Every action links to its policy, decision, grant, actor, output, and evidence.
7. **Small vertical slices.** Each milestone produces a demonstrable, tested capability.
8. **No silent degradation.** Missing isolation, failed attestation, or unsupported networking disables execution.
9. **Human authority remains explicit.** Policy activation, sensitive validation, and report submission require review.
10. **Cross-platform safety parity.** A feature ships only where its security guarantees are verified.

## 4. Team and Ownership Model

Recommended accountable roles:

| Role | Primary accountability |
|---|---|
| Product Lead | Scope, user research, program priorities, acceptance |
| Principal Architect | Architecture integrity, ADRs, dependency boundaries |
| Security Lead | Threat model, policy invariants, abuse cases, security gates |
| Backend Lead | Domain, API, persistence, workflow, audit |
| Desktop/UI Lead | Tauri shell, React UI, accessibility, user safety controls |
| Systems Engineer | Gateway, process isolation, containers, OS networking |
| AI/Agent Lead | Model adapters, prompts, orchestration, evaluation |
| QA/SDET | Test strategy, automation, recovery, cross-platform conformance |
| Release/DevSecOps | CI, signing, SBOM, packaging, updates, release evidence |

For a smaller team, roles may be combined, but security-critical code requires a reviewer who did not author the change.

### 4.1 Decision authority

- Architecture changes: Principal Architect + Security Lead.
- Policy semantics and safety invariants: Security Lead, with two-person approval.
- Product scope: Product Lead, constrained by security release gates.
- Release approval: Product, Security, QA, and Release owners.
- Risk acceptance: named project sponsor; never an individual feature developer.

## 5. Workstreams

### WS1 — Product, architecture, and governance

Deliverables:

- Product requirements and explicit non-goals.
- Architecture Decision Record process.
- Threat model and trust-boundary diagrams.
- Security invariant register.
- Data classification and retention policy.
- Release and risk-acceptance process.
- Definition of Done and evidence templates.

### WS2 — Desktop experience

Deliverables:

- Tauri shell and React application.
- Navigation, command palette, status strip, notifications, and emergency stop.
- Intake, Programs, Assessments, Agents, Evidence, Findings, Reports, Logs, Settings, AI, Tools, and Plugins pages.
- Accessibility and platform-native behavior.
- Safe approval and policy-diff experiences.

### WS3 — Core domain and persistence

Deliverables:

- Program, Engagement, Policy, Assessment, Task, Action, Evidence, Finding, Report, and Plugin aggregates.
- SQLite/WAL persistence, migrations, encrypted fields, backups, and integrity checks.
- Versioned API and optimistic concurrency.
- Transactional outbox, leases, checkpoints, and dead-letter workflow.
- Hash-chained audit ledger.

### WS4 — Intake and policy engine

Deliverables:

- Source ingestion and provenance.
- Manifest schema v2.
- Canonicalizers and typed asset matchers.
- Conflict, completeness, and expiry validation.
- Policy intermediate representation, compiler, evaluator, signing, activation, and revocation.
- Approval records and semantic source/policy diffs.

### WS5 — Execution and network enforcement

Deliverables:

- Execution broker.
- Short-lived single-use action grants.
- Rootless container runner.
- Mandatory egress gateway and controlled DNS.
- Rate, concurrency, time, total-request, and data budgets.
- VPN/proxy/static-IP profiles, IP attestation, kill switch, and emergency stop.

### WS6 — Evidence, findings, and reporting

Deliverables:

- Encrypted content-addressed evidence store.
- Evidence classification, immutable originals, redaction derivatives, and chain of custody.
- Finding lifecycle, scoring, duplicate checks, and validation status.
- HackerOne-, Bugcrowd-, and Intigriti-oriented templates.
- Markdown, HTML, JSON, and PDF exports.
- Coverage-based “No Findings” report.

### WS7 — AI and agent system

Deliverables:

- Provider-neutral model interface and privacy routing.
- Structured output validation and untrusted-content handling.
- Master Orchestrator and durable plan graph.
- Specialist agents introduced incrementally.
- Model evaluation, token/cost budgets, context and memory controls.
- Prompt-injection and data-leakage regression suite.

### WS8 — Plugin and tool platform

Deliverables:

- Plugin manifest and SDK.
- Signature, digest, compatibility, SBOM, and permission verification.
- Out-of-process/container adapter runtime.
- Health checks, structured inputs, parsers, and normalized observations.
- Initial official adapters selected by risk and user value.

### WS9 — Quality, security, and release engineering

Deliverables:

- Unit, property, integration, recovery, security, and end-to-end suites.
- Cross-platform CI and reference environments.
- Dependency, container, license, secret, and code scanning.
- Reproducible signed builds and installers.
- Release evidence bundle, rollback, backup/restore, and incident runbooks.

## 6. Phase Plan

## Phase 0 — Foundations and Safety Contracts

**Duration:** 4–6 weeks<br>
**Objective:** Establish buildable project foundations and freeze the first safety contracts before feature implementation.<br>
**Status:** Completed 2026-08-08 under the documented non-independent
sole-maintainer security-review exception.

### 6.1 Actions

- [x] Confirm MVP personas, authorized use cases, and explicit non-goals.
- [x] Create the monorepo structure defined in the architecture.
- [x] Establish formatting, linting, type checking, tests, branch protection, and dependency locking.
- [x] Record ADR 0001 for the implemented local API transport decision; defer
  component-specific ADRs for gateway/container choices until those Phase 1
  implementation decisions are made.
- [x] Build the local-transport threat model and abuse-case baseline; broader system STRIDE review remains open.
- [x] Define the initial security invariants and map each to an owner, automated evidence, missing verification, and approval state.
- [x] Define manifest v2, policy IR v1, `ActionIntent`, `PolicyDecision`, `Approval`, and `ActionGrant`; generic message envelopes remain deferred.
- [x] Build deterministic canonicalization libraries for domains, wildcards, URLs, ports, IPs/CIDRs, and paths.
- [x] Create a malicious and ambiguous authorization test corpus with property and differential tests.
- [x] Implement the desktop shell, local core bootstrap, per-launch authentication, and health endpoint.
- [x] Implement database migrations and the Phase 0 authorization persistence slice; broader Program/Engagement/Source APIs remain Phase 1.
- [x] Resolve operating-system credential-store scope: ephemeral launch credentials
  must not be durable; Product Owner, Security Lead, and sole-maintainer Security
  Reviewer approved deferral of a durable-secret proof until such a secret exists.
- [x] Defer intake, policy-diff, approval, network-state, and emergency-stop prototypes
  to their Phase 1 UI work; they are not Phase 0 exit criteria.

### 6.2 Deliverables

- Approved product scope and non-goals.
- Architecture and threat-model baseline.
- Versioned contracts and schemas.
- Running development desktop shell connected to a digest-verified packaged local
  core; production signing and notarization remain release work.
- Deterministic canonicalization proof of concept.
- Cross-platform CI smoke build.

### 6.3 Exit gate

Phase 0 is complete only when:

- Every authorization-critical schema has an owner and compatibility policy.
- Canonicalizers pass property tests for IDNA, wildcards, URL boundaries, CIDRs, encoded paths, and IPv4/IPv6 edge cases.
- The local API is not accessible without the launch credential.
- The threat model has no unowned critical threats.
- The security team approves the initial safety invariants.

All criteria passed on 2026-08-08. Evidence, ownership, approval scope, and deferred
enforcement are recorded in `docs/security/phase0_status.md`.

## Phase 1 — Safe Supervised MVP

**Duration:** 8–12 weeks<br>
**Objective:** Deliver an end-to-end supervised assessment workflow with enforceable policy and controlled HTTP(S) execution.

### 6.4 Actions: intake and policy

- [x] Implement source import for files, URLs, and pasted text.
- [x] Store source authority, timestamps, effective dates, hashes, and encrypted originals.
- [ ] Build the full intake UI from `design_intake_workflow.md`.
- [x] Implement draft manifest editing with field-level provenance.
- [x] Add deterministic completeness, conflict, expiration, and contradiction checks.
- [x] Implement typed asset matchers with explicit wildcard/apex/path/port behavior.
- [ ] Build policy compilation, deterministic decision evaluation, signing, activation, revocation, and version history.
- [ ] Build typed, expiring approvals and activation workflow.
  - Signed lifecycle implementation was merged in PR #26 and accepted under the
    explicitly non-independent local-development governance scope. This does not grant
    production, release, or external assurance; Phase 1 completion remains gated by
    the remaining execution, recovery, evidence, and reporting demonstrations.
- [x] Build semantic diffs for scope, techniques, limits, and reporting terms.

### 6.5 Actions: execution and safety

- [ ] Implement `ActionIntent → PolicyDecision → ActionGrant → Execution` end to end.
- [x] Build a single-use, audience-bound, short-lived grant verifier.
  - The non-executing `ActionIntent → PolicyDecision → ActionGrant` chain and atomic
    local verifier are implemented on `feature/action-grant-chain`; gateway execution
    remains explicitly deferred.
  - Gateway integration remains technically gated by containment, controlled DNS,
    route/source-IP attestation, redirect reauthorization, stop controls, and negative
    bypass tests.
- [ ] Build the first gateway supporting HTTP(S), controlled DNS, redirects, and rate enforcement.
  - The non-networking gateway control plane now persists immutable destination
    decisions, atomically reserves total-request/concurrency/response capacity, and
    prepares durable sessions with execution disabled. Rate token buckets, sockets,
    containment, and external effects remain required before this item is complete.
- [ ] Create an isolated HTTP/browser worker with no direct outbound route.
- [ ] Implement source-IP attestation and approved-IP comparison.
- [x] Implement global and assessment-level pause, stop, and grant revocation.
- [ ] Implement route failure and public-IP change kill switches.
- [ ] Reauthorize DNS answers, redirects, SNI/Host, port, and protocol changes.

### 6.6 Actions: durable workflow and audit

- [ ] Implement assessment state machine and persistent task queue.
- [ ] Add leases, heartbeats, checkpoints, retries, fencing, idempotency, outbox, and dead letters.
- [ ] Create an append-only hash-chained audit ledger.
- [ ] Link every execution to its intent, decision, policy rules, grant, tool version, and outputs.
- [x] Build recovery startup that revokes stale grants before reclaiming tasks.

### 6.7 Actions: evidence, findings, reports, and UI

- [ ] Implement encrypted content-addressed evidence storage.
- [ ] Support metadata, files, screenshots, request/response records, notes, and tool output.
- [ ] Implement classification, preview sandboxing, redaction derivatives, and retention.
- [ ] Implement finding lifecycle, CVSS/CWE, affected assets, confidence, and validation status.
- [ ] Build Dashboard, Programs, Intake, Assessments, Evidence, Findings, Reports, and Logs pages.
- [ ] Generate Markdown, HTML, JSON, and PDF report drafts.
- [ ] Generate a coverage-aware “No Findings” report.
- [ ] Require explicit human report approval before export-ready status.

### 6.8 Phase 1 vertical demonstrations

1. Import a program and preserve its sources.
2. Normalize and approve an exact local test scope.
3. Compile and activate policy.
4. Attest the controlled local network route.
5. Attempt a denied target and show that no connection occurs.
6. Run an approved benign HTTP action against an owned test target.
7. Capture evidence and audit linkage.
8. Kill the application during work, restart, and recover safely.
9. Produce a finding report and a separate “No Findings” report.

### 6.9 Exit gate

- No known policy, redirect, DNS, alternate-port, or direct-egress bypass.
- Every target-facing execution has complete audit linkage.
- Public-IP or route change blocks new actions and closes active gateway sessions.
- Crash/power-loss tests show no committed state loss or duplicate external action.
- Backup and restore pass integrity verification.
- Reports contain policy version, testing timestamps, evidence references, and coverage limits.
- The product remains supervised; no autonomous active testing is enabled.

## Phase 2 — Agent and Plugin Platform

**Duration:** 10–14 weeks<br>
**Objective:** Add bounded AI orchestration and extensible tools without weakening the Phase 1 enforcement boundary.

### 6.10 Actions: AI foundation

- [ ] Implement provider adapters for one approved remote model and one local-model runtime.
- [ ] Add provider/model allowlists, secret references, privacy classes, and cost/token budgets.
- [ ] Implement strict structured-output parsing with rejection and bounded repair.
- [ ] Create untrusted-content envelopes and prompt-injection regression tests.
- [ ] Implement assessment-scoped retrieval with provenance and ACL filters.
- [ ] Ensure secrets and raw restricted evidence cannot enter model contexts by default.

### 6.11 Actions: orchestration

- [ ] Build the durable plan graph and Master Orchestrator.
- [ ] Require all agent tool requests to become typed `ActionIntent` records.
- [ ] Add task dependency, lease, cancellation, budget, checkpoint, and human-approval handling.
- [ ] Implement Scope, RoE, Evidence, Validation, and Reporting agents first.
- [ ] Add Web Agent only after supervised HTTP/browser controls are stable.
- [ ] Expose structured agent state, tasks, budgets, and approval requests in the UI.
- [ ] Prevent worker-to-worker delegation and privilege inheritance.

### 6.12 Actions: plugin platform

- [ ] Freeze plugin manifest v1 and capability naming conventions.
- [ ] Build plugin verification for signature, digest, SDK compatibility, permissions, and SBOM.
- [ ] Implement rootless container execution with read-only root, dropped capabilities, resource limits, temporary mounts, and gateway-only networking.
  - Non-executing WorkerContainmentAttestation v1 and WorkerLaunchSpec v1 preflight
    contracts now fail closed on missing controls, stale measurements, mutable image
    identity, unbounded commands/resources, runtime-socket access, and inactive gateway
    sessions. Trusted runtime measurement, actual launch/enforcement, continuous health
    checks, termination, and platform bypass verification remain required before this
    item can be completed.
- [ ] Implement structured command templates; reject arbitrary free-form flags.
- [ ] Build adapter health checks, timeout handling, output limits, and typed parsers.
- [ ] Deliver an initial low-risk official adapter set, recommended:
  - [ ] `httpx`
  - [ ] `testssl.sh`
  - [ ] `dnsx`
  - [ ] One passive subdomain adapter where program policy permits
- [ ] Pin plugin and tool versions to each assessment.
- [ ] Add staged update and revocation behavior.

### 6.13 Exit gate

- Agents cannot create policies, approvals, grants, secrets, or direct network connections.
- Malicious target content cannot cause an unauthorized tool call.
- Plugin escape, path traversal, oversized output, alternate egress, and resource-exhaustion tests pass.
- Duplicate message delivery does not duplicate external effects.
- Model outage and invalid output lead to bounded recovery or human review.
- Agent decisions remain reproducible from structured state and provenance.

## Phase 3 — Advanced Assessment Surfaces

**Duration:** 12–18 weeks<br>
**Objective:** Expand supported assessment types and network configurations through tested capabilities.

### 6.14 Actions

- [ ] Add API Agent and OpenAPI/GraphQL/gRPC-aware adapters.
- [ ] Add Authentication Agent with just-in-time secret brokerage and test-account constraints.
- [ ] Add Business Logic Agent with owned-test-data tracking and sensitive-action approvals.
- [ ] Add Recon and Asset Discovery agents with quarantine for newly discovered assets.
- [ ] Add Mobile Agent with isolated static analysis and emulator integration.
- [ ] Add Cloud Agent with typed cloud resource identities and read-only-first adapters.
- [ ] Add repository analysis for explicitly authorized repository/ref combinations.
- [ ] Add Burp Suite and OWASP ZAP adapters without creating alternate egress.
- [ ] Add VPN, authenticated proxy, local gateway, and optional cloud NAT profiles.
- [ ] Add controlled IPv6 support; retain deny-by-default when unattested.
- [ ] Add controlled callback/OAST infrastructure with explicit domain and data policies.
- [ ] Expand reporting templates and duplicate-fingerprint workflows.

### 6.15 Capability release procedure

Each capability must:

1. Define versioned input/output schemas.
2. Map to a named policy capability.
3. Define canonical target identity.
4. Define allowed and forbidden side effects.
5. Declare network, filesystem, secret, and evidence permissions.
6. Define rate, concurrency, time, data, and cost budgets.
7. Document retry safety and idempotency.
8. Pass revocation, failure, injection, and bypass tests.
9. Provide a human-readable approval explanation.
10. Be disabled by default until configured.

### 6.16 Exit gate

- Every advanced surface passes its platform-specific conformance suite.
- Cross-tenant, real-user-data, mutation, command-execution, and callback controls fail closed.
- VPN/proxy/NAT route identity is continuously attested.
- Burp/ZAP/tool integration cannot bypass PentAI grants or logging.
- Security review confirms parity across supported operating systems.

## Phase 4 — Production and Commercial Hardening

**Duration:** 12–20 weeks<br>
**Objective:** Prepare a reliable, supportable, signed production release.

### 6.17 Actions

- [ ] Complete signed Windows installers, macOS notarization, and signed Linux packages.
- [ ] Implement TUF-style signed updates with rollback and freeze protection.
- [ ] Produce release SBOMs and provenance attestations.
- [ ] Run full dependency, container, license, and vulnerability review.
- [ ] Complete database migration, upgrade, downgrade/rollback, backup, and restore tests.
- [ ] Conduct an independent application penetration test and architecture review.
- [ ] Resolve all critical/high findings or formally block release.
- [ ] Complete accessibility, keyboard navigation, localization readiness, and performance work.
- [ ] Add privacy controls, telemetry consent, data export, retention, and secure deletion.
- [ ] Create installation, onboarding, operations, troubleshooting, and incident documentation.
- [ ] Establish vulnerability disclosure, incident response, patch SLA, and plugin revocation processes.
- [ ] Run closed beta with authorized researchers using owned/sandbox targets first.
- [ ] Add production support diagnostics with automatic secret/evidence redaction.

### 6.18 Exit gate

- Independent security assessment is accepted.
- Release artifacts are signed, reproducible where practical, and include SBOM/provenance.
- Restore drills and emergency revocation drills meet targets.
- Zero known critical/high enforcement vulnerabilities remain.
- Legal/product documentation accurately describes authorization and local-host limitations.
- Release owners sign the production readiness checklist.

## 7. Dependency and Critical Path

```text
Threat model + contracts
        ↓
Canonicalization + manifest schema
        ↓
Policy compiler/evaluator + approvals
        ↓
Action grants + audit ledger
        ↓
Gateway + isolated runner + emergency stop
        ↓
Supervised vertical assessment
        ↓
Durable orchestration
        ↓
AI agents + plugin SDK
        ↓
Advanced tools/surfaces
        ↓
Production signing and hardening
```

Critical-path rules:

- Agent execution cannot precede policy and gateway enforcement.
- Broad tool integration cannot precede the plugin sandbox.
- Automatic recovery cannot resume active work before grant revocation and network re-attestation.
- “No Findings” reporting cannot ship before coverage tracking.
- Team/cloud architecture cannot start until local tenant and evidence boundaries are stable.

## 8. Initial Prioritized Backlog

### P0 — Must complete first

- [x] PRD, non-goals, and safety invariant register approved by the Product Owner,
  Security Lead, and non-independent sole-maintainer Security Reviewer.
- [x] Local-transport threat model and abuse-case inventory approved under the
  sole-maintainer security-review exception.
- [x] Monorepo, CI, quality gates, and ADR process.
- [x] Manifest v2 and authorization-critical schemas.
- [x] Canonical asset/value-object library.
- [x] Policy compiler/evaluator skeleton.
- [x] Tauri/FastAPI authenticated bootstrap.
- [x] Persistence/migration baseline.
- [x] Defer OS credential-store proof until a future durable secret exists; Product Owner and Security Lead approved the deferral.
- [x] Policy and canonicalization test corpus.

### P1 — Enables supervised execution

- [ ] Full intake and approval workflow.
- [ ] Policy signing, activation, revocation, and semantic diff.
- [ ] Action intent/decision/grant chain.
- [ ] HTTP(S) gateway and controlled DNS.
- [ ] Rootless isolated worker.
- [ ] Network/IP attestation and kill switch.
- [ ] Assessment workflow and audit ledger.
- [ ] Evidence store and finding lifecycle.
- [ ] Report export and recovery.

### P2 — Enables bounded extensibility

- [ ] Provider-neutral AI layer.
- [ ] Master Orchestrator.
- [ ] First five low-risk agents.
- [ ] Plugin SDK, verifier, and container broker.
- [ ] Initial official adapters.
- [ ] Agent/plugin UI and evaluation harness.

### P3 — Expands coverage

- [ ] API and authentication workflows.
- [ ] Recon and discovery.
- [ ] Business logic.
- [ ] Burp/ZAP.
- [ ] Mobile, cloud, and repository analysis.
- [ ] Advanced egress and callbacks.

## 9. Definition of Done

A feature is done only when:

- Product acceptance criteria are met.
- Threats and policy effects are documented.
- Schemas and migrations are versioned.
- Unit, property, integration, negative, and recovery tests pass as applicable.
- Authorization, audit, evidence, and error behavior are implemented.
- Secrets and sensitive data are classified and protected.
- UI covers loading, empty, denied, degraded, error, pause, and recovery states.
- Accessibility and keyboard operation are verified.
- Documentation and diagnostics are updated.
- Observability is sufficient to investigate failure without exposing secrets.
- A non-author reviews security-sensitive changes.

An executable capability must additionally satisfy all ten conditions in Appendix B of the architecture specification.

## 10. Testing and Verification Plan

### Continuous checks

- Formatting, linting, type checking, unit tests, schema compatibility.
- Secret, dependency, license, and static-analysis scans.
- Rust, Python, and TypeScript dependency locks.
- Plugin/image digest and SBOM verification.

### Per-merge security checks

- Policy decision golden corpus.
- Canonicalization property suite.
- Grant expiry/replay/revocation suite.
- Audit-chain verification.
- Database migration and rollback smoke tests.

### Nightly checks

- Local target-lab integration.
- DNS rebinding and redirect suite.
- Gateway bypass and IPv4/IPv6 suite.
- Crash, power-loss simulation, duplicate delivery, and disk-full tests.
- Prompt-injection and data-routing evaluations.
- Cross-platform desktop smoke tests.

### Release-candidate checks

- Full end-to-end assessment on owned targets.
- Backup/restore and upgrade drill.
- Route/IP change and emergency-stop drill.
- Malicious plugin and sandbox suite.
- Report accuracy, evidence integrity, and redaction review.
- Installer/signature/update verification.
- Manual security and accessibility review.

## 11. Metrics and Operating Targets

Track:

- Percentage of actions with complete policy and audit linkage: target 100%.
- Unauthorized-action attempts blocked before connection: target 100%.
- Policy decision p95: under 10 ms excluding DNS.
- Recovery point: no loss beyond the last committed transaction.
- Duplicate execution after recovery: zero.
- Route/IP change detection and pause: target under 5 seconds, then tighten.
- Critical approval clarity in usability testing: at least 95% correct interpretation.
- Secret leakage in logs/model traces/report fixtures: zero.
- Crash-free desktop sessions: ≥99.5% in beta, improving toward production.
- Policy corpus pass rate: 100% required for release.
- Mean time to revoke a malicious plugin: define in beta, production target under 24 hours.

Metrics never justify relaxing safety invariants.

## 12. Risk Management Actions

| Risk | Immediate action | Owner | Trigger |
|---|---|---|---|
| Policy ambiguity | Expand corpus; require exact provenance and human resolution | Security Lead | Any inconsistent decision |
| Gateway bypass | Stop releases; isolate root cause; add regression | Systems + Security | Any direct connection |
| Cross-platform control gap | Disable affected execution capability on that OS | Release Lead | Safety parity failure |
| Prompt injection | Remove exposed capability; strengthen deterministic boundary | AI + Security | Unauthorized intent or data leak |
| Plugin compromise | Revoke digest/publisher, notify users, rotate affected secrets | Security + Release | Signature/reputation alert |
| Database/evidence corruption | Stop execution, restore verified backup, preserve incident artifacts | Backend Lead | Integrity check failure |
| Public-IP mismatch | Kill sessions and pause assessment | Systems Engineer | Attestation disagreement |
| Schedule pressure | Reduce features, never enforcement scope | Product Lead | Missed milestone |

Maintain a live risk register with probability, impact, mitigation, owner, due date, residual risk, and acceptance authority.

## 13. Review Cadence

- **Daily:** workstream blockers and safety-impacting changes.
- **Weekly:** integrated demo, dependency review, risk register, architecture decisions.
- **Biweekly:** milestone acceptance and user workflow test.
- **Monthly:** threat-model delta, dependency/security posture, recovery drill.
- **Per phase:** formal exit-gate review with recorded evidence.
- **Before release:** independent security review and production readiness review.

Avoid progress reporting based only on completed tickets. Report demonstrable vertical capabilities and passed safety gates.

## 14. First 30 Days

### Week 1

- [ ] Confirm accountable humans for the recorded roles and approve MVP scope/non-goals.
- [x] Create repository structure and engineering standards.
- [ ] Open ADRs for unresolved implementation decisions.
- [ ] Run the first threat-model workshop.
- [x] Convert architecture invariants into a tracked owner/evidence/gap checklist.

### Week 2

- [x] Draft manifest v2 and policy IR v1.
- [x] Define authorization contract and local API compatibility rules.
- [x] Build the canonicalization fixture, property, differential, and malicious-input corpus.
- [x] Scaffold desktop, UI, core service, and database.
- [x] Establish Windows, macOS, and Ubuntu CI smoke builds.

### Week 3

- [x] Implement domain/wildcard/port/path/IP/URL/CIDR canonicalizers.
- [ ] Implement Program, Engagement, Source, and Manifest persistence.
- [x] Implement authenticated desktop-to-core startup.
- [ ] Prototype intake, policy conflict, approval, and safety status screens.
- [ ] Validate OS credential storage when a durable secret exists, or approve the documented deferral.

### Week 4

- [ ] Demonstrate source import with hashes and provenance.
- [x] Demonstrate deterministic allow/deny decisions without network execution.
- [x] Run property and malicious-input tests locally; record PR CI evidence when available.
- [ ] Review Phase 0 risks and architecture decisions.
- [ ] Reforecast Phase 1 using measured team velocity.

### Day-30 evidence package

- Approved PRD/non-goals.
- Threat model v1.
- Safety invariant register.
- ADR set.
- Schema and compatibility baseline.
- CI results across target platforms.
- Canonicalization corpus results.
- Working desktop/core/database demonstration.
- Updated delivery forecast and risk register.

## 15. Release Readiness Checklist

- [ ] Active policy is required for all target-facing actions.
- [ ] Deny precedence and exact scope matching are verified.
- [ ] DNS, redirect, port, SNI/Host, protocol, IPv4, and IPv6 checks pass.
- [ ] Workers have no alternate egress.
- [ ] Public source IP and route are continuously verified.
- [ ] Emergency stop revokes grants and closes sessions.
- [ ] Sensitive approvals are typed, bounded, expiring, and auditable.
- [ ] Secrets do not appear in logs, AI contexts, evidence previews, or reports.
- [ ] Evidence integrity and redaction workflows pass.
- [ ] Crash, recovery, backup, restore, and disk-full tests pass.
- [ ] Plugin signatures, digests, permissions, and isolation pass.
- [ ] Installers and updates are signed and verified.
- [ ] All critical/high security findings are resolved or release is blocked.
- [ ] User and incident documentation is complete.
- [ ] Product, Security, QA, and Release owners approve.

## 16. Deferred Items

The following are intentionally deferred until the local supervised platform is stable:

- Multi-user/team collaboration.
- Hosted SaaS control plane.
- Automatic report submission.
- Unsupervised high-impact validation.
- Unrestricted custom shell commands or tool flags.
- Automatic scope expansion.
- Cross-program private-data sharing.
- Remote runners not bound to an attested approved egress.
- Marketplace-scale third-party plugins.
- Enterprise SSO and organizational RBAC.

Deferral prevents commercial ambitions from weakening the initial enforcement model.

## 17. Immediate Next Decision

The project should begin with Phase 0 and make the policy contracts the first irreversible interface. The first implementation milestone is not “an AI agent runs a scanner.” It is:

> A user imports authoritative program material, PentAI produces a provenance-linked draft, a human approves a deterministic policy, and a comprehensive test corpus proves that ambiguous or unauthorized actions are denied.

Only after that milestone should the team permit any target-facing execution.
