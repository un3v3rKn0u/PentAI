# PentAI MVP Product Requirements

**Document ID:** PENTAI-PRD-MVP-001<br>
**Version:** 1.0.0<br>
**Status:** Product Owner and Security Lead approved<br>
**Date:** 2026-08-08<br>
**Architecture:** `PentAI_Software_Architecture.md`<br>
**Intake authority:** `design_intake_workflow.md`

This document specifies the intended MVP, including Phase 1 capabilities that are not
implemented. Phase 0 acceptance and approval status are recorded in
`docs/security/phase0_status.md` and `docs/security/phase0_approvals.md`.
Product Owner approval by `un3v3rKn0u` was recorded on 2026-08-08 with the limitations
in the approval record.
Security Lead approval by `un3v3rKn0u` was recorded on the same date; it is not an
independent security review.

## 1. Product Goal

The MVP is a local-first desktop application that helps an authorized security researcher prepare, supervise, document, and report an HTTP/HTTPS assessment without allowing AI or tools to exceed a human-approved Rules of Engagement policy.

The MVP proves the complete safety path:

```text
Authoritative sources
→ provenance-linked manifest
→ deterministic validation
→ human approval
→ signed active policy
→ supervised action intent
→ deterministic decision
→ short-lived action grant
→ controlled HTTP/HTTPS gateway
→ evidence and audit
→ human-reviewed report export
```

## 2. Target User

The first release targets one authorized security researcher working locally on one device and one active assessment at a time. The user understands HTTP testing and remains responsible for selecting programs, resolving ambiguous authorization, supervising actions, and reviewing reports.

## 3. MVP Success Criteria

The MVP succeeds when a user can:

1. Import authoritative program sources and retain their provenance and hashes.
2. Create a complete engagement manifest containing exact HTTP/HTTPS scope and restrictions.
3. Resolve validation errors and approve a deterministic compiled policy.
4. Verify the configured public source IP and controlled network path.
5. Request a supervised HTTP/HTTPS action against an approved target.
6. See an unauthorized target, technique, port, redirect, or expired action blocked before connection.
7. Capture encrypted evidence with complete policy and audit linkage.
8. Create and review a finding.
9. Export a Markdown, HTML, JSON, or PDF report without automatic submission.
10. Restart after a crash without losing committed state or repeating an external action.

## 4. Supported MVP Scope

### 4.1 Desktop and operating model

- Local desktop application for current Windows, macOS, and Ubuntu LTS.
- Tauri shell with a React/TypeScript UI.
- Local Python/FastAPI service bound only to loopback.
- SQLite database with migrations and WAL operation.
- One local user and one active assessment.
- Supervised execution only.

### 4.2 Program intake

- Create and edit programs and engagements.
- Import program text from local files, pasted content, and manually supplied URLs.
- Preserve source location, authority, retrieval time, effective date, and SHA-256 hash.
- Collect all fields required by `design_intake_workflow.md`.
- Record field-level source references and unresolved questions.
- Canonicalize domains, URLs, ports, IPv4, IPv6, and CIDRs.
- Detect missing fields, contradictions, expiry, ambiguous wildcards, and conflicting sources.
- Require human approval before policy activation.
- Retain immutable manifest and policy versions.

### 4.3 Rules of Engagement enforcement

- Deterministic Policy IR v1.
- Exact allow and deny rules for HTTP/HTTPS assets.
- Explicit wildcard apex semantics.
- Scheme, hostname, port, and path-boundary enforcement.
- Most-specific applicable deny precedence.
- Explicit allowed HTTP methods and testing windows.
- Global and per-host request-rate and concurrency limits.
- Registered public IPv4/IPv6 and approved route identity.
- Redirect and DNS reauthorization.
- Policy expiry and revocation.
- Typed, expiring approvals for conditional actions.

### 4.4 Supervised HTTP/HTTPS execution

- User or supervised assistant proposes a structured `ActionIntent`.
- The deterministic policy engine returns a `PolicyDecision`.
- Allowed actions receive a signed, short-lived, single-use `ActionGrant`.
- A controlled gateway performs DNS, destination, redirect, time, route, and rate checks.
- Requests use explicitly approved methods, headers, body size, target, and account reference.
- Responses are size and time limited.
- The user can pause or stop an assessment at any time.
- A public-IP or route-identity change immediately pauses network execution.

Initially supported methods are `GET`, `HEAD`, and `OPTIONS`. `POST`, `PUT`, `PATCH`, and `DELETE` are recognized by the contracts but disabled unless a later approved capability adds explicit side-effect controls.

### 4.5 Minimal AI assistance

- AI-assisted extraction may propose manifest fields with source references.
- AI-assisted reporting may draft text from approved, sanitized evidence.
- All AI output is treated as untrusted candidate data.
- Models cannot activate policies, issue approvals or grants, access secrets, or create network connections.
- Remote-model use is opt-in and controlled by data-classification policy.

### 4.6 Evidence and audit

- Content-addressed encrypted evidence storage.
- Immutable original evidence plus separately stored redacted derivatives.
- Supported evidence: notes, HTTP metadata, bounded response excerpts, screenshots, and imported files.
- Hash, timestamp, classification, action link, policy version, and chain of custody.
- Append-only hash-chained audit events for privileged decisions and actions.
- Evidence retention configuration and manual secure-deletion workflow.

### 4.7 Findings and reports

- Finding lifecycle from observation through human review and closure.
- Severity, CVSS, CWE, affected assets, confidence, validation status, reproduction, impact, remediation, references, and evidence links.
- Scope and RoE compliance record per finding.
- Duplicate-check status and reviewer decision.
- HackerOne-, Bugcrowd-, and Intigriti-oriented report layouts.
- Markdown, HTML, JSON, and PDF export.
- “No Findings” report with coverage, blocked/skipped areas, constraints, policy version, and testing period.
- Human approval before final export status.

### 4.8 Reliability and administration

- Durable task state, idempotency keys, leases, checkpoints, bounded retries, and dead letters.
- Safe startup recovery that revokes stale grants before work resumes.
- Encrypted backup, restore, and integrity verification.
- Structured logs with secret and sensitive-payload redaction.
- Settings for storage, retention, network route, AI provider, and report defaults.

## 5. Explicit Non-Goals

The MVP will not provide:

- Autonomous or unsupervised active scanning.
- Automatic scope expansion from discoveries, redirects, DNS, certificates, or related assets.
- Mobile application, cloud, repository, hardware, wireless, or thick-client testing.
- Social engineering, phishing, physical testing, denial of service, destructive testing, persistence, or lateral movement.
- Exploit generation, automatic exploitation, bulk data extraction, or proof beyond the minimum reporting threshold.
- Credential stuffing, password spraying, testing real-user accounts, or multi-tenant access validation.
- Raw-socket scanning, UDP testing, arbitrary ports, or non-HTTP application protocols.
- Nmap, sqlmap, nuclei, ffuf, Burp, ZAP, or other broad external-tool integration.
- Third-party plugins or a plugin marketplace.
- Arbitrary shell commands, arbitrary tool flags, or user-authored executable plugins.
- Automatic report submission to HackerOne, Bugcrowd, Intigriti, email, or other external services.
- Team collaboration, hosted control plane, SaaS operation, RBAC, SSO, or multi-user tenancy.
- Remote runners or cloud execution gateways.
- Background execution after logout or without an active supervised desktop session.
- Guaranteed protection against a malicious local administrator or compromised host operating system.
- Legal advice, authorization inference, or a guarantee that testing is lawful.

## 6. Core User Journeys

### Journey A — Intake and activation

1. User creates a Program and Engagement.
2. User imports authoritative sources.
3. PentAI hashes sources and records provenance.
4. Extraction proposes structured candidate fields.
5. User reviews conflicts, unknowns, exact scope, and operational limits.
6. Deterministic validation produces errors and warnings.
7. User resolves all blocking errors.
8. Authorized reviewer approves the manifest.
9. PentAI compiles, signs, and activates Policy IR v1.

### Journey B — Supervised action

1. User selects the active engagement and exact target.
2. PentAI verifies policy status, time, route, DNS, and public IP.
3. A structured action intent is displayed for confirmation.
4. The policy engine evaluates scope, capability, method, limits, and approval.
5. The broker issues a short-lived single-use grant.
6. The gateway executes within the grant.
7. PentAI stores bounded output, evidence, and audit linkage.
8. Any runtime mismatch blocks execution and pauses when required.

### Journey C — Finding and report

1. User promotes an observation to a finding.
2. PentAI confirms scope and known-issue/duplicate status.
3. User performs only approved minimal validation.
4. Evidence is redacted and linked.
5. User reviews severity and factual accuracy.
6. PentAI renders report formats.
7. User approves and exports; submission occurs outside PentAI.

## 7. Functional Acceptance Criteria

| ID | Requirement | Acceptance evidence |
|---|---|---|
| MVP-001 | No active policy means no action grant | Automated integration test |
| MVP-002 | Exact allowed URL succeeds within limits | Local owned-target test |
| MVP-003 | Denied host/path/port fails before connection | Gateway connection assertion |
| MVP-004 | Redirect is reauthorized | Allowed and denied redirect tests |
| MVP-005 | Mixed or changed DNS answers fail closed | Controlled DNS test |
| MVP-006 | Public-IP change pauses assessment | Route-attestation test |
| MVP-007 | Grant is expiring and single use | Replay/expiry test |
| MVP-008 | Every execution has full audit linkage | Database invariant test |
| MVP-009 | Crash does not repeat committed external action | Recovery test |
| MVP-010 | Evidence originals are immutable | Storage and API tests |
| MVP-011 | AI cannot approve, grant, or execute | Capability-boundary tests |
| MVP-012 | Report export requires reviewed state | API and UI tests |

## 8. Non-Functional Acceptance Criteria

- Authorization decision p95 under 10 ms excluding DNS on reference hardware.
- UI interactions under 100 ms for local state changes under normal load.
- No committed job loss after process termination.
- No raw secret in application logs, audit data, model traces, or report fixtures.
- Keyboard-accessible safety controls and approvals.
- Cross-platform smoke builds on Windows, macOS, and Ubuntu.
- Database integrity check and verified restore pass before release.

## 9. Release Blocking Conditions

The MVP must not ship with:

- Any known path to direct worker egress.
- Any known scope, redirect, DNS, port, or grant bypass.
- Missing audit linkage for a privileged action.
- Automatic active execution initiated solely by an AI model.
- Unresolved critical or high severity security findings.
- A platform on which network enforcement does not provide equivalent guarantees.

## 10. Deferred Roadmap Boundary

After MVP safety gates pass, the next release may add the Master Orchestrator, signed official plugins, and selected low-risk tools. Advanced surfaces and greater autonomy require separate capability reviews and cannot be activated merely by configuration.
