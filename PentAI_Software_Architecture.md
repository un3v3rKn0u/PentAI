# PentAI Software Architecture

**Status:** Architecture baseline<br>
**Version:** 1.0<br>
**Date:** 2026-08-05<br>
**Audience:** Product, security, engineering, operations, and compliance teams<br>
**Source of truth for intake:** `design_intake_workflow.md`

## 1. Executive Summary

PentAI is a local-first, cross-platform desktop application for authorized bug-bounty and vulnerability-disclosure assessments. It combines a deterministic Rules of Engagement (RoE) enforcement plane, a hierarchical AI-agent control plane, isolated tool execution, evidence management, and professional reporting.

The central architectural rule is:

> AI may propose and interpret; deterministic policy and isolated infrastructure decide and enforce.

No agent receives unrestricted network, process, filesystem, credential, or tool access. Every external action is represented as a typed `ActionIntent`, evaluated against a signed and active engagement policy, converted into a short-lived `ActionGrant`, and executed through a controlled gateway. Default deny applies to missing, ambiguous, stale, conflicting, or unverifiable authorization.

The recommended implementation is:

- Tauri 2 desktop shell with a React/TypeScript interface.
- Python 3.13 local backend using FastAPI and Pydantic.
- SQLite in WAL mode for the initial product, with SQLCipher-compatible encryption and an explicit migration path to PostgreSQL for future team/server editions.
- A durable local workflow engine based on persisted state machines and a transactional outbox, not an in-memory agent loop.
- Rootless containers for tool execution, with a restricted native-runner fallback only for platforms where containers are unavailable.
- A mandatory local egress gateway that enforces destination, DNS, rate, time, technique, and approved-source-IP controls.
- An append-only, hash-chained audit ledger and content-addressed encrypted evidence store.
- Provider-neutral AI adapters supporting local and remote models with strict data-routing rules.

The architecture deliberately separates four planes:

1. **Presentation plane** — desktop UI and local user interaction.
2. **Control plane** — orchestration, workflows, approvals, and agent state.
3. **Policy plane** — source ingestion, policy compilation, signing, and authorization.
4. **Execution plane** — sandboxed tools, controlled egress, evidence capture, and telemetry.

This separation is more complex than a monolithic desktop script, but it creates enforceable safety boundaries, crash recovery, auditability, and a credible path to a commercial product.

## 2. Functional Requirements

### 2.1 Program and intake

PentAI shall:

- Create, import, clone, archive, and version programs and engagements.
- Ingest program pages, files, pasted text, signed authorization, written clarifications, and platform rules.
- Record retrieval time, authority, effective dates, hashes, and source lineage.
- Extract candidate rules without treating AI output as authorization.
- Collect scope, exclusions, allowed techniques, limits, credentials, network constraints, testing windows, reporting rules, safe harbor, rewards, disclosure, contacts, and known issues.
- Canonicalize domains, wildcards, URLs, paths, IPs, CIDRs, API surfaces, mobile identities, repositories, cloud resources, and third-party boundaries.
- Detect contradictions, omissions, expiry, and ambiguity.
- Require human approval before activation.
- Recheck and semantically diff source changes.

### 2.2 Assessment execution

PentAI shall:

- Build assessment plans from the active signed policy.
- Run one Master Orchestrator and bounded specialist workers.
- Require an authorization decision before every external action.
- Schedule passive and active tasks within time, rate, concurrency, and technique constraints.
- Pause immediately on expiry, policy change, network-path change, stop conditions, or safety signals.
- Support manual, supervised, and bounded-execution modes.
- Recover jobs after application or machine failure.
- Prevent duplicate actions through idempotency keys and leases.

### 2.3 Evidence and findings

PentAI shall:

- Capture request/response metadata, screenshots, logs, files, notes, and tool output.
- Encrypt, hash, timestamp, classify, redact, and retain evidence according to policy.
- Link each evidence item to the exact action, policy rule, target, finding, and actor.
- Track findings through observation, scope review, duplicate review, validation, reporting, retest, and closure.
- Distinguish facts, model inference, analyst notes, and unverified hypotheses.
- Support CVSS, CWE, program-specific severity, confidence, validation status, and compliance status.

### 2.4 Reporting

PentAI shall generate HackerOne-, Bugcrowd-, and Intigriti-oriented reports plus Markdown, HTML, JSON, and PDF. It shall also generate a signed “No Findings” report stating coverage, constraints, incomplete areas, policy version, and testing period without implying absence of vulnerabilities.

Submission is always a separate, human-approved action. The initial product exports reports but does not automatically submit them.

### 2.5 Administration and extension

PentAI shall:

- Configure AI providers, local models, budgets, and data-routing policies.
- Configure tools, runtimes, network paths, callbacks, and credentials.
- Install, verify, enable, disable, update, and revoke plugins.
- Export diagnostic bundles with secret and evidence redaction.
- Support secure backup, restore, migrations, and retention.

## 3. Non-Functional Requirements

| Attribute | Initial target | Production target |
|---|---:|---:|
| Supported OS | Current Windows, macOS, Ubuntu LTS | Signed installers across major supported versions |
| Cold start | < 5 seconds on reference hardware | < 3 seconds |
| UI responsiveness | < 100 ms for local interaction | Same |
| Authorization latency | p95 < 10 ms excluding DNS | p99 < 10 ms |
| Crash recovery | No committed job loss | Recovery point ≤ 1 committed transaction |
| Audit coverage | 100% of privileged decisions/actions | Cryptographically verifiable export |
| Availability | Desktop-session availability | 99.5% for optional team services |
| Scale | 1 user, 10 active workers, 1M audit events | 50 workers/device; team-scale service later |
| Offline behavior | Intake, review, local AI, reporting | Same; external actions blocked if verification required |
| Accessibility | Keyboard navigation and WCAG-inspired desktop UI | WCAG 2.2 AA where applicable |

All sensitive local data must be encrypted at rest, and secrets must be held in the operating-system credential store. Logs must not contain raw secrets or unnecessary response bodies.

## 4. System Architecture

```text
┌──────────────────────── PentAI Desktop ────────────────────────┐
│ Tauri Shell + React UI                                         │
│   │ authenticated loopback IPC                                 │
│ Local API (FastAPI)                                            │
│   ├─ Program/Assessment/Findings/Report services                │
│   ├─ Durable Workflow + Master Orchestrator                     │
│   ├─ Agent Runtime and Provider Adapters                        │
│   ├─ Policy Compiler + Decision Point                           │
│   ├─ Approval Service + Audit Ledger                            │
│   └─ Plugin Manager                                            │
│          │ ActionIntent → ActionGrant                           │
│ Execution Broker                                               │
│   ├─ Rootless container workers                                │
│   ├─ Filesystem/evidence broker                                │
│   └─ Mandatory Egress Gateway ── VPN/Proxy ── Authorized target │
│                                                               │
│ SQLite/SQLCipher │ Encrypted CAS │ OS Keychain │ Local Queue    │
└───────────────────────────────────────────────────────────────┘
```

### 4.1 Process boundaries

- **Desktop shell:** renders UI; never holds durable secrets.
- **Core service:** single local authority for state and policy; binds to loopback only using an ephemeral port and per-launch authentication token.
- **Execution broker:** privileged mediator for containers and native runners; accepts only signed grants.
- **Egress gateway:** sole network route for worker traffic; denies direct and unresolved destinations.
- **Workers:** disposable, least-privilege processes or containers with read-only root filesystems.

The UI must not call tools directly. Agents must not call the operating system, network, or secret store directly. Plugins cannot register arbitrary in-process code in the core service.

### 4.2 Key decision record

| Decision | Why | Alternative and trade-off | Complexity | Future bottleneck |
|---|---|---|---|---|
| Tauri + React | Small installers, native security model, mature web UI ecosystem | Electron is easier to staff but heavier; Qt is cohesive Python but less flexible for modern UI | M | Rust bridge expertise |
| Python core | Best security-tool and AI ecosystem | Rust/Go improve isolation/performance but slow feature delivery | M | CPU-heavy parsing; move hotspots to Rust |
| Modular monolith | Reliable local transactions and simpler distribution | Microservices improve independent scaling but are operationally excessive on desktops | M | Team/cloud edition boundaries |
| SQLite first | Embedded, robust, zero administration | PostgreSQL adds concurrency but requires a service | M | Very large evidence metadata/audit queries |
| Durable state machines | Explicit recovery and approvals | Temporal is powerful but burdens a desktop install | H | Scheduler throughput at very large scale |
| Out-of-process plugins | Fault and privilege isolation | In-process Python plugins are simpler but unsafe | H | IPC overhead and SDK versioning |
| Mandatory egress proxy | Enforceable network policy | Application hooks are bypassable and tool-specific | H | TLS/tool compatibility |

## 5. Desktop UI Architecture

### 5.1 Shell

The visual model uses a collapsible left navigation rail, contextual top bar, central workspace, optional right inspector, bottom activity/status strip, command palette, and notification center.

```text
┌──── Nav ────┬──────── Header / breadcrumbs / global actions ───────┐
│ Dashboard   │                                                       │
│ Intake      │ Main workspace                         Inspector      │
│ Programs    │                                                       │
│ Assessments │                                                       │
│ Agents      │                                                       │
│ Evidence    ├───────────────────────────────────────────────────────┤
│ Findings    │ Network path • policy version • running jobs • alerts │
└─────────────┴───────────────────────────────────────────────────────┘
```

Global safety state—active engagement, policy version, approved egress IP, and pause status—remains visible during execution. A persistent emergency stop is keyboard accessible and requires no modal navigation.

### 5.2 Pages

| Page | Purpose and layout | Main interactions and workflow |
|---|---|---|
| Dashboard | Risk/safety banner, recent programs, active assessments, approvals, findings, health | Resume work, review blocking approvals, verify network, inspect alerts |
| Bug Bounty Intake | Stepper with source viewer left, structured fields center, provenance/conflicts right | Import → extract → normalize → resolve → validate → approve |
| Programs | Searchable table/cards with platform, dates, state, changes | Create, clone, refresh sources, compare versions, archive |
| Assessments | Timeline/kanban, plan tree, coverage matrix, live controls | Create plan, approve phases, start/pause/stop, resume recovery |
| AI Agents | Orchestrator graph, worker cards, task queues, budgets, messages | Inspect rationale, reassign/cancel tasks, approve requests; no free-form privilege elevation |
| Evidence | Filterable gallery/table with chain-of-custody inspector | Preview sanitized evidence, classify, redact, link, export, enforce retention |
| Findings | Table/board and finding editor with validation/duplicate panels | Triage, merge, validate, score, approve |
| Reports | Template picker, live preview, completeness/compliance checks | Generate, edit, approve, export; submission stays manual |
| Logs | Structured event stream and policy-decision explorer | Filter by action/rule/agent, verify ledger, export diagnostics |
| Settings | General, storage, retention, updates, accessibility | Configure safe application defaults |
| AI Configuration | Provider cards, model roles, privacy, token/cost budgets, evaluation | Test provider, choose local/remote routing, rotate credentials |
| Tool Configuration | Tool catalog, versions, health, permissions, images | Install approved adapters, pin versions, run non-network self-tests |
| Plugins | Trust status, signatures, permissions, compatibility | Review manifest, install, enable, revoke, update |

### 5.3 UX safety controls

- Red means blocked or stopped, never merely “interesting.”
- Approvals show exact target, technique, impact, policy rule, expiry, and proposed evidence.
- Destructive or sensitive actions cannot be batch approved.
- Raw AI rationale is not presented as proof; the UI shows structured decision facts.
- Changing policy while an assessment runs pauses affected jobs.
- Closing the window does not silently terminate jobs; the user chooses background, pause, or stop.

## 6. Intake Workflow Review

### 6.1 What remains unchanged

The source workflow’s default-deny authorization chain, exact scope matching, source provenance, precedence rules, semantic validation, safe validation ladder, duplicate checks, finding lifecycle, human checkpoints, and append-only audit requirements remain normative.

### 6.2 Recommended improvements

| Current design | Improvement | Reason | Trade-off |
|---|---|---|---|
| One reusable manifest | Separate `SourceBundle`, `DraftManifest`, compiled `PolicyBundle` | Prevent extracted text from being confused with enforceable policy | More versioned artifacts |
| `allowed_tools` list | Capability-level grants such as `network.http.get` | Tool names do not describe behavior or impact | Adapter authors must map capabilities |
| Asset allow/deny entries | Typed asset matcher with explicit wildcard/apex/path/port semantics | Avoid inconsistent matching across tools | More compiler/test work |
| Registered source IP list | Egress route identity and continuous attestation | A configured IP is not proof that traffic uses it | Requires gateway/VPN integration |
| Generic approvals | Typed, expiring, single-purpose approval records | Prevent approval reuse and ambiguity | More user prompts |
| Hashes and append-only log | Signed policy bundle plus hash-chained audit ledger | Adds tamper evidence and reproducibility | Key lifecycle management |
| Known-issue fingerprints | Privacy-aware local similarity index with human decision | Improves duplicate screening without automatic rejection | False matches require review |
| Source recheck schedule | Source adapters with semantic diff and change impact analysis | Pauses only affected actions quickly | Website changes may be noisy |

### 6.3 Additional intake fields

Add:

- Authorization jurisdiction, legal entity, researcher identity, and applicable platform account.
- Wildcard apex behavior and DNS rebinding policy per asset.
- IPv4/IPv6 treatment, proxy/VPN identity, DNS resolver, and callback allowlist.
- Per-endpoint and global rate windows, cooldown behavior, and platform-wide quotas.
- Allowed HTTP methods, protocol upgrades, WebSockets, GraphQL introspection, and file-size limits.
- Data classification, residency, model-provider routing, retention, secure deletion, and export constraints.
- Mobile package/bundle ID, signer fingerprint, store/source, version/build, device/root restrictions.
- Repository owner/name/ref, permitted branches, CI restrictions, and secret-handling rules.
- Cloud provider, account/subscription/project, region, resource ARN/ID pattern, and tenant boundary.
- Supply-chain/vendor ownership and explicit shared-service permission.
- OAST/callback domains, approved provider, payload/data restrictions, and expiry.
- Automation window, maximum total requests, spend/token budget, and emergency kill contact.
- Report encryption, permitted recipients, attachments, and coordinated disclosure dates.

### 6.4 Activation gates

The compiler emits errors (cannot activate), warnings (review required), and informational notes. Activation requires schema validity, semantic consistency, at least one exact allowed asset, usable limits, active authorization, source provenance, network-route verification, data rules, stop process, and signatures from required roles.

## 7. Agent Architecture

### 7.1 Hierarchy

The **Master Orchestrator** is the only component permitted to create worker tasks. It does not itself bypass the action broker. Workers produce structured observations and intents; they do not delegate.

Common agent envelope:

```json
{
  "task_id": "uuid",
  "assessment_id": "uuid",
  "policy_version": "sha256",
  "objective": "bounded statement",
  "inputs": [{"type": "artifact_ref", "id": "uuid"}],
  "capabilities": ["evidence.read_sanitized"],
  "limits": {"deadline": "RFC3339", "max_steps": 20, "token_budget": 12000},
  "output_schema": "schema URI",
  "idempotency_key": "stable value"
}
```

### 7.2 Agent catalog

| Agent | Responsibilities / inputs → outputs | Permissions and tools | Forbidden actions / retry | Context and memory |
|---|---|---|---|
| Master Orchestrator | Policy, coverage, findings, queues → plans, tasks, approvals, stop decisions | Task/state APIs, policy queries; no direct target access | Cannot grant itself permission; retry orchestration 3x then DLQ | Large context; persisted plan graph and summaries |
| Scope Agent | Sources, draft assets → canonical candidates/conflicts | Parsers, DNS metadata through guarded passive capability | No scope approval/inference; deterministic retries only | Medium; source excerpts plus matcher results |
| RoE Agent | Sources, schema → extracted candidate rules/questions | Document parsing and policy lint | Cannot activate policy; retry model twice with alternate parser | Large; provenance-linked working set |
| Recon Agent | Approved passive plan → observations/candidates | Passive adapters and granted network capabilities | No active validation or automatic scope expansion; bounded backoff | Medium; asset summary and prior observations |
| Asset Discovery Agent | Approved seeds → discovered candidate assets | DNS/cert/search adapters | Discovered assets remain denied; max 2 transient retries | Medium; discovery graph |
| Web Agent | Approved URLs/techniques → observations and candidate findings | Browser/HTTP adapters through broker | No unrestricted payload generation, redirects, or real-user exploration | Large; sanitized page/API summaries |
| API Agent | API specs/endpoints → coverage and candidates | HTTP/GraphQL/gRPC adapters as policy permits | No unapproved mutation or bulk enumeration | Large; schema chunks with retrieval |
| Authentication Agent | Test accounts/rules → auth-flow observations | Secret handles, browser/HTTP broker | Never expose credentials or use real accounts; sensitive steps need approval | Medium; ephemeral secret use, durable redacted state |
| Business Logic Agent | Workflows/test data → hypotheses and minimal plans | State/model analysis; brokered interactions | No financial/destructive action; no cross-tenant proof without approval | Large; workflow graph and owned-data ledger |
| Cloud Agent | Explicit cloud resources → configuration observations | Provider read-only adapters if granted | No neighbor enumeration, mutation, or credential pivot | Large; resource graph |
| Mobile Agent | Approved app/build → static/dynamic observations | Isolated emulator/static-analysis adapters | No unrelated app/device data or production account abuse | Large; indexed artifacts |
| Evidence Agent | Action outputs → classified/redacted evidence | Evidence write, hash, redact | Cannot delete or alter originals; retry storage 3x then stop | Small; metadata only |
| Validation Agent | Candidate/policy/evidence → validation plan/status | Read evidence, propose ActionIntents | No self-approval or escalation beyond ladder | Large; finding-centered bundle |
| Reporting Agent | Validated findings/template → report drafts | Sanitized evidence and report rendering | No submission or unsupported claims | Large; retrieval over approved evidence |
| Documentation Agent | Events/coverage → notes, no-findings draft | Read sanitized state | Cannot change facts, policy, or findings | Medium; assessment summaries |

Agents are instantiated only when assessment content requires them. A mobile worker is not loaded for a web-only program.

### 7.3 Prompt design

Every system prompt contains immutable role, allowed output schema, policy-summary reference, default-deny instruction, prompt-injection handling, escalation conditions, and prohibited behaviors. Engagement text and target responses are delimited as untrusted data. Tool descriptions are capability-scoped and generated from grants, not from all installed tools.

Prompts use:

- Stable system layer controlled by PentAI.
- Signed policy summary rendered from deterministic data.
- Bounded task layer from the orchestrator.
- Retrieved, provenance-tagged evidence.
- Untrusted-content envelope with no authority.
- Strict JSON output validated before persistence or execution.

### 7.4 Memory strategy

- **Working memory:** ephemeral model context for one task.
- **Task memory:** persisted structured state, checkpoints, and summaries.
- **Assessment memory:** scoped observations, evidence references, coverage, and decisions.
- **Program memory:** approved policy versions, known issues, and historical findings.
- **Global knowledge:** product documentation and public references; never private engagement data by default.

Vector search is advisory only. Authorization always queries normalized relational/policy data. Secrets never enter vector stores. Memory has engagement and data-classification ACLs, retention, provenance, and deletion workflows.

## 8. Communication Protocols

All internal messages use versioned JSON/Protobuf-compatible schemas. Required fields include message ID, correlation ID, causation ID, actor, assessment, policy version, timestamp, expiry, payload schema, sensitivity, and signature/MAC where crossing a trust boundary.

Core message types:

- `TaskRequested`, `TaskLeased`, `TaskHeartbeat`, `TaskCheckpointed`, `TaskCompleted`, `TaskFailed`
- `ActionIntent`, `PolicyDecision`, `ApprovalRequested`, `ApprovalGranted`, `ActionGrant`
- `ExecutionStarted`, `ObservationRecorded`, `EvidenceStored`, `StopTriggered`
- `FindingProposed`, `FindingValidated`, `ReportGenerated`
- `PolicyChanged`, `GrantRevoked`, `AssessmentPaused`

Delivery is at least once. Consumers must be idempotent. A transactional outbox commits domain changes and events together. Leases use monotonic deadlines; heartbeats do not prove success. Large content travels by artifact reference, not inside queue messages.

## 9. Data Model

Primary aggregates:

- `Program` owns authoritative source history and reusable configuration.
- `Engagement` owns time-bound authorization and compiled policy versions.
- `Assessment` owns plans, tasks, coverage, observations, findings, and reports.
- `PolicyBundle` is immutable, signed, and content addressed.
- `Action` links intent, decision, approval, grant, execution, and audit events.
- `EvidenceObject` has immutable encrypted content and mutable classification/redaction derivatives.
- `Finding` is a versioned case record, not an agent chat artifact.
- `Plugin` and `ToolAdapter` define capabilities and execution constraints.

Every mutable aggregate uses optimistic concurrency (`version`) and timestamps. Security-sensitive records are soft-retired but not silently overwritten. Secret values are represented only by `SecretRef`.

## 10. Database Schema

Recommended logical tables:

```text
programs(id, name, platform, url, status, created_at, version)
source_documents(id, program_id, authority, uri, retrieved_at, effective_at,
                 content_hash, encrypted_blob_ref, metadata_json)
engagements(id, program_id, status, effective_from, expires_at, timezone, version)
manifest_versions(id, engagement_id, schema_version, document_json, content_hash,
                  created_at, supersedes_id)
policy_bundles(id, manifest_version_id, compiler_version, policy_json, hash,
               signature, signer_key_id, activated_at, revoked_at)
assets(id, policy_bundle_id, type, canonical_value, matcher_json, effect, priority)
technique_rules(id, policy_bundle_id, capability, effect, conditions_json)
limit_rules(id, policy_bundle_id, dimension, scope_key, window_ms, value)
approvals(id, type, subject_ref, constraints_json, approver, expires_at, signature)
assessments(id, engagement_id, policy_bundle_id, status, started_at, ended_at)
plans(id, assessment_id, graph_json, version)
tasks(id, assessment_id, parent_id, agent_type, state, lease_until, attempt,
      input_refs_json, checkpoint_json, idempotency_key UNIQUE)
action_intents(id, task_id, target_json, capability, parameters_hash, impact, created_at)
policy_decisions(id, intent_id, outcome, rule_refs_json, reason_codes_json, decided_at)
action_grants(id, intent_id, decision_id, token_hash, constraints_json, expires_at, used_at)
executions(id, grant_id, runner_id, state, started_at, ended_at, exit_code, metrics_json)
observations(id, execution_id, type, facts_json, confidence, provenance_json)
evidence_objects(id, assessment_id, sha256, storage_ref, size, media_type,
                 classification, encryption_key_ref, created_at)
evidence_links(id, evidence_id, subject_type, subject_id, relation)
findings(id, assessment_id, state, title, severity, cvss_json, cwe, confidence, version)
finding_versions(id, finding_id, document_json, author_type, created_at)
duplicate_checks(id, finding_id, result, candidates_json, reviewer, created_at)
reports(id, assessment_id, format, template_id, state, artifact_ref, hash, approved_by)
plugins(id, plugin_id, version, publisher, manifest_json, signature_status, state)
audit_events(seq INTEGER PRIMARY KEY, event_id UNIQUE, timestamp, actor, action,
             subject_ref, data_json, previous_hash, event_hash, signature)
outbox(id, aggregate_type, aggregate_id, event_type, payload_json, published_at)
dead_letters(id, source, payload_ref, reason, attempts, created_at, resolved_at)
```

Indexes cover assessment/state, active policy, canonical assets, task leases, finding fingerprints, evidence hashes, and audit timestamps. JSON is used for extensible data; authorization-critical fields are normalized and indexed.

SQLite uses WAL, foreign keys, `FULL` synchronous mode for security transactions, periodic integrity checks, bounded WAL checkpoints, and online encrypted backups. Large evidence is never stored as database BLOBs.

## 11. API Design

The local API is versioned under `/api/v1`, loopback-only, protected by a per-launch token and origin checks. Tauri commands may later replace HTTP for selected UI operations, but the domain API remains transport independent.

Representative endpoints:

```text
POST   /programs
POST   /programs/{id}/sources
POST   /engagements/{id}/manifests/extract
POST   /engagements/{id}/manifests/{version}/validate
POST   /engagements/{id}/policies/compile
POST   /engagements/{id}/policies/{id}/approve
POST   /engagements/{id}/policies/{id}/activate
POST   /assessments
POST   /assessments/{id}/plan
POST   /assessments/{id}/start
POST   /assessments/{id}/pause
POST   /assessments/{id}/stop
GET    /assessments/{id}/events
POST   /tasks/{id}/intents
POST   /approvals/{id}/decide
GET    /evidence/{id}/metadata
POST   /evidence/{id}/redactions
POST   /findings/{id}/validate
POST   /reports
POST   /reports/{id}/approve
POST   /reports/{id}/export
```

Mutating requests require `Idempotency-Key`; updates require `If-Match` or an expected version. Errors use stable problem-detail codes. Event streaming uses Server-Sent Events initially; WebSocket is reserved for interactive terminal/browser streams.

Internal action authorization is not exposed to arbitrary UI clients. The execution broker verifies signed, audience-bound, single-use grant tokens and reports the measured destination, route, and output digest.

## 12. Plugin Architecture

### 12.1 Package and contract

A plugin is a signed archive containing:

```text
plugin.yaml
schemas/
adapter executable or OCI image reference
health checks
output parsers
permission rationale
SBOM
signature and publisher chain
```

The manifest declares identity, semantic version, SDK/API range, platform/architecture, capabilities, container image digest, command template, input/output schemas, required mounts, network mode, resource limits, licenses, and update source.

Tools such as Nmap, Amass, Subfinder, httpx, Katana, ffuf, nuclei, dnsx, Naabu, Burp Suite, ZAP, sqlmap, testssl.sh, feroxbuster, and Gobuster are adapters—not trusted core components. Each adapter maps safe structured inputs to pinned tool arguments and parses output back into typed observations. User-supplied arbitrary flags are rejected unless a policy-controlled expert mode explicitly permits them.

### 12.2 Isolation

- Default: rootless OCI container, read-only root, dropped capabilities, no host PID/IPC, no Docker socket, bounded CPU/memory/processes, temporary workspace, and gateway-only network.
- Native fallback: signed executable under a low-privilege child process with OS sandboxing and equivalent broker rules.
- Burp and ZAP integrate through explicit proxy/API adapters and isolated project files; they do not become alternate ungoverned egress paths.

### 12.3 Supply-chain lifecycle

Verify publisher signature, archive digest, image digest, SBOM, compatibility, and revocation before enabling. Pin every assessment to plugin/tool versions. Updates are staged and health-tested; active assessments do not change versions silently.

WASM/WASI is a future option for pure transforms, but unsuitable as the only runtime because many security tools require native networking and binaries.

## 13. Rules of Engagement Engine

### 13.1 Pipeline

```text
Sources → AI-assisted extraction → Draft manifest → Deterministic normalization
→ Conflict/completeness checks → Human approval → Policy compilation
→ Signature/activation → Runtime decision point → Enforcement gateway
```

AI extraction produces candidates with exact source spans and confidence. It never directly writes an active allow rule. The deterministic compiler rejects unknown schema fields in critical sections, ambiguous wildcards, invalid networks, contradictory effects, missing limits, expired approvals, and unresolved critical questions.

### 13.2 Canonical matching

- Domains use IDNA normalization, lowercase, and no trailing dot.
- Wildcards have explicit `include_apex`; label-boundary matching prevents suffix tricks.
- URLs normalize scheme, host, effective port, percent encoding, dot segments, and path boundaries.
- IP/CIDR matching uses parsed binary networks, with most-specific deny precedence.
- DNS is resolved through the controlled resolver; all returned addresses must satisfy policy and are pinned for the action.
- Redirects, SNI, Host headers, alternate ports, CNAME chains, and protocol upgrades are reauthorized.
- IPv4-mapped IPv6, NAT64, link-local, private, multicast, metadata, and loopback ranges are handled explicitly.
- Mobile, cloud, repository, and tenant matchers use typed identities, not free text.

### 13.3 Decision algorithm

For each `ActionIntent`:

1. Verify active assessment and exact policy hash.
2. Check authorization time, testing window, revocation epoch, and clock health.
3. Canonicalize target and reject ambiguity.
4. Apply most-specific deny, then explicit allow; absence is deny.
5. Evaluate capability/technique and asset applicability.
6. Verify account, environment, tool, plugin, and validation-depth constraints.
7. Reserve rate, concurrency, total-request, cost, and data budgets atomically.
8. Verify typed human approval if conditional.
9. Check network-route health and source-IP attestation.
10. Check known-issue/duplicate gate and current stop conditions.
11. Issue a short-lived, signed, audience-bound, single-use grant.

The gateway repeats destination, DNS, port, protocol, route, time, and rate checks at execution. A grant is necessary but not sufficient if runtime facts differ.

### 13.4 Policy technology

Use a small PentAI policy intermediate representation and a deterministic evaluator in the core. Cedar is a strong future candidate for principal/resource/action authorization; OPA/Rego is powerful but adds runtime/distribution complexity and makes typed asset semantics harder to control. The initial custom IR must remain narrow, versioned, side-effect free, exhaustively tested, and replaceable behind a decision API.

### 13.5 Formal safety invariants

- No active policy, no execution.
- No exact allowed asset, no network connection.
- A deny always overrides an allow at equal or greater specificity.
- Agents cannot mint grants, approvals, policies, or secret values.
- Every execution maps to one intent, decision, policy version, and grant.
- Any route uncertainty, policy change, expiry, or clock failure fails closed.
- Evidence cannot authorize a later action.

## 14. Assessment Workflow

```text
Draft intake → Sources verified → Manifest normalized → Human approval
→ Policy activated → Network attested → Assessment planned → Phase approval
→ Bounded execution ↔ Checkpoint/observe/evidence
→ Candidate finding → Scope + duplicate check → Safe validation ladder
→ Human review → Report / No Findings report → Export → Retest → Close
```

Assessment phases are passive discovery, surface mapping, targeted testing, minimal validation, reporting, and optional retest. Each phase has entry/exit criteria, budget, coverage map, and approval policy.

Discovery never expands scope automatically. Candidate assets enter a quarantine list for human review. Coverage records attempted, completed, blocked, skipped, failed, and not-applicable states so a “No Findings” report is honest about limitations.

Emergency stop revokes grants, closes gateway sessions, stops workers, checkpoints safe state, preserves minimal logs, and surfaces contact instructions. Resumption requires a fresh policy/network check and explicit user action.

## 15. Fault Tolerance

### 15.1 Mechanisms

- Persist the plan before dispatch and checkpoint after meaningful steps.
- Lease tasks; reclaim only after lease expiry and worker fencing.
- Retry identities are immutable, predecessor-chained coordination records. Under retry
  policy v2, attempt three is derived only from the exact second retry-consumption
  receipt and is the closed ceiling; registration alone cannot schedule, activate,
  transition, lease, dispatch, or authorize an effect.
- Attempt-three scheduling derives timing only from the immutable retry decision and
  remains inert; a separate reviewed consumer is required before any readiness change.
- Heartbeats indicate liveness, while idempotency keys prevent duplicate effects.
- Use exponential backoff with jitter only for classified transient failures.
- Circuit-break failing AI providers, tools, source sites, and network routes.
- Move exhausted or malformed work to a dead-letter queue with a safe review path.
- Commit domain state and outbox events atomically.
- Use single-use grants so replayed execution fails.
- Resume tools only when their adapters declare a safe checkpoint protocol; otherwise restart the bounded task.

### 15.2 Failure matrix

| Failure | Response |
|---|---|
| UI crash | Core continues only if user selected background execution; reconnect from persisted state |
| Core crash/power loss | SQLite recovery, ledger verification, revoke stale grants, reclaim expired leases |
| Worker/tool crash | Capture diagnostics, classify retry safety, restart within attempt limit |
| Network/VPN failure | Gateway closes sessions and pauses network tasks; no direct fallback |
| Public IP change | Immediate global network pause and incident event |
| AI timeout/rate limit | Retry boundedly, switch only to policy-approved provider/model, checkpoint |
| AI invalid output | Schema reject, repair pass once, alternate model once, then human queue |
| Database corruption | Stop execution, restore latest verified backup, replay valid audit/outbox tail where possible |
| Disk full | Stop new evidence/actions, preserve database integrity, notify user |
| Policy source changes | Revoke affected grants, pause impacted tasks, compile and approve new version |

Backups are encrypted, integrity-checked, rotated, and restore-tested. “Automatic recovery” never means automatically resuming potentially impactful network activity after uncertainty.

## 16. Security Architecture

### 16.1 Trust boundaries and least privilege

The UI, core, AI provider, plugin, runner, target, source documents, evidence, and update service are separate trust zones. Each receives the minimum capabilities required. Workers get opaque artifact and secret handles, never database access.

### 16.2 Secrets

Use macOS Keychain, Windows Credential Manager/DPAPI, and Linux Secret Service. A local envelope-encryption key protects database fields and evidence keys. Secret material is delivered just in time to a brokered action, masked from logs, never sent to models unless explicitly allowed, and revoked on assessment closure.

### 16.3 Prompt injection

- Treat program pages, target content, tool output, documents, and evidence as untrusted data.
- Never expose policy mutation, approvals, shell, filesystem, or unrestricted network tools to models.
- Use typed tool calls with deterministic validation.
- Separate trusted instructions from retrieved content.
- Detect suspicious instruction-like content and annotate it; do not rely on detection alone.
- Minimize retrieved context and strip active content.
- Require deterministic authorization after model output.

### 16.4 Evidence integrity and privacy

Evidence is content addressed with SHA-256, encrypted per object, and linked to the audit ledger. Originals are immutable; redactions create derived objects. Exports contain a manifest of hashes and chain-of-custody events. Previews are sandboxed and active content disabled.

### 16.5 Network architecture and approved public IP

All runner containers attach only to an internal network whose default route is the PentAI egress gateway. Host-level firewall rules deny worker identities direct outbound access.

Supported routes:

1. **Static-IP VPN:** recommended for individuals; WireGuard/OpenVPN tunnel with full-tunnel routes and provider/residential static address.
2. **Local gateway appliance:** PentAI routes through a managed router or VM with a static public IP.
3. **Authenticated forward/SOCKS proxy:** acceptable when the program registers the proxy egress; gateway prevents proxy bypass.
4. **Cloud NAT gateway:** optional remote execution gateway with reserved IP; introduces custody, latency, cost, and program-rule concerns.

At startup and continuously:

- Verify the tunnel/interface, routes, resolver, external IPv4 and IPv6 through at least two approved attestation endpoints.
- Compare results to the active policy.
- Resolve DNS through the approved tunnel resolver; block port 53/853 and unauthorized DoH/DoT.
- Disable IPv6 for the worker network unless an approved IPv6 egress is configured and attested.
- Use a kill switch: loss/change closes connections and pauses all network actions.
- Log route identity, interface, resolver, public IP, destination IP, SNI/host, policy decision, and timestamps without logging secrets.

Tools that attempt raw sockets require an explicit capability and still run inside a network namespace routed through the gateway. Where a tool cannot operate through the controlled route, it is unavailable—not granted a bypass.

### 16.6 Updates and plugins

Use TUF-style signed metadata with threshold/root key rotation, rollback/freeze protection, pinned channels, and staged rollout. Verify application and plugin signatures before execution. Generate SBOMs, scan dependencies/images, pin lockfiles and digests, and define a vulnerability-response SLA.

### 16.7 Tenant isolation

The local edition isolates engagements by database authorization, per-engagement encryption keys, artifact namespaces, model-routing policies, and container workspaces. A future team edition requires separate tenant databases or strong row-level security, tenant-scoped KMS keys, queues, object prefixes, and independently verified authorization.

## 17. Deployment Strategy

### 17.1 Desktop distribution

- Build reproducibly in CI for Windows x64/ARM64, macOS universal, and Linux x64/ARM64 as support permits.
- Sign Windows binaries, notarize/sign macOS apps, and provide signed AppImage/deb/rpm packages.
- Bundle the Python service in a controlled runtime; do not depend on system Python.
- Detect Docker/Podman/rootless runtime during onboarding and clearly degrade to non-execution mode if safe isolation is unavailable.
- Store application data in OS-standard directories with configurable encrypted evidence storage.

### 17.2 Editions

- **Local Community/Professional:** all core services on one device.
- **Team (future):** desktop client plus self-hosted control/data services; runners remain near approved egress.
- **Managed commercial (future):** only after tenant isolation, regional data controls, enterprise identity, audited operations, and explicit program compatibility.

Remote execution is never silently enabled because it changes the testing source IP and evidence custody.

## 18. Technology Stack

| Layer | Recommendation |
|---|---|
| Desktop | Tauri 2, Rust stable |
| UI | React, TypeScript, Vite, TanStack Query/Router, Zustand, accessible component primitives |
| Local API | Python 3.13, FastAPI, Pydantic v2, Uvicorn |
| Domain/data | SQLAlchemy 2, Alembic, SQLite WAL; SQLCipher-compatible encryption |
| Workflows | Explicit Python state machines, persisted tasks, transactional outbox |
| Validation | JSON Schema 2020-12 plus custom typed canonicalizers |
| Containers | Docker/Podman rootless OCI, platform-specific sandbox fallback |
| Gateway | Rust or Go service for low-level proxy/DNS/rate enforcement |
| Evidence | Encrypted content-addressed filesystem store |
| AI | Provider adapter interface; local llama.cpp/Ollama-compatible and approved remote APIs |
| Observability | OpenTelemetry, structured JSON logs, local metrics |
| Reporting | Jinja2/Markdown, Playwright or WeasyPrint PDF pipeline |
| Testing | Pytest, Hypothesis, Playwright, Vitest, cargo test, Testcontainers |
| Packaging | uv/locked Python deps, pnpm, Cargo, signed CI artifacts |

Rust is preferred for the gateway because this small, security-critical component benefits from memory safety and predictable concurrency. Keeping business logic in Python preserves delivery speed.

## 19. Project Structure

```text
pentai/
├── apps/
│   ├── desktop/                 # Tauri shell
│   └── ui/                      # React application
├── services/
│   ├── core/                    # FastAPI composition root
│   ├── gateway/                 # mandatory egress/DNS enforcement
│   └── execution-broker/
├── packages/
│   ├── domain/                  # entities, value objects, state machines
│   ├── policy/                  # IR, compiler, evaluator, canonicalizers
│   ├── agents/                  # prompts, schemas, orchestrator, workers
│   ├── workflows/               # durable job logic
│   ├── evidence/
│   ├── reporting/
│   ├── audit/
│   ├── ai-providers/
│   ├── plugin-sdk/
│   └── api-contracts/
├── plugins/
│   ├── official/                # tool adapters
│   └── fixtures/
├── schemas/
│   ├── engagement/
│   ├── policy/
│   ├── messages/
│   └── reports/
├── migrations/
├── tests/
│   ├── unit/
│   ├── property/
│   ├── integration/
│   ├── security/
│   ├── recovery/
│   └── e2e/
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   ├── decisions/
│   └── operations/
├── packaging/
└── tools/
```

Dependency direction is inward: UI and adapters depend on application/domain contracts; the domain never imports FastAPI, databases, AI SDKs, or tool implementations.

## 20. Development Roadmap

### Phase 0 — Foundations (4–6 weeks)

- Threat model, architecture decision records, monorepo, CI, schemas, domain model.
- Intake manifest v2 and deterministic canonicalization/matcher test suite.
- Desktop shell, local API authentication, encrypted storage proof of concept.

Exit: malicious/ambiguous scope corpus fails closed; signed policy round-trip works.

### Phase 1 — Safe MVP (8–12 weeks)

- Complete intake UI, sources/provenance, validation, approvals, policy compiler.
- Programs, assessments, evidence, findings, logs, Markdown/HTML/JSON/PDF reports.
- Manual tasks and one supervised HTTP/browser worker.
- Mandatory gateway for HTTP(S), route/IP attestation, pause/stop.
- Durable task state, audit ledger, backup/restore.

Exit: end-to-end supervised assessment against an owned test environment with no direct egress.

### Phase 2 — Tool and agent platform (10–14 weeks)

- Master Orchestrator and initial Scope, RoE, Web, Evidence, Validation, Reporting agents.
- Plugin SDK and signed official adapters for a small low-risk tool set.
- Container broker, capability permissions, queues, checkpoints, circuit breakers.
- Known-issue index and coverage/no-findings reporting.

Exit: recovery, policy bypass, plugin isolation, and rate-limit suites pass.

### Phase 3 — Advanced surfaces (12–18 weeks)

- API, authentication, business-logic, mobile, cloud, and repository workflows.
- VPN/proxy/NAT profiles, IPv6, controlled callbacks, Burp/ZAP integration.
- Provider routing, local models, evaluation harness, cost/privacy controls.

Exit: platform-specific conformance and red-team review complete.

### Phase 4 — Production/commercial hardening (12–20 weeks)

- Signed installers/updates, SBOM, telemetry consent, accessibility/localization.
- External security assessment, incident response, support tooling, migration testing.
- Enterprise policy, team architecture prototype, SSO/RBAC only if team edition proceeds.

Estimates assume a cross-functional team of 6–9. A smaller team should reduce surface area, not weaken the gateway or policy boundary.

## 21. Testing Strategy

### 21.1 Test pyramid

- Unit tests for domain transitions, schema rules, grants, budgets, and adapters.
- Property-based tests for domains, IDNA, URL paths, CIDRs, redirects, IPv4/IPv6, and deny precedence.
- Differential tests against independent URL/IP parsers.
- Integration tests with local target labs, fake DNS, proxy, VPN, AI, and tool processes.
- End-to-end desktop tests for intake, approval, execution, crash/restart, findings, and reports.
- Golden tests for policy compilation, source diffs, plugin outputs, and report formats.
- Mutation/fuzz tests for policy inputs, IPC, parsers, plugin manifests, and evidence viewers.

### 21.2 Mandatory security scenarios

- Prompt content attempts to alter policy or invoke tools.
- DNS rebinding, CNAME changes, redirect to denied host, mixed allowed/denied IP answers.
- Host/SNI mismatch, encoded paths, alternate ports, IPv4-mapped IPv6, proxy bypass.
- Expired/replayed grants, clock rollback, policy revocation mid-connection.
- Malicious plugin, oversized output, symlink/path traversal, container escape attempts.
- Secrets in logs/model prompts/reports and unsafe active-content previews.
- Power loss during database/evidence writes and disk-full recovery.
- Duplicate worker delivery and retry of non-idempotent actions.

### 21.3 Quality gates

No release if a known policy bypass exists. Security-critical modules require two-person review, branch protection, dependency and secret scanning, signed builds, coverage thresholds focused on decisions rather than line count, and periodic independent penetration tests. Maintain a reference corpus of real program-rule patterns with sensitive data removed.

## 22. Risks

| Risk | Impact | Mitigation | Residual concern |
|---|---|---|---|
| LLM misinterprets rules | Unauthorized testing | Candidate-only extraction, provenance, deterministic compile, approval | Human review quality |
| Tool bypasses gateway | Wrong target/source IP | Network namespace, firewall, broker, route attestation | Host compromise/admin tampering |
| Program rules change | Stale authorization | Scheduled source diff, grant revocation, session recheck | Source adapters may miss gated changes |
| Plugin supply-chain compromise | Code execution/data loss | Signatures, pinned digests, SBOM, isolation, revocation | Container-runtime vulnerabilities |
| Prompt injection | Agent manipulation/data leak | Untrusted-data boundary, least privilege, typed calls | Model output remains untrusted |
| Local device compromise | Evidence/secret theft | OS security, encryption, keychain, auto-lock | Compromised logged-in account |
| SQLite corruption/scale | Lost state/slow UI | WAL, integrity checks, backups, archival | Very large long-running programs |
| VPN/DNS/IPv6 leak | RoE breach | Full-tunnel kill switch, controlled DNS, IPv6 deny by default | Platform-specific networking bugs |
| False-positive validation | Bad reports/unnecessary impact | Validation ladder, evidence requirements, human review | Expert judgment remains necessary |
| Excess agent autonomy | Runaway cost/actions | Budgets, maximum depth/runtime, grants, emergency stop | Complex plans may stall |
| Evidence privacy breach | Legal/reputational harm | Minimize, encrypt, classify, redact, retention | Screenshots and raw tool output |
| Cross-platform inconsistency | Unequal safety guarantees | Capability matrix and conformance tests | Native sandbox parity |

The largest architectural risk is pretending a desktop application can be secure against a malicious local administrator. PentAI protects against mistakes, untrusted content, plugins, tools, and ordinary compromise boundaries; it cannot guarantee enforcement after the host OS or PentAI binaries are deliberately subverted. The UI and documentation must state this clearly.

## 23. Future Improvements

- Cedar/OPA evaluation after the custom IR stabilizes and conformance fixtures exist.
- Formally modeled policy invariants using TLA+ or Alloy.
- Hardware-backed signing and evidence timestamping.
- Reproducible remote runners bound to attested egress gateways.
- Privacy-preserving duplicate matching across a user’s programs.
- Team collaboration with four-eyes approvals and independently scoped tenants.
- Enterprise connectors for program platforms, ticketing, and evidence repositories.
- Mobile companion for approval notifications only, never an execution bypass.
- Pluggable static-analysis and code-assisted workflows for explicitly authorized repositories.
- Local semantic models for rule extraction and evidence classification.
- Signed assessment export bundles that another PentAI instance can verify.

These improvements should follow measured product needs. Distributed services, multi-user collaboration, and autonomous high-impact validation must not be introduced before policy enforcement, audit integrity, and operational safety are independently validated.

## Appendix A — Architectural Decision Template

Every significant future decision should record:

- Context and safety invariants.
- Chosen option and why.
- Alternatives rejected.
- Security, privacy, operations, UX, and portability trade-offs.
- Initial implementation complexity (`S`, `M`, `H`, `XL`).
- Migration/reversibility plan.
- Expected scale ceiling and observable bottleneck.
- Required tests and owner.

## Appendix B — Definition of Done for an Executable Capability

A new tool or agent capability is not complete until:

1. Its typed input/output and capability name are versioned.
2. It maps to deterministic policy rules and denial reasons.
3. It has explicit target canonicalization and redirect/DNS behavior.
4. It runs in the appropriate sandbox with no alternate egress.
5. Its rate, concurrency, time, data, and cost budgets are enforced.
6. Its secrets and evidence flows are classified.
7. Its retry and idempotency behavior are documented and tested.
8. Its audit events and report provenance are complete.
9. Malicious input, crash, network loss, and policy revocation tests pass.
10. A human-readable permission explanation appears in the UI.
