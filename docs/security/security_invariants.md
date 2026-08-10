# PentAI Security Invariant Register

**Document ID:** PENTAI-SEC-INV-001<br>
**Version:** 1.0.0<br>
**Status:** Phase 0 baseline approved under sole-maintainer exception<br>
**Date:** 2026-08-08<br>
**Owner:** Security Lead<br>

## 1. Purpose

Security invariants are conditions that must remain true across every supported operating system, failure mode, plugin, tool, model provider, and user workflow. A violated invariant is a security incident and release blocker, not an ordinary defect.

## 2. Enforcement Model

Each invariant has:

- A stable ID.
- A precise statement.
- One authoritative enforcing component.
- Defense-in-depth checks.
- Required verification.
- A defined failure response.

AI output, UI state, plugin behavior, and prompt instructions are never authoritative enforcement mechanisms.

The accountable owner, automated evidence, missing downstream enforcement, and
approval state for every invariant are maintained in `phase0_traceability.md`.
Acceptance of implementation through a pull request is not itself security approval.
The Phase 0 approval is a separately recorded, non-independent sole-maintainer review.
Phase 1 components named below are requirements, not claims that those components
exist.

## 3. Authorization Invariants

### INV-AUTH-001 — Active policy required

**Statement:** No target-facing execution may start or continue without one active, unexpired, unrevoked, cryptographically verified policy bundle bound to the assessment.

**Primary enforcement:** Execution Broker<br>
**Secondary enforcement:** Policy Decision Point and Gateway<br>
**Failure response:** Deny, revoke outstanding grants, pause assessment, record critical audit event.<br>
**Verification:** Missing, expired, tampered, superseded, and revoked-policy integration tests.

### INV-AUTH-002 — Exact policy version binding

**Statement:** Every intent, decision, approval, grant, execution, observation, and evidence item must reference the exact policy-bundle hash used for authorization.

**Primary enforcement:** Core domain service<br>
**Failure response:** Reject persistence or execution.<br>
**Verification:** Database constraints and end-to-end linkage tests.

### INV-AUTH-003 — Default deny

**Statement:** Missing, unknown, ambiguous, conflicting, malformed, stale, or unverified authorization evaluates to deny.

**Primary enforcement:** Policy evaluator<br>
**Failure response:** Return a stable deny reason and create an unresolved-review item.<br>
**Verification:** Golden corpus and property-based tests.

### INV-AUTH-004 — Deny precedence

**Statement:** A matching explicit deny overrides an allow at equal or greater specificity. No broad allow can override a narrower deny.

**Primary enforcement:** Policy evaluator<br>
**Verification:** Host, port, path, scheme, address, and technique precedence corpus.

### INV-AUTH-005 — Human activation

**Statement:** AI agents, plugins, tools, and automated workflows cannot approve or activate an engagement policy.

**Primary enforcement:** Approval service and capability authorization<br>
**Failure response:** Reject and audit attempted privilege violation.<br>
**Verification:** Actor/capability negative tests.

## 4. Action Grant Invariants

### INV-GRANT-001 — Valid grant per connection

**Statement:** Every target connection requires a valid, signed, audience-bound, assessment-bound, policy-bound, short-lived, single-use ActionGrant.

**Primary enforcement:** Gateway<br>
**Secondary enforcement:** Execution Broker<br>
**Failure response:** Refuse connection and audit denial.<br>
**Verification:** Missing, malformed, wrong-audience, wrong-policy, expired, and replay tests.

### INV-GRANT-002 — Intent immutability

**Statement:** The executed method, canonical target, parameters digest, account reference, and capability must match the authorized ActionIntent and grant.

**Primary enforcement:** Gateway and Execution Broker<br>
**Failure response:** Reject execution; revoke grant.<br>
**Verification:** Mutation and confused-deputy tests.

### INV-GRANT-003 — Approval cannot broaden policy

**Statement:** A human approval may satisfy a policy-declared condition but cannot authorize a target or capability denied or absent from the active policy.

**Primary enforcement:** Policy evaluator<br>
**Verification:** Approval escalation tests.

### INV-GRANT-004 — Grant revocation epoch

**Statement:** Policy change, assessment pause/stop, network identity change, or emergency stop increments a revocation epoch that invalidates all older grants.

**Primary enforcement:** Core and Gateway<br>
**Verification:** Mid-flight revocation tests.

## 5. Scope Invariants

### INV-SCOPE-001 — Canonical comparison only

**Statement:** Raw user, tool, agent, URL, DNS, or redirect strings are never compared directly to scope rules; both policy and runtime targets use the same versioned canonicalizers.

**Primary enforcement:** Canonicalization package<br>
**Verification:** Differential and property-based tests.

### INV-SCOPE-002 — Ambiguity denies

**Statement:** Ambiguous wildcard apex behavior, encoded path boundary, hostname, address family, port, scheme, tenant, ownership, or third-party status denies execution.

**Primary enforcement:** Policy compiler and evaluator<br>
**Verification:** Malformed and ambiguous corpus.

### INV-SCOPE-003 — Runtime reauthorization

**Statement:** DNS answers, CNAME chains, redirects, SNI, Host header, port, protocol upgrade, and resolved IP changes are reauthorized before use.

**Primary enforcement:** Gateway<br>
**Verification:** Controlled DNS and redirect integration suite.

### INV-SCOPE-004 — Discovery does not expand authority

**Statement:** Discovered hosts, URLs, ports, IPs, services, repositories, tenants, and integrations remain denied until added through a new approved policy version.

**Primary enforcement:** Policy evaluator<br>
**Verification:** Discovery-quarantine tests.

## 6. Network Invariants

### INV-NET-001 — Mandatory gateway

**Statement:** All worker-originated target traffic traverses the PentAI controlled gateway; workers have no alternate route.

**Primary enforcement:** OS/container network isolation<br>
**Secondary enforcement:** Execution Broker and host firewall<br>
**Failure response:** Stop all execution on the affected platform.<br>
**Verification:** Direct socket, alternate proxy, DNS, IPv4, IPv6, and raw-route bypass tests.

### INV-NET-002 — Approved source identity

**Statement:** Network execution is permitted only while the measured public source IPv4/IPv6 and route identity match the active policy.

**Primary enforcement:** Network Attestation Service and Gateway<br>
**Failure response:** Immediately close sessions, revoke grants, and pause the assessment.<br>
**Verification:** VPN loss, interface change, address change, disagreement, and attestation timeout tests.

**Phase 1 setup note:** OS-discovered route and resolver values are untrusted,
short-lived proposals only. They cannot satisfy this invariant, supply a registered
source identity, or enable execution without explicit human confirmation and a later
attestation against active policy.

### INV-NET-003 — Controlled DNS

**Statement:** Workers cannot use unauthorized DNS, DoH, or DoT resolvers; resolution occurs through the policy-approved route and resolver.

**Primary enforcement:** Gateway and OS/container network rules<br>
**Verification:** Port 53/853, known DoH, custom resolver, and DNS rebinding tests.

### INV-NET-004 — IPv6 fail-safe

**Statement:** IPv6 is disabled for worker traffic unless an approved and continuously attested IPv6 egress path is configured.

**Primary enforcement:** Gateway/network namespace<br>
**Verification:** IPv6 and IPv4-mapped IPv6 bypass suite.

### INV-NET-005 — Atomic budget reservation

**Statement:** Rate, concurrency, request, data, time, and cost budgets are reserved atomically before execution and cannot be bypassed by concurrent workers.

**Primary enforcement:** Policy/budget service<br>
**Verification:** Concurrency and race-condition tests.

## 7. Agent and AI Invariants

### INV-AGENT-001 — No agent authority

**Statement:** Agents cannot approve actions, activate or modify policy, mint grants, reveal secrets, change network controls, or grant themselves capabilities.

**Primary enforcement:** Core capability model<br>
**Verification:** Tool exposure inspection and negative authorization tests.

### INV-AGENT-002 — Structured intents only

**Statement:** Agent requests for effects must pass a versioned schema and become persisted ActionIntents; prose and model-generated commands cannot execute directly.

**Primary enforcement:** Agent runtime<br>
**Verification:** Invalid output and injection tests.

### INV-AGENT-003 — Untrusted content has no authority

**Statement:** Program pages, target responses, tool output, evidence, retrieved documents, and plugin messages cannot modify system instructions or authorization state.

**Primary enforcement:** Agent runtime and deterministic action pipeline<br>
**Verification:** Prompt-injection regression suite.

### INV-AGENT-004 — Data routing

**Statement:** Secrets and restricted evidence do not enter model prompts; remote providers receive data only when the active data-routing policy explicitly permits the classification.

**Primary enforcement:** Context builder and provider adapter<br>
**Verification:** Canary and trace inspection tests.

## 8. Isolation and Plugin Invariants

### INV-ISO-001 — No direct core access

**Statement:** Workers and plugins have no direct database, keychain, audit-ledger, policy-signing-key, or host-container-runtime socket access.

**Primary enforcement:** Process/container isolation<br>
**Verification:** Mount, environment, IPC, and socket inspection.

### INV-ISO-002 — Pinned executable identity

**Statement:** An execution uses the plugin and tool digest pinned to the assessment; versions cannot change silently during an assessment.

**Primary enforcement:** Plugin Manager and Execution Broker<br>
**Verification:** Update and digest-mismatch tests.

### INV-ISO-003 — Least privilege

**Statement:** Workers run without root, host PID/IPC, unnecessary Linux capabilities, writable host paths, or unbounded CPU, memory, processes, runtime, and output.

**Primary enforcement:** Execution Broker<br>
**Verification:** Sandbox conformance suite.

## 9. Secret, Evidence, and Audit Invariants

### INV-DATA-001 — Secret references only

**Statement:** Manifests, policies, tasks, logs, audit events, reports, and model contexts store secret references, never raw secret values.

**Primary enforcement:** Schema validation and secret broker<br>
**Verification:** Repository/database/log/model-trace secret scans.

### INV-DATA-002 — Immutable evidence originals

**Statement:** Original evidence objects are content-addressed and immutable; redaction or annotation creates a derived object with provenance.

**Primary enforcement:** Evidence service<br>
**Verification:** API, filesystem, and digest tests.

### INV-DATA-003 — Complete privileged audit

**Statement:** Every policy activation/revocation, approval, grant, execution, stop event, evidence access, and report transition produces an append-only audit event.

**Primary enforcement:** Domain services with transactional outbox<br>
**Verification:** Domain-event coverage tests.

### INV-DATA-004 — Tamper evidence

**Statement:** Audit events form a verifiable hash chain, and evidence/report exports include content digests.

**Primary enforcement:** Audit and export services<br>
**Verification:** Mutation, removal, reorder, and export verification tests.

### INV-DATA-005 — Safe failure on storage risk

**Statement:** Database integrity failure, evidence-write failure, unavailable encryption key, or disk-full condition blocks new target actions.

**Primary enforcement:** Core health gate<br>
**Verification:** Fault-injection tests.

## 10. Reliability Invariants

### INV-REL-001 — At-most-once external effect

**Statement:** At-least-once task delivery must not cause a grant or external action to be used more than once.

**Primary enforcement:** Single-use grants, idempotency keys, and gateway ledger<br>
**Verification:** Duplicate delivery and crash-window tests.

### INV-REL-002 — Recovery revalidates safety

**Statement:** Startup recovery revokes stale grants and revalidates policy, time, storage, route, DNS controls, and public IP before network work can resume.

**Primary enforcement:** Recovery Coordinator<br>
**Verification:** Process-kill and machine-restart simulations.

### INV-REL-003 — Clock uncertainty denies

**Statement:** If wall-clock trust is insufficient to validate authorization, approval, grant, or testing windows, network execution pauses.

**Primary enforcement:** Core health and policy evaluator<br>
**Verification:** Clock rollback/forward tests.

## 11. User-Control Invariants

### INV-USER-001 — Emergency stop is unconditional

**Statement:** The user can trigger emergency stop without agent, plugin, task, or model cooperation.

**Primary enforcement:** Core and Gateway direct control path<br>
**Verification:** Hung-worker and disconnected-UI tests.

### INV-USER-002 — Sensitive actions are individually visible

**Statement:** Conditional or sensitive actions display their exact target, technique, impact, policy rule, evidence plan, and expiry and cannot be approved through an unrelated batch.

**Primary enforcement:** Approval API and UI<br>
**Verification:** UI/API approval-binding tests.

### INV-USER-003 — No automatic report submission

**Statement:** The MVP cannot submit reports to an external platform; export requires a human-reviewed report state.

**Primary enforcement:** Report service capability set<br>
**Verification:** API surface and network tests.

## 12. Verification and Incident Procedure

Before every release:

1. Run all invariant-linked automated tests.
2. Review any new execution capability against this register.
3. Verify cross-platform enforcement parity.
4. Record evidence for each invariant in the release bundle.

On suspected violation:

1. Stop target execution and revoke grants.
2. Preserve minimal incident evidence.
3. Identify affected policies, actions, plugins, tools, and versions.
4. Notify the Security Lead and product owner.
5. Add a regression test before remediation is accepted.
6. Rotate secrets or signing material if exposure cannot be excluded.
7. Resume only after explicit security approval.

## 13. Change Control

An invariant may be clarified or strengthened through a reviewed document version. Removing or weakening an invariant requires a formal architecture decision, threat-model update, compensating controls, test changes, and named risk acceptance. Product schedule is not sufficient justification.
