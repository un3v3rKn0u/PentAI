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

**Phase 1 pre-resolution note:** Controlled DNS is not contacted until the core has
validated the signed gateway grant, active policy and revocation epoch, global and
assessment safety, and exact unexpired attestation. The assessment used for resolver
selection is derived from those records. Authority is checked again transactionally
when the immutable destination decision is stored.

**Phase 1 redirect note:** Each redirect is derived from one prior immutable allowed
decision for the same grant and attestation. Persisted lineage supplies the hop count
and permits only one child, preventing caller-controlled count reset, branching, and
replay. Relative locations are resolved against the exact canonical parent. Same-host
DNS changes are rebinding denials; changed hosts are independently reauthorized.

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

**Phase 1 fixture note:** The first HTTP effect is limited in the image-pinned gateway
binary to one owned TEST-NET fixture tuple and runs on the managed internal network.
The core atomically issues one-use execution claims only for committed, unexpired
starts whose consumed grant, budget, rate reservation, destination decision, running
runtime, image, network, and fresh containment identity all match. Claim-bound
finalization or fail-closed recovery prevents reuse. The core has no socket transport.
Hosted rootless evidence must show the fixed request
succeeds while direct egress, external DNS, IPv6, runtime sockets, host mounts, host
namespaces, and unconstrained resources remain blocked. The hosted proof must derive
the live claim from the complete durable supervised authorization chain, verify the
linked result and audit hash chain, and terminate the runtime. This does not yet verify
worker-to-gateway routing or authorize external destinations.

### INV-NET-002 — Approved source identity

**Statement:** Network execution is permitted only while the measured public source IPv4/IPv6 and route identity match the active policy.

**Primary enforcement:** Network Attestation Service and Gateway<br>
**Failure response:** Immediately close sessions, revoke grants, and pause the assessment.<br>
**Verification:** VPN loss, interface change, address change, disagreement, and attestation timeout tests.

**Phase 1 setup note:** OS-discovered route and resolver values are untrusted,
short-lived proposals only. They cannot satisfy this invariant, supply a registered
source identity, or enable execution without explicit human confirmation and a later
attestation against active policy. Human-confirmed profiles are durable configuration,
but still cannot satisfy the invariant until independent observations match the active
policy. Attestor composition now requires the active policy and profile to match
exactly; profile activation always records `execution_enabled: false`.

### INV-NET-003 — Controlled DNS

**Statement:** Workers cannot use unauthorized DNS, DoH, or DoT resolvers; resolution occurs through the policy-approved route and resolver.

**Primary enforcement:** Gateway and OS/container network rules<br>
**Verification:** Port 53/853, known DoH, custom resolver, and DNS rebinding tests.

**Phase 1 composition note:** Controlled-resolver construction obtains resolver mode,
identity, and allowed addresses from the current active policy-bound network profile
for each assessment. A separately pinned transport address must be a member of that
profile, and TCP/53 versus verified DoT must match its mode. Missing, revoked,
mismatched, malformed, or changed profile state denies resolver construction; legacy
environment resolver identity cannot grant authority.

### INV-NET-004 — IPv6 fail-safe

**Statement:** IPv6 is disabled for worker traffic unless an approved and continuously attested IPv6 egress path is configured.

**Primary enforcement:** Gateway/network namespace<br>
**Verification:** IPv6 and IPv4-mapped IPv6 bypass suite.

### INV-NET-005 — Atomic budget reservation

**Statement:** Rate, concurrency, request, data, time, and cost budgets are reserved atomically before execution and cannot be bypassed by concurrent workers.

**Primary enforcement:** Policy/budget service<br>
**Verification:** Concurrency and race-condition tests.

**Phase 1 rate note:** Non-executing gateway preparation reserves one durable global
and canonical-host token in the same immediate transaction as total-request and
connection capacity. Refill uses persisted policy rates, burst capacity, and a
nondecreasing wall clock. Exhaustion or rollback denies; concurrent contenders cannot
oversubscribe. Abort and recovery return only uncommitted tokens and cap every refund.
The request-start boundary revalidates current authority and atomically converts both
rate tokens and total-request capacity to committed state while consuming the grant.
Its deadline is the earliest of the grant timeout, grant expiry, engagement expiry,
and attestation expiry. Once committed, request/rate capacity is never refunded;
safety recovery only cancels the execution-disabled handoff and releases its
connection slot.
Finalization re-derives the deadline and response ceiling from durable state, retains
at most the authorized bytes, permits only one additional observed proof byte, closes
the connection slot exactly once, and never refunds committed capacity.

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

Migration 0021 and the evidence service enforce content-addressed authenticated
encryption, immutable database originals, and derived-key separation from source
blobs. No original-content HTTP read route exists in this slice.

Migration 0022 adds immutable redaction derivatives. The service, rather than the
caller, generates derivative bytes from validated non-overlapping text ranges and
binds each derivative to the original digest. Only derivatives can use the bounded
inactive plain-text preview contract; originals remain unavailable over HTTP.

### INV-DATA-003 — Complete privileged audit

**Statement:** Every policy activation/revocation, approval, grant, execution, stop event, evidence access, and report transition produces an append-only audit event.

**Primary enforcement:** Domain services with transactional outbox<br>
**Verification:** Domain-event coverage tests.

Evidence storage and every metadata/content access append both an evidence custody
event and an audit-ledger event without including evidence bytes.

Redaction creation and preview also append immutable per-derivative events and
privileged audit entries without including source or derivative content.

Deletion requests commit an audit event before filesystem work, and completion commits
a second event after the disposition is known. Tombstones preserve metadata and deny
content access through interrupted and recovered states.

The currently enabled owned-fixture effect atomically creates a content-hashed
execution trace linking its intent, decision, evaluated policy rules, grant, committed
start, execution claim, digest-pinned runtime/tool, bounded result, and final audit
event. No caller supplies these links.

### INV-DATA-004 — Tamper evidence

**Statement:** Audit events form a verifiable hash chain, and evidence/report exports include content digests.

**Primary enforcement:** Audit and export services<br>
**Verification:** Mutation, removal, reorder, and export verification tests.

Database triggers deny audit mutation, deletion, and insertion away from the current
head. Core startup validates event contracts, contiguous sequence, previous hashes,
and canonical event hashes before recovery or supervisors start. Invalid legacy state
denies startup.

### INV-DATA-005 — Safe failure on storage risk

**Statement:** Database integrity failure, evidence-write failure, unavailable encryption key, or disk-full condition blocks new target actions.

**Primary enforcement:** Core health gate<br>
**Verification:** Fault-injection tests.

The composed evidence service stops global execution when its key is unavailable or
an authenticated blob store/write/read fails. Resumption remains a human action.

The composed core also maintains a process-local storage-safety latch. Classified
SQLite disk-full, I/O, corruption, read-only, or open failures and encrypted
source/evidence/backup write failures trip it irreversibly for that process. Health and
readiness degrade, and intent evaluation, grant consumption, gateway preparation,
request commitment, and fixture execution claims deny before authority can advance.
Restart can clear the volatile latch only after ordinary migration and audit-integrity
startup gates pass.

Deletion I/O failure also stops global execution. Startup resumes durable pending or
processing deletions without restoring content visibility; content-addressed blobs are
unlinked only after every reference is tombstoned.

Findings bind to one workflow and its exact immutable policy. Creation rejects denied
or unknown asset rules, cross-workflow/policy evidence, deleted evidence, malformed CWE
or CVSS input, score/severity disagreement, and conflicting idempotent replay. Only a
human may perform ordered, version-fenced scope, duplicate, validation, report-readiness,
retest, rejection, and closure transitions. Full finding versions and audit events are
append-only; findings cannot grant execution authority or approve report export.

Report drafts are human-requested and snapshot only exact current `report_ready`
finding versions from one workflow and policy. Rendered Markdown, inactive escaped
HTML, canonical JSON, and text-only PDF artifacts are bounded, content-digested,
immutable, and audit-linked. Draft status cannot approve export or create a submission
transport.

Assessment coverage records are human-authored, immutable, audit-linked assertions for
one allowed policy asset/capability pair. Claims that testing occurred require
available evidence from the same workflow and policy. Blocked and untested outcomes
remain explicit gaps, every record disclaims completeness, and no coverage entry can
authorize execution or make a report export-ready.

“No Findings” drafts require a completed workflow, no unresolved finding, and exact
coverage of every allowed policy asset/capability pair by one unambiguous latest
evidence-backed `tested_no_findings` record. Missing, blocked, untested, finding-bearing,
stale, or ambiguous coverage denies generation. The immutable draft carries the exact
coverage hashes, evidence references, testing intervals, and limitations and cannot
approve export or claim exhaustive security.

Export-ready status exists only as an immutable human approval bound to one exact
findings or No Findings draft content hash and all four artifact digests. Approval
requires explicit confirmation and revalidates stored metadata and artifact bytes in
one transaction. Missing, changed, incomplete, already-decided, or ambiguous input
denies; approval never enables submission.

Local report export requires that exact approval, revalidates the selected artifact
bytes and digest, derives the filename from the report identifier, refuses an existing
destination, publishes through an exclusive same-directory temporary file, and records
an immutable receipt plus audit event. Export paths and artifact content are excluded
from audit data, and no network or submission transport exists.

Encrypted backups use a key domain separated from evidence storage, an online SQLite
snapshot, an exact authenticated member manifest, and authenticated evidence reads.
Restore verification occurs only in a newly created isolated directory and never
replaces live data. Current deletion tombstones take precedence over older backup
content, including shared-digest last-reference semantics. Missing keys, inconsistent
members, corruption, path conflicts, or stale deletion state deny the operation and
remove the incomplete drill directory.
V2 backups additionally require every source-provenance row to bind an available,
supported encrypted blob reference to its exact content hash. Creation authenticates
each source blob; restore reconstructs a separate source store, re-authenticates every
blob, and compares the complete source digest inventory with the restored database.
The narrower authenticated v1 format remains restore-only compatible and is reported
with zero source blobs rather than being represented as a complete provenance backup.

Backup inventory authenticates exact server-generated filenames and envelopes and
rejects symlink, type, identity, member, and size ambiguity. Rotation is proposal-only:
it protects a bounded newest set and the newest restore-verified copy and never deletes
automatically. Purge requires exact human-confirmed identity and digest, rechecks the
file immediately before unlink, protects the last verified copy, commits its request
first, synchronizes the directory, and completes interrupted unlink on exact replay.
No purge result claims forensic erase or removal of copies outside the local inventory.

## 10. Reliability Invariants

### INV-REL-001 — At-most-once external effect

**Statement:** At-least-once task delivery must not cause a grant or external action to be used more than once.

**Primary enforcement:** Single-use grants, idempotency keys, and gateway ledger<br>
**Verification:** Duplicate delivery and crash-window tests.

The durable workflow boundary stores idempotent task intent but cannot dispatch it or
cause an external effect. Workflow and task contracts fix those capabilities to
`false`; execution remains exclusively governed by the authorization and gateway
chains.

Task attempts additionally require both the current lifecycle version and an opaque,
unexpired lease token whose digest alone is persisted. Completion/failure receipts
make terminal retries idempotent; competing or stale lease holders cannot mutate the
task. Leases remain coordination records and never substitute for execution grants.

### INV-REL-002 — Recovery revalidates safety

**Statement:** Startup recovery revokes stale grants and revalidates policy, time, storage, route, DNS controls, and public IP before network work can resume.

**Primary enforcement:** Recovery Coordinator<br>
**Verification:** Process-kill and machine-restart simulations.

Running assessment workflows are synchronously changed to `paused` on core startup.
They cannot resume without a fresh human transition and revalidation of active policy,
engagement expiry, revocation, and global safety state.

Startup also invalidates every outstanding task lease before any future claim. An
exhausted task enters dead letter; other interrupted tasks enter retry wait with no
automatic claimant.

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
