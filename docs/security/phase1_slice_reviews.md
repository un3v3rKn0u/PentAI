# Phase 1 slice security reviews

These records use the `GIT_WORKFLOW.md` sole-maintainer exception. They are formal
project reviews but are not independent security reviews and do not satisfy any
external dual-control requirement.

## 2026-08-08 — Source provenance intake

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** Program/source APIs, immutable provenance persistence, migration
`0004_source_provenance.sql`, audit events, compatibility behavior, tests, contracts,
and security documentation in `feature/source-provenance-intake`.

**Evidence examined:** complete diff against `main`; source authority and kind checks;
manifest hash binding; immutable-row triggers; idempotent import behavior; audit-chain
coverage; migration upgrade test; negative tests for blank, malformed, unsupported,
and missing-Program inputs; repository quality checks reported with the slice.

**Findings:** No unresolved material finding. Missing or ambiguous provenance fails
closed. Source content is not returned or written to audit data. Existing rows receive
compatible defaults and are not rewritten.

**Limitations and deferred work:** This slice stores provenance metadata only. It does
not claim encrypted originals, file/URL acquisition, field-level provenance, or any
target-facing enforcement. Cross-platform behavior remains dependent on CI.

**Residual risk accepted:** The review is self-authored and non-independent. The
limited assurance is accepted for this internal slice under the sole-maintainer
exception; it does not approve later Phase 1 execution capabilities.

## 2026-08-08 — Encrypted source storage

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** AES-256-GCM content-addressed source store, OS credential-service
key custody, one-use desktop-to-core key delivery, migration
`0005_encrypted_source_blobs.sql`, packaged-core lifecycle changes, dependency locks,
negative/recovery tests, ADR 0002, and related contract/security documentation.

**Evidence examined:** complete diff after synchronization with `main`; AEAD nonce and
associated-data binding; digest verification; atomic write/fsync/rename sequence;
wrong-key, tamper, malformed-object, missing-key, digest-mismatch, and write-failure
tests; legacy migration behavior; desktop key generation/retrieval/error handling;
key output scans; packaged PyInstaller lifecycle smoke; local Python, Rust, UI, and
contract checks.

**Findings:** No unresolved material finding. Missing or ambiguous credential-store
results fail closed. Only a definite missing-entry result creates a new key. Blob
authentication or storage failure prevents provenance persistence. Legacy placeholders
remain explicitly marked unavailable rather than being relabeled as encrypted.

**Limitations and deferred work:** Windows Credential Manager and Linux Secret Service
behavior require hosted verification. Key rotation, key backup/restore, locked-store
manual testing, native file selection, and URL acquisition remain deferred and block
production claims. Python cannot guarantee complete in-memory key zeroization.

**Residual risk accepted:** This is a self-authored, non-independent review. Its reduced
governance assurance and the documented cross-platform/key-lifecycle limitations are
accepted for the internal slice only. It does not authorize target-facing execution.

## 2026-08-08 — Bounded file-source import

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** Path-free authenticated file-import API, base64 transport bound,
filename/media/extension/content validation, encrypted persistence integration, audit
linkage, negative tests, and `docs/security/file_source_import_slice.md`.

**Evidence examined:** complete diff after synchronization with the encrypted-storage
mainline; the 2 MiB decoded-content bound and matching encoded transport bound;
rejection of paths, empty/oversized payloads, unapproved or mismatched media types,
binary or malformed UTF-8 text, malformed JSON, invalid PDF signatures, and invalid
base64; encrypted round-trip and audit-content tests; repository quality checks.

**Findings:** No unresolved material finding. The core receives bytes and a basename,
never a caller-controlled filesystem path. Invalid or ambiguous content fails closed
before provenance persistence, and accepted originals use the existing authenticated
encrypted store without exposing content in audit records.

**Limitations and deferred work:** PDF validation is signature-only and conveys no
rendering-safety claim. Files are stored but never rendered or parsed beyond the stated
checks. A native file picker still needs bounded, race-resistant regular-file reads.
URL acquisition, previews, extraction, and active-content rendering remain deferred.

**Residual risk accepted:** This is a self-authored, non-independent review. The
limited assurance and documented format-validation limitations are accepted for this
internal storage-only slice. It does not authorize target-facing execution.

## 2026-08-08 — Guarded URL-source acquisition

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** URL canonicalization, resolver answer checks, pinned HTTP(S)
transport, TLS hostname verification, peer-IP attestation, redirect revalidation,
response/time/media bounds, encrypted URL provenance, endpoint, tests, and operations
documentation on `codex/ssrf-resistant-url-acquisition`.

**Evidence examined:** complete diff against merged `main`; negative tests for private,
loopback, IPv6, mixed and empty DNS answers, peer mismatch, redirect to loopback, HTTPS
downgrade, unsafe ports and schemes, credentials, fragments, control characters,
overlong/malformed URLs, oversized bodies, and unapproved media; redirect DNS pinning,
public IPv6 canonicalization, encrypted persistence, and audit-content tests; full local
quality, audit, contract, recovery, and wheel-build checks.

**Findings:** No unresolved material finding. Every connection uses a checked and pinned
address, the observed peer must match that pin, and every redirect repeats the complete
URL and DNS decision. Missing, mixed, malformed, private, or unverifiable state denies
before persistence. Acquired content is not emitted into audit events.

**Limitations and deferred work:** The default resolver is the host system resolver;
dedicated tunnel-resolver identity and OS egress containment belong to the later
assessment gateway. CNAME-chain metadata is not retained, proxies are not supported,
and no live external acquisition was performed. Content is stored but not rendered,
executed, decompressed, crawled, or authenticated.

**Residual risk accepted:** This is a self-authored, non-independent review. Host DNS
configuration remains trusted for naming, while public-address checks, address pinning,
and peer verification constrain SSRF/rebinding. This acceptance covers source intake
only and does not authorize assessment traffic or claim gateway containment.

## 2026-08-09 — Supervised source-intake UI

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** Explicit pasted/file/URL intake controls, webview-native file
selection, pre/post-read bounds, basename-derived media type, source history and
recovery, loading/empty/denied/degraded/error states, safety copy, tests, and UI build.

**Evidence examined:** complete diff against `main`; confirmation that no filesystem
path is read or transmitted; approved-extension media mapping and rejection test;
base64 byte-preservation test; disabled controls during loading or degraded core state;
explicit-only URL submission; rendered desktop-width layout and accessibility snapshot;
UI typecheck, unit tests, and production build.

**Findings:** No unresolved material finding. The UI cannot confer authority and core
validation remains mandatory. File selection transmits only the selected basename and
bounded bytes. URL acquisition is clearly distinguished from simulated assessment
traffic and never starts or retries autonomously.

**Limitations and deferred work:** Visual verification used the browser development
surface with the core intentionally unavailable, proving degraded/recovery presentation
but not a packaged OS-dialog interaction. Hosted Tauri smoke remains required. Import
requests are atomic and cannot be paused mid-request; there is no background queue.

**Residual risk accepted:** This is a self-authored, non-independent review. Browser and
OS file-picker behavior still depends on hosted/platform verification. This acceptance
does not approve assessment execution or relax any core source validation.

## 2026-08-09 — Manifest versioning and field provenance

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** Manifest v2 field-provenance contract, immutable version metadata,
migration `0006_manifest_version_history.sql`, engagement-bound history and semantic
diff APIs, supervised history UI, validation persistence, compatibility, and tests.

**Evidence examined:** complete diff against `main`; source UUID/hash verification for
every authority-bearing section; rejection of missing, unknown, duplicate, and stale
links; idempotent saves; monotonic per-engagement versions; deterministic section
diffs; cross-engagement denial; immutable legacy-upgrade test; contract, Python, UI,
migration, and repository quality checks reported with the slice.

**Findings:** No unresolved material finding. Invalid drafts are retained for diagnosis
but cannot compile. Versions cannot be updated or deleted. Semantic diffs resolve both
identifiers inside one engagement and disclose no source content.

**Limitations and deferred work:** This slice does not sign, approve, activate, or
revoke policy changes beyond the existing Phase 0 vertical slice. It does not add a
structured form editor for every manifest field. Pre-upgrade manifests are visible as
`legacy_unverified` and require human resave before compilation.

**Residual risk accepted:** This is a self-authored, non-independent review. The
strengthened schema intentionally fails closed for legacy compilation. This acceptance
does not authorize target-facing execution or satisfy independent review.

## 2026-08-09 — Deterministic manifest validation and typed matchers

**Decision:** Sole-maintainer security review — non-independent<br>
**Reviewer:** `un3v3rKn0u`<br>
**Roles held:** author, sole maintainer, Product Owner, Security Lead, repository owner

**Scope reviewed:** Manifest semantic validation, compiler v1.1 matcher specificity,
negative/default-deny behavior, compatibility, tests, contracts, and documentation on
`feature/deterministic-manifest-validation`.

**Evidence examined:** complete diff against `main`; explicit wildcard apex, port,
ownership, capability, URL base-path, duplicate asset/source, path conflict, IPv6,
resolver, rate, runtime, and validity checks; exact-IP versus CIDR precedence test;
deterministic compilation and existing authorization regression suite; all repository
quality and hosted checks reported with the slice.

**Findings:** No unresolved material finding. Missing or contradictory authority is
retained as a diagnosable invalid manifest version and cannot compile. Matcher ordering
is deterministic and deny precedence remains effective at equal specificity.

**Limitations and deferred work:** Validation does not prove external asset ownership;
it requires the human-authored manifest to record that verification and bind it to an
authoritative source. Runtime DNS/redirect/address reauthorization remains a gateway
responsibility. Existing compiler v1.0 policies remain readable but receive no new
assurance claim.

**Residual risk accepted:** This is a self-authored, non-independent review. Its
governance limitation is accepted for this internal validation slice only. It does not
authorize target-facing execution or substitute for independent assessment.

## 2026-08-09 — Signed policy lifecycle

**Decision:** Sole-maintainer security review — non-independent; accepted for local
development only<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None. The project governance decision permits this exception only
for keys confined to local development on the sole maintainer's device.

**Scope prepared for review:** OS-credential-service Ed25519 seed custody, one-use
desktop-to-core delivery, policy and Approval v1.2 signatures, activation/evaluation
verification, lifecycle history, explicit revocation, UI states, compatibility, tests,
and ADR 0003 on `feature/signed-policy-lifecycle`.

**Author review evidence:** Missing/wrong/malformed/tampered signature tests; exact key
ID and policy/approval binding; unsigned legacy denial; key absence and invalid-length
failure; expiry, replacement, revocation, and audit regressions; local and hosted checks
reported on the PR.

**Review decision:** The sole maintainer reviewed generation, credential-store behavior
on macOS/Windows/Linux, key delivery, memory exposure, domain separation, verification,
loss/rotation behavior, compatibility, recovery, and the passing PR #26 checks. No
unresolved material finding was recorded for local development.

**Accepted residual risk:** The review is self-authored and lacks independent challenge.
This acceptance supports local development with synthetic, owned fixtures only. It is
not production approval, release authorization, external assurance, or permission to
bypass remaining execution and networking controls. Independent review remains the
preferred assurance upgrade when another qualified reviewer becomes available.

## 2026-08-09 — Non-executing ActionGrant authorization chain

**Decision:** Sole-maintainer security review — non-independent; approved for the
non-executing local slice only<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; the documented sole-maintainer exception is used. This review
does not extend production or external signing assurance and authorizes no target
execution.

**Scope reviewed:** additive migration `0007`; immutable ActionIntent persistence;
deterministic PolicyDecision linkage; Ed25519 ActionGrant minting; audience,
assessment, policy, epoch, capability, target/HTTP/account, and parameter bindings;
30-second maximum lifetime; atomic single-use consumption; revocation; audit linkage;
API and supervised UI states.

**Evidence examined:** complete branch diff; ActionIntent, PolicyDecision, and
ActionGrant v1 schemas; INV-GRANT-001 through INV-GRANT-004; exact allow-only minting;
malformed/wrong-key/wrong-audience/mutated/expired/replayed/revoked/idempotency paths;
two-consumer race proof; immutable database triggers; migration idempotency; full local
Python, contracts, UI, desktop compile, and dependency-audit results.

**Findings:** No unresolved material finding in the non-executing scope. Grant
issuance requires an immutable allow decision and current signed policy. Verification
uses a write-reserving transaction so concurrent consumers cannot both succeed.
Policy revocation or replacement invalidates outstanding grants and increments the
epoch. All verifier failures deny and perform no external effect.

**Limitations and deferred work:** The current core process hosts the logical execution
broker boundary; process isolation comes with the worker slice. Budget reservation,
clock-health attestation, controlled DNS, destination/redirect reauthorization,
route/source-IP checks, gateway containment, and target-facing HTTP(S) remain absent.
The verifier result is not permission to bypass any of those controls.

**Residual risk accepted:** This review is self-authored and non-independent. It is
accepted only for local grant issuance and consumption with no networking. Independent
review remains the preferred assurance upgrade before production or external use.

## 2026-08-09 — Durable safety control plane

**Decision:** Sole-maintainer security review — non-independent; accepted for local
development with no target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Additive migration `0008`; durable global pause and emergency
stop; assessment pause/resume; revocation-epoch invalidation; startup stale-grant
revocation; audit linkage; authenticated API and supervised UI states.

**Evidence examined:** Missing reason and invalid-state denial, restart recovery,
explicit two-stage global/assessment resume, revoked-policy resume denial, emergency
stop, stale grant consumption, epoch invalidation, migration integrity, and repository
quality checks reported with the slice.

**Findings:** Safety state is stored independently of UI state. Pause, stop, and
startup recovery revoke outstanding grants and increment affected assessment epochs
inside the same write transaction. Resume is explicit and cannot revive an expired,
revoked, missing, or unverifiable policy. No operation in this slice opens a socket or
enables execution.

**Limitations and deferred work:** Route failure and public-IP kill switches, clock
attestation, controlled DNS, redirect reauthorization, worker containment, and gateway
session termination remain prerequisites for target-facing HTTP(S). Startup recovery
cannot validate those absent controls and therefore never enables execution.

**Residual risk accepted:** This is a self-authored, non-independent review for local
synthetic development only. It is not production approval, release authorization, or
external assurance.

## 2026-08-09 — Non-executing network authorization control

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Additive migration `0009`; NetworkAttestation and
DestinationDecision v1 contracts; active signed-policy, route, source-IP, resolver,
grant audience, expiry, epoch, DNS answer, CNAME, redirect, protocol, port, SNI, Host,
IPv6, and pin-change checks; safety invalidation; immutable persistence and audit.

**Evidence examined:** Contract validation; synthetic RFC 5737 allow path; private and
loopback denial; IPv6-disabled denial; SNI mismatch; DNS pin-change denial; pause
invalidation; grant remains unconsumed; migration and repository quality checks
reported with the slice.

**Findings:** Missing, malformed, stale, mismatched, or unverifiable authority denies.
Only gateway-audience grants are eligible. The fixture resolver exception is narrowly
limited to documentation address ranges and no code in this slice performs DNS or
HTTP networking. Decisions explicitly remain non-executing.

**Limitations and deferred work:** No trusted attestor, public-IP observation,
controlled resolver, gateway socket, active session, worker containment, or firewall
enforcement exists yet. Therefore INV-NET-001 through INV-NET-004 are only partially
prepared and are not claimed verified. Live route loss and DNS bypass tests remain
blocked on those later components.

**Residual risk accepted:** This review is self-authored and non-independent. It is
not production approval, release authorization, external assurance, or permission to
contact any target.

## 2026-08-09 — Trusted attestor and controlled-resolver boundaries

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Injectable two-observer source identity attestor, route and resolver
binding, short lifetime, controlled DNS answer/CNAME canonicalization and bounds, core
policy derivation, private raw-decision boundary, documentation, and negative tests.

**Evidence examined:** Observer agreement and disagreement, duplicate endpoint IDs,
wrong address family, resolver-attestation mismatch, duplicate and oversized DNS
answers, canonical names and addresses, existing destination bypass tests, and complete
local Python quality checks reported with the slice.

**Findings:** AI, UI, and workers cannot produce or persist measurements through an
API. The core selects the active policy hash, resolver results remain non-authoritative
until destination authorization, and all outputs remain explicitly non-executing.

**Limitations and deferred work:** All observers and DNS backends are injected synthetic
fixtures. Authentication of real observation endpoints, OS route inspection, live DNS
transport, continuous monitoring, containment, and gateway session termination remain
absent. No network invariant is claimed fully verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, external targets, or target-facing networking.

## 2026-08-09 — Network health kill-switch checkpoint

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Attestation replacement, route/source/resolver identity-change
detection, observer failure handling, durable assessment pause, grant revocation,
revocation-epoch increment, attestation invalidation, audit linkage, and tests.

**Evidence examined:** Two-endpoint disagreement produces the original diagnostic,
pauses the active assessment, revokes its unused grant, and invalidates its current
attestation. Successful refresh leaves only one valid attestation. Full warning-as-error
Python checks are reported with the slice.

**Findings:** A failed network-health checkpoint cannot preserve usable runtime
authority. Human resume cannot restore an invalidated attestation or revoked grant.
No external network activity or execution path was added.

**Limitations and deferred work:** Refresh is synchronously invoked; continuous
scheduling, OS change notification, production observations, live gateway sessions,
and session closure do not yet exist. Containment invariants remain unverified.

**Residual risk accepted:** This review is self-authored and non-independent and does
not authorize production or target-facing execution.

## 2026-08-09 — Atomic gateway budget reservations

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Migration `0010`; GatewaySession v1; atomic total-request,
concurrency, and response-byte reservations; grant/destination/attestation/policy
bindings; replay denial; immutable lifecycle history; abort, safety, policy, and
startup recovery integration; audit linkage and race tests.

**Evidence examined:** Two concurrent reservations against a one-connection policy
produce exactly one prepared session; duplicate grants deny; abort restores only
reserved counters; health failure aborts sessions and removes capacity; finalized rows
cannot be resurrected; complete warning-as-error Python and contract checks reported
with the slice.

**Findings:** Reservation and durable session creation occur in one immediate
transaction. Any validation, budget, uniqueness, contract, or audit failure rolls back
counters and rows. Prepared sessions explicitly cannot execute.

**Limitations and deferred work:** Rate token buckets, actual response accounting,
grant consumption at connection start, sockets, containment, live-session closure, and
committed reservation transitions remain absent. INV-NET-005 is partially enforced for
request/concurrency capacity but is not claimed complete.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not authorize production or target-facing execution.

## 2026-08-09 — Worker containment preflight contracts

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without worker or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** WorkerContainmentAttestation v1, WorkerLaunchSpec v1, short-lived
preflight validation, digest pinning, bounded arguments and resources, and negative
control tests.

**Evidence examined:** Every required containment flag fails closed when absent;
runtime-socket access, stale/future/overlong attestations, inactive gateway sessions,
mutable image references, invalid resource limits, NUL arguments, oversized arguments,
and excessive argument counts are denied. Successful output remains non-executing.

**Findings:** The contract fixes the minimum isolation posture that a future trusted
broker must enforce. It does not create authority, launch a runtime, or perform network
access.

**Limitations and deferred work:** Attestations are synthetic and not yet emitted by a
trusted Docker/Podman adapter. No container, network namespace, firewall, gateway route,
continuous health check, termination path, or platform bypass test exists. Network and
isolation invariants are therefore not claimed verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Trusted runtime containment measurement boundary

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without worker or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Typed runtime and gateway-network snapshots, trusted inspector
boundary, short-lived attestation production, failure diagnostics, and exhaustive
control-denial tests.

**Evidence examined:** Each rootless, filesystem, privilege, namespace, resource,
temporary-mount, runtime-socket, internal-network, gateway-route, DNS, and IPv6
measurement fails closed independently. Inspection exceptions, unsupported runtimes,
missing identities, and invalid lifetimes deny attestation production. Successful
output validates against WorkerContainmentAttestation v1.

**Findings:** Raw dictionaries from untrusted consumers cannot directly enter this
producer. The deterministic attestor emits a contract only from typed measurements and
does not expose raw inspector errors. No process, container, or network operation was
added.

**Limitations and deferred work:** Tests use synthetic inspectors. Production
Docker/Podman CLI or API collection, runtime-instance authentication, managed-network
ownership verification, bounded raw-output parsing, continuous inspection, and live
sandbox conformance tests remain absent. Isolation invariants are not claimed verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Bounded OCI runtime snapshot collector

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without worker or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Fixed Docker/Podman information and network-inspection commands,
trusted executable checks, timeout/output/argument limits, strict JSON parsing,
runtime/network identity binding, PentAI ownership labels, typed snapshot conversion,
and attestor integration.

**Evidence examined:** Command templates cannot be supplied by consumers; option-like
and oversized identifiers deny construction; wrong runtime/network identities,
unsupported versions, non-rootless mode, unavailable limits, missing ownership labels,
external networks, IPv6, nonzero exits, malformed/multiple/oversized JSON, command
changes, and invalid bounds fail closed. Synthetic Docker and Podman success paths emit
typed snapshots and a contract-valid non-executing attestation.

**Findings:** The collector adds no launch or network effect. Diagnostics suppress raw
runtime output. Exact management labels bind observations to the configured PentAI
instance but do not independently prove firewall behavior.

**Limitations and deferred work:** No daemon was invoked. Docker/Podman output remains
fixture-verified rather than cross-platform verified. Managed-network creation,
firewall enforcement, live bypass/conformance probes, continuous reinspection, worker
launch, and termination remain absent. Isolation invariants are not claimed verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Managed gateway network and conformance gate

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without worker or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Idempotent Docker/Podman internal-network provisioning, ownership
and identity validation, non-destructive failure handling, pinned local conformance
probe command, strict probe output, and mandatory collector conformance evidence.

**Evidence examined:** Ambiguous, unowned, externally routed, IPv6-enabled, malformed,
failed, raced, or unverifiable networks deny provisioning. Probe image mutability,
identity mismatch, invalid types/output, nonzero exit, excessive output, and any
successful bypass deny safe snapshot production. Fixed commands use bounded synthetic
TEST-NET destinations only.

**Findings:** The preceding collector treated internal metadata and labels as sufficient
to set DNS and direct-egress controls true. This slice closes that assurance gap by
requiring independent live probe evidence. No caller without a conformance verifier can
construct the collector.

**Limitations and deferred work:** The local Docker daemon is version 29.6.2 but did
not report rootless mode, so no network was created and no live probe was launched.
Docker/Podman command behavior remains fixture-tested. A reviewed pinned probe image,
rootless cross-platform runs, gateway and firewall setup, continuous probes, worker
termination, and the full bypass matrix remain absent. Isolation invariants are not
claimed verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.
