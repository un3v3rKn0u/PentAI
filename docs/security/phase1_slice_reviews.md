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

## 2026-08-09 — Rootless network-probe fixture and hosted conformance harness

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development and hosted TEST-NET-only verification without worker or target
execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Dependency-free static probe, `scratch` image construction,
content-addressed invocation, fixed TEST-NET destinations, rootless-runtime gate,
run-scoped cleanup, strict result parsing, and direct-egress, DNS, IPv6,
runtime-socket, host-mount, host-PID-namespace, and resource-limit signals.

**Evidence examined:** Rust tests reject changed destinations, unsafe network IDs,
missing, duplicate, and unknown arguments. Python tests reject rootful, missing,
malformed, and failed runtime evidence; legacy or malformed probe output; identity
mismatch; and each negative containment result. The OCI command uses a read-only root,
non-root UID, dropped capabilities, no-new-privileges, fixed limits, an exact managed
network, and a locally obtained SHA-256 image ID. Image construction has no base image,
pull, or network access.

**Findings:** The earlier command could not bind real probe output to its network because
it did not pass the expected network ID. It also represented only three network
signals. This slice binds the identity explicitly and makes all seven signals mandatory.
The harness refuses to build or create runtime resources before rootless mode is
verified and removes only its UUID-named fixtures.

**Limitations and deferred work:** The local Docker daemon is not rootless and was not
used. Hosted Linux Podman must pass before live containment evidence exists. The PID-1
signal detects host PID namespace use but does not exhaust every namespace escape.
Rootless Docker, macOS, Windows, gateway attachment, firewall enforcement, continuous
probing, proxy/DoH/DoT/raw-route bypasses, worker launch, and termination remain absent.
Isolation invariants are not claimed verified.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Durable non-target gateway runtime lifecycle

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without HTTP, DNS, worker, or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Additive migration `0011`, GatewayRuntimeInstance v1, fixed OCI
sentinel commands, post-launch inspection, repeatable watchdog checks, durable safety
adapter, hash-chained lifecycle audit events, immutable lifecycle history, and startup
termination recovery.

**Evidence examined:** Missing/stale containment, inactive sessions, mutable image
identity, replay, changed runtime/network identity, inspection failure, control drift,
launch failure, termination failure, and failed-cleanup recovery deny or halt. Commands
use a read-only root, non-root image user, dropped capabilities, no-new-privileges,
private namespaces, no binds/runtime socket, fixed resources, exact network, ownership
labels, and a SHA-256 image identity. The sentinel accepts no target or URL argument.

**Findings:** The container ID is persisted immediately after launch and before
inspection so a crash or cleanup failure leaves a recoverable durable identity.
Termination failure remains fail-closed and retryable rather than being finalized as
success. Runtime records and their authority bindings cannot be deleted or rewritten.

**Hosted evidence:** PR #44's Linux rootless Podman workflow passed live sentinel
launch, exact internal-network attachment, kernel verification that inheritable,
permitted, effective, bounding, and ambient capability masks were zero, repeated
containment monitoring, explicit termination, and startup-recovery termination.

**Limitations and deferred work:** The local Docker daemon is rootful and was not used.
Application-startup watchdog wiring, controlled DNS transport, outbound gateway
networking, HTTP sockets, redirect handling, worker attachment, and continuous
production scheduling remain absent. Other operating systems and production deployment
were not containment-verified. Target-facing execution is still prohibited.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Application-owned gateway runtime supervision

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without HTTP, DNS, worker, or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Core startup ordering, injected runtime-supervisor ownership,
recovery-before-readiness, bounded watchdog thread lifetime, degraded health, missing
supervisor behavior, direct safety pause, authenticated shutdown, and idempotent
framework cleanup.

**Evidence examined:** Tests prove successful recovery precedes ready state; recovery
and watchdog failures pause safety and remain degraded; a possibly live durable runtime
with no configured supervisor returns degraded readiness; shutdown stops monitoring and
retries durable cleanup; repeated shutdown does not repeat successful cleanup; and
diagnostics contain only fixed reason codes and non-authoritative counts/state.

**Findings:** The core previously revoked grants and paused assessments on startup but
did not own the merged sentinel lifecycle. It could therefore report ready without
terminating a recorded sentinel or starting continuous checks. The supervisor closes
that application-lifetime gap while preserving `execution_enabled: false`.

**Limitations and deferred work:** OCI runtime construction is still injected rather
than built from production configuration. Hosted process-kill testing of the composed
core, other operating systems, route/source-IP attestation, controlled DNS, HTTP,
redirects, worker attachment, and production scheduling remain unverified or absent.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-09 — Strict gateway runtime composition and crash harness

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without HTTP, DNS, worker, or target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Disabled-by-default runtime configuration, complete identity and
digest validation, trusted executable construction, production supervisor composition,
recovery ordering, continuous containment revalidation, fixed degraded diagnostics,
and the hosted abrupt-process-loss harness.

**Evidence examined:** Unit and integration tests prove partial or ambiguous opt-in,
unsupported runtimes, relative executable paths, malformed identities, mutable image
references, invalid watchdog bounds, and unavailable executables deny or degrade. Tests
also prove durable cleanup precedes containment revalidation, readiness follows both,
watchdog checks repeat, and execution remains false. The hosted harness uses a spawned
child that launches only the repository sentinel and exits through `os._exit`; a new
production-composed supervisor must terminate the durable container and pause its
synthetic owning assessment.

**Findings:** Core previously accepted only an injected lifecycle and therefore could
not establish the trusted runtime, managed-network, and pinned-probe identities from
operator configuration. Strict composition closes that gap without provisioning a
network, building an image, or creating any target-facing capability.

**Hosted evidence recorded 2026-08-10:** PR #47's Linux rootless Podman job passed the
TEST-NET containment matrix, launched the non-networking sentinel in a spawned
application process, ended that process abruptly, and verified that a newly
production-composed supervisor terminated the durable container and paused its
synthetic owning assessment. Quality, dependency review, CodeQL, and Ubuntu, macOS,
and Windows desktop smoke jobs also passed.

**Limitations and deferred work:** The local Docker daemon is rootful, so the live
crash harness was not run locally. Machine reboot, production deployment, route and
source-IP attestation, controlled DNS, HTTP, redirects, and worker attachment remain
unverified or absent.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not approve production use, worker execution, or target-facing networking.

## 2026-08-10 — Continuous network-identity kill switch

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Application startup/readiness/shutdown ownership, bounded network
identity watchdog, current-attestation comparison, expiry and authorization-race
handling, assessment/global safety transitions, fixed diagnostics, and audit linkage.

**Evidence examined:** Tests cover successful pre-readiness and repeat checks; route,
resolver, source, observer, expiry, missing-monitor, state-query, startup, watchdog,
pause, and shutdown failures; prepared-session abortion and reservation release;
attestation/grant invalidation; fixed health output; and authenticated shutdown.

**Findings:** A successful monitor check does not rotate or extend authority. Any
failure uses the existing atomic assessment safety transition, while unexpected
supervisor failure also pauses global safety and degrades readiness. Audit events omit
source addresses and raw observer output. No AI, UI, worker, or tool can configure or
claim monitor success.

**Limitations and deferred work:** Attestors remain injected. Production public-IP
endpoints, platform route inspection, live resolver transport, gateway sockets,
redirect execution, worker attachment, and machine-reboot evidence remain absent.
Target-facing execution remains prohibited.

**Residual risk accepted:** This review is self-authored and non-independent. It does
not satisfy an external independence requirement and does not approve production or
target-facing networking.

## 2026-08-10 — Production-composable network attestor

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Disabled-by-default configuration, HTTPS observer parsing and
transport, per-family agreement, operating-system route and resolver collection,
exact expected-state comparison, supervisor composition, degraded readiness, and
fixed safety diagnostics.

**Evidence examined:** Owned-fixture tests cover explicit/incomplete configuration,
unique origins, HTTPS-only/default-port endpoints, credentials and query rejection,
bounded response handling, malformed/extra JSON, public and wrong-family addresses,
single-observer family denial, observer agreement, interface/gateway/resolver drift,
ambiguous route output, pre-readiness attestation, and composition failure. Full core,
contract, lint, type, packaging, and dependency checks are required before review.

**Findings:** Ambient proxies cannot redirect observer traffic; redirects are not
followed; normal TLS hostname/certificate verification remains mandatory. No UI, AI,
worker, or public API controls configuration or supplies measurements. Missing,
ambiguous, unsupported, or malformed state pauses safety and never enables execution.

**Limitations and deferred work:** Repository tests contact no external observer and
cannot prove operator independence, live VPN behavior, or platform command output.
Controlled DNS transport enforcement, firewall bypass evidence, gateway HTTP sockets,
redirect execution, and worker attachment remain absent. Windows and Linux route
collection require hosted verification.

**Residual risk accepted:** Distinct origins do not prove infrastructure independence,
and this review is self-authored and non-independent. It does not approve production
or target-facing networking.

## 2026-08-10 — Pinned controlled-DNS transport

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Explicit configuration, attested-server binding, TCP and DoT
framing, TLS requirements, transaction construction, DNS name compression parsing,
response validation, A/AAAA and CNAME extraction, application composition, diagnostics,
compatibility, and rollback.

**Evidence examined:** Owned-fixture tests cover pinned server/port/timeout/TLS
arguments, TCP framing, TLS 1.2 minimum, independent A/AAAA transactions, canonical
questions, CNAME merging, replay/spoofed IDs, truncation, result codes, mismatched
questions, compression loops, malformed/trailing records, transport failure, invalid
transaction sources, incomplete opt-in, resolver-set mismatch, transport-mode mismatch,
environment parsing, and attestation-bound resolver use.

**Findings:** The transport never invokes the ambient resolver because it connects to
a canonical literal address. It never reads proxy configuration or falls back to UDP,
another server, or plaintext for approved-resolver mode. Wire failures are fixed-code
denials and no packet content is logged or audited. UI, AI, workers, and API callers
cannot select a resolver or supply a response.

**Limitations and deferred work:** Tests do not send live DNS. Resolver-specific route
proof, hosted DoT/certificate failure, worker firewall denial of port 53/853, DoH,
custom resolvers, raw sockets, gateway HTTP integration, and redirect execution remain
absent. This does not fully satisfy `INV-NET-003`.

**Residual risk accepted:** TCP/53 relies on the separately attested tunnel for
confidentiality and integrity, platform routing has not been independently verified,
and this review is self-authored and non-independent. It does not approve production
or target-facing networking.

## 2026-08-10 — Non-authoritative network profile discovery

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** OS-local route and resolver discovery, canonicalization,
deterministic identifiers, proposal expiry, authenticated API exposure, fixed failure
diagnostics, explicit unresolved requirements, and UI degraded/recovery states.

**Evidence examined:** Contract, unit, authentication, and UI tests cover stable
identities, unique proposals, canonical IP values, duplicate resolver normalization,
bounded lifetime, empty/malformed/oversized observations, naive clocks, probe failures,
fixed diagnostics, and explicit human-review messages.

**Findings:** The proposal cannot persist, approve, attest, grant, or activate
authority. It contains no registered source IP and fixes execution to false. Discovery
contacts neither observers nor targets and returns no raw probe details.

**Limitations and deferred work:** Platform discovery behavior still requires hosted
and live-environment evidence. Profile persistence, confirmation, resolver-mode
selection, registered source-IP validation, observer configuration, activation,
revocation, and audit linkage remain absent. Target-facing execution remains
prohibited.

**Residual risk accepted:** Host commands and resolver files can reflect stale or
compromised local state, so every value remains an untrusted proposal. This review is
self-authored and non-independent and does not satisfy an external independent-review
requirement.

## 2026-08-11 — Durable network profile confirmation and revocation

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Immutable proposal persistence, explicit route confirmation,
resolver and IPv6 choice validation, registered public source-IP validation, proposal
expiry/replay checks, one-active-profile enforcement, revocation, API/UI states,
bounded pending-proposal capacity, contract validation, migration constraints, and
hash-chained audit linkage.

**Evidence examined:** Unit, migration, API authentication, contract, and UI tests
cover activation and revocation, missing confirmation, stale/missing/replayed
proposals, non-public or absent source addresses, resolver and IPv6 conflicts, active
profile collision, database mutation/deletion attempts, audit integrity, and omission
of raw source addresses from audit data.

**Findings:** Only the authenticated human principal can confirm or revoke. Activation
uses the exact stored proposal rather than accepting route data from the client. It
cannot replace an active profile or enable execution. Database constraints retain
immutable history and require an explicit active-to-revoked transition.

**Limitations and deferred work:** A confirmed profile is configuration, not an
attestation. Observer designation, live public-IP comparison, controlled resolver
provisioning, policy binding, continuous re-attestation, and hosted live platform
evidence remain required. Target-facing execution remains prohibited.

**Residual risk accepted:** The sole local bearer principal represents the human
operator, and public source-IP ownership is asserted rather than independently proven
at confirmation time. This self-authored review is non-independent and cannot satisfy
an external independent-review requirement.

## 2026-08-11 — Durable profile-to-policy attestor binding

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Active profile lookup, active-policy matching, dynamic route
inspector/attestor composition, removal of duplicated environment authority, observer
configuration validation, startup/watchdog failure behavior, and manifest draft
population from confirmed profile state.

**Evidence examined:** Core and UI tests cover exact binding, missing and mismatched
profiles, observer-only configuration, legacy environment values being ignored by
attestation, profile-derived route measurements, startup degradation and safety pause,
and profile-derived versus unresolved manifest network sections.

**Findings:** The attestor is constructed only after the active profile and policy
match on route ID, registered IPv4/IPv6 arrays, IPv6 mode, and resolver mode. Route
interface, gateway, resolver ID, and resolver addresses come only from the durable
profile. Missing or malformed state fails closed before measurement. No API, UI, AI,
worker, or legacy route environment value can replace the selected profile.

**Limitations and deferred work:** Observer URLs remain explicit trusted deployment
configuration and no real observer is designated or contacted in tests. Controlled
DNS still has a separate legacy resolver configuration path. Live public-IP/route
matrices and cross-platform evidence remain required. Target-facing execution remains
prohibited.

**Residual risk accepted:** Profile confirmation asserts source-IP ownership, while
observer independence remains an operator responsibility. This self-authored review
is non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Controlled DNS durable-profile binding

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Per-assessment controlled-resolver composition, active
policy/profile lookup, resolver-mode and identifier binding, allowed-address
membership, pinned TCP/53 versus verified DoT selection, compatibility of legacy
environment fields, and application startup wiring.

**Evidence examined:** Unit and integration tests cover profile-derived resolver
identity, fresh lookup for each assessment, pinned-server exclusion, resolver-mode/TLS
mismatch, malformed or empty resolver state, configuration bounds, DNS wire parsing,
and attestation identity comparison. The complete diff, INV-NET-002/003, rollback,
and deferred containment requirements were reviewed.

**Findings:** Resolver authority now comes only from the same durable profile that must
match the active policy. Transport settings can pin how to reach that resolver but
cannot introduce a resolver absent from the profile. Revocation or profile/policy
mismatch propagates as a denial before DNS resolution. Legacy resolver environment
values remain accepted for compatibility but are ignored by composition.

**Limitations and deferred work:** No live resolver, public observer, worker, or target
is contacted by repository tests. OS/container firewall enforcement against alternate
DNS, hosted resolver matrices, gateway HTTP integration, and cross-platform live
evidence remain required. Target-facing execution remains prohibited.

**Residual risk accepted:** The pinned transport address and optional TLS hostname
remain trusted local deployment choices constrained by the profile rather than
automatically provisioned network resources. This self-authored review is
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Gateway DNS authorization preflight

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Pre-resolution grant and attestation validation, assessment
derivation, trusted resolver-source selection, policy/safety/revocation checks,
post-resolution transactional revalidation, diagnostics, compatibility, and rollback.

**Evidence examined:** Integration tests cover exact assessment derivation, invalid
grant and paused/inactivated attestation denial with zero resolver-source calls,
profile-bound resolver identity, DNS rebinding, special-address and IPv6 denial,
SNI/Host mismatch, and the existing transactional destination decision. The complete
diff and INV-AUTH-001/002/003, INV-GRANT-001/004, INV-SCOPE-003, and INV-NET-002/003
were reviewed.

**Findings:** Controlled DNS no longer occurs before runtime authority validation.
Neither a caller-provided assessment identifier nor a resolver identity can replace
the engagement derived from the signed grant and matching attestation. The second
transactional check preserves default denial if authority changes during resolution.

**Limitations and deferred work:** The trusted resolver source is an internal Python
composition boundary, not an isolated gateway process. Tests use synthetic DNS packets
and do not contact a live resolver, worker, observer, or target. Live redirects, HTTP
sockets, firewall enforcement, and cross-platform containment evidence remain required.
Target-facing execution remains prohibited.

**Residual risk accepted:** A compromise of the local core process can replace in-memory
dependencies; process isolation and gateway binary enforcement remain future controls.
This self-authored review is non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-11 — Durable redirect-chain authorization

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Redirect parent linkage, relative-location resolution, derived hop
counts, one-child enforcement, grant and attestation continuity, same-host rebinding,
changed-host reauthorization, migration compatibility, diagnostics, and rollback.

**Evidence examined:** Integration tests cover allowed relative redirects, exact
persisted lineage, parent replay with zero DNS calls, independently allowed changed
hosts, same-host DNS rebinding, maximum-hop denial, malformed control-bearing
locations, protocol/port/scope/SNI checks inherited from destination authorization,
and additive migration/idempotency. The complete diff and INV-SCOPE-001/002/003,
INV-GRANT-001/002/004, INV-NET-002/003, and recovery implications were reviewed.

**Findings:** Callers can no longer supply a root redirect count. Each next target is
derived from one allowed parent for the same grant and attestation, and the database
prevents a second child. DNS pin comparison is limited to the same host and port, so a
different explicitly in-scope host is reauthorized rather than falsely treated as
rebinding. Missing, denied, foreign, malformed, replayed, or over-limit state denies.

**Limitations and deferred work:** Redirect responses are not fetched; `Location` is
synthetic input to a non-networking control plane. There is no HTTP loop, response
parser, isolated gateway-process enforcement, live resolver, or target contact.
Cross-platform live redirect and containment matrices remain required, and
target-facing execution remains prohibited.

**Residual risk accepted:** The redirect lineage is enforced in SQLite and the local
core process rather than a separately isolated gateway binary. This self-authored
review is non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-11 — Durable gateway rate reservations

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Global and per-host token-bucket persistence, canonical host-key
derivation, atomic preparation, concurrent contention, refill arithmetic, clock
rollback, abort/pause/stop/startup refunds, capacity bounds, migration compatibility,
audit linkage, diagnostics, and rollback.

**Evidence examined:** Integration tests cover simultaneous reservations at one burst
token, deterministic exhaustion, refill after the policy interval, durable global and
host state, capped abort refunds, existing total/concurrency interaction, safety
recovery, and additive migration/idempotency. The complete diff and INV-NET-005,
INV-AUTH-003, INV-GRANT-001/004, INV-REC-001/002, and clock-trust implications were
reviewed.

**Findings:** The immutable allowed destination supplies the canonical host key. Both
buckets and existing budgets update under one `BEGIN IMMEDIATE` transaction, so any
failure rolls back all reservations. A preparation cannot exceed burst capacity,
concurrent callers serialize safely, and backward wall-clock movement denies new
capacity. Tokens return only while the session remains prepared and are capped.

**Limitations and deferred work:** Tokens are reservations for non-executing sessions;
there is no isolated request-start transition that permanently commits them. No HTTP
socket, worker, live resolver, observer, or target is used. Response bytes, deadlines,
gateway-process enforcement, and cross-platform live timing evidence remain required.
Target-facing execution remains prohibited.

**Residual risk accepted:** Refill uses the system wall clock persisted in SQLite;
rollback denies but forward clock jumps can refill to burst capacity. A future trusted
clock-health control remains required before execution. This self-authored review is
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Atomic gateway request-start commitment

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Last-boundary authority revalidation, single-use grant
consumption, total/rate commitment, bounded deadlines, replay and concurrent commit,
abort behavior, pause/stop/startup cancellation, audit linkage, migration
compatibility, diagnostics, and rollback.

**Evidence examined:** Integration tests cover valid atomic commitment, schema
validation, expiry denial without partial mutation, two-thread contention, replay,
non-refundable abort denial, and startup recovery that preserves committed request
and rate capacity while releasing the connection slot. Migration tests cover additive
installation, idempotency, immutable identity, and non-deletable history. The complete
diff and INV-GRANT-001/004, INV-NET-005, INV-AUTH-003, and INV-REC-001/002 were
reviewed.

**Findings:** One `BEGIN IMMEDIATE` transaction rechecks canonical stored grant,
intent, destination, policy, attestation, safety, expiry, and signature state before
consuming the grant and committing capacity. Failure rolls back every mutation.
Committed capacity is never refunded, and recovery cancels only the execution-disabled
handoff while closing its concurrency slot.

**Limitations and deferred work:** No socket, HTTP parser, response-byte meter, live
resolver, isolated gateway-process enforcement, worker, observer, or target is used.
The persisted deadline is not yet enforced by a live I/O loop. Target-facing execution
remains prohibited until the remaining containment and bypass proofs exist.

**Residual risk accepted:** Enforcement remains in the local core process and uses a
wall-clock deadline. A compromised process or forward clock jump is not independently
contained. This self-authored review is non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-11 — Bounded gateway response accounting

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Chunk bounds, proof-byte semantics, absolute deadline checks,
trusted-clock rejection, durable outcome derivation, request/session/grant linkage,
concurrency release, replay, recovery interaction, audit data, schema/migration
compatibility, diagnostics, and rollback.

**Evidence examined:** Unit tests cover exact-limit completion, split-chunk overflow,
deadline crossings, invalid/empty chunks, and naive clocks. Integration tests cover
atomic successful finalization, immutable contract output, committed capacity
preservation, exact concurrency release, replay denial, contradictory limit outcome
rollback, and durable deadline outcome. Migration tests cover additive installation,
idempotency, immutable rows, and non-deletable history. The complete diff and
INV-NET-005, INV-AUTH-003, INV-GRANT-001/004, and INV-REC-001/002 were reviewed.

**Findings:** The reader never retains more than the policy/grant response ceiling and
records at most one additional byte to prove overflow. The transactional finalizer
does not trust the reported hard-limit outcome: it re-derives it from durable deadline
and reservation state before closing the connection slot and writing linked immutable
history. Any disagreement rolls back all state.

**Limitations and deferred work:** Tests use in-memory chunks. The reader cannot
interrupt a transport blocked between chunks, so a future isolated gateway must apply
the absolute deadline to every I/O operation. There is no socket, HTTP parser, TLS,
live resolver, redirect fetch, evidence body, worker, or target contact. Target-facing
execution remains prohibited.

**Residual risk accepted:** Accounting remains in the local core process and trusts a
future isolated gateway to report its bounded measurement. A compromised reporter is
not yet independently contained. This self-authored review is non-independent and
cannot satisfy an external independent-review requirement.

## 2026-08-11 — Isolated HTTP TEST-NET fixture transport

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without external target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Fixed target/method/host/path validation, OCI argument
construction, image digest and network identity, TEST-NET subnet restriction,
rootless/internal containment, monotonic connect/write/read deadlines, HTTP status and
header framing, response proof-byte bounds, typed output validation, fixture cleanup,
workflow permissions, compatibility, rollback, and diagnostic disclosure.

**Evidence examined:** Rust tests cover exact accepted arguments, changed/real target
denial, missing/duplicate/unknown arguments, timeout/size bounds, status denial,
transfer-encoding denial, and ambiguous content length. Python tests inspect the exact
fixed OCI command and reject unsafe identities, bounds, types, outcomes, counts, JSON,
and process failures. Managed-network tests prove only the documentation TEST-NET
subnet is accepted. The hosted workflow is configured to exercise a successful
17-byte request and an 8-byte limit-plus-one stop while rerunning all containment and
lifecycle probes. The complete diff and INV-NET-001/003/004/005, INV-ISO-001/003,
INV-AUTH-003, and recovery implications were reviewed.

**Findings:** The core has no target socket implementation. The fixed OCI adapter
cannot select a real address, alternate host/path/method, or unconstrained deadline or
response size. The Rust client reads headers under a separate hard ceiling, rejects
ambiguous framing, and never reads more than one body byte beyond the authorized
limit. Only typed counts leave the container; response content does not.

**Limitations and deferred work:** Live rootless containment is not claimed until the
hosted workflow passes. The transport is HTTP-only and fixed to an owned synthetic
fixture. It does not load or verify grants/starts inside the process, use controlled
DNS, perform TLS, follow redirects, preserve evidence, expose a product API, route a
worker, or reach an external target. General target-facing execution remains
prohibited.

**Residual risk accepted:** The fixture server and client share one internal bridge,
and the host-side OCI adapter supplies relative timeout and response bounds. A future
gateway must load immutable authority itself, use its absolute deadline, re-attest a
dual-homed route, and terminate live sessions on safety changes. This self-authored
review is non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-11 — Durable fixture execution authority binding

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without external target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** One-use execution-claim schema and migration, committed-start and
grant validation, budget/rate/destination/runtime linkage, containment identity,
absolute deadline propagation, claim-bound finalization, replay behavior, recovery,
audit linkage, hosted workflow triggers, compatibility, and rollback.

**Evidence examined:** Migration tests prove additive application, idempotence, and
immutable identity/status history. Authorization integration tests exercise the exact
owned fixture decision, reject containment mismatch and missing claim identity, deny
replay, complete the claim atomically with the request result, and abandon an
unfinalized claim during startup recovery. Adapter tests inspect the fixed OCI vector
and absolute deadline, reject unsafe or stale inputs, and prove the coordinator claims
before transport and binds finalization. Rust tests reject expired or overlong
deadlines and continue to cover strict HTTP framing and response bounds. The hosted
rootless workflow is triggered by every authority, contract, migration, adapter, and
probe file in this slice.

**Findings:** AI, UI, and worker state cannot mint authority. Only the deterministic
core may create a claim, and only after reloading all durable prerequisite state in an
immediate transaction. A start and runtime can each be claimed once. The adapter
derives every effect parameter from the schema-valid claim and fresh matching
containment, while the isolated client converts the absolute wall deadline once to a
monotonic I/O deadline. Finalization without the matching active claim rolls back.

**Limitations and deferred work:** The effect remains fixed to the owned HTTP TEST-NET
fixture and is not exposed through the product API or UI. The isolated probe does not
independently load signed grants or database state. HTTPS/TLS, policy-derived
destinations, live controlled DNS, redirects, evidence bodies, worker routing, and
external targets remain prohibited. Live rootless evidence is not claimed until the
hosted workflow passes.

**Residual risk accepted:** The trusted core creates the claim and supplies it to the
isolated adapter; compromise of that same core is not independently checked inside the
probe. Runtime termination after a successful one-shot request remains owned by the
existing lifecycle supervisor. This self-authored review is non-independent and cannot
satisfy an external independent-review requirement.

## 2026-08-11 — Owned fixture end-to-end hosted proof

**Decision:** Sole-maintainer security review — non-independent; accepted for local
synthetic development without external target-facing execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Hosted composition of source provenance, manifest validation,
signed policy lifecycle, supervised intent, deterministic decision, single-use grant,
network attestation, controlled fixture DNS, budget/rate commitment, request start,
verified runtime lifecycle, execution claim, isolated effect, result finalization,
audit verification, response overflow, and cleanup.

**Evidence examined:** Local tests create the full committed authority chain, validate
its session/start contracts and audit hash chain, inspect committed grant and budget
state, confirm the fixed pinned address, and reject invalid response ceilings and
every alternate DNS tuple. The rootless workflow is configured to run two independent
durable chains: one completes the owned 17-byte response and one proves the eight-byte
limit with exactly one additional observation byte. It also requires every privileged
audit action, exact start/result linkage, a valid complete audit chain, verified
runtime termination, and the existing direct-egress bypass matrix and crash recovery.

**Findings:** The hosted HTTP effect no longer relies on a synthetic host-created
claim. It is reachable only after all deterministic authority and containment layers
produce matching durable state. Separate chains avoid grant, start, claim, runtime,
and budget reuse. The first hosted run exposed that the request-start transaction
consumed its grant without a dedicated consumption audit event. The corrected boundary
now appends that event atomically with the grant update and start, including exact
intent, decision, policy, session, start, and grant-hash linkage; rollback tests prove
denied starts append nothing. Failure of any expected link or cleanup step fails the
workflow.

**Limitations and deferred work:** Hosted results are not claimed until the Linux
rootless workflow passes. The only destination remains the repository-owned HTTP
TEST-NET fixture. HTTPS/TLS, live resolver transport in the isolated gateway,
policy-derived external destinations, redirect execution, response evidence, worker
routing, product API/UI exposure, and all public/customer targets remain prohibited.

**Residual risk accepted:** The conformance harness uses deterministic synthetic
source, route, observer, and DNS adapters and local-development signing/storage keys.
It proves component composition and live containment, not production observer
independence, key custody, or an external route. This self-authored review is
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Durable supervised assessment workflow boundary

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development without task dispatch or external effects<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Assessment workflow and task contracts, additive migration,
version-fenced lifecycle, human start/resume, idempotent task persistence, parent
linkage, cancellation, startup pause recovery, API authentication, audit/outbox
linkage, compatibility, and rollback.

**Evidence examined:** Contract validation, migration upgrade and trigger tests,
concurrent transition fencing, idempotent replay and conflict tests, stale safety and
policy denial, parent cancellation ordering, unresolved-task completion denial,
atomic queue cancellation, startup pause/no-auto-resume behavior, authenticated-route
coverage, and audit-chain verification.

**Findings:** Workflow state and task records cannot grant authority or dispatch work.
The schemas and database fix execution capabilities to false. Human supervision and a
fresh active authority check are required before entering or re-entering running state.
Startup recovery always pauses previously running work. Mutations are durable and
audit-linked in the same transaction.

**Limitations and deferred work:** Tasks have no claimable state. Leases, heartbeats,
worker fencing, retries, checkpoints, dead letters, and execution integration are not
implemented. There is no supervised assessment UI in this slice. Hosted checks do not
prove live worker recovery or dispatch because both remain prohibited.

**Residual risk accepted:** The current queue is useful only as durable supervised
intent; an operator must cancel tasks before completing a workflow. Future claiming
semantics will require a separate security review and crash-window proof. This
self-authored review is non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-11 — Durable task leases and crash-safe retry lifecycle

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development without worker dispatch or external effects<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Additive lifecycle migration and backfill, lease/lifecycle/
checkpoint contracts, authenticated claiming, version and token fencing, bounded
heartbeats, monotonic checkpoints, idempotent terminal receipts, retry exhaustion,
dead letters, workflow cancellation, startup recovery, audit/outbox linkage,
compatibility, and rollback.

**Evidence examined:** Concurrent claim tests prove one winner. Negative tests reject
stale versions, mismatched or expired tokens, inactive authority, paused workflows,
decreasing progress, premature retry, malformed clocks, and attempts beyond the fixed
maximum. Recovery tests invalidate live leases without automatic reclaim. Migration
tests cover additive application, old-task backfill, transition triggers, immutable
checkpoints/receipts, and idempotence. The full audit chain remains valid.

**Findings:** A task mutation requires the latest durable version and matching opaque
lease token; the database stores only its digest. API claim identity comes from the
authenticated principal rather than request data. Terminal retries return an immutable
receipt without repeating the state transition. Startup converts interrupted attempts
to retry wait or dead letter and pauses running workflows before future work.

**Limitations and deferred work:** Claims are coordination authority only. No worker
is launched, no task is dispatched, and no gateway or target-facing action is enabled.
Checkpoint output values are UUID references only; evidence storage is deferred. The
UI does not yet expose task recovery or dead-letter controls.

**Residual risk accepted:** Lease owners currently use local API principals rather
than independently attested worker identities because worker dispatch remains absent.
Future worker binding must introduce runtime identity and revalidate every external
effect through the existing authorization/gateway chain. This self-authored review is
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Append-only audit and complete fixture execution trace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
owned-fixture development without external target execution<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** AuditEvent and ExecutionTrace contracts, additive migration,
database immutability and chain-head enforcement, startup verification, malformed
legacy data, atomic trace creation, foreign-key-derived authority links, tool/runtime
version, bounded output reference, API authentication, compatibility, and rollback.

**Evidence examined:** Existing domain coverage verifies the complete ledger after
privileged intake, policy, grant, network, gateway, runtime, workflow, and recovery
events. New negative tests deny row mutation, deletion, forged-head insertion,
malformed legacy-event startup, trace mutation/deletion, and result replay. The owned
fixture integration test validates the trace contract and exact intent, decision,
evaluated-rule, policy, grant, request, claim, runtime image, result, and audit links.
Migration tests cover additive/idempotent application and all protection triggers.

**Findings:** Existing writers already compute canonical hashes and append within
domain transactions. Migration 0020 closes direct update/delete and forked-head gaps.
Startup now validates the entire ledger before recovery writes or supervisors start.
The finalizer derives trace identity exclusively from immutable database joins and
rolls back result, claim completion, audit event, and trace together if any link or
contract is missing or malformed.

**Limitations and deferred work:** The trace contract covers the only currently
enabled effect, the owned TEST-NET fixture. General HTTP(S), external destinations,
and evidence bodies remain prohibited. Output linkage identifies the immutable bounded
gateway result; encrypted evidence content and chain of custody are later slices. The
ledger is hash-chained but not externally anchored or independently signed.

**Residual risk accepted:** A process with arbitrary database-file replacement access
could replace the entire database and its chain; local OS access control and future
backup/export anchoring remain defense layers. Hash chaining proves internal
continuity, not independent timestamping. This self-authored review is non-independent
and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Encrypted immutable evidence originals

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic evidence only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** EvidenceOriginal and EvidenceCustodyEvent contracts, additive
migration, authenticated bounded ingestion, content-addressed authenticated encryption,
HKDF domain separation, workflow/policy/execution-trace linkage, immutable metadata,
custody/audit events, storage-failure stop behavior, compatibility, and rollback.

**Evidence examined:** Tests cover ciphertext-at-rest, digest verification, wrong-key
and modified-ciphertext denial, unavailable-key denial and stop notification, size,
type, classification and media-type rejection, idempotency conflicts, database update
and deletion denial, custody/audit coverage, contract validation, migration
idempotence, Ruff, mypy, and the full Python suite. Only clearly synthetic local bytes
were used.

**Findings:** Evidence content never enters SQLite or the audit ledger. The desktop's
existing OS-keychain-backed master secret requires no additional user setup and derives
a distinct evidence AEAD key. Metadata authority comes from the durable supervised
workflow; optional execution traces must share its engagement and policy. Original
content has no HTTP read route, and any key/blob failure in the composed application
stops global execution pending human recovery.

**Limitations and deferred work:** Sandboxed previewing, format-specific parsing,
redaction derivatives, retention and secure deletion, export manifests, backup/restore,
findings, reports, and Evidence UI are not implemented. The custody chain is locally
hash-chained but not externally timestamped. Hosted cross-platform checks still need
to run on the pull request.

**Residual risk accepted:** The evidence key derives from the existing source master
secret, so loss of that single OS credential makes both stores unavailable; key
rotation and backup recovery remain release blockers. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Immutable text redactions and inactive previews

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic evidence only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** EvidenceRedaction, EvidencePreview, and derivative-event contracts;
additive migration; deterministic server-side range replacement; explicit human
classification confirmation; source and derivative digest provenance; authenticated
derivative-only preview; encryption, immutability, custody/audit linkage, compatibility,
and rollback.

**Evidence examined:** Tests cover encrypted derivative bytes, authenticated source
loading, literal script content returned only as inert plain text, explicit
classification confirmation, idempotent replay/conflict, ordered and non-overlapping
range enforcement, range bounds, unknown reasons, binary and invalid-UTF-8 denial,
original-preview denial, ciphertext tamper denial, immutable rows/events, event and
audit coverage, migration idempotence, contract validation, Ruff, mypy, and the full
Python suite. Fixtures contain synthetic local data only.

**Findings:** Callers identify ranges but cannot upload derivative content or choose
replacement text. The core authenticates the original, generates the derivative with
a fixed marker, records exact source and output hashes, and requires a human to confirm
any `public` or `internal` derivative classification. The preview route accepts only a
derivative ID and returns bounded `application/json` with fixed plain-text rendering
metadata; original content remains unavailable over HTTP.

**Limitations and deferred work:** No UI renderer exists yet, so hosted checks can
verify the contract/API but not a browser sandbox. Consumers must not use HTML
injection APIs. Image/PDF parsing, original previews, annotations, retention and secure
deletion, export manifests, model routing, findings, reports, and UI remain deferred.

**Residual risk accepted:** A future consumer could violate the plain-text contract;
the Evidence UI must add its own sandbox and negative browser tests before general
preview support is claimed. The local custody chain is not externally timestamped.
This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-11 — Policy-derived retention and crash-safe content deletion

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic evidence only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** EvidenceDeletion contract, additive migration and transition
triggers, immutable-policy retention derivation, exact artifact/digest binding, human
confirmation and reason, durable-before-filesystem ordering, immediate tombstone
enforcement, shared content-addressed references, directory synchronization, startup
recovery, audit linkage, compatibility, rollback, and erasure claims.

**Evidence examined:** Negative tests reject missing confirmation, artifact-type and
digest mismatch, and deletion before the policy deadline without persisting a request.
Success tests cover last-reference unlink, shared-blob retention then final unlink,
original and derivative tombstones, immutable request/history fields, metadata/audit
preservation, and idempotent missing-blob recovery. Fault injection interrupts after
unlink and proves the durable processing record completes on startup without restoring
content. The full contract, migration, lint, type, and Python suites were reviewed.

**Findings:** The caller cannot select retention duration; it comes from the exact
manifest version linked by the artifact's policy bundle. A durable human-confirmed
request makes content unavailable before filesystem work starts. The service never
unlinks a digest still referenced by a non-tombstoned artifact. Interrupted deletion
is monotonic and recovery only advances it toward completion.

**Limitations and deferred work:** Unlink plus directory synchronization is not a
portable forensic erase guarantee on copy-on-write filesystems or SSDs. Existing
backup copies are not inventoried or purged. The current shared master-key format does
not support per-object cryptographic erasure. Legal holds, automated expiry scheduling,
restore-time tombstone reconciliation, and Evidence UI are not implemented.

**Residual risk accepted:** The contract explicitly reports
`forensic_erase_guaranteed: false`; this slice must be described as supervised content
deletion, not forensic secure erase. Older binaries do not enforce migration-0023
tombstones, so rollback requires a verified pre-migration backup. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-11 — Encrypted backup and isolated restore integrity

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Domain-separated backup encryption, online SQLite snapshots,
authenticated evidence inclusion, exact archive membership, migration/audit/database
verification, live deletion-tombstone precedence, shared-digest behavior, isolated
restore installation, bounded expansion, path ownership, API confirmation, rollback,
and recovery claims.

**Evidence examined:** Tests cover encrypted creation and verified restore, SQLite and
evidence identity, ciphertext tampering, wrong keys, existing destinations, missing
blobs, failed-drill cleanup, stale pre-deletion backups, post-deletion backups, and
shared content retained until its final active reference is deleted. Contract, lint,
type, and complete Python validation are required before publication.

**Findings:** API callers cannot choose filesystem paths. The service authenticates
referenced evidence before committing an atomic encrypted archive. Restore accepts an
exact manifest only, authenticates the envelope and blobs, verifies database integrity,
migrations and audit head, and installs solely into a new drill directory. Live data
is never replaced and target-facing work is never resumed.

**Limitations and deferred work:** This slice does not include source blobs, automatic
rotation, backup-copy inventory/purge, production replacement, or off-device custody.
If both the live database and its later tombstones are lost, an older archive cannot
prove deletions that happened after it was created. Full disaster-recovery and
disk-full drills remain required for the Phase 1 exit gate.

**Residual risk accepted:** The drill proves integrity for database and evidence
snapshots on the current device; it is not yet a complete disaster-recovery mechanism.
This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-11 — Complete source-provenance backup integrity

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** V2 archive/report versioning, source metadata-to-blob binding,
authenticated source reads, exact member inventory, isolated source-store restoration,
database/source reconciliation, v1 restore compatibility, API composition, failure
cleanup, compatibility, rollback, and privacy.

**Evidence examined:** Tests cover v2 source creation and isolated restoration, exact
restored plaintext digest and database provenance, missing-source denial before archive
commit, v1 database/evidence restore compatibility with truthful zero-source reporting,
and all prior tamper, wrong-key, tombstone, shared-digest, missing-evidence, and cleanup
proofs. Full contract, lint, type, and Python suites are required before publication.

**Findings:** New backups cannot silently omit a referenced source. Metadata must be
available, use the supported encryption version, and name the exact content digest;
the store must authenticate that digest before the encrypted outer archive is written.
Restore requires the v2 manifest, database inventory, archive paths, decrypted source
content, and digest to agree. V1 remains a deliberately narrower restore-only format.

**Limitations and deferred work:** Live replacement, automatic rotation, backup
inventory/purge, off-device custody, full-device-loss tombstone preservation, and
disk-full/power-loss drills remain open. V1 archives do not contain source blobs.

**Residual risk accepted:** Backup completeness now covers local database, evidence,
and intake sources, but complete-device-loss recovery and operational backup lifecycle
are not yet proven. This review is self-authored and non-independent and cannot satisfy
an external independent-review requirement.

## 2026-08-11 — Supervised backup inventory, rotation, and purge

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Authenticated bounded inventory, server-controlled paths,
filename/manifest identity, symlink and type rejection, live tombstone reporting,
deterministic retention planning, verified-copy protection, exact purge confirmation,
pre-unlink audit ordering, on-disk digest recheck, directory synchronization,
interrupted-purge replay, erasure claims, compatibility, and rollback.

**Evidence examined:** Tests authenticate multi-backup inventory, distinguish verified
archives, protect the newest configured set and newest verified copy, prove that
rotation performs no deletion, reject absent confirmation and digest mismatch, protect
the last verified archive, complete an authorized unlink, and recover a synthetic crash
after unlink as an idempotent `already_absent` result. All earlier backup tamper,
source/evidence integrity, v1 compatibility, and tombstone tests remain required.

**Findings:** Neither AI nor a caller can choose arbitrary paths or cause automatic
rotation. A purge is bound to a canonical ID, authenticated envelope digest, reason,
human confirmation, and durable audit request. The last verified recovery point is
preserved, and an exact retry can only advance an interrupted purge to completion.

**Limitations and deferred work:** Inventory covers only the configured local backup
directory. Off-device copies, automatic scheduling, storage quotas, production restore,
full-device-loss tombstones, and disk-full/power-loss drills remain open. Filesystem
unlink cannot prove SSD or copy-on-write forensic erasure.

**Residual risk accepted:** Local rotation is supervised and auditable but does not
control copies outside PentAI's local directory. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-11 — Storage failure stop and deterministic fault injection

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** SQLite storage-risk classification, process-local safety latching,
source/evidence/backup failure propagation, health/readiness degradation, execution
authority gates, atomic ciphertext publication, temporary cleanup, compatibility,
rollback, and the boundary of injected durability evidence.

**Evidence examined:** Tests inject SQLite disk-full failure inside an open transaction
and `fsync` disk-full failure into source, evidence, and backup writes. They verify
transaction rollback and integrity, preservation and authentication of earlier
committed content, absence of partial destinations and temporary files, backup recovery
point preservation, latch activation, and default denial before intent evaluation.
The complete Python, contract, lint, and type suites remain required before publication.

**Findings:** A classified storage failure is remembered without relying on the failed
database and blocks each boundary that could advance target-facing authority. The latch
cannot be reset through an API. Same-directory temporary publication prevents partial
ciphertext from replacing a committed object; a post-replacement synchronization
failure is treated as uncertain and keeps authority stopped.

**Limitations and deferred work:** Faults are deterministic software injections, not
physical power cuts. Filesystem, kernel, drive-cache, Windows, and Linux durability
behavior still requires hosted or hardware evidence. The latch is process-local; a
restart relies on migrations, audit verification, encrypted-object authentication, and
operator remediation rather than persisting a new stop record to potentially unsafe
storage.

**Residual risk accepted:** The slice proves logical fail-closed behavior and committed
state preservation under injected failures, not physical-media durability. This review
is self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-11 — Supervised findings lifecycle

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Finding v1 contract, migration 0024, exact workflow/policy/evidence
binding, policy allow-rule validation, deleted-evidence exclusion, deterministic CVSS
3.1 scoring and severity mapping, CWE/confidence bounds, duplicate identity, human-only
ordered transitions, optimistic fencing, immutable version history, audit coverage,
API authentication, compatibility, privacy, and rollback.

**Evidence examined:** Success tests create a synthetic finding and traverse scope,
duplicate, validation, report-readiness, and closure with six immutable versions and
matching audit events. Negative tests reject conflicting replay, CVSS mismatch,
severity mismatch, malformed CWE, unknown policy assets, missing evidence, skipped
review, stale versions, missing duplicate outcomes, and invalid duplicate identity.
Database tests deny forged current-row changes and deletion of current/history records.
The complete migration, contract, lint, type, and Python suites are required before
publication.

**Findings:** Callers cannot assert an arbitrary score, severity, asset, evidence link,
duplicate, or validation result. Exact policy and evidence provenance are checked in the
same transaction as creation. Every state change is human-authored, reasoned, fenced,
fully snapshotted, content hashed, and audit linked. Finding state has no authority over
the gateway or report export.

**Limitations and deferred work:** Program-specific severity, automated similarity
search, rich finding editing, retest evidence replacement, UI rendering, report drafts,
and human report approval/export remain separate slices. CVSS v4 is not supported by
this v1 contract. Local custody is not externally timestamped.

**Residual risk accepted:** CVSS 3.1 computation is locally implemented and requires
independent corpus comparison before release assurance. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

### Hosted containment follow-up — bounded Podman startup readiness

PR #100 exposed the recurring rootless Podman race where a freshly created internal
network was inspectable but the first isolated probe process failed to start. The
conformance verifier now permits exactly three process-start attempts separated by a
fixed 250 ms delay. It retries only OCI runtime exit 125 (container startup failure);
probe exit failures, malformed output, identity mismatch, and every unsafe containment
measurement still deny on the first observation. Persistent startup failure denies with
an explicit bounded-attempt reason. Unit tests prove eventual readiness, exact
exhaustion, and no retry of invalid or unsafe successful output. Hosted Linux remains
the required live evidence.
