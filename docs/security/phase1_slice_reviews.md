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

## 2026-08-13 — Reporting-terms review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Submission channel, required fields, evidence rules, disclosure
timeline, fixed human approval and automatic-submission denial, manifest mapping,
compatibility, rollback, and absence of export or submission effects.

**Evidence examined:** UI typecheck; 123 Vitest checks including complete mapping and
missing channel/field/evidence denial; production UI build; desktop Cargo check; complete
diff; manifest v2 reporting contract and existing supervised report workflow.

**Findings:** Reporting terms are explicit without creating submission authority. Human
approval remains true and automatic submission remains false regardless of reviewed text.
Malformed or incomplete review fails before draft construction.

**Limitations and residual risk:** Terms are reviewed prose, not proof of portal or
disclosure compliance. Account, testing-window, and source-statement review remain.
Synthetic terms remain visible locally. This self-authored review is non-independent and
cannot satisfy an external independent-review requirement.

## 2026-08-13 — Data-handling review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Real-user-data mode, record-view ceiling, retention, fixed encrypted
storage, remote-AI classification, redaction rules, stale authority clearing, manifest
mapping, compatibility, rollback, and absence of data access or transmission.

**Evidence examined:** UI typecheck; 120 Vitest checks including complete data-handling
mapping, missing-retention denial, missing-record-ceiling denial, stale-ceiling conflict,
unknown-classification denial, and legacy builder defaults; production UI build; desktop
Cargo check; complete diff; manifest v2 data-handling contract and evidence retention use.

**Findings:** Intake no longer relies exclusively on fixed hidden data-handling values.
Minimal real-user-data authority is bounded by an explicit record ceiling, while the
default remains avoid-and-stop, encrypted local storage, and no remote AI. Invalid or
contradictory review fails before draft construction.

**Limitations and deferred work:** Redaction rules are reviewed prose and do not perform
or prove redaction. General preview sandboxing and remaining deletion/backup assurances
are unchanged. Account, testing-window, reporting, and source-statement review remain.
Rollback affects draft presentation only.

**Residual risk accepted:** UI review cannot prove downstream minimization, redaction, or
model-context filtering; core evidence and future provider boundaries remain mandatory.
Synthetic handling terms remain visible inside the authenticated same-user desktop
boundary. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-13 — Operational-limit review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Global/per-host rates, burst and concurrency ceilings, runtime,
request totals, request/response byte bounds, stop conditions, internal consistency,
manifest mapping, compatibility, rollback, and absence of enforcement or execution.

**Evidence examined:** UI typecheck; 117 Vitest checks including complete limit mapping,
per-host-over-global denial, fractional-ceiling denial, blank/negative-body denial,
missing-stop denial, and legacy builder compatibility; production UI build; desktop Cargo check;
complete diff; manifest v2 operational-limit contract and core limit validation.

**Findings:** Intake no longer relies on fixed burst, concurrency, runtime, body, and stop
values. Every operational ceiling is explicitly reviewed, and inconsistent inputs fail
before draft construction. The core and gateway remain the only enforcement authorities.

**Limitations and deferred work:** Testing windows and blackout periods remain unmodeled
because their contract objects are not yet structurally defined. Live rate, budget, and
stop enforcement are unchanged. Account, data-handling, reporting, and source-statement
review remain. Rollback affects draft presentation only.

**Residual risk accepted:** UI numeric checks cannot establish runtime enforcement or
clock health; core policy validation, gateway reservations, accounting, and safety stops
remain mandatory. Synthetic limits remain visible inside the authenticated same-user
desktop boundary. This review is self-authored and non-independent and cannot satisfy an
external independent-review requirement.

## 2026-08-13 — Structured technique review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Allowed, denied, and conditional capability classification; explicit
HTTP methods; conditional approval type and conditions; overlap and completeness denial;
manifest mapping; compatibility; rollback; and absence of execution.

**Evidence examined:** UI typecheck; 114 Vitest checks including full technique mapping,
empty-allow denial, overlap denial, incomplete-conditional denial, missing-method denial,
and legacy builder compatibility; production UI build; desktop Cargo check; complete
diff; manifest v2 technique contract and core contradiction/method validation.

**Findings:** Technique authority is no longer represented only by an allow list and a
fixed GET method. Each capability has one reviewed classification, conditional rules keep
their approval requirement, and directly allowed built-in HTTP capabilities require their
matching method. The core remains authoritative for supported capabilities and policy.

**Limitations and deferred work:** Intake offers one conditional capability and the three
HTTP capabilities currently supported by the core. General conditional-rule editing,
forbidden-technique prose, account, timing, stop-condition, data-handling, and reporting
review plus source-statement extraction remain. Rollback affects draft presentation only.

**Residual risk accepted:** UI syntax and method checks are defense in depth and cannot
replace the core's supported-capability set or semantic validation. Synthetic technique
terms remain visible inside the authenticated same-user desktop boundary. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

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

## 2026-08-13 — Supervised source provenance review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Optional effective timestamp normalization, bounded source-version
provenance, all three import modes, exact immutable-history selection, malformed and
duplicate history denial, downstream manifest/policy invalidation, compatibility,
rollback, privacy, and absence of automatic acquisition or authority inference.

**Evidence examined:** UI typecheck; 90 Vitest checks including provenance preservation,
ambiguous history denial, and malformed digest denial; production UI build; desktop Cargo
check; complete diff; source request models; immutable source listing implementation; and
the source-intake security boundary.

**Findings:** The UI no longer silently treats only the most recently imported source as
the sole reviewable history item. An operator selects one exact core-returned source, and
any selection change invalidates derived manifest and policy presentation before a new
draft is constructed. The core remains authoritative for provenance validation,
immutability, encryption, and persistence.

**Limitations and deferred work:** This remains a single-source manifest draft. It does
not resolve conflicts across multiple sources, merge authority, render imported active
content, or infer rules from text. Historical source review after a full restart still
requires durable engagement selection. Rollback affects presentation only.

**Residual risk accepted:** Source references, timestamps, version labels, and hashes are
visible inside the authenticated same-user desktop boundary. Local datetime conversion is
made explicit as an ISO timestamp and may be rejected safely by the core. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-13 — Durable engagement history recovery

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Program-owned engagement collection, unknown-program denial, exact
identity and validity-window selection, status allowlist, duplicate and cross-program
denial, program-change isolation, downstream manifest/policy invalidation, authenticated
route integration, compatibility, rollback, privacy, and absence of mutation authority.

**Evidence examined:** Focused authorization pytest suite; UI typecheck; 91 Vitest checks
including cross-program and invalid-window denial; production UI build; desktop Cargo
check; full Python tests; contract validation; Ruff; mypy; complete diff; engagement table
constraints; and existing intake/recovery security boundaries.

**Findings:** A restarted UI can recover a program's durable engagement identity instead
of manufacturing a replacement window. Unknown programs fail closed in the core, while
the UI accepts only one exact returned UUID with a valid ordered window for the selected
program. Selection changes clear all derived manifest and policy presentation.

**Limitations and deferred work:** Engagement selection does not automatically select a
source, manifest version, or active policy. Full workflow recovery still requires those
explicit steps, and multi-source conflict resolution remains deferred. The endpoint is
read-only and rollback removes discovery without changing durable engagements.

**Residual risk accepted:** Engagement identifiers, status, validity, active-policy ID,
and revocation epoch are visible inside the authenticated same-user desktop boundary.
They are coordination metadata and confer no grant or execution authority. This review
is self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-13 — Canonical manifest history recovery

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact engagement-bound manifest and policy-history loading, stale
response rejection, canonical manifest UUID/schema/version/digest/document validation,
embedded engagement binding, validation-status consistency, duplicate denial, explicit
selection, downstream policy invalidation, compatibility, rollback, and absence of
policy-authority inference.

**Evidence examined:** UI typecheck; 92 Vitest checks including cross-engagement,
duplicate-record, and inconsistent-validation denial; production UI build; desktop Cargo
check; complete diff; canonical manifest record implementation; manifest v2 contract;
and policy-history summary behavior.

**Findings:** Restart recovery can now continue from an exact canonical manifest rather
than rebuilding it from mutable session state. Late history responses cannot cross an
engagement selection boundary. Selecting a historical manifest clears displayed policy
state and conservatively returns a valid version to awaiting approval rather than
claiming any historical approval or activation.

**Limitations and deferred work:** Signed policy history lacks the policy document and
signature needed for exact restoration, so summaries remain non-selectable. Manifest
diff restoration is not automatic, and multi-source conflict resolution remains open.
Rollback removes history selection without changing immutable manifest records.

**Residual risk accepted:** Canonical manifest content and policy summary metadata are
visible inside the authenticated same-user desktop boundary. A restored valid manifest
can be explicitly recompiled, but no approval or activation is inferred. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-13 — Exact signed-policy recovery

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Engagement-scoped exact-policy reads, current-signer availability,
stored content/manifest hash recomputation, row/document signature consistency, Ed25519
verification, lifecycle status recovery, active-policy identity binding, summary/response
agreement, matching manifest restoration, compatibility, rollback, privacy, and absence
of new approval or activation authority.

**Evidence examined:** Focused authorization pytest suite; UI typecheck; 93 Vitest checks
including wrong-engagement, wrong-active-identity, and digest mismatch denial; full Python
tests; contract validation; Ruff; mypy; production UI build; desktop Cargo check; complete
diff; Policy IR v1 contract; compilation, activation, and signature verification paths.

**Findings:** Policy content is no longer reconstructed or trusted from summary metadata.
The core returns it only after revalidating its stored manifest/content bindings and
signature with the current local signer. The UI binds that response back to the exact
selected summary and engagement. Recovery displays the persisted lifecycle state and
does not record a human decision, activate a policy, or mint a grant.

**Limitations and deferred work:** A rotated or unavailable local signing key denies old
policy recovery; no key migration is inferred. An approved-but-not-active policy is shown
as awaiting approval in the UI and must receive a fresh explicit decision before
activation. Rollback removes the read endpoint and selector without changing policies.

**Residual risk accepted:** Exact signed policy rules and signer identifiers are visible
inside the authenticated same-user desktop boundary. Signature verification depends on
the local development key custody already accepted under the non-independent exception.
This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-13 — Historical manifest comparison recovery

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Explicit baseline/target selection, distinct immutable identities,
engagement-scoped diff route, stale response rejection, exact version/digest binding,
authorization-bearing section allowlist, changed-summary/detail agreement, duplicate and
reversed-selection denial, compatibility, rollback, privacy, and absence of mutation or
policy authority.

**Evidence examined:** UI typecheck; 94 Vitest checks including reversed identity and
unknown-section denial; production UI build; desktop Cargo check; complete diff; existing
manifest diff service; canonical manifest history validation; and manifest v2 contract.

**Findings:** Semantic comparisons are recoverable after restart without reconstructing
them in the browser. The UI accepts only a response bound to two exact loaded immutable
records and rejects unknown or internally inconsistent change categories. A late response
cannot cross the selected engagement boundary.

**Limitations and deferred work:** Comparisons cover the eight authorization-bearing
sections implemented by the existing core service and do not provide arbitrary JSON
diffs. The selection is not persisted across restart. Multi-source conflict resolution
and comparison of unsigned drafts remain deferred. Rollback affects presentation only.

**Residual risk accepted:** Before/after authorization terms are visible inside the
authenticated same-user desktop boundary. Comparison display grants no approval,
activation, or execution authority. This review is self-authored and non-independent and
cannot satisfy an external independent-review requirement.

## 2026-08-13 — Policy-derived coverage selection

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact workflow snapshot binding, active policy bundle matching,
non-executing workflow assertion, allow-only asset filtering, non-deny capability
filtering, asset applicability, malformed and duplicate rule denial, workflow-change
invalidation, compatibility, rollback, and absence of inferred coverage or execution.

**Evidence examined:** UI typecheck; 86 Vitest checks including exact policy selection,
wrong-policy denial, inactive-policy denial, and authority-bearing workflow denial;
production UI build; desktop Cargo check; complete diff; Policy IR schema; core coverage
policy-link validation.

**Findings:** Manual authority-bearing rule identifiers are no longer accepted by the
coverage form. Recording remains disabled until the exact workflow is bound to the active
policy, and capability comes from the selected authoritative rule. The core remains the
final enforcement boundary and revalidates every policy link.

**Limitations and deferred work:** The selector uses the active policy currently held by
the workbench; reopening a historical workflow still requires restoring its exact policy
to the workbench. There is no bulk matrix editor, automatic inference, submission, or
network execution. Rollback affects presentation only.

**Residual risk accepted:** Policy matchers and synthetic identifiers are visible inside
the authenticated same-user desktop boundary. JSON matcher labels favor exactness over
friendly formatting. This review is self-authored and non-independent and cannot satisfy
an external independent-review requirement.

## 2026-08-13 — Phase 1 workspace navigation

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact required workspace inventory, unique identifiers, native-button
navigation, current-page semantics, keyboard focus visibility, inactive accessibility,
mounted state preservation, global safety visibility, compatibility, rollback, and
absence of authority-bearing navigation side effects.

**Evidence examined:** UI typecheck; 88 Vitest checks including exact unique Phase 1
workspace inventory; production UI build; desktop Cargo check; complete diff; existing
workspace security reviews and global safety-control placement.

**Findings:** Each required Phase 1 area is now an explicit destination. Navigation only
changes local presentation state, and hidden workspaces cannot be reached through the
accessibility tree. The global safety control and core failure state remain outside the
workspace switcher and visible regardless of destination.

**Limitations and deferred work:** Navigation does not persist across application restart,
encode destinations in URLs, or create separate desktop windows. Supporting controls for
network setup, policy, and authorization remain intentionally grouped under Assessments.
Rollback affects presentation only.

**Residual risk accepted:** Inactive workspace component state remains in same-process
memory until its existing identity key changes or the application closes. That state is
already inside the authenticated same-user desktop boundary and does not grant authority.
This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

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

## 2026-08-13 — Structured scope-boundary review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Third-party-service and shared-hosting/CDN decisions, bounded scope
expansion procedure, conservative defaults, manifest mapping, invalid and missing input,
compatibility, rollback, and absence of discovery or execution.

**Evidence examined:** UI typecheck; 111 Vitest checks including explicit boundary
review, unknown-value denial, missing-process denial, length-bound denial, exact manifest
mapping, and prior multi-row scope tests; production UI build; desktop Cargo check;
complete diff; manifest v2 scope contract and intake completeness requirements.

**Findings:** External infrastructure handling is no longer an implicit fixed builder
value. Both decisions begin at deny, and `allow_if_explicit` cannot create authority
without a separately reviewed exact asset. Incomplete boundary review fails before draft
construction. The core remains authoritative for validation and activation.

**Limitations and deferred work:** The expansion procedure is bounded human-authored text
and is not parsed into authority. Structured technique, account, timing, stop-condition,
data-handling, and reporting review plus source-statement extraction remain. Rollback
affects draft presentation only.

**Residual risk accepted:** The UI cannot prove that free-text expansion instructions are
operationally sufficient; explicit assets and core validation remain mandatory. Synthetic
review text remains visible inside the authenticated same-user desktop boundary. This
review is self-authored and non-independent and cannot satisfy an external independent-
review requirement.

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

## 2026-08-14 — Gateway schedule revalidation

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Immutable Policy IR reload, canonical stored-document comparison,
schedule evaluation at exact request-start time, transaction ordering, denial before
grant/budget mutation, legacy compatibility, rollback, and absence of execution.

**Evidence examined:** Focused request-start denial test proving the schedule check is
called with the commit instant and leaves the grant unused and reservation reserved;
authorization tests; complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop
Cargo check; complete diff; schedule evaluator and atomic request-start contracts.

**Findings:** Schedule authority is no longer checked only when the intent is evaluated.
It is revalidated inside the final atomic commitment, closing the prepared-session race
without consuming one-use authority on denial.

**Limitations and deferred work:** The product still has no general target-facing worker.
Continuous clock-health proof and termination of already-running work at a schedule
boundary remain open.

**Residual risk accepted:** The check trusts the same host wall clock as other expiry and
deadline controls; clock uncertainty must independently pause execution. This review is
self-authored and non-independent and cannot satisfy external independent assurance.

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

## 2026-08-12 — Immutable supervised report drafts

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Report draft v1 contract, additive migration 0025, human request
binding, exact workflow/policy and finding-version snapshots, deterministic Markdown,
escaped inactive HTML, canonical JSON, minimal text-only PDF, output bounds and
digests, restricted classification, immutable storage, audit linkage, authenticated
API surface, compatibility, privacy, rollback, and the absence of submission authority.

**Evidence examined:** Contract validation; exact `report_ready` finding version/hash
capture; four artifact formats and digest/size verification; HTML injection escaping;
PDF framing; conflicting idempotency, duplicate IDs, missing/closed findings, and
unknown formats denying the entire request; database mutation denial; authenticated
route coverage; explicit absence of submission routes; 189 unittest tests, 384 pytest
tests plus 235 subtests, Ruff, mypy, 38 contract files, 15 UI tests, UI typecheck/build,
and desktop Cargo check.

**Findings:** Callers supply only a bounded template choice, title, and finding IDs;
they cannot supply rendered bodies or assert arbitrary finding versions. Generation
reloads current findings in one immediate transaction and accepts only exact
`report_ready` rows from the same workflow. Every artifact is immutable and digested,
HTML is fully escaped and served with deny-all sandbox headers, and all metadata remains
explicitly `draft` and `restricted`. No network or platform-submission capability exists.

**Limitations and deferred work:** Draft retrieval is not human approval or an
export-ready transition. Rich layout, images, redaction-aware display choices,
coverage-aware “No Findings” reports, signed export manifests, explicit approval,
and external submission remain separate slices. The minimal PDF is text-only.

**Residual risk accepted:** PDF rendering uses a deliberately narrow repository-owned
writer rather than an independently assessed rendering engine. Report content may be
sensitive and depends on local access controls. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Immutable supervised assessment coverage

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Assessment coverage v1 contract, additive migration 0026, human
actor binding, exact workflow/policy and allowed asset/capability-rule linkage, ordered
testing intervals, same-workflow available evidence, explicit gap outcomes and
limitations, idempotency, immutable storage, audit linkage, authenticated API surface,
compatibility, privacy, rollback, and absence of completeness or export authority.

**Evidence examined:** Successful evidence-backed coverage recording and retrieval;
contract validation; database mutation denial; audit content; idempotent replay and
conflicting replay; denial of missing evidence for tested claims, unknown assets,
mismatched capabilities, malformed policy collections, invalid intervals, deleted or
foreign evidence paths, and unsupported outcomes; explicit `blocked` outcome behavior;
189 unittest tests, 392 pytest tests plus 235 subtests, Ruff, mypy, and 39 contract files.

**Findings:** A caller cannot assert coverage outside the immutable workflow policy.
The service accepts only allowed asset rules and non-denied capability rules applicable
to that asset. Tested outcomes require available evidence from the same workflow and
policy. Every record is immutable, content-digested, audit-linked, and sets
`coverage_complete` to false. Gap outcomes remain distinguishable from tested claims.

**Limitations and deferred work:** This slice records observations; it does not derive
the expected policy coverage matrix, calculate sufficiency, generate a “No Findings”
report, approve/export a report, or submit externally. Notes and limitations can
contain sensitive assessment context and remain protected by the local authenticated
boundary. The additive migration can be rolled back only by reverting application code
while leaving its unused immutable table in place; no data transformation is required.

**Residual risk accepted:** Coverage truth still depends on human assertions and linked
evidence quality. A later sufficiency slice must default-deny missing matrix cells,
gaps, stale policy bindings, and ambiguous outcomes. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Coverage-aware No Findings report drafts

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** No Findings report draft v1 contract, additive migration 0027,
completed-workflow requirement, immutable policy matrix derivation, explicit coverage
selection, latest-record fencing, evidence availability, finding absence, deterministic
Markdown/HTML/JSON/PDF rendering, output bounds and digests, immutable storage, audit
linkage, authenticated API surface, compatibility, privacy, rollback, and absence of
approval, export-ready, or submission authority.

**Evidence examined:** Successful complete-matrix generation, contract validation,
four artifact formats and digest verification, immutable metadata, audit content,
idempotent replay, and denial of incomplete workflows, missing coverage, blocked
coverage, unresolved findings, deleted evidence, and incomplete policy matrices; 189
unittest tests, 399 pytest tests plus 235 subtests, Ruff, mypy, and 40 contract files.

**Findings:** Generation recomputes the full allowed policy asset/capability matrix in
one immediate transaction and requires the explicitly selected records to equal it.
Each selected record must be the unique latest record for its pair, retain its content
hash, have outcome `tested_no_findings`, and reference available same-workflow,
same-policy evidence. Any non-rejected finding denies. The report states only that no
findings were identified within documented coverage and preserves every limitation.

**Limitations and deferred work:** The result remains a restricted immutable draft and
does not prove exhaustive security, assess methodology quality, approve export, or
submit externally. The minimal PDF is text-only. The additive migration can be rolled
back by reverting application code and leaving its unused immutable tables in place;
no existing data is transformed.

**Residual risk accepted:** Coverage assertions and linked evidence remain
human-authored, and policy matrix completeness reflects the policy's declared rules
rather than an independent methodology catalog. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Explicit report export approval

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Report export approval v1 contract, additive migration 0028,
authenticated-human identity, explicit confirmation, exact findings and No Findings
draft selection, expected-status fencing, report metadata hash verification, all four
artifact byte/digest checks, immutable one-decision persistence, audit linkage,
authenticated API surface, compatibility, privacy, rollback, and absence of file
export or submission capability.

**Evidence examined:** Successful approval for both report kinds; exact report and
artifact digest binding; contract validation; approval retrieval; immutable database
record; audit content; denial of missing confirmation, wrong expected status, unknown
report kind, empty reason, duplicate decision, and changed artifact bytes; 189 unittest
tests, 407 pytest tests plus 235 subtests, Ruff, mypy, and 41 contract files.

**Findings:** Only the authenticated server-side human principal can approve. The
service accepts exactly `draft` as the expected state, requires explicit boolean
confirmation, recomputes the immutable report document hash and all four artifact
digests in one immediate transaction, then stores one non-replayable approval per
report. Export-ready status is derived only from that exact binding and always records
`submission_enabled: false`.

**Limitations and deferred work:** This slice records authorization to export; it does
not write a file, choose a destination, create a signed export manifest, expose a
platform transport, or submit a report. Local session possession remains the human
identity boundary. Migration rollback leaves the unused immutable approval table in
place and requires no transformation of existing report data.

**Residual risk accepted:** A sole local user performs both report review and approval,
so this does not provide dual control. Artifact confidentiality still depends on the
local authenticated boundary and any future export implementation must preserve safe
destination and filesystem semantics. This review is self-authored and non-independent
and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Supervised Reports workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Reports presentation component, exact UUID selection parsing,
findings/No Findings endpoint routing, authenticated request reuse, immutable artifact
metadata display, explicit export-ready reason and confirmation, error handling,
responsive layout, absence of artifact embedding and unauthenticated links, and absence
of download, destination, upload, retry, or submission controls.

**Evidence examined:** UI typecheck; 20 Vitest tests including empty, malformed,
duplicate, and valid selection cases and endpoint non-submission checks; production UI
build; complete diff; API-boundary review; security invariant and workspace guidance.

**Findings:** The UI supplies no authority beyond the existing authenticated core
contracts. It generates a fresh idempotency key, passes exact operator-entered IDs,
shows only classification, policy identity, sizes, and shortened digests, and requires
a non-empty review reason plus explicit checkbox before calling approval. Core
default-deny validation remains authoritative. Artifact bytes are not exposed through
an unauthenticated browser link.

**Limitations and deferred work:** Operators currently enter workflow and record UUIDs
manually; searchable workflow, finding, and coverage lists remain future workspace
slices. The UI does not render artifact contents or write files. Broader Dashboard,
Programs, Assessments, Evidence, Findings, Reports history, and Logs navigation remains
incomplete.

**Residual risk accepted:** Manual UUID entry is usable for a vertical slice but can
produce safe denials and operator friction. The local session remains the human
identity boundary. This review is self-authored and non-independent and cannot satisfy
an external independent-review requirement.

## 2026-08-12 — Supervised local report file export

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Report file export v1 contract, additive migration 0029, exact
approval and artifact binding, authenticated-human confirmation, existing-directory
selection, server-derived filenames, exclusive same-directory publication, overwrite
denial, output synchronization, immutable receipts, audit linkage, API authentication,
compatibility, privacy, rollback, and absence of submission authority.

**Evidence examined:** Successful exact Markdown export and digest binding; contract
validation; immutable receipt and audit metadata; idempotent exact retry; denial without
approval or confirmation, for missing directories, existing destinations, changed
exported bytes, and changed approved artifacts; cleanup after publication/audit failure;
the complete migration, contract, lint, type, and Python suites required before
publication.

**Findings:** A caller cannot choose the output filename or export an unapproved or
changed artifact. The service recomputes the approval document hash and selected
artifact digest in one immediate transaction, refuses existing targets, publishes from
an exclusively created temporary file, and records no destination path or report body
in audit data. The capability has no network transport or submission endpoint.

**Limitations and deferred work:** Directory selection relies on the authenticated
local-user boundary and does not defend against a malicious same-user process racing
the selected directory. A crash after filesystem publication but before database
commit can leave an unrecorded file that a retry safely refuses to overwrite. UI file
selection, export history, detached signed manifests, and external submission remain
separate capabilities. Rollback leaves the unused immutable receipt table in place.

**Residual risk accepted:** Export deliberately creates a restricted plaintext file,
so confidentiality thereafter depends on the operator-selected local destination and
OS controls. The receipt proves the approved bytes written by PentAI, not continuing
custody after export. This review is self-authored and non-independent and cannot
satisfy an external independent-review requirement.

## 2026-08-12 — Reports workspace local export control

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Desktop directory-dialog dependency and least-privilege capability,
post-approval export presentation, exact report-kind/format/directory request binding,
restricted-plaintext confirmation, immutable receipt display, state reset behavior,
error handling, responsive layout, compatibility, privacy, rollback, and absence of
upload or submission controls.

**Evidence examined:** UI typecheck; 22 Vitest tests including exact endpoint/body
construction and explicit absence of submit/upload paths; production UI build; desktop
Cargo check with the official Tauri dialog plugin; complete manifest and lockfile diff;
API-boundary, capability, and security-invariant review.

**Findings:** The export control appears only after the core returns exact export-ready
approval. The operator chooses one bounded format through a native directory picker and
must separately acknowledge restricted plaintext custody. The UI cannot provide a
filename, does not read or render artifact bytes, and displays only the core-issued
filename, size, and shortened digest. The desktop grants only core defaults and dialog
open permission; no filesystem-read, network-upload, or shell capability is added.

**Limitations and deferred work:** The dialog permission can select a file as well as a
directory at the plugin boundary, although this UI invokes directory-only mode and the
core independently requires an existing directory. Export history, destination
bookmarks, signed manifests, richer report preview, searchable report inputs, and
external submission remain separate slices. Rollback removes the dialog plugin and UI
controls without changing persisted report or export records.

**Residual risk accepted:** The selected directory path is visible in the local UI and
passed to the authenticated loopback core; it is not persisted in the receipt or audit
ledger. Exported plaintext remains under operator and OS custody. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-12 — Supervised Findings workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Finding candidate presentation, exact workflow/asset/evidence UUID
parsing, CVSS/CWE/confidence input, bounded narrative and reference fields, authenticated
API reuse, workflow-scoped listing, contract-defined transition choices, expected-version
fencing, explicit duplicate and validation outcomes, duplicate identity handling, error
display, responsive layout, compatibility, privacy, rollback, and absence of execution,
report-approval, or submission authority.

**Evidence examined:** UI typecheck; Vitest coverage for exact UUID preservation,
malformed/empty/duplicate denial, allowed next-state derivation, version-bound transition
requests, and conditional duplicate identity; production UI build; complete diff;
finding contract, service boundary, and security-invariant review.

**Findings:** The UI invents no policy, evidence, score, severity, duplicate, validation,
or lifecycle fact. Candidate creation passes exact operator inputs to the authenticated
core, which remains authoritative for all semantic checks. Transitions are limited to
contract edges and bind the displayed version plus explicit human reason and review
outcomes. Changing workflow identity clears prior displayed findings.

**Limitations and deferred work:** Operators still enter policy asset and evidence UUIDs
manually. The UI does not calculate CVSS, retrieve finding history, edit immutable
candidate content, propose duplicates, preview evidence, or search policies/evidence.
Those remain separate slices. Rollback removes only presentation code and leaves all
immutable finding records unchanged.

**Residual risk accepted:** Manual identifiers and CVSS inputs can create safe core
denials and operator friction. Sensitive finding narratives are displayed locally and
remain protected by the authenticated desktop boundary. This review is self-authored
and non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Supervised Evidence workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Bounded note/file capture, browser byte encoding without path
disclosure, exact workflow and optional execution-trace binding, evidence kind/media
type/classification input, metadata lookup, Unicode-codepoint redaction parsing,
classification confirmation, derivative-only preview, inactive text rendering, API
authentication, error handling, responsive layout, compatibility, privacy, rollback,
and absence of original preview, deletion, execution, or submission authority.

**Evidence examined:** UI typecheck; Vitest coverage for exact custody endpoint routing,
absence of execution/grant/submission paths, ordered redaction parsing, and malformed
range/reason denial; production UI build; complete diff; evidence original, redaction,
preview, retention, and security-invariant review.

**Findings:** The UI sends selected bytes but never a filesystem path and enforces the
same 2 MiB client bound before the authoritative core check. It never requests original
content. Redaction requests contain only ranges, reasons, classification, and explicit
confirmation; derivative bytes remain server-generated. Preview rendering proceeds only
after exact inactive plain-text assertions and uses React text rendering, not HTML.

**Limitations and deferred work:** Operators manually enter workflow, trace, evidence,
and redaction offsets. The workspace does not list evidence by workflow, visualize text
offsets, preview files/images/originals, manage annotations, initiate retention deletion,
or route data to models. Those remain separate slices. Rollback removes presentation
code without changing immutable evidence, derivative, custody, or audit records.

**Residual risk accepted:** Selected evidence bytes briefly exist in webview memory for
base64 transport, and derivative text displayed locally may remain sensitive despite
redaction. The authenticated local session and OS boundary remain trusted. This review
is self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-12 — Evidence retention deletion control

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact original/redaction identity and full-digest presentation,
bounded human reason, explicit permanent-deletion confirmation, authenticated API reuse,
policy retention enforcement, shared-blob handling, durable tombstones and audit history,
crash recovery, result wording, privacy, rollback, and absence of deadline override,
automatic scheduling, execution, or submission authority.

**Evidence examined:** UI typecheck; Vitest coverage for custody endpoint routing, exact
request identity/digest/reason binding, and denial of manufactured confirmation;
production UI build; complete diff; evidence deletion contract, service implementation,
retention tests, and security-invariant review.

**Findings:** The UI can request deletion only for an artifact whose immutable identity
and full digest came from the authenticated core response. It supplies no deadline or
storage instruction. The core remains authoritative for retention, digest equality,
shared references, durable state transitions, and audit events. The control and result
both state that deletion is not forensic secure erase.

**Limitations and deferred work:** The UI does not list deletion history, schedule future
deletion, retry requests, implement legal holds, manage per-object encryption keys, purge
off-device copies, or claim physical-media erasure. Rollback removes only presentation
code; existing deletion records, tombstones, metadata, and audit events remain immutable.

**Residual risk accepted:** Encrypted content unlinking cannot guarantee recovery-resistant
physical erasure, and custody metadata intentionally remains. A malicious principal inside
the authenticated same-user desktop boundary remains outside this UI control's threat
model. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-12 — Supervised Logs workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Authenticated audit endpoint reuse, complete-chain verification
status, read-only ordered history, bounded local filtering, exact identity/hash detail,
invalid-chain warning, sensitive event-data exclusion, responsive layout, compatibility,
privacy, rollback, and absence of mutation, deletion, replay, export, or execution.

**Evidence examined:** UI typecheck; Vitest coverage for read-only routing, identity-field
filtering, stable empty-filter ordering, and exclusion of arbitrary event data; production
UI build; complete diff; audit event contract, chain verification implementation, and
security-invariant review.

**Findings:** The workspace obtains all events and verification state from the existing
authenticated core and invents no integrity result. Filters do not leave the webview and
cannot search or display the unconstrained event data object. An invalid chain is an
explicit alert that directs the operator not to trust the displayed history.

**Limitations and deferred work:** The endpoint returns the complete ledger without
pagination, so very large local histories will require a separate bounded-query contract.
The UI does not provide date ranges, structured data inspection, export, correlation, or
alerting. Rollback affects presentation only and leaves the append-only ledger unchanged.

**Residual risk accepted:** Actor and subject identifiers can themselves be sensitive and
are displayed within the authenticated same-user desktop boundary. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-12 — Operational Dashboard workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Read-only aggregation of authenticated connectivity, global safety,
local policy lifecycle, active network-profile cardinality, and audit verification;
default-away-from-ready behavior; automatic authenticated audit refresh; responsive
layout; compatibility, privacy, rollback, and absence of mutation or authority.

**Evidence examined:** UI typecheck; Vitest coverage for exact ready presentation,
missing/incomplete state, ambiguous active profiles, and invalid audit verification;
production UI build; complete diff; existing safety, network-profile, audit contracts,
and authorization-boundary review.

**Findings:** The dashboard invents no policy, safety, network, connectivity, or audit
fact. Missing and ambiguous state is attention or blocked, never ready. Multiple active
profiles fail presentation closed, and audit readiness requires a complete verified
response. The cards do not feed action requests or bypass core revalidation.

**Limitations and deferred work:** Policy lifecycle is the current workspace's local
presentation state rather than an independently refreshed durable policy inventory.
The dashboard has no program/workflow rollups, navigation, history, notifications, or
operator actions. Those remain separate slices. Rollback removes presentation only.

**Residual risk accepted:** A stale displayed state can briefly lag a core transition;
this cannot authorize an operation because action boundaries revalidate authoritative
state. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-12 — Supervised Programs workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Authenticated program list/create reuse, trimmed bounded name input,
explicit immutable-ID selection, downstream state clearing, source-history refresh,
error behavior, responsive layout, compatibility, privacy, rollback, and absence of
program edit/delete/activation or execution authority.

**Evidence examined:** UI typecheck; Vitest coverage for collection routing, normalized
creation input, and empty-name preservation for default-deny handling; production UI
build; complete diff; existing program service validation, persistence, and audit path.

**Findings:** The workspace never infers selection from list ordering or program status.
Selecting any program clears all source-derived and authorization presentation state
before its source history is requested. Program identity, status, and version remain
core-generated; creation cannot activate a program or authorize work.

**Limitations and deferred work:** Program URL and platform selection, status lifecycle,
editing, archival, deletion, search, pagination, and engagement inventory are absent.
Source intake remains a separate adjacent UI flow. Rollback affects presentation only.

**Residual risk accepted:** Program names and identifiers are displayed within the
authenticated same-user desktop boundary. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Dedicated Intake workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Extraction of explicit paste/file/URL modes, selected-program
prerequisite, authority preservation, dual 2 MiB file checks, allowlisted basename media
typing, path non-disclosure, browser-only byte encoding, guarded URL handoff, immutable
history and digest presentation, errors, compatibility, privacy, and rollback.

**Evidence examined:** UI typecheck; Vitest coverage for byte encoding, media allowlist,
pasted and URL request preparation, and missing-file denial; existing App regression
tests; production UI build; complete diff; source-intake endpoints and prior review.

**Findings:** No import starts automatically or retries in the background. File handling
cannot obtain or send a filesystem path. URL resolution remains wholly core-controlled.
The application adds the currently selected immutable program ID only at the authenticated
request boundary; the extracted workspace cannot invent program linkage.

**Limitations and deferred work:** The UI does not compare sources, preview active
content, parse terms, resolve conflicts visually, or edit immutable history. Engagement
creation and manifest drafting remain adjacent application orchestration pending their
own workspace slices. Rollback restores the inline presentation without data changes.

**Residual risk accepted:** Selected bytes and pasted terms briefly exist in webview
memory, and URLs can contain sensitive path/query values. The authenticated same-user
desktop boundary remains trusted. This review is self-authored and non-independent and
cannot satisfy an external independent-review requirement.

## 2026-08-12 — Supervised Assessments workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact engagement-bound idempotent workflow creation, UUID lookup,
active displayed-policy comparison, execution-disabled assertion, contract-defined
lifecycle edges, expected-version fencing, human start/resume labels, error behavior,
responsive layout, compatibility, rollback, and absence of task or execution authority.

**Evidence examined:** UI typecheck; Vitest coverage for coordination-only routing,
creation identity/idempotency binding, complete lifecycle edges, version fencing, and
invalid transition denial; production UI build; complete diff; workflow contract,
service transition implementation, recovery behavior, and authorization boundary.

**Findings:** The workspace cannot manufacture a transition edge or omit the displayed
version. A mismatched active policy or any response claiming execution enabled disables
all transitions. Creation keeps its key after errors and rotates it only after a confirmed
response. Core authority revalidation remains mandatory and workflows grant no authority.

**Limitations and deferred work:** There is no workflow collection endpoint, task list,
task creation, lease/progress display, recovery history, program-level rollup, or evidence
navigation. Those remain separate slices. Rollback leaves durable workflow records intact.

**Residual risk accepted:** Exact workflow and policy identifiers are visible inside the
authenticated same-user desktop boundary. A stale presentation may cause a safe fenced
denial. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-12 — Supervised assessment task queue

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Four allowlisted task kinds, ready/running workflow restriction,
retry-stable idempotency, exact unique UUID input references, optional parent identity,
workflow response binding, explicit no-dispatch/no-effect assertions, session-only list,
queued cancellation, API method behavior, compatibility, rollback, and absent lease or
worker controls.

**Evidence examined:** UI typecheck; Vitest coverage for enqueue/cancel-only routing,
absence of claim/lease/dispatch/execution paths, UUID parsing and duplicate denial, and
exact request binding; production UI build; complete diff; workflow task contract,
enqueue/cancel implementation, lifecycle extension, and authorization boundary.

**Findings:** Task creation is available only for a displayed ready/running workflow with
matching engagement/policy authority and `execution_enabled: false`. Responses enter the
UI list only when bound to that workflow and both authority flags are false. Cancellation
uses an explicit POST body. No lease token or worker operation is exposed.

**Limitations and deferred work:** Without a task-list endpoint, restart or workflow load
cannot reconstruct task history; the UI says so explicitly. Parent availability and task
completion remain core-authoritative. Claim, heartbeat, checkpoint, retry, dead-letter,
dispatch, worker, and gateway UI remain absent. Rollback leaves durable tasks unchanged.

**Residual risk accepted:** Input/task UUIDs are displayed within the authenticated
same-user desktop boundary. A lost success response may require idempotent retry before
the task appears locally. This review is self-authored and non-independent and cannot
satisfy an external independent-review requirement.

## 2026-08-12 — Supervised Policy lifecycle workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Manifest editing/validation, immutable history and semantic diff,
signed compilation, full digest presentation, separate typed approval and activation,
future expiry, bounded mandatory reasons, rejection, reasoned revocation, exact response
binding, stale local approval clearing, compatibility, rollback, and absent execution.

**Evidence examined:** UI typecheck; Vitest coverage for exact approval shape, malformed,
past, or missing expiry denial, bounded reason denial, and normalized revocation; existing
App regression tests; production UI build; complete diff; approval contract, compilation,
activation, revocation, signing, and audit implementation review.

**Findings:** Approval no longer implies activation. The UI requires a confirmed response
matching the displayed policy ID, digest, and decision before enabling activation, and
validates activation/revocation identity and status. Editing any approval-bearing input
or changing engagement/policy clears the local gate. Core checks remain authoritative.

**Limitations and deferred work:** The datetime control uses the host locale before ISO
conversion, and policy history remains engagement-scoped rather than globally searchable.
There is no dual-human approval, external identity provider, production signing custody,
or target execution. Rollback affects presentation only.

**Residual risk accepted:** Policy documents and identifiers are visible inside the
authenticated same-user desktop boundary. Host clock error can cause safe approval denial
or an unsuitable requested expiry that the core still validates. This review is
self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-12 — Supervised Network Profiles workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Non-authoritative discovery presentation, exact proposal activation,
explicit route confirmation, allowlisted resolver modes, normalized unique registered
source input, active-profile identity display, ambiguity warning, reasoned exact-profile
revocation, error behavior, compatibility, rollback, and absence of attestation/execution.

**Evidence examined:** UI typecheck; Vitest coverage for exact activation shape,
incomplete confirmation denial, unknown resolver denial, normalized addresses, bounded
revocation reasons, and unresolved requirement display; production UI build; complete
diff; network-profile setup contract, persistence implementation, and core validation.

**Findings:** Discovery cannot activate a profile. The workspace constructs only the
allowlisted confirmation contract and cannot claim attestation. Revocation can no longer
use a hidden generic reason. Multiple active profiles are explicitly treated as ambiguous;
the authenticated core remains authoritative for every mutation and execution stays off.

**Limitations and deferred work:** IPv6 confirmation remains disabled in this UI slice.
There is no observer enrollment, live public-IP comparison, attestation history, route
health timeline, VPN matrix, or execution control. Rollback affects presentation only.

**Residual risk accepted:** Local interface, resolver, and registered source addresses are
visible inside the authenticated same-user desktop boundary. Browser-side validation is
advisory and core denial remains required. This review is self-authored and non-independent
and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Durable assessment task history

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact workflow snapshot loading, workflow/task identity binding,
unique and complete task/lifecycle joins, execution and dispatch denial assertions,
post-enqueue and post-cancel refresh, attempt/failure presentation, error clearing,
compatibility, rollback, and absence of lease/worker/gateway controls.

**Evidence examined:** UI typecheck; Vitest coverage for exact snapshot reconstruction,
mismatched workflow denial, and authority-bearing task denial; production UI build;
desktop Cargo check; complete diff; workflow snapshot service, task and lifecycle schemas,
authenticated route coverage, recovery behavior, and task lifecycle contract.

**Findings:** Session memory is no longer treated as durable task truth. A partial,
mismatched, duplicated, or authority-bearing snapshot is denied and cleared. Mutation
success is followed by an exact authenticated read. No lease token, dispatch operation,
worker capability, checkpoint output, or external-effect path is added.

**Limitations and deferred work:** The workspace displays task lifecycle and bounded error
codes but not checkpoint content, receipts, outbox state, or a cross-workflow queue. It
cannot claim, heartbeat, retry, complete, or dead-letter tasks. Rollback affects only task
presentation; durable workflow records remain unchanged.

**Residual risk accepted:** Task identifiers and bounded internal error codes are visible
inside the authenticated same-user desktop boundary. Snapshot validation in the UI is a
defense-in-depth presentation control; core contracts remain authoritative. This review
is self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-12 — Supervised Authorization workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Target canonicalization, intent construction, exact decision identity
and hash binding, explicit-allow gating, exact single-use grant binding, consumption
receipt validation, target-edit invalidation, policy/safety invalidation, error behavior,
compatibility, rollback, and absence of gateway/network execution.

**Evidence examined:** UI typecheck; Vitest coverage for ambiguous target denial, exact
decision binding, wrong-policy denial, exact audience-bound grant validation, and exact
consumption receipt validation; production UI build; desktop Cargo check; complete diff;
ActionIntent, PolicyDecision, and ActionGrant schemas; authorization service evaluation,
issuance, consumption, audit, and revocation behavior.

**Findings:** A response cannot unlock the next presentation step unless it matches the
entire displayed authorization chain. Deny and approval-required outcomes cannot mint a
grant. Safety or policy changes remove displayed intent, decision, and grant state. The
workspace calls no gateway or execution endpoint and states that evaluation makes no
connection.

**Limitations and deferred work:** This is a non-executing local demonstration. It does
not attest a route, resolve DNS, authorize redirects, prepare gateway capacity, claim a
worker, open a socket, or capture execution evidence. Rollback affects presentation only.

**Residual risk accepted:** Authorization identifiers and canonical synthetic targets are
visible inside the authenticated same-user desktop boundary. UI validation is defense in
depth and cannot replace core enforcement. This review is self-authored and
non-independent and cannot satisfy an external independent-review requirement.

## 2026-08-12 — Supervised report coverage workspace

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact workflow coverage routes, asset/capability rule identifiers,
capability syntax, ordered intervals, outcome allowlist, evidence requirements, unique
evidence/limitations, human notes, retry-stable idempotency, response workflow binding,
individual-incompleteness assertion, history loading, draft selection, compatibility,
rollback, and absence of inferred sufficiency/submission.

**Evidence examined:** UI typecheck; Vitest coverage for exact request construction,
tested-without-evidence denial, authority-bearing completeness denial, and deterministic
coverage selection; production UI build; desktop Cargo check; complete diff; assessment
coverage and No Findings contracts; core coverage validation, immutability, audit, and
report completeness implementation.

**Findings:** The UI cannot claim that one record is complete and cannot record tested
coverage without evidence. Every record retains explicit limitations. History is accepted
only for the exact workflow. The core still computes final matrix sufficiency and rejects
stale, missing, incomplete, or finding-conflicted selections.

**Limitations and deferred work:** Policy rule discovery is not yet presented, so users
must copy exact rule identifiers from authoritative policy information. There is no
automatic testing inference, bulk matrix editor, submission, or network execution.
Rollback affects presentation only.

**Residual risk accepted:** Coverage notes and synthetic identifiers are visible inside
the authenticated same-user desktop boundary. Host-local datetime conversion may lead to
a safe core denial if unsuitable. This review is self-authored and non-independent and
cannot satisfy an external independent-review requirement.

## 2026-08-13 — Supervised source-bundle review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Exact source identity and digest validation, unique bundle selection,
authority precedence, deterministic ordering, divergent-version detection, bounded human
review notes, manifest source/provenance construction, unresolved-conflict blocking,
state invalidation, compatibility, rollback, and absence of extraction or execution.

**Evidence examined:** UI typecheck; Vitest coverage for precedence, ambiguous identity,
divergent-version denial, bounded conflict review, complete manifest provenance, and
pending unresolved conflicts; production UI build; complete diff; manifest v2 schema,
intake and normalization procedure, source history contract, and core manifest validation.

**Findings:** A multi-source draft cannot omit the selected immutable provenance links.
Conflicting versions cannot be silently preferred or presented as resolved: both remain
visible, the review note is retained as a warning, and an unresolved question keeps core
activation eligibility fail-closed. The UI adds no authority or external effect.

**Limitations and deferred work:** This slice detects divergent hashes for one exact
reference; it does not semantically extract statements, compare differently located
sources, edit normalized fields, or verify human clarification. Full structured
normalization review remains. Rollback affects presentation and draft construction only.

**Residual risk accepted:** Source references, hashes, and bounded human review notes are
visible inside the authenticated same-user desktop boundary. UI precedence is defense in
depth; canonical manifest validation and activation remain core-authoritative. This
review is self-authored and non-independent and cannot satisfy an external independent-
review requirement.

## 2026-08-13 — Structured normalization review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Explicit normalized domain, path, port, capability, request-rate,
total-request, response-size, and rationale inputs; source-import invalidation; manifest
mapping and provenance; malformed/missing-input denial; pending approval; compatibility;
rollback; and absence of extraction, policy authority, or execution.

**Evidence examined:** UI typecheck; 100 Vitest checks including successful restrictive
normalization and malformed domain, wildcard, path, port, and rationale denial;
production UI build; desktop Cargo check; complete diff; manifest v2 schema, intake and
normalization procedure, source-bundle review, and core canonical validation boundary.

**Findings:** Importing immutable material alone no longer creates a seemingly reviewed
scope. Every draft constructed through Intake has an explicit bounded normalization
record and retains pending approval. Invalid or incomplete values fail before draft
construction, while the core independently rejects semantic ambiguity and contradiction.

**Limitations and deferred work:** This slice covers one exact domain and the principal
HTTP/budget fields. Typed URL, IP, CIDR, wildcard/apex, testing-window, data-handling,
reporting, and conditional-capability editors, plus source-statement extraction, remain.
Rollback affects presentation and draft construction only.

**Residual risk accepted:** The UI's domain grammar and list normalization are defense in
depth and may safely over-deny; they cannot replace core canonicalization. Reviewed
synthetic scope and rationale remain visible inside the authenticated same-user desktop
boundary. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-13 — Typed asset normalization review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Domain, wildcard-domain, URL, IPv4, IPv6, and CIDR selection;
type-specific syntax normalization; explicit wildcard apex semantics; manifest mapping;
type-switch invalidation; ambiguous and credential-bearing input denial; compatibility;
rollback; and absence of discovery or execution.

**Evidence examined:** UI typecheck; 102 Vitest checks covering every asset type,
wildcard apex false preservation, ambiguous IPv4, credential-bearing URL, invalid CIDR,
wildcard-as-domain denial, and existing structured-review paths; production UI build;
desktop Cargo check; complete diff; manifest v2 asset contract, policy canonicalizers,
typed matcher tests, and intake normalization procedure.

**Findings:** Asset type is now deliberate rather than an implicit exact-domain default.
Wildcard apex authority cannot be inferred, and a value cannot survive a type switch.
The draft preserves the selected matcher semantics while the core still performs the
complete canonical and contradiction decision before compilation or activation.

**Limitations and deferred work:** This slice supports one allow asset. Multiple allow
and deny rows, per-asset provenance, internationalized-domain preview, URL component
inspection, and structured third-party/shared-hosting rules remain. UI CIDR checking
does not prove zero host bits; the core rejects that ambiguity. Rollback affects draft
presentation only.

**Residual risk accepted:** Browser URL normalization is defense in depth and may differ
from the security canonicalizer; only the core result can become policy. Synthetic asset
values remain visible inside the authenticated same-user desktop boundary. This review
is self-authored and non-independent and cannot satisfy an external independent-review
requirement.

## 2026-08-13 — Explicit deny-boundary review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Optional typed deny-boundary input, complete-pair validation,
type-switch invalidation, wildcard apex semantics, exact allow/deny duplicate denial,
independent manifest identity and provenance, omission of allow-only fields,
compatibility, rollback, and absence of discovery or execution.

**Evidence examined:** UI typecheck; 105 Vitest checks including complete typed denial,
partial-input denial, exact canonical duplicate denial, deny-row manifest construction,
and absence of allow ports and ownership claims; production UI build; desktop Cargo
check; complete diff; manifest v2 asset contract, policy deny precedence and
contradiction tests, typed asset review, and intake completeness requirements.

**Findings:** The draft can now state one explicit out-of-scope boundary without
accidentally granting it allow metadata. Partial or exact contradictory input cannot
construct a draft. The core remains the only authority for overlapping matcher
specificity, canonical contradictions, compilation, and activation.

**Limitations and deferred work:** This is one optional deny row tied to the primary
reviewed source. General multi-row allow/deny editing, per-row source selection, overlap
preview, third-party/shared-hosting details, and source-statement extraction remain.
Rollback affects draft presentation only.

**Residual risk accepted:** UI equality checks do not prove semantic non-overlap across
different matcher types; core deny precedence and contradiction validation are mandatory.
Synthetic boundary values remain visible inside the authenticated same-user desktop
boundary. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-13 — Multi-row scope review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Bounded multi-row allow/deny entry, per-row immutable-source
provenance, typed normalization, wildcard-apex handling, allow-only authority fields,
canonical duplicate rejection, minimum allow coverage, manifest construction,
compatibility, rollback, and absence of discovery or execution.

**Evidence examined:** UI typecheck; 108 Vitest checks including multi-row normalization,
unknown provenance denial, duplicate-source denial, deny authority denial, deny-only
denial, canonical duplicate denial, and exact manifest source references; production UI
build; desktop Cargo check; complete diff; manifest v2 validation and duplicate-asset
tests; intake completeness requirements.

**Findings:** A supervised review can now express multiple exact asset boundaries without
sharing provenance or leaking allow-only authority into deny rows. Local validation is
conservative and aligned with the core's duplicate-asset rejection. The core remains the
only authority for canonical manifest validation, compilation, approval, and activation.

**Limitations and deferred work:** Scope review is capped at 50 rows and still depends on
manual transcription. Structured technique, reporting, account, timing, stop-condition,
and data-handling rules plus source-statement extraction remain. Rollback affects draft
presentation only.

**Residual risk accepted:** Per-row UI validation cannot prove that different matcher
types are semantically non-overlapping; core deny precedence and contradiction validation
remain mandatory. Synthetic boundary values remain visible inside the authenticated
same-user desktop boundary. This review is self-authored and non-independent and cannot
satisfy an external independent-review requirement.

## 2026-08-13 — Testing-window review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Structured allowed weekdays, local start/end ordering, IANA timezone,
optional blackout interval and reason, manifest mapping, contract validation,
compatibility, rollback, and absence of scheduling or execution.

**Evidence examined:** UI unit tests for normalization and denial paths; manifest-builder
mapping tests; TypeScript typecheck and production build; Python policy checks; manifest
v2 schema validation; complete diff; operational-limit review and MVP requirements.

**Findings:** Intake can no longer place opaque objects into testing-window fields. A
complete reviewed window is mandatory for new UI drafts, partial blackouts fail closed,
and the policy boundary independently validates timezone identity and interval ordering.

**Limitations and deferred work:** Runtime wall-clock trust and window enforcement,
multiple-window editing, recurring blackout rules, account-reference review, and
source-statement extraction remain. Rollback affects draft construction only.

**Residual risk accepted:** Browser and host timezone databases can differ; the core is
authoritative and may safely over-deny. Reviewed timing terms do not authorize execution.
This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-14 — Account-use review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Unauthenticated-only and approved-test-account modes, bounded account
identifiers, shared-account denial, external secret-store declaration, manifest
provenance, Policy IR compilation, deterministic intent denial, compatibility, rollback,
and absence of credential storage or execution.

**Evidence examined:** UI review and manifest-builder tests; policy compilation and
allow/deny tests; contract validation; TypeScript typecheck and production build; Python
tests, Ruff, mypy, desktop Cargo check; complete diff; authorization invariants and MVP
request-account binding requirements.

**Findings:** New supervised drafts cannot silently treat an arbitrary intent account as
authorized. The exact identifier set is signed into Policy IR, and missing, unexpected,
or prohibited references deny before an allow decision. No credential value enters the
manifest, policy, decision, or UI state.

**Limitations and deferred work:** Secret resolution/injection, per-account capability or
asset restrictions, credential rotation, login/session lifecycle, and runtime execution
remain gated. Source-statement extraction also remains in Intake.

**Residual risk accepted:** Identifier syntax reduces accidental secret entry but cannot
prove that a human did not paste opaque secret material. The external secret boundary
must independently prevent disclosure. This review is self-authored and non-independent
and cannot satisfy an external independent-review requirement.

## 2026-08-14 — Source-statement review

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Bounded exact statement and candidate interpretation entry, selected
immutable-source ID/hash binding, authorization-field allowlist, duplicate rejection,
manifest preservation, core provenance validation, compatibility, rollback, and absence
of automatic extraction or authority.

**Evidence examined:** UI normalization and denial tests; manifest-builder candidate
mapping; policy provenance mismatch and duplicate tests; manifest v2 contract; TypeScript
typecheck and production build; Python tests, Ruff, mypy, desktop Cargo check; complete
diff; source-bundle and structured-normalization reviews; MVP AI-assistance boundary.

**Findings:** Intake now retains the exact language used to support a human interpretation
without treating that interpretation as a rule. Unknown or stale provenance denies, and
candidate text cannot enter Policy IR or bypass structured field review.

**Limitations and deferred work:** Encrypted-original preview and document parsing remain
disabled. AI-assisted proposal generation awaits sandboxing and model-data controls.
Statement-level semantic contradiction detection and exact character-offset citations
remain later work.

**Residual risk accepted:** Manual transcription can contain mistakes and the UI cannot
prove that entered text is a byte-exact excerpt because originals remain encrypted and
unexposed. Immutable source identity, separate candidate status, and mandatory structured
review limit this risk. This review is self-authored and non-independent and cannot
satisfy an external independent-review requirement.

## 2026-08-14 — Testing-window enforcement

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Manifest-to-Policy-IR schedule compilation, deterministic ordering,
IANA timezone conversion, weekday and half-open time matching, blackout precedence,
malformed-data fail closure, legacy compatibility, compiler versioning, rollback, and
absence of new execution capability.

**Evidence examined:** End-to-end compiled-policy allow test; closed-weekday, blackout,
and unknown-timezone denial tests; Policy IR contract; authorization test suite; complete
Python tests, Ruff, mypy, UI tests/build/typecheck, desktop Cargo check; complete diff;
testing-window review and clock-safety invariant.

**Findings:** A reviewed schedule can no longer disappear during compilation. Signed
Policy IR binds the exact windows and blackouts, and decisions deny unless the current
instant is inside at least one allowed window and outside every blackout.

**Limitations and deferred work:** Decision-time enforcement does not independently prove
wall-clock trust or terminate an already active gateway session at the exact schedule
boundary. Those remain required execution-gateway controls. Older policies omit schedules
and retain their prior engagement-validity behavior.

**Residual risk accepted:** Host timezone data may lag upstream IANA changes and safely
over-deny. Clock compromise remains outside schedule matching and must trigger the
separate clock-health safety boundary. This review is self-authored and non-independent
and cannot satisfy an external independent-review requirement.

## 2026-08-14 — Gateway schedule deadline

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Shared schedule-boundary calculation, overlapping-window union,
blackout precedence, timezone conversion, ambiguous or invalid local-time fail closure,
atomic request-start persistence, compatibility, rollback, and absence of new execution
capability.

**Evidence examined:** Schedule union and blackout deadline tests; closed, active-blackout,
and malformed-schedule tests; gateway deadline persistence and no-consumption denial tests;
Policy IR contract; complete authorization suite; Ruff, mypy, UI tests/build/typecheck,
desktop Cargo check; complete diff; testing-window and gateway revalidation reviews.

**Findings:** The final gateway commit now uses the same policy-owned schedule semantics as
decision evaluation and persists a deadline no later than the active window union's end or
the next blackout. Existing response finalization already rejects completion after that
durable deadline.

**Limitations and deferred work:** The slice does not independently interrupt an active
transport at the boundary or establish trusted continuous wall-clock health. Those remain
required gateway exit controls. Policies without schedules preserve legacy behavior.

**Residual risk accepted:** Host timezone data can lag upstream changes and safely
over-deny. Clock compromise and scheduler delay remain outside boundary calculation. This
review is self-authored and non-independent and cannot satisfy an external independent-
review requirement.

## 2026-08-14 — Gateway clock health

**Decision:** Sole-maintainer security review — non-independent; accepted for local
supervised development with synthetic data only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** UTC wall-clock and monotonic sampling, bounded drift tolerance,
rollback and forward-jump detection, startup ordering, watchdog ordering, concurrency,
fixed diagnostics, global safety pause behavior, compatibility, and absence of new
execution capability.

**Evidence examined:** Deterministic healthy-progress, rollback, and divergence tests;
startup and watchdog fail-closed ordering tests; gateway runtime supervisor and composition
tests; complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop Cargo check;
complete diff; testing-window, gateway revalidation, and schedule-deadline reviews.

**Findings:** Gateway recovery and runtime lifecycle checks can no longer proceed while
the process observes invalid, backward, or materially divergent wall-clock progress. The
existing global safety control is paused with fixed non-sensitive diagnostics.

**Limitations and deferred work:** The baseline is process-local and is re-established
after restart. This is a consistency check, not independent trusted-time attestation, and
it does not actively interrupt transport at a committed deadline.

**Residual risk accepted:** Coordinated compromise of wall and monotonic sources may evade
detection, and scheduling delay can postpone a watchdog observation by its configured
interval. Independent time attestation and active deadline interruption remain defense
layers. This review is self-authored and non-independent and cannot satisfy an external
independent-review requirement.

## 2026-08-14 — Gateway deadline interruption

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Durable-to-effective deadline derivation, millisecond truncation,
host executor timeout propagation, timeout error normalization, post-execution boundary
classification, clock validation, compatibility, and the fixed transport boundary.

**Evidence examined:** Exact host-timeout propagation, executor-timeout denial, late
completion reclassification, expired-deadline, fixed-argument, malformed-output, and
containment tests; response finalization tests; complete Python tests, Ruff, mypy, UI
tests/build/typecheck, desktop Cargo check; complete diff; clock-health and schedule-
deadline reviews.

**Findings:** The isolated effect no longer relies only on in-container deadline handling.
The host bounded executor receives the same earlier boundary and kills an overlong OCI
command, while late success cannot be durably classified as completed.

**Limitations and deferred work:** The slice is deliberately fixture-specific. General
gateway transports remain disabled and require equivalent deadline interruption. The
follow-on timeout-cleanup slice now explicitly removes the claim-bound fixture container
instead of relying only on attached-command termination and `--rm` behavior.

**Residual risk accepted:** Scheduler latency may delay observation or cleanup slightly,
though the isolated client independently stops socket I/O at its monotonic boundary. OCI
runtime defects remain bounded by internal TEST-NET-only containment. This review is
self-authored and non-independent and cannot satisfy external independent assurance.

## 2026-08-14 — Gateway timeout cleanup

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Claim-derived OCI naming, fixed launch arguments, timeout-only cleanup,
bounded force-removal, cleanup exception and nonzero-result handling, fixed diagnostics,
compatibility, and the fixture-only execution boundary.

**Evidence examined:** Fixed named-launch assertions, host-timeout cleanup command and
deadline-denial test, cleanup-failure denial test, malformed-output and containment tests;
complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop Cargo check; complete
diff; fixture transport and deadline-interruption reviews.

**Findings:** A killed attached runtime command is no longer treated as proof of container
removal. Timeout handling identifies and force-removes the exact claim-bound container and
fails closed unless the runtime reports successful cleanup.

**Limitations and deferred work:** The follow-on cleanup safety-latch slice now requires a
global safety callback for every fixture composition. General gateway execution remains
disabled and must provide a durable latch and recovery workflow before activation.

**Residual risk accepted:** A defective or malicious OCI runtime could falsely report
successful removal. Hosted rootless containment and post-run conformance provide additional
evidence, while the only enabled proof target remains internal TEST-NET. This review is
self-authored and non-independent and cannot satisfy external independent assurance.

## 2026-08-14 — Gateway cleanup safety latch

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Required safety dependency, cleanup exception and nonzero-result paths,
fixed pause reason and actor, pause-failure handling, exception-detail suppression,
composition completeness, compatibility, and fixture-only authority.

**Evidence examined:** Cleanup-failure pause assertion, successful-cleanup no-pause test,
pause-failure fixed-code test, required constructor updates, hosted proof composition;
complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop Cargo check; complete
diff; timeout cleanup and global safety-control reviews.

**Findings:** Timeout cleanup can no longer fail as an isolated adapter error. Every
transport composition supplies a safety dependency, and cleanup failure latches the core's
global safety state before control returns. Pause failure remains fail closed and
non-sensitive.

**Limitations and deferred work:** The follow-on durable cleanup-recovery slice now uses
unfinished claim records as a restart-safe cleanup queue before supervisor readiness.
General gateway transports remain disabled and require the same reconciliation pattern.

**Residual risk accepted:** Process termination between cleanup failure and the synchronous
pause call could prevent latching. The hosted proof remains internal TEST-NET only, and
startup recovery keeps execution disabled. This review is self-authored and non-independent
and cannot satisfy external independent assurance.

## 2026-08-14 — Durable fixture cleanup recovery

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Durable claimed-state discovery, deterministic ordering, claim-derived
container identity, exact-name bounded queries, idempotent absence, force-removal and
post-removal verification, recovery ordering, global safety pause, compatibility, and the
fixture-only authority boundary.

**Evidence examined:** Present-container removal and verified-absence test; ambiguous-query
pause test; verified lifecycle ordering and composed supervisor tests; timeout cleanup and
safety-latch tests; complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop
Cargo check; complete diff; runtime supervisor and fixture claim contracts.

**Findings:** Process restart can no longer abandon durable fixture claims while assuming
their OCI effects disappeared. Claim-bound cleanup completes and proves absence before
runtime recovery and containment attestation can report readiness.

**Limitations and deferred work:** Authorization startup performs the later transactional
claim abandonment, so an abrupt crash between verified cleanup and abandonment repeats a
safe absence check. General gateway transports remain disabled and need their own durable
effect identities.

**Residual risk accepted:** A defective or malicious OCI runtime could return a false empty
listing. The follow-on cleanup ownership slice now verifies exact PentAI role and claim
labels before deletion; rootless internal TEST-NET containment and subsequent conformance
attestation remain additional layers. This review is self-authored and non-independent and
cannot satisfy external independent assurance.

## 2026-08-14 — Fixture cleanup ownership verification

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Fixed launch labels, claim-to-container binding, exact-name discovery,
bounded label inspection, required-label subset matching, mismatch denial before deletion,
post-removal absence verification, compatibility, and fixture-only authority.

**Evidence examined:** Fixed launch-argument label assertions; successful exact-label
inspection, removal, and absence test; missing-label safety-pause test; malformed and
ambiguous recovery paths; complete Python tests, Ruff, mypy, UI tests/build/typecheck,
desktop Cargo check; complete diff; durable cleanup and managed-runtime ownership reviews.

**Findings:** Container name equality is no longer sufficient deletion authority. Cleanup
requires the runtime object to prove PentAI management, the fixed fixture role, and the
exact immutable execution claim before issuing force-removal.

**Limitations and deferred work:** OCI labels are runtime-reported rather than independently
signed. The follow-on runtime-binding slice now cross-checks durable runtime, image, and
network identity as well as ownership. The adapter remains an internal TEST-NET proof and
general gateway execution stays disabled pending stronger production runtime identity.

**Residual risk accepted:** A compromised OCI runtime can forge inspection output. Rootless
containment, trusted executable checks, exact claim identity, and subsequent conformance
attestation remain defense layers. This review is self-authored and non-independent and
cannot satisfy external independent assurance.

## 2026-08-14 — Fixture cleanup runtime binding

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Claim-to-runtime durable join, missing-link fail closure, runtime-ID
syntax, pinned digest and network validation, fixed launch bindings, complete-label subset
matching, mismatch denial before deletion, compatibility, and fixture-only authority.

**Evidence examined:** Fixed runtime/image/network launch-label assertions; complete
durable-binding inspection and cleanup test; missing-label safety-pause test; malformed
identity and ambiguous recovery paths; complete Python tests, Ruff, mypy, UI
tests/build/typecheck, desktop Cargo check; complete diff; ownership and runtime lifecycle
reviews.

**Findings:** A container that matches only the claim-derived name and ownership labels can
no longer authorize deletion. Cleanup requires the exact immutable runtime record, pinned
image, and managed network associated with that claim.

**Limitations and deferred work:** Bindings are still reported by the configured OCI
runtime and are not independently signed. The follow-on inspection-binding slice now
cross-checks actual OCI name, container ID, image, and network state in addition to labels.
The transport remains limited to internal TEST-NET proof and general execution stays disabled.

**Residual risk accepted:** A compromised OCI runtime can forge labels and inspection
output. Trusted executable checks, rootless containment, pinned images, durable identity,
and subsequent conformance attestation remain defense layers. This review is self-authored
and non-independent and cannot satisfy external independent assurance.

## 2026-08-14 — Fixture cleanup OCI inspection binding

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Full OCI object parsing, canonical container ID and name, actual pinned
image, exact managed-network set, complete durable-label matching, ID-based removal,
post-removal absence verification, compatibility, and fixture-only authority.

**Evidence examined:** Successful full-object inspection and ID-removal test; image-
mismatch safety-pause test; fixed launch bindings; malformed identity, label, and discovery
paths; complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop Cargo check;
complete diff; runtime-binding and OCI lifecycle inspection reviews.

**Findings:** Runtime-reported labels are no longer the only cleanup evidence. The actual
container name, immutable ID, image, and network attachment must agree with durable
authority, and removal uses the verified ID rather than the discoverable name.

**Limitations and deferred work:** OCI inspection remains a configured local trust boundary
and is not independently attested within this recovery transaction. The follow-on audit
slice now records verified cleanup outcome in the immutable audit chain. General gateway
execution remains disabled pending stronger production runtime identity.

**Residual risk accepted:** A compromised OCI runtime can forge the entire inspection
document. Trusted executable checks, rootless containment, durable cross-binding, and
subsequent independent conformance measurement remain defense layers. This review is
self-authored and non-independent and cannot satisfy external independent assurance.

## 2026-08-14 — Fixture cleanup audit trail

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Post-effect audit ordering, removed and already-absent outcomes,
claim/runtime/container linkage, trusted timestamps, fixed actor and action, hash-chain
serialization, failure rollback, repeated recovery semantics, compatibility, and
fixture-only authority.

**Evidence examined:** Verified ID-removal audit test; already-absent audit test; exact
action/subject/actor/data assertions; mismatch safety-pause path without success; audit
chain implementation; complete Python tests, Ruff, mypy, UI tests/build/typecheck, desktop
Cargo check; complete diff; cleanup inspection and authorization recovery reviews.

**Findings:** Crash cleanup is no longer operationally silent. Each successful durable
reconciliation records whether a verified container was removed or already absent, and no
success is written before absence is proven.

**Limitations and deferred work:** Audit events are locally hash-chained but not externally
anchored or independently timestamped. Repeated recovery before transactional claim
abandonment records repeated truthful observations.

**Residual risk accepted:** Full database replacement can replace both cleanup state and
its audit chain. Local OS controls and future backup/export anchoring remain defense layers.
This review is self-authored and non-independent and cannot satisfy external independent
assurance.

## 2026-08-14 — Gateway fixture execution claim integrity

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Canonical claim coverage, signature domain separation, key identity,
missing-key denial, schema ordering, pre-launch verification, mutation rejection, verifier
composition, single-use semantics, compatibility, and fixture-only authority.

**Evidence examined:** Authority issuance and mutation-verification assertions; transport
mutation test proving no executor call; schema contract; shared canonical payload helper;
hosted harness composition; complete Python tests, Ruff, mypy, UI tests/build/typecheck,
desktop Cargo check; complete diff and preceding fixture authority reviews.

**Findings:** Claim data can no longer be changed between atomic issuance and transport
launch without invalidating the authority signature. Verification happens before any claim
value becomes a runtime argument, and signing configuration fails closed.

**Limitations and deferred work:** Verification occurs in the host adapter, not independently
inside the isolated probe image. Key rotation and multi-key verification are not implemented
for this fixture-only proof.

**Residual risk accepted:** A compromised core process with signing-key access can issue a
new valid claim. Process isolation, protected key storage, and independent execution-broker
verification remain production work. This review is self-authored and non-independent and
cannot satisfy external independent assurance.

## 2026-08-15 — Signed gateway fixture claim contract v2

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Required-field compatibility, major-version selection, schema IDs and
constants, v1 restoration, v2 producer/consumer agreement, signature domain separation,
cross-version denial, persistence impact, rollback, and fixture-only authority.

**Evidence examined:** Contract compatibility regression for valid unsigned v1 and signed
v2 documents; cross-version rejection assertions; authority and transport schema calls;
canonical signature payload; contract validator; complete local checks and complete diff.

**Findings:** The newly required signature is no longer retrofitted onto v1. Historical v1
documents remain valid under their original contract, while the active execution path
defaults-deny every claim other than signed v2 before launching a process.

**Limitations and deferred work:** v1 remains available for historical validation but is
not accepted for execution. Key rotation and verification inside the isolated probe remain
deferred.

**Residual risk accepted:** Local code still carries two fixture contract schemas, so every
future consumer must select v2 explicitly for execution. Centralized schema constants may
be added when another consumer exists. This review is self-authored and non-independent
and cannot satisfy external independent assurance.

## 2026-08-15 — Public-only fixture claim verifier

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Private/public key separation, verifier construction and key identity,
transport ownership of verification, missing and mismatched key denial, mutation denial,
pre-launch ordering, compatibility, persistence impact, rollback, and fixture-only scope.

**Evidence examined:** Verification-only API tests; absence of a signing method; wrong-key
transport regression proving no executor call; existing mutation regression; authority
composition; complete local checks; complete diff; signed-v2 contract and claim-integrity
reviews.

**Findings:** The transport can validate claims without retaining signing capability or
calling the private-key-owning authority during launch. Tampered claims and claims from an
untrusted public key deny before any runtime process is invoked.

**Limitations and deferred work:** Python process compromise can still replace objects in
memory, and verification remains outside the isolated probe. Public-key rotation and trust-set
versioning are not implemented.

**Residual risk accepted:** The signer and verifier currently exist in the same core host
process even though capability objects are separated. Strong process isolation and probe-side
verification remain production work. This review is self-authored and non-independent and
cannot satisfy external independent assurance.

## 2026-08-15 — Probe-side fixture claim verification

**Decision:** Sole-maintainer security review — non-independent; accepted for the owned
TEST-NET fixture only<br>
**Author/reviewer:** `un3v3rKn0u` (sole maintainer, Product Owner, Security Lead,
repository owner)<br>
**Independence:** None; this uses the documented local-development exception.

**Scope reviewed:** Image trust-anchor ordering, public/private key separation, digest
binding, signed payload transport, strict parsing, signature verification, tuple and bound
cross-checks, deadline non-extension, pre-socket ordering, malformed/wrong-key/default-deny
paths, dependency lockfile, compatibility, privacy, rollback, and fixture-only authority.

**Evidence examined:** Rust valid-signature, wrong-key, malformed payload/signature, changed
bound, and deadline tests; host command assertions; public-key export tests; locked Cargo
build/test/clippy; Python and contract checks; complete diff; claim v2 and host verifier
reviews.

**Findings:** A host-side mutation can no longer cause the probe to open its fixture socket
unless the command still carries a valid authority-signed v2 claim whose effect bounds agree.
The image contains only public verification material, and its digest is measured after the
key is embedded.

**Limitations and deferred work:** The hosted conformance builder currently creates the
ephemeral key/image pairing; production image-key provisioning and rotation are not defined.
The probe validates the signed claim rather than independently loading the durable ledger.

**Residual risk accepted:** A compromised image build step can replace both probe and trust
anchor before digest approval. Reproducible builds, provenance, independent digest approval,
and production key lifecycle remain required. This review is self-authored and
non-independent and cannot satisfy external independent assurance.
