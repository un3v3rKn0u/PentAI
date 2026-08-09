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

## 2026-08-09 — Signed policy lifecycle (review pending)

**Decision:** Not approved — independent security review required<br>
**Author/reviewer:** `un3v3rKn0u` (author, sole maintainer, Product Owner, Security
Lead, repository owner)<br>
**Independence:** None; the sole-maintainer exception is prohibited for signing-key
custody.

**Scope prepared for review:** OS-credential-service Ed25519 seed custody, one-use
desktop-to-core delivery, policy and Approval v1.2 signatures, activation/evaluation
verification, lifecycle history, explicit revocation, UI states, compatibility, tests,
and ADR 0003 on `feature/signed-policy-lifecycle`.

**Author review evidence:** Missing/wrong/malformed/tampered signature tests; exact key
ID and policy/approval binding; unsigned legacy denial; key absence and invalid-length
failure; expiry, replacement, revocation, and audit regressions; local and hosted checks
reported on the PR.

**Open gate:** A qualified independent reviewer must examine and approve generation,
credential-store behavior on macOS/Windows/Linux, key delivery, memory exposure,
domain separation, verification, loss/rotation behavior, compatibility, and recovery.
No merge or security claim is permitted before that approval.
