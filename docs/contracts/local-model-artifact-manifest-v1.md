# Local-model artifact manifest v1

## Scope and authority

This contract is the closed machine-readable form of ADR 0008 for owned local
development on macOS arm64. Trusted core contains exactly one built-in manifest for the
approved `llama.cpp` b10516 runtime closure and immutable Qwen Q4_K_M GGUF. The resolver
accepts no selector, path, version, digest, provenance, platform, or activation input.

The manifest is fixed to `inactive`, `activation_enabled: false`,
`verification_enabled: false`, `receipt_enabled: false`, `authority: none`, and
`execution_enabled: false`. Structural validity or built-in provenance does not prove
that an artifact is installed, current, safe, or verified and does not create policy
approval, a grant, availability, or execution authority.

## Closed identity and default denial

V1 pins the operating system, architecture, APFS assurance scope, official runtime
release/source/archive provenance, entry point, complete dynamic-library closure,
installed regular-file names, exact component sizes and SHA-256 values, exact Qwen
repository/revision/file/GGUF/quantization identity, platform-derived relative layout,
ownership and mode policy, link restrictions, hashing bound, stable identity fields,
and inactive lifecycle semantics.

The schema uses exact constants, including the ordered component closure. Missing,
additional, changed, reordered, duplicate, caller-selected, mixed-version, path-
bearing, privilege-expanding, activating, verifying, receipt-producing, or executing
input denies with `LOCAL_MODEL_ARTIFACT_MANIFEST_MALFORMED`. The public compiler only
validates and canonicalizes an exact document; it does not authenticate an untrusted
caller as the manifest source. Only the no-argument built-in resolver supplies the
repository-owned identity.

## Replay, concurrency, cancellation, and recovery

Compilation is pure, deterministic, and produces immutable typed state and a canonical
digest. It performs no file I/O and has no replay ledger, mutable lifecycle, competing
transition, cancellation window, or recovery producer. Restart creates or advances
nothing. A future activation and verifier must separately authenticate current registry
state and bind cancellation, safety, policy epoch, fencing, replacement, expiry,
revocation, and recovery lineage.

## Compatibility and rollback

This is an additive v1 contract and pure module. It changes no API, database, migration,
ActionIntent, PolicyDecision, ActionGrant, HTTP, provider, or runtime behavior. Older
code ignores it. Rollback removes the resolver while ADR 0008 remains decision history.
Changing any approved artifact fact requires a newly reviewed additive manifest version
or revision; v1 must not be edited into a new identity or treated as active.

## Deferred work

Authenticated registry activation and its exact validity window, installation,
descriptor-based APFS/ownership/permission/link verification, stable file identity,
bounded hashing, GGUF parsing, immutable verification receipts, persistence, startup
reconciliation, approval consumption, ActionGrant v2, model loading, process launch,
supervision, metering, and execution remain unavailable.
