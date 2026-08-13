# Authorization Vertical Slice

This local-only slice covers program and source intake, Manifest v2 validation,
deterministic Policy IR v1 compilation, exact human approval, immutable activation,
persisted ActionIntent evaluation, signed ActionGrant issuance, atomic local
verification/consumption, and hash-chained audit. It contains no target-facing
networking code.

## Invariants

- Meaningful manifest edits create immutable, engagement-sequenced versions; identical
  saves are idempotent and approval is never inherited.
- Compilation requires a valid, resolved manifest and matching persisted source hashes.
- Activation requires the newest manifest version and an unrevoked human
  `policy_activation` approval bound to the exact manifest and policy hashes.
- Database triggers protect active manifest and policy content from mutation.
- Evaluation recalculates the policy hash, checks lifecycle and validity, canonicalizes
  the target, uses path boundaries and deny precedence, and defaults to deny.
- Each audit hash covers the full event and previous hash. Verification reports the
  first broken sequence after mutation, interior deletion, or reordering. Detecting
  truncation of the final event requires a separately anchored head hash, which is not
  part of this slice.

Approval v1.2 uses an actual Ed25519 operation over the canonical approval document.
Policy IR content hashes bind the unsigned policy and stable public-key ID; signatures
then bind that hash with a domain-separated Ed25519 message.
Activation verifies both signatures and their persisted linkage. Legacy transaction
attestations and unsigned policies remain readable as history but are ineligible for
activation and must be recompiled and reapproved.

## Stable decision codes

The slice emits `EXPLICIT_ALLOW`, `DEFAULT_DENY`, `EXPLICIT_DENY`, `POLICY_INACTIVE`,
`POLICY_EXPIRED`, `POLICY_REVOKED`, `POLICY_HASH_MISMATCH`, `TARGET_AMBIGUOUS`,
`TARGET_OUT_OF_SCOPE`, `CAPABILITY_DENIED`, `METHOD_DENIED`, `PORT_DENIED`, and
`PATH_DENIED` from PolicyDecision v1.

## ActionGrant v1 lifecycle

Only a persisted, contract-valid `allow` PolicyDecision linked to the exact immutable
ActionIntent and current active signed policy can mint a grant. Grants bind the
assessment, policy hash, revocation epoch, audience, capability, canonical target and
HTTP/account digest, and parameters digest. They expire after at most 30 seconds and
authorize one request and one connection.

Verification compares the presented grant and intent with their immutable database
records, verifies the domain-separated Ed25519 signature, current policy and epoch,
audience, time window, and all intent bindings, then atomically records consumption.
Replay, mutation, expiry, revocation, wrong-key, wrong-audience, and stale-epoch paths
deny. This verifier performs no network or tool action.

Migration `0007_action_grants.sql` adds immutable intent and grant ledgers plus atomic
consumption/revocation state. It is additive: earlier records and APIs remain intact,
and older application code ignores the new tables after rollback.

## Durable safety control plane

Migration `0008_safety_control_plane.sql` adds a non-deletable singleton global state
with `active`, `paused`, and `stopped` states and a monotonic generation. Every core
startup fails closed to `paused`, revokes unused grants, pauses active assessments,
increments their revocation epochs, and records a linked audit event. Global pause or
stop performs the same invalidation atomically. Assessment pause invalidates only that
assessment; resume requires an explicit authenticated human request, active global
state, and a current, unrevoked, unexpired, verifiable signed policy.

Policy evaluation, grant minting, and grant consumption all require the applicable
safety state to be active. Missing or malformed state denies. The API never enables
network execution: `execution_enabled` and `network_attested` remain false. Rolling
back application code leaves the additive state and audit history intact; operators
must not drop the migration to bypass a pause.

## Manifest v2 field provenance and history

Manifest v2 requires `field_provenance` for scope, techniques, operational limits,
network, data handling, reporting, and agent controls. Every link carries an imported
source UUID and its exact SHA-256 hash. Missing, unknown, duplicate, or stale links
fail validation and cannot compile. Asset-level `source_reference` remains mandatory.

Migration `0006_manifest_version_history.sql` adds engagement-local sequence numbers,
stored validation outcomes, and immutable-row triggers. Pre-migration rows remain
readable as `legacy_unverified` but fail closed at compilation until a human resaves
them under the strengthened contract. The API lists history newest-first and computes
engagement-bound deterministic diffs across authorization-bearing sections. There is
no destructive down migration; rolling back code retains the additive columns/data.

Policy compiler `1.1.0` strengthens the existing Policy IR v1 semantics without
changing its JSON shape. Allow assets require explicit ownership verification and at
least one allowed port; wildcard assets require an explicit apex decision; URL paths
cannot broaden their canonical base; duplicate typed assets and contradictory path,
IPv6, DNS, rate, or runtime constraints fail validation. At least one capability must
be explicitly allowed. Matcher specificity orders URL, exact host/address, wildcard,
and CIDR rules deterministically, with CIDR prefix length contributing specificity.
Previously compiled Policy IR remains readable, but manifests relying on implicit
authority must be corrected and compiled with `1.1.0` before later activation.

Policy compiler `1.2.0` additionally preserves reviewed testing windows and blackout
periods in signed Policy IR. The evaluator converts the current UTC instant through each
window's IANA timezone, requires an allowed weekday and half-open local time interval,
and gives active blackout intervals precedence. Missing schedules remain readable for
legacy compatibility; malformed schedules deny closed.

Phase 1 migration `0004_source_provenance.sql` strengthens the persisted source side
of this binding with normalized source kind, media type, optional source version,
immutable rows, idempotent repeated imports, and audit linkage. Migration
`0005_encrypted_source_blobs.sql` distinguishes legacy placeholders from new
AES-256-GCM encrypted originals. Pasted text is the only accepted acquisition kind in
this baseline. Bounded file payloads are accepted by the additive local API described
in `docs/security/file_source_import_slice.md`. Bounded URL payloads use the separately
guarded acquisition boundary in `docs/security/url_source_acquisition_slice.md`.

## Verification

```text
PYTHONPATH=packages/policy/src:services/core/src python3 -m unittest discover -s tests -p "test_*.py"
python3 scripts/validate_contracts.py
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
pnpm typecheck
pnpm test
pnpm build
cargo check --manifest-path apps/desktop/Cargo.toml
```
