# Authorization Vertical Slice

This local-only slice covers program and source intake, Manifest v2 validation,
deterministic Policy IR v1 compilation, exact human approval, immutable activation,
ActionIntent simulation, and hash-chained audit. It creates no ActionGrant and contains
no target-facing networking code.

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

Approval v1.1 labels the Phase 0 transactional attestation as
`local-transaction-sha256`; it is integrity linkage inside the protected SQLite
transaction, not a public-key signature. Previously persisted v1.0 local attestations
remain readable for activation compatibility but no new approval claims Ed25519
without an Ed25519 operation.

## Stable decision codes

The slice emits `EXPLICIT_ALLOW`, `DEFAULT_DENY`, `EXPLICIT_DENY`, `POLICY_INACTIVE`,
`POLICY_EXPIRED`, `POLICY_REVOKED`, `POLICY_HASH_MISMATCH`, `TARGET_AMBIGUOUS`,
`TARGET_OUT_OF_SCOPE`, `CAPABILITY_DENIED`, `METHOD_DENIED`, `PORT_DENIED`, and
`PATH_DENIED` from PolicyDecision v1.

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
