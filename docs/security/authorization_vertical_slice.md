# Authorization Vertical Slice

**Status:** implemented local-only milestone
**Contracts:** Engagement Manifest v2, Policy IR v1, ActionIntent v1, PolicyDecision v1,
Approval v1.1, canonicalization v1

## Workflow

The local UI and core API implement:

```text
Program → Engagement → SourceDocument (SHA-256)
→ immutable ManifestVersion → validated canonical manifest
→ deterministic PolicyBundle → exact human policy_activation Approval
→ immutable active policy → deterministic ActionIntent decision
→ hash-chained AuditEvent
```

This milestone performs policy simulation only. It does not issue `ActionGrant` objects,
resolve DNS, create sockets, contact targets, or perform HTTP/HTTPS requests.

## State and version rules

- Programs begin `draft` and become `active` only with an active engagement policy.
- Engagements move from `draft` to `active`; revocation changes the state to `revoked`
  and increments the revocation epoch.
- A manifest is eligible for compilation only when schema/semantic checks, source
  provenance, validity, canonical scope, supported capabilities, limits, and unresolved
  questions all pass.
- Saving an edit creates a new `ManifestVersion` with `supersedes_id`. An approval for
  an older version is never considered for the new version.
- Approval persistence binds the exact manifest-version ID, manifest SHA-256,
  policy-bundle ID, and Policy IR SHA-256. Approval v1's contract-level `policy_hash`
  remains unchanged; Policy IR's `manifest_hash` completes the binding.
- Activated Policy IR and its approved manifest are protected by database immutability
  triggers. A change requires a new version, compilation, and approval.
- Activation re-hashes the source-linked manifest and Policy IR and rejects stale,
  expired, altered, missing, or mismatched approvals.

## Determinism and fail-closed behavior

Canonical JSON uses sorted object keys, compact UTF-8 JSON, and stable list ordering for
authorization sets. Stable UUIDv5 identifiers are derived from canonical inputs for
compiled rules, policies, and decisions. Identical canonical manifest input produces the
same Policy IR and hash. Identical policy and ActionIntent input produces the same
decision ID, outcome, evaluated rules, and reason codes.

Evaluation compares canonical URL objects, enforces segment boundaries (`/api` does not
match `/apiv2`), applies explicit wildcard apex behavior, selects the most-specific
rules, and gives deny precedence. Missing, ambiguous, altered, inactive, revoked,
expired, unsupported, or out-of-scope input denies.

PolicyDecision v1 reason codes used by this slice:

- `EXPLICIT_ALLOW`
- `DEFAULT_DENY`
- `EXPLICIT_DENY`
- `POLICY_INACTIVE`
- `POLICY_EXPIRED`
- `POLICY_REVOKED`
- `POLICY_HASH_MISMATCH`
- `TARGET_AMBIGUOUS`
- `TARGET_OUT_OF_SCOPE`
- `CAPABILITY_DENIED`
- `PORT_DENIED`
- `PATH_DENIED`
- `APPROVAL_MISSING`

Manifest/compiler validation uses stable codes including `AUTHORIZATION_AMBIGUOUS`,
`AUTHORIZATION_EXPIRED`, `AUTHORIZATION_NOT_YET_VALID`, `CONTRADICTORY_RULES`,
`UNSUPPORTED_CAPABILITY`, `LIMITS_INVALID`, `PROVENANCE_MISSING`,
`PROVENANCE_HASH_MISMATCH`, `PROVENANCE_AMBIGUOUS`, `ASSET_INVALID`,
`ASSET_AMBIGUOUS`, `PORT_AUTHORITY_MISSING`, `OWNERSHIP_UNVERIFIED`,
`SCOPE_AMBIGUOUS`, `TECHNIQUES_INCOMPLETE`, and `NETWORK_CONSTRAINTS_INCOMPLETE`.

Compiler v1.1 assigns type-aware specificity: URL rules are narrower than exact
domain/IP rules, exact domains are narrower than wildcard domains, and longer CIDR
prefixes are narrower than shorter prefixes. Runtime evaluation still gathers all
matches at the greatest specificity and applies deny precedence there. This lets a
reviewed exact exception override a broader range rule while an equal-specificity deny
always wins.

## Audit verification

Approval, activation, rejection, revocation, and every policy evaluation append an
event containing minimal linkage and explanation data. Each event hash covers the
event body and `previous_hash`. Verification starts at the genesis event and rejects
mutation, interior removal, or reordering at the first invalid sequence. Detecting
truncation of the final event requires a separately anchored head hash, which is not
part of this slice.

The UI displays the event chain and current verification result. Audit data stores
hashes, stable reason codes, rule IDs, actor identity, and subject identity; it does
not store source text or secret values.

## Verification

```text
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/python scripts/validate_contracts.py
pnpm typecheck
pnpm test
pnpm build
cargo fmt --manifest-path apps/desktop/Cargo.toml -- --check
cargo check --manifest-path apps/desktop/Cargo.toml
cargo test --manifest-path apps/desktop/Cargo.toml
```

## Known limitations

- Approval v1 contains a local human-attestation value shaped by the contract, but
  operating-system key management and independently verifiable Ed25519 signing are not
  part of this slice. Activation relies on the transactional exact-hash approval record.
- Source content is hashed and represented by a content-addressed blob reference; an
  encrypted source-blob store is deferred.
- Testing windows, live route/DNS/source-IP attestation, budget reservation, grant
  issuance, and controlled HTTP/HTTPS execution are deliberately deferred.
