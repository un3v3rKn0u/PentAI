# Phase 1 source intake provenance slice

**Status:** Encrypted-storage extension implemented locally; security review pending
**Scope:** Pasted-text source metadata and provenance only

## Outcome

The local core can create and list Programs, accept a pasted authoritative source,
compute its SHA-256 digest, persist normalized provenance, return the same immutable
record for an identical repeat import, and link the import to the hash-chained audit
ledger. Source content is used only to compute the digest and is neither returned by
the API nor written to general logs or audit data.

Supported authority values match Engagement Manifest v2: `contract`,
`program_staff`, `program_page`, `platform_rule`, and `internal_note`. Timestamps with
offsets are normalized to UTC. Unknown authority or source kind, blank content or
metadata, invalid timestamps, and nonexistent Programs fail closed.

## Persistence and compatibility

Migration `0004_source_provenance.sql` adds `source_kind`, `media_type`, and
`source_version` with compatible defaults for existing records. It also makes source
rows immutable and adds an identity lookup index. Existing records are preserved.
Application rollback can ignore the additive columns, while the immutability trigger
continues to protect provenance; no destructive down migration is provided.

The existing Manifest v2 contract is unchanged. Its source identifiers and hashes
continue to bind manifests to these persisted source records.

## Security properties and limitations

- `INV-AUTH-003`: malformed, ambiguous, unsupported, or missing provenance is denied.
- `INV-AUTH-002`: the persisted source ID and digest remain the manifest provenance
  anchor.
- `INV-DATA-001`: source content is excluded from responses after import, audit events,
  and diagnostics.
- `INV-DATA-003` and `INV-DATA-004`: new imports produce hash-chained audit events.

New pasted-source originals are persisted as AES-256-GCM authenticated,
content-addressed blobs. Their durable master key is created and retrieved by the
desktop through the operating-system credential service, then delivered to the owned
core over a one-use stdin channel. Missing keys, failed storage, authentication
failure, and digest mismatch deny import. Phase 0 placeholder records remain honestly
marked `legacy_missing` after migration.

File payloads are accepted only through the bounded, path-free API documented in
`file_source_import_slice.md`; the native file-picker UI remains open. URL sources use
the guarded boundary in `url_source_acquisition_slice.md`. Key rotation, credential-store
backup/restore, and Windows/Linux credential-store verification are also open.
Therefore the Phase 1 vertical demonstration remains incomplete pending supervised UI.

No target-facing networking or authority is introduced by this slice.
