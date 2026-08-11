# Evidence original and custody event v1

## Outcome and authority boundary

`EvidenceOriginal` records a bounded immutable original for one supervised assessment
workflow. The service derives its engagement and exact policy bundle from that
workflow; an optional execution trace is accepted only when its engagement and policy
match. Evidence bytes, UI identifiers, and callers never grant execution authority.

The authenticated local API accepts 1 byte through 2 MiB as base64 and supports notes,
HTTP metadata, bounded response excerpts, screenshots, imported files, and tool output.
Only metadata and digests enter SQLite and the audit ledger. The original is written to
the content-addressed blob store before its metadata is committed.

## Encryption and custody

Originals use AES-256-GCM with a fresh nonce. HKDF-SHA-256 derives an evidence-only key
from the existing OS-keychain-backed source master key, so desktop users need no new
configuration and evidence/source nonce spaces do not share an AEAD key. The plaintext
SHA-256 digest is authenticated and determines the blob path. Reads authenticate and
rehash plaintext before returning it.

Database triggers prohibit update or deletion of originals and custody events. Each
successful store, metadata access, and internal content access appends both a custody
event and a privileged audit event. Custody events form a per-object hash chain.
Missing keys, malformed input, trace mismatches, storage errors, tampering, and
idempotency conflicts fail closed. In the composed application, key or storage failure
also stops global execution and requires human recovery.

## Compatibility, recovery, and deferred work

Migration `0021_encrypted_evidence_originals.sql` is additive and does not reinterpret
legacy data. Older binaries may ignore the new tables and sibling `evidence-blobs`
directory, but rollback must restore a verified pre-migration backup rather than delete
immutable records. Database/blob backup without the OS credential cannot decrypt
originals.

Original content remains unavailable through HTTP. Migration 0022 adds separately
encrypted immutable text-redaction derivatives and bounded inactive plain-text
previews; see `evidence-redaction-preview-v1.md`. Retention deletion, general file or
image previews, exports, findings, and reports remain deferred.
