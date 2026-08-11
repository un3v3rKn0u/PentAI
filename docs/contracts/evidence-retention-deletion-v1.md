# Evidence retention and deletion v1

## Policy and human authority

`EvidenceDeletion` records a permanent content-deletion workflow for an original or
redaction derivative. The retention period comes only from `data_handling.retention_days`
in the immutable manifest version bound to the artifact's exact policy bundle. The API
cannot shorten that period.

An authenticated human must provide the exact artifact type, identifier, immutable
SHA-256 digest, a bounded reason, and `confirm_permanent_deletion: true`. Missing or
ambiguous identity, digest mismatch, invalid policy, early deletion, or conflicting
replay fails closed. A durable request and audit event commit before filesystem work.

## Crash safety and shared content

The state machine is `pending` version 1, `processing` version 2, then `completed`
version 3. Database triggers enforce transitions and preserve immutable request fields.
As soon as a request exists, content reads and previews are denied. Startup resumes
both pending and processing requests; it never makes deleted content readable again.

Content-addressed blobs may be shared by multiple originals or derivatives. A blob is
unlinked only when every database reference to its digest has a deletion request.
Otherwise the completed record reports `retained_shared`. Missing blobs during retry
are idempotently reported as `already_absent`. Metadata, hashes, provenance, custody,
and audit history remain available and immutable.

## Erasure boundary, compatibility, and rollback

The encrypted file is unlinked and its directory is synchronized. The contract always
reports `forensic_erase_guaranteed: false`: general filesystems and SSDs do not provide
a portable overwrite guarantee, and the current evidence store does not use a
destroyable per-object key. PentAI must not describe this control as forensic secure
erase or cryptographic erasure.

Migration `0023_evidence_retention_deletions.sql` is additive. Older binaries may
ignore deletion records, but running an older binary after a deletion request is unsafe
because it does not enforce tombstones; operational rollback therefore requires a
verified pre-migration backup and must not reopen a database containing migration 0023.

New encrypted backups omit fully tombstoned digests and restore drills reject older
archives that conflict with the live tombstone set. Backup inventory/purge,
full-device-loss tombstone custody, per-object envelope keys, legal holds, and
independently verified forensic deletion remain deferred release work. No automatic
scheduler initiates deletion; every request remains human-supervised.
