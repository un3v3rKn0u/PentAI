# Backup inventory, rotation, and purge contract v1

The authenticated local API inventories at most 1,000 server-named
`<uuid>.pentai-backup` files. Matching symlinks, non-files, filename/manifest identity
mismatches, invalid envelopes, ambiguous members, unsupported manifests, and oversized
expanded archives deny the entire inventory. Each item reports its authenticated
envelope digest, size, archive version, bounded content counts, whether an isolated
restore was previously verified in the audit ledger, and whether it contains evidence
now covered by the live deletion tombstone set.

Rotation is advisory and deterministic. The operator selects a retention count from 2
through 20. The newest requested number and the newest restore-verified backup are
protected; all other IDs are proposed as candidates. The plan always reports
`requires_human_confirmation=true` and `automatic_deletion_performed=false`.

Purge accepts only the server-selected backup root, canonical UUID, exact authenticated
envelope SHA-256, a bounded reason, and explicit human confirmation. The last existing
restore-verified backup cannot be purged. The service commits an append-only request
before rechecking the on-disk identity and unlinking the file, synchronizes the backup
directory, then records completion. A crash after unlink is safely completed on an
exact retry as `already_absent`; conflicting retries deny.

Filesystem unlink is not forensic erasure and every inventory/purge report states
`forensic_erase_guaranteed=false`. This contract does not delete off-device copies,
automatically schedule rotation, replace live state, or authorize target-facing work.
Rollback removes the API while leaving any existing backup files and immutable audit
events intact.
