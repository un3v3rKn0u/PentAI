# Encrypted backup and restore-drill contract v1

`backup-restore-report-v1.schema.json` describes creation and isolated restore-drill
results. Backup creation requires the local evidence key and explicit human
confirmation. The service uses SQLite's online backup API, verifies `integrity_check`,
authenticates every referenced evidence blob, excludes tombstoned content, and then
encrypts and authenticates the complete archive with a domain-separated AES-256-GCM
key.

Restore drills require explicit confirmation and accept only an authenticated v1
archive with an exact, non-ambiguous member set. They verify the database digest,
migration inventory, audit head, SQLite integrity, evidence metadata, and every
evidence blob. Current deletion tombstones take precedence over an older archive, so
a backup that would resurrect deleted evidence is denied. A successful drill is
installed into a new isolated directory and always reports `live_data_replaced=false`.
Creation and drill request/completion transitions are append-only audit events; failed
operations retain their request event for diagnosis without recording sensitive bytes.

The endpoint chooses its own backup and drill paths under the local backup directory;
callers cannot provide filesystem paths. Existing destinations, malformed identifiers,
missing keys, incomplete blobs, corrupt databases, invalid manifests, oversized
members, and authentication failures deny without changing live data.

This contract does not authorize live replacement, automatic recovery, or automatic
resumption of target-facing activity. Loss of the live database and its deletion
tombstones at the same time can make an older backup's later deletion state
unverifiable. Off-device backup custody, rotation, full-device-loss deletion journals,
source-blob inclusion, and production restore remain deferred.

Rollback removes the new API/service code. Existing `.pentai-backup` files remain
opaque encrypted artifacts and must be retained or deleted according to operator
policy; older binaries cannot restore them.
