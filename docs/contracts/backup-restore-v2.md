# Encrypted backup and restore-drill contract v2

`backup-restore-report-v2.schema.json` extends the isolated backup drill with complete
encrypted source-provenance custody. Every new archive has manifest version `2.0.0`
and includes the exact unique source content hashes referenced by its SQLite snapshot.
Before archive creation, each source row must declare the supported available-blob
state and exact `encrypted-source:v1:<sha256>` identity, and the source store must
authenticate the plaintext against that digest.

The authenticated archive contains only exact generated paths:
`database/pentai.db`, `manifest.json`, `evidence/<sha256>.blob`, and
`sources/<sha256>.blob`. Restore drills reconstruct separate evidence and source stores,
authenticate every object with the OS-keychain-backed master key, and require the v2
source hash inventory to exactly match the restored database. Missing, extra,
duplicated, malformed, unavailable, or unauthenticated source content denies creation
or restore and leaves no completed drill directory.

The envelope format and key derivation are unchanged from v1. Authenticated v1
database/evidence archives remain accepted as their original narrower restore drill;
the returned v2 report truthfully records `source_blob_count=0`. New backups are
always v2. This major contract version prevents consumers from mistaking a v1 archive
for a complete intake-provenance backup.

This capability still does not replace live data, resume work, rotate or purge backup
copies, provide off-device custody, or preserve post-backup deletion knowledge after
complete device loss. Rollback to the v1 producer loses source-blob coverage but does
not make existing v2 envelopes readable by the old implementation.
