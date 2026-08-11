# Phase 1 storage-failure recovery slice

This slice turns runtime storage uncertainty into a process-local, irreversible safety
stop. SQLite `FULL`, `IOERR`, `CORRUPT`, `NOTADB`, `CANTOPEN`, and `READONLY` failures,
plus encrypted source, evidence, deletion, and backup write failures, trip the latch.
The latch degrades health/readiness and denies intent evaluation, grant consumption,
gateway preparation, request commitment, and fixture execution claims. Only a human
restart after storage repair and normal startup integrity verification can clear it.

Encrypted blob and backup writers use same-directory temporary files, synchronize the
complete ciphertext before atomic replacement, synchronize the parent directory, and
remove incomplete temporary files on failure. A failure after replacement can leave a
complete authenticated object whose durability is uncertain; the operation still
reports failure and authority remains stopped. Content-addressed source/evidence retry
authenticates such an object, while backup inventory authenticates a surviving archive.
No partial object is treated as committed metadata.

Fault tests inject synthetic disk-full failures before publication and SQLite failures
inside a transaction. They prove rollback, database integrity, preservation of earlier
committed blobs/backups, temporary-file cleanup, and denial of new authority after the
first storage fault. Tests use only synthetic local fixtures and create no network
effect.

No schema, migration, archive format, or public API contract changes. Older data remains
compatible. Rolling back the code removes the runtime latch but does not alter stored
data. Real power-cut and filesystem-specific durability tests remain required hosted or
hardware validation; injected `fsync` and SQLite errors do not prove physical media
behavior.
