# Supervised Programs workspace

The Programs workspace lists durable programs from the existing authenticated collection
endpoint and creates local draft programs. An operator must explicitly select a program;
the UI does not infer a current program from ordering, status, or name.

Changing the selected immutable program ID clears all downstream source, engagement,
manifest, policy, decision, and grant presentation state before loading that program's
source history. Program creation sends only the trimmed human-entered name and the fixed
local platform marker. The core remains authoritative for validation, identity, status,
versioning, persistence, and audit events.

The workspace cannot edit, activate, archive, or delete programs. It adds no endpoint,
schema, migration, network access, or execution authority. Rollback restores the former
inline creation form without changing durable programs.
