# ADR 0006: Verified SQLite table rebuilds

## Status

Accepted for local development on 2026-08-29. This is a migration-safety prerequisite;
it authorizes no particular schema reconstruction or runtime behavior.

## Context

SQLite cannot alter an existing `CHECK` constraint in place. The orchestration task
table is referenced by many foreign keys and triggers, so dropping it inside the current
migration transaction invalidates dependent schema before a replacement can be named.
Renaming it with modern SQLite defaults can instead rewrite those references to the
temporary name. A speculative second task-state source would create ambiguous durable
state.

## Decision

The migration runner recognizes only SQL files whose first line is exactly
`-- pentai: table-rebuild` and whose filename ends in `_table_rebuild.sql`. For that
explicit class, it establishes a transaction boundary, temporarily disables foreign-key
enforcement outside the transaction, enables legacy rename behavior, and then runs the
migration in one immediate transaction. Before commit it requires both
`PRAGMA integrity_check` to return exactly `ok` and `PRAGMA foreign_key_check` to return
no rows. Any SQL, verification, or interruption failure rolls back the migration and its
version record. Foreign-key enforcement and modern alter-table behavior are restored
after success or failure.

Rebuild SQL may not control foreign-key enforcement, use `writable_schema`, or commit
its own transaction. Each future rebuild must still inventory and explicitly preserve
the target table's columns, rows, defaults, constraints, indexes, triggers, and
references in its own reviewed migration and tests.

## Consequences

Ordinary migrations retain their existing execution behavior. The protocol does not
modify `orchestration_tasks`, add `dead_letter`, enable terminal consumption, or weaken
transition guards. A future task-state migration can use the protocol only after its
exact schema preservation and compatibility evidence is reviewed. Downgrade of a future
reconstructed table remains migration-specific and may be unsupported.
