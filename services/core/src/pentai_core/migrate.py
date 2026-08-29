from __future__ import annotations

import os
import re
import sqlite3
from importlib import resources
from pathlib import Path

from pentai_core.database import transaction


def _source_migrations_dir() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "migrations"
        if candidate.is_dir():
            return candidate
    return None


MIGRATIONS_DIR = _source_migrations_dir()
MIGRATION_NAME = re.compile(r"^(?P<version>\d{4})_[a-z0-9_]+\.sql$")
TABLE_REBUILD_DIRECTIVE = "-- pentai: table-rebuild"


class MigrationIntegrityError(RuntimeError):
    """Raised before commit when a migration violates durable SQLite integrity."""


def _migration_sources() -> list[tuple[str, str]]:
    packaged = resources.files("pentai_core").joinpath("migrations")
    try:
        packaged_sources = sorted(
            (
                item.name,
                item.read_text(encoding="utf-8"),
            )
            for item in packaged.iterdir()
            if item.name.endswith(".sql")
        )
    except (FileNotFoundError, NotADirectoryError):
        packaged_sources = []
    if packaged_sources:
        return packaged_sources
    if MIGRATIONS_DIR is not None and MIGRATIONS_DIR.is_dir():
        return [
            (path.name, path.read_text(encoding="utf-8"))
            for path in sorted(MIGRATIONS_DIR.glob("*.sql"))
        ]
    raise FileNotFoundError("no packaged or source migrations were found")


def migrate(database_path: Path | None = None) -> list[str]:
    database_path = database_path or Path(os.getenv("PENTAI_DATABASE_PATH", "var/pentai.db"))
    applied_now: list[str] = []
    with transaction(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        applied = {
            row["version"] for row in connection.execute("SELECT version FROM schema_migrations")
        }
        for migration_name, migration in _migration_sources():
            match = MIGRATION_NAME.match(migration_name)
            if not match:
                continue
            version = match.group("version")
            if version in applied:
                continue
            table_rebuild = migration.startswith(TABLE_REBUILD_DIRECTIVE + "\n")
            if table_rebuild:
                _validate_table_rebuild_source(migration_name, migration)
                _prepare_table_rebuild(connection)
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    f"{migration}\n"
                    f"INSERT INTO schema_migrations(version) VALUES ('{version}');\n"
                )
                if table_rebuild:
                    _verify_integrity(connection, migration_name)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                if table_rebuild:
                    _finish_table_rebuild(connection)
            applied_now.append(version)
    return applied_now


def _prepare_table_rebuild(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        raise MigrationIntegrityError("table rebuild requires a transaction boundary")
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("PRAGMA legacy_alter_table = ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 0:
        connection.execute("PRAGMA legacy_alter_table = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        raise MigrationIntegrityError("table rebuild could not disable foreign keys")


def _validate_table_rebuild_source(migration_name: str, migration: str) -> None:
    if not migration_name.endswith("_table_rebuild.sql"):
        raise MigrationIntegrityError("table rebuild migration name is not explicit")
    normalized = migration.casefold()
    forbidden = (
        r"\bpragma\s+foreign_keys\b",
        r"\bpragma\s+writable_schema\b",
        r"\bbegin(?:\s+(?:deferred|immediate|exclusive|transaction))*\s*;",
        r"\bcommit(?:\s+transaction)?\s*;",
    )
    if any(re.search(pattern, normalized) for pattern in forbidden):
        raise MigrationIntegrityError("table rebuild contains forbidden transaction control")


def _finish_table_rebuild(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA legacy_alter_table = OFF")
    connection.execute("PRAGMA foreign_keys = ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise MigrationIntegrityError("foreign-key enforcement was not restored")


def _verify_integrity(connection: sqlite3.Connection, migration_name: str) -> None:
    integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
    if integrity != ["ok"]:
        raise MigrationIntegrityError(f"{migration_name} failed integrity_check")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise MigrationIntegrityError(f"{migration_name} failed foreign_key_check")


if __name__ == "__main__":
    versions = migrate()
    print(f"Applied migrations: {', '.join(versions) if versions else 'none'}")
