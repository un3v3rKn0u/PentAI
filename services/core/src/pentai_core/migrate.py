from __future__ import annotations

import os
import re
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
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                f"{migration}\n"
                f"INSERT INTO schema_migrations(version) VALUES ('{version}');\n"
                "COMMIT;"
            )
            applied_now.append(version)
    return applied_now


if __name__ == "__main__":
    versions = migrate()
    print(f"Applied migrations: {', '.join(versions) if versions else 'none'}")
