from __future__ import annotations

import re
from pathlib import Path

from pentai_core.config import settings
from pentai_core.database import transaction

MIGRATIONS_DIR = Path(__file__).resolve().parents[4] / "migrations"
MIGRATION_NAME = re.compile(r"^(?P<version>\d{4})_[a-z0-9_]+\.sql$")


def migrate(database_path: Path = settings.database_path) -> list[str]:
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
        for migration_path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            match = MIGRATION_NAME.match(migration_path.name)
            if not match:
                continue
            version = match.group("version")
            if version in applied:
                continue
            connection.executescript(migration_path.read_text(encoding="utf-8"))
            connection.execute(
                "INSERT INTO schema_migrations(version) VALUES (?)",
                (version,),
            )
            applied_now.append(version)
    return applied_now


if __name__ == "__main__":
    versions = migrate()
    print(f"Applied migrations: {', '.join(versions) if versions else 'none'}")
