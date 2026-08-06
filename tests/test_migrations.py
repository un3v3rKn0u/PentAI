from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pentai_core.migrate import migrate


class MigrationTests(unittest.TestCase):
    def test_initial_migration_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pentai.db"
            self.assertEqual(migrate(database), ["0001", "0002"])
            self.assertEqual(migrate(database), [])
            with sqlite3.connect(database) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertTrue(
                {
                    "programs",
                    "engagements",
                    "policy_bundles",
                    "approvals",
                    "policy_evaluations",
                    "audit_events",
                    "outbox",
                }
                <= tables
            )

    def test_failed_migration_rolls_back_its_schema_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "0001_valid.sql").write_text(
                "CREATE TABLE stable (id INTEGER PRIMARY KEY);",
                encoding="utf-8",
            )
            (migrations / "0002_broken.sql").write_text(
                """
                CREATE TABLE should_rollback (id INTEGER PRIMARY KEY);
                THIS IS NOT VALID SQL;
                """,
                encoding="utf-8",
            )
            database = root / "pentai.db"

            with (
                patch("pentai_core.migrate.MIGRATIONS_DIR", migrations),
                self.assertRaises(sqlite3.OperationalError),
            ):
                migrate(database)

            with sqlite3.connect(database) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                versions = {
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM schema_migrations"
                    )
                }
            self.assertIn("stable", tables)
            self.assertNotIn("should_rollback", tables)
            self.assertEqual(versions, {"0001"})


if __name__ == "__main__":
    unittest.main()
