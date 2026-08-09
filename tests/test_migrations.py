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
            self.assertEqual(migrate(database), ["0001", "0002", "0003", "0004", "0005", "0006"])
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
                    row[0] for row in connection.execute("SELECT version FROM schema_migrations")
                }
            self.assertIn("stable", tables)
            self.assertNotIn("should_rollback", tables)
            self.assertEqual(versions, {"0001"})

    def test_existing_authorization_database_receives_immutability_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for name in ("0001_initial.sql", "0002_authorization_slice.sql"):
                (migrations / name).write_text(
                    (repository_migrations / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0001", "0002"])

            (migrations / "0003_authorization_immutability.sql").write_text(
                (repository_migrations / "0003_authorization_immutability.sql").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0003"])
                self.assertEqual(migrate(database), [])

            with sqlite3.connect(database) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertTrue(
                {
                    "immutable_active_policy_update",
                    "immutable_approved_manifest_update",
                    "immutable_approval_update",
                    "immutable_approval_delete",
                }
                <= triggers
            )

    def test_existing_rows_receive_compatible_source_provenance_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for name in (
                "0001_initial.sql",
                "0002_authorization_slice.sql",
                "0003_authorization_immutability.sql",
            ):
                (migrations / name).write_text(
                    (repository_migrations / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "INSERT INTO programs(id, name, status) VALUES ('p1', 'fixture', 'draft')"
                )
                connection.execute(
                    """
                    INSERT INTO source_documents(
                        id, program_id, authority, reference, retrieved_at,
                        content_hash, encrypted_blob_ref
                    ) VALUES ('s1', 'p1', 'contract', 'synthetic://legacy',
                              '2026-08-08T00:00:00Z', ?, ?)
                    """,
                    ("a" * 64, "sha256:" + "a" * 64),
                )
            (migrations / "0004_source_provenance.sql").write_text(
                (repository_migrations / "0004_source_provenance.sql").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0004"])
            with sqlite3.connect(database) as connection:
                row = connection.execute(
                    "SELECT source_kind, media_type, source_version FROM source_documents"
                ).fetchone()
            self.assertEqual(row, ("pasted_text", "text/plain", None))

            (migrations / "0005_encrypted_source_blobs.sql").write_text(
                (repository_migrations / "0005_encrypted_source_blobs.sql").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0005"])
            with sqlite3.connect(database) as connection:
                encrypted = connection.execute(
                    """
                    SELECT blob_status, encryption_version, plaintext_size
                    FROM source_documents
                    """
                ).fetchone()
            self.assertEqual(encrypted, ("legacy_missing", None, None))

    def test_manifest_history_upgrade_preserves_rows_and_makes_them_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("000[1-5]_*.sql")):
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "INSERT INTO programs(id, name, status) VALUES ('p', 'p', 'draft')"
                )
                connection.execute(
                    """INSERT INTO engagements(
                        id, program_id, status, effective_from, expires_at, timezone
                    ) VALUES (
                        'e', 'p', 'draft', '2026-01-01T00:00:00Z',
                        '2027-01-01T00:00:00Z', 'UTC'
                    )"""
                )
                connection.execute(
                    """INSERT INTO manifest_versions(id, engagement_id, schema_version,
                    document_json, content_hash) VALUES ('m', 'e', '2.0.0', '{}', ?)""",
                    ("a" * 64,),
                )
            migration = repository_migrations / "0006_manifest_version_history.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0006"])
            with sqlite3.connect(database) as connection:
                row = connection.execute(
                    "SELECT version_number, validation_status FROM manifest_versions"
                ).fetchone()
                self.assertEqual(row, (1, "legacy_unverified"))
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE manifest_versions SET document_json = '{}' WHERE id = 'm'"
                    )


if __name__ == "__main__":
    unittest.main()
