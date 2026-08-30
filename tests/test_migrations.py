from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from pentai_core.migrate import MigrationIntegrityError, migrate


class MigrationTests(unittest.TestCase):
    def test_initial_migration_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pentai.db"
            self.assertEqual(
                migrate(database),
                [
                    "0001",
                    "0002",
                    "0003",
                    "0004",
                    "0005",
                    "0006",
                    "0007",
                    "0008",
                    "0009",
                    "0010",
                    "0011",
                    "0012",
                    "0013",
                    "0014",
                    "0015",
                    "0016",
                    "0017",
                    "0018",
                    "0019",
                    "0020",
                    "0021",
                    "0022",
                    "0023",
                    "0024",
                    "0025",
                    "0026",
                    "0027",
                    "0028",
                    "0029",
                    "0030",
                    "0031",
                    "0032",
                    "0033",
                    "0034",
                    "0035",
                    "0036",
                    "0037",
                    "0038",
                    "0039",
                    "0040",
                    "0041",
                    "0042",
                    "0043",
                    "0044",
                    "0045",
                    "0046",
                    "0047",
                    "0048",
                    "0049",
                    "0050",
                    "0051",
                    "0052",
                    "0053",
                    "0054",
                    "0055",
                    "0056",
                    "0057",
                    "0058",
                    "0059",
                    "0060",
                    "0061",
                    "0062",
                    "0063",
                    "0064",
                    "0065",
                    "0066",
                    "0067",
                    "0068",
                    "0069",
                    "0070",
                    "0071",
                    "0072",
                    "0073",
                    "0074",
                    "0075",
                    "0076",
                    "0077",
                    "0078",
                    "0079",
                    "0080",
                    "0081",
                    "0082",
                    "0083",
                    "0084",
                    "0085",
                    "0086",
                    "0087",
                    "0088",
                ],
            )
            self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection, connection:
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
                    "action_intents",
                    "action_grants",
                    "safety_state",
                    "audit_events",
                    "outbox",
                    "network_attestations",
                    "destination_authorizations",
                    "budget_accounts",
                    "budget_reservations",
                    "gateway_sessions",
                    "gateway_runtime_instances",
                    "gateway_request_starts",
                    "gateway_request_results",
                    "gateway_fixture_execution_claims",
                    "assessment_workflows",
                    "workflow_tasks",
                    "workflow_task_lifecycles",
                    "workflow_task_checkpoints",
                    "workflow_task_receipts",
                    "execution_traces",
                    "evidence_objects",
                    "evidence_custody_events",
                    "evidence_derivatives",
                    "evidence_derivative_events",
                    "evidence_deletions",
                    "network_profile_proposals",
                    "network_profiles",
                    "report_drafts",
                    "report_draft_artifacts",
                    "assessment_coverage",
                    "no_findings_report_drafts",
                    "no_findings_report_artifacts",
                    "report_export_approvals",
                    "report_file_exports",
                    "worker_runtime_instances",
                    "worker_network_attachments",
                    "worker_attachment_recoveries",
                    "worker_fixture_executions",
                    "orchestration_plans",
                    "orchestration_tasks",
                    "orchestration_dependencies",
                    "orchestration_commands",
                    "agent_action_intent_links",
                    "task_capability_manifests",
                    "orchestration_budget_accounts",
                    "orchestration_task_budget_reservations",
                    "orchestration_task_approval_consumptions",
                    "orchestration_task_lease_fences",
                    "orchestration_task_leases",
                    "orchestration_task_lease_events",
                    "orchestration_task_lease_consumptions",
                    "orchestration_task_checkpoints",
                    "orchestration_task_checkpoints_v3",
                    "orchestration_task_failures_v3",
                    "orchestration_retry_failed_attempts_v3",
                    "orchestration_terminal_dispositions",
                    "orchestration_task_completions_v3",
                    "orchestration_provider_usage_measurements_v1",
                    "ai_provider_configuration_snapshots_v1",
                    "ai_provider_registry_snapshots_v1",
                    "ai_provider_registry_snapshot_productions_v1",
                    "ai_provider_configuration_snapshot_productions_v1",
                    "ai_runtime_meter_identities_v1",
                    "orchestration_retry_budget_consumptions",
                    "orchestration_retry_attempts",
                    "orchestration_retry_schedules",
                    "orchestration_retry_activations",
                }
                <= tables
            )
            with closing(sqlite3.connect(database)) as connection:
                manifest_columns = {
                    row[1]: row[4]
                    for row in connection.execute(
                        "PRAGMA table_info(task_capability_manifests)"
                    )
                }
                reservation_columns = {
                    row[1]: row[4]
                    for row in connection.execute(
                        "PRAGMA table_info(orchestration_task_budget_reservations)"
                    )
                }
                lease_columns = {
                    row[1]: row[4]
                    for row in connection.execute(
                        "PRAGMA table_info(orchestration_task_leases)"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertEqual(manifest_columns["task_state"], "'running'")
            self.assertEqual(reservation_columns["task_state"], "'running'")
            self.assertIn("retry_activation_id", manifest_columns)
            self.assertIn("retry_attempt_id", manifest_columns)
            self.assertIn("retry_budget_consumption_id", manifest_columns)
            self.assertIn("capability_manifest_digest", reservation_columns)
            self.assertIn("retry_activation_id", reservation_columns)
            self.assertIn("retry_attempt_id", reservation_columns)
            self.assertIn("retry_budget_consumption_id", reservation_columns)
            self.assertIn("task_capability_manifest_state_immutable", triggers)
            self.assertIn("orchestration_task_budget_state_immutable", triggers)
            self.assertIn("orchestration_retry_budget_reservation_binding_valid", triggers)
            self.assertIn("orchestration_retry_budget_reservation_fields_immutable", triggers)
            self.assertIn("capability_manifest_digest", lease_columns)
            self.assertIn("budget_request_digest", lease_columns)
            self.assertIn("retry_activation_id", lease_columns)
            self.assertIn("retry_attempt_id", lease_columns)
            self.assertIn("retry_budget_consumption_id", lease_columns)
            self.assertIn("orchestration_retry_task_lease_binding_valid", triggers)
            self.assertIn("orchestration_retry_task_lease_fields_immutable", triggers)
            self.assertIn("orchestration_retry_budget_consumptions_v2", tables)
            self.assertIn("orchestration_retry_budget_consumptions_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_budget_consumptions_v2_immutable", triggers)
            self.assertIn("orchestration_retry_budget_consumptions_v2_no_delete", triggers)

    def test_retry_attempt_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0062_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0062_retry_attempts_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0062"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_attempts_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_attempts_v2_immutable", triggers)
            self.assertIn("orchestration_retry_attempts_v2_no_delete", triggers)

    def test_retry_schedule_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0063_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0063_retry_schedules_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0063"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_schedules_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_schedules_v2_immutable", triggers)
            self.assertIn("orchestration_retry_schedules_v2_no_delete", triggers)

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

            with closing(sqlite3.connect(database)) as connection, connection:
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

    def test_opt_in_table_rebuild_preserves_rows_references_indexes_and_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "0001_valid.sql").write_text(
                """
                CREATE TABLE tasks(id INTEGER PRIMARY KEY,state TEXT NOT NULL
                  CHECK(state IN ('failed')));
                CREATE TABLE children(id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL
                  REFERENCES tasks(id));
                CREATE INDEX children_task_id ON children(task_id);
                CREATE TRIGGER children_task_valid BEFORE INSERT ON children
                WHEN NOT EXISTS(SELECT 1 FROM tasks WHERE id=NEW.task_id)
                BEGIN SELECT RAISE(ABORT,'missing task'); END;
                INSERT INTO tasks VALUES (1,'failed');
                INSERT INTO children VALUES (1,1);
                """,
                encoding="utf-8",
            )
            (migrations / "0002_tasks_table_rebuild.sql").write_text(
                """-- pentai: table-rebuild
                ALTER TABLE tasks RENAME TO tasks_old;
                CREATE TABLE tasks(id INTEGER PRIMARY KEY,state TEXT NOT NULL
                  CHECK(state IN ('failed','dead_letter')));
                INSERT INTO tasks SELECT * FROM tasks_old;
                DROP TABLE tasks_old;
                """,
                encoding="utf-8",
            )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0001", "0002"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("PRAGMA foreign_keys=ON")
                self.assertEqual(
                    connection.execute("SELECT * FROM tasks").fetchall(), [(1, "failed")]
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                child_fk = connection.execute("PRAGMA foreign_key_list(children)").fetchone()
                self.assertEqual(child_fk[2], "tasks")
                objects = {
                    (row[0], row[1])
                    for row in connection.execute(
                        "SELECT type,name FROM sqlite_master WHERE name IN "
                        "('children_task_id','children_task_valid')"
                    )
                }
                self.assertEqual(
                    objects,
                    {("index", "children_task_id"), ("trigger", "children_task_valid")},
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("INSERT INTO children VALUES (2,99)")

    def test_table_rebuild_integrity_failure_rolls_back_and_restores_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "0001_valid.sql").write_text(
                """
                CREATE TABLE parents(id INTEGER PRIMARY KEY);
                CREATE TABLE children(id INTEGER PRIMARY KEY,parent_id INTEGER NOT NULL
                  REFERENCES parents(id));
                INSERT INTO parents VALUES (1);
                """,
                encoding="utf-8",
            )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0001"])
            (migrations / "0002_children_table_rebuild.sql").write_text(
                """-- pentai: table-rebuild
                INSERT INTO children VALUES (1,999);
                """,
                encoding="utf-8",
            )
            with (
                patch("pentai_core.migrate.MIGRATIONS_DIR", migrations),
                self.assertRaises(MigrationIntegrityError),
            ):
                migrate(database)
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("PRAGMA foreign_keys=ON")
                self.assertEqual(connection.execute("SELECT * FROM children").fetchall(), [])
                self.assertEqual(
                    connection.execute("SELECT version FROM schema_migrations").fetchall(),
                    [("0001",)],
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("INSERT INTO children VALUES (1,999)")

    def test_table_rebuild_rejects_controls_and_interrupted_sql_without_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "0001_valid.sql").write_text(
                "CREATE TABLE stable(id INTEGER PRIMARY KEY); INSERT INTO stable VALUES(1);",
                encoding="utf-8",
            )
            rebuild = migrations / "0002_stable_table_rebuild.sql"
            rebuild.write_text(
                """-- pentai: table-rebuild
                PRAGMA foreign_keys=OFF;
                """,
                encoding="utf-8",
            )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                with self.assertRaises(MigrationIntegrityError):
                    migrate(database)
            rebuild.write_text(
                """-- pentai: table-rebuild
                CREATE TABLE interrupted(id INTEGER PRIMARY KEY);
                THIS IS NOT VALID SQL;
                """,
                encoding="utf-8",
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                with self.assertRaises(sqlite3.OperationalError):
                    migrate(database)
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(connection.execute("SELECT * FROM stable").fetchall(), [(1,)])
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='interrupted'"
                    ).fetchone()
                )
                self.assertEqual(
                    connection.execute("SELECT version FROM schema_migrations").fetchall(),
                    [("0001",)],
                )

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

            with closing(sqlite3.connect(database)) as connection, connection:
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
            with closing(sqlite3.connect(database)) as connection, connection:
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
            with closing(sqlite3.connect(database)) as connection, connection:
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
            with closing(sqlite3.connect(database)) as connection, connection:
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
            with closing(sqlite3.connect(database)) as connection, connection:
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
            with closing(sqlite3.connect(database)) as connection, connection:
                row = connection.execute(
                    "SELECT version_number, validation_status FROM manifest_versions"
                ).fetchone()
                self.assertEqual(row, (1, "legacy_unverified"))
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE manifest_versions SET document_json = '{}' WHERE id = 'm'"
                    )

    def test_network_profile_upgrade_is_additive_and_history_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0012_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0012_network_profiles.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0012"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection, connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertIn("network_profile_proposals", tables)
            self.assertIn("network_profiles", tables)
            self.assertIn("network_profiles_no_delete", triggers)

    def test_redirect_lineage_upgrade_is_additive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0013_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0013_destination_redirect_lineage.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0013"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                columns = {
                    row[1]: row[4]
                    for row in connection.execute(
                        "PRAGMA table_info(destination_authorizations)"
                    )
                }
                indexes = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA index_list(destination_authorizations)"
                    )
                }
            self.assertIn("parent_authorization_id", columns)
            self.assertEqual(columns["redirect_count"], "0")
            self.assertIn("destination_authorizations_one_child", indexes)

    def test_gateway_rate_reservation_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0014_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0014_gateway_rate_reservations.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0014"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertIn("gateway_rate_buckets", tables)
            self.assertIn("gateway_rate_reservations", tables)
            self.assertIn("gateway_rate_reservations_no_delete", triggers)

    def test_gateway_request_start_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0015_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0015_gateway_request_starts.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0015"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(gateway_request_starts)"
                    )
                }
            self.assertIn("deadline_at", columns)
            self.assertIn("gateway_request_starts_no_delete", triggers)

    def test_gateway_request_result_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0016_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0016_gateway_request_results.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0016"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(gateway_request_results)"
                    )
                }
            self.assertIn("observed_response_bytes", columns)
            self.assertIn("gateway_request_results_immutable", triggers)
            self.assertIn("gateway_request_results_no_delete", triggers)

    def test_gateway_fixture_claim_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0017_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0017_gateway_fixture_execution_claims.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0017"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(gateway_fixture_execution_claims)"
                    )
                }
            self.assertIn("containment_attestation_id", columns)
            self.assertIn("gateway_fixture_execution_claims_identity_immutable", triggers)
            self.assertIn("gateway_fixture_execution_claims_status_transition", triggers)
            self.assertIn("gateway_fixture_execution_claims_no_delete", triggers)

    def test_assessment_workflow_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0018_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0018_assessment_workflows.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0018"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                indexes = {
                    row[1]
                    for row in connection.execute("PRAGMA index_list(workflow_tasks)")
                }
            self.assertIn("workflow_tasks_by_state", indexes)
            self.assertIn("assessment_workflows_identity_immutable", triggers)
            self.assertIn("assessment_workflows_transition", triggers)
            self.assertIn("assessment_workflows_no_delete", triggers)
            self.assertIn("workflow_tasks_identity_immutable", triggers)
            self.assertIn("workflow_tasks_transition", triggers)
            self.assertIn("workflow_tasks_no_delete", triggers)

    def test_workflow_task_lease_upgrade_backfills_and_protects_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0019_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                connection.execute(
                    """INSERT INTO assessment_workflows(
                        workflow_id, engagement_id, policy_bundle_id, idempotency_key,
                        status, version, created_at, updated_at, execution_enabled
                    ) VALUES ('w', 'e', 'p', 'workflow-upgrade-key-01', 'ready', 1,
                              '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z', 0)"""
                )
                connection.execute(
                    """INSERT INTO workflow_tasks(
                        task_id, workflow_id, task_kind, state, idempotency_key,
                        input_refs_json, created_at, dispatch_enabled,
                        external_effect_enabled
                    ) VALUES ('t', 'w', 'manual_checkpoint', 'queued',
                              'task-upgrade-key-0001', '[]',
                              '2026-08-11T00:00:00Z', 0, 0)"""
                )

            migration = repository_migrations / "0019_workflow_task_leases.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0019"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                lifecycle = connection.execute(
                    """SELECT state, version, attempt_count, max_attempts,
                              dispatch_enabled, external_effect_enabled
                    FROM workflow_task_lifecycles WHERE task_id = 't'"""
                ).fetchone()
            self.assertEqual(lifecycle, ("queued", 1, 0, 3, 0, 0))
            self.assertIn("workflow_task_lifecycles_version_fenced", triggers)
            self.assertIn("workflow_task_lifecycles_no_delete", triggers)
            self.assertIn("workflow_task_checkpoints_immutable", triggers)
            self.assertIn("workflow_task_receipts_immutable", triggers)

    def test_audit_trace_upgrade_is_additive_and_protects_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0020_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0020_audit_execution_traces.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0020"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertIn("execution_traces", tables)
            self.assertIn("audit_events_immutable", triggers)
            self.assertIn("audit_events_no_delete", triggers)
            self.assertIn("audit_events_chain_guard", triggers)
            self.assertIn("execution_traces_immutable", triggers)
            self.assertIn("execution_traces_no_delete", triggers)

    def test_worker_runtime_registry_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0030_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0030_worker_runtime_registry.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0030"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                indexes = {
                    row[1]
                    for row in connection.execute("PRAGMA index_list(worker_runtime_instances)")
                }
            self.assertIn("worker_runtime_active_identity", indexes)
            self.assertIn("worker_runtime_identity_immutable", triggers)
            self.assertIn("worker_runtime_container_once", triggers)
            self.assertIn("worker_runtime_version_fenced", triggers)
            self.assertIn("worker_runtime_status_transition", triggers)
            self.assertIn("worker_runtime_no_delete", triggers)

    def test_worker_attachment_registry_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0031_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0031_worker_network_attachments.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0031"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                indexes = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA index_list(worker_network_attachments)"
                    )
                }
            self.assertIn("worker_network_attachment_recovery_queue", indexes)
            self.assertIn("worker_network_attachment_identity_immutable", triggers)
            self.assertIn("worker_network_attachment_version_fenced", triggers)
            self.assertIn("worker_network_attachment_status_transition", triggers)
            self.assertIn("worker_network_attachment_transition_required", triggers)
            self.assertIn("worker_network_attachment_no_delete", triggers)

    def test_worker_attachment_recovery_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0032_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0032_worker_attachment_recoveries.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0032"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertIn("worker_attachment_recovery_immutable", triggers)
            self.assertIn("worker_attachment_recovery_no_delete", triggers)

    def test_worker_fixture_execution_upgrade_is_additive_and_protected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0033_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0033_worker_fixture_executions.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0033"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
            self.assertIn("worker_fixture_execution_identity_immutable", triggers)
            self.assertIn("worker_fixture_execution_status_transition", triggers)
            self.assertIn("worker_fixture_execution_no_delete", triggers)

    def test_retry_policy_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0059_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)

            migration = repository_migrations / "0059_retry_policy_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0059"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_policies_v2", tables)
            self.assertIn("orchestration_retry_policies_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_policies_v2_immutable", triggers)
            self.assertIn("orchestration_retry_policies_v2_no_delete", triggers)

    def test_retry_decision_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0060_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0060_retry_decisions_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0060"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_decisions_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_decisions_v2_immutable", triggers)
            self.assertIn("orchestration_retry_decisions_v2_no_delete", triggers)

    def test_retry_budget_consumption_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0061_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0061_retry_budget_consumptions_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0061"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_budget_consumptions_v2", tables)
            self.assertIn(
                "orchestration_retry_budget_consumptions_v2_binding_valid", triggers
            )
            self.assertIn("orchestration_retry_budget_consumptions_v2_immutable", triggers)
            self.assertIn("orchestration_retry_budget_consumptions_v2_no_delete", triggers)

    def test_retry_activation_v2_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0064_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0064_retry_activations_v2.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0064"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_activations_v2", tables)
            self.assertIn("orchestration_retry_activations_v2_binding_valid", triggers)
            self.assertIn("orchestration_retry_activations_v2_immutable", triggers)
            self.assertIn("orchestration_retry_activations_v2_no_delete", triggers)

    def test_attempt_three_manifest_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0065_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0065_attempt_three_capability_manifests.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0065"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("task_capability_manifests_v4", tables)
            self.assertIn("task_capability_manifests_v4_binding_valid", triggers)
            self.assertIn("task_capability_manifests_v4_immutable", triggers)
            self.assertIn("task_capability_manifests_v4_no_delete", triggers)

    def test_attempt_three_budget_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0066_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0066_attempt_three_budget_reservations.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0066"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_task_budget_reservations_v4", tables)
            self.assertIn("orchestration_task_budget_reservations_v4_binding_valid", triggers)
            self.assertIn(
                "orchestration_task_budget_reservations_v4_immutable_identity", triggers
            )
            self.assertIn("orchestration_task_budget_reservations_v4_no_delete", triggers)

    def test_attempt_three_lease_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0067_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0067_attempt_three_task_leases.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0067"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_task_leases_v3", tables)
            self.assertIn("orchestration_task_lease_events_v3", tables)
            self.assertIn("orchestration_task_leases_v3_binding_valid", triggers)
            self.assertIn("orchestration_task_leases_v3_identity_immutable", triggers)
            self.assertIn("orchestration_task_leases_v3_no_delete", triggers)

    def test_attempt_three_lease_consumption_upgrade_is_additive_and_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0068_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0068_attempt_three_lease_consumptions.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0068"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_task_lease_consumptions_v3", tables)
            self.assertIn(
                "orchestration_task_lease_consumptions_v3_binding_valid", triggers
            )
            self.assertIn("orchestration_task_lease_consumptions_v3_immutable", triggers)
            self.assertIn("orchestration_task_lease_consumptions_v3_no_delete", triggers)

    def test_attempt_three_checkpoint_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0069_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0069_attempt_three_task_checkpoints.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0069"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_task_checkpoints_v3", tables)
            self.assertIn("orchestration_task_checkpoints_v3_binding_valid", triggers)
            self.assertIn("orchestration_task_checkpoints_v3_immutable", triggers)
            self.assertIn("orchestration_task_checkpoints_v3_no_delete", triggers)

    def test_attempt_three_failure_upgrade_is_additive_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
            for path in sorted(repository_migrations.glob("*.sql")):
                if path.name >= "0070_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0070_attempt_three_task_failures.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0070"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_task_failures_v3", tables)
            self.assertIn("orchestration_task_failures_v3_binding_valid", triggers)
            self.assertIn("orchestration_task_failures_v3_immutable", triggers)
            self.assertIn("orchestration_task_failures_v3_no_delete", triggers)

    def test_attempt_three_failed_attempt_migration_upgrades_additively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0071_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0071_attempt_three_failed_attempts.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0071"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_retry_failed_attempts_v3", tables)
            self.assertIn("orchestration_retry_failed_attempts_v3_binding_valid", triggers)
            self.assertIn("orchestration_retry_failed_attempts_v3_immutable", triggers)
            self.assertIn("orchestration_retry_failed_attempts_v3_no_delete", triggers)

    def test_terminal_disposition_migration_upgrades_additively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0072_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0072_terminal_dispositions.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0072"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
            self.assertIn("orchestration_terminal_dispositions", tables)
            self.assertIn("orchestration_terminal_dispositions_binding_valid", triggers)
            self.assertIn("orchestration_terminal_dispositions_immutable", triggers)
            self.assertIn("orchestration_terminal_dispositions_no_delete", triggers)

    def test_terminal_consumption_prerequisite_upgrades_additively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0073_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0073_terminal_consumption_prerequisite.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0073"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                task_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='orchestration_tasks'"
                ).fetchone()[0]
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertIn("orchestration_terminal_consumptions", tables)
            self.assertIn("orchestration_terminal_consumptions_binding_valid", triggers)
            self.assertIn("orchestration_terminal_consumptions_producer_disabled", triggers)
            self.assertIn("orchestration_terminal_consumptions_immutable", triggers)
            self.assertIn("orchestration_terminal_consumptions_no_delete", triggers)
            self.assertNotIn("dead_letter", task_sql)

    def test_attempt_three_completion_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0077_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0077_attempt_three_completion_prerequisite.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0077"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                table = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='orchestration_task_completions_v3'"
                ).fetchone()
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                task_trigger = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' "
                    "AND name='orchestration_tasks_version_fenced'"
                ).fetchone()[0]
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM orchestration_task_completions_v3"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "completion producer is disabled"
                ):
                    connection.execute(
                        """INSERT INTO orchestration_task_completions_v3 VALUES
                        ('00000000-0000-4000-8000-000000000001',
                         '00000000-0000-4000-8000-000000000002',
                         ?, '00000000-0000-4000-8000-000000000003',
                         '00000000-0000-4000-8000-000000000004', 7, 8,
                         '00000000-0000-4000-8000-000000000005', 7, 8,
                         '00000000-0000-4000-8000-000000000006',
                         '00000000-0000-4000-8000-000000000007', NULL,
                         '{}', ?, '2026-08-29T12:00:00Z', 'none', 0)""",
                        ("sha256:" + "a" * 64, "b" * 64),
                    )
            self.assertIsNotNone(table)
            self.assertIn("orchestration_task_completions_v3_binding_valid", triggers)
            self.assertIn("orchestration_task_completions_v3_producer_disabled", triggers)
            self.assertIn("orchestration_task_completions_v3_immutable", triggers)
            self.assertIn("orchestration_task_completions_v3_no_delete", triggers)
            self.assertIn("NEW.state IN ('cancelling','succeeded')", task_trigger)

    def test_attempt_three_completion_consumer_upgrades_additively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0078_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0078_attempt_three_completion_consumption.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0078"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertNotIn(
                "orchestration_task_completions_v3_producer_disabled", triggers
            )
            self.assertIn(
                "orchestration_task_completions_v3_current_binding", triggers
            )
            self.assertIn(
                "orchestration_attempt_three_completion_required", triggers
            )
            self.assertIn("orchestration_task_completions_v3_immutable", triggers)
            self.assertIn("orchestration_task_completions_v3_no_delete", triggers)

    def test_attempt_three_provider_usage_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0079_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations
                / "0079_attempt_three_provider_usage_prerequisite.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0079"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM orchestration_provider_usage_measurements_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "provider usage producer is disabled"
                ):
                    connection.execute(
                        """INSERT INTO orchestration_provider_usage_measurements_v1(
                        measurement_id,completion_id,completion_digest,assessment_id,
                        plan_id,plan_revision,task_id,task_revision,retry_attempt_id,
                        budget_reservation_id,budget_account_id,budget_account_version,
                        measurement_json,measurement_digest,recorded_at,authority,
                        execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "00000000-0000-4000-8000-000000000002",
                            "sha256:" + "a" * 64,
                            "00000000-0000-4000-8000-000000000003",
                            "00000000-0000-4000-8000-000000000004",
                            8,
                            "00000000-0000-4000-8000-000000000005",
                            8,
                            "00000000-0000-4000-8000-000000000006",
                            "00000000-0000-4000-8000-000000000007",
                            "00000000-0000-4000-8000-000000000008",
                            4,
                            "{}",
                            "sha256:" + "b" * 64,
                            "2026-08-29T20:00:01Z",
                        ),
                    )
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn(
                "orchestration_provider_usage_measurements_v1_binding_valid", triggers
            )
            self.assertIn(
                "orchestration_provider_usage_measurements_v1_producer_disabled", triggers
            )
            self.assertIn(
                "orchestration_provider_usage_measurements_v1_immutable", triggers
            )
            self.assertIn(
                "orchestration_provider_usage_measurements_v1_no_delete", triggers
            )

    def test_provider_configuration_snapshot_prerequisite_is_additive_and_inert(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0080_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations
                / "0080_provider_configuration_snapshot_prerequisite.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0080"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_configuration_snapshots_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "provider configuration snapshot producer is disabled",
                ):
                    connection.execute(
                        """INSERT INTO ai_provider_configuration_snapshots_v1(
                        snapshot_id,configuration_id,configuration_hash,registry_id,
                        registry_revision,provider_type,provider_id,model_id,snapshot_json,
                        snapshot_digest,recorded_at,state,meter_binding_enabled,authority,
                        execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,'inactive',0,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "00000000-0000-4000-8000-000000000002",
                            "a" * 64,
                            "00000000-0000-4000-8000-000000000003",
                            1,
                            "approved_remote",
                            "synthetic-remote",
                            "synthetic-model-v1",
                            "{}",
                            "sha256:" + "b" * 64,
                            "2026-08-29T20:00:01Z",
                        ),
                    )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn(
                "ai_provider_configuration_snapshots_v1_binding_valid", triggers
            )
            self.assertIn(
                "ai_provider_configuration_snapshots_v1_producer_disabled", triggers
            )
            self.assertIn("ai_provider_configuration_snapshots_v1_immutable", triggers)
            self.assertIn("ai_provider_configuration_snapshots_v1_no_delete", triggers)

    def test_provider_registry_snapshot_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0081_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0081_provider_registry_snapshot_prerequisite.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0081"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_registry_snapshots_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "provider registry snapshot producer is disabled",
                ):
                    connection.execute(
                        """INSERT INTO ai_provider_registry_snapshots_v1(
                        snapshot_id,registry_id,registry_revision,registry_digest,
                        providers_digest,snapshot_json,snapshot_digest,recorded_at,state,
                        activation_enabled,revocation_enabled,authority,execution_enabled)
                        VALUES (?,?,?,?,?,?,?,?,'inactive',0,0,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "00000000-0000-4000-8000-000000000002",
                            1,
                            "sha256:" + "a" * 64,
                            "sha256:" + "b" * 64,
                            "{}",
                            "sha256:" + "c" * 64,
                            "2026-08-29T20:00:01Z",
                        ),
                    )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn("ai_provider_registry_snapshots_v1_binding_valid", triggers)
            self.assertIn("ai_provider_registry_snapshots_v1_producer_disabled", triggers)
            self.assertIn("ai_provider_registry_snapshots_v1_immutable", triggers)
            self.assertIn("ai_provider_registry_snapshots_v1_no_delete", triggers)

    def test_provider_registry_production_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0082_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations
                / "0082_provider_registry_snapshot_production_prerequisite.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0082"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_registry_snapshot_productions_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "provider registry snapshot production is disabled",
                ):
                    connection.execute(
                        """INSERT INTO ai_provider_registry_snapshot_productions_v1(
                        command_id,command_digest,snapshot_id,registry_id,registry_revision,
                        registry_digest,providers_digest,actor_id,session_id,command_json,
                        receipt_json,receipt_digest,recorded_at,production_enabled,authority,
                        execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "sha256:" + "a" * 64,
                            "00000000-0000-4000-8000-000000000002",
                            "00000000-0000-4000-8000-000000000003",
                            1,
                            "sha256:" + "b" * 64,
                            "sha256:" + "c" * 64,
                            "local-desktop-session",
                            "00000000-0000-4000-8000-000000000004",
                            "{}",
                            "{}",
                            "sha256:" + "d" * 64,
                            "2026-08-29T21:30:01Z",
                        ),
                    )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_binding_valid", triggers
            )
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_producer_disabled", triggers
            )
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_immutable", triggers
            )
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_no_delete", triggers
            )

    def test_provider_registry_snapshot_production_migration_is_additive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0083_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations / "0083_provider_registry_snapshot_production.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0083"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_registry_snapshots_v1"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_registry_snapshot_productions_v1"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertNotIn(
                "ai_provider_registry_snapshots_v1_producer_disabled", triggers
            )
            self.assertNotIn(
                "ai_provider_registry_snapshot_productions_v1_producer_disabled", triggers
            )
            self.assertIn(
                "ai_provider_registry_snapshots_v1_production_required", triggers
            )
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_current_binding", triggers
            )
            self.assertIn("ai_provider_registry_snapshots_v1_immutable", triggers)
            self.assertIn(
                "ai_provider_registry_snapshot_productions_v1_immutable", triggers
            )

    def test_provider_registry_activation_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0084_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0084_provider_registry_activation_prerequisite.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0084"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_registry_activations_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "provider registry activation producer is disabled",
                ):
                    connection.execute(
                        """INSERT INTO ai_provider_registry_activations_v1(
                        activation_id,receipt_digest,command_id,command_digest,
                        snapshot_id,snapshot_digest,snapshot_receipt_digest,registry_id,
                        registry_revision,registry_digest,providers_digest,actor_id,
                        session_id,command_json,receipt_json,activated_at,expires_at,state,
                        configuration_snapshot_enabled,revocation_enabled,authority,
                        execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                        'active',0,0,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "sha256:" + "a" * 64,
                            "00000000-0000-4000-8000-000000000002",
                            "sha256:" + "b" * 64,
                            "00000000-0000-4000-8000-000000000003",
                            "sha256:" + "c" * 64,
                            "sha256:" + "d" * 64,
                            "00000000-0000-4000-8000-000000000004",
                            1,
                            "sha256:" + "e" * 64,
                            "sha256:" + "f" * 64,
                            "test-session",
                            "00000000-0000-4000-8000-000000000005",
                            "{}",
                            "{}",
                            "2026-08-30T10:00:01Z",
                            "2026-09-13T10:00:00Z",
                        ),
                    )
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn("ai_provider_registry_activations_v1_binding_valid", triggers)
            self.assertIn("ai_provider_registry_activations_v1_producer_disabled", triggers)
            self.assertIn("ai_provider_registry_activations_v1_immutable", triggers)
            self.assertIn("ai_provider_registry_activations_v1_no_delete", triggers)

    def test_provider_registry_activation_migration_is_additive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0085_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0085_provider_registry_activation.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0085"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertNotIn("ai_provider_registry_activations_v1_producer_disabled", triggers)
            self.assertIn("ai_provider_registry_activations_v1_current_binding", triggers)
            self.assertIn("ai_provider_registry_activations_v1_binding_valid", triggers)
            self.assertIn("ai_provider_registry_activations_v1_immutable", triggers)
            self.assertIn("ai_provider_registry_activations_v1_no_delete", triggers)

    def test_provider_configuration_production_prerequisite_is_additive_and_inert(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0086_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations
                / "0086_provider_configuration_snapshot_production_prerequisite.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0086"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM "
                        "ai_provider_configuration_snapshot_productions_v1"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "provider configuration snapshot production is disabled",
                ):
                    connection.execute(
                        """INSERT INTO ai_provider_configuration_snapshot_productions_v1(
                        command_id,command_digest,snapshot_id,snapshot_digest,
                        configuration_id,configuration_hash,activation_id,
                        activation_receipt_digest,registry_snapshot_id,
                        registry_snapshot_digest,registry_snapshot_receipt_digest,
                        registry_id,registry_revision,registry_digest,providers_digest,
                        provider_type,provider_id,model_id,secret_reference_digest,
                        actor_id,session_id,command_json,receipt_json,receipt_digest,
                        recorded_at,production_enabled,authority,execution_enabled)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'none',0)""",
                        (
                            "00000000-0000-4000-8000-000000000001",
                            "sha256:" + "a" * 64,
                            "00000000-0000-4000-8000-000000000002",
                            "sha256:" + "b" * 64,
                            "00000000-0000-4000-8000-000000000003",
                            "c" * 64,
                            "00000000-0000-4000-8000-000000000004",
                            "sha256:" + "d" * 64,
                            "00000000-0000-4000-8000-000000000005",
                            "sha256:" + "e" * 64,
                            "sha256:" + "f" * 64,
                            "00000000-0000-4000-8000-000000000006",
                            1,
                            "sha256:" + "1" * 64,
                            "sha256:" + "2" * 64,
                            "approved_remote",
                            "synthetic-remote",
                            "synthetic-model-v1",
                            "sha256:" + "3" * 64,
                            "local-desktop-session",
                            "00000000-0000-4000-8000-000000000007",
                            "{}",
                            "{}",
                            "sha256:" + "4" * 64,
                            "2026-08-30T11:00:01Z",
                        ),
                    )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_key_check").fetchall(), []
                )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_binding_valid",
                triggers,
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_producer_disabled",
                triggers,
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_immutable", triggers
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_no_delete", triggers
            )

    def test_provider_configuration_producer_activation_is_additive_and_guarded(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0087_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = (
                repository_migrations
                / "0087_provider_configuration_snapshot_production.sql"
            )
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0087"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_provider_configuration_snapshots_v1"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_key_check").fetchall(), []
                )
            self.assertNotIn(
                "ai_provider_configuration_snapshot_productions_v1_producer_disabled",
                triggers,
            )
            self.assertNotIn(
                "ai_provider_configuration_snapshots_v1_producer_disabled", triggers
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_current_binding",
                triggers,
            )
            self.assertIn(
                "ai_provider_configuration_snapshots_v1_production_required", triggers
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_immutable", triggers
            )
            self.assertIn(
                "ai_provider_configuration_snapshot_productions_v1_no_delete", triggers
            )
            self.assertIn("ai_provider_configuration_snapshots_v1_immutable", triggers)
            self.assertIn("ai_provider_configuration_snapshots_v1_no_delete", triggers)

    def test_orchestration_task_state_rebuild_preserves_authoritative_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0074_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            states = (
                "blocked",
                "awaiting_human",
                "ready",
                "running",
                "cancelling",
                "cancelled",
                "succeeded",
                "failed",
            )
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    """INSERT INTO orchestration_plans(
                    plan_id,assessment_id,idempotency_key,creation_digest,revision,state,
                    created_at,updated_at,authority,execution_enabled)
                    VALUES ('plan','assessment','synthetic-plan-key-0001',?,1,'active',
                    '2026-08-29T00:00:00Z','2026-08-29T00:00:00Z','none',0)""",
                    ("sha256:" + "0" * 64,),
                )
                for index, state in enumerate(states, start=1):
                    connection.execute(
                        """INSERT INTO orchestration_tasks(
                        task_id,plan_id,assessment_id,task_type,objective,input_refs_json,
                        requires_human_approval,state,revision,created_at,updated_at,
                        authority,execution_enabled)
                        VALUES (?,?,?,?,?,'[]',0,?,1,?,?, 'none',0)""",
                        (
                            f"task-{index}",
                            "plan",
                            "assessment",
                            "validation",
                            f"synthetic {state}",
                            state,
                            "2026-08-29T00:00:00Z",
                            "2026-08-29T00:00:00Z",
                        ),
                    )
                before_rows = connection.execute(
                    "SELECT * FROM orchestration_tasks ORDER BY task_id"
                ).fetchall()
                before_columns = connection.execute(
                    "PRAGMA table_info(orchestration_tasks)"
                ).fetchall()
                before_foreign_keys = connection.execute(
                    "PRAGMA foreign_key_list(orchestration_tasks)"
                ).fetchall()
                before_indexes = connection.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='orchestration_tasks' ORDER BY name"
                ).fetchall()
                before_triggers = {
                    row[0]: " ".join(row[1].split())
                    for row in connection.execute(
                        "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                        "AND tbl_name='orchestration_tasks' ORDER BY name"
                    )
                }
                before_dependents = {
                    table: tuple(connection.execute(f"PRAGMA foreign_key_list({table})"))
                    for (table,) in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                }
                before_external_triggers = {
                    row[0]: " ".join(row[1].split())
                    for row in connection.execute(
                        "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                        "AND tbl_name!='orchestration_tasks' AND sql LIKE '%orchestration_tasks%'"
                    )
                }

            migration = repository_migrations / "0074_orchestration_tasks_table_rebuild.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0074"])
                self.assertEqual(migrate(database), [])

            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("PRAGMA foreign_keys=ON")
                self.assertEqual(
                    connection.execute(
                        "SELECT * FROM orchestration_tasks ORDER BY task_id"
                    ).fetchall(),
                    before_rows,
                )
                self.assertEqual(
                    connection.execute("PRAGMA table_info(orchestration_tasks)").fetchall(),
                    before_columns,
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_key_list(orchestration_tasks)").fetchall(),
                    before_foreign_keys,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT name,sql FROM sqlite_master WHERE type='index' "
                        "AND tbl_name='orchestration_tasks' ORDER BY name"
                    ).fetchall(),
                    before_indexes,
                )
                after_triggers = {
                    row[0]: " ".join(row[1].split())
                    for row in connection.execute(
                        "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                        "AND tbl_name='orchestration_tasks' ORDER BY name"
                    )
                }
                for name, sql in before_triggers.items():
                    self.assertEqual(after_triggers[name], sql)
                self.assertIn("orchestration_tasks_dead_letter_insert_disabled", after_triggers)
                after_dependents = {
                    table: tuple(connection.execute(f"PRAGMA foreign_key_list({table})"))
                    for (table,) in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                }
                self.assertEqual(after_dependents, before_dependents)
                self.assertEqual(
                    {
                        row[0]: " ".join(row[1].split())
                        for row in connection.execute(
                            "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                            "AND tbl_name!='orchestration_tasks' "
                            "AND sql LIKE '%orchestration_tasks%'"
                        )
                    },
                    before_external_triggers,
                )
                task_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='orchestration_tasks'"
                ).fetchone()[0]
                self.assertIn("'failed', 'dead_letter'", task_sql)
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE orchestration_tasks SET state='dead_letter',revision=2 "
                        "WHERE task_id='task-8'"
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """INSERT INTO orchestration_tasks VALUES(
                        'dead','plan','assessment','validation','synthetic','[]',0,
                        'dead_letter',1,'2026-08-29T00:00:00Z','2026-08-29T00:00:00Z',
                        'none',0)"""
                    )

    def test_runtime_meter_identity_prerequisite_is_additive_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0088_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            migration = repository_migrations / "0088_runtime_meter_identity_prerequisite.sql"
            (migrations / migration.name).write_text(
                migration.read_text(encoding="utf-8"), encoding="utf-8"
            )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0088"])
                self.assertEqual(migrate(database), [])

            meter_id = "00000000-0000-4000-8000-000000000001"
            configuration_snapshot_id = "00000000-0000-4000-8000-000000000002"
            configuration_id = "00000000-0000-4000-8000-000000000003"
            registry_id = "00000000-0000-4000-8000-000000000004"
            containment_id = "00000000-0000-4000-8000-000000000005"
            identity = {
                "schema_version": "1.0.0",
                "meter_id": meter_id,
                "implementation_id": "synthetic-meter",
                "implementation_version": 1,
                "configuration_snapshot_id": configuration_snapshot_id,
                "configuration_snapshot_digest": "sha256:" + "a" * 64,
                "configuration_id": configuration_id,
                "configuration_hash": "b" * 64,
                "registry_id": registry_id,
                "registry_revision": 1,
                "provider_type": "local_runtime",
                "provider_id": "local-synthetic",
                "model_id": "synthetic-local-q4",
                "worker_id": "synthetic-worker",
                "worker_version": 1,
                "runtime_instance_id": "synthetic-runtime",
                "containment_attestation_id": containment_id,
                "image_digest": "sha256:" + "c" * 64,
                "supported_dimensions": ["runtime_seconds"],
                "valid_from": "2026-08-30T17:30:00Z",
                "expires_at": "2026-08-30T17:35:00Z",
                "state": "inactive",
                "measurement_enabled": False,
                "authority": "none",
                "execution_enabled": False,
            }
            receipt = {
                "schema_version": "1.0.0",
                "meter_id": meter_id,
                "meter_identity_digest": "sha256:" + "d" * 64,
                "configuration_snapshot_id": configuration_snapshot_id,
                "configuration_snapshot_digest": "sha256:" + "a" * 64,
                "worker_id": "synthetic-worker",
                "worker_version": 1,
                "implementation_id": "synthetic-meter",
                "implementation_version": 1,
                "recorded_at": "2026-08-30T17:30:01Z",
                "state": "inactive",
                "attestation_enabled": False,
                "measurement_enabled": False,
                "authority": "none",
                "execution_enabled": False,
            }
            with closing(sqlite3.connect(database)) as connection:
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "runtime meter identity production is disabled"
                ):
                    connection.execute(
                        """INSERT INTO ai_runtime_meter_identities_v1(
                        meter_id,meter_identity_digest,configuration_snapshot_id,
                        configuration_snapshot_digest,configuration_id,configuration_hash,
                        registry_id,registry_revision,provider_type,provider_id,model_id,
                        worker_id,worker_version,runtime_instance_id,containment_attestation_id,
                        image_digest,implementation_id,implementation_version,identity_json,
                        receipt_json,receipt_digest,recorded_at,expires_at,state,
                        attestation_enabled,measurement_enabled,authority,execution_enabled)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                        'inactive',0,0,'none',0)""",
                        (
                            meter_id,
                            receipt["meter_identity_digest"],
                            configuration_snapshot_id,
                            identity["configuration_snapshot_digest"],
                            configuration_id,
                            identity["configuration_hash"],
                            registry_id,
                            1,
                            "local_runtime",
                            "local-synthetic",
                            "synthetic-local-q4",
                            "synthetic-worker",
                            1,
                            "synthetic-runtime",
                            containment_id,
                            identity["image_digest"],
                            "synthetic-meter",
                            1,
                            json.dumps(identity, separators=(",", ":"), sort_keys=True),
                            json.dumps(receipt, separators=(",", ":"), sort_keys=True),
                            "sha256:" + "e" * 64,
                            receipt["recorded_at"],
                            identity["expires_at"],
                        ),
                    )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM ai_runtime_meter_identities_v1"
                    ).fetchone(),
                    (0,),
                )
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertIn("ai_runtime_meter_identities_v1_binding_valid", triggers)
            self.assertIn("ai_runtime_meter_identities_v1_producer_disabled", triggers)
            self.assertIn("ai_runtime_meter_identities_v1_immutable", triggers)
            self.assertIn("ai_runtime_meter_identities_v1_no_delete", triggers)

    def test_terminal_prerequisites_upgrade_from_0072_through_registration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrations = root / "migrations"
            migrations.mkdir()
            repository_migrations = Path(__file__).parents[1] / "migrations"
            for path in repository_migrations.glob("*.sql"):
                if path.name >= "0073_":
                    continue
                (migrations / path.name).write_text(
                    path.read_text(encoding="utf-8"), encoding="utf-8"
                )
            database = root / "pentai.db"
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                migrate(database)
            for name in (
                "0073_terminal_consumption_prerequisite.sql",
                "0074_orchestration_tasks_table_rebuild.sql",
                "0075_terminal_consumption.sql",
                "0076_dead_letter_registration.sql",
            ):
                (migrations / name).write_text(
                    (repository_migrations / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            with patch("pentai_core.migrate.MIGRATIONS_DIR", migrations):
                self.assertEqual(migrate(database), ["0073", "0074", "0075", "0076"])
                self.assertEqual(migrate(database), [])
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                task_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='orchestration_tasks'"
                ).fetchone()[0]
                self.assertIn("'dead_letter'", task_sql)
                triggers = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                self.assertNotIn(
                    "orchestration_terminal_consumptions_producer_disabled", triggers
                )
                self.assertIn("orchestration_tasks_dead_letter_insert_disabled", triggers)
                self.assertIn("orchestration_dead_letter_registrations_binding_valid", triggers)
                self.assertIn("orchestration_dead_letter_registrations_immutable", triggers)
                self.assertIn("orchestration_dead_letter_registrations_no_delete", triggers)
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM orchestration_dead_letter_registrations"
                    ).fetchone(),
                    (0,),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """INSERT INTO orchestration_tasks VALUES(
                        'invalid','plan','assessment','validation','synthetic','[]',0,
                        'unknown',1,'2026-08-29T00:00:00Z','2026-08-29T00:00:00Z',
                        'none',0)"""
                    )


if __name__ == "__main__":
    unittest.main()
