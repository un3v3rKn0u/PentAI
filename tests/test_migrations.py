from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from pentai_core.migrate import migrate


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


if __name__ == "__main__":
    unittest.main()
