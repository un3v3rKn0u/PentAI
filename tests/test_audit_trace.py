from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from pentai_core.authorization import AuthorizationService
from pentai_core.config import Settings
from pentai_core.main import create_app
from pentai_core.migrate import migrate


def test_legacy_malformed_audit_chain_denies_startup(tmp_path: Path) -> None:
    repository_migrations = Path(__file__).resolve().parents[1] / "migrations"
    legacy_migrations = tmp_path / "legacy-migrations"
    legacy_migrations.mkdir()
    initial = repository_migrations / "0001_initial.sql"
    (legacy_migrations / initial.name).write_text(
        initial.read_text(encoding="utf-8"), encoding="utf-8"
    )
    database = tmp_path / "audit.db"
    with patch("pentai_core.migrate.MIGRATIONS_DIR", legacy_migrations):
        assert migrate(database) == ["0001"]
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            """INSERT INTO audit_events(
                event_id, occurred_at, actor_type, actor_id, action, subject_type,
                subject_id, data_json, previous_hash, event_hash
            ) VALUES (?, '2026-08-11T00:00:00Z', 'service', 'legacy-fixture',
                      'audit.legacy', 'audit_event', ?, '{malformed', NULL, ?)""",
            (str(uuid4()), str(uuid4()), "a" * 64),
        )

    verification = AuthorizationService(database).verify_audit_chain()
    assert verification["valid"] is False
    assert verification["reason"] == "AUDIT_EVENT_INVALID"
    with pytest.raises(RuntimeError, match="audit ledger verification failed"):
        create_app(
            Settings(
                environment="production",
                host="127.0.0.1",
                port=8741,
                database_path=database,
                launch_credential="x" * 43,
            )
        )
