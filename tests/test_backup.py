from __future__ import annotations

import hashlib
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from pentai_core.backup import BackupError, BackupService
from pentai_policy.document import parse_time
from test_evidence_originals import capture, evidence_fixture


def service_fixture(tmp_path: Path) -> tuple[BackupService, Path, object, dict[str, object]]:
    database, workflow_id, evidence, store = evidence_fixture(tmp_path)
    original = capture(evidence, workflow_id)
    service = BackupService(database, store, b"k" * 32)
    return service, database, evidence, original


def test_encrypted_backup_restores_to_isolated_verified_drill(tmp_path: Path) -> None:
    service, database, _, original = service_fixture(tmp_path)
    backup = tmp_path / "snapshot.pentai-backup"

    created = service.create(backup, actor_id="local-reviewer")

    assert created["status"] == "created"
    assert created["evidence_blob_count"] == 1
    assert created["live_data_replaced"] is False
    assert backup.read_bytes()[:2] != b"PK"
    assert b"Synthetic local evidence only" not in backup.read_bytes()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == created["encrypted_backup_sha256"]

    drill = tmp_path / "restore-drill"
    verified = service.restore_drill(backup, drill)

    assert verified["status"] == "verified"
    assert verified["live_data_replaced"] is False
    with sqlite3.connect(drill / "pentai.db") as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute(
            "SELECT sha256 FROM evidence_objects WHERE evidence_id = ?",
            (original["evidence_id"],),
        ).fetchone() == (original["sha256"],)
    assert (drill / "evidence-blobs" / str(original["sha256"])[:2]).is_dir()
    with sqlite3.connect(database) as connection:
        actions = [
            row[0]
            for row in connection.execute(
                "SELECT action FROM audit_events WHERE subject_type = 'backup' ORDER BY sequence"
            )
        ]
    assert actions == [
        "backup.creation_requested",
        "backup.created",
        "backup.restore_drill_requested",
        "backup.restore_drill_verified",
    ]


def test_tampering_wrong_key_and_conflicting_destination_deny_without_partial_restore(
    tmp_path: Path,
) -> None:
    service, database, _, _ = service_fixture(tmp_path)
    backup = tmp_path / "snapshot.pentai-backup"
    service.create(backup, actor_id="local-reviewer")
    payload = bytearray(backup.read_bytes())
    payload[-1] ^= 1
    tampered = tmp_path / "tampered.pentai-backup"
    tampered.write_bytes(payload)

    with pytest.raises(BackupError, match="authentication failed"):
        service.restore_drill(tampered, tmp_path / "tampered-drill")
    assert not (tmp_path / "tampered-drill").exists()

    wrong_key = BackupService(database, service.evidence_store, b"x" * 32)
    with pytest.raises(BackupError, match="authentication failed"):
        wrong_key.restore_drill(backup, tmp_path / "wrong-key-drill")
    assert not (tmp_path / "wrong-key-drill").exists()

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(BackupError, match="must not exist"):
        service.restore_drill(backup, existing)


def test_missing_or_corrupt_evidence_blocks_backup_creation(tmp_path: Path) -> None:
    service, _, _, original = service_fixture(tmp_path)
    blob = service.evidence_store._path(str(original["sha256"]))  # type: ignore[union-attr]
    blob.unlink()

    with pytest.raises(BackupError, match="failed closed"):
        service.create(tmp_path / "missing.pentai-backup", actor_id="local-reviewer")
    assert not (tmp_path / "missing.pentai-backup").exists()


def test_current_deletion_tombstone_prevents_stale_backup_restore(tmp_path: Path) -> None:
    service, _, evidence, original = service_fixture(tmp_path)
    backup = tmp_path / "before-deletion.pentai-backup"
    service.create(backup, actor_id="local-reviewer")
    evidence.delete_artifact(
        "original",
        str(original["evidence_id"]),
        expected_sha256=str(original["sha256"]),
        reason="Synthetic retention expiry",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=parse_time(str(original["created_at"])) + timedelta(days=2),
    )

    with pytest.raises(BackupError, match="restore deleted evidence"):
        service.restore_drill(backup, tmp_path / "stale-drill")
    assert not (tmp_path / "stale-drill").exists()

    current = tmp_path / "after-deletion.pentai-backup"
    report = service.create(current, actor_id="local-reviewer")
    assert report["evidence_blob_count"] == 0
    assert report["deletion_tombstone_count"] == 1
    assert service.restore_drill(current, tmp_path / "current-drill")["status"] == "verified"


def test_shared_digest_remains_backed_up_until_final_reference_is_deleted(tmp_path: Path) -> None:
    service, _, evidence, first = service_fixture(tmp_path)
    second = capture(evidence, str(first["workflow_id"]), idempotency_key="evidence-fixture-0002")
    deletion_time = parse_time(str(first["created_at"])) + timedelta(days=2)
    evidence.delete_artifact(
        "original",
        str(first["evidence_id"]),
        expected_sha256=str(first["sha256"]),
        reason="Synthetic first reference expiry",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=deletion_time,
    )

    shared = service.create(tmp_path / "shared.pentai-backup", actor_id="local-reviewer")
    assert shared["evidence_blob_count"] == 1
    assert shared["deletion_tombstone_count"] == 0

    evidence.delete_artifact(
        "original",
        str(second["evidence_id"]),
        expected_sha256=str(second["sha256"]),
        reason="Synthetic final reference expiry",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=deletion_time,
    )
    final = service.create(tmp_path / "final.pentai-backup", actor_id="local-reviewer")
    assert final["evidence_blob_count"] == 0
    assert final["deletion_tombstone_count"] == 1
