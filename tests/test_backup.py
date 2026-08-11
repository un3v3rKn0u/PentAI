from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from datetime import timedelta
from pathlib import Path

import pentai_core.backup as backup_module
import pytest
from pentai_core.authorization import AuthorizationService
from pentai_core.backup import BackupError, BackupService
from pentai_core.source_store import EncryptedSourceStore
from pentai_policy.document import parse_time
from test_evidence_originals import capture, evidence_fixture


def service_fixture(tmp_path: Path) -> tuple[BackupService, Path, object, dict[str, object]]:
    database, workflow_id, evidence, store = evidence_fixture(tmp_path)
    original = capture(evidence, workflow_id)
    source_store = EncryptedSourceStore(tmp_path / "source-blobs", b"k" * 32)
    service = BackupService(database, store, b"k" * 32, source_store=source_store)
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


def test_v2_backup_authenticates_and_restores_source_provenance(tmp_path: Path) -> None:
    service, database, _, _ = service_fixture(tmp_path)
    assert service.source_store is not None
    with sqlite3.connect(database) as connection:
        program_id = str(connection.execute("SELECT id FROM programs").fetchone()[0])
    source = AuthorizationService(database, source_store=service.source_store).import_source(
        program_id,
        authority="contract",
        reference="synthetic://backup-source",
        content="Synthetic source provenance for an owned local fixture.",
        actor_id="local-reviewer",
    )
    backup = tmp_path / "source-complete.pentai-backup"

    created = service.create(backup, actor_id="local-reviewer")
    drill = tmp_path / "source-drill"
    verified = service.restore_drill(backup, drill, actor_id="local-reviewer")

    assert created["schema_version"] == "2.0.0"
    assert created["source_blob_count"] == 1
    assert verified["source_blob_count"] == 1
    restored_store = EncryptedSourceStore(drill / "source-blobs", b"k" * 32)
    assert restored_store.load(str(source["content_hash"])) == (
        b"Synthetic source provenance for an owned local fixture."
    )
    with sqlite3.connect(drill / "pentai.db") as connection:
        assert connection.execute(
            "SELECT content_hash FROM source_documents WHERE id = ?", (source["id"],)
        ).fetchone() == (source["content_hash"],)


def test_merged_v1_database_and_evidence_backup_remains_restore_compatible(
    tmp_path: Path,
) -> None:
    service, database, _, _ = service_fixture(tmp_path)
    assert service.source_store is not None
    with sqlite3.connect(database) as connection:
        program_id = str(connection.execute("SELECT id FROM programs").fetchone()[0])
    AuthorizationService(database, source_store=service.source_store).import_source(
        program_id,
        authority="contract",
        reference="synthetic://legacy-v1-omitted-source",
        content="Synthetic source intentionally absent from the legacy v1 archive.",
    )
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary) / "pentai.db"
        service._snapshot_database(snapshot)
        manifest, members = service._build_archive(
            snapshot, actor_id="local-reviewer", backup_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        )
    manifest["schema_version"] = "1.0.0"
    del manifest["source_sha256"]
    members = {
        name: content for name, content in members.items() if not name.startswith("sources/")
    }
    archive = service._archive(manifest, members)
    nonce = os.urandom(12)
    assert service._cipher is not None
    envelope = (
        backup_module._MAGIC + nonce + service._cipher.encrypt(nonce, archive, backup_module._MAGIC)
    )
    backup = tmp_path / "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.pentai-backup"
    backup.write_bytes(envelope)

    restored = service.restore_drill(backup, tmp_path / "v1-drill", actor_id="local-reviewer")

    assert restored["schema_version"] == "2.0.0"
    assert restored["source_blob_count"] == 0
    assert restored["status"] == "verified"


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

    wrong_key = BackupService(
        database,
        service.evidence_store,
        b"x" * 32,
        source_store=EncryptedSourceStore(tmp_path / "wrong-source-blobs", b"x" * 32),
    )
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


def test_missing_source_blob_blocks_backup_creation(tmp_path: Path) -> None:
    service, database, _, _ = service_fixture(tmp_path)
    assert service.source_store is not None
    with sqlite3.connect(database) as connection:
        program_id = str(connection.execute("SELECT id FROM programs").fetchone()[0])
    source = AuthorizationService(database, source_store=service.source_store).import_source(
        program_id,
        authority="contract",
        reference="synthetic://missing-source",
        content="Synthetic source scheduled for a missing-blob test.",
    )
    service.source_store._path(str(source["content_hash"])).unlink()

    with pytest.raises(BackupError, match="source backup failed closed"):
        service.create(tmp_path / "missing-source.pentai-backup", actor_id="local-reviewer")
    assert not (tmp_path / "missing-source.pentai-backup").exists()


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


def test_inventory_authenticates_archives_and_rotation_only_proposes_candidates(
    tmp_path: Path,
) -> None:
    service, _, _, _ = service_fixture(tmp_path)
    root = tmp_path / "backups"
    identifiers = [
        "10000000-0000-4000-8000-000000000001",
        "10000000-0000-4000-8000-000000000002",
        "10000000-0000-4000-8000-000000000003",
        "10000000-0000-4000-8000-000000000004",
    ]
    for backup_id in identifiers:
        service.create(
            root / f"{backup_id}.pentai-backup",
            actor_id="local-reviewer",
            backup_id=backup_id,
        )
    service.restore_drill(
        root / f"{identifiers[0]}.pentai-backup",
        root / "restore-drills" / identifiers[0],
        actor_id="local-reviewer",
    )

    inventory = service.inventory(root, actor_id="local-reviewer")
    plan = service.rotation_plan(root, retain_count=2, actor_id="local-reviewer")

    assert inventory["backup_count"] == 4
    items = {item["backup_id"]: item for item in inventory["items"]}
    assert items[identifiers[0]]["restore_verified"] is True
    assert all(item["forensic_erase_guaranteed"] is False for item in items.values())
    assert identifiers[0] in plan["protected_backup_ids"]
    assert len(plan["protected_backup_ids"]) == 3
    assert len(plan["purge_candidates"]) == 1
    assert plan["automatic_deletion_performed"] is False
    assert all((root / f"{backup_id}.pentai-backup").exists() for backup_id in identifiers)


def test_inventory_rejects_tampered_and_symlinked_matching_entries(tmp_path: Path) -> None:
    service, _, _, _ = service_fixture(tmp_path)
    tampered_root = tmp_path / "tampered-backups"
    backup_id = "15000000-0000-4000-8000-000000000001"
    path = tampered_root / f"{backup_id}.pentai-backup"
    service.create(path, actor_id="local-reviewer", backup_id=backup_id)
    payload = bytearray(path.read_bytes())
    payload[-1] ^= 1
    path.write_bytes(payload)
    with pytest.raises(BackupError, match="authentication failed"):
        service.inventory(tampered_root, actor_id="local-reviewer")

    symlink_root = tmp_path / "symlink-backups"
    symlink_root.mkdir()
    linked_id = "15000000-0000-4000-8000-000000000002"
    (symlink_root / f"{linked_id}.pentai-backup").symlink_to(path)
    with pytest.raises(BackupError, match="entry is unsafe"):
        service.inventory(symlink_root, actor_id="local-reviewer")


def test_purge_requires_exact_confirmation_and_protects_last_verified_backup(
    tmp_path: Path,
) -> None:
    service, _, _, _ = service_fixture(tmp_path)
    root = tmp_path / "backups"
    first_id = "20000000-0000-4000-8000-000000000001"
    second_id = "20000000-0000-4000-8000-000000000002"
    first = service.create(
        root / f"{first_id}.pentai-backup", actor_id="local-reviewer", backup_id=first_id
    )
    second = service.create(
        root / f"{second_id}.pentai-backup", actor_id="local-reviewer", backup_id=second_id
    )
    service.restore_drill(
        root / f"{first_id}.pentai-backup",
        root / "restore-drills" / first_id,
        actor_id="local-reviewer",
    )

    with pytest.raises(BackupError, match="explicit human confirmation"):
        service.purge(
            root,
            second_id,
            expected_sha256=str(second["encrypted_backup_sha256"]),
            reason="Synthetic rotation",
            confirm_permanent_deletion=False,
            actor_id="local-reviewer",
        )
    with pytest.raises(BackupError, match="digest does not match"):
        service.purge(
            root,
            second_id,
            expected_sha256="0" * 64,
            reason="Synthetic rotation",
            confirm_permanent_deletion=True,
            actor_id="local-reviewer",
        )
    with pytest.raises(BackupError, match="last restore-verified backup"):
        service.purge(
            root,
            first_id,
            expected_sha256=str(first["encrypted_backup_sha256"]),
            reason="Synthetic rotation",
            confirm_permanent_deletion=True,
            actor_id="local-reviewer",
        )

    service.restore_drill(
        root / f"{second_id}.pentai-backup",
        root / "restore-drills" / second_id,
        actor_id="local-reviewer",
    )
    purged = service.purge(
        root,
        first_id,
        expected_sha256=str(first["encrypted_backup_sha256"]),
        reason="Synthetic rotation",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
    )
    assert purged["disposition"] == "unlinked"
    assert purged["forensic_erase_guaranteed"] is False
    assert not (root / f"{first_id}.pentai-backup").exists()


def test_interrupted_purge_recovers_as_already_absent(tmp_path: Path) -> None:
    service, database, _, _ = service_fixture(tmp_path)
    root = tmp_path / "backups"
    first_id = "30000000-0000-4000-8000-000000000001"
    second_id = "30000000-0000-4000-8000-000000000002"
    first = service.create(
        root / f"{first_id}.pentai-backup", actor_id="local-reviewer", backup_id=first_id
    )
    service.create(
        root / f"{second_id}.pentai-backup", actor_id="local-reviewer", backup_id=second_id
    )
    service.restore_drill(
        root / f"{first_id}.pentai-backup",
        root / "restore-drills" / first_id,
        actor_id="local-reviewer",
    )
    service.restore_drill(
        root / f"{second_id}.pentai-backup",
        root / "restore-drills" / second_id,
        actor_id="local-reviewer",
    )

    def crash() -> None:
        raise RuntimeError("synthetic crash after unlink")

    interrupted = BackupService(
        database,
        service.evidence_store,
        b"k" * 32,
        source_store=service.source_store,
        purge_after_unlink_handler=crash,
    )
    with pytest.raises(RuntimeError, match="synthetic crash"):
        interrupted.purge(
            root,
            first_id,
            expected_sha256=str(first["encrypted_backup_sha256"]),
            reason="Synthetic interrupted rotation",
            confirm_permanent_deletion=True,
            actor_id="local-reviewer",
        )
    assert not (root / f"{first_id}.pentai-backup").exists()

    recovered = service.purge(
        root,
        first_id,
        expected_sha256=str(first["encrypted_backup_sha256"]),
        reason="Synthetic interrupted rotation",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
    )
    replay = service.purge(
        root,
        first_id,
        expected_sha256=str(first["encrypted_backup_sha256"]),
        reason="Synthetic interrupted rotation",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
    )
    assert recovered["disposition"] == "already_absent"
    assert replay == recovered
