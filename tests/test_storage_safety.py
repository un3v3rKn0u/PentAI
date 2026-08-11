from __future__ import annotations

import errno
import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.backup import BackupError, BackupService
from pentai_core.database import register_storage_failure_handler, transaction
from pentai_core.evidence_store import EncryptedEvidenceStore, EvidenceStoreError
from pentai_core.source_store import EncryptedSourceStore, SourceStoreError
from pentai_core.storage_safety import StorageSafetyLatch


def _full_disk() -> OSError:
    return OSError(errno.ENOSPC, "synthetic disk full")


def test_source_interrupted_write_preserves_committed_blob_and_stops_authority(
    tmp_path: Path,
) -> None:
    latch = StorageSafetyLatch()
    store = EncryptedSourceStore(tmp_path / "sources", b"s" * 32, failure_handler=latch.trip)
    committed = b"committed synthetic source"
    committed_digest = hashlib.sha256(committed).hexdigest()
    store.store(committed, committed_digest)

    interrupted = b"interrupted synthetic source"
    interrupted_digest = hashlib.sha256(interrupted).hexdigest()
    with patch("pentai_core.source_store.os.fsync", side_effect=_full_disk()):
        with pytest.raises(SourceStoreError, match="could not be persisted"):
            store.store(interrupted, interrupted_digest)

    assert store.load(committed_digest) == committed
    assert not store._path(interrupted_digest).exists()
    assert list(store.root.glob("**/*.tmp")) == []
    service = AuthorizationService(tmp_path / "pentai.db", storage_safety=latch)
    with pytest.raises(DomainError) as denied:
        service.evaluate_intent("00000000-0000-4000-8000-000000000001", {})
    assert denied.value.code == "STORAGE_SAFETY_STOPPED"


def test_evidence_disk_full_preserves_prior_ciphertext_and_removes_temporary(
    tmp_path: Path,
) -> None:
    latch = StorageSafetyLatch()
    store = EncryptedEvidenceStore(
        tmp_path / "evidence", b"e" * 32, failure_handler=latch.trip
    )
    committed = b"committed synthetic evidence"
    committed_digest = hashlib.sha256(committed).hexdigest()
    store.store(committed, committed_digest)

    interrupted = b"interrupted synthetic evidence"
    interrupted_digest = hashlib.sha256(interrupted).hexdigest()
    with patch("pentai_core.evidence_store.os.fsync", side_effect=_full_disk()):
        with pytest.raises(EvidenceStoreError, match="could not be persisted"):
            store.store(interrupted, interrupted_digest)

    assert store.load(committed_digest) == committed
    assert not store._path(interrupted_digest).exists()
    assert list(store.root.glob("**/*.tmp")) == []
    assert latch.reason_code() == "STORAGE_FAILURE"


def test_database_disk_full_trips_latch_and_rolls_back(tmp_path: Path) -> None:
    database = tmp_path / "pentai.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE durable(value TEXT NOT NULL)")
        connection.execute("INSERT INTO durable VALUES ('committed')")
    latch = StorageSafetyLatch()
    register_storage_failure_handler(database, latch.trip)

    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        with transaction(database) as connection:
            connection.execute("INSERT INTO durable VALUES ('uncommitted')")
            raise sqlite3.OperationalError("database or disk is full")

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM durable").fetchall() == [("committed",)]
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert latch.reason_code() == "STORAGE_FAILURE"


def test_backup_disk_full_preserves_existing_recovery_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_backup import service_fixture

    service, database, _, _ = service_fixture(tmp_path)
    committed = tmp_path / "committed.pentai-backup"
    service.create(committed, actor_id="local-reviewer")
    committed_digest = hashlib.sha256(committed.read_bytes()).hexdigest()
    latch = StorageSafetyLatch()
    interrupted_service = BackupService(
        database,
        service.evidence_store,
        b"k" * 32,
        source_store=service.source_store,
        storage_failure_handler=latch.trip,
    )
    interrupted = tmp_path / "interrupted.pentai-backup"
    def fail_sync(_descriptor: int) -> None:
        raise _full_disk()

    monkeypatch.setattr("pentai_core.backup.os.fsync", fail_sync)

    with pytest.raises(BackupError) as denied:
        interrupted_service.create(interrupted, actor_id="local-reviewer")

    assert denied.value.code == "BACKUP_WRITE_FAILED"
    assert hashlib.sha256(committed.read_bytes()).hexdigest() == committed_digest
    assert not interrupted.exists()
    assert list(tmp_path.glob(".*.tmp")) == []
    assert latch.reason_code() == "STORAGE_FAILURE"
