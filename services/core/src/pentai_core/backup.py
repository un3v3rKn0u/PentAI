from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction
from pentai_core.evidence_store import EncryptedEvidenceStore, EvidenceStoreError
from pentai_core.source_store import EncryptedSourceStore, SourceStoreError

_MAGIC = b"PENTAI-ENCRYPTED-BACKUP-V1\x00"
_NONCE_SIZE = 12
_MAX_BACKUP_BYTES = 256 * 1024 * 1024
_DATABASE_MEMBER = "database/pentai.db"
_MANIFEST_MEMBER = "manifest.json"
_BACKUP_NAME = re.compile(
    r"^(?P<id>[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.pentai-backup$"
)
_MAX_INVENTORY = 1000


class BackupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class BackupService:
    """Create authenticated snapshots and restore them only into an isolated drill path."""

    def __init__(
        self,
        database_path: Path,
        evidence_store: EncryptedEvidenceStore | None,
        master_key: bytes | None,
        *,
        source_store: EncryptedSourceStore | None = None,
        purge_after_unlink_handler: Callable[[], None] | None = None,
        storage_failure_handler: Callable[[], None] | None = None,
    ) -> None:
        self.database_path = database_path
        self.evidence_store = evidence_store
        self.source_store = source_store
        self.purge_after_unlink_handler = purge_after_unlink_handler
        self.storage_failure_handler = storage_failure_handler
        self._master_key = master_key
        if master_key is None:
            self._cipher = None
        elif len(master_key) != 32:
            raise ValueError("backup master key must contain 32 bytes")
        else:
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"pentai-local-backup-v1",
                info=b"database-and-evidence",
            ).derive(master_key)
            self._cipher = AESGCM(key)

    def create(
        self, destination: Path, *, actor_id: str, backup_id: str | None = None
    ) -> dict[str, object]:
        self._available(actor_id)
        if destination.exists() or not destination.name:
            raise BackupError("BACKUP_DESTINATION_INVALID", "backup destination must not exist")
        identifier = backup_id or str(uuid4())
        if not _uuid(identifier):
            raise BackupError("BACKUP_ID_INVALID", "backup id is invalid")
        self._audit(
            "backup.creation_requested",
            identifier,
            actor_id,
            {"destination_name": destination.name, "live_data_replaced": False},
        )
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="pentai-backup-") as temporary:
            snapshot = Path(temporary) / "pentai.db"
            self._snapshot_database(snapshot)
            manifest, members = self._build_archive(
                snapshot, actor_id=actor_id, backup_id=identifier
            )
            archive = self._archive(manifest, members)
        if len(archive) > _MAX_BACKUP_BYTES:
            raise BackupError("BACKUP_SIZE_EXCEEDED", "encrypted backup exceeds the local limit")
        nonce = os.urandom(_NONCE_SIZE)
        assert self._cipher is not None
        envelope = _MAGIC + nonce + self._cipher.encrypt(nonce, archive, _MAGIC)
        try:
            self._atomic_write(destination, envelope)
        except BackupError:
            if self.storage_failure_handler is not None:
                self.storage_failure_handler()
            raise
        self._audit(
            "backup.created",
            identifier,
            actor_id,
            {
                "destination_name": destination.name,
                "encrypted_backup_sha256": hashlib.sha256(envelope).hexdigest(),
                "live_data_replaced": False,
            },
        )
        return self._report(manifest, envelope, destination, status="created")

    def restore_drill(
        self, backup: Path, destination: Path, *, actor_id: str = "restore-drill"
    ) -> dict[str, object]:
        self._available(actor_id)
        if destination.exists() or not destination.name:
            raise BackupError(
                "RESTORE_DESTINATION_INVALID", "restore drill destination must not exist"
            )
        try:
            envelope = backup.read_bytes()
        except OSError as exc:
            raise BackupError("BACKUP_UNAVAILABLE", "encrypted backup is unavailable") from exc
        if len(envelope) > _MAX_BACKUP_BYTES or not envelope.startswith(_MAGIC):
            raise BackupError("BACKUP_FORMAT_INVALID", "encrypted backup format is invalid")
        self._audit(
            "backup.restore_drill_requested",
            backup.stem,
            actor_id,
            {"backup_name": backup.name, "live_data_replaced": False},
        )
        start = len(_MAGIC)
        if len(envelope) <= start + _NONCE_SIZE:
            raise BackupError("BACKUP_FORMAT_INVALID", "encrypted backup format is invalid")
        assert self._cipher is not None
        try:
            archive = self._cipher.decrypt(
                envelope[start : start + _NONCE_SIZE], envelope[start + _NONCE_SIZE :], _MAGIC
            )
        except InvalidTag as exc:
            raise BackupError(
                "BACKUP_AUTHENTICATION_FAILED", "backup authentication failed"
            ) from exc

        temporary = destination.parent / f".{destination.name}.{uuid4().hex}.restore"
        try:
            manifest = self._extract_and_verify(archive, temporary)
            os.replace(temporary, destination)
            self._fsync_directory(destination.parent)
        except Exception:
            self._remove_drill(temporary)
            raise
        self._audit(
            "backup.restore_drill_verified",
            str(manifest["backup_id"]),
            actor_id,
            {
                "backup_name": backup.name,
                "encrypted_backup_sha256": hashlib.sha256(envelope).hexdigest(),
                "live_data_replaced": False,
            },
        )
        return self._report(manifest, envelope, destination, status="verified")

    def inventory(self, backup_root: Path, *, actor_id: str) -> dict[str, object]:
        self._available(actor_id)
        items = self._inventory_items(backup_root)
        self._audit(
            "backup.inventory_reviewed",
            "local-backup-inventory",
            actor_id,
            {"backup_count": len(items), "live_data_replaced": False},
        )
        report: dict[str, object] = {
            "schema_version": "1.0.0",
            "backup_count": len(items),
            "items": items,
            "live_data_replaced": False,
        }
        self._valid(report, "backup-inventory-v1.schema.json")
        return report

    def rotation_plan(
        self, backup_root: Path, *, retain_count: int, actor_id: str
    ) -> dict[str, object]:
        self._available(actor_id)
        if not 2 <= retain_count <= 20:
            raise BackupError("BACKUP_RETENTION_INVALID", "backup retention count is invalid")
        items = self._inventory_items(backup_root)
        newest = sorted(
            items, key=lambda item: (str(item["created_at"]), str(item["backup_id"])), reverse=True
        )
        protected = {str(item["backup_id"]) for item in newest[:retain_count]}
        verified = [item for item in newest if item["restore_verified"] is True]
        if verified:
            protected.add(str(verified[0]["backup_id"]))
        candidates = [item for item in newest if str(item["backup_id"]) not in protected]
        plan: dict[str, object] = {
            "schema_version": "1.0.0",
            "retain_count": retain_count,
            "protected_backup_ids": sorted(protected),
            "purge_candidates": [item["backup_id"] for item in candidates],
            "requires_human_confirmation": True,
            "automatic_deletion_performed": False,
        }
        self._audit(
            "backup.rotation_planned",
            "local-backup-inventory",
            actor_id,
            {
                "retain_count": retain_count,
                "protected_backup_ids": plan["protected_backup_ids"],
                "purge_candidates": plan["purge_candidates"],
                "automatic_deletion_performed": False,
            },
        )
        self._valid(plan, "backup-rotation-plan-v1.schema.json")
        return plan

    def purge(
        self,
        backup_root: Path,
        backup_id: str,
        *,
        expected_sha256: str,
        reason: str,
        confirm_permanent_deletion: bool,
        actor_id: str,
    ) -> dict[str, object]:
        self._available(actor_id)
        if not _uuid(backup_id) or not _digest(expected_sha256):
            raise BackupError("BACKUP_PURGE_IDENTITY_INVALID", "backup purge identity is invalid")
        normalized_reason = reason.strip()
        if not normalized_reason or len(normalized_reason) > 500:
            raise BackupError("BACKUP_PURGE_REASON_INVALID", "backup purge reason is invalid")
        if confirm_permanent_deletion is not True:
            raise BackupError(
                "BACKUP_PURGE_CONFIRMATION_REQUIRED",
                "backup purge requires explicit human confirmation",
            )
        requested = self._purge_request(backup_id)
        path = backup_root / f"{backup_id}.pentai-backup"
        if requested is not None:
            if (
                requested.get("expected_sha256") != expected_sha256
                or requested.get("reason") != normalized_reason
            ):
                raise BackupError("BACKUP_PURGE_CONFLICT", "backup purge request conflicts")
            if path.exists():
                raise BackupError("BACKUP_PURGE_STATE_INVALID", "purged backup unexpectedly exists")
            return self._complete_purge(
                backup_id, expected_sha256, actor_id, disposition="already_absent"
            )

        items = self._inventory_items(backup_root)
        matches = [item for item in items if item["backup_id"] == backup_id]
        if len(matches) != 1:
            raise BackupError("BACKUP_NOT_FOUND", "backup does not exist")
        item = matches[0]
        if item["encrypted_backup_sha256"] != expected_sha256:
            raise BackupError("BACKUP_PURGE_DIGEST_MISMATCH", "backup digest does not match")
        verified = [entry for entry in items if entry["restore_verified"] is True]
        if item["restore_verified"] is True and len(verified) <= 1:
            raise BackupError(
                "BACKUP_LAST_VERIFIED_PROTECTED", "last restore-verified backup is protected"
            )
        self._audit(
            "backup.purge_requested",
            backup_id,
            actor_id,
            {
                "expected_sha256": expected_sha256,
                "reason": normalized_reason,
                "forensic_erase_guaranteed": False,
            },
        )
        try:
            self._unlink_exact(path, expected_sha256)
            self._fsync_directory(backup_root)
        except OSError as exc:
            raise BackupError("BACKUP_PURGE_FAILED", "backup purge failed closed") from exc
        if self.purge_after_unlink_handler is not None:
            self.purge_after_unlink_handler()
        return self._complete_purge(backup_id, expected_sha256, actor_id, disposition="unlinked")

    @staticmethod
    def _unlink_exact(path: Path, expected_sha256: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise BackupError("BACKUP_PURGE_STATE_INVALID", "backup purge target is unsafe")
        try:
            before = path.stat(follow_symlinks=False)
            content = path.read_bytes()
            after = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BackupError("BACKUP_PURGE_FAILED", "backup purge target is unavailable") from exc
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) or hashlib.sha256(content).hexdigest() != expected_sha256:
            raise BackupError("BACKUP_PURGE_DIGEST_MISMATCH", "backup changed before purge")
        path.unlink()

    def _inventory_items(self, backup_root: Path) -> list[dict[str, object]]:
        if backup_root.is_symlink():
            raise BackupError("BACKUP_INVENTORY_INVALID", "backup root cannot be a symlink")
        if not backup_root.exists():
            return []
        try:
            paths = sorted(backup_root.iterdir())
        except OSError as exc:
            raise BackupError(
                "BACKUP_INVENTORY_UNAVAILABLE", "backup inventory is unavailable"
            ) from exc
        matching = [path for path in paths if _BACKUP_NAME.fullmatch(path.name)]
        if len(matching) > _MAX_INVENTORY:
            raise BackupError("BACKUP_INVENTORY_LIMIT", "backup inventory exceeds the limit")
        verified = self._verified_backup_ids()
        tombstones = self._current_tombstones()
        items: list[dict[str, object]] = []
        for path in matching:
            if path.is_symlink() or not path.is_file():
                raise BackupError("BACKUP_INVENTORY_INVALID", "backup inventory entry is unsafe")
            envelope, manifest = self._inspect_backup(path)
            match = _BACKUP_NAME.fullmatch(path.name)
            assert match is not None
            backup_id = match.group("id")
            if manifest["backup_id"] != backup_id:
                raise BackupError("BACKUP_INVENTORY_INVALID", "backup filename identity changed")
            evidence = set(cast(list[str], manifest["evidence_sha256"]))
            items.append(
                {
                    "backup_id": backup_id,
                    "schema_version": manifest["schema_version"],
                    "created_at": manifest["created_at"],
                    "encrypted_backup_sha256": hashlib.sha256(envelope).hexdigest(),
                    "size_bytes": len(envelope),
                    "evidence_blob_count": len(evidence),
                    "source_blob_count": len(cast(list[str], manifest.get("source_sha256", []))),
                    "deletion_tombstone_count": len(
                        cast(list[str], manifest["deletion_tombstones"])
                    ),
                    "restore_verified": backup_id in verified,
                    "contains_currently_deleted_evidence": bool(evidence & tombstones),
                    "forensic_erase_guaranteed": False,
                }
            )
        return sorted(items, key=lambda item: (str(item["created_at"]), str(item["backup_id"])))

    def _inspect_backup(self, path: Path) -> tuple[bytes, dict[str, object]]:
        try:
            envelope = path.read_bytes()
        except OSError as exc:
            raise BackupError("BACKUP_UNAVAILABLE", "encrypted backup is unavailable") from exc
        if len(envelope) > _MAX_BACKUP_BYTES or not envelope.startswith(_MAGIC):
            raise BackupError("BACKUP_FORMAT_INVALID", "encrypted backup format is invalid")
        start = len(_MAGIC)
        if len(envelope) <= start + _NONCE_SIZE:
            raise BackupError("BACKUP_FORMAT_INVALID", "encrypted backup format is invalid")
        assert self._cipher is not None
        try:
            archive_bytes = self._cipher.decrypt(
                envelope[start : start + _NONCE_SIZE], envelope[start + _NONCE_SIZE :], _MAGIC
            )
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
                names = archive.namelist()
                if len(names) != len(set(names)) or _MANIFEST_MEMBER not in names:
                    raise BackupError("BACKUP_MANIFEST_INVALID", "backup members are ambiguous")
                if sum(info.file_size for info in archive.infolist()) > _MAX_BACKUP_BYTES:
                    raise BackupError("BACKUP_SIZE_EXCEEDED", "expanded backup exceeds the limit")
                manifest = cast(dict[str, object], json.loads(archive.read(_MANIFEST_MEMBER)))
                self._validate_manifest(manifest)
                evidence = cast(list[str], manifest["evidence_sha256"])
                sources = cast(list[str], manifest.get("source_sha256", []))
                expected = (
                    {_MANIFEST_MEMBER, _DATABASE_MEMBER}
                    | {f"evidence/{digest}.blob" for digest in evidence}
                    | {f"sources/{digest}.blob" for digest in sources}
                )
                if set(names) != expected:
                    raise BackupError("BACKUP_MEMBERS_INVALID", "backup members do not match")
        except InvalidTag as exc:
            raise BackupError(
                "BACKUP_AUTHENTICATION_FAILED", "backup authentication failed"
            ) from exc
        except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
            raise BackupError("BACKUP_MANIFEST_INVALID", "backup manifest is invalid") from exc
        return envelope, manifest

    def _verified_backup_ids(self) -> set[str]:
        with transaction(self.database_path) as connection:
            return {
                str(row[0])
                for row in connection.execute(
                    """SELECT DISTINCT subject_id FROM audit_events
                       WHERE action = 'backup.restore_drill_verified'
                         AND subject_type = 'backup'"""
                )
            }

    def _purge_request(self, backup_id: str) -> dict[str, object] | None:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT data_json FROM audit_events
                   WHERE action = 'backup.purge_requested' AND subject_type = 'backup'
                     AND subject_id = ? ORDER BY sequence DESC LIMIT 1""",
                (backup_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row[0])
        except (TypeError, json.JSONDecodeError) as exc:
            raise BackupError(
                "BACKUP_PURGE_STATE_INVALID", "backup purge state is invalid"
            ) from exc
        if not isinstance(data, dict):
            raise BackupError("BACKUP_PURGE_STATE_INVALID", "backup purge state is invalid")
        return cast(dict[str, object], data)

    def _complete_purge(
        self,
        backup_id: str,
        expected_sha256: str,
        actor_id: str,
        *,
        disposition: str,
    ) -> dict[str, object]:
        with transaction(self.database_path) as connection:
            existing = connection.execute(
                """SELECT data_json FROM audit_events
                   WHERE action = 'backup.purge_completed' AND subject_type = 'backup'
                     AND subject_id = ? ORDER BY sequence DESC LIMIT 1""",
                (backup_id,),
            ).fetchone()
        if existing is not None:
            try:
                stored = json.loads(existing[0])
                disposition = str(stored["disposition"])
            except (TypeError, KeyError, json.JSONDecodeError) as exc:
                raise BackupError(
                    "BACKUP_PURGE_STATE_INVALID", "backup purge state is invalid"
                ) from exc
        else:
            self._audit(
                "backup.purge_completed",
                backup_id,
                actor_id,
                {
                    "expected_sha256": expected_sha256,
                    "disposition": disposition,
                    "forensic_erase_guaranteed": False,
                },
            )
        report: dict[str, object] = {
            "schema_version": "1.0.0",
            "backup_id": backup_id,
            "expected_sha256": expected_sha256,
            "disposition": disposition,
            "forensic_erase_guaranteed": False,
            "live_data_replaced": False,
        }
        self._valid(report, "backup-purge-v1.schema.json")
        return report

    @staticmethod
    def _valid(document: dict[str, object], schema: str) -> None:
        if contract_issues(document, schema):
            raise BackupError("BACKUP_CONTRACT_INVALID", "backup contract is invalid")

    def _available(self, actor_id: str) -> None:
        if self._cipher is None or self.evidence_store is None or self.source_store is None:
            raise BackupError("BACKUP_KEY_UNAVAILABLE", "backup encryption is unavailable")
        if not actor_id or len(actor_id) > 128:
            raise BackupError("BACKUP_ACTOR_INVALID", "backup actor is invalid")

    def _audit(
        self,
        action: str,
        backup_id: str,
        actor_id: str,
        data: dict[str, object],
    ) -> None:
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            append_audit_event(
                connection,
                action=action,
                subject_type="backup",
                subject_id=backup_id,
                actor_type="human",
                actor_id=actor_id,
                data=data,
                occurred_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )

    def _snapshot_database(self, destination: Path) -> None:
        try:
            source = sqlite3.connect(f"file:{self.database_path}?mode=ro", uri=True)
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
                target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                target.close()
                source.close()
        except sqlite3.Error as exc:
            raise BackupError("BACKUP_DATABASE_FAILED", "database snapshot failed") from exc

    def _build_archive(
        self, snapshot: Path, *, actor_id: str, backup_id: str
    ) -> tuple[dict[str, object], dict[str, bytes]]:
        database_bytes = snapshot.read_bytes()
        connection = sqlite3.connect(snapshot)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise BackupError("BACKUP_DATABASE_INVALID", "database snapshot is not integral")
            migrations = [
                str(row[0])
                for row in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                )
            ]
            audit = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            deleted = {
                str(row[0]) for row in connection.execute("SELECT sha256 FROM evidence_deletions")
            }
            active = self._active_digests(connection)
            sources = self._source_digests(connection)
        finally:
            connection.close()
        deleted -= active
        members: dict[str, bytes] = {_DATABASE_MEMBER: database_bytes}
        assert self.evidence_store is not None
        for digest in sorted(active):
            try:
                self.evidence_store.load(digest)
                members[f"evidence/{digest}.blob"] = self.evidence_store._path(digest).read_bytes()
            except (EvidenceStoreError, OSError) as exc:
                raise BackupError(
                    "BACKUP_EVIDENCE_INVALID", "evidence backup failed closed"
                ) from exc
        assert self.source_store is not None
        for digest in sorted(sources):
            try:
                self.source_store.load(digest)
                members[f"sources/{digest}.blob"] = self.source_store._path(digest).read_bytes()
            except (SourceStoreError, OSError) as exc:
                raise BackupError("BACKUP_SOURCE_INVALID", "source backup failed closed") from exc
        created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        manifest: dict[str, object] = {
            "schema_version": "2.0.0",
            "backup_id": backup_id,
            "created_at": created_at,
            "created_by": actor_id,
            "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
            "audit_head_hash": str(audit[0]) if audit is not None else None,
            "migration_versions": migrations,
            "evidence_sha256": sorted(active),
            "deletion_tombstones": sorted(deleted),
            "source_sha256": sorted(sources),
        }
        self._validate_manifest(manifest)
        return manifest, members

    @staticmethod
    def _archive(manifest: dict[str, object], members: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                _MANIFEST_MEMBER, json.dumps(manifest, sort_keys=True, separators=(",", ":"))
            )
            for name, content in sorted(members.items()):
                archive.writestr(name, content)
        return output.getvalue()

    def _extract_and_verify(self, archive_bytes: bytes, destination: Path) -> dict[str, object]:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
                names = archive.namelist()
                if len(names) != len(set(names)) or _MANIFEST_MEMBER not in names:
                    raise BackupError("BACKUP_MANIFEST_INVALID", "backup members are ambiguous")
                if any(info.file_size > _MAX_BACKUP_BYTES for info in archive.infolist()):
                    raise BackupError("BACKUP_SIZE_EXCEEDED", "backup member exceeds the limit")
                if sum(info.file_size for info in archive.infolist()) > _MAX_BACKUP_BYTES:
                    raise BackupError("BACKUP_SIZE_EXCEEDED", "expanded backup exceeds the limit")
                manifest = cast(dict[str, object], json.loads(archive.read(_MANIFEST_MEMBER)))
                self._validate_manifest(manifest)
                evidence = set(cast(list[str], manifest["evidence_sha256"]))
                sources = set(cast(list[str], manifest.get("source_sha256", [])))
                expected = (
                    {_MANIFEST_MEMBER, _DATABASE_MEMBER}
                    | {f"evidence/{digest}.blob" for digest in evidence}
                    | {f"sources/{digest}.blob" for digest in sources}
                )
                if set(names) != expected:
                    raise BackupError(
                        "BACKUP_MEMBERS_INVALID", "backup members do not match manifest"
                    )
                current_tombstones = self._current_tombstones()
                if evidence & current_tombstones:
                    raise BackupError(
                        "BACKUP_TOMBSTONE_STALE", "backup would restore deleted evidence"
                    )
                database = archive.read(_DATABASE_MEMBER)
                if hashlib.sha256(database).hexdigest() != manifest["database_sha256"]:
                    raise BackupError("BACKUP_DATABASE_INVALID", "database digest does not match")
                database_path = destination / "pentai.db"
                database_path.write_bytes(database)
                evidence_root = destination / "evidence-blobs"
                for digest in sorted(evidence):
                    path = evidence_root / digest[:2] / f"{digest}.blob"
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    path.write_bytes(archive.read(f"evidence/{digest}.blob"))
                source_root = destination / "source-blobs"
                for digest in sorted(sources):
                    path = source_root / digest[:2] / f"{digest}.blob"
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    path.write_bytes(archive.read(f"sources/{digest}.blob"))
            self._verify_restored_database(database_path, manifest)
            assert self._master_key is not None
            restored_store = EncryptedEvidenceStore(evidence_root, self._master_key)
            for digest in cast(list[str], manifest["evidence_sha256"]):
                restored_store.load(digest)
            if manifest["schema_version"] == "2.0.0":
                restored_sources = EncryptedSourceStore(source_root, self._master_key)
                for digest in cast(list[str], manifest["source_sha256"]):
                    restored_sources.load(digest)
        except (
            OSError,
            zipfile.BadZipFile,
            json.JSONDecodeError,
            EvidenceStoreError,
            SourceStoreError,
        ) as exc:
            if isinstance(exc, BackupError):
                raise
            raise BackupError(
                "BACKUP_RESTORE_INVALID", "backup restore verification failed"
            ) from exc
        return manifest

    def _verify_restored_database(self, path: Path, manifest: dict[str, object]) -> None:
        connection = sqlite3.connect(path)
        try:
            row = connection.execute("PRAGMA integrity_check").fetchone()
            migrations = [
                str(item[0])
                for item in connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                )
            ]
            audit = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            active = sorted(self._active_digests(connection))
            deleted = {
                str(item[0]) for item in connection.execute("SELECT sha256 FROM evidence_deletions")
            }
            tombstones = sorted(deleted - set(active))
            sources = (
                sorted(self._source_digests(connection))
                if manifest["schema_version"] == "2.0.0"
                else []
            )
        except sqlite3.Error as exc:
            raise BackupError("BACKUP_DATABASE_INVALID", "restored database is invalid") from exc
        finally:
            connection.close()
        if (
            row is None
            or row[0] != "ok"
            or migrations != manifest["migration_versions"]
            or (str(audit[0]) if audit is not None else None) != manifest["audit_head_hash"]
            or active != manifest["evidence_sha256"]
            or tombstones != manifest["deletion_tombstones"]
            or (manifest["schema_version"] == "2.0.0" and sources != manifest["source_sha256"])
        ):
            raise BackupError("BACKUP_DATABASE_INVALID", "restored database verification failed")
        from pentai_core.authorization import AuthorizationService

        if not AuthorizationService(path).verify_audit_chain()["valid"]:
            raise BackupError("BACKUP_AUDIT_INVALID", "restored audit chain is invalid")

    def _current_tombstones(self) -> set[str]:
        connection = sqlite3.connect(self.database_path)
        try:
            deleted = {
                str(row[0]) for row in connection.execute("SELECT sha256 FROM evidence_deletions")
            }
            return deleted - self._active_digests(connection)
        except sqlite3.Error as exc:
            raise BackupError(
                "BACKUP_TOMBSTONES_UNAVAILABLE", "deletion state is unavailable"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _validate_manifest(manifest: object) -> None:
        required = {
            "schema_version",
            "backup_id",
            "created_at",
            "created_by",
            "database_sha256",
            "audit_head_hash",
            "migration_versions",
            "evidence_sha256",
            "deletion_tombstones",
        }
        if not isinstance(manifest, dict):
            raise BackupError("BACKUP_MANIFEST_INVALID", "backup manifest is invalid")
        version = manifest.get("schema_version")
        if version == "2.0.0":
            required.add("source_sha256")
        elif version != "1.0.0":
            raise BackupError("BACKUP_MANIFEST_INVALID", "backup manifest is invalid")
        if set(manifest) != required:
            raise BackupError("BACKUP_MANIFEST_INVALID", "backup manifest is invalid")
        digests = manifest.get("evidence_sha256")
        tombstones = manifest.get("deletion_tombstones")
        sources = manifest.get("source_sha256", [])
        if (
            not _uuid(manifest.get("backup_id"))
            or not _date_time(manifest.get("created_at"))
            or not isinstance(manifest.get("created_by"), str)
            or not 1 <= len(cast(str, manifest.get("created_by"))) <= 128
            or not _digest(manifest.get("database_sha256"))
            or not (
                manifest.get("audit_head_hash") is None or _digest(manifest.get("audit_head_hash"))
            )
            or not isinstance(manifest.get("migration_versions"), list)
            or any(
                not isinstance(value, str) or not value.isdigit() or len(value) != 4
                for value in cast(list[object], manifest.get("migration_versions"))
            )
            or manifest.get("migration_versions")
            != sorted(set(cast(list[str], manifest.get("migration_versions"))))
            or not isinstance(digests, list)
            or not isinstance(tombstones, list)
            or not isinstance(sources, list)
            or digests != sorted(set(digests))
            or tombstones != sorted(set(tombstones))
            or sources != sorted(set(sources))
            or any(not _digest(value) for value in [*digests, *tombstones, *sources])
            or set(digests) & set(tombstones)
        ):
            raise BackupError("BACKUP_MANIFEST_INVALID", "backup manifest is invalid")

    @staticmethod
    def _active_digests(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in connection.execute(
                """SELECT sha256 FROM evidence_objects o
                   WHERE NOT EXISTS (
                       SELECT 1 FROM evidence_deletions d
                       WHERE d.artifact_type = 'original' AND d.artifact_id = o.evidence_id
                   )
                   UNION
                   SELECT sha256 FROM evidence_derivatives r
                   WHERE NOT EXISTS (
                       SELECT 1 FROM evidence_deletions d
                       WHERE d.artifact_type = 'redaction' AND d.artifact_id = r.derivative_id
                   )"""
            )
        }

    @staticmethod
    def _source_digests(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            """SELECT content_hash, encrypted_blob_ref, blob_status, encryption_version
               FROM source_documents"""
        ).fetchall()
        digests: set[str] = set()
        for row in rows:
            digest = str(row[0])
            if (
                not _digest(digest)
                or row[1] != f"encrypted-source:v1:{digest}"
                or row[2] != "available"
                or row[3] != "aes-256-gcm-v1"
            ):
                raise BackupError("BACKUP_SOURCE_INVALID", "source metadata is invalid")
            digests.add(digest)
        return digests

    @staticmethod
    def _atomic_write(destination: Path, content: bytes) -> None:
        temporary = destination.parent / f".{destination.name}.{uuid4().hex}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            BackupService._fsync_directory(destination.parent)
        except OSError as exc:
            raise BackupError(
                "BACKUP_WRITE_FAILED", "encrypted backup could not be persisted"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _remove_drill(path: Path) -> None:
        if not path.exists():
            return
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        path.rmdir()

    def _report(
        self, manifest: dict[str, object], envelope: bytes, destination: Path, *, status: str
    ) -> dict[str, object]:
        report = {
            "schema_version": "2.0.0",
            "backup_id": manifest["backup_id"],
            "status": status,
            "created_at": manifest["created_at"],
            "database_sha256": manifest["database_sha256"],
            "audit_head_hash": manifest["audit_head_hash"],
            "evidence_blob_count": len(cast(list[object], manifest["evidence_sha256"])),
            "source_blob_count": len(cast(list[object], manifest.get("source_sha256", []))),
            "deletion_tombstone_count": len(cast(list[object], manifest["deletion_tombstones"])),
            "encrypted_backup_sha256": hashlib.sha256(envelope).hexdigest(),
            "destination": destination.name,
            "live_data_replaced": False,
        }
        if contract_issues(report, "backup-restore-report-v2.schema.json"):
            raise BackupError("BACKUP_CONTRACT_INVALID", "backup report contract is invalid")
        return report


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return parse_time(value).tzinfo is not None
    except ValueError:
        return False
