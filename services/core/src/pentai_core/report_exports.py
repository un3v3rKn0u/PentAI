from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction

_TABLES = {
    "findings": "report_draft_artifacts",
    "no_findings": "no_findings_report_artifacts",
}
_EXTENSIONS = {"markdown": "md", "html": "html", "json": "json", "pdf": "pdf"}


class ReportExportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReportExportService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def export(
        self,
        report_id: str,
        *,
        report_kind: str,
        format_name: str,
        destination_directory: Path,
        confirm_restricted_export: bool,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        _uuid(report_id)
        if report_kind not in _TABLES or format_name not in _EXTENSIONS:
            raise ReportExportError("REPORT_EXPORT_REQUEST_INVALID", "export request is invalid")
        if confirm_restricted_export is not True:
            raise ReportExportError(
                "REPORT_EXPORT_CONFIRMATION_REQUIRED", "restricted export requires confirmation"
            )
        if not 1 <= len(actor_id.strip()) <= 128:
            raise ReportExportError("REPORT_EXPORT_ACTOR_INVALID", "human actor is invalid")
        try:
            destination = destination_directory.resolve(strict=True)
        except OSError as exc:
            raise ReportExportError(
                "REPORT_EXPORT_DESTINATION_INVALID", "destination directory is unavailable"
            ) from exc
        if not destination.is_dir() or destination_directory.is_symlink():
            raise ReportExportError(
                "REPORT_EXPORT_DESTINATION_INVALID", "destination must be an existing directory"
            )
        directory_digest = sha256(os.fsencode(destination)).hexdigest()
        filename = f"{report_id}.{_EXTENSIONS[format_name]}"
        target = destination / filename

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            approval = connection.execute(
                """SELECT * FROM report_export_approvals
                   WHERE report_kind = ? AND report_id = ?""",
                (report_kind, report_id),
            ).fetchone()
            if approval is None:
                raise ReportExportError(
                    "REPORT_EXPORT_APPROVAL_REQUIRED", "exact report approval is required"
                )
            approval_document = cast(dict[str, Any], json.loads(approval["document_json"]))
            artifact = connection.execute(
                f"SELECT content, sha256, size_bytes FROM {_TABLES[report_kind]} "  # noqa: S608
                "WHERE report_id = ? AND format = ?",
                (report_id, format_name),
            ).fetchone()
            if artifact is None:
                raise ReportExportError("REPORT_EXPORT_ARTIFACT_MISSING", "artifact is missing")
            content = bytes(artifact["content"])
            digest = sha256(content).hexdigest()
            if (
                content_hash(approval_document) != approval["content_hash"]
                or approval_document.get("export_ready") is not True
                or approval_document.get("artifact_digests", {}).get(format_name) != digest
                or artifact["sha256"] != digest
                or artifact["size_bytes"] != len(content)
            ):
                raise ReportExportError(
                    "REPORT_EXPORT_INTEGRITY_FAILED", "approved artifact integrity failed"
                )
            existing = connection.execute(
                """SELECT document_json FROM report_file_exports
                   WHERE report_kind = ? AND report_id = ? AND format = ?
                   AND destination_directory_sha256 = ?""",
                (report_kind, report_id, format_name, directory_digest),
            ).fetchone()
            if existing is not None:
                document = cast(dict[str, Any], json.loads(existing["document_json"]))
                if target.is_file() and sha256(target.read_bytes()).hexdigest() == digest:
                    return document
                raise ReportExportError(
                    "REPORT_EXPORT_STATE_CONFLICT", "recorded export does not match destination"
                )
            self._publish_exclusive(target, content)
            exported_at = _timestamp(now)
            document = {
                "schema_version": "1.0.0",
                "export_id": str(uuid4()),
                "report_id": report_id,
                "report_kind": report_kind,
                "approval_id": approval["approval_id"],
                "format": format_name,
                "artifact_sha256": digest,
                "size_bytes": len(content),
                "filename": filename,
                "classification": "restricted",
                "exported_by": actor_id,
                "exported_at": exported_at,
                "submission_enabled": False,
            }
            if contract_issues(document, "report-file-export-v1.schema.json"):
                target.unlink(missing_ok=True)
                raise ReportExportError("REPORT_EXPORT_CONTRACT_INVALID", "contract is invalid")
            try:
                connection.execute(
                    """INSERT INTO report_file_exports(
                        export_id, report_id, report_kind, approval_id, format,
                        artifact_sha256, size_bytes, filename, destination_directory_sha256,
                        exported_by, exported_at, document_json, content_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        document["export_id"], report_id, report_kind, approval["approval_id"],
                        format_name, digest, len(content), filename, directory_digest, actor_id,
                        exported_at, canonical_json(document), content_hash(document),
                    ),
                )
                append_audit_event(
                    connection,
                    action="report.file_exported",
                    subject_type="report",
                    subject_id=report_id,
                    actor_type="human",
                    actor_id=actor_id,
                    data={
                        "export_id": document["export_id"],
                        "approval_id": approval["approval_id"],
                        "report_kind": report_kind,
                        "format": format_name,
                        "artifact_sha256": digest,
                        "filename": filename,
                        "classification": "restricted",
                        "submission_enabled": False,
                    },
                    occurred_at=exported_at,
                )
            except Exception:
                target.unlink(missing_ok=True)
                raise
        return document

    @staticmethod
    def _publish_exclusive(target: Path, content: bytes) -> None:
        temporary = target.parent / f".{target.name}.{uuid4().hex}.tmp"
        published = False
        try:
            with temporary.open("xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                raise ReportExportError(
                    "REPORT_EXPORT_DESTINATION_EXISTS", "export destination already exists"
                ) from exc
            published = True
            temporary.unlink()
            if os.name != "nt":
                descriptor = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except OSError as exc:
            if published:
                target.unlink(missing_ok=True)
            raise ReportExportError("REPORT_EXPORT_WRITE_FAILED", "file export failed") from exc
        finally:
            temporary.unlink(missing_ok=True)


def _uuid(value: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportExportError("REPORT_EXPORT_ID_INVALID", "report id is invalid") from exc


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ReportExportError("REPORT_EXPORT_TIME_INVALID", "time must include timezone")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")
