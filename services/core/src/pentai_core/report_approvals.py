from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction

_REPORT_TABLES = {
    "findings": ("report_drafts", "report_draft_artifacts"),
    "no_findings": ("no_findings_report_drafts", "no_findings_report_artifacts"),
}
_FORMATS = {"markdown", "html", "json", "pdf"}


class ReportApprovalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReportApprovalService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def approve(
        self,
        report_id: str,
        *,
        report_kind: str,
        expected_status: str,
        reason: str,
        confirm_export_ready: bool,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        _uuid(report_id, "REPORT_APPROVAL_ID_INVALID")
        if report_kind not in _REPORT_TABLES:
            raise ReportApprovalError("REPORT_APPROVAL_KIND_INVALID", "report kind is invalid")
        if expected_status != "draft" or confirm_export_ready is not True:
            raise ReportApprovalError(
                "REPORT_APPROVAL_CONFIRMATION_REQUIRED", "exact draft confirmation is required"
            )
        normalized_reason = reason.strip()
        if not 1 <= len(normalized_reason) <= 1000:
            raise ReportApprovalError("REPORT_APPROVAL_REASON_INVALID", "reason is invalid")
        if not 1 <= len(actor_id.strip()) <= 128:
            raise ReportApprovalError("REPORT_APPROVAL_ACTOR_INVALID", "human actor is invalid")
        approved_at = _timestamp(now)
        report_table, artifact_table = _REPORT_TABLES[report_kind]
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT document_json FROM report_export_approvals
                   WHERE report_kind = ? AND report_id = ?""",
                (report_kind, report_id),
            ).fetchone()
            if existing is not None:
                raise ReportApprovalError(
                    "REPORT_APPROVAL_ALREADY_DECIDED", "report already has an approval decision"
                )
            report = connection.execute(
                f"SELECT * FROM {report_table} WHERE report_id = ?",  # noqa: S608 -- fixed map
                (report_id,),
            ).fetchone()
            if report is None:
                raise ReportApprovalError("REPORT_APPROVAL_NOT_FOUND", "report draft is missing")
            try:
                report_document = cast(dict[str, Any], json.loads(report["document_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ReportApprovalError(
                    "REPORT_APPROVAL_INTEGRITY_FAILED", "report metadata is invalid"
                ) from exc
            if (
                report_document.get("status") != "draft"
                or content_hash(report_document) != report["content_hash"]
                or report_document.get("report_id") != report_id
            ):
                raise ReportApprovalError(
                    "REPORT_APPROVAL_INTEGRITY_FAILED", "report metadata integrity failed"
                )
            artifact_rows = connection.execute(
                f"SELECT format, content, sha256 FROM {artifact_table} WHERE report_id = ?",  # noqa: S608 -- fixed map
                (report_id,),
            ).fetchall()
            digests = {str(row["format"]): str(row["sha256"]) for row in artifact_rows}
            if set(digests) != _FORMATS or any(
                sha256(bytes(row["content"])).hexdigest() != row["sha256"]
                for row in artifact_rows
            ):
                raise ReportApprovalError(
                    "REPORT_APPROVAL_INTEGRITY_FAILED", "report artifact integrity failed"
                )
            approval_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "approval_id": approval_id,
                "approval_type": "report_export",
                "report_id": report_id,
                "report_kind": report_kind,
                "workflow_id": report["workflow_id"],
                "policy_bundle_id": report["policy_bundle_id"],
                "report_content_hash": report["content_hash"],
                "artifact_digests": digests,
                "expected_status": "draft",
                "decision": "approved",
                "reason": normalized_reason,
                "approver": {"actor_type": "human", "actor_id": actor_id},
                "approved_at": approved_at,
                "export_ready": True,
                "submission_enabled": False,
            }
            _valid(document)
            digest = content_hash(document)
            connection.execute(
                """INSERT INTO report_export_approvals(
                    approval_id, report_id, report_kind, workflow_id, policy_bundle_id,
                    report_content_hash, artifact_digests_json, expected_status,
                    decision, reason, approver_id, approved_at, document_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', 'approved', ?, ?, ?, ?, ?)""",
                (
                    approval_id,
                    report_id,
                    report_kind,
                    report["workflow_id"],
                    report["policy_bundle_id"],
                    report["content_hash"],
                    canonical_json(digests),
                    normalized_reason,
                    actor_id,
                    approved_at,
                    canonical_json(document),
                    digest,
                ),
            )
            append_audit_event(
                connection,
                action="report.export_approved",
                subject_type="report",
                subject_id=report_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "approval_id": approval_id,
                    "report_kind": report_kind,
                    "workflow_id": report["workflow_id"],
                    "policy_bundle_id": report["policy_bundle_id"],
                    "report_content_hash": report["content_hash"],
                    "artifact_digests": digests,
                    "export_ready": True,
                    "submission_enabled": False,
                },
                occurred_at=approved_at,
            )
        return document

    def get(self, report_id: str, *, report_kind: str) -> dict[str, Any]:
        _uuid(report_id, "REPORT_APPROVAL_ID_INVALID")
        if report_kind not in _REPORT_TABLES:
            raise ReportApprovalError("REPORT_APPROVAL_KIND_INVALID", "report kind is invalid")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT document_json FROM report_export_approvals
                   WHERE report_kind = ? AND report_id = ?""",
                (report_kind, report_id),
            ).fetchone()
        if row is None:
            raise ReportApprovalError("REPORT_APPROVAL_NOT_FOUND", "approval is missing")
        document = cast(dict[str, Any], json.loads(row["document_json"]))
        _valid(document)
        return document


def _valid(document: dict[str, Any]) -> None:
    if contract_issues(document, "report-export-approval-v1.schema.json"):
        raise ReportApprovalError("REPORT_APPROVAL_CONTRACT_INVALID", "contract is invalid")


def _uuid(value: str, code: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportApprovalError(code, "identifier is invalid") from exc


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ReportApprovalError("REPORT_APPROVAL_TIME_INVALID", "time must include timezone")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")
