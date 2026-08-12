from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pentai_core.report_exports import ReportExportError, ReportExportService
from pentai_policy.document import contract_issues
from test_report_approvals import approve, findings_draft


def approved_report(tmp_path: Path):
    database, draft, approvals = findings_draft(tmp_path)
    approval = approve(approvals, draft["report_id"])
    return database, draft, approval, ReportExportService(database)


def export(service, report_id, destination, **overrides):
    values = {
        "report_kind": "findings",
        "format_name": "markdown",
        "destination_directory": destination,
        "confirm_restricted_export": True,
        "actor_id": "local-reviewer",
        "now": datetime(2026, 8, 12, 2, tzinfo=UTC),
    }
    values.update(overrides)
    return service.export(report_id, **values)


def test_export_writes_exact_approved_artifact_and_audits_receipt(tmp_path: Path) -> None:
    database, draft, approval, service = approved_report(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()

    receipt = export(service, draft["report_id"], destination)

    assert contract_issues(receipt, "report-file-export-v1.schema.json") == ()
    assert receipt["approval_id"] == approval["approval_id"]
    assert receipt["submission_enabled"] is False
    exported = destination / receipt["filename"]
    assert exported.read_bytes().startswith(b"# Synthetic Finding Report")
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT data_json FROM audit_events WHERE action = 'report.file_exported'"
        ).fetchone()
        assert row is not None
        data = json.loads(row[0])
        assert "destination_directory" not in data
        assert data["submission_enabled"] is False


def test_export_requires_exact_human_approval(tmp_path: Path) -> None:
    database, draft, _ = findings_draft(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()

    with pytest.raises(ReportExportError) as raised:
        export(ReportExportService(database), draft["report_id"], destination)

    assert raised.value.code == "REPORT_EXPORT_APPROVAL_REQUIRED"
    assert list(destination.iterdir()) == []


def test_export_refuses_overwrite(tmp_path: Path) -> None:
    _, draft, _, service = approved_report(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()
    target = destination / f"{draft['report_id']}.md"
    target.write_text("user content", encoding="utf-8")

    with pytest.raises(ReportExportError) as raised:
        export(service, draft["report_id"], destination)

    assert raised.value.code == "REPORT_EXPORT_DESTINATION_EXISTS"
    assert target.read_text(encoding="utf-8") == "user content"
    assert list(destination.glob(".*.tmp")) == []


def test_export_defaults_deny_without_confirmation_or_valid_directory(tmp_path: Path) -> None:
    _, draft, _, service = approved_report(tmp_path)
    with pytest.raises(ReportExportError) as confirmation:
        export(
            service,
            draft["report_id"],
            tmp_path,
            confirm_restricted_export=False,
        )
    assert confirmation.value.code == "REPORT_EXPORT_CONFIRMATION_REQUIRED"

    with pytest.raises(ReportExportError) as destination:
        export(service, draft["report_id"], tmp_path / "missing")
    assert destination.value.code == "REPORT_EXPORT_DESTINATION_INVALID"


def test_identical_retry_returns_receipt_but_changed_file_denies(tmp_path: Path) -> None:
    _, draft, _, service = approved_report(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()
    first = export(service, draft["report_id"], destination)
    assert export(service, draft["report_id"], destination) == first

    (destination / first["filename"]).write_text("changed", encoding="utf-8")
    with pytest.raises(ReportExportError) as raised:
        export(service, draft["report_id"], destination)
    assert raised.value.code == "REPORT_EXPORT_STATE_CONFLICT"


def test_audit_failure_removes_unrecorded_file(tmp_path: Path) -> None:
    _, draft, _, service = approved_report(tmp_path)
    destination = tmp_path / "exports"
    destination.mkdir()

    with (
        patch("pentai_core.report_exports.append_audit_event", side_effect=RuntimeError("fault")),
        pytest.raises(RuntimeError, match="fault"),
    ):
        export(service, draft["report_id"], destination)

    assert list(destination.iterdir()) == []
