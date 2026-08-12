from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pentai_core.report_approvals import ReportApprovalError, ReportApprovalService
from pentai_policy.document import contract_issues
from test_no_findings_reports import create as create_no_findings
from test_no_findings_reports import no_findings_fixture
from test_reports import report_ready_finding


def findings_draft(tmp_path: Path):
    database, workflow_id, _, ready, reports = report_ready_finding(tmp_path)
    draft = reports.create_draft(
        workflow_id,
        idempotency_key="approval-report-fixture-0001",
        title="Synthetic Finding Report",
        template="generic",
        finding_ids=[str(ready["finding_id"])],
        actor_id="local-reviewer",
        now=datetime(2026, 8, 12, tzinfo=UTC),
    )
    return database, draft, ReportApprovalService(database)


def approve(service, report_id, **overrides):
    values = {
        "report_kind": "findings",
        "expected_status": "draft",
        "reason": "Human reviewed the complete synthetic report and its artifacts.",
        "confirm_export_ready": True,
        "actor_id": "local-reviewer",
        "now": datetime(2026, 8, 12, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return service.approve(report_id, **values)


def test_human_approval_binds_exact_report_and_artifact_digests(tmp_path: Path) -> None:
    database, draft, service = findings_draft(tmp_path)
    approval = approve(service, draft["report_id"])
    assert contract_issues(approval, "report-export-approval-v1.schema.json") == ()
    assert approval["export_ready"] is True
    assert approval["submission_enabled"] is False
    assert approval["artifact_digests"] == {
        item["format"]: item["sha256"] for item in draft["artifacts"]
    }
    assert service.get(draft["report_id"], report_kind="findings") == approval
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT action, data_json FROM audit_events WHERE action = 'report.export_approved'"
        ).fetchone()
        assert row is not None and json.loads(row[1])["submission_enabled"] is False
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE report_export_approvals SET reason = 'forged' WHERE approval_id = ?",
                (approval["approval_id"],),
            )


def test_no_findings_draft_uses_same_exact_approval_boundary(tmp_path: Path) -> None:
    database, workflow_id, _, _, coverage, reports = no_findings_fixture(tmp_path)
    draft = create_no_findings(reports, workflow_id, coverage["coverage_id"])
    service = ReportApprovalService(database)
    approval = approve(
        service,
        draft["report_id"],
        report_kind="no_findings",
        reason="Human reviewed coverage, evidence references, and limitations.",
    )
    assert approval["report_kind"] == "no_findings"
    assert approval["report_content_hash"]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"confirm_export_ready": False}, "REPORT_APPROVAL_CONFIRMATION_REQUIRED"),
        ({"expected_status": "export_ready"}, "REPORT_APPROVAL_CONFIRMATION_REQUIRED"),
        ({"report_kind": "unknown"}, "REPORT_APPROVAL_KIND_INVALID"),
        ({"reason": "   "}, "REPORT_APPROVAL_REASON_INVALID"),
    ],
)
def test_report_approval_defaults_deny(overrides: dict, code: str, tmp_path: Path) -> None:
    _, draft, service = findings_draft(tmp_path)
    with pytest.raises(ReportApprovalError) as raised:
        approve(service, draft["report_id"], **overrides)
    assert raised.value.code == code


def test_report_cannot_be_approved_twice(tmp_path: Path) -> None:
    _, draft, service = findings_draft(tmp_path)
    approve(service, draft["report_id"])
    with pytest.raises(ReportApprovalError) as raised:
        approve(service, draft["report_id"])
    assert raised.value.code == "REPORT_APPROVAL_ALREADY_DECIDED"


def test_changed_artifact_denies_approval(tmp_path: Path) -> None:
    database, draft, service = findings_draft(tmp_path)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER report_artifacts_immutable")
        connection.execute(
            "UPDATE report_draft_artifacts SET content = ? WHERE report_id = ? AND format = 'json'",
            (b"{}", draft["report_id"]),
        )
    with pytest.raises(ReportApprovalError) as raised:
        approve(service, draft["report_id"])
    assert raised.value.code == "REPORT_APPROVAL_INTEGRITY_FAILED"
