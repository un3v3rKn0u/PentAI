from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pentai_core.findings import FindingService
from pentai_core.reports import ReportError, ReportService
from pentai_policy.document import contract_issues
from test_findings import create_finding, finding_fixture


def report_ready_finding(tmp_path: Path, *, title: str = "<script>alert(1)</script>"):
    database, workflow_id, asset_id, evidence_id, findings, _ = finding_fixture(tmp_path)
    finding = create_finding(
        findings, workflow_id, asset_id, evidence_id, title=title
    )
    reviewed = findings.transition(
        str(finding["finding_id"]),
        target_state="scope_reviewed",
        expected_version=1,
        reason="Exact policy scope confirmed",
        actor_id="local-reviewer",
    )
    duplicate_reviewed = findings.transition(
        str(finding["finding_id"]),
        target_state="duplicate_reviewed",
        expected_version=2,
        duplicate_status="clear",
        reason="No duplicate exists",
        actor_id="local-reviewer",
    )
    validated = findings.transition(
        str(finding["finding_id"]),
        target_state="validated",
        expected_version=3,
        validation_status="confirmed",
        reason="Human validated the synthetic evidence",
        actor_id="local-reviewer",
    )
    ready = findings.transition(
        str(finding["finding_id"]),
        target_state="report_ready",
        expected_version=4,
        reason="Human reviewed report content",
        actor_id="local-reviewer",
    )
    assert [reviewed["version"], duplicate_reviewed["version"], validated["version"]] == [
        2,
        3,
        4,
    ]
    return database, workflow_id, finding, ready, ReportService(database)


def test_human_requested_report_draft_renders_four_immutable_formats(tmp_path: Path) -> None:
    database, workflow_id, _, ready, reports = report_ready_finding(tmp_path)
    draft = reports.create_draft(
        workflow_id,
        idempotency_key="report-draft-fixture-0001",
        title="Synthetic Assessment Report",
        template="hackerone",
        finding_ids=[str(ready["finding_id"])],
        actor_id="local-reviewer",
        now=datetime(2026, 8, 12, tzinfo=UTC),
    )
    assert contract_issues(draft, "report-draft-v1.schema.json") == ()
    assert draft["status"] == "draft"
    assert draft["finding_refs"] == [
        {
            "finding_id": ready["finding_id"],
            "version": 5,
            "content_hash": _finding_hash(database, str(ready["finding_id"])),
        }
    ]
    assert {item["format"] for item in draft["artifacts"]} == {
        "markdown",
        "html",
        "json",
        "pdf",
    }

    markdown = reports.artifact(str(draft["report_id"]), "markdown")[1]
    html = reports.artifact(str(draft["report_id"]), "html")[1]
    json_body = reports.artifact(str(draft["report_id"]), "json")[1]
    pdf = reports.artifact(str(draft["report_id"]), "pdf")[1]
    assert b"<script>alert(1)</script>" in markdown
    assert b"<script>" not in html
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert json.loads(json_body)["findings"][0]["finding_id"] == ready["finding_id"]
    assert pdf.startswith(b"%PDF-1.4") and pdf.endswith(b"%%EOF\n")
    for descriptor in draft["artifacts"]:
        content = reports.artifact(str(draft["report_id"]), descriptor["format"])[1]
        assert sha256(content).hexdigest() == descriptor["sha256"]
        assert len(content) == descriptor["size_bytes"]

    assert reports.get(str(draft["report_id"])) == draft
    assert reports.create_draft(
        workflow_id,
        idempotency_key="report-draft-fixture-0001",
        title="Synthetic Assessment Report",
        template="hackerone",
        finding_ids=[str(ready["finding_id"])],
        actor_id="local-reviewer",
    ) == draft
    with closing(sqlite3.connect(database)) as connection:
        audit = connection.execute(
            "SELECT action, data_json FROM audit_events WHERE subject_type = 'report'"
        ).fetchone()
        assert audit is not None and audit[0] == "report.draft_created"
        assert json.loads(audit[1])["status"] == "draft"
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE report_drafts SET title = 'forged' WHERE report_id = ?",
                (draft["report_id"],),
            )


def test_report_generation_denies_unready_foreign_and_conflicting_inputs(tmp_path: Path) -> None:
    _, workflow_id, original, ready, reports = report_ready_finding(tmp_path)
    cases = [
        ([str(original["finding_id"])], "REPORT_FINDING_NOT_READY"),
        ([str(ready["finding_id"]), str(ready["finding_id"])], "REPORT_FINDINGS_INVALID"),
        (["00000000-0000-0000-0000-000000000000"], "REPORT_FINDING_NOT_READY"),
    ]
    # The original and ready documents share an identity; close it through the real lifecycle.
    FindingService(reports.database_path).transition(
        str(ready["finding_id"]),
        target_state="closed",
        expected_version=5,
        reason="Report denial fixture is now closed",
        actor_id="local-reviewer",
    )
    for finding_ids, expected in cases:
        with pytest.raises(ReportError) as raised:
            reports.create_draft(
                workflow_id,
                idempotency_key=f"report-denial-{expected.lower()}",
                title="Denied report",
                template="generic",
                finding_ids=finding_ids,
                actor_id="local-reviewer",
            )
        assert raised.value.code == expected


def test_report_idempotency_conflict_and_unknown_format_deny(tmp_path: Path) -> None:
    _, workflow_id, _, ready, reports = report_ready_finding(tmp_path)
    draft = reports.create_draft(
        workflow_id,
        idempotency_key="report-conflict-fixture",
        title="Original title",
        template="generic",
        finding_ids=[str(ready["finding_id"])],
        actor_id="local-reviewer",
    )
    with pytest.raises(ReportError) as raised:
        reports.create_draft(
            workflow_id,
            idempotency_key="report-conflict-fixture",
            title="Changed title",
            template="generic",
            finding_ids=[str(ready["finding_id"])],
            actor_id="local-reviewer",
        )
    assert raised.value.code == "REPORT_IDEMPOTENCY_CONFLICT"
    with pytest.raises(ReportError) as raised:
        reports.artifact(str(draft["report_id"]), "docx")
    assert raised.value.code == "REPORT_FORMAT_INVALID"


def _finding_hash(database: Path, finding_id: str) -> str:
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT content_hash FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    assert row is not None
    return str(row[0])
