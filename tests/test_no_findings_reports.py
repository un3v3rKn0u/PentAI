from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pentai_core.coverage import AssessmentCoverageService
from pentai_core.no_findings_reports import NoFindingsReportError, NoFindingsReportService
from pentai_policy.document import contract_issues
from test_coverage import record
from test_findings import finding_fixture


def no_findings_fixture(
    tmp_path: Path, *, outcome: str = "tested_no_findings", complete: bool = True
):
    database, workflow_id, asset_id, evidence_id, _, _ = finding_fixture(tmp_path)
    coverage = record(
        AssessmentCoverageService(database),
        workflow_id,
        asset_id,
        evidence_id,
        outcome=outcome,
        evidence_ids=[] if outcome == "blocked" else [evidence_id],
    )
    if complete:
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(
                """UPDATE assessment_workflows SET status = 'completed', version = 4,
                   updated_at = '2026-08-11T03:00:00Z', finalized_at = '2026-08-11T03:00:00Z'
                   WHERE workflow_id = ?""",
                (workflow_id,),
            )
    return database, workflow_id, asset_id, evidence_id, coverage, NoFindingsReportService(database)


def create(service, workflow_id, coverage_id, **overrides):
    values = {
        "idempotency_key": "no-findings-fixture-0001",
        "title": "Synthetic No Findings Report",
        "template": "generic",
        "coverage_ids": [coverage_id],
        "actor_id": "local-reviewer",
        "now": datetime(2026, 8, 12, tzinfo=UTC),
    }
    values.update(overrides)
    return service.create_draft(workflow_id, **values)


def test_complete_coverage_renders_immutable_no_findings_draft(tmp_path: Path) -> None:
    database, workflow_id, _, _, coverage, service = no_findings_fixture(tmp_path)
    draft = create(service, workflow_id, coverage["coverage_id"])
    assert contract_issues(draft, "no-findings-report-draft-v1.schema.json") == ()
    assert draft["report_kind"] == "no_findings" and draft["status"] == "draft"
    assert draft["coverage_refs"][0]["coverage_id"] == coverage["coverage_id"]
    assert create(service, workflow_id, coverage["coverage_id"]) == draft
    assert service.get(draft["report_id"]) == draft
    body = service.artifact(draft["report_id"], "json")[1]
    assert json.loads(body)["statement"].startswith("No findings were identified")
    for descriptor in draft["artifacts"]:
        artifact = service.artifact(draft["report_id"], descriptor["format"])[1]
        assert sha256(artifact).hexdigest() == descriptor["sha256"]
    with closing(sqlite3.connect(database)) as connection:
        audit = connection.execute(
            "SELECT action FROM audit_events WHERE action = 'report.no_findings_draft_created'"
        ).fetchone()
        assert audit is not None
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE no_findings_report_drafts SET title = 'forged' WHERE report_id = ?",
                (draft["report_id"],),
            )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("running", "NO_FINDINGS_WORKFLOW_INCOMPLETE"),
        ("missing", "NO_FINDINGS_COVERAGE_MISSING"),
        ("blocked", "NO_FINDINGS_COVERAGE_INSUFFICIENT"),
        ("finding", "NO_FINDINGS_FINDINGS_PRESENT"),
        ("evidence_deleted", "NO_FINDINGS_EVIDENCE_UNAVAILABLE"),
    ],
)
def test_no_findings_generation_fails_closed(tmp_path: Path, mutation: str, code: str) -> None:
    database, workflow_id, asset_id, evidence_id, coverage, service = no_findings_fixture(
        tmp_path,
        outcome="blocked" if mutation == "blocked" else "tested_no_findings",
        complete=mutation != "running",
    )
    selected = coverage["coverage_id"]
    with closing(sqlite3.connect(database)) as connection, connection:
        if mutation == "finding":
            connection.execute("DROP TRIGGER findings_no_delete")
            connection.execute(
                """INSERT INTO findings(
                    finding_id, workflow_id, engagement_id, policy_bundle_id,
                    idempotency_key, state, version, title, severity, cvss_vector,
                    cvss_score, cwe, confidence, validation_status, duplicate_status,
                    affected_asset_rule_ids_json, evidence_ids_json, reproduction, impact,
                    remediation, references_json, fingerprint, created_by, created_at,
                    updated_at, document_json, content_hash
                ) SELECT '50000000-0000-4000-8000-000000000001', workflow_id,
                    engagement_id, policy_bundle_id, 'synthetic-no-findings-finding',
                    'candidate', 1, 'Synthetic', 'informational',
                    'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0.0, 'CWE-1', 1,
                    'unverified', 'pending', ?, ?, 'x', 'x', 'x', '[]', ?, 'human',
                    created_at, created_at, '{}', ? FROM assessment_workflows
                    WHERE workflow_id = ?""",
                (
                    json.dumps([asset_id]),
                    json.dumps([evidence_id]),
                    "a" * 64,
                    "b" * 64,
                    workflow_id,
                ),
            )
        elif mutation == "evidence_deleted":
            connection.execute(
                """INSERT INTO evidence_deletions(
                    deletion_id, artifact_type, artifact_id, policy_bundle_id, sha256,
                    retention_days, retention_deadline, reason, requested_by, requested_at,
                    request_hash, status, version, forensic_erase_guaranteed
                ) SELECT '60000000-0000-4000-8000-000000000001', 'original', evidence_id,
                    policy_bundle_id, sha256, 1, '2026-08-12T00:00:00Z', 'synthetic',
                    'human', '2026-08-12T00:00:00Z', ?, 'pending', 1, 0
                  FROM evidence_objects WHERE evidence_id = ?""",
                ("c" * 64, evidence_id),
            )
    if mutation == "missing":
        selected = "70000000-0000-4000-8000-000000000001"
    with pytest.raises(NoFindingsReportError) as raised:
        create(service, workflow_id, selected)
    assert raised.value.code == code


def test_matrix_requires_every_allowed_policy_pair(tmp_path: Path) -> None:
    database, workflow_id, _, _, coverage, service = no_findings_fixture(tmp_path)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER immutable_active_policy_update")
        row = connection.execute(
            """SELECT p.id, p.policy_json FROM policy_bundles p JOIN assessment_workflows w
               ON w.policy_bundle_id = p.id WHERE w.workflow_id = ?""",
            (workflow_id,),
        ).fetchone()
        policy = json.loads(row[1])
        policy["capability_rules"].append(
            {
                "rule_id": "80000000-0000-4000-8000-000000000001",
                "capability": "http.head",
                "effect": "allow",
                "applicable_asset_rule_ids": [coverage["asset_rule_id"]],
            }
        )
        connection.execute(
            "UPDATE policy_bundles SET policy_json = ? WHERE id = ?", (json.dumps(policy), row[0])
        )
    with pytest.raises(NoFindingsReportError) as raised:
        create(service, workflow_id, coverage["coverage_id"])
    assert raised.value.code == "NO_FINDINGS_COVERAGE_INCOMPLETE"
