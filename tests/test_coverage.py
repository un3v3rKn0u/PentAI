from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pentai_core.coverage import AssessmentCoverageService, CoverageError
from pentai_policy.document import contract_issues
from test_evidence_originals import EVIDENCE_CAPABILITY_RULE_ID
from test_findings import finding_fixture


def coverage_fixture(tmp_path: Path):
    database, workflow_id, asset_rule_id, evidence_id, _, _ = finding_fixture(tmp_path)
    return database, workflow_id, asset_rule_id, evidence_id, AssessmentCoverageService(database)


def record(service, workflow_id, default_asset_rule_id, evidence_id, **overrides):
    values = {
        "idempotency_key": "coverage-fixture-0001",
        "asset_rule_id": default_asset_rule_id,
        "capability_rule_id": EVIDENCE_CAPABILITY_RULE_ID,
        "capability": "http.get",
        "outcome": "tested_no_findings",
        "started_at": datetime(2026, 8, 11, 1, tzinfo=UTC),
        "ended_at": datetime(2026, 8, 11, 2, tzinfo=UTC),
        "evidence_ids": [evidence_id],
        "limitations": ["Only the synthetic authenticated path was exercised."],
        "notes": "Human reviewed the bounded synthetic request and response.",
        "actor_id": "local-reviewer",
        "now": datetime(2026, 8, 12, tzinfo=UTC),
    }
    values.update(overrides)
    return service.record(workflow_id, **values)


def test_human_coverage_is_policy_bound_immutable_and_audited(tmp_path: Path) -> None:
    database, workflow_id, asset_id, evidence_id, service = coverage_fixture(tmp_path)
    coverage = record(service, workflow_id, asset_id, evidence_id)
    assert contract_issues(coverage, "assessment-coverage-v1.schema.json") == ()
    assert coverage["coverage_complete"] is False
    assert service.list_for_workflow(workflow_id) == [coverage]
    assert record(service, workflow_id, asset_id, evidence_id) == coverage

    with closing(sqlite3.connect(database)) as connection:
        audit = connection.execute(
            "SELECT action, data_json FROM audit_events WHERE subject_type = 'assessment_coverage'"
        ).fetchone()
        assert audit is not None and audit[0] == "coverage.recorded"
        assert json.loads(audit[1])["coverage_complete"] is False
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE assessment_coverage SET notes = 'forged' WHERE coverage_id = ?",
                (coverage["coverage_id"],),
            )


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"evidence_ids": []}, "COVERAGE_EVIDENCE_REQUIRED"),
        (
            {"evidence_ids": ["40000000-0000-4000-8000-000000000001"]},
            "COVERAGE_EVIDENCE_UNAVAILABLE",
        ),
        ({"asset_rule_id": "30000000-0000-4000-8000-000000000001"}, "COVERAGE_ASSET_DENIED"),
        ({"capability": "http.post"}, "COVERAGE_CAPABILITY_DENIED"),
        ({"outcome": "complete"}, "COVERAGE_OUTCOME_INVALID"),
        (
            {
                "started_at": datetime(2026, 8, 11, 3, tzinfo=UTC),
                "ended_at": datetime(2026, 8, 11, 2, tzinfo=UTC),
            },
            "COVERAGE_INTERVAL_INVALID",
        ),
    ],
)
def test_coverage_claims_fail_closed(tmp_path: Path, overrides: dict, code: str) -> None:
    _, workflow_id, asset_id, evidence_id, service = coverage_fixture(tmp_path)
    with pytest.raises(CoverageError) as raised:
        record(service, workflow_id, asset_id, evidence_id, **overrides)
    assert raised.value.code == code


def test_gap_outcomes_are_explicit_and_idempotency_cannot_change_claim(tmp_path: Path) -> None:
    _, workflow_id, asset_id, evidence_id, service = coverage_fixture(tmp_path)
    gap = record(
        service,
        workflow_id,
        asset_id,
        evidence_id,
        outcome="blocked",
        evidence_ids=[],
        idempotency_key="coverage-gap-fixture-0001",
        limitations=["Authentication fixture was unavailable."],
    )
    assert gap["outcome"] == "blocked" and gap["coverage_complete"] is False
    with pytest.raises(CoverageError) as raised:
        record(
            service,
            workflow_id,
            asset_id,
            evidence_id,
            idempotency_key="coverage-gap-fixture-0001",
        )
    assert raised.value.code == "COVERAGE_IDEMPOTENCY_CONFLICT"
