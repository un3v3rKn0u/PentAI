from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.evidence import EvidenceService
from pentai_core.findings import FindingError, FindingService, _cvss_score
from pentai_policy.document import contract_issues
from test_evidence_originals import EVIDENCE_ASSET_RULE_ID, capture, evidence_fixture

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


def finding_fixture(
    tmp_path: Path,
) -> tuple[Path, str, str, str, FindingService, EvidenceService]:
    database, workflow_id, evidence_service, _ = evidence_fixture(tmp_path)
    asset_rule_id = EVIDENCE_ASSET_RULE_ID
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        workflow = connection.execute(
            "SELECT policy_bundle_id FROM assessment_workflows WHERE workflow_id = ?",
            (workflow_id,),
        ).fetchone()
        assert workflow is not None
        connection.execute(
            """UPDATE assessment_workflows
               SET status = 'running', version = 3, updated_at = '2026-08-11T00:01:00Z',
                   started_at = '2026-08-11T00:01:00Z'
               WHERE workflow_id = ?""",
            (workflow_id,),
        )
    evidence = capture(evidence_service, workflow_id)
    return (
        database,
        workflow_id,
        asset_rule_id,
        str(evidence["evidence_id"]),
        FindingService(database),
        evidence_service,
    )


def create_finding(
    service: FindingService,
    workflow_id: str,
    asset_rule_id: str,
    evidence_id: str,
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "idempotency_key": "finding-fixture-0001",
        "title": "Synthetic authorization boundary weakness",
        "severity": "medium",
        "cvss_vector": VECTOR,
        "cvss_score": 6.5,
        "cwe": "CWE-284",
        "confidence": 90,
        "affected_asset_rule_ids": [asset_rule_id],
        "evidence_ids": [evidence_id],
        "reproduction": "Use the owned synthetic fixture and observe the bounded response.",
        "impact": "The synthetic fixture demonstrates an authorization boundary mismatch.",
        "remediation": "Require exact policy and evidence linkage before reporting.",
        "references": ["https://example.invalid/synthetic-guidance"],
        "actor_id": "local-reviewer",
    }
    values.update(overrides)
    return service.create(workflow_id, **values)  # type: ignore[arg-type]


def test_human_supervised_finding_lifecycle_is_versioned_and_audited(tmp_path: Path) -> None:
    database, workflow_id, asset_id, evidence_id, service, _ = finding_fixture(tmp_path)
    finding = create_finding(service, workflow_id, asset_id, evidence_id)
    assert contract_issues(finding, "finding-v1.schema.json") == ()
    assert create_finding(service, workflow_id, asset_id, evidence_id) == finding

    reviewed = service.transition(
        str(finding["finding_id"]),
        target_state="scope_reviewed",
        expected_version=1,
        reason="Confirmed against the exact active policy snapshot",
        actor_id="local-reviewer",
    )
    deduplicated = service.transition(
        str(finding["finding_id"]),
        target_state="duplicate_reviewed",
        expected_version=2,
        duplicate_status="clear",
        reason="No matching synthetic finding exists",
        actor_id="local-reviewer",
    )
    validated = service.transition(
        str(finding["finding_id"]),
        target_state="validated",
        expected_version=3,
        validation_status="confirmed",
        reason="Human confirmed the bounded reproduction evidence",
        actor_id="local-reviewer",
    )
    report_ready = service.transition(
        str(finding["finding_id"]),
        target_state="report_ready",
        expected_version=4,
        reason="Finding content is ready for a future report draft",
        actor_id="local-reviewer",
    )
    closed = service.transition(
        str(finding["finding_id"]),
        target_state="closed",
        expected_version=5,
        reason="Synthetic lifecycle completed",
        actor_id="local-reviewer",
    )

    assert [reviewed["state"], deduplicated["state"], validated["state"]] == [
        "scope_reviewed",
        "duplicate_reviewed",
        "validated",
    ]
    assert report_ready["state"] == "report_ready"
    assert closed["state"] == "closed"
    assert closed["version"] == 6
    assert [item["version"] for item in service.history(str(finding["finding_id"]))] == list(
        range(1, 7)
    )
    with closing(sqlite3.connect(database)) as connection:
        actions = [
            row[0]
            for row in connection.execute(
                "SELECT action FROM audit_events WHERE subject_type = 'finding' ORDER BY sequence"
            )
        ]
    assert actions == ["finding.created", *("finding.transitioned" for _ in range(5))]


def test_scope_evidence_cvss_and_idempotency_fail_closed(tmp_path: Path) -> None:
    _, workflow_id, asset_id, evidence_id, service, _ = finding_fixture(tmp_path)
    finding = create_finding(service, workflow_id, asset_id, evidence_id)
    cases = (
        (
            {"idempotency_key": "finding-fixture-0001", "title": "Conflict"},
            "FINDING_IDEMPOTENCY_CONFLICT",
        ),
        ({"idempotency_key": "finding-fixture-0002", "cvss_score": 6.4}, "FINDING_CVSS_INVALID"),
        (
            {"idempotency_key": "finding-fixture-0003", "severity": "high"},
            "FINDING_SEVERITY_INVALID",
        ),
        (
            {"idempotency_key": "finding-fixture-0004", "affected_asset_rule_ids": [str(uuid4())]},
            "FINDING_ASSET_OUT_OF_SCOPE",
        ),
        (
            {"idempotency_key": "finding-fixture-0005", "evidence_ids": [str(uuid4())]},
            "FINDING_EVIDENCE_MISMATCH",
        ),
        (
            {"idempotency_key": "finding-fixture-0006", "cwe": "CWE-0"},
            "FINDING_CLASSIFICATION_INVALID",
        ),
    )
    for override, code in cases:
        with pytest.raises(FindingError) as denied:
            create_finding(service, workflow_id, asset_id, evidence_id, **override)
        assert denied.value.code == code
    assert service.get(str(finding["finding_id"])) == finding


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss31_golden_vectors_are_recomputed(vector: str, score: float) -> None:
    assert _cvss_score(vector) == score


def test_deleted_and_cross_workflow_evidence_cannot_support_a_finding(tmp_path: Path) -> None:
    _, workflow_id, asset_id, evidence_id, service, evidence_service = finding_fixture(
        tmp_path / "first"
    )
    _, _, _, other_evidence_id, _, _ = finding_fixture(tmp_path / "second")
    with pytest.raises(FindingError) as crossed:
        create_finding(
            service,
            workflow_id,
            asset_id,
            other_evidence_id,
            idempotency_key="finding-cross-workflow",
        )
    assert crossed.value.code == "FINDING_EVIDENCE_MISMATCH"

    metadata = evidence_service.metadata(evidence_id, actor_id="local-reviewer")["evidence"]
    evidence_service.delete_artifact(
        "original",
        evidence_id,
        expected_sha256=str(metadata["sha256"]),
        reason="Synthetic retention-complete finding test",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=datetime.now(UTC) + timedelta(days=2),
    )
    with pytest.raises(FindingError) as deleted:
        create_finding(
            service,
            workflow_id,
            asset_id,
            evidence_id,
            idempotency_key="finding-deleted-evidence",
        )
    assert deleted.value.code == "FINDING_EVIDENCE_MISMATCH"


def test_transitions_require_ordered_human_review_and_fencing(tmp_path: Path) -> None:
    _, workflow_id, asset_id, evidence_id, service, _ = finding_fixture(tmp_path)
    finding = create_finding(service, workflow_id, asset_id, evidence_id)
    finding_id = str(finding["finding_id"])
    with pytest.raises(FindingError) as skipped:
        service.transition(
            finding_id,
            target_state="validated",
            expected_version=1,
            validation_status="confirmed",
            duplicate_status="clear",
            reason="Attempted skipped review",
            actor_id="local-reviewer",
        )
    assert skipped.value.code == "FINDING_TRANSITION_DENIED"
    service.transition(
        finding_id,
        target_state="scope_reviewed",
        expected_version=1,
        reason="Scope checked",
        actor_id="local-reviewer",
    )
    with pytest.raises(FindingError) as stale:
        service.transition(
            finding_id,
            target_state="duplicate_reviewed",
            expected_version=1,
            duplicate_status="clear",
            reason="Stale review",
            actor_id="local-reviewer",
        )
    assert stale.value.code == "FINDING_FENCED"
    with pytest.raises(FindingError) as pending:
        service.transition(
            finding_id,
            target_state="duplicate_reviewed",
            expected_version=2,
            reason="Missing duplicate outcome",
            actor_id="local-reviewer",
        )
    assert pending.value.code == "FINDING_DUPLICATE_REQUIRED"


def test_duplicate_review_is_scoped_and_records_rejection(tmp_path: Path) -> None:
    _, workflow_id, asset_id, evidence_id, service, _ = finding_fixture(tmp_path)
    original = create_finding(service, workflow_id, asset_id, evidence_id)
    duplicate = create_finding(
        service,
        workflow_id,
        asset_id,
        evidence_id,
        idempotency_key="finding-fixture-duplicate",
        title="Synthetic authorization boundary weakness duplicate",
    )
    scoped = service.transition(
        str(duplicate["finding_id"]),
        target_state="scope_reviewed",
        expected_version=1,
        reason="Scope checked",
        actor_id="local-reviewer",
    )
    reviewed = service.transition(
        str(duplicate["finding_id"]),
        target_state="duplicate_reviewed",
        expected_version=int(scoped["version"]),
        duplicate_status="duplicate",
        duplicate_of=str(original["finding_id"]),
        reason="Matched the original synthetic finding",
        actor_id="local-reviewer",
    )
    rejected = service.transition(
        str(duplicate["finding_id"]),
        target_state="rejected",
        expected_version=int(reviewed["version"]),
        reason="Closed as a reviewed duplicate",
        actor_id="local-reviewer",
    )
    assert rejected["duplicate_of"] == original["finding_id"]
    assert rejected["state"] == "rejected"


def test_finding_current_and_version_history_cannot_be_deleted_or_forged(tmp_path: Path) -> None:
    database, workflow_id, asset_id, evidence_id, service, _ = finding_fixture(tmp_path)
    finding = create_finding(service, workflow_id, asset_id, evidence_id)
    with closing(sqlite3.connect(database)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError, match="transition"):
            connection.execute(
                "UPDATE findings SET title = 'forged' WHERE finding_id = ?",
                (finding["finding_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="version chain"):
            connection.execute(
                """INSERT INTO finding_versions(
                       version_id, finding_id, version, document_json, content_hash,
                       transition_reason, author_type, author_id, created_at
                   ) VALUES (?, ?, 3, '{}', ?, 'forged', 'human', 'forger',
                             '2026-08-11T00:00:00Z')""",
                (str(uuid4()), finding["finding_id"], "c" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM finding_versions WHERE finding_id = ?", (finding["finding_id"],)
            )
        with pytest.raises(sqlite3.IntegrityError, match="history cannot be deleted"):
            connection.execute(
                "DELETE FROM findings WHERE finding_id = ?", (finding["finding_id"],)
            )
