from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from pentai_core.orchestration_retry import OrchestrationRetryError
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry import setup


def test_issues_closed_v2_policy_without_evaluation_or_authority(tmp_path: Path) -> None:
    service, _, v1 = setup(tmp_path)
    policy = service.issue_policy_v2(
        assessment_id=v1["assessment_id"],
        policy_bundle_id=v1["policy_bundle_id"],
        policy_hash=v1["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW,
    )
    assert contract_issues(policy, "orchestration-retry-policy-v2.schema.json") == ()
    assert policy["failure_contract_version"] == "2.0.0"
    assert policy["attempt_contract_version"] == "2.0.0"
    assert policy["maximum_attempts"] == 3
    assert policy["backoff_seconds"] == [5, 30]
    assert policy["authority"] == "none" and policy["execution_enabled"] is False
    assert service.issue_policy_v2(
        assessment_id=v1["assessment_id"],
        policy_bundle_id=v1["policy_bundle_id"],
        policy_hash=v1["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW,
    ) == policy
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_decisions_v2"
        ).fetchone()[0] == 0
        task = connection.execute(
            """SELECT state FROM orchestration_tasks
            WHERE task_id=(SELECT task_id FROM orchestration_task_attempts LIMIT 1)"""
        ).fetchone()
        assert task == ("failed",)


def test_v2_policy_denies_stale_safety_and_identity_conflict(tmp_path: Path) -> None:
    service, _, v1 = setup(tmp_path)
    common = {
        "assessment_id": v1["assessment_id"],
        "policy_bundle_id": v1["policy_bundle_id"],
        "policy_hash": v1["policy_hash"],
    }
    with pytest.raises(OrchestrationRetryError) as stale:
        service.issue_policy_v2(
            **common, expires_at=NOW + timedelta(hours=2), now=NOW
        )
    assert stale.value.code == "ORCHESTRATION_RETRY_POLICY_STALE"

    accepted = service.issue_policy_v2(
        **common, expires_at=NOW + timedelta(minutes=2), now=NOW
    )
    with pytest.raises(OrchestrationRetryError) as conflict:
        service.issue_policy_v2(
            **common, expires_at=NOW + timedelta(minutes=3), now=NOW
        )
    assert conflict.value.code == "ORCHESTRATION_RETRY_POLICY_IDENTITY_CONFLICT"
    assert accepted["schema_version"] == "2.0.0"

    paused, _, paused_v1 = setup(tmp_path / "paused")
    with closing(sqlite3.connect(paused.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationRetryError) as safety:
        paused.issue_policy_v2(
            assessment_id=paused_v1["assessment_id"],
            policy_bundle_id=paused_v1["policy_bundle_id"],
            policy_hash=paused_v1["policy_hash"],
            expires_at=NOW + timedelta(minutes=2),
            now=NOW,
        )
    assert safety.value.code == "ORCHESTRATION_RETRY_POLICY_SECURITY_DENIED"


def test_v2_policy_storage_is_version_exact_and_immutable(tmp_path: Path) -> None:
    service, _, v1 = setup(tmp_path)
    policy = service.issue_policy_v2(
        assessment_id=v1["assessment_id"],
        policy_bundle_id=v1["policy_bundle_id"],
        policy_hash=v1["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW,
    )
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_retry_policies_v2 SET authority='grant'
                WHERE retry_policy_id=?""",
                (policy["retry_policy_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_policies_v2 WHERE retry_policy_id=?",
                (policy["retry_policy_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_retry_policies_v2
                SELECT ?, assessment_id, policy_bundle_id, policy_hash, revision,
                replace(policy_json, '2.0.0', '1.0.0'), ?, issued_at, expires_at,
                authority, execution_enabled FROM orchestration_retry_policies_v2
                WHERE retry_policy_id=?""",
                (v1["retry_policy_id"], "sha256:" + "0" * 64, policy["retry_policy_id"]),
            )
