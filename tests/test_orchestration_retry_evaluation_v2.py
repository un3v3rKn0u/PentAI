from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.orchestration_retry import OrchestrationRetryError, OrchestrationRetryService
from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_failed_attempt import setup as attempt_setup


def setup(tmp_path: Path) -> tuple[OrchestrationRetryService, dict[str, Any]]:
    attempts, attempt_command = attempt_setup(tmp_path)
    attempt = attempts.register(attempt_command, now=NOW + timedelta(seconds=10))
    service = OrchestrationRetryService(attempts.authorization)
    policy = service.issue_policy_v2(
        assessment_id=attempt["assessment_id"],
        policy_bundle_id=attempt["policy_bundle_id"],
        policy_hash=attempt["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW + timedelta(seconds=10),
    )
    command = {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "expected_plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "expected_task_revision": attempt["task_revision"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "retry_policy_id": policy["retry_policy_id"],
        "retry_policy_revision": policy["revision"],
        "retry_policy_digest": policy["policy_digest"],
        "purpose": "evaluate_retry_validation_attempt",
        "requested_at": (NOW + timedelta(seconds=10)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return service, command


def test_evaluates_attempt_two_without_consumption_or_activation(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        consumption_before = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_budget_consumptions"
        ).fetchone()[0]
    decision = service.evaluate(command, now=NOW + timedelta(seconds=10))
    assert contract_issues(decision, "orchestration-retry-decision-v2.schema.json") == ()
    assert decision["outcome"] == "denied"
    assert decision["reason_code"] == "RETRY_DENIED_CAPACITY_UNAVAILABLE"
    assert decision["current_attempt_number"] == 2
    assert decision["proposed_attempt_number"] == 3
    assert decision["earliest_retry_at"] is None
    assert decision["retry_units_consumed"] == 0
    assert decision["authority"] == "none" and decision["execution_enabled"] is False
    assert service.evaluate(command, now=NOW + timedelta(seconds=10)) == decision
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("failed",)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_budget_consumptions"
        ).fetchone()[0] == consumption_before


def test_rejects_mixed_versions_tampering_and_caller_semantics(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "1.0.0"},
        {"attempt_digest": "sha256:" + "0" * 64},
        {"retry_policy_digest": "sha256:" + "0" * 64},
        {"current_attempt_number": 2},
        {"retryable": True},
        {"backoff_seconds": 1},
        {"authority": "grant"},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryError):
            service.evaluate(command, now=NOW + timedelta(seconds=10))


def test_closed_outcome_derivation_allows_only_policy_and_capacity(tmp_path: Path) -> None:
    database = tmp_path / "outcome.db"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """CREATE TABLE orchestration_retry_budget_consumptions (
            consumption_id TEXT PRIMARY KEY, receipt_json TEXT, receipt_hash TEXT)"""
        )
        receipt = {
            "consumption_id": "consumption-synthetic",
            "assessment_id": "assessment-synthetic",
            "plan_id": "plan-synthetic",
            "task_id": "task-synthetic",
            "remaining_retry_units": 1,
        }
        connection.execute(
            "INSERT INTO orchestration_retry_budget_consumptions VALUES (?, ?, ?)",
            ("consumption-synthetic", canonical_json(receipt), content_hash(receipt)),
        )
        attempt = {
            "attempt_number": 2,
            "retry_budget_consumption_id": "consumption-synthetic",
            "assessment_id": "assessment-synthetic",
            "plan_id": "plan-synthetic",
            "task_id": "task-synthetic",
            "failure_class": "coordination_timeout",
        }
        policy = {
            "maximum_attempts": 3,
            "eligible_failure_classes": ["coordination_timeout"],
        }
        assert OrchestrationRetryService._retry_attempt_outcome(
            connection, attempt, policy
        ) == ("eligible", "RETRY_ELIGIBLE_TRANSIENT_FAILURE")
        attempt["failure_class"] = "checkpoint_stalled"
        assert OrchestrationRetryService._retry_attempt_outcome(
            connection, attempt, policy
        ) == ("denied", "RETRY_DENIED_MANUAL_REVIEW_REQUIRED")
        attempt["attempt_number"] = 3
        assert OrchestrationRetryService._retry_attempt_outcome(
            connection, attempt, policy
        ) == ("denied", "RETRY_DENIED_ATTEMPT_LIMIT")


def test_changed_replay_concurrency_and_security_fences_deny(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    accepted = service.evaluate(command, now=NOW + timedelta(seconds=10))
    conflict = copy.deepcopy(command)
    conflict["expires_at"] = (NOW + timedelta(seconds=50)).isoformat()
    with pytest.raises(OrchestrationRetryError) as reused:
        service.evaluate(conflict, now=NOW + timedelta(seconds=10))
    assert reused.value.code == "ORCHESTRATION_RETRY_EVALUATION_IDENTITY_CONFLICT"
    assert service.evaluate(command, now=NOW + timedelta(seconds=10)) == accepted

    concurrent, contender = setup(tmp_path / "concurrent")
    commands = (copy.deepcopy(contender), copy.deepcopy(contender))
    commands[1]["command_id"] = str(uuid4())

    def evaluate(candidate: dict[str, Any]) -> str:
        try:
            result = concurrent.evaluate(candidate, now=NOW + timedelta(seconds=10))
            return str(result["decision_id"])
        except OrchestrationRetryError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(evaluate, commands))
    assert sum(value.startswith("ORCHESTRATION_RETRY_") for value in outcomes) == 1

    for name in ("safety", "cancel", "worker", "recovery"):
        fenced, fenced_command = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    "UPDATE engagements SET status='revoked' WHERE id=?",
                    (fenced_command["assessment_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id='worker:synthetic:retry-lease'"""
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (fenced_command["task_id"],),
                )
        with pytest.raises(OrchestrationRetryError) as denied:
            fenced.evaluate(fenced_command, now=NOW + timedelta(seconds=10))
        assert denied.value.code == "ORCHESTRATION_RETRY_SECURITY_DENIED"


def test_storage_is_immutable_and_rejects_direct_bypass(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    decision = service.evaluate(command, now=NOW + timedelta(seconds=10))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_retry_decisions_v2 SET authority='grant'
                WHERE decision_id=?""",
                (decision["decision_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_decisions_v2 WHERE decision_id=?",
                (decision["decision_id"],),
            )
