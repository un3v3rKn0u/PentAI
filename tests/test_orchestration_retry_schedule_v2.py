from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration_retry_schedule import (
    OrchestrationRetryScheduleError,
    OrchestrationRetryScheduleService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_attempt_v2 import setup as attempt_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryScheduleService, dict[str, object], dict[str, object]]:
    attempts, attempt_command = attempt_setup(tmp_path)
    attempt = attempts.register(attempt_command, now=NOW + timedelta(seconds=40))
    command: dict[str, object] = {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "expected_plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "expected_task_revision": attempt["task_revision"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "purpose": "register_validation_retry_schedule_three",
        "requested_at": (NOW + timedelta(seconds=41)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=55)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryScheduleService(attempts.authorization), command, attempt


def test_registers_inert_attempt_three_schedule_with_derived_time(tmp_path: Path) -> None:
    service, command, attempt = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        decision_time = connection.execute(
            "SELECT json_extract(decision_json, '$.earliest_retry_at') "
            "FROM orchestration_retry_decisions_v2 WHERE decision_id=?",
            (attempt["eligibility_decision_id"],),
        ).fetchone()[0]
        account_version = connection.execute(
            "SELECT version FROM orchestration_budget_accounts"
        ).fetchone()[0]
    receipt = service.register(command, now=NOW + timedelta(seconds=41))
    assert contract_issues(receipt, "orchestration-retry-schedule-receipt-v2.schema.json") == ()
    assert receipt["attempt_number"] == 3
    assert receipt["scheduled_for"] == decision_time
    assert receipt["schedule_state"] == "registered"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=41)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("failed",)
        assert connection.execute(
            "SELECT attempt_state FROM orchestration_retry_attempts_v2 WHERE attempt_id=?",
            (attempt["attempt_id"],),
        ).fetchone() == ("registered",)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_schedules_v2"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT version FROM orchestration_budget_accounts"
        ).fetchone() == (account_version,)


def test_rejects_mixed_versions_caller_timing_attempt_four_and_authority(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "1.0.0"},
        {"attempt_number": 4},
        {"scheduled_for": (NOW + timedelta(minutes=2)).isoformat()},
        {"backoff_seconds": 1},
        {"priority": 10},
        {"retryable": True},
        {"worker_id": "caller-worker"},
        {"authority": "grant"},
    )
    for index, changes in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryScheduleError) as denied:
            service.register(command, now=NOW + timedelta(seconds=41))
        assert denied.value.code == "ORCHESTRATION_RETRY_SCHEDULE_COMMAND_MALFORMED"


def test_premature_tampered_cross_scope_and_expired_inputs_deny(tmp_path: Path) -> None:
    cases = (
        ({"requested_at": (NOW + timedelta(seconds=39)).isoformat()}, NOW + timedelta(seconds=39)),
        ({"attempt_digest": "sha256:" + "0" * 64}, NOW + timedelta(seconds=41)),
        ({"assessment_id": str(uuid4())}, NOW + timedelta(seconds=41)),
        ({"expires_at": (NOW + timedelta(minutes=10)).isoformat()}, NOW + timedelta(seconds=41)),
    )
    for index, (changes, instant) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryScheduleError):
            service.register(command, now=instant)


def test_changed_replay_concurrency_and_security_fences(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path / "replay")
    accepted = service.register(command, now=NOW + timedelta(seconds=41))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=50)).isoformat()
    with pytest.raises(OrchestrationRetryScheduleError) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=41))
    assert conflict.value.code == "ORCHESTRATION_RETRY_SCHEDULE_IDENTITY_CONFLICT"
    assert service.register(command, now=NOW + timedelta(seconds=41)) == accepted

    concurrent, contender, _ = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, object]) -> str:
        try:
            return str(
                concurrent.register(candidate, now=NOW + timedelta(seconds=41))["schedule_id"]
            )
        except OrchestrationRetryScheduleError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_SCHEDULE_") for value in outcomes) == 1

    for name in ("safety", "cancel", "worker", "recovery"):
        fenced, fenced_command, _ = setup(tmp_path / name)
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
        with pytest.raises(OrchestrationRetryScheduleError):
            fenced.register(fenced_command, now=NOW + timedelta(seconds=41))


def test_storage_is_immutable_and_direct_bypass_denies(tmp_path: Path) -> None:
    service, command, attempt = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=41))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_retry_schedules_v2 SET schedule_state='active' "
                "WHERE schedule_id=?",
                (receipt["schedule_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_schedules_v2 WHERE schedule_id=?",
                (receipt["schedule_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_retry_schedules_v2 (
                schedule_id, command_id, command_digest, assessment_id, plan_id,
                plan_revision, task_id, task_revision, attempt_id,
                retry_budget_consumption_id, eligibility_decision_id, schedule_revision,
                schedule_state, scheduled_for, expires_at, receipt_json, receipt_hash,
                registered_at, authority, execution_enabled
                ) SELECT ?, ?, command_digest, assessment_id, plan_id, plan_revision,
                task_id, task_revision, attempt_id, retry_budget_consumption_id,
                eligibility_decision_id, 1, 'registered', scheduled_for, expires_at,
                receipt_json, receipt_hash, registered_at, 'none', 0
                FROM orchestration_retry_schedules_v2 WHERE schedule_id=?""",
                (str(uuid4()), str(uuid4()), receipt["schedule_id"]),
            )
    assert attempt["attempt_number"] == 3
