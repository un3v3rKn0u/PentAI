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
from test_orchestration_retry_attempt import setup as attempt_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryScheduleService, dict[str, object], dict[str, object]]:
    attempts, attempt_command, _ = attempt_setup(tmp_path)
    attempt = attempts.register(attempt_command, now=NOW + timedelta(seconds=5))
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "expected_plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "expected_task_revision": attempt["task_revision"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "purpose": "register_validation_retry_schedule",
        "requested_at": (NOW + timedelta(seconds=6)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryScheduleService(attempts.authorization), command, attempt


def test_registers_immutable_inert_schedule_with_derived_time(tmp_path: Path) -> None:
    service, command, attempt = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=6))
    assert contract_issues(receipt, "orchestration-retry-schedule-receipt-v1.schema.json") == ()
    assert receipt["attempt_id"] == attempt["attempt_id"]
    assert receipt["attempt_digest"] == attempt["attempt_digest"]
    assert receipt["scheduled_for"] == attempt["earliest_retry_at"]
    assert receipt["schedule_revision"] == 1
    assert receipt["schedule_state"] == "registered"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=6)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone()
        attempt_state = connection.execute(
            "SELECT attempt_state FROM orchestration_retry_attempts WHERE attempt_id = ?",
            (attempt["attempt_id"],),
        ).fetchone()
        active_leases = connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
        ).fetchone()[0]
        grants = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
        schedules = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_schedules"
        ).fetchone()[0]
    assert task == ("failed", command["expected_task_revision"])
    assert attempt_state == ("registered",)
    assert active_leases == 0
    assert grants == 1
    assert schedules == 1


def test_rejects_caller_timing_state_worker_budget_and_authority(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    for field, value in (
        ("scheduled_for", (NOW + timedelta(minutes=2)).isoformat()),
        ("backoff_seconds", 1),
        ("priority", 10),
        ("retryable", True),
        ("schedule_state", "active"),
        ("worker_id", "caller-worker"),
        ("budget_units", 1),
        ("authority", "grant"),
    ):
        candidate = copy.deepcopy(command)
        candidate[field] = value
        with pytest.raises(OrchestrationRetryScheduleError) as malformed:
            service.register(candidate, now=NOW + timedelta(seconds=6))
        assert malformed.value.code == "ORCHESTRATION_RETRY_SCHEDULE_COMMAND_MALFORMED"


def test_malformed_stale_premature_and_cross_scope_inputs_deny(tmp_path: Path) -> None:
    cases = (
        (
            {"attempt_digest": "sha256:" + "0" * 64},
            "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISMATCH",
            NOW + timedelta(seconds=6),
        ),
        (
            {"assessment_id": str(uuid4())},
            "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISMATCH",
            NOW + timedelta(seconds=6),
        ),
        (
            {"requested_at": (NOW + timedelta(seconds=4)).isoformat()},
            "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISMATCH",
            NOW + timedelta(seconds=4),
        ),
        (
            {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
            "ORCHESTRATION_RETRY_SCHEDULE_COMMAND_STALE",
            NOW + timedelta(seconds=6),
        ),
    )
    for index, (changes, code, instant) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryScheduleError) as denied:
            service.register(command, now=instant)
        assert denied.value.code == code


def test_missing_attempt_changed_replay_and_competing_schedule_deny(tmp_path: Path) -> None:
    missing_service, missing_command, _ = setup(tmp_path / "missing")
    missing_command["attempt_id"] = str(uuid4())
    with pytest.raises(OrchestrationRetryScheduleError) as missing:
        missing_service.register(missing_command, now=NOW + timedelta(seconds=6))
    assert missing.value.code == "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISSING"

    service, command, _ = setup(tmp_path / "replay")
    service.register(command, now=NOW + timedelta(seconds=6))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=45)).isoformat()
    with pytest.raises(OrchestrationRetryScheduleError) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=6))
    assert conflict.value.code == "ORCHESTRATION_RETRY_SCHEDULE_IDENTITY_CONFLICT"

    concurrent, contender, _ = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, object]) -> str:
        try:
            receipt = concurrent.register(candidate, now=NOW + timedelta(seconds=6))
            return str(receipt["schedule_id"])
        except OrchestrationRetryScheduleError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_SCHEDULE_") for value in outcomes) == 1
    with closing(sqlite3.connect(concurrent.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_schedules"
        ).fetchone()[0] == 1


def test_safety_worker_budget_policy_and_recovery_fences_deny(tmp_path: Path) -> None:
    cases = ("safety", "worker", "budget", "policy", "recovery")
    for name in cases:
        service, command, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=(SELECT worker_id
                    FROM orchestration_task_leases LIMIT 1)"""
                )
            elif name == "budget":
                connection.execute(
                    """UPDATE orchestration_task_budget_reservations SET state='released',
                    released_at=?, release_reason='recovery'""",
                    ((NOW + timedelta(seconds=7)).isoformat(),),
                )
            elif name == "policy":
                connection.execute(
                    "UPDATE policy_bundles SET revoked_at=?",
                    ((NOW + timedelta(seconds=7)).isoformat(),),
                )
            else:
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
        with pytest.raises(OrchestrationRetryScheduleError) as denied:
            service.register(command, now=NOW + timedelta(seconds=8))
        assert denied.value.code == "ORCHESTRATION_RETRY_SCHEDULE_SECURITY_DENIED"


def test_schedule_storage_is_immutable(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=6))
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_retry_schedules SET schedule_state='active' WHERE schedule_id=?",
            (receipt["schedule_id"],),
        )
