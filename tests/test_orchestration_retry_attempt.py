from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration_retry_attempt import (
    OrchestrationRetryAttemptError,
    OrchestrationRetryAttemptService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_budget import setup as budget_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryAttemptService, dict[str, object], dict[str, object]]:
    budget, consumption_command, _ = budget_setup(tmp_path)
    consumption = budget.consume(consumption_command, now=NOW + timedelta(seconds=5))
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": consumption["assessment_id"],
        "plan_id": consumption["plan_id"],
        "expected_plan_revision": consumption["plan_revision"],
        "task_id": consumption["task_id"],
        "expected_task_revision": consumption["task_revision"],
        "prior_attempt_id": consumption["attempt_id"],
        "prior_attempt_digest": consumption["attempt_digest"],
        "retry_budget_consumption_id": consumption["consumption_id"],
        "retry_budget_consumption_digest": consumption["receipt_digest"],
        "attempt_number": 2,
        "purpose": "register_validation_retry_attempt",
        "requested_at": (NOW + timedelta(seconds=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryAttemptService(budget.authorization), command, consumption


def test_registers_immutable_attempt_two_without_activation(tmp_path: Path) -> None:
    service, command, consumption = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=5))
    assert contract_issues(receipt, "orchestration-retry-attempt-receipt-v1.schema.json") == ()
    assert receipt["prior_attempt_id"] == consumption["attempt_id"]
    assert receipt["retry_budget_consumption_id"] == consumption["consumption_id"]
    assert receipt["attempt_number"] == 2
    assert receipt["attempt_state"] == "registered"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=5)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone()
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_task_attempts").fetchone()[0]
            == 1
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_retry_attempts").fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1
    assert task == ("failed", command["expected_task_revision"])


def test_rejects_caller_attempt_state_schedule_and_authority(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    for field, value in (
        ("attempt_number", 3),
        ("attempt_state", "ready"),
        ("schedule_at", (NOW + timedelta(minutes=1)).isoformat()),
        ("retryable", True),
        ("worker_id", "caller-selected-worker"),
        ("authority", "grant"),
    ):
        candidate = copy.deepcopy(command)
        candidate[field] = value
        with pytest.raises(OrchestrationRetryAttemptError) as malformed:
            service.register(candidate, now=NOW + timedelta(seconds=5))
        assert malformed.value.code == "ORCHESTRATION_RETRY_ATTEMPT_COMMAND_MALFORMED"


def test_malformed_stale_premature_and_cross_scope_inputs_deny(tmp_path: Path) -> None:
    cases = (
        (
            {"retry_budget_consumption_digest": "sha256:" + "0" * 64},
            "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_MISMATCH",
            NOW + timedelta(seconds=5),
        ),
        (
            {"assessment_id": str(uuid4())},
            "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_MISMATCH",
            NOW + timedelta(seconds=5),
        ),
        (
            {
                "requested_at": (NOW + timedelta(seconds=4)).isoformat(),
                "expires_at": (NOW + timedelta(seconds=30)).isoformat(),
            },
            "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_MISMATCH",
            NOW + timedelta(seconds=4),
        ),
        (
            {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
            "ORCHESTRATION_RETRY_ATTEMPT_COMMAND_STALE",
            NOW + timedelta(seconds=5),
        ),
    )
    for index, (changes, code, instant) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryAttemptError) as denied:
            service.register(command, now=instant)
        assert denied.value.code == code


def test_changed_replay_and_concurrent_competing_registration_deny(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path / "replay")
    service.register(command, now=NOW + timedelta(seconds=5))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=45)).isoformat()
    with pytest.raises(OrchestrationRetryAttemptError) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=5))
    assert conflict.value.code == "ORCHESTRATION_RETRY_ATTEMPT_IDENTITY_CONFLICT"

    concurrent, contender, _ = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, object]) -> str:
        try:
            return str(concurrent.register(candidate, now=NOW + timedelta(seconds=5))["attempt_id"])
        except OrchestrationRetryAttemptError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_ATTEMPT_") for value in outcomes) == 1
    with closing(sqlite3.connect(concurrent.database_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_retry_attempts").fetchone()[0]
            == 1
        )


def test_safety_worker_budget_recovery_and_replay_fences_deny(tmp_path: Path) -> None:
    safety_service, safety_command, _ = setup(tmp_path / "safety")
    with closing(sqlite3.connect(safety_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationRetryAttemptError) as safety:
        safety_service.register(safety_command, now=NOW + timedelta(seconds=5))
    assert safety.value.code == "ORCHESTRATION_RETRY_ATTEMPT_SECURITY_DENIED"

    worker_service, worker_command, _ = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=(SELECT worker_id FROM orchestration_task_leases
            LIMIT 1)"""
        )
    with pytest.raises(OrchestrationRetryAttemptError) as worker:
        worker_service.register(worker_command, now=NOW + timedelta(seconds=5))
    assert worker.value.code == "ORCHESTRATION_RETRY_ATTEMPT_SECURITY_DENIED"

    recovery_service, recovery_command, _ = setup(tmp_path / "recovery")
    with closing(sqlite3.connect(recovery_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET state='released',
            released_at=?, release_reason='recovery'""",
            ((NOW + timedelta(seconds=6)).isoformat(),),
        )
    with pytest.raises(OrchestrationRetryAttemptError) as recovery:
        recovery_service.register(recovery_command, now=NOW + timedelta(seconds=7))
    assert recovery.value.code == "ORCHESTRATION_RETRY_ATTEMPT_SECURITY_DENIED"

    replay_service, replay_command, _ = setup(tmp_path / "fenced-replay")
    replay_service.register(replay_command, now=NOW + timedelta(seconds=5))
    with closing(sqlite3.connect(replay_service.database_path)) as connection, connection:
        connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
    with pytest.raises(OrchestrationRetryAttemptError) as replay:
        replay_service.register(replay_command, now=NOW + timedelta(seconds=5))
    assert replay.value.code == "ORCHESTRATION_RETRY_ATTEMPT_SECURITY_DENIED"


def test_retry_attempt_storage_is_immutable(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=5))
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            """UPDATE orchestration_retry_attempts SET attempt_state='ready'
            WHERE attempt_id=?""",
            (receipt["attempt_id"],),
        )
