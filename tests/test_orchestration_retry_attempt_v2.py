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
from test_orchestration_retry_budget_v2 import setup as budget_setup


def setup(tmp_path: Path) -> tuple[OrchestrationRetryAttemptService, dict[str, object]]:
    budget, budget_command = budget_setup(tmp_path)
    consumption = budget.consume(budget_command, now=NOW + timedelta(seconds=40))
    command: dict[str, object] = {
        "schema_version": "2.0.0",
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
        "attempt_number": 3,
        "purpose": "register_validation_retry_attempt_three",
        "requested_at": (NOW + timedelta(seconds=40)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryAttemptService(budget.authorization), command


def test_registers_inert_attempt_three_exactly_once(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        version_before = connection.execute(
            "SELECT version FROM orchestration_budget_accounts"
        ).fetchone()[0]
        schedules_before = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_schedules"
        ).fetchone()[0]
    receipt = service.register(command, now=NOW + timedelta(seconds=40))
    assert contract_issues(receipt, "orchestration-retry-attempt-receipt-v2.schema.json") == ()
    assert receipt["attempt_number"] == 3
    assert receipt["attempt_state"] == "registered"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=40)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("failed",)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts_v2"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_schedules"
        ).fetchone() == (schedules_before,)
        assert connection.execute(
            "SELECT version FROM orchestration_budget_accounts"
        ).fetchone() == (version_before,)


def test_malformed_mixed_tampered_and_attempt_four_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "1.0.0"},
        {"attempt_number": 4},
        {"prior_attempt_digest": "sha256:" + "0" * 64},
        {"retry_budget_consumption_digest": "sha256:" + "0" * 64},
        {"remaining_retry_units": 10},
        {"authority": "grant"},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryAttemptError):
            service.register(command, now=NOW + timedelta(seconds=40))


def test_replay_concurrency_and_security_fences(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    accepted = service.register(command, now=NOW + timedelta(seconds=40))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=55)).isoformat()
    with pytest.raises(OrchestrationRetryAttemptError) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=40))
    assert conflict.value.code == "ORCHESTRATION_RETRY_ATTEMPT_IDENTITY_CONFLICT"
    assert service.register(command, now=NOW + timedelta(seconds=40)) == accepted

    concurrent, contender = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, object]) -> str:
        try:
            return str(
                concurrent.register(candidate, now=NOW + timedelta(seconds=40))["attempt_id"]
            )
        except OrchestrationRetryAttemptError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_ATTEMPT_") for value in outcomes) == 1

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
        with pytest.raises(OrchestrationRetryAttemptError):
            fenced.register(fenced_command, now=NOW + timedelta(seconds=40))


def test_storage_is_immutable_and_direct_bypass_denies(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.register(command, now=NOW + timedelta(seconds=40))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_retry_attempts_v2 SET authority='grant' WHERE attempt_id=?",
                (receipt["attempt_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_attempts_v2 WHERE attempt_id=?",
                (receipt["attempt_id"],),
            )
