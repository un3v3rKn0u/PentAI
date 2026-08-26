from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_retry_activation import (
    OrchestrationRetryActivationError,
    OrchestrationRetryActivationService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_schedule_v2 import setup as schedule_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryActivationService, dict[str, object], dict[str, object]]:
    schedules, schedule_command, _ = schedule_setup(tmp_path)
    schedule = schedules.register(schedule_command, now=NOW + timedelta(seconds=41))
    command: dict[str, object] = {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "assessment_id": schedule["assessment_id"],
        "plan_id": schedule["plan_id"],
        "expected_plan_revision": schedule["plan_revision"],
        "task_id": schedule["task_id"],
        "expected_task_revision": schedule["task_revision"],
        "schedule_id": schedule["schedule_id"],
        "schedule_digest": schedule["schedule_digest"],
        "attempt_id": schedule["attempt_id"],
        "attempt_digest": schedule["attempt_digest"],
        "purpose": "activate_validation_retry_readiness_three",
        "requested_at": (NOW + timedelta(seconds=42)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=55)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryActivationService(schedules.authorization), command, schedule


def test_consumes_attempt_three_schedule_into_non_authoritative_readiness(
    tmp_path: Path,
) -> None:
    service, command, schedule = setup(tmp_path)
    receipt = service.consume(command, now=NOW + timedelta(seconds=42))
    assert contract_issues(receipt, "orchestration-retry-activation-receipt-v2.schema.json") == ()
    assert receipt["attempt_number"] == 3
    assert receipt["schedule_id"] == schedule["schedule_id"]
    assert receipt["resulting_task_state"] == "ready"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=42)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id=?",
            (command["task_id"],),
        ).fetchone() == ("ready", receipt["resulting_task_revision"])
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_activations_v2"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state='active'"
        ).fetchone() == (0,)


def test_mixed_versions_tampering_and_general_transition_deny(tmp_path: Path) -> None:
    for index, changes in enumerate(
        (
            {"schema_version": "1.0.0"},
            {"attempt_number": 4},
            {"schedule_digest": "sha256:" + "0" * 64},
            {"assessment_id": str(uuid4())},
            {"authority": "grant"},
        )
    ):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryActivationError):
            service.consume(command, now=NOW + timedelta(seconds=42))

    service, command, _ = setup(tmp_path / "transition")
    graph = DurablePlanGraphService(service.database_path)
    with pytest.raises(OrchestrationError):
        graph.transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "assessment_id": command["assessment_id"],
                "plan_id": command["plan_id"],
                "expected_plan_revision": command["expected_plan_revision"],
                "task_id": command["task_id"],
                "expected_task_revision": command["expected_task_revision"],
                "target_state": "ready",
                "requested_at": (NOW + timedelta(seconds=42)).isoformat(),
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW + timedelta(seconds=42),
        )


def test_changed_replay_concurrency_and_security_fences(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path / "replay")
    service.consume(command, now=NOW + timedelta(seconds=42))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=54)).isoformat()
    with pytest.raises(OrchestrationRetryActivationError) as conflict:
        service.consume(changed, now=NOW + timedelta(seconds=42))
    assert conflict.value.code == "ORCHESTRATION_RETRY_ACTIVATION_IDENTITY_CONFLICT"

    concurrent, contender, _ = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, object]) -> str:
        try:
            return str(
                concurrent.consume(candidate, now=NOW + timedelta(seconds=42))["activation_id"]
            )
        except OrchestrationRetryActivationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_ACTIVATION_") for value in outcomes) == 1

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
        with pytest.raises(OrchestrationRetryActivationError):
            fenced.consume(fenced_command, now=NOW + timedelta(seconds=42))


def test_storage_is_immutable_and_direct_bypass_denies(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_tasks SET state='ready', revision=revision+1 WHERE task_id=?",
                (command["task_id"],),
            )
    receipt = service.consume(command, now=NOW + timedelta(seconds=42))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_retry_activations_v2 SET authority='none' "
                "WHERE activation_id=?",
                (receipt["activation_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_activations_v2 WHERE activation_id=?",
                (receipt["activation_id"],),
            )
