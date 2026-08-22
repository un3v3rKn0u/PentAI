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
from pentai_core.orchestration_checkpoint import OrchestrationCheckpointService
from pentai_core.orchestration_failure import (
    OrchestrationFailureError,
    OrchestrationFailureService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_checkpoint import setup as checkpoint_setup


def setup(tmp_path: Path) -> tuple[OrchestrationFailureService, dict[str, object]]:
    checkpoints, checkpoint = checkpoint_setup(tmp_path)
    command = {
        key: value
        for key, value in checkpoint.items()
        if key
        not in {
            "sequence",
            "previous_checkpoint_digest",
            "progress_percent",
            "status",
        }
    }
    command.update(
        command_id=str(uuid4()),
        checkpoint_id=None,
        checkpoint_sequence=None,
        checkpoint_digest=None,
        failure_class="coordination_timeout",
        purpose="record_validation_task_failure",
    )
    return OrchestrationFailureService(checkpoints.authorization), command


def test_consumes_closed_failure_without_retry_or_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.record(command, now=NOW)
    assert contract_issues(
        receipt, "orchestration-task-failure-receipt-v1.schema.json"
    ) == ()
    assert service.record(command, now=NOW) == receipt
    assert receipt["resulting_task_state"] == "failed"
    assert receipt["authority"] == "none"
    assert receipt["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone()
        assert task == ("failed", command["expected_task_revision"] + 1)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
        ).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM outbox WHERE aggregate_type='orchestration_task_failure'"
        ).fetchone()[0] == 1


def test_binds_exact_checkpoint_head_and_rejects_ambiguous_lineage(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    checkpoints = OrchestrationCheckpointService(service.authorization)
    checkpoint_command = {
        key: value
        for key, value in command.items()
        if key
        not in {
            "checkpoint_id",
            "checkpoint_sequence",
            "checkpoint_digest",
            "failure_class",
        }
    }
    checkpoint_command.update(
        command_id=str(uuid4()),
        sequence=1,
        previous_checkpoint_digest=None,
        progress_percent=25,
        status="in_progress",
        purpose="record_validation_progress",
    )
    checkpoint = checkpoints.record(checkpoint_command, now=NOW)
    stale = copy.deepcopy(command)
    with pytest.raises(OrchestrationFailureError) as fenced:
        service.record(stale, now=NOW)
    assert fenced.value.code == "ORCHESTRATION_FAILURE_CHECKPOINT_FENCED"
    command.update(
        checkpoint_id=checkpoint["checkpoint_id"],
        checkpoint_sequence=checkpoint["sequence"],
        checkpoint_digest=checkpoint["checkpoint_digest"],
    )
    assert service.record(command, now=NOW)["checkpoint_id"] == checkpoint["checkpoint_id"]

    ambiguous_service, ambiguous = setup(tmp_path / "ambiguous")
    ambiguous["checkpoint_id"] = str(uuid4())
    with pytest.raises(OrchestrationFailureError) as denied:
        ambiguous_service.record(ambiguous, now=NOW)
    assert denied.value.code == "ORCHESTRATION_FAILURE_CHECKPOINT_AMBIGUOUS"


def test_denies_free_form_unknown_security_and_conflicting_input(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    malformed_cases = (
        {"failure_class": "policy_denied"},
        {"failure_message": "synthetic stack trace"},
        {"authority": "grant"},
        {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
    )
    for changes in malformed_cases:
        candidate = copy.deepcopy(command)
        candidate.update(changes)
        with pytest.raises(OrchestrationFailureError) as denied:
            service.record(candidate, now=NOW)
        assert denied.value.code in {
            "ORCHESTRATION_FAILURE_MALFORMED",
            "ORCHESTRATION_FAILURE_STALE",
        }

    accepted = service.record(command, now=NOW)
    conflict = copy.deepcopy(command)
    conflict["failure_class"] = "runtime_unavailable"
    with pytest.raises(OrchestrationFailureError) as reused:
        service.record(conflict, now=NOW)
    assert reused.value.code == "ORCHESTRATION_FAILURE_IDENTITY_CONFLICT"
    assert service.record(command, now=NOW) == accepted


def test_general_and_direct_running_failure_paths_are_closed(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    transition = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "plan_id": command["plan_id"],
        "assessment_id": command["assessment_id"],
        "task_id": command["task_id"],
        "expected_plan_revision": command["expected_plan_revision"],
        "expected_task_revision": command["expected_task_revision"],
        "target_state": "failed",
        "requested_at": NOW.isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    with pytest.raises(OrchestrationError) as denied:
        DurablePlanGraphService(service.database_path).transition(transition, now=NOW)
    assert denied.value.code == "ORCHESTRATION_TRANSITION_DENIED"
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_tasks SET state='failed', revision=revision+1 WHERE task_id=?",
            (command["task_id"],),
        )


def test_concurrent_failure_consumption_allows_one_result(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, object]) -> str:
        try:
            return str(service.record(candidate, now=NOW)["failure_id"])
        except OrchestrationFailureError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, contenders))
    assert sum(value.startswith("ORCHESTRATION_FAILURE_") for value in outcomes) == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_failures"
        ).fetchone()[0] == 1


def test_safety_worker_recovery_and_immutability_deny(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationFailureError) as paused:
        service.record(command, now=NOW)
    assert paused.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"

    worker_service, worker_command = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=?""",
            (worker_command["worker_id"],),
        )
    with pytest.raises(OrchestrationFailureError) as worker:
        worker_service.record(worker_command, now=NOW)
    assert worker.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"

    recovery_service, recovery_command = setup(tmp_path / "recovery")
    assert DurablePlanGraphService(recovery_service.database_path).recover(
        now=NOW + timedelta(seconds=1)
    ) == [recovery_command["plan_id"]]
    with pytest.raises(OrchestrationFailureError) as recovered:
        recovery_service.record(recovery_command, now=NOW + timedelta(seconds=1))
    assert recovered.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"
    with (
        closing(sqlite3.connect(recovery_service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("DELETE FROM orchestration_task_recovery_failures")


def test_failure_receipts_are_storage_immutable(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.record(command, now=NOW)
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_task_failures SET authority='grant' WHERE failure_id=?",
            (receipt["failure_id"],),
        )
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "DELETE FROM orchestration_task_failures WHERE failure_id=?",
            (receipt["failure_id"],),
        )
