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
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_failure import OrchestrationFailureError, OrchestrationFailureService
from pentai_core.orchestration_failure_v3 import (
    OrchestrationFailureV3Error,
    OrchestrationFailureV3Service,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_checkpoint_v3 import setup as checkpoint_setup


def setup(tmp_path: Path) -> tuple[OrchestrationFailureV3Service, dict[str, Any]]:
    checkpoints, checkpoint = checkpoint_setup(tmp_path)
    command = {
        key: value
        for key, value in checkpoint.items()
        if key not in {"sequence", "previous_checkpoint_digest", "progress_percent", "status"}
    }
    command.update(
        command_id=str(uuid4()),
        checkpoint_id=None,
        checkpoint_sequence=None,
        checkpoint_digest=None,
        failure_class="coordination_timeout",
        purpose="record_attempt_three_validation_task_failure",
        requested_at=(NOW + timedelta(seconds=48)).isoformat(),
        expires_at=(NOW + timedelta(seconds=108)).isoformat(),
    )
    return OrchestrationFailureV3Service(checkpoints.authorization), command


def test_records_terminal_attempt_three_failure_without_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        attempts_before = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts_v2"
        ).fetchone()[0]
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    receipt = service.record(command, now=NOW + timedelta(seconds=48))
    assert contract_issues(receipt, "orchestration-task-failure-receipt-v3.schema.json") == ()
    assert receipt["attempt_number"] == 3 and receipt["resulting_task_state"] == "failed"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.record(command, now=NOW + timedelta(seconds=48)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("failed",)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts_v2"
        ).fetchone() == (attempts_before,)
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone() == (
            grants_before,
        )


def test_binds_exact_checkpoint_v3_head_or_explicit_absence(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    checkpoint_service = service._checkpoints
    checkpoint_command = {
        key: value
        for key, value in command.items()
        if key not in {"checkpoint_id", "checkpoint_sequence", "checkpoint_digest", "failure_class"}
    }
    checkpoint_command.update(
        command_id=str(uuid4()),
        sequence=1,
        previous_checkpoint_digest=None,
        progress_percent=25,
        status="in_progress",
        purpose="record_attempt_three_validation_progress",
        requested_at=(NOW + timedelta(seconds=48)).isoformat(),
        expires_at=(NOW + timedelta(seconds=108)).isoformat(),
    )
    checkpoint = checkpoint_service.record(checkpoint_command, now=NOW + timedelta(seconds=48))
    with pytest.raises(OrchestrationFailureV3Error) as stale:
        service.record(command, now=NOW + timedelta(seconds=48))
    assert stale.value.code == "ORCHESTRATION_FAILURE_V3_CHECKPOINT_FENCED"
    command.update(
        checkpoint_id=checkpoint["checkpoint_id"],
        checkpoint_sequence=checkpoint["sequence"],
        checkpoint_digest=checkpoint["checkpoint_digest"],
    )
    assert (
        service.record(command, now=NOW + timedelta(seconds=48))["checkpoint_id"]
        == checkpoint["checkpoint_id"]
    )


def test_malformed_mixed_tampered_partial_and_changed_replay_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"attempt_number": 2},
        {"authority": "grant"},
        {"failure_class": "policy_denied"},
        {"lease_consumption_id": str(uuid4())},
        {"retry_attempt_digest": "sha256:" + "0" * 64},
        {"checkpoint_id": str(uuid4())},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationFailureV3Error):
            service.record(command, now=NOW + timedelta(seconds=48))
    service, command = setup(tmp_path / "changed")
    service.record(command, now=NOW + timedelta(seconds=48))
    changed = copy.deepcopy(command)
    changed["failure_class"] = "runtime_unavailable"
    with pytest.raises(OrchestrationFailureV3Error) as error:
        service.record(changed, now=NOW + timedelta(seconds=48))
    assert error.value.code == "ORCHESTRATION_FAILURE_V3_IDENTITY_CONFLICT"


def test_concurrency_security_fences_and_legacy_consumer_deny(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def record(candidate: dict[str, Any]) -> str:
        try:
            return service.record(candidate, now=NOW + timedelta(seconds=48))["failure_id"]
        except OrchestrationFailureV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(record, contenders))
    assert sum(value.startswith("ORCHESTRATION_FAILURE_V3_") for value in outcomes) == 1

    for name in ("safety", "cancel", "worker", "account", "recovery"):
        fenced, candidate = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    """UPDATE orchestration_tasks SET state='cancelling', revision=revision+1
                    WHERE task_id=?""",
                    (candidate["task_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=?""",
                    (candidate["worker_id"],),
                )
            elif name == "account":
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (candidate["task_id"],),
                )
        with pytest.raises(OrchestrationFailureV3Error):
            fenced.record(candidate, now=NOW + timedelta(seconds=48))

    legacy_service, legacy_command = setup(tmp_path / "legacy")
    with pytest.raises(OrchestrationFailureError):
        OrchestrationFailureService(legacy_service.authorization).record(
            legacy_command, now=NOW + timedelta(seconds=48)
        )


def test_transition_and_storage_bypass_deny(tmp_path: Path) -> None:
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
        "requested_at": (NOW + timedelta(seconds=48)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    with pytest.raises(OrchestrationError):
        DurablePlanGraphService(service.database_path).transition(
            transition, now=NOW + timedelta(seconds=48)
        )
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_tasks SET state='failed', revision=revision+1
                WHERE task_id=?""",
                (command["task_id"],),
            )
    receipt = service.record(command, now=NOW + timedelta(seconds=48))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE orchestration_task_failures_v3 SET failure_class='x'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_failures_v3")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_task_failures_v3
                SELECT ?, ?, command_digest, assessment_id, plan_id,
                expected_plan_revision, resulting_plan_revision, task_id,
                expected_task_revision, resulting_task_revision, lease_consumption_id,
                checkpoint_id, failure_class, receipt_json, ?, recorded_at, 'none', 0
                FROM orchestration_task_failures_v3 WHERE failure_id=?""",
                (str(uuid4()), str(uuid4()), "0" * 64, receipt["failure_id"]),
            )
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_failures_v3 WHERE failure_id=?",
            (receipt["failure_id"],),
        ).fetchone() == (1,)
