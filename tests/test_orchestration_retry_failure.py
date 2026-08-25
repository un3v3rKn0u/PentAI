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
from pentai_core.orchestration_checkpoint import OrchestrationCheckpointService
from pentai_core.orchestration_failure import OrchestrationFailureError, OrchestrationFailureService
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_checkpoint import setup as checkpoint_setup


def setup(tmp_path: Path) -> tuple[OrchestrationFailureService, dict[str, Any]]:
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
        purpose="record_retry_validation_task_failure",
    )
    return OrchestrationFailureService(checkpoints.authorization), command


def test_consumes_retry_failure_without_retry_or_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        attempts_before = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts"
        ).fetchone()[0]
    receipt = service.record(command, now=NOW + timedelta(seconds=10))
    assert contract_issues(receipt, "orchestration-task-failure-receipt-v2.schema.json") == ()
    assert receipt["retry_attempt_id"] == command["retry_attempt_id"]
    assert receipt["resulting_task_state"] == "failed"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.record(command, now=NOW + timedelta(seconds=10)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute(
                "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
            ).fetchone()[0]
            == "failed"
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_retry_attempts").fetchone()[0]
            == attempts_before
        )


def test_binds_exact_checkpoint_v2_head_and_rejects_mixed_versions(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    checkpoints = OrchestrationCheckpointService(service.authorization)
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
        purpose="record_retry_validation_progress",
    )
    checkpoint = checkpoints.record(checkpoint_command, now=NOW + timedelta(seconds=10))
    with pytest.raises(OrchestrationFailureError) as stale:
        service.record(command, now=NOW + timedelta(seconds=10))
    assert stale.value.code == "ORCHESTRATION_FAILURE_CHECKPOINT_FENCED"
    command.update(
        checkpoint_id=checkpoint["checkpoint_id"],
        checkpoint_sequence=checkpoint["sequence"],
        checkpoint_digest=checkpoint["checkpoint_digest"],
    )
    assert (
        service.record(command, now=NOW + timedelta(seconds=10))["checkpoint_id"]
        == checkpoint["checkpoint_id"]
    )

    mixed_service, mixed = setup(tmp_path / "mixed")
    for field in (
        "capability_manifest_digest",
        "budget_request_digest",
        "retry_activation_id",
        "retry_activation_digest",
        "retry_attempt_id",
        "retry_attempt_digest",
        "retry_budget_consumption_id",
    ):
        mixed.pop(field)
    mixed.update(schema_version="1.0.0", purpose="record_validation_task_failure")
    with pytest.raises(OrchestrationFailureError) as denied:
        mixed_service.record(mixed, now=NOW + timedelta(seconds=10))
    assert denied.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"


def test_denies_tampering_ambiguity_and_direct_transition(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    tampered = copy.deepcopy(command)
    tampered["retry_attempt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationFailureError) as denied:
        service.record(tampered, now=NOW + timedelta(seconds=10))
    assert denied.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"

    ambiguous = copy.deepcopy(command)
    ambiguous["checkpoint_id"] = str(uuid4())
    with pytest.raises(OrchestrationFailureError) as partial:
        service.record(ambiguous, now=NOW + timedelta(seconds=10))
    assert partial.value.code == "ORCHESTRATION_FAILURE_CHECKPOINT_AMBIGUOUS"

    transition = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "plan_id": command["plan_id"],
        "assessment_id": command["assessment_id"],
        "task_id": command["task_id"],
        "expected_plan_revision": command["expected_plan_revision"],
        "expected_task_revision": command["expected_task_revision"],
        "target_state": "failed",
        "requested_at": (NOW + timedelta(seconds=10)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    with pytest.raises(OrchestrationError):
        DurablePlanGraphService(service.database_path).transition(
            transition, now=NOW + timedelta(seconds=10)
        )
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_tasks SET state='failed', revision=revision+1 WHERE task_id=?",
            (command["task_id"],),
        )


def test_concurrent_retry_failure_allows_one_winner(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, Any]) -> str:
        try:
            return str(service.record(candidate, now=NOW + timedelta(seconds=10))["failure_id"])
        except OrchestrationFailureError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, contenders))
    assert sum(value.startswith("ORCHESTRATION_FAILURE_") for value in outcomes) == 1


def test_safety_cancellation_worker_recovery_and_storage_lineage_deny(tmp_path: Path) -> None:
    for name in ("safety", "cancel", "worker", "recovery"):
        service, command = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    """UPDATE orchestration_tasks
                    SET state='cancelling', revision=revision+1 WHERE task_id=?""",
                    (command["task_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances
                    SET status='termination_requested', version=version+1
                    WHERE worker_id=?""",
                    (command["worker_id"],),
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (command["task_id"],),
                )
        with pytest.raises(OrchestrationFailureError) as denied:
            service.record(command, now=NOW + timedelta(seconds=10))
        assert denied.value.code == "ORCHESTRATION_FAILURE_SECURITY_DENIED"

    service, command = setup(tmp_path / "storage")
    receipt = service.record(command, now=NOW + timedelta(seconds=10))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_failures SET retry_attempt_id=NULL WHERE failure_id=?",
                (receipt["failure_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_task_failures(
                failure_id, command_id, command_digest, assessment_id, plan_id,
                expected_plan_revision, resulting_plan_revision, task_id,
                expected_task_revision, resulting_task_revision, lease_consumption_id,
                failure_class, receipt_json, receipt_hash, recorded_at, authority,
                execution_enabled)
                SELECT ?, ?, command_digest, assessment_id, plan_id,
                expected_plan_revision, resulting_plan_revision, task_id,
                expected_task_revision, resulting_task_revision, lease_consumption_id,
                failure_class, receipt_json, ?, recorded_at, 'none', 0
                FROM orchestration_task_failures WHERE failure_id=?""",
                (str(uuid4()), str(uuid4()), "0" * 64, receipt["failure_id"]),
            )

    replay_service, replay_command = setup(tmp_path / "replay")
    replay_service.record(replay_command, now=NOW + timedelta(seconds=10))
    with closing(sqlite3.connect(replay_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationFailureError) as fenced:
        replay_service.record(replay_command, now=NOW + timedelta(seconds=10))
    assert fenced.value.code == "ORCHESTRATION_FAILURE_REPLAY_FENCED"
