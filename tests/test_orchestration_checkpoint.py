from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration_checkpoint import (
    OrchestrationCheckpointError,
    OrchestrationCheckpointService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW, TASK_ID, lease_consumption, lease_setup


def setup(tmp_path: Path) -> tuple[OrchestrationCheckpointService, dict[str, object]]:
    leases, lease_request = lease_setup(tmp_path)
    acquired = leases.acquire(lease_request, now=NOW)
    token = acquired.pop("lease_token")
    consumption = leases.consume(
        lease_consumption(acquired, token, lease_request), now=NOW
    )
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": consumption["assessment_id"],
        "plan_id": consumption["plan_id"],
        "expected_plan_revision": consumption["resulting_plan_revision"],
        "task_id": consumption["task_id"],
        "expected_task_revision": consumption["resulting_task_revision"],
        "agent_id": consumption["agent_id"],
        "capability_manifest_id": consumption["capability_manifest_id"],
        "manifest_revision": consumption["manifest_revision"],
        "budget_reservation_id": consumption["budget_reservation_id"],
        "budget_account_version": consumption["budget_account_version"],
        "approval_consumption_id": consumption["approval_consumption_id"],
        "lease_consumption_id": consumption["consumption_id"],
        "lease_consumption_digest": "sha256:" + content_hash(consumption),
        "policy_bundle_id": consumption["policy_bundle_id"],
        "policy_hash": consumption["policy_hash"],
        "worker_id": consumption["worker_id"],
        "expected_worker_version": consumption["worker_version"],
        "lease_generation": consumption["lease_generation"],
        "fencing_token": consumption["fencing_token"],
        "expected_recovery_generation": consumption["recovery_generation"],
        "sequence": 1,
        "previous_checkpoint_digest": None,
        "progress_percent": 10,
        "status": "started",
        "purpose": "record_validation_progress",
        "requested_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationCheckpointService(leases.authorization), command


def test_records_monotonic_metadata_without_state_or_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    first = service.record(command, now=NOW)
    assert contract_issues(
        first, "orchestration-task-checkpoint-receipt-v1.schema.json"
    ) == ()
    assert service.record(command, now=NOW) == first
    second_command = copy.deepcopy(command)
    second_command.update(
        command_id=str(uuid4()),
        sequence=2,
        previous_checkpoint_digest=first["checkpoint_digest"],
        progress_percent=40,
        status="in_progress",
    )
    second = service.record(second_command, now=NOW)
    assert second["sequence"] == 2
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?", (TASK_ID,)
        ).fetchone()
        grants = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    assert task == ("running", 2)
    assert grants == grants_before


def test_denies_malformed_cross_binding_gap_fork_and_rollback(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    malformed = dict(command, progress_percent=100)
    with pytest.raises(OrchestrationCheckpointError) as bad:
        service.record(malformed, now=NOW)
    assert bad.value.code == "ORCHESTRATION_CHECKPOINT_MALFORMED"
    first = service.record(command, now=NOW)
    cases = (
        ({"sequence": 3}, "ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED"),
        ({"sequence": 2, "previous_checkpoint_digest": "sha256:" + "0" * 64},
         "ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED"),
        ({"sequence": 2, "previous_checkpoint_digest": first["checkpoint_digest"],
          "progress_percent": 9}, "ORCHESTRATION_CHECKPOINT_PROGRESS_ROLLBACK"),
        ({"worker_id": "synthetic-other-worker"},
         "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH"),
    )
    for changes, code in cases:
        candidate = copy.deepcopy(command)
        candidate.update(command_id=str(uuid4()), **changes)
        with pytest.raises(OrchestrationCheckpointError) as denied:
            service.record(candidate, now=NOW)
        assert denied.value.code == code


def test_concurrent_checkpoint_heads_allow_one_winner(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    commands = (copy.deepcopy(command), copy.deepcopy(command))
    commands[1]["command_id"] = str(uuid4())

    def record(candidate: dict[str, object]) -> str:
        try:
            return str(service.record(candidate, now=NOW)["checkpoint_id"])
        except OrchestrationCheckpointError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(record, commands))
    assert outcomes.count("ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED") == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_checkpoints"
        ).fetchone()[0] == 1


def test_safety_worker_recovery_and_storage_tampering_deny(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationCheckpointError) as paused:
        service.record(command, now=NOW)
    assert paused.value.code == "ORCHESTRATION_CHECKPOINT_SAFETY_DENIED"

    worker_service, worker_command = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=?""",
            (worker_command["worker_id"],),
        )
    with pytest.raises(OrchestrationCheckpointError) as worker:
        worker_service.record(worker_command, now=NOW)
    assert worker.value.code == "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH"

    recovery_service, recovery_command = setup(tmp_path / "recovery")
    with closing(sqlite3.connect(recovery_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_lease_fences SET recovery_generation=2,
            version=version+1, updated_at=? WHERE task_id=?""",
            (NOW.isoformat(), TASK_ID),
        )
    with pytest.raises(OrchestrationCheckpointError) as recovery:
        recovery_service.record(recovery_command, now=NOW)
    assert recovery.value.code == "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH"

    immutable_service, immutable_command = setup(tmp_path / "immutable")
    immutable_service.record(immutable_command, now=NOW)
    with closing(sqlite3.connect(immutable_service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_checkpoints")
