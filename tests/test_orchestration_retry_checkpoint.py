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
from pentai_core.orchestration_checkpoint import (
    OrchestrationCheckpointError,
    OrchestrationCheckpointService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_lease import consumption as lease_consumption
from test_orchestration_retry_lease import setup as lease_setup


def setup(tmp_path: Path) -> tuple[OrchestrationCheckpointService, dict[str, Any]]:
    leases, lease_request, _ = lease_setup(tmp_path)
    acquired = leases.acquire(lease_request, now=NOW + timedelta(seconds=10))
    token = acquired.pop("lease_token")
    consumed = leases.consume(
        lease_consumption(acquired, token, lease_request),
        now=NOW + timedelta(seconds=10),
    )
    command: dict[str, Any] = {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "assessment_id": consumed["assessment_id"],
        "plan_id": consumed["plan_id"],
        "expected_plan_revision": consumed["resulting_plan_revision"],
        "task_id": consumed["task_id"],
        "expected_task_revision": consumed["resulting_task_revision"],
        "agent_id": consumed["agent_id"],
        "capability_manifest_id": consumed["capability_manifest_id"],
        "capability_manifest_digest": consumed["capability_manifest_digest"],
        "manifest_revision": consumed["manifest_revision"],
        "budget_reservation_id": consumed["budget_reservation_id"],
        "budget_request_digest": consumed["budget_request_digest"],
        "budget_account_version": consumed["budget_account_version"],
        "retry_activation_id": consumed["retry_activation_id"],
        "retry_activation_digest": consumed["retry_activation_digest"],
        "retry_attempt_id": consumed["retry_attempt_id"],
        "retry_attempt_digest": consumed["retry_attempt_digest"],
        "retry_budget_consumption_id": consumed["retry_budget_consumption_id"],
        "approval_consumption_id": consumed["approval_consumption_id"],
        "lease_consumption_id": consumed["consumption_id"],
        "lease_consumption_digest": "sha256:" + content_hash(consumed),
        "policy_bundle_id": consumed["policy_bundle_id"],
        "policy_hash": consumed["policy_hash"],
        "worker_id": consumed["worker_id"],
        "expected_worker_version": consumed["worker_version"],
        "lease_generation": consumed["lease_generation"],
        "fencing_token": consumed["fencing_token"],
        "expected_recovery_generation": consumed["recovery_generation"],
        "sequence": 1,
        "previous_checkpoint_digest": None,
        "progress_percent": 10,
        "status": "started",
        "purpose": "record_retry_validation_progress",
        "requested_at": (NOW + timedelta(seconds=10)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationCheckpointService(leases.authorization), command


def test_records_retry_checkpoint_lineage_without_state_or_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    first = service.record(command, now=NOW + timedelta(seconds=10))
    assert contract_issues(
        first, "orchestration-task-checkpoint-receipt-v2.schema.json"
    ) == ()
    assert first["retry_activation_id"] == command["retry_activation_id"]
    assert first["retry_attempt_id"] == command["retry_attempt_id"]
    assert service.record(command, now=NOW + timedelta(seconds=10)) == first
    second_command = copy.deepcopy(command)
    second_command.update(
        command_id=str(uuid4()),
        sequence=2,
        previous_checkpoint_digest=first["checkpoint_digest"],
        progress_percent=40,
        status="in_progress",
    )
    second = service.record(second_command, now=NOW + timedelta(seconds=10))
    assert second["sequence"] == 2
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id=?",
            (command["task_id"],),
        ).fetchone()
        grants = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    assert task == ("running", command["expected_task_revision"])
    assert grants == grants_before


def test_denies_mixed_version_tampering_gaps_forks_and_rollback(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    legacy = {
        key: value
        for key, value in command.items()
        if key
        not in {
            "capability_manifest_digest",
            "budget_request_digest",
            "retry_activation_id",
            "retry_activation_digest",
            "retry_attempt_id",
            "retry_attempt_digest",
            "retry_budget_consumption_id",
        }
    }
    legacy.update(schema_version="1.0.0", purpose="record_validation_progress")
    with pytest.raises(OrchestrationCheckpointError) as mixed:
        service.record(legacy, now=NOW + timedelta(seconds=10))
    assert mixed.value.code == "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH"

    tampered = copy.deepcopy(command)
    tampered["retry_attempt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationCheckpointError) as mismatch:
        service.record(tampered, now=NOW + timedelta(seconds=10))
    assert mismatch.value.code == "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH"

    first = service.record(command, now=NOW + timedelta(seconds=10))
    cases = (
        {"sequence": 3},
        {"sequence": 2, "previous_checkpoint_digest": "sha256:" + "0" * 64},
        {
            "sequence": 2,
            "previous_checkpoint_digest": first["checkpoint_digest"],
            "progress_percent": 9,
        },
    )
    expected = (
        "ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED",
        "ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED",
        "ORCHESTRATION_CHECKPOINT_PROGRESS_ROLLBACK",
    )
    for changes, code in zip(cases, expected, strict=True):
        candidate = copy.deepcopy(command)
        candidate.update(command_id=str(uuid4()), **changes)
        with pytest.raises(OrchestrationCheckpointError) as denied:
            service.record(candidate, now=NOW + timedelta(seconds=10))
        assert denied.value.code == code


def test_concurrent_retry_checkpoint_heads_allow_one_winner(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    commands = (copy.deepcopy(command), copy.deepcopy(command))
    commands[1]["command_id"] = str(uuid4())

    def record(candidate: dict[str, Any]) -> str:
        try:
            return str(service.record(candidate, now=NOW + timedelta(seconds=10))["checkpoint_id"])
        except OrchestrationCheckpointError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(record, commands))
    assert outcomes.count("ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED") == 1


def test_safety_cancellation_worker_recovery_replay_and_storage_fences(
    tmp_path: Path,
) -> None:
    for name in ("safety", "cancel", "worker", "recovery"):
        service, command = setup(tmp_path / name)
        receipt = service.record(command, now=NOW + timedelta(seconds=10))
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    """UPDATE orchestration_tasks SET state='cancelling', revision=revision+1
                    WHERE task_id=?""",
                    (command["task_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=?""",
                    (command["worker_id"],),
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (command["task_id"],),
                )
        with pytest.raises(OrchestrationCheckpointError):
            service.record(command, now=NOW + timedelta(seconds=10))
        assert receipt["authority"] == "none" and receipt["execution_enabled"] is False

    immutable, immutable_command = setup(tmp_path / "immutable")
    immutable.record(immutable_command, now=NOW + timedelta(seconds=10))
    with closing(sqlite3.connect(immutable.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_checkpoints SET retry_attempt_id=NULL"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_task_checkpoints(
                checkpoint_id, command_id, command_digest, assessment_id, plan_id,
                plan_revision, task_id, task_revision, lease_consumption_id, sequence,
                previous_checkpoint_digest, checkpoint_digest, receipt_json, created_at,
                authority, execution_enabled)
                SELECT ?, ?, command_digest, assessment_id, plan_id, plan_revision,
                task_id, task_revision, lease_consumption_id, 2, checkpoint_digest,
                ?, receipt_json, created_at, 'none', 0
                FROM orchestration_task_checkpoints LIMIT 1""",
                (str(uuid4()), str(uuid4()), "sha256:" + "0" * 64),
            )
