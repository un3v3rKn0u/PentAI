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
from pentai_core.orchestration_checkpoint_v3 import (
    OrchestrationCheckpointV3Error,
    OrchestrationCheckpointV3Service,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_lease_v3 import consumption
from test_orchestration_lease_v3 import setup as lease_setup


def setup(tmp_path: Path) -> tuple[OrchestrationCheckpointV3Service, dict[str, Any]]:
    leases, request = lease_setup(tmp_path)
    state = leases.acquire(request, now=NOW + timedelta(seconds=45))
    token = state.pop("lease_token")
    spent = leases.consume(consumption(state, token), now=NOW + timedelta(seconds=46))
    command: dict[str, Any] = {
        "schema_version": "3.0.0",
        "command_id": str(uuid4()),
        "assessment_id": spent["assessment_id"],
        "plan_id": spent["plan_id"],
        "expected_plan_revision": spent["resulting_plan_revision"],
        "task_id": spent["task_id"],
        "expected_task_revision": spent["resulting_task_revision"],
        "agent_id": spent["agent_id"],
        "capability_manifest_id": spent["capability_manifest_id"],
        "capability_manifest_digest": spent["capability_manifest_digest"],
        "manifest_revision": spent["manifest_revision"],
        "budget_reservation_id": spent["budget_reservation_id"],
        "budget_request_digest": spent["budget_request_digest"],
        "budget_account_version": spent["budget_account_version"],
        "retry_policy_id": spent["retry_policy_id"],
        "retry_policy_digest": spent["retry_policy_digest"],
        "retry_activation_id": spent["retry_activation_id"],
        "retry_activation_digest": spent["retry_activation_digest"],
        "retry_schedule_id": spent["retry_schedule_id"],
        "retry_schedule_digest": spent["retry_schedule_digest"],
        "retry_attempt_id": spent["retry_attempt_id"],
        "retry_attempt_digest": spent["retry_attempt_digest"],
        "attempt_number": 3,
        "prior_retry_budget_consumption_id": spent["prior_retry_budget_consumption_id"],
        "retry_budget_consumption_id": spent["retry_budget_consumption_id"],
        "approval_consumption_id": spent["approval_consumption_id"],
        "lease_consumption_id": spent["consumption_id"],
        "lease_consumption_digest": "sha256:" + content_hash(spent),
        "policy_bundle_id": spent["policy_bundle_id"],
        "policy_hash": spent["policy_hash"],
        "worker_id": spent["worker_id"],
        "expected_worker_version": spent["worker_version"],
        "lease_id": spent["lease_id"],
        "lease_generation": spent["lease_generation"],
        "fencing_token": spent["fencing_token"],
        "expected_recovery_generation": spent["recovery_generation"],
        "sequence": 1,
        "previous_checkpoint_digest": None,
        "progress_percent": 10,
        "status": "started",
        "purpose": "record_attempt_three_validation_progress",
        "requested_at": (NOW + timedelta(seconds=47)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=107)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationCheckpointV3Service(leases.authorization), command


def test_records_monotonic_metadata_only_attempt_three_checkpoints(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grant_count = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()
    first = service.record(command, now=NOW + timedelta(seconds=47))
    assert contract_issues(first, "orchestration-task-checkpoint-receipt-v3.schema.json") == ()
    assert first["attempt_number"] == 3
    assert first["authority"] == "none" and first["execution_enabled"] is False
    assert service.record(command, now=NOW + timedelta(seconds=47)) == first
    second_command = copy.deepcopy(command)
    second_command.update(
        {
            "command_id": str(uuid4()),
            "sequence": 2,
            "previous_checkpoint_digest": first["checkpoint_digest"],
            "progress_percent": 20,
            "status": "in_progress",
        }
    )
    second = service.record(second_command, now=NOW + timedelta(seconds=47))
    assert second["previous_checkpoint_digest"] == first["checkpoint_digest"]
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("running",)
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone() == grant_count


def test_malformed_mixed_cross_lineage_and_changed_replay_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"attempt_number": 2},
        {"authority": "grant"},
        {"lease_consumption_id": str(uuid4())},
        {"retry_attempt_digest": "sha256:" + "0" * 64},
        {"progress_percent": 100},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationCheckpointV3Error):
            service.record(command, now=NOW + timedelta(seconds=47))
    service, command = setup(tmp_path / "changed")
    service.record(command, now=NOW + timedelta(seconds=47))
    changed = copy.deepcopy(command)
    changed["progress_percent"] = 11
    with pytest.raises(OrchestrationCheckpointV3Error) as error:
        service.record(changed, now=NOW + timedelta(seconds=47))
    assert error.value.code == "ORCHESTRATION_CHECKPOINT_V3_IDENTITY_CONFLICT"


def test_sequence_forks_rollback_and_concurrency_deny(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    first = service.record(command, now=NOW + timedelta(seconds=47))
    gap = copy.deepcopy(command)
    gap.update(
        {
            "command_id": str(uuid4()),
            "sequence": 3,
            "previous_checkpoint_digest": first["checkpoint_digest"],
        }
    )
    with pytest.raises(OrchestrationCheckpointV3Error):
        service.record(gap, now=NOW + timedelta(seconds=47))
    contenders = []
    for progress in (20, 30):
        item = copy.deepcopy(command)
        item.update(
            {
                "command_id": str(uuid4()),
                "sequence": 2,
                "previous_checkpoint_digest": first["checkpoint_digest"],
                "progress_percent": progress,
                "status": "in_progress",
            }
        )
        contenders.append(item)

    def record(item: dict[str, Any]) -> str:
        try:
            return service.record(item, now=NOW + timedelta(seconds=47))["checkpoint_id"]
        except OrchestrationCheckpointV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(record, contenders))
    assert sum(value.startswith("ORCHESTRATION_") for value in results) == 1
    rollback = copy.deepcopy(command)
    rollback.update(
        {
            "command_id": str(uuid4()),
            "sequence": 3,
            "previous_checkpoint_digest": next(
                value for value in results if not value.startswith("ORCHESTRATION_")
            ),
            "progress_percent": 5,
        }
    )
    # A checkpoint id is not a predecessor digest, so the request is fenced before rollback.
    with pytest.raises(OrchestrationCheckpointV3Error):
        service.record(rollback, now=NOW + timedelta(seconds=47))


def test_current_security_fences_and_storage_guards(tmp_path: Path) -> None:
    for name in ("safety", "worker", "account", "recovery"):
        service, command = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=?""",
                    (command["worker_id"],),
                )
            elif name == "account":
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (command["task_id"],),
                )
        with pytest.raises(OrchestrationCheckpointV3Error):
            service.record(command, now=NOW + timedelta(seconds=47))
    service, command = setup(tmp_path / "storage")
    service.record(command, now=NOW + timedelta(seconds=47))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE orchestration_task_checkpoints_v3 SET sequence=2")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_checkpoints_v3")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_task_checkpoints_v3
                SELECT ?, ?, command_digest, assessment_id, plan_id, plan_revision,
                task_id, task_revision, ?, sequence+1, checkpoint_digest,
                'sha256:'||substr(checkpoint_digest,8), receipt_json, created_at,
                authority, execution_enabled FROM orchestration_task_checkpoints_v3 LIMIT 1""",
                (str(uuid4()), str(uuid4()), str(uuid4())),
            )
    legacy = OrchestrationCheckpointService(service.authorization)
    with pytest.raises(OrchestrationCheckpointError):
        legacy.record(command, now=NOW + timedelta(seconds=47))
