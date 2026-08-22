from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration import DurablePlanGraphService
from pentai_core.orchestration_attempt import (
    OrchestrationAttemptError,
    OrchestrationAttemptService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_failure import setup as failure_setup


def setup(tmp_path: Path) -> tuple[OrchestrationAttemptService, dict[str, object]]:
    failures, failure_command = failure_setup(tmp_path)
    failure = failures.record(failure_command, now=NOW)
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": failure["assessment_id"],
        "plan_id": failure["plan_id"],
        "expected_plan_revision": failure["resulting_plan_revision"],
        "task_id": failure["task_id"],
        "expected_task_revision": failure["resulting_task_revision"],
        "agent_id": failure["agent_id"],
        "capability_manifest_id": failure["capability_manifest_id"],
        "manifest_revision": failure["manifest_revision"],
        "budget_reservation_id": failure["budget_reservation_id"],
        "budget_account_version": failure["budget_account_version"],
        "approval_consumption_id": failure["approval_consumption_id"],
        "lease_consumption_id": failure["lease_consumption_id"],
        "policy_bundle_id": failure["policy_bundle_id"],
        "policy_hash": failure["policy_hash"],
        "worker_id": failure["worker_id"],
        "expected_worker_version": failure["worker_version"],
        "lease_generation": failure["lease_generation"],
        "fencing_token": failure["fencing_token"],
        "expected_recovery_generation": failure["recovery_generation"],
        "checkpoint_id": failure["checkpoint_id"],
        "checkpoint_sequence": failure["checkpoint_sequence"],
        "checkpoint_digest": failure["checkpoint_digest"],
        "failure_id": failure["failure_id"],
        "failure_receipt_digest": "sha256:" + content_hash(failure),
        "attempt_number": 1,
        "purpose": "register_failed_validation_attempt",
        "requested_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationAttemptService(failures.authorization), command


def test_registers_failed_attempt_without_retry_or_state_change(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        account_before = connection.execute(
            """SELECT version FROM orchestration_budget_accounts WHERE account_id =
            (SELECT account_id FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?)""",
            (command["budget_reservation_id"],),
        ).fetchone()[0]
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    receipt = service.register(command, now=NOW)
    assert contract_issues(
        receipt, "orchestration-task-attempt-receipt-v1.schema.json"
    ) == ()
    assert service.register(command, now=NOW) == receipt
    assert receipt["attempt_number"] == 1 and receipt["attempt_state"] == "failed"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone()
        account_after = connection.execute(
            """SELECT version FROM orchestration_budget_accounts WHERE account_id =
            (SELECT account_id FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?)""",
            (command["budget_reservation_id"],),
        ).fetchone()[0]
        grants_after = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
        outbox = connection.execute(
            "SELECT COUNT(*) FROM outbox WHERE aggregate_type='orchestration_task_attempt'"
        ).fetchone()[0]
    assert task == ("failed", command["expected_task_revision"])
    assert account_after == account_before
    assert grants_after == grants_before
    assert outbox == 1


def test_rejects_malformed_attempt_number_diagnostics_and_conflicting_replay(
    tmp_path: Path,
) -> None:
    service, command = setup(tmp_path)
    cases = (
        {"attempt_number": 0},
        {"attempt_number": 2},
        {"failure_message": "synthetic diagnostic"},
        {"authority": "grant"},
        {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
    )
    for changes in cases:
        candidate = copy.deepcopy(command)
        candidate.update(changes)
        with pytest.raises(OrchestrationAttemptError) as denied:
            service.register(candidate, now=NOW)
        assert denied.value.code in {
            "ORCHESTRATION_ATTEMPT_MALFORMED",
            "ORCHESTRATION_ATTEMPT_STALE",
        }
    service.register(command, now=NOW)
    conflict = copy.deepcopy(command)
    conflict["worker_id"] = "synthetic-other-worker"
    with pytest.raises(OrchestrationAttemptError) as reused:
        service.register(conflict, now=NOW)
    assert reused.value.code == "ORCHESTRATION_ATTEMPT_IDENTITY_CONFLICT"


def test_rejects_failure_digest_scope_checkpoint_and_fence_substitution(tmp_path: Path) -> None:
    cases = (
        ({"failure_receipt_digest": "sha256:" + "0" * 64}, "ORCHESTRATION_ATTEMPT_FAILURE_INVALID"),
        ({"assessment_id": str(uuid4())}, "ORCHESTRATION_ATTEMPT_BINDING_MISMATCH"),
        ({"checkpoint_id": str(uuid4())}, "ORCHESTRATION_ATTEMPT_BINDING_MISMATCH"),
        ({"fencing_token": 999}, "ORCHESTRATION_ATTEMPT_BINDING_MISMATCH"),
    )
    for index, (changes, code) in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationAttemptError) as denied:
            service.register(command, now=NOW)
        assert denied.value.code == code


def test_rejects_safety_worker_budget_and_recovery_staleness(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "safety")
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationAttemptError) as paused:
        service.register(command, now=NOW)
    assert paused.value.code == "ORCHESTRATION_ATTEMPT_SECURITY_DENIED"

    worker_service, worker_command = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=?""",
            (worker_command["worker_id"],),
        )
    with pytest.raises(OrchestrationAttemptError) as worker:
        worker_service.register(worker_command, now=NOW)
    assert worker.value.code == "ORCHESTRATION_ATTEMPT_PREREQUISITE_INVALID"

    budget_service, budget_command = setup(tmp_path / "budget")
    with closing(sqlite3.connect(budget_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET state='released',
            released_at=?, release_reason='recovery' WHERE reservation_id=?""",
            (NOW.isoformat(), budget_command["budget_reservation_id"]),
        )
    with pytest.raises(OrchestrationAttemptError) as budget:
        budget_service.register(budget_command, now=NOW)
    assert budget.value.code == "ORCHESTRATION_ATTEMPT_PREREQUISITE_INVALID"

def test_recovery_failure_marker_cannot_register_worker_attempt(tmp_path: Path) -> None:
    failures, failure_command = failure_setup(tmp_path)
    plans = DurablePlanGraphService(failures.database_path)
    assert plans.recover(now=NOW + timedelta(seconds=1)) == [failure_command["plan_id"]]
    command = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": failure_command["assessment_id"],
        "plan_id": failure_command["plan_id"],
        "expected_plan_revision": failure_command["expected_plan_revision"] + 1,
        "task_id": failure_command["task_id"],
        "expected_task_revision": failure_command["expected_task_revision"] + 1,
        "agent_id": failure_command["agent_id"],
        "capability_manifest_id": failure_command["capability_manifest_id"],
        "manifest_revision": 1,
        "budget_reservation_id": failure_command["budget_reservation_id"],
        "budget_account_version": failure_command["budget_account_version"],
        "approval_consumption_id": None,
        "lease_consumption_id": failure_command["lease_consumption_id"],
        "policy_bundle_id": failure_command["policy_bundle_id"],
        "policy_hash": failure_command["policy_hash"],
        "worker_id": failure_command["worker_id"],
        "expected_worker_version": failure_command["expected_worker_version"],
        "lease_generation": failure_command["lease_generation"],
        "fencing_token": failure_command["fencing_token"],
        "expected_recovery_generation": failure_command["expected_recovery_generation"],
        "checkpoint_id": None,
        "checkpoint_sequence": None,
        "checkpoint_digest": None,
        "failure_id": str(uuid4()),
        "failure_receipt_digest": "sha256:" + "0" * 64,
        "attempt_number": 1,
        "purpose": "register_failed_validation_attempt",
        "requested_at": (NOW + timedelta(seconds=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    with pytest.raises(OrchestrationAttemptError) as missing:
        OrchestrationAttemptService(failures.authorization).register(
            command, now=NOW + timedelta(seconds=1)
        )
    assert missing.value.code == "ORCHESTRATION_ATTEMPT_FAILURE_MISSING"


def test_concurrent_registration_has_one_immutable_attempt(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, object]) -> str:
        try:
            return str(service.register(candidate, now=NOW)["attempt_id"])
        except OrchestrationAttemptError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, contenders))
    assert sum(value.startswith("ORCHESTRATION_ATTEMPT_") for value in outcomes) == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_attempts"
        ).fetchone()[0] == 1


def test_attempt_storage_is_immutable(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.register(command, now=NOW)
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_task_attempts SET authority='grant' WHERE attempt_id=?",
            (receipt["attempt_id"],),
        )
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "DELETE FROM orchestration_task_attempts WHERE attempt_id=?",
            (receipt["attempt_id"],),
        )


def test_exact_replay_denies_after_budget_binding_is_invalidated(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    service.register(command, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET state='released',
            released_at=?, release_reason='recovery' WHERE reservation_id=?""",
            (NOW.isoformat(), command["budget_reservation_id"]),
        )
    with pytest.raises(OrchestrationAttemptError) as denied:
        service.register(command, now=NOW)
    assert denied.value.code == "ORCHESTRATION_ATTEMPT_PREREQUISITE_INVALID"
