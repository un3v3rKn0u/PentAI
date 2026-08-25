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
from pentai_core.orchestration_attempt import OrchestrationAttemptError, OrchestrationAttemptService
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_failure import setup as failure_setup


def setup(tmp_path: Path) -> tuple[OrchestrationAttemptService, dict[str, Any]]:
    failures, failure_command = failure_setup(tmp_path)
    failure = failures.record(failure_command, now=NOW + timedelta(seconds=10))
    command: dict[str, Any] = {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "assessment_id": failure["assessment_id"],
        "plan_id": failure["plan_id"],
        "expected_plan_revision": failure["resulting_plan_revision"],
        "task_id": failure["task_id"],
        "expected_task_revision": failure["resulting_task_revision"],
        "agent_id": failure["agent_id"],
        "capability_manifest_id": failure["capability_manifest_id"],
        "capability_manifest_digest": failure["capability_manifest_digest"],
        "manifest_revision": failure["manifest_revision"],
        "budget_reservation_id": failure["budget_reservation_id"],
        "budget_request_digest": failure["budget_request_digest"],
        "budget_account_version": failure["budget_account_version"],
        "retry_activation_id": failure["retry_activation_id"],
        "retry_activation_digest": failure["retry_activation_digest"],
        "retry_attempt_id": failure["retry_attempt_id"],
        "retry_attempt_digest": failure["retry_attempt_digest"],
        "retry_budget_consumption_id": failure["retry_budget_consumption_id"],
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
        "failure_class": failure["failure_class"],
        "attempt_number": 2,
        "purpose": "register_failed_retry_validation_attempt",
        "requested_at": (NOW + timedelta(seconds=10)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationAttemptService(failures.authorization), command


def test_registers_existing_attempt_two_as_failed_without_attempt_three(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        retry_attempts_before = connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts"
        ).fetchone()[0]
    receipt = service.register(command, now=NOW + timedelta(seconds=10))
    assert contract_issues(receipt, "orchestration-task-attempt-receipt-v2.schema.json") == ()
    assert receipt["attempt_id"] == command["retry_attempt_id"]
    assert receipt["attempt_number"] == 2 and receipt["attempt_state"] == "failed"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=10)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_retry_attempts").fetchone()[0]
            == retry_attempts_before
        )
        assert (
            connection.execute(
                "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
            ).fetchone()[0]
            == "failed"
        )


def test_denies_malformed_attempt_numbers_mixed_versions_and_tampering(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    for changes in (
        {"attempt_number": 1},
        {"attempt_number": 3},
        {"failure_class": "policy_denied"},
        {"retry_attempt_digest": "sha256:" + "0" * 64},
        {"authority": "grant"},
        {"diagnostic": "synthetic exception"},
    ):
        candidate = copy.deepcopy(command)
        candidate.update(changes)
        with pytest.raises(OrchestrationAttemptError) as denied:
            service.register(candidate, now=NOW + timedelta(seconds=10))
        assert denied.value.code in {
            "ORCHESTRATION_ATTEMPT_MALFORMED",
            "ORCHESTRATION_ATTEMPT_LINEAGE_INVALID",
        }

    legacy = copy.deepcopy(command)
    legacy["schema_version"] = "1.0.0"
    with pytest.raises(OrchestrationAttemptError) as mixed:
        service.register(legacy, now=NOW + timedelta(seconds=10))
    assert mixed.value.code == "ORCHESTRATION_ATTEMPT_MALFORMED"


def test_rejects_cross_scope_and_conflicting_replay(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    for field, value in (
        ("plan_id", str(uuid4())),
        ("task_id", str(uuid4())),
        ("retry_activation_id", str(uuid4())),
        ("failure_id", str(uuid4())),
    ):
        candidate = copy.deepcopy(command)
        candidate[field] = value
        with pytest.raises(OrchestrationAttemptError):
            service.register(candidate, now=NOW + timedelta(seconds=10))

    accepted = service.register(command, now=NOW + timedelta(seconds=10))
    conflict = copy.deepcopy(command)
    conflict["failure_class"] = "runtime_unavailable"
    with pytest.raises(OrchestrationAttemptError) as reused:
        service.register(conflict, now=NOW + timedelta(seconds=10))
    assert reused.value.code == "ORCHESTRATION_ATTEMPT_IDENTITY_CONFLICT"
    assert service.register(command, now=NOW + timedelta(seconds=10)) == accepted


def test_concurrent_registration_allows_one_immutable_result(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def register(candidate: dict[str, Any]) -> str:
        try:
            return str(service.register(candidate, now=NOW + timedelta(seconds=10))["attempt_id"])
        except OrchestrationAttemptError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, contenders))
    assert sum(value.startswith("ORCHESTRATION_ATTEMPT_") for value in outcomes) == 1


def test_safety_cancellation_worker_recovery_and_storage_fences(tmp_path: Path) -> None:
    for name in ("safety", "cancel", "worker", "recovery"):
        service, command = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    "UPDATE engagements SET status='revoked' WHERE id=?",
                    (command["assessment_id"],),
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
        with pytest.raises(OrchestrationAttemptError) as denied:
            service.register(command, now=NOW + timedelta(seconds=10))
        assert denied.value.code == "ORCHESTRATION_ATTEMPT_SECURITY_DENIED"

    service, command = setup(tmp_path / "storage")
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_retry_failed_attempts(
                attempt_id, command_id, command_digest, assessment_id, plan_id,
                plan_revision, task_id, task_revision, failure_id,
                failure_receipt_digest, receipt_json, receipt_hash, registered_at,
                authority, execution_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, 'none', 0)""",
                (
                    command["retry_attempt_id"],
                    str(uuid4()),
                    "sha256:" + "0" * 64,
                    command["assessment_id"],
                    command["plan_id"],
                    command["expected_plan_revision"],
                    command["task_id"],
                    command["expected_task_revision"],
                    command["failure_id"],
                    command["failure_receipt_digest"],
                    "0" * 64,
                    command["requested_at"],
                ),
            )
    receipt = service.register(command, now=NOW + timedelta(seconds=10))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_retry_failed_attempts
                SET authority='grant' WHERE attempt_id=?""",
                (receipt["attempt_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_failed_attempts WHERE attempt_id=?",
                (receipt["attempt_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_retry_failed_attempts(
                attempt_id, command_id, command_digest, assessment_id, plan_id,
                plan_revision, task_id, task_revision, failure_id,
                failure_receipt_digest, receipt_json, receipt_hash, registered_at,
                authority, execution_enabled)
                SELECT attempt_id, ?, command_digest, assessment_id, plan_id,
                plan_revision, task_id, task_revision, failure_id,
                failure_receipt_digest, receipt_json, ?, registered_at, 'none', 0
                FROM orchestration_retry_failed_attempts WHERE attempt_id=?""",
                (str(uuid4()), "0" * 64, receipt["attempt_id"]),
            )
