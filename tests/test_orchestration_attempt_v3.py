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
from pentai_core.orchestration_attempt_v3 import (
    OrchestrationAttemptV3Error,
    OrchestrationAttemptV3Service,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_failure_v3 import setup as failure_setup


def setup(tmp_path: Path) -> tuple[OrchestrationAttemptV3Service, dict[str, Any]]:
    failures, failure_command = failure_setup(tmp_path)
    failure = failures.record(failure_command, now=NOW + timedelta(seconds=48))
    command = {
        "schema_version": "3.0.0",
        "command_id": str(uuid4()),
        "assessment_id": failure["assessment_id"],
        "plan_id": failure["plan_id"],
        "expected_plan_revision": failure["resulting_plan_revision"],
        "task_id": failure["task_id"],
        "expected_task_revision": failure["resulting_task_revision"],
        "retry_attempt_id": failure["retry_attempt_id"],
        "retry_attempt_digest": failure["retry_attempt_digest"],
        "failure_id": failure["failure_id"],
        "failure_receipt_digest": "sha256:" + content_hash(failure),
        "attempt_number": 3,
        "purpose": "register_failed_validation_attempt_three",
        "requested_at": (NOW + timedelta(seconds=48)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationAttemptV3Service(failures.authorization), command


def test_registers_terminal_attempt_without_transition_or_attempt_four(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        revisions = connection.execute(
            "SELECT p.revision,t.revision,t.state FROM orchestration_plans p "
            "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
            (command["task_id"],),
        ).fetchone()
    receipt = service.register(command, now=NOW + timedelta(seconds=48))
    assert contract_issues(receipt, "orchestration-task-attempt-receipt-v3.schema.json") == ()
    assert (
        receipt["attempt_number"],
        receipt["attempt_state"],
        receipt["terminal_retry_ceiling"],
    ) == (3, "failed", 3)
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.register(command, now=NOW + timedelta(seconds=48)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute(
                "SELECT p.revision,t.revision,t.state FROM orchestration_plans p "
                "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
                (command["task_id"],),
            ).fetchone()
            == revisions
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_retry_attempts_v2").fetchone()[0]
            == 1
        )


def test_malformed_mixed_tampered_cross_scope_and_legacy_deny(tmp_path: Path) -> None:
    for index, changes in enumerate(
        (
            {"schema_version": "2.0.0"},
            {"attempt_number": 4},
            {"authority": "grant"},
            {"retry_attempt_digest": "sha256:" + "0" * 64},
            {"failure_id": str(uuid4())},
            {"task_id": str(uuid4())},
            {"diagnostic": "synthetic stack"},
        )
    ):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationAttemptV3Error):
            service.register(command, now=NOW + timedelta(seconds=48))
    service, command = setup(tmp_path / "legacy")
    with pytest.raises(OrchestrationAttemptError):
        OrchestrationAttemptService(service.authorization).register(
            command, now=NOW + timedelta(seconds=48)
        )


def test_changed_replay_concurrency_security_and_storage_fences(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    service.register(command, now=NOW + timedelta(seconds=48))
    changed = copy.deepcopy(command)
    changed["failure_receipt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationAttemptV3Error) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=48))
    assert conflict.value.code == "ORCHESTRATION_ATTEMPT_V3_IDENTITY_CONFLICT"

    concurrent, candidate = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(candidate), copy.deepcopy(candidate))
    contenders[1]["command_id"] = str(uuid4())

    def register(value: dict[str, Any]) -> str:
        try:
            return concurrent.register(value, now=NOW + timedelta(seconds=48))["attempt_id"]
        except OrchestrationAttemptV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, contenders))
    assert sum(value.startswith("ORCHESTRATION_ATTEMPT_V3_") for value in outcomes) == 1

    for name, sql in (
        ("safety", "UPDATE safety_state SET global_status='paused',generation=generation+1"),
        ("cancel", "UPDATE engagements SET status='revoked'"),
        (
            "worker",
            "UPDATE worker_runtime_instances SET status='termination_requested',version=version+1",
        ),
        ("account", "UPDATE orchestration_budget_accounts SET version=version+1"),
        (
            "recovery",
            "UPDATE orchestration_task_lease_fences SET "
            "recovery_generation=recovery_generation+1,version=version+1",
        ),
    ):
        fenced, fenced_command = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            connection.execute(sql)
        with pytest.raises(OrchestrationAttemptV3Error) as denied:
            fenced.register(fenced_command, now=NOW + timedelta(seconds=48))
        assert denied.value.code == "ORCHESTRATION_ATTEMPT_V3_SECURITY_DENIED"

    stored, stored_command = setup(tmp_path / "storage")
    receipt = stored.register(stored_command, now=NOW + timedelta(seconds=48))
    with closing(sqlite3.connect(stored.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_retry_failed_attempts_v3 SET authority='grant'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_retry_failed_attempts_v3")
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_retry_failed_attempts_v3 WHERE attempt_id=?",
                (receipt["attempt_id"],),
            ).fetchone()[0]
            == 1
        )
