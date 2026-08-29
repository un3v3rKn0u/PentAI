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
from pentai_core.orchestration_terminal import (
    OrchestrationTerminalError,
    OrchestrationTerminalService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_attempt_v3 import setup as attempt_setup
from test_orchestration_budget import NOW


def setup(tmp_path: Path) -> tuple[OrchestrationTerminalService, dict[str, Any]]:
    attempts, attempt_command = attempt_setup(tmp_path)
    attempt = attempts.register(attempt_command, now=NOW + timedelta(seconds=48))
    command = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "expected_plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "expected_task_revision": attempt["task_revision"],
        "failed_attempt_id": attempt["attempt_id"],
        "failed_attempt_digest": "sha256:" + content_hash(attempt),
        "retry_policy_id": attempt["retry_policy_id"],
        "retry_policy_digest": attempt["retry_policy_digest"],
        "attempt_number": 3,
        "purpose": "decide_attempt_three_terminal_disposition",
        "requested_at": (NOW + timedelta(seconds=49)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationTerminalService(attempts.authorization), command


def test_decides_inert_dead_letter_eligibility_without_transition(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        before = connection.execute(
            "SELECT p.revision,t.revision,t.state FROM orchestration_plans p "
            "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
            (command["task_id"],),
        ).fetchone()
    decision = service.decide(command, now=NOW + timedelta(seconds=49))
    assert contract_issues(
        decision, "orchestration-terminal-disposition-decision-v1.schema.json"
    ) == ()
    assert decision["outcome"] == "dead_letter_eligible"
    assert decision["reason_code"] == "retry_ceiling_exhausted"
    assert decision["additional_attempts_permitted"] == 0
    assert not decision["dead_letter_transition_enabled"]
    assert not decision["queue_enabled"] and not decision["operator_review_enabled"]
    assert decision["authority"] == "none" and decision["execution_enabled"] is False
    assert service.decide(command, now=NOW + timedelta(seconds=49)) == decision
    with closing(sqlite3.connect(service.database_path)) as connection:
        after = connection.execute(
            "SELECT p.revision,t.revision,t.state FROM orchestration_plans p "
            "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
            (command["task_id"],),
        ).fetchone()
        assert after == before


def test_malformed_mixed_tampered_and_caller_semantics_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"attempt_number": 2},
        {"attempt_number": 4},
        {"authority": "grant"},
        {"failed_attempt_digest": "sha256:" + "0" * 64},
        {"retry_policy_digest": "sha256:" + "0" * 64},
        {"task_id": str(uuid4())},
        {"outcome": "operator_review"},
        {"queue": "synthetic"},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationTerminalError):
            service.decide(command, now=NOW + timedelta(seconds=49))


def test_changed_replay_concurrency_and_current_security_fences(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    service.decide(command, now=NOW + timedelta(seconds=49))
    changed = copy.deepcopy(command)
    changed["failed_attempt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationTerminalError) as conflict:
        service.decide(changed, now=NOW + timedelta(seconds=49))
    assert conflict.value.code == "ORCHESTRATION_TERMINAL_IDENTITY_CONFLICT"

    concurrent, candidate = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(candidate), copy.deepcopy(candidate))
    contenders[1]["command_id"] = str(uuid4())

    def decide(value: dict[str, Any]) -> str:
        try:
            return concurrent.decide(value, now=NOW + timedelta(seconds=49))["decision_id"]
        except OrchestrationTerminalError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(decide, contenders))
    assert sum(value.startswith("ORCHESTRATION_TERMINAL_") for value in outcomes) == 1

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
        with pytest.raises(OrchestrationTerminalError) as denied:
            fenced.decide(fenced_command, now=NOW + timedelta(seconds=49))
        assert denied.value.code == "ORCHESTRATION_TERMINAL_SECURITY_DENIED"


def test_storage_guards_are_immutable_and_version_exact(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_terminal_dispositions(
                decision_id,command_id,command_digest,assessment_id,plan_id,plan_revision,
                task_id,task_revision,failed_attempt_id,failed_attempt_digest,failure_id,
                failure_receipt_digest,retry_policy_id,retry_policy_digest,outcome,
                reason_code,decision_json,decision_hash,decided_at,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'dead_letter_eligible',
                'retry_ceiling_exhausted','{}',?,?, 'none',0)""",
                (
                    str(uuid4()),
                    str(uuid4()),
                    "sha256:" + "0" * 64,
                    command["assessment_id"],
                    command["plan_id"],
                    command["expected_plan_revision"],
                    command["task_id"],
                    command["expected_task_revision"],
                    command["failed_attempt_id"],
                    command["failed_attempt_digest"],
                    str(uuid4()),
                    "sha256:" + "0" * 64,
                    command["retry_policy_id"],
                    command["retry_policy_digest"],
                    "0" * 64,
                    command["requested_at"],
                ),
            )
    decision = service.decide(command, now=NOW + timedelta(seconds=49))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_terminal_dispositions SET authority='grant'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_terminal_dispositions")
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_terminal_dispositions WHERE decision_id=?",
            (decision["decision_id"],),
        ).fetchone()[0] == 1
