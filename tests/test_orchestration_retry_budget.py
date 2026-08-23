from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration_budget import OrchestrationBudgetService
from pentai_core.orchestration_retry_budget import (
    OrchestrationRetryBudgetError,
    OrchestrationRetryBudgetService,
)
from pentai_policy import canonical_json
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry import setup as retry_setup


def setup(
    tmp_path: Path, *, failure_class: str = "coordination_timeout"
) -> tuple[OrchestrationRetryBudgetService, dict[str, object], dict[str, object]]:
    retry, evaluation, _ = retry_setup(tmp_path, failure_class=failure_class)
    decision = retry.evaluate(evaluation, now=NOW)
    with closing(sqlite3.connect(retry.database_path)) as connection:
        account_version = connection.execute(
            """SELECT a.version FROM orchestration_budget_accounts a
            JOIN orchestration_task_budget_reservations r ON r.account_id = a.account_id
            WHERE r.reservation_id = ?""",
            (decision["budget_reservation_id"],),
        ).fetchone()[0]
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": decision["assessment_id"],
        "plan_id": decision["plan_id"],
        "expected_plan_revision": decision["plan_revision"],
        "task_id": decision["task_id"],
        "expected_task_revision": decision["task_revision"],
        "attempt_id": decision["attempt_id"],
        "attempt_digest": decision["attempt_digest"],
        "eligibility_decision_id": decision["decision_id"],
        "eligibility_decision_digest": decision["decision_digest"],
        "retry_policy_id": decision["retry_policy_id"],
        "retry_policy_revision": decision["retry_policy_revision"],
        "retry_policy_digest": decision["retry_policy_digest"],
        "budget_reservation_id": decision["budget_reservation_id"],
        "expected_budget_account_version": account_version,
        "proposed_attempt_number": 2,
        "purpose": "consume_validation_retry_budget",
        "requested_at": (NOW + timedelta(seconds=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryBudgetService(retry.authorization), command, decision


def test_consumes_one_unit_atomically_without_activating_work(tmp_path: Path) -> None:
    service, command, decision = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        before = connection.execute(
            """SELECT a.version, r.amounts_json FROM orchestration_budget_accounts a
            JOIN orchestration_task_budget_reservations r ON r.account_id = a.account_id
            WHERE r.reservation_id = ?""",
            (command["budget_reservation_id"],),
        ).fetchone()
    receipt = service.consume(command, now=NOW + timedelta(seconds=5))
    assert (
        contract_issues(receipt, "orchestration-retry-budget-consumption-receipt-v1.schema.json")
        == ()
    )
    assert receipt["eligibility_decision_id"] == decision["decision_id"]
    assert receipt["reserved_retry_units"] == 1
    assert receipt["consumed_retry_units"] == 1
    assert receipt["remaining_retry_units"] == 0
    assert receipt["budget_account_version_before"] == before[0]
    assert receipt["budget_account_version_after"] == before[0] + 1
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=5)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        after = connection.execute(
            """SELECT a.version, r.amounts_json, r.state FROM orchestration_budget_accounts a
            JOIN orchestration_task_budget_reservations r ON r.account_id = a.account_id
            WHERE r.reservation_id = ?""",
            (command["budget_reservation_id"],),
        ).fetchone()
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone()
        assert (
            connection.execute("SELECT COUNT(*) FROM orchestration_task_attempts").fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1
    assert after == (before[0] + 1, before[1], "reserved")
    assert task == ("failed", command["expected_task_revision"])


def test_denied_decision_and_caller_accounting_overrides_deny(tmp_path: Path) -> None:
    denied_service, denied_command, _ = setup(
        tmp_path / "denied", failure_class="checkpoint_stalled"
    )
    with pytest.raises(OrchestrationRetryBudgetError) as denied:
        denied_service.consume(denied_command, now=NOW + timedelta(seconds=5))
    assert denied.value.code == "ORCHESTRATION_RETRY_BUDGET_DECISION_INVALID"

    service, command, _ = setup(tmp_path / "override")
    for field, value in (
        ("consumed_retry_units", 2),
        ("remaining_retry_units", 100),
        ("retryable", True),
        ("authority", "grant"),
    ):
        candidate = copy.deepcopy(command)
        candidate[field] = value
        with pytest.raises(OrchestrationRetryBudgetError) as malformed:
            service.consume(candidate, now=NOW + timedelta(seconds=5))
        assert malformed.value.code == "ORCHESTRATION_RETRY_BUDGET_COMMAND_MALFORMED"


def test_malformed_stale_cross_scope_and_version_fences_deny(tmp_path: Path) -> None:
    cases = (
        (
            {"eligibility_decision_digest": "sha256:" + "0" * 64},
            "ORCHESTRATION_RETRY_BUDGET_DECISION_INVALID",
        ),
        ({"assessment_id": str(uuid4())}, "ORCHESTRATION_RETRY_BUDGET_DECISION_INVALID"),
        ({"proposed_attempt_number": 3}, "ORCHESTRATION_RETRY_BUDGET_COMMAND_MALFORMED"),
        ({"expected_budget_account_version": 2**63}, "ORCHESTRATION_RETRY_BUDGET_VERSION_FENCED"),
        (
            {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
            "ORCHESTRATION_RETRY_BUDGET_COMMAND_STALE",
        ),
    )
    for index, (changes, code) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryBudgetError) as denied:
            service.consume(command, now=NOW + timedelta(seconds=5))
        assert denied.value.code == code


def test_changed_replay_and_concurrent_competing_consumption_deny(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path / "replay")
    service.consume(command, now=NOW + timedelta(seconds=5))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=45)).isoformat()
    with pytest.raises(OrchestrationRetryBudgetError) as conflict:
        service.consume(changed, now=NOW + timedelta(seconds=5))
    assert conflict.value.code == "ORCHESTRATION_RETRY_BUDGET_IDENTITY_CONFLICT"

    concurrent, contender, _ = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, object]) -> str:
        try:
            return str(
                concurrent.consume(candidate, now=NOW + timedelta(seconds=5))["consumption_id"]
            )
        except OrchestrationRetryBudgetError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_BUDGET_") for value in outcomes) == 1
    with closing(sqlite3.connect(concurrent.database_path)) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_retry_budget_consumptions"
            ).fetchone()[0]
            == 1
        )


def test_current_security_state_recovery_and_storage_mutation_deny(tmp_path: Path) -> None:
    safety_service, safety_command, _ = setup(tmp_path / "safety")
    with closing(sqlite3.connect(safety_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationRetryBudgetError) as safety:
        safety_service.consume(safety_command, now=NOW + timedelta(seconds=5))
    assert safety.value.code == "ORCHESTRATION_RETRY_BUDGET_SECURITY_DENIED"

    worker_service, worker_command, _ = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=(SELECT worker_id FROM orchestration_task_leases
            LIMIT 1)"""
        )
    with pytest.raises(OrchestrationRetryBudgetError) as worker:
        worker_service.consume(worker_command, now=NOW + timedelta(seconds=5))
    assert worker.value.code == "ORCHESTRATION_RETRY_BUDGET_SECURITY_DENIED"

    recovery_service, recovery_command, _ = setup(tmp_path / "recovery")
    with closing(sqlite3.connect(recovery_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET state='released',
            released_at=?, release_reason='recovery'""",
            ((NOW + timedelta(seconds=1)).isoformat(),),
        )
    with pytest.raises(OrchestrationRetryBudgetError) as recovery:
        recovery_service.consume(recovery_command, now=NOW + timedelta(seconds=5))
    assert recovery.value.code == "ORCHESTRATION_RETRY_BUDGET_SECURITY_DENIED"

    immutable, immutable_command, _ = setup(tmp_path / "immutable")
    receipt = immutable.consume(immutable_command, now=NOW + timedelta(seconds=5))
    with (
        closing(sqlite3.connect(immutable.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            """UPDATE orchestration_retry_budget_consumptions
            SET remaining_retry_units=99 WHERE consumption_id=?""",
            (receipt["consumption_id"],),
        )


def test_reservation_receipt_tampering_and_account_version_overflow_deny(
    tmp_path: Path,
) -> None:
    tampered_service, tampered_command, _ = setup(tmp_path / "tampered")
    with closing(sqlite3.connect(tampered_service.database_path)) as connection, connection:
        row = connection.execute(
            """SELECT reservation_id, receipt_json
            FROM orchestration_task_budget_reservations"""
        ).fetchone()
        reservation_receipt = json.loads(row[1])
        reservation_receipt["assessment_id"] = str(uuid4())
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET receipt_json = ?
            WHERE reservation_id = ?""",
            (canonical_json(reservation_receipt), row[0]),
        )
    with pytest.raises(OrchestrationRetryBudgetError) as tampered:
        tampered_service.consume(tampered_command, now=NOW + timedelta(seconds=5))
    assert tampered.value.code == "ORCHESTRATION_RETRY_BUDGET_RESERVATION_INVALID"

    overflow_service, overflow_command, _ = setup(tmp_path / "overflow")
    maximum = 2**63 - 1
    with closing(sqlite3.connect(overflow_service.database_path)) as connection, connection:
        connection.execute("UPDATE orchestration_budget_accounts SET version = ?", (maximum,))
    overflow_command["expected_budget_account_version"] = maximum
    with pytest.raises(OrchestrationRetryBudgetError) as overflow:
        overflow_service.consume(overflow_command, now=NOW + timedelta(seconds=5))
    assert overflow.value.code == "ORCHESTRATION_RETRY_BUDGET_VERSION_OVERFLOW"


def test_recovery_releases_reservation_without_refunding_consumed_unit(
    tmp_path: Path,
) -> None:
    service, command, _ = setup(tmp_path)
    receipt = service.consume(command, now=NOW + timedelta(seconds=5))
    released = OrchestrationBudgetService(service.authorization).recover(
        now=NOW + timedelta(seconds=6)
    )
    assert len(released) == 1 and released[0]["state"] == "released"
    with closing(sqlite3.connect(service.database_path)) as connection:
        state = connection.execute(
            """SELECT state FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (receipt["budget_reservation_id"],),
        ).fetchone()[0]
        consumed = connection.execute(
            """SELECT SUM(consumed_retry_units)
            FROM orchestration_retry_budget_consumptions WHERE budget_reservation_id = ?""",
            (receipt["budget_reservation_id"],),
        ).fetchone()[0]
    assert state == "released" and consumed == 1
    with pytest.raises(OrchestrationRetryBudgetError) as replay:
        service.consume(command, now=NOW + timedelta(seconds=6))
    assert replay.value.code == "ORCHESTRATION_RETRY_BUDGET_SECURITY_DENIED"
