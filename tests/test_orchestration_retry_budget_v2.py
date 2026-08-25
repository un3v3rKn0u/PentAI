from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import test_orchestration_budget
from pentai_core.orchestration_retry_budget import (
    OrchestrationRetryBudgetError,
    OrchestrationRetryBudgetService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_evaluation_v2 import setup as evaluation_setup


def setup(tmp_path: Path) -> tuple[OrchestrationRetryBudgetService, dict[str, object]]:
    retry, evaluation = evaluation_setup(tmp_path)
    decision = retry.evaluate(evaluation, now=NOW + timedelta(seconds=40))
    assert decision["outcome"] == "eligible"
    with closing(sqlite3.connect(retry.database_path)) as connection:
        account_version = connection.execute(
            """SELECT version FROM orchestration_budget_accounts
            WHERE account_id=(SELECT budget_account_id
            FROM orchestration_retry_budget_consumptions
            WHERE consumption_id=?)""",
            (decision["retry_budget_consumption_id"],),
        ).fetchone()[0]
    command: dict[str, object] = {
        "schema_version": "2.0.0",
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
        "prior_retry_budget_consumption_id": decision["retry_budget_consumption_id"],
        "expected_budget_account_version": account_version,
        "proposed_attempt_number": 3,
        "purpose": "consume_retry_validation_budget",
        "requested_at": (NOW + timedelta(seconds=40)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryBudgetService(retry.authorization), command


def test_consumes_second_reserved_unit_without_activation(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.consume(command, now=NOW + timedelta(seconds=40))
    assert contract_issues(
        receipt, "orchestration-retry-budget-consumption-receipt-v2.schema.json"
    ) == ()
    assert receipt["reserved_retry_units"] == 2
    assert receipt["previous_consumed_retry_units"] == 1
    assert receipt["consumed_retry_units"] == 1
    assert receipt["remaining_retry_units"] == 0
    assert receipt["proposed_attempt_number"] == 3
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=40)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("failed",)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_budget_consumptions_v2"
        ).fetchone() == (1,)


def test_denied_mixed_tampered_and_caller_accounting_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "1.0.0"},
        {"proposed_attempt_number": 2},
        {"eligibility_decision_digest": "sha256:" + "0" * 64},
        {"consumed_retry_units": 1},
        {"remaining_retry_units": 10},
        {"authority": "grant"},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryBudgetError):
            service.consume(command, now=NOW + timedelta(seconds=40))


def test_one_unit_lineage_denies_before_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(test_orchestration_budget, "RETRY_UNITS", 1)
    retry, evaluation = evaluation_setup(tmp_path)
    decision = retry.evaluate(evaluation, now=NOW + timedelta(seconds=40))
    assert decision["outcome"] == "denied"
    assert decision["reason_code"] == "RETRY_DENIED_CAPACITY_UNAVAILABLE"
    with closing(sqlite3.connect(retry.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_budget_consumptions_v2"
        ).fetchone() == (0,)


def test_replay_concurrency_exhaustion_and_security_fences(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    accepted = service.consume(command, now=NOW + timedelta(seconds=40))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=55)).isoformat()
    with pytest.raises(OrchestrationRetryBudgetError) as conflict:
        service.consume(changed, now=NOW + timedelta(seconds=40))
    assert conflict.value.code == "ORCHESTRATION_RETRY_BUDGET_IDENTITY_CONFLICT"
    assert service.consume(command, now=NOW + timedelta(seconds=40)) == accepted

    concurrent, contender = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, object]) -> str:
        try:
            return str(
                concurrent.consume(candidate, now=NOW + timedelta(seconds=40))["consumption_id"]
            )
        except OrchestrationRetryBudgetError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_BUDGET_") for value in outcomes) == 1

    for name in ("safety", "cancel", "worker", "recovery"):
        fenced, fenced_command = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    "UPDATE engagements SET status='revoked' WHERE id=?",
                    (fenced_command["assessment_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id='worker:synthetic:retry-lease'"""
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (fenced_command["task_id"],),
                )
        with pytest.raises(OrchestrationRetryBudgetError):
            fenced.consume(fenced_command, now=NOW + timedelta(seconds=40))


def test_storage_is_immutable_and_direct_bypass_denies(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.consume(command, now=NOW + timedelta(seconds=40))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_retry_budget_consumptions_v2
                SET authority='grant' WHERE consumption_id=?""",
                (receipt["consumption_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_retry_budget_consumptions_v2 WHERE consumption_id=?",
                (receipt["consumption_id"],),
            )
