from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_lease import OrchestrationLeaseError, OrchestrationLeaseService
from pentai_core.orchestration_lease_v3 import (
    OrchestrationLeaseV3Error,
    OrchestrationLeaseV3Service,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_budget_v4 import setup as budget_setup


def setup(tmp_path: Path) -> tuple[OrchestrationLeaseV3Service, dict[str, Any]]:
    budgets, budget_command = budget_setup(tmp_path)
    budget = budgets.reserve_v4(budget_command, now=NOW + timedelta(seconds=44))
    with closing(sqlite3.connect(budgets.database_path)) as connection:
        recovery_generation = connection.execute(
            "SELECT recovery_generation FROM orchestration_task_lease_fences WHERE task_id=?",
            (budget["task_id"],),
        ).fetchone()[0]
    command: dict[str, Any] = {
        "schema_version": "3.0.0",
        "request_id": str(uuid4()),
        "assessment_id": budget["assessment_id"],
        "plan_id": budget["plan_id"],
        "expected_plan_revision": budget["plan_revision"],
        "task_id": budget["task_id"],
        "expected_task_revision": budget["task_revision"],
        "agent_id": budget["agent_id"],
        "capability_manifest_id": budget["capability_manifest_id"],
        "capability_manifest_digest": budget["capability_manifest_digest"],
        "manifest_revision": budget["manifest_revision"],
        "budget_reservation_id": budget["reservation_id"],
        "budget_request_digest": budget["request_digest"],
        "budget_account_version": budget["account_version"],
        "retry_policy_id": budget["retry_policy_id"],
        "retry_policy_digest": budget["retry_policy_digest"],
        "retry_activation_id": budget["retry_activation_id"],
        "retry_activation_digest": budget["retry_activation_digest"],
        "retry_schedule_id": budget["retry_schedule_id"],
        "retry_schedule_digest": budget["retry_schedule_digest"],
        "retry_attempt_id": budget["retry_attempt_id"],
        "retry_attempt_digest": budget["retry_attempt_digest"],
        "attempt_number": 3,
        "prior_retry_budget_consumption_id": budget["prior_retry_budget_consumption_id"],
        "retry_budget_consumption_id": budget["retry_budget_consumption_id"],
        "approval_consumption_id": budget["approval_consumption_id"],
        "policy_bundle_id": budget["policy_bundle_id"],
        "policy_hash": budget["policy_hash"],
        "worker_id": budget["worker_id"],
        "expected_worker_version": budget["worker_version"],
        "expected_recovery_generation": recovery_generation,
        "lease_seconds": 5,
        "requested_at": (NOW + timedelta(seconds=45)).isoformat(),
        "purpose": "coordinate_attempt_three_validation_task",
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationLeaseV3Service(budgets.authorization), command


def consumption(state: dict[str, Any], token: str) -> dict[str, Any]:
    return {
        "schema_version": "3.0.0",
        "command_id": str(uuid4()),
        "assessment_id": state["assessment_id"],
        "plan_id": state["plan_id"],
        "expected_plan_revision": state["plan_revision"],
        "task_id": state["task_id"],
        "expected_task_revision": state["task_revision"],
        "agent_id": state["agent_id"],
        "capability_manifest_id": state["capability_manifest_id"],
        "capability_manifest_digest": state["capability_manifest_digest"],
        "manifest_revision": state["manifest_revision"],
        "budget_reservation_id": state["budget_reservation_id"],
        "budget_request_digest": state["budget_request_digest"],
        "budget_account_version": state["budget_account_version"],
        "retry_policy_id": state["retry_policy_id"],
        "retry_policy_digest": state["retry_policy_digest"],
        "retry_activation_id": state["retry_activation_id"],
        "retry_activation_digest": state["retry_activation_digest"],
        "retry_schedule_id": state["retry_schedule_id"],
        "retry_schedule_digest": state["retry_schedule_digest"],
        "retry_attempt_id": state["retry_attempt_id"],
        "retry_attempt_digest": state["retry_attempt_digest"],
        "attempt_number": 3,
        "prior_retry_budget_consumption_id": state["prior_retry_budget_consumption_id"],
        "retry_budget_consumption_id": state["retry_budget_consumption_id"],
        "approval_consumption_id": state["approval_consumption_id"],
        "policy_bundle_id": state["policy_bundle_id"],
        "policy_hash": state["policy_hash"],
        "worker_id": state["worker_id"],
        "expected_worker_version": state["worker_version"],
        "lease_id": state["lease_id"],
        "expected_lease_version": state["lease_version"],
        "lease_generation": state["lease_generation"],
        "fencing_token": state["fencing_token"],
        "expected_recovery_generation": state["recovery_generation"],
        "lease_state_digest": "sha256:" + content_hash(state),
        "lease_token": token,
        "purpose": "start_attempt_three_validation_coordination",
        "requested_at": (NOW + timedelta(seconds=46)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }


def test_acquires_attempt_three_lease_without_transition_or_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grant_count = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()
    acquired = service.acquire(command, now=NOW + timedelta(seconds=45))
    token = acquired.pop("lease_token")
    assert token
    assert contract_issues(acquired, "orchestration-task-lease-state-v3.schema.json") == ()
    assert acquired["attempt_number"] == 3
    assert acquired["authority"] == "none" and acquired["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        row = connection.execute(
            "SELECT token_hash, state_json FROM orchestration_task_leases_v3 WHERE lease_id=?",
            (acquired["lease_id"],),
        ).fetchone()
        assert token not in row[0] and token not in row[1]
        assert "lease_token" not in json.loads(row[1])
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("ready",)
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone() == grant_count
    with pytest.raises(OrchestrationLeaseV3Error) as replay:
        service.acquire(command, now=NOW + timedelta(seconds=45))
    assert replay.value.code == "ORCHESTRATION_LEASE_V3_ACQUIRE_REPLAY_DENIED"


def test_malformed_mixed_version_cross_lineage_and_changed_replay_deny(
    tmp_path: Path,
) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"attempt_number": 2},
        {"authority": "grant"},
        {"capability_manifest_id": str(uuid4())},
        {"budget_reservation_id": str(uuid4())},
        {"retry_activation_digest": "sha256:" + "0" * 64},
        {"agent_id": "agent://validation/other"},
        {"worker_id": "worker:synthetic:other"},
        {"lease_seconds": 61},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationLeaseV3Error):
            service.acquire(command, now=NOW + timedelta(seconds=45))

    service, command = setup(tmp_path / "changed")
    service.acquire(command, now=NOW + timedelta(seconds=45))
    changed = copy.deepcopy(command)
    changed["lease_seconds"] = 6
    with pytest.raises(OrchestrationLeaseV3Error) as conflict:
        service.acquire(changed, now=NOW + timedelta(seconds=45))
    assert conflict.value.code == "ORCHESTRATION_LEASE_V3_IDENTITY_CONFLICT"


def test_concurrency_worker_safety_account_and_recovery_fences(tmp_path: Path) -> None:
    service, contender = setup(tmp_path / "concurrent")
    commands = (copy.deepcopy(contender), copy.deepcopy(contender))
    commands[1]["request_id"] = str(uuid4())

    def acquire(command: dict[str, Any]) -> str:
        try:
            return str(service.acquire(command, now=NOW + timedelta(seconds=45))["state"])
        except OrchestrationLeaseV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(acquire, commands))
    assert outcomes.count("active") == 1
    assert outcomes.count("ORCHESTRATION_LEASE_V3_CONFLICT") == 1

    for name in ("safety", "worker", "account", "recovery"):
        fenced, command = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
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
                connection.execute(
                    "UPDATE orchestration_budget_accounts SET version=version+1"
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (command["task_id"],),
                )
        with pytest.raises(OrchestrationLeaseV3Error):
            fenced.acquire(command, now=NOW + timedelta(seconds=45))


def test_recovery_invalidates_and_advances_fence_without_token_or_transition(
    tmp_path: Path,
) -> None:
    service, command = setup(tmp_path)
    acquired = service.acquire(command, now=NOW + timedelta(seconds=45))
    token = acquired.pop("lease_token")
    events = service.recover(now=NOW + timedelta(seconds=46))
    assert len(events) == 1 and events[0]["resulting_state"] == "invalidated"
    assert service.recover(now=NOW + timedelta(seconds=46)) == ()
    with closing(sqlite3.connect(service.database_path)) as connection:
        row = connection.execute(
            "SELECT state_json FROM orchestration_task_leases_v3"
        ).fetchone()[0]
        assert token not in row
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("ready",)
        generation = connection.execute(
            "SELECT recovery_generation FROM orchestration_task_lease_fences WHERE task_id=?",
            (command["task_id"],),
        ).fetchone()[0]
        assert generation == command["expected_recovery_generation"] + 1


def test_storage_guards_and_legacy_consumers_reject_v3(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    acquired = service.acquire(command, now=NOW + timedelta(seconds=45))
    token = acquired.pop("lease_token")
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_leases_v3 SET worker_id='worker:forged'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_leases_v3")
    legacy = OrchestrationLeaseService(service.authorization)
    with pytest.raises(OrchestrationLeaseError):
        legacy.consume(
            {
                "schema_version": "3.0.0",
                "command_id": str(uuid4()),
                "lease_id": acquired["lease_id"],
                "lease_token": token,
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW + timedelta(seconds=45),
        )


def test_consumes_attempt_three_lease_atomically_without_dispatch_or_authority(
    tmp_path: Path,
) -> None:
    service, request = setup(tmp_path)
    acquired = service.acquire(request, now=NOW + timedelta(seconds=45))
    token = acquired.pop("lease_token")
    command = consumption(acquired, token)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()
        links_before = connection.execute(
            "SELECT COUNT(*) FROM agent_action_intent_links"
        ).fetchone()
    receipt = service.consume(command, now=NOW + timedelta(seconds=46))
    assert contract_issues(
        receipt, "orchestration-task-lease-consumption-receipt-v3.schema.json"
    ) == ()
    assert receipt["attempt_number"] == 3
    assert receipt["resulting_task_state"] == "running"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=46)) == receipt
    assert service.recover(now=NOW + timedelta(seconds=47)) == ()
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (request["task_id"],)
        ).fetchone() == ("running",)
        stored = connection.execute(
            "SELECT receipt_json FROM orchestration_task_lease_consumptions_v3"
        ).fetchone()[0]
        assert token not in stored and "lease_token" not in json.loads(stored)
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone() == grants_before
        assert connection.execute(
            "SELECT COUNT(*) FROM agent_action_intent_links"
        ).fetchone() == links_before


def test_consumption_denies_transition_bypass_tampering_and_changed_replay(
    tmp_path: Path,
) -> None:
    direct, request = setup(tmp_path / "direct")
    with pytest.raises(OrchestrationError):
        DurablePlanGraphService(direct.database_path).transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "plan_id": request["plan_id"],
                "assessment_id": request["assessment_id"],
                "task_id": request["task_id"],
                "expected_plan_revision": request["expected_plan_revision"],
                "expected_task_revision": request["expected_task_revision"],
                "target_state": "running",
                "requested_at": request["requested_at"],
                "authority": "none",
                "execution_enabled": False,
            }
        )
    with closing(sqlite3.connect(direct.database_path)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_tasks SET state='running', revision=revision+1
                WHERE task_id=?""",
                (request["task_id"],),
            )

    service, request = setup(tmp_path / "tampered")
    state = service.acquire(request, now=NOW + timedelta(seconds=45))
    token = state.pop("lease_token")
    command = consumption(state, token)
    changed = copy.deepcopy(command)
    changed["lease_token"] = "x" * 43
    with pytest.raises(OrchestrationLeaseV3Error) as token_error:
        service.consume(changed, now=NOW + timedelta(seconds=46))
    assert token_error.value.code == "ORCHESTRATION_LEASE_V3_TOKEN_MISMATCH"
    receipt = service.consume(command, now=NOW + timedelta(seconds=46))
    changed = copy.deepcopy(command)
    changed["purpose"] = "start_attempt_three_validation_coordination"
    changed["lease_token"] = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(OrchestrationLeaseV3Error) as replay:
        service.consume(changed, now=NOW + timedelta(seconds=46))
    assert replay.value.code == "ORCHESTRATION_LEASE_V3_CONSUMPTION_IDENTITY_CONFLICT"
    assert receipt["resulting_task_state"] == "running"


def test_consumption_concurrency_and_current_security_fences(tmp_path: Path) -> None:
    service, request = setup(tmp_path / "concurrent")
    state = service.acquire(request, now=NOW + timedelta(seconds=45))
    token = state.pop("lease_token")
    commands = [consumption(state, token), consumption(state, token)]

    def consume_one(command: dict[str, Any]) -> str:
        try:
            return service.consume(command, now=NOW + timedelta(seconds=46))[
                "resulting_task_state"
            ]
        except OrchestrationLeaseV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume_one, commands))
    assert outcomes.count("running") == 1
    assert len([outcome for outcome in outcomes if outcome != "running"]) == 1

    for name in ("safety", "worker", "account", "recovery", "cancelled", "expired"):
        fenced, request = setup(tmp_path / name)
        state = fenced.acquire(request, now=NOW + timedelta(seconds=45))
        token = state.pop("lease_token")
        command = consumption(state, token)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute("UPDATE safety_state SET global_status='paused'")
            elif name == "worker":
                connection.execute(
                    "UPDATE worker_runtime_instances SET version=version+1 WHERE worker_id=?",
                    (state["worker_id"],),
                )
            elif name == "account":
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
            elif name == "recovery":
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (state["task_id"],),
                )
        if name == "cancelled":
            DurablePlanGraphService(fenced.database_path).transition(
                {
                    "schema_version": "1.0.0",
                    "command_id": str(uuid4()),
                    "plan_id": state["plan_id"],
                    "assessment_id": state["assessment_id"],
                    "task_id": state["task_id"],
                    "expected_plan_revision": state["plan_revision"],
                    "expected_task_revision": state["task_revision"],
                    "target_state": "cancelled",
                    "requested_at": (NOW + timedelta(seconds=46)).isoformat(),
                    "authority": "none",
                    "execution_enabled": False,
                },
                now=NOW + timedelta(seconds=46),
            )
        at = NOW + timedelta(seconds=51 if name == "expired" else 46)
        with pytest.raises(OrchestrationLeaseV3Error):
            fenced.consume(command, now=at)
