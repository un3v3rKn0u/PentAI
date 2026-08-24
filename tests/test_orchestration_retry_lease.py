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
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW, lease_consumption
from test_orchestration_retry_budget_reservation import setup as budget_setup

WORKER_ID = "worker:synthetic:retry-lease"


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationLeaseService, dict[str, Any], dict[str, Any]]:
    budgets, budget_request, _ = budget_setup(tmp_path)
    budget = budgets.reserve(budget_request, now=NOW + timedelta(seconds=9))
    with closing(sqlite3.connect(budgets.database_path)) as connection, connection:
        connection.execute(
            """INSERT INTO worker_runtime_instances(
            worker_id, containment_attestation_id, oci_runtime, runtime_instance_id,
            worker_gateway_network_id, image_digest, container_id, status, created_at,
            updated_at, execution_enabled, version)
            VALUES (?, 'synthetic-retry-lease-attestation', 'podman',
            'synthetic-retry-lease-runtime', 'synthetic-retry-lease-network', ?, ?,
            'running', ?, ?, 0, 2)""",
            (
                WORKER_ID,
                "sha256:" + "e" * 64,
                "f" * 64,
                (NOW + timedelta(seconds=10)).isoformat(),
                (NOW + timedelta(seconds=10)).isoformat(),
            ),
        )
        recovery_generation = connection.execute(
            "SELECT recovery_generation FROM orchestration_task_lease_fences WHERE task_id=?",
            (budget["task_id"],),
        ).fetchone()[0]
    request: dict[str, Any] = {
        "schema_version": "2.0.0",
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
        "retry_activation_id": budget["retry_activation_id"],
        "retry_activation_digest": budget["retry_activation_digest"],
        "retry_attempt_id": budget["retry_attempt_id"],
        "retry_attempt_digest": budget["retry_attempt_digest"],
        "retry_budget_consumption_id": budget["retry_budget_consumption_id"],
        "approval_consumption_id": None,
        "policy_bundle_id": budget["policy_bundle_id"],
        "policy_hash": budget["policy_hash"],
        "worker_id": WORKER_ID,
        "expected_worker_version": 2,
        "expected_recovery_generation": recovery_generation,
        "lease_seconds": 20,
        "requested_at": (NOW + timedelta(seconds=10)).isoformat(),
        "purpose": "coordinate_validation_task",
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationLeaseService(budgets.authorization), request, budget


def mutation(
    state: dict[str, Any], operation: str, *, command_id: str | None = None
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": command_id or str(uuid4()),
        "lease_id": state["lease_id"],
        "worker_id": state["worker_id"],
        "expected_worker_version": state["worker_version"],
        "expected_lease_version": state["lease_version"],
        "lease_generation": state["lease_generation"],
        "fencing_token": state["fencing_token"],
        "expected_recovery_generation": state["recovery_generation"],
        "lease_token": state["lease_token"],
        "operation": operation,
        "lease_seconds": 30 if operation == "renew" else None,
        "requested_at": (NOW + timedelta(seconds=12)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }


def consumption(
    state: dict[str, Any], token: str, request: dict[str, Any], *, command_id: str | None = None
) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "command_id": command_id or str(uuid4()),
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
        "retry_activation_id": state["retry_activation_id"],
        "retry_activation_digest": state["retry_activation_digest"],
        "retry_attempt_id": state["retry_attempt_id"],
        "retry_attempt_digest": state["retry_attempt_digest"],
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
        "purpose": "start_retry_validation_task_coordination",
        "requested_at": request["requested_at"],
        "authority": "none",
        "execution_enabled": False,
    }


def test_acquires_retry_bound_lease_without_transition_or_authority(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path)
    state = service.acquire(request, now=NOW + timedelta(seconds=10))
    token = state.pop("lease_token")
    assert token
    assert contract_issues(state, "orchestration-task-lease-state-v2.schema.json") == ()
    assert state["retry_activation_id"] == request["retry_activation_id"]
    assert state["retry_attempt_id"] == request["retry_attempt_id"]
    assert state["authority"] == "none" and state["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        row = connection.execute(
            "SELECT token_hash, state_json FROM orchestration_task_leases WHERE lease_id=?",
            (state["lease_id"],),
        ).fetchone()
        assert token not in row[0] and token not in row[1]
        assert "lease_token" not in json.loads(row[1])
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (request["task_id"],)
        ).fetchone() == ("ready",)
        assert (
            connection.execute("SELECT COUNT(*) FROM agent_action_intent_links").fetchone()[0]
            == 0
        )
    legacy = lease_consumption(state, token, request)
    with pytest.raises(OrchestrationLeaseError) as denied:
        service.consume(legacy, now=NOW + timedelta(seconds=10))
    assert denied.value.code == "ORCHESTRATION_LEASE_CONSUMPTION_UNSUPPORTED"


def test_consumes_retry_lease_atomically_without_dispatch_or_authority(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    acquired = service.acquire(request, now=NOW + timedelta(seconds=10))
    token = acquired.pop("lease_token")
    command = consumption(acquired, token, request)
    receipt = service.consume(command, now=NOW + timedelta(seconds=10))
    assert contract_issues(
        receipt, "orchestration-task-lease-consumption-receipt-v2.schema.json"
    ) == ()
    assert receipt["retry_activation_id"] == request["retry_activation_id"]
    assert receipt["retry_attempt_id"] == request["retry_attempt_id"]
    assert receipt["resulting_task_state"] == "running"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=10)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (request["task_id"],)
        ).fetchone() == ("running",)
        stored = connection.execute(
            "SELECT receipt_json FROM orchestration_task_lease_consumptions"
        ).fetchone()[0]
        assert token not in stored
        assert (
            connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
            == grants_before
        )


def test_retry_consumption_denies_tampering_direct_transition_and_concurrency(
    tmp_path: Path,
) -> None:
    direct, direct_request, _ = setup(tmp_path / "direct")
    with pytest.raises(OrchestrationError):
        DurablePlanGraphService(direct.database_path).transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "plan_id": direct_request["plan_id"],
                "assessment_id": direct_request["assessment_id"],
                "task_id": direct_request["task_id"],
                "expected_plan_revision": direct_request["expected_plan_revision"],
                "expected_task_revision": direct_request["expected_task_revision"],
                "target_state": "running",
                "requested_at": direct_request["requested_at"],
                "authority": "none",
                "execution_enabled": False,
            }
        )

    tampered, tampered_request, _ = setup(tmp_path / "tampered")
    acquired = tampered.acquire(tampered_request, now=NOW + timedelta(seconds=10))
    token = acquired.pop("lease_token")
    command = consumption(acquired, token, tampered_request)
    command["retry_attempt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationLeaseError) as denied:
        tampered.consume(command, now=NOW + timedelta(seconds=10))
    assert denied.value.code == "ORCHESTRATION_LEASE_CONSUMPTION_BINDING_MISMATCH"

    concurrent, concurrent_request, _ = setup(tmp_path / "concurrent")
    state = concurrent.acquire(concurrent_request, now=NOW + timedelta(seconds=10))
    holder = state.pop("lease_token")
    commands = (
        consumption(state, holder, concurrent_request),
        consumption(state, holder, concurrent_request),
    )

    def consume(candidate: dict[str, Any]) -> str:
        try:
            return str(
                concurrent.consume(candidate, now=NOW + timedelta(seconds=10))[
                    "resulting_task_state"
                ]
            )
        except OrchestrationLeaseError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, commands))
    assert outcomes.count("running") == 1
    assert outcomes.count("ORCHESTRATION_LEASE_CONSUMPTION_BINDING_MISMATCH") == 1


def test_retry_consumption_replay_denies_after_safety_or_recovery_fence(tmp_path: Path) -> None:
    for name in ("safety", "recovery"):
        service, request, _ = setup(tmp_path / name)
        state = service.acquire(request, now=NOW + timedelta(seconds=10))
        token = state.pop("lease_token")
        command = consumption(state, token, request)
        service.consume(command, now=NOW + timedelta(seconds=10))
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (request["task_id"],),
                )
        with pytest.raises(OrchestrationLeaseError) as denied:
            service.consume(command, now=NOW + timedelta(seconds=10))
        assert denied.value.code == "ORCHESTRATION_LEASE_CONSUMPTION_REPLAY_STALE"


def test_malformed_mixed_version_tampered_and_replay_deny(tmp_path: Path) -> None:
    cases = (
        ("schema_version", "3.0.0", "ORCHESTRATION_LEASE_REQUEST_MALFORMED"),
        ("authority", "grant", "ORCHESTRATION_LEASE_REQUEST_MALFORMED"),
        (
            "capability_manifest_digest",
            "sha256:" + "0" * 64,
            "ORCHESTRATION_LEASE_PREREQUISITE_MISMATCH",
        ),
        ("retry_activation_id", str(uuid4()), "ORCHESTRATION_LEASE_PREREQUISITE_MISMATCH"),
    )
    for index, (field, value, code) in enumerate(cases):
        service, request, _ = setup(tmp_path / str(index))
        request[field] = value
        with pytest.raises(OrchestrationLeaseError) as denied:
            service.acquire(request, now=NOW + timedelta(seconds=10))
        assert denied.value.code == code

    service, request, _ = setup(tmp_path / "replay")
    service.acquire(request, now=NOW + timedelta(seconds=10))
    with pytest.raises(OrchestrationLeaseError) as replay:
        service.acquire(request, now=NOW + timedelta(seconds=10))
    assert replay.value.code == "ORCHESTRATION_LEASE_ACQUIRE_REPLAY_DENIED"


def test_concurrent_acquisition_allows_one_holder(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path)
    other = copy.deepcopy(request)
    other["request_id"] = str(uuid4())

    def acquire(document: dict[str, Any]) -> str:
        try:
            return service.acquire(document, now=NOW + timedelta(seconds=10))["lease_id"]
        except OrchestrationLeaseError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(acquire, (request, other)))
    assert outcomes.count("ORCHESTRATION_LEASE_CONFLICT") == 1


def test_renew_release_worker_cancellation_recovery_and_storage_fences(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path / "lifecycle")
    acquired = service.acquire(request, now=NOW + timedelta(seconds=10))
    renewed = service.mutate(
        mutation(acquired, "renew"), now=NOW + timedelta(seconds=12)
    )
    assert renewed["resulting_state"] == "active"
    acquired["lease_version"] = renewed["resulting_lease_version"]
    released = service.mutate(
        mutation(acquired, "release"), now=NOW + timedelta(seconds=12)
    )
    assert released["resulting_state"] == "released"

    for name in ("worker", "task", "safety", "account"):
        fenced, candidate, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=?""",
                    (WORKER_ID,),
                )
            elif name == "task":
                connection.execute(
                    """UPDATE orchestration_tasks SET state='cancelled', revision=revision+1
                    WHERE task_id=?""",
                    (candidate["task_id"],),
                )
            elif name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            else:
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
        with pytest.raises(OrchestrationLeaseError):
            fenced.acquire(candidate, now=NOW + timedelta(seconds=10))

    recovery, recovery_request, _ = setup(tmp_path / "recovery")
    active = recovery.acquire(recovery_request, now=NOW + timedelta(seconds=10))
    events = recovery.recover(now=NOW + timedelta(seconds=11))
    assert len(events) == 1 and events[0]["resulting_state"] == "invalidated"
    with closing(sqlite3.connect(recovery.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_task_leases SET retry_attempt_id=NULL
                WHERE lease_id=?""",
                (active["lease_id"],),
            )
