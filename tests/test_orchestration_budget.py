from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.agent_intent import AgentActionIntentService
from pentai_core.ai_provider_config import ProviderPolicy
from pentai_core.ai_provider_registry import build_provider_policy
from pentai_core.migrate import migrate
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_budget import (
    OrchestrationBudgetError,
    OrchestrationBudgetService,
)
from pentai_core.orchestration_lease import (
    OrchestrationLeaseError,
    OrchestrationLeaseService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues

from scripts.owned_fixture_authority import prepare_owned_fixture_session

NOW = datetime.now(UTC).replace(microsecond=0)
PLAN_ID = "33333333-3333-4333-8333-333333333333"
TASK_ID = "44444444-4444-4444-8444-444444444444"
WORKER_ID = "synthetic-worker-lease"
RETRY_UNITS = 2


def _provider_policy() -> ProviderPolicy:
    return build_provider_policy(
        {
            "schema_version": "1.0.0",
            "registry_id": "55555555-5555-4555-8555-555555555555",
            "revision": 3,
            "providers": [
                {
                    "provider_id": "local-approved",
                    "provider_type": "local_runtime",
                    "models": ["local-model-v1"],
                    "allowed_input_classifications": ["public"],
                    "state": "enabled",
                }
            ],
            "budget_ceilings": {
                "max_input_tokens": 100,
                "max_output_tokens": 50,
                "max_requests": 2,
                "max_cost_microusd": 1000,
                "max_runtime_seconds": 30,
            },
            "remote_providers_enabled": False,
            "configured_at": (NOW - timedelta(days=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=10)).isoformat(),
            "execution_enabled": False,
        },
        now=NOW,
    )


def _configuration() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "configuration_id": "66666666-6666-4666-8666-666666666666",
        "provider_type": "local_runtime",
        "provider_id": "local-approved",
        "model_id": "local-model-v1",
        "secret_ref": None,
        "privacy_classification": "local_device",
        "allowed_input_classifications": ["public"],
        "budgets": {
            "max_input_tokens": 100,
            "max_output_tokens": 50,
            "max_requests": 2,
            "max_cost_microusd": 0,
            "max_runtime_seconds": 30,
        },
        "remote_provider_opt_in": False,
        "configured_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "execution_enabled": False,
    }


def setup(
    tmp_path: Path, *, task_state: str = "running"
) -> tuple[OrchestrationBudgetService, dict[str, Any]]:
    database = tmp_path / "orchestration-budget.db"
    migrate(database)
    authorization, session = prepare_owned_fixture_session(
        database_path=database, source_store_path=tmp_path / "sources"
    )
    with closing(sqlite3.connect(database)) as connection:
        assessment_id, policy_id, policy_hash = connection.execute(
            """SELECT e.id, e.active_policy_id, p.content_hash FROM engagements e
            JOIN policy_bundles p ON p.id = e.active_policy_id
            JOIN budget_reservations b ON b.engagement_id = e.id
            WHERE b.reservation_id = ?""",
            (session["reservation_id"],),
        ).fetchone()
    graph = {
        "schema_version": "1.0.0",
        "plan_id": PLAN_ID,
        "assessment_id": assessment_id,
        "idempotency_key": "synthetic-budget-plan-0001",
        "revision": 1,
        "state": "active",
        "tasks": [
            {
                "task_id": TASK_ID,
                "task_type": "validation",
                "objective": "Reserve synthetic non-executing task budget.",
                "input_refs": [],
                "requires_human_approval": False,
                "state": "pending",
                "revision": 1,
                "created_at": NOW.isoformat(),
                "updated_at": NOW.isoformat(),
                "authority": "none",
                "execution_enabled": False,
            }
        ],
        "dependencies": [],
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    plans = DurablePlanGraphService(database)
    plans.create(graph)
    if task_state == "running":
        ready_manifest = AgentActionIntentService(authorization).issue_capability_manifest(
            assessment_id=assessment_id,
            plan_id=PLAN_ID,
            expected_plan_revision=1,
            task_id=TASK_ID,
            expected_task_revision=1,
            agent_id="agent://validation/budget-fixture",
            policy_bundle_id=policy_id,
            policy_hash=policy_hash,
            task_state="ready",
            now=NOW,
        )
        preparation = OrchestrationBudgetService(authorization)
        preparation_account = preparation.activate_account(
            assessment_id=assessment_id,
            policy_bundle_id=policy_id,
            policy_hash=policy_hash,
            configuration=_configuration(),
            provider_policy=_provider_policy(),
            maximum_retries=3,
            maximum_task_amounts={
                "input_tokens": 60,
                "output_tokens": 30,
                "requests": 2,
                "cost_microusd": 0,
                "runtime_seconds": 20,
                "retries": 2,
            },
            now=NOW,
        )
        ready_reservation = preparation.reserve(
            {
                "schema_version": "2.0.0",
                "request_id": str(uuid4()),
                "account_id": preparation_account["account_id"],
                "expected_account_version": preparation_account["version"],
                "assessment_id": assessment_id,
                "plan_id": PLAN_ID,
                "expected_plan_revision": 1,
                "task_id": TASK_ID,
                "expected_task_revision": 1,
                "task_state": "ready",
                "agent_id": "agent://validation/budget-fixture",
                "capability_manifest_id": ready_manifest["manifest_id"],
                "expected_manifest_revision": 1,
                "policy_bundle_id": policy_id,
                "policy_hash": policy_hash,
                "purpose": "reserve_validation_task_budget",
                "amounts": {
                    "input_tokens": 1,
                    "output_tokens": 0,
                    "requests": 0,
                    "cost_microusd": 0,
                    "runtime_seconds": 0,
                    "retries": 0,
                },
                "requested_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW,
        )
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(
                """INSERT INTO worker_runtime_instances(
                worker_id, containment_attestation_id, oci_runtime, runtime_instance_id,
                worker_gateway_network_id, image_digest, container_id, status, created_at,
                updated_at, execution_enabled, version)
                VALUES (?, 'synthetic-preparation-attestation', 'podman',
                'synthetic-preparation-runtime', 'synthetic-preparation-network', ?, ?,
                'running', ?, ?, 0, 2)""",
                (WORKER_ID, "sha256:" + "c" * 64, "d" * 64, NOW.isoformat(), NOW.isoformat()),
            )
        leases = OrchestrationLeaseService(authorization)
        lease_request = {
            "schema_version": "1.0.0",
            "request_id": str(uuid4()),
            "assessment_id": assessment_id,
            "plan_id": PLAN_ID,
            "expected_plan_revision": 1,
            "task_id": TASK_ID,
            "expected_task_revision": 1,
            "agent_id": "agent://validation/budget-fixture",
            "capability_manifest_id": ready_manifest["manifest_id"],
            "manifest_revision": 1,
            "budget_reservation_id": ready_reservation["reservation_id"],
            "budget_account_version": ready_reservation["account_version"],
            "approval_consumption_id": None,
            "policy_bundle_id": policy_id,
            "policy_hash": policy_hash,
            "worker_id": WORKER_ID,
            "expected_worker_version": 2,
            "expected_recovery_generation": 1,
            "lease_seconds": 30,
            "requested_at": NOW.isoformat(),
            "purpose": "coordinate_validation_task",
            "authority": "none",
            "execution_enabled": False,
        }
        prepared = leases.acquire(lease_request, now=NOW)
        preparation_token = prepared.pop("lease_token")
        leases.consume(lease_consumption(prepared, preparation_token, lease_request), now=NOW)
        preparation.recover(now=NOW)
    plan_revision = 2 if task_state == "running" else 1
    task_revision = 2 if task_state == "running" else 1
    manifest = AgentActionIntentService(authorization).issue_capability_manifest(
        assessment_id=assessment_id,
        plan_id=PLAN_ID,
        expected_plan_revision=plan_revision,
        task_id=TASK_ID,
        expected_task_revision=task_revision,
        agent_id="agent://validation/budget-fixture",
        policy_bundle_id=policy_id,
        policy_hash=policy_hash,
        task_state=task_state,
        now=NOW,
    )
    service = OrchestrationBudgetService(authorization)
    account = service.activate_account(
        assessment_id=assessment_id,
        policy_bundle_id=policy_id,
        policy_hash=policy_hash,
        configuration=_configuration(),
        provider_policy=_provider_policy(),
        maximum_retries=3,
        maximum_task_amounts={
            "input_tokens": 60,
            "output_tokens": 30,
            "requests": 2,
            "cost_microusd": 0,
            "runtime_seconds": 20,
            "retries": 2,
        },
        now=NOW,
    )
    request = {
        "schema_version": "1.0.0" if task_state == "running" else "2.0.0",
        "request_id": str(uuid4()),
        "account_id": account["account_id"],
        "expected_account_version": account["version"],
        "assessment_id": assessment_id,
        "plan_id": PLAN_ID,
        "expected_plan_revision": plan_revision,
        "task_id": TASK_ID,
        "expected_task_revision": task_revision,
        "agent_id": "agent://validation/budget-fixture",
        "capability_manifest_id": manifest["manifest_id"],
        "expected_manifest_revision": 1,
        "policy_bundle_id": policy_id,
        "policy_hash": policy_hash,
        "purpose": "reserve_validation_task_budget",
        "amounts": {
            "input_tokens": 10,
            "output_tokens": 5,
            "requests": 1,
            "cost_microusd": 0,
            "runtime_seconds": 3,
            "retries": RETRY_UNITS,
        },
        "requested_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    if task_state != "running":
        request["task_state"] = task_state
    return service, request


def test_v2_reserves_ready_task_budget_without_transition_or_authority(tmp_path: Path) -> None:
    service, request = setup(tmp_path, task_state="ready")
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    receipt = service.reserve(request, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection:
        manifest = json.loads(
            connection.execute("SELECT manifest_json FROM task_capability_manifests").fetchone()[0]
        )
    assert contract_issues(manifest, "task-capability-manifest-v2.schema.json") == ()
    assert manifest["task_state"] == "ready"
    assert contract_issues(receipt, "orchestration-task-budget-reservation-v2.schema.json") == ()
    assert receipt["task_state"] == "ready"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?", (TASK_ID,)
        ).fetchone()
        assert tuple(task) == ("ready", 1)
        assert (
            connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == grants_before
        )


def test_v2_ready_binding_denies_missing_ambiguous_and_changed_state(tmp_path: Path) -> None:
    service, request = setup(tmp_path, task_state="ready")
    for change in (
        {"task_state": "blocked"},
        {"task_state": "running"},
        {"schema_version": "3.0.0"},
    ):
        with pytest.raises(OrchestrationBudgetError) as denied:
            service.reserve(dict(request, **change), now=NOW)
        assert denied.value.code in {
            "ORCHESTRATION_BUDGET_REQUEST_MALFORMED",
            "ORCHESTRATION_BUDGET_TASK_FENCED",
        }
    missing = copy.deepcopy(request)
    del missing["task_state"]
    with pytest.raises(OrchestrationBudgetError) as malformed:
        service.reserve(missing, now=NOW)
    assert malformed.value.code == "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"


def test_v2_ready_replay_is_exact_and_state_change_is_recovery_fenced(tmp_path: Path) -> None:
    service, request = setup(tmp_path, task_state="ready")
    receipt = service.reserve(request, now=NOW)
    assert service.reserve(request, now=NOW) == receipt
    DurablePlanGraphService(service.database_path).transition(
        {
            "schema_version": "1.0.0",
            "command_id": "77777777-7777-4777-8777-777777777777",
            "plan_id": PLAN_ID,
            "assessment_id": request["assessment_id"],
            "task_id": TASK_ID,
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
            "target_state": "cancelled",
            "requested_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        now=NOW,
    )
    with pytest.raises(OrchestrationBudgetError) as stale:
        service.reserve(request, now=NOW)
    assert stale.value.code == "ORCHESTRATION_BUDGET_PLAN_FENCED"
    released = service.recover(now=NOW)
    assert released[0]["release_reason"] == "cancelled"
    assert released[0]["task_state"] == "ready"


def lease_setup(
    tmp_path: Path,
) -> tuple[OrchestrationLeaseService, dict[str, Any]]:
    budget_service, budget_request = setup(tmp_path, task_state="ready")
    reservation = budget_service.reserve(budget_request, now=NOW)
    with closing(sqlite3.connect(budget_service.database_path)) as connection, connection:
        connection.execute(
            """INSERT INTO worker_runtime_instances(
            worker_id, containment_attestation_id, oci_runtime, runtime_instance_id,
            worker_gateway_network_id, image_digest, container_id, status, created_at,
            updated_at, execution_enabled, version)
            VALUES (?, ?, 'podman', ?, ?, ?, ?, 'running', ?, ?, 0, 2)""",
            (
                WORKER_ID,
                "synthetic-containment-attestation",
                "synthetic-runtime-instance",
                "synthetic-worker-gateway",
                "sha256:" + "a" * 64,
                "b" * 64,
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )
    request = {
        "schema_version": "1.0.0",
        "request_id": "88888888-8888-4888-8888-888888888888",
        "assessment_id": budget_request["assessment_id"],
        "plan_id": PLAN_ID,
        "expected_plan_revision": 1,
        "task_id": TASK_ID,
        "expected_task_revision": 1,
        "agent_id": budget_request["agent_id"],
        "capability_manifest_id": budget_request["capability_manifest_id"],
        "manifest_revision": 1,
        "budget_reservation_id": reservation["reservation_id"],
        "budget_account_version": reservation["account_version"],
        "approval_consumption_id": None,
        "policy_bundle_id": budget_request["policy_bundle_id"],
        "policy_hash": budget_request["policy_hash"],
        "worker_id": WORKER_ID,
        "expected_worker_version": 2,
        "expected_recovery_generation": 1,
        "lease_seconds": 30,
        "requested_at": NOW.isoformat(),
        "purpose": "coordinate_validation_task",
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationLeaseService(budget_service.authorization), request


def lease_command(state: dict[str, Any], token: str, operation: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "operation": operation,
        "lease_id": state["lease_id"],
        "lease_token": token,
        "worker_id": state["worker_id"],
        "expected_worker_version": state["worker_version"],
        "expected_lease_version": state["lease_version"],
        "lease_generation": state["lease_generation"],
        "fencing_token": state["fencing_token"],
        "expected_recovery_generation": state["recovery_generation"],
        "requested_at": (NOW + timedelta(seconds=1)).isoformat(),
        "lease_seconds": 45 if operation == "renew" else None,
        "authority": "none",
        "execution_enabled": False,
    }


def lease_consumption(
    state: dict[str, Any], token: str, request: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": state["assessment_id"],
        "plan_id": state["plan_id"],
        "expected_plan_revision": state["plan_revision"],
        "task_id": state["task_id"],
        "expected_task_revision": state["task_revision"],
        "agent_id": state["agent_id"],
        "capability_manifest_id": state["capability_manifest_id"],
        "manifest_revision": state["manifest_revision"],
        "budget_reservation_id": state["budget_reservation_id"],
        "budget_account_version": state["budget_account_version"],
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
        "purpose": "start_validation_task_coordination",
        "requested_at": request["requested_at"],
        "authority": "none",
        "execution_enabled": False,
    }


def test_lease_consumption_atomically_starts_coordination_without_dispatch(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    command = lease_consumption(acquired, token, request)
    receipt = service.consume(command, now=NOW)
    assert contract_issues(
        receipt, "orchestration-task-lease-consumption-receipt-v1.schema.json"
    ) == ()
    assert receipt["resulting_task_state"] == "running"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?", (TASK_ID,)
        ).fetchone()
        lease = connection.execute(
            "SELECT state, lease_version FROM orchestration_task_leases"
        ).fetchone()
        grants = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
        stored = " ".join(
            str(value)
            for value in connection.execute(
                "SELECT receipt_json, command_digest FROM orchestration_task_lease_consumptions"
            ).fetchone()
        )
    assert task == ("running", 2)
    assert lease == ("released", 2)
    assert grants == grants_before
    assert token not in stored


def test_lease_consumption_denies_general_transition_and_stale_or_tampered_holder(
    tmp_path: Path,
) -> None:
    service, request = lease_setup(tmp_path)
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    with pytest.raises(OrchestrationError) as direct:
        DurablePlanGraphService(service.database_path).transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "plan_id": PLAN_ID,
                "assessment_id": request["assessment_id"],
                "task_id": TASK_ID,
                "expected_plan_revision": 1,
                "expected_task_revision": 1,
                "target_state": "running",
                "requested_at": NOW.isoformat(),
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW,
        )
    assert getattr(direct.value, "code", None) == "ORCHESTRATION_TRANSITION_DENIED"
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """UPDATE orchestration_tasks SET state='running', revision=revision+1
                WHERE task_id=?""",
                (TASK_ID,),
            )
    command = lease_consumption(acquired, token, request)
    for change, code in (
        ({"lease_token": "x" * 43}, "ORCHESTRATION_LEASE_TOKEN_MISMATCH"),
        (
            {"lease_state_digest": "sha256:" + "0" * 64},
            "ORCHESTRATION_LEASE_STATE_TAMPERED",
        ),
        (
            {"fencing_token": acquired["fencing_token"] + 1},
            "ORCHESTRATION_LEASE_CONSUMPTION_BINDING_MISMATCH",
        ),
    ):
        with pytest.raises(OrchestrationLeaseError) as denied:
            service.consume(dict(command, command_id=str(uuid4()), **change), now=NOW)
        assert denied.value.code == code


def test_lease_consumption_concurrency_allows_one_transition(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    commands = (
        lease_consumption(acquired, token, request),
        lease_consumption(acquired, token, request),
    )

    def consume(value: dict[str, Any]) -> str:
        try:
            return str(service.consume(value, now=NOW)["resulting_task_state"])
        except OrchestrationLeaseError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, commands))
    assert outcomes.count("running") == 1
    assert outcomes.count("ORCHESTRATION_LEASE_CONSUMPTION_BINDING_MISMATCH") == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_lease_consumptions"
        ).fetchone()[0] == 1


def test_consumed_running_task_uses_existing_terminal_and_recovery_rules(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    service.consume(lease_consumption(acquired, token, request), now=NOW)
    plans = DurablePlanGraphService(service.database_path)
    completed = plans.transition(
        {
            "schema_version": "1.0.0",
            "command_id": str(uuid4()),
            "plan_id": PLAN_ID,
            "assessment_id": request["assessment_id"],
            "task_id": TASK_ID,
            "expected_plan_revision": 2,
            "expected_task_revision": 2,
            "target_state": "succeeded",
            "requested_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        now=NOW,
    )
    assert completed["state"] == "completed"

    recovery, recovery_request = lease_setup(tmp_path / "recovery")
    recovery_lease = recovery.acquire(recovery_request, now=NOW)
    recovery_token = recovery_lease.pop("lease_token")
    recovery.consume(
        lease_consumption(recovery_lease, recovery_token, recovery_request), now=NOW
    )
    recovered = DurablePlanGraphService(recovery.database_path)
    assert recovered.recover(now=NOW + timedelta(seconds=1)) == [PLAN_ID]
    assert recovered.get(PLAN_ID)["tasks"][0]["state"] == "failed"


def test_lease_acquisition_returns_token_once_without_authority_or_dispatch(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    assert len(token) >= 43
    assert contract_issues(acquired, "orchestration-task-lease-state-v1.schema.json") == ()
    assert acquired["state"] == "active"
    assert acquired["authority"] == "none" and acquired["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM orchestration_task_leases").fetchone()
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?", (TASK_ID,)
        ).fetchone()
        persisted = " ".join(
            str(value)
            for value in connection.execute(
                "SELECT state_json, token_hash FROM orchestration_task_leases"
            ).fetchone()
        )
        audits = " ".join(
            row[0]
            for row in connection.execute(
                "SELECT data_json FROM audit_events WHERE action LIKE 'orchestration.task_lease_%'"
            )
        )
        assert token not in persisted and token not in audits
        assert len(row["token_hash"]) == 64
        assert tuple(task) == ("ready", 1)
        assert (
            connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
            == grants_before
        )
    with pytest.raises(OrchestrationLeaseError) as replay:
        service.acquire(request, now=NOW)
    assert replay.value.code == "ORCHESTRATION_LEASE_ACQUIRE_REPLAY_DENIED"


def test_lease_renew_release_and_stale_holder_denials(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    wrong = lease_command(acquired, "x" * 43, "renew")
    with pytest.raises(OrchestrationLeaseError) as token_error:
        service.mutate(wrong, now=NOW + timedelta(seconds=1))
    assert token_error.value.code == "ORCHESTRATION_LEASE_TOKEN_MISMATCH"
    renewed = service.mutate(
        lease_command(acquired, token, "renew"), now=NOW + timedelta(seconds=1)
    )
    assert renewed["event_type"] == "renewed"
    state = {**acquired, "lease_version": 2, "expires_at": renewed["expires_at"]}
    released = service.mutate(
        lease_command(state, token, "release"), now=NOW + timedelta(seconds=2)
    )
    assert released["resulting_state"] == "released"
    with pytest.raises(OrchestrationLeaseError) as stale:
        service.mutate(
            lease_command(acquired, token, "release"), now=NOW + timedelta(seconds=2)
        )
    assert stale.value.code == "ORCHESTRATION_LEASE_FENCED"


def test_lease_concurrency_recovery_and_generation_fencing(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)

    def acquire(_: int) -> str:
        try:
            return service.acquire(request, now=NOW)["lease_id"]
        except OrchestrationLeaseError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(acquire, range(2)))
    assert outcomes.count("ORCHESTRATION_LEASE_ACQUIRE_REPLAY_DENIED") == 1
    events = service.recover(now=NOW + timedelta(seconds=1))
    assert len(events) == 1 and events[0]["reason"] == "recovery"
    assert service.recover(now=NOW + timedelta(seconds=2)) == ()
    next_request = dict(
        request,
        request_id="99999999-9999-4999-8999-999999999999",
        expected_recovery_generation=2,
        requested_at=(NOW + timedelta(seconds=2)).isoformat(),
    )
    next_lease = service.acquire(next_request, now=NOW + timedelta(seconds=2))
    assert next_lease["lease_generation"] == 2
    assert next_lease["fencing_token"] == 2
    assert next_lease["recovery_generation"] == 2


def test_lease_worker_safety_and_storage_tampering_deny(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    for change, code in (
        ({"expected_worker_version": 1}, "ORCHESTRATION_LEASE_WORKER_INELIGIBLE"),
        ({"expected_recovery_generation": 2}, "ORCHESTRATION_LEASE_RECOVERY_FENCED"),
        ({"lease_seconds": 61}, "ORCHESTRATION_LEASE_REQUEST_MALFORMED"),
    ):
        with pytest.raises(OrchestrationLeaseError) as denied:
            service.acquire(dict(request, **change), now=NOW)
        assert denied.value.code == code
    acquired = service.acquire(request, now=NOW)
    token = acquired.pop("lease_token")
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=?""",
            (WORKER_ID,),
        )
    with pytest.raises(OrchestrationLeaseError) as worker:
        service.mutate(
            lease_command(acquired, token, "renew"), now=NOW + timedelta(seconds=1)
        )
    assert worker.value.code == "ORCHESTRATION_LEASE_WORKER_INELIGIBLE"
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_lease_events")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_leases SET worker_id='forged-worker'"
            )


def test_lease_expiry_is_durable_and_advances_recovery_fence(tmp_path: Path) -> None:
    service, request = lease_setup(tmp_path)
    acquired = service.acquire(dict(request, lease_seconds=5), now=NOW)
    events = service.recover(now=NOW + timedelta(seconds=6))
    assert len(events) == 1
    assert events[0]["event_type"] == "expired"
    assert events[0]["resulting_state"] == "expired"
    assert events[0]["reason"] == "expired"
    next_request = dict(
        request,
        request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        expected_recovery_generation=2,
        requested_at=(NOW + timedelta(seconds=6)).isoformat(),
    )
    next_lease = service.acquire(next_request, now=NOW + timedelta(seconds=6))
    assert next_lease["lease_generation"] == acquired["lease_generation"] + 1


def test_reserves_durable_non_authoritative_budget_with_audit(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
    receipt = service.reserve(request, now=NOW)
    assert contract_issues(
        receipt, "orchestration-task-budget-reservation-v1.schema.json"
    ) == ()
    assert receipt["state"] == "reserved"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            """SELECT COUNT(*) FROM orchestration_task_budget_reservations
            WHERE state = 'reserved'"""
        ).fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
            == grants_before
        )
        assert connection.execute(
            """SELECT COUNT(*) FROM audit_events
            WHERE action = 'orchestration.task_budget_reserved' AND subject_id = ?""",
            (receipt["reservation_id"],),
        ).fetchone()[0] == 1
    assert service.authorization.verify_audit_chain()["valid"] is True


def test_account_activation_replay_and_conflicting_ceiling_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    arguments: dict[str, Any] = {
        "assessment_id": request["assessment_id"],
        "policy_bundle_id": request["policy_bundle_id"],
        "policy_hash": request["policy_hash"],
        "configuration": _configuration(),
        "provider_policy": _provider_policy(),
        "maximum_retries": 3,
        "maximum_task_amounts": {
            "input_tokens": 60,
            "output_tokens": 30,
            "requests": 2,
            "cost_microusd": 0,
            "runtime_seconds": 20,
            "retries": 2,
        },
        "now": NOW,
    }
    first = service.activate_account(**arguments)
    assert service.activate_account(**arguments) == first
    with pytest.raises(OrchestrationBudgetError) as conflict:
        service.activate_account(**(arguments | {"maximum_retries": 4}))
    assert conflict.value.code == "ORCHESTRATION_BUDGET_ACCOUNT_CONFLICT"


def test_per_task_ceiling_is_stricter_than_assessment_ceiling(tmp_path: Path) -> None:
    service, first_request = setup(tmp_path)
    service.reserve(first_request, now=NOW)
    second = copy.deepcopy(first_request)
    second["request_id"] = str(uuid4())
    second["expected_account_version"] = first_request["expected_account_version"] + 1
    second["amounts"]["input_tokens"] = 51
    with pytest.raises(OrchestrationBudgetError) as exceeded:
        service.reserve(second, now=NOW)
    assert exceeded.value.code == "ORCHESTRATION_TASK_BUDGET_EXCEEDED"


def test_malformed_empty_cross_binding_version_and_limit_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    cases: list[tuple[dict[str, Any], str]] = []
    malformed = copy.deepcopy(request)
    malformed["authority"] = "grant"
    cases.append((malformed, "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"))
    fractional = copy.deepcopy(request)
    fractional["amounts"]["cost_microusd"] = 1.5
    cases.append((fractional, "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"))
    empty = copy.deepcopy(request)
    empty["amounts"] = {field: 0 for field in empty["amounts"]}
    cases.append((empty, "ORCHESTRATION_BUDGET_AMOUNT_INVALID"))
    stale_version = copy.deepcopy(request)
    stale_version["expected_account_version"] = 2
    cases.append((stale_version, "ORCHESTRATION_BUDGET_VERSION_STALE"))
    cross_agent = copy.deepcopy(request)
    cross_agent["agent_id"] = "agent://validation/other"
    cases.append((cross_agent, "ORCHESTRATION_BUDGET_MANIFEST_MISMATCH"))
    over = copy.deepcopy(request)
    over["amounts"]["input_tokens"] = 101
    cases.append((over, "ORCHESTRATION_BUDGET_EXCEEDED"))
    for document, code in cases:
        with pytest.raises(OrchestrationBudgetError) as raised:
            service.reserve(document, now=NOW)
        assert raised.value.code == code


def test_replay_conflict_and_concurrency_prevent_double_reservation(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    first = service.reserve(request, now=NOW)
    assert service.reserve(request, now=NOW) == first
    conflict = copy.deepcopy(request)
    conflict["amounts"]["input_tokens"] = 11
    with pytest.raises(OrchestrationBudgetError) as raised:
        service.reserve(conflict, now=NOW)
    assert raised.value.code == "ORCHESTRATION_BUDGET_IDENTITY_CONFLICT"

    other, contender = setup(tmp_path / "concurrent")
    contender["amounts"]["input_tokens"] = 60
    second = copy.deepcopy(contender)
    second["request_id"] = str(uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda item: _reserve_code(other, item),
                (contender, second),
            )
        )
    assert outcomes.count("reserved") == 1
    assert outcomes.count("ORCHESTRATION_BUDGET_VERSION_STALE") == 1


def _reserve_code(service: OrchestrationBudgetService, request: dict[str, Any]) -> str:
    try:
        return str(service.reserve(request, now=NOW)["state"])
    except OrchestrationBudgetError as error:
        return error.code


def test_cancellation_and_recovery_release_without_resuming_authority(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    service.reserve(request, now=NOW)
    plans = DurablePlanGraphService(service.database_path)
    plans.transition(
        {
            "schema_version": "1.0.0",
            "command_id": str(uuid4()),
            "plan_id": PLAN_ID,
            "assessment_id": request["assessment_id"],
            "task_id": TASK_ID,
            "expected_plan_revision": 2,
            "expected_task_revision": 2,
            "target_state": "cancelling",
            "requested_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        now=NOW,
    )
    with pytest.raises(OrchestrationBudgetError) as cancelled:
        service.reserve(request, now=NOW)
    assert cancelled.value.code == "ORCHESTRATION_BUDGET_PLAN_FENCED"
    released = service.recover(now=NOW)
    assert len(released) == 1 and released[0]["state"] == "released"
    assert released[0]["release_reason"] == "cancelled"
    assert service.recover(now=NOW) == ()


def test_expiry_recovery_and_immutable_identity(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    request["expires_at"] = (NOW + timedelta(seconds=1)).isoformat()
    receipt = service.reserve(request, now=NOW)
    released = service.recover(now=NOW + timedelta(seconds=2))
    assert released[0]["reservation_id"] == receipt["reservation_id"]
    assert released[0]["release_reason"] == "expired"
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_task_budget_reservations SET agent_id = 'changed'"
        )
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("DELETE FROM orchestration_budget_accounts")


def test_recovery_rejects_tampered_receipt_state(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    service.reserve(request, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations
            SET receipt_json = '{"tampered":true}'"""
        )
    with pytest.raises(OrchestrationBudgetError) as invalid:
        service.recover(now=NOW + timedelta(minutes=3))
    assert invalid.value.code == "ORCHESTRATION_BUDGET_RECOVERY_INVALID"
