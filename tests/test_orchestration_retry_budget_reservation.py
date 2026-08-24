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
from pentai_core.orchestration_budget import OrchestrationBudgetError, OrchestrationBudgetService
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_manifest import setup as manifest_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationBudgetService, dict[str, Any], dict[str, Any]]:
    manifests, arguments, activation = manifest_setup(tmp_path)
    manifest = manifests.issue(**arguments)
    with closing(sqlite3.connect(manifests.database_path)) as connection:
        account_id, account_version = connection.execute(
            """SELECT a.account_id, a.version FROM orchestration_budget_accounts a
            JOIN orchestration_retry_budget_consumptions c ON c.budget_account_id=a.account_id
            WHERE c.consumption_id=?""",
            (activation["retry_budget_consumption_id"],),
        ).fetchone()
    request: dict[str, Any] = {
        "schema_version": "3.0.0",
        "request_id": str(uuid4()),
        "account_id": account_id,
        "expected_account_version": account_version,
        "assessment_id": activation["assessment_id"],
        "plan_id": activation["plan_id"],
        "expected_plan_revision": activation["resulting_plan_revision"],
        "task_id": activation["task_id"],
        "expected_task_revision": activation["resulting_task_revision"],
        "task_state": "ready",
        "agent_id": manifest["agent_id"],
        "capability_manifest_id": manifest["manifest_id"],
        "capability_manifest_digest": "sha256:" + content_hash(manifest),
        "expected_manifest_revision": manifest["manifest_revision"],
        "retry_activation_id": activation["activation_id"],
        "retry_activation_digest": activation["activation_digest"],
        "retry_attempt_id": activation["attempt_id"],
        "retry_attempt_digest": activation["attempt_digest"],
        "retry_budget_consumption_id": activation["retry_budget_consumption_id"],
        "policy_bundle_id": activation["policy_bundle_id"],
        "policy_hash": activation["policy_hash"],
        "purpose": "reserve_validation_task_budget",
        "amounts": {
            "input_tokens": 5,
            "output_tokens": 2,
            "requests": 1,
            "cost_microusd": 0,
            "runtime_seconds": 2,
            "retries": 0,
        },
        "requested_at": (NOW + timedelta(seconds=9)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationBudgetService(manifests.authorization), request, manifest


def test_reserves_retry_bound_ready_budget_without_authority(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path)
    receipt = service.reserve(request, now=NOW + timedelta(seconds=9))
    assert contract_issues(receipt, "orchestration-task-budget-reservation-v3.schema.json") == ()
    assert receipt["retry_activation_id"] == request["retry_activation_id"]
    assert receipt["retry_budget_consumption_id"] == request["retry_budget_consumption_id"]
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.reserve(request, now=NOW + timedelta(seconds=9)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (request["task_id"],)
        ).fetchone() == ("ready",)
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_task_leases WHERE state='active'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM agent_action_intent_links").fetchone()[0] == 0
        )


def test_malformed_unknown_tampered_and_cross_lineage_deny(tmp_path: Path) -> None:
    cases = (
        ("schema_version", "4.0.0", "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"),
        ("task_state", "running", "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"),
        ("authority", "grant", "ORCHESTRATION_BUDGET_REQUEST_MALFORMED"),
        (
            "capability_manifest_digest",
            "sha256:" + "0" * 64,
            "ORCHESTRATION_BUDGET_RETRY_MISMATCH",
        ),
        ("retry_activation_id", str(uuid4()), "ORCHESTRATION_BUDGET_RETRY_MISMATCH"),
    )
    for index, (field, value, code) in enumerate(cases):
        service, request, _ = setup(tmp_path / str(index))
        request[field] = value
        with pytest.raises(OrchestrationBudgetError) as denied:
            service.reserve(request, now=NOW + timedelta(seconds=9))
        assert denied.value.code == code


def test_changed_replay_concurrency_and_account_version_fence(tmp_path: Path) -> None:
    service, request, _ = setup(tmp_path / "replay")
    service.reserve(request, now=NOW + timedelta(seconds=9))
    changed = copy.deepcopy(request)
    changed["amounts"]["input_tokens"] += 1
    with pytest.raises(OrchestrationBudgetError) as conflict:
        service.reserve(changed, now=NOW + timedelta(seconds=9))
    assert conflict.value.code == "ORCHESTRATION_BUDGET_IDENTITY_CONFLICT"

    concurrent, candidate, _ = setup(tmp_path / "concurrent")
    other = copy.deepcopy(candidate)
    other["request_id"] = str(uuid4())

    def reserve(document: dict[str, Any]) -> str:
        try:
            return concurrent.reserve(document, now=NOW + timedelta(seconds=9))["reservation_id"]
        except OrchestrationBudgetError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(reserve, (candidate, other)))
    assert outcomes.count("ORCHESTRATION_BUDGET_VERSION_STALE") == 1


def test_expiry_safety_policy_cancellation_recovery_and_storage_fences(tmp_path: Path) -> None:
    expired, expired_request, _ = setup(tmp_path / "expired")
    with pytest.raises(OrchestrationBudgetError) as stale:
        expired.reserve(expired_request, now=NOW + timedelta(minutes=3))
    assert stale.value.code == "ORCHESTRATION_BUDGET_REQUEST_STALE"

    for name in ("safety", "policy", "task", "recovery"):
        service, request, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "policy":
                connection.execute(
                    "UPDATE policy_bundles SET revoked_at=?",
                    ((NOW + timedelta(seconds=9)).isoformat(),),
                )
            elif name == "task":
                connection.execute(
                    """UPDATE orchestration_tasks SET state='cancelled', revision=revision+1
                    WHERE task_id=?""",
                    (request["task_id"],),
                )
            else:
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
        with pytest.raises(OrchestrationBudgetError):
            service.reserve(request, now=NOW + timedelta(seconds=9))

    immutable, immutable_request, _ = setup(tmp_path / "immutable")
    receipt = immutable.reserve(immutable_request, now=NOW + timedelta(seconds=9))
    with (
        closing(sqlite3.connect(immutable.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET retry_attempt_id=NULL
            WHERE reservation_id=?""",
            (receipt["reservation_id"],),
        )
