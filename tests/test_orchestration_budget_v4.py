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
from pentai_core.orchestration_budget import OrchestrationBudgetError, OrchestrationBudgetService
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_manifest_v4 import setup as manifest_setup


def setup(tmp_path: Path) -> tuple[OrchestrationBudgetService, dict[str, Any]]:
    manifests, manifest_command, _ = manifest_setup(tmp_path)
    manifest = manifests.issue_v4(manifest_command, now=NOW + timedelta(seconds=43))
    with closing(sqlite3.connect(manifests.database_path)) as connection:
        account_id, account_version = connection.execute(
            "SELECT account_id, version FROM orchestration_budget_accounts"
        ).fetchone()
    command: dict[str, Any] = {
        "schema_version": "4.0.0",
        "request_id": str(uuid4()),
        "account_id": account_id,
        "expected_account_version": account_version,
        "assessment_id": manifest["assessment_id"],
        "plan_id": manifest["plan_id"],
        "expected_plan_revision": manifest["plan_revision"],
        "task_id": manifest["task_id"],
        "expected_task_revision": manifest["task_revision"],
        "task_state": "ready",
        "agent_id": manifest["agent_id"],
        "capability_manifest_id": manifest["manifest_id"],
        "capability_manifest_digest": "sha256:" + content_hash(manifest),
        "expected_manifest_revision": 1,
        "retry_activation_id": manifest["retry_activation_id"],
        "retry_activation_digest": manifest["retry_activation_digest"],
        "retry_attempt_id": manifest["retry_attempt_id"],
        "retry_attempt_digest": manifest["retry_attempt_digest"],
        "policy_bundle_id": manifest["policy_bundle_id"],
        "policy_hash": manifest["policy_hash"],
        "purpose": "reserve_attempt_three_validation_task_budget",
        "amounts": {
            "input_tokens": 1,
            "output_tokens": 1,
            "requests": 0,
            "cost_microusd": 0,
            "runtime_seconds": 1,
            "retries": 0,
        },
        "requested_at": (NOW + timedelta(seconds=44)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=53)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationBudgetService(manifests.authorization), command


def test_reserves_attempt_three_capacity_without_authority(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    receipt = service.reserve_v4(command, now=NOW + timedelta(seconds=44))
    assert contract_issues(
        receipt, "orchestration-task-budget-reservation-v4.schema.json"
    ) == ()
    assert receipt["attempt_number"] == 3
    assert receipt["amounts"]["retries"] == 0
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.reserve_v4(command, now=NOW + timedelta(seconds=44)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_budget_reservations_v4"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state='active'"
        ).fetchone() == (0,)


def test_malformed_mixed_version_empty_retry_and_cross_lineage_deny(tmp_path: Path) -> None:
    changes = (
        {"schema_version": "3.0.0"},
        {"authority": "grant"},
        {"retry_activation_digest": "sha256:" + "0" * 64},
        {"retry_attempt_id": str(uuid4())},
        {"agent_id": "agent://validation/other"},
        {"amounts": {"input_tokens": 0, "output_tokens": 0, "requests": 0,
                     "cost_microusd": 0, "runtime_seconds": 0, "retries": 0}},
        {"amounts": {"input_tokens": 1, "output_tokens": 1, "requests": 0,
                     "cost_microusd": 0, "runtime_seconds": 1, "retries": 1}},
        {"amounts": {"input_tokens": 1.5, "output_tokens": 1, "requests": 0,
                     "cost_microusd": 0, "runtime_seconds": 1, "retries": 0}},
        {"amounts": {"input_tokens": -1, "output_tokens": 1, "requests": 0,
                     "cost_microusd": 0, "runtime_seconds": 1, "retries": 0}},
        {"amounts": {"input_tokens": 1_000_001, "output_tokens": 1, "requests": 0,
                     "cost_microusd": 0, "runtime_seconds": 1, "retries": 0}},
    )
    for index, change in enumerate(changes):
        service, command = setup(tmp_path / str(index))
        command.update(change)
        with pytest.raises(OrchestrationBudgetError):
            service.reserve_v4(command, now=NOW + timedelta(seconds=44))


def test_changed_replay_concurrency_and_account_version_fencing(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "replay")
    service.reserve_v4(command, now=NOW + timedelta(seconds=44))
    changed = copy.deepcopy(command)
    changed["amounts"]["input_tokens"] = 2
    with pytest.raises(OrchestrationBudgetError) as conflict:
        service.reserve_v4(changed, now=NOW + timedelta(seconds=44))
    assert conflict.value.code == "ORCHESTRATION_BUDGET_IDENTITY_CONFLICT"

    concurrent, contender = setup(tmp_path / "concurrent")
    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["request_id"] = str(uuid4())

    def reserve(candidate: dict[str, Any]) -> str:
        try:
            return str(concurrent.reserve_v4(candidate, now=NOW + timedelta(seconds=44))["state"])
        except OrchestrationBudgetError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(reserve, candidates))
    assert outcomes.count("reserved") == 1
    assert outcomes.count("ORCHESTRATION_BUDGET_VERSION_STALE") == 1

    stale, stale_command = setup(tmp_path / "stale")
    stale_command["expected_account_version"] -= 1
    with pytest.raises(OrchestrationBudgetError) as fenced:
        stale.reserve_v4(stale_command, now=NOW + timedelta(seconds=44))
    assert fenced.value.code == "ORCHESTRATION_BUDGET_VERSION_STALE"


def test_safety_worker_recovery_expiry_and_storage_tampering_deny(tmp_path: Path) -> None:
    for name in ("safety", "worker", "recovery"):
        service, command = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
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
                    (command["task_id"],),
                )
        with pytest.raises(OrchestrationBudgetError):
            service.reserve_v4(command, now=NOW + timedelta(seconds=44))

    service, command = setup(tmp_path / "storage")
    receipt = service.reserve_v4(command, now=NOW + timedelta(seconds=44))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_budget_reservations_v4 SET task_id=?",
                (str(uuid4()),),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM orchestration_task_budget_reservations_v4"
            )
    assert receipt["state"] == "reserved"

    tampered, tampered_command = setup(tmp_path / "receipt-tamper")
    stored = tampered.reserve_v4(tampered_command, now=NOW + timedelta(seconds=44))
    stored["worker_version"] += 1
    with closing(sqlite3.connect(tampered.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations_v4 SET receipt_json=?
            WHERE reservation_id=?""",
            (json.dumps(stored, sort_keys=True, separators=(",", ":")), stored["reservation_id"]),
        )
    with pytest.raises(OrchestrationBudgetError) as denied:
        tampered.reserve_v4(tampered_command, now=NOW + timedelta(seconds=44))
    assert denied.value.code == "ORCHESTRATION_BUDGET_REPLAY_FENCED"


def test_expiry_recovery_releases_without_refund_or_activation(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    command["expires_at"] = (NOW + timedelta(seconds=45)).isoformat()
    receipt = service.reserve_v4(command, now=NOW + timedelta(seconds=44))
    released = service.recover_v4(now=NOW + timedelta(seconds=46))
    assert len(released) == 1
    assert released[0]["reservation_id"] == receipt["reservation_id"]
    assert released[0]["state"] == "released"
    assert released[0]["release_reason"] == "expired"
    assert released[0]["amounts"]["retries"] == 0
    assert service.recover_v4(now=NOW + timedelta(seconds=46)) == ()
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_attempts_v2"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("ready",)
