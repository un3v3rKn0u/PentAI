from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_retry_activation import (
    OrchestrationRetryActivationError,
    OrchestrationRetryActivationService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_schedule import setup as schedule_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryActivationService, dict[str, object], dict[str, object]]:
    schedules, schedule_command, _ = schedule_setup(tmp_path)
    schedule = schedules.register(schedule_command, now=NOW + timedelta(seconds=6))
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": schedule["assessment_id"],
        "plan_id": schedule["plan_id"],
        "expected_plan_revision": schedule["plan_revision"],
        "task_id": schedule["task_id"],
        "expected_task_revision": schedule["task_revision"],
        "schedule_id": schedule["schedule_id"],
        "schedule_digest": schedule["schedule_digest"],
        "attempt_id": schedule["attempt_id"],
        "attempt_digest": schedule["attempt_digest"],
        "purpose": "activate_validation_retry_readiness",
        "requested_at": (NOW + timedelta(seconds=7)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryActivationService(schedules.authorization), command, schedule


def test_consumes_schedule_into_readiness_without_authority(tmp_path: Path) -> None:
    service, command, schedule = setup(tmp_path)
    receipt = service.consume(command, now=NOW + timedelta(seconds=7))
    assert contract_issues(receipt, "orchestration-retry-activation-receipt-v1.schema.json") == ()
    assert receipt["schedule_id"] == schedule["schedule_id"]
    assert receipt["attempt_id"] == schedule["attempt_id"]
    assert receipt["resulting_task_state"] == "ready"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.consume(command, now=NOW + timedelta(seconds=7)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (command["task_id"],),
        ).fetchone() == ("ready", receipt["resulting_task_revision"])
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_retry_activations"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
        ).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1


def test_general_transition_cannot_reopen_failed_task(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    graph = DurablePlanGraphService(service.database_path)
    with pytest.raises(OrchestrationError) as denied:
        graph.transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "assessment_id": command["assessment_id"],
                "plan_id": command["plan_id"],
                "expected_plan_revision": command["expected_plan_revision"],
                "task_id": command["task_id"],
                "expected_task_revision": command["expected_task_revision"],
                "target_state": "ready",
                "requested_at": (NOW + timedelta(seconds=7)).isoformat(),
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW + timedelta(seconds=7),
        )
    assert denied.value.code == "ORCHESTRATION_COMMAND_MALFORMED"
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            """UPDATE orchestration_tasks SET state='ready', revision=revision+1
            WHERE task_id=?""",
            (command["task_id"],),
        )


def test_malformed_tampered_cross_scope_and_changed_replay_deny(tmp_path: Path) -> None:
    cases = (
        ("authority", "grant", "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_MALFORMED"),
        (
            "schedule_digest",
            "sha256:" + "0" * 64,
            "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISMATCH",
        ),
        ("assessment_id", str(uuid4()), "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISMATCH"),
    )
    for index, (field, value, code) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command[field] = value
        with pytest.raises(OrchestrationRetryActivationError) as denied:
            service.consume(command, now=NOW + timedelta(seconds=7))
        assert denied.value.code == code

    service, command, _ = setup(tmp_path / "replay")
    service.consume(command, now=NOW + timedelta(seconds=7))
    changed = copy.deepcopy(command)
    changed["expires_at"] = (NOW + timedelta(seconds=50)).isoformat()
    with pytest.raises(OrchestrationRetryActivationError) as conflict:
        service.consume(changed, now=NOW + timedelta(seconds=7))
    assert conflict.value.code == "ORCHESTRATION_RETRY_ACTIVATION_IDENTITY_CONFLICT"

    fenced, fenced_command, _ = setup(tmp_path / "fenced-replay")
    fenced.consume(fenced_command, now=NOW + timedelta(seconds=7))
    with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationRetryActivationError) as replay_denied:
        fenced.consume(fenced_command, now=NOW + timedelta(seconds=8))
    assert replay_denied.value.code == "ORCHESTRATION_RETRY_ACTIVATION_REPLAY_FENCED"


def test_missing_expired_and_security_fences_deny(tmp_path: Path) -> None:
    missing, missing_command, _ = setup(tmp_path / "missing")
    missing_command["schedule_id"] = str(uuid4())
    with pytest.raises(OrchestrationRetryActivationError) as absent:
        missing.consume(missing_command, now=NOW + timedelta(seconds=7))
    assert absent.value.code == "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISSING"

    expired, expired_command, _ = setup(tmp_path / "expired")
    with pytest.raises(OrchestrationRetryActivationError) as stale:
        expired.consume(expired_command, now=NOW + timedelta(minutes=2))
    assert stale.value.code == "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_STALE"

    for name in ("safety", "policy", "budget", "worker", "recovery"):
        service, command, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    """UPDATE safety_state SET global_status='paused',
                    generation=generation+1"""
                )
            elif name == "policy":
                connection.execute(
                    "UPDATE policy_bundles SET revoked_at=?",
                    ((NOW + timedelta(seconds=7)).isoformat(),),
                )
            elif name == "budget":
                connection.execute(
                    """UPDATE orchestration_task_budget_reservations SET state='released',
                    released_at=?, release_reason='recovery'""",
                    ((NOW + timedelta(seconds=7)).isoformat(),),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id=(SELECT worker_id
                    FROM orchestration_task_leases LIMIT 1)"""
                )
            else:
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
        with pytest.raises(OrchestrationRetryActivationError) as denied:
            service.consume(command, now=NOW + timedelta(seconds=8))
        assert denied.value.code == "ORCHESTRATION_RETRY_ACTIVATION_SECURITY_DENIED"


def test_concurrency_and_storage_immutability(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    candidates = (copy.deepcopy(command), copy.deepcopy(command))
    candidates[1]["command_id"] = str(uuid4())

    def consume(candidate: dict[str, object]) -> str:
        try:
            return str(service.consume(candidate, now=NOW + timedelta(seconds=7))["activation_id"])
        except OrchestrationRetryActivationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, candidates))
    assert sum(value.startswith("ORCHESTRATION_RETRY_ACTIVATION_") for value in outcomes) == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        activation_id = connection.execute(
            "SELECT activation_id FROM orchestration_retry_activations"
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_retry_activations SET authority='none' WHERE activation_id=?",
                (activation_id,),
            )
