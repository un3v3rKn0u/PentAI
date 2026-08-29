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
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_core.orchestration_completion_v3 import (
    OrchestrationCompletionV3Error,
    OrchestrationCompletionV3Service,
)
from pentai_core.orchestration_failure_v3 import (
    OrchestrationFailureV3Error,
    OrchestrationFailureV3Service,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_failure_v3 import setup as failure_setup


def setup(tmp_path: Path) -> tuple[OrchestrationCompletionV3Service, dict[str, Any]]:
    failures, failure_command = failure_setup(tmp_path)
    command = {
        key: value for key, value in failure_command.items() if key != "failure_class"
    }
    command.update(
        command_id=str(uuid4()),
        purpose="consume_attempt_three_validation_task_completion",
        requested_at=(NOW + timedelta(seconds=48)).isoformat(),
        expires_at=(NOW + timedelta(seconds=108)).isoformat(),
    )
    return OrchestrationCompletionV3Service(failures.authorization), command


def test_completes_attempt_three_without_authority_or_external_effect(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grants_before = connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0]
        outbox_before = connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
    receipt = service.complete(command, now=NOW + timedelta(seconds=48))
    assert contract_issues(
        receipt, "orchestration-task-completion-receipt-v3.schema.json"
    ) == ()
    assert receipt["attempt_number"] == 3
    assert receipt["resulting_task_state"] == "succeeded"
    assert receipt["authority"] == "none" and receipt["execution_enabled"] is False
    assert service.complete(command, now=NOW + timedelta(seconds=48)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id=?", (command["task_id"],)
        ).fetchone() == ("succeeded",)
        assert connection.execute(
            "SELECT state FROM orchestration_plans WHERE plan_id=?", (command["plan_id"],)
        ).fetchone() == ("completed",)
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone() == (
            grants_before,
        )
        assert connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == (
            outbox_before + 1
        )


def test_requires_exact_checkpoint_head_or_complete_absence(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    checkpoint_command = {
        key: value
        for key, value in command.items()
        if key not in {"checkpoint_id", "checkpoint_sequence", "checkpoint_digest"}
    }
    checkpoint_command.update(
        command_id=str(uuid4()),
        sequence=1,
        previous_checkpoint_digest=None,
        progress_percent=50,
        status="in_progress",
        purpose="record_attempt_three_validation_progress",
    )
    checkpoint = service._checkpoints.record(
        checkpoint_command, now=NOW + timedelta(seconds=48)
    )
    with pytest.raises(OrchestrationCompletionV3Error) as stale:
        service.complete(command, now=NOW + timedelta(seconds=48))
    assert stale.value.code == "ORCHESTRATION_COMPLETION_V3_CHECKPOINT_FENCED"
    command.update(
        checkpoint_id=checkpoint["checkpoint_id"],
        checkpoint_sequence=checkpoint["sequence"],
        checkpoint_digest=checkpoint["checkpoint_digest"],
    )
    assert service.complete(command, now=NOW + timedelta(seconds=48))["checkpoint_id"] == (
        checkpoint["checkpoint_id"]
    )


def test_malformed_mixed_cross_scope_and_changed_replay_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"attempt_number": 2},
        {"attempt_number": 4},
        {"authority": "grant"},
        {"lease_consumption_id": str(uuid4())},
        {"task_id": str(uuid4())},
        {"output": "synthetic forbidden output"},
        {"checkpoint_id": str(uuid4())},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationCompletionV3Error):
            service.complete(command, now=NOW + timedelta(seconds=48))
    service, command = setup(tmp_path / "changed")
    service.complete(command, now=NOW + timedelta(seconds=48))
    changed = copy.deepcopy(command)
    changed["command_id"] = command["command_id"]
    changed["expires_at"] = (NOW + timedelta(seconds=109)).isoformat()
    with pytest.raises(OrchestrationCompletionV3Error) as conflict:
        service.complete(changed, now=NOW + timedelta(seconds=48))
    assert conflict.value.code == "ORCHESTRATION_COMPLETION_V3_IDENTITY_CONFLICT"

    replay_service, replay_command = setup(tmp_path / "stale-replay")
    replay_service.complete(replay_command, now=NOW + timedelta(seconds=48))
    with closing(sqlite3.connect(replay_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused',generation=generation+1"
        )
    with pytest.raises(OrchestrationCompletionV3Error) as stale_replay:
        replay_service.complete(replay_command, now=NOW + timedelta(seconds=48))
    assert stale_replay.value.code == "ORCHESTRATION_COMPLETION_V3_REPLAY_FENCED"


def test_concurrency_failure_competition_and_current_security_fences(tmp_path: Path) -> None:
    service, command = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(command), copy.deepcopy(command))
    contenders[1]["command_id"] = str(uuid4())

    def complete(candidate: dict[str, Any]) -> str:
        try:
            return service.complete(candidate, now=NOW + timedelta(seconds=48))["completion_id"]
        except OrchestrationCompletionV3Error as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(complete, contenders))
    assert sum(value.startswith("ORCHESTRATION_COMPLETION_V3_") for value in outcomes) == 1

    failure_service, failure_command = failure_setup(tmp_path / "failure-first")
    failure_service.record(failure_command, now=NOW + timedelta(seconds=48))
    completion_command = {
        key: value for key, value in failure_command.items() if key != "failure_class"
    }
    completion_command.update(
        command_id=str(uuid4()),
        purpose="consume_attempt_three_validation_task_completion",
    )
    with pytest.raises(OrchestrationCompletionV3Error):
        OrchestrationCompletionV3Service(failure_service.authorization).complete(
            completion_command, now=NOW + timedelta(seconds=48)
        )

    success_service, success_command = setup(tmp_path / "success-first")
    success_service.complete(success_command, now=NOW + timedelta(seconds=48))
    failure_command = copy.deepcopy(success_command)
    failure_command.update(
        command_id=str(uuid4()),
        failure_class="coordination_timeout",
        purpose="record_attempt_three_validation_task_failure",
    )
    with pytest.raises(OrchestrationFailureV3Error):
        OrchestrationFailureV3Service(success_service.authorization).record(
            failure_command, now=NOW + timedelta(seconds=48)
        )

    for name in ("safety", "cancel", "worker", "account", "recovery"):
        fenced, candidate = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused',generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    "UPDATE orchestration_tasks SET state='cancelling',revision=revision+1 "
                    "WHERE task_id=?",
                    (candidate["task_id"],),
                )
            elif name == "worker":
                connection.execute(
                    "UPDATE worker_runtime_instances SET status='termination_requested',"
                    "version=version+1 WHERE worker_id=?",
                    (candidate["worker_id"],),
                )
            elif name == "account":
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
            else:
                connection.execute(
                    "UPDATE orchestration_task_lease_fences SET recovery_generation="
                    "recovery_generation+1,version=version+1 WHERE task_id=?",
                    (candidate["task_id"],),
                )
        with pytest.raises(OrchestrationCompletionV3Error):
            fenced.complete(candidate, now=NOW + timedelta(seconds=48))


def test_generic_transition_and_direct_storage_bypass_deny_attempt_three(
    tmp_path: Path,
) -> None:
    service, command = setup(tmp_path)
    transition = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "plan_id": command["plan_id"],
        "assessment_id": command["assessment_id"],
        "task_id": command["task_id"],
        "expected_plan_revision": command["expected_plan_revision"],
        "expected_task_revision": command["expected_task_revision"],
        "target_state": "succeeded",
        "requested_at": (NOW + timedelta(seconds=48)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    with pytest.raises(OrchestrationError) as denied:
        DurablePlanGraphService(service.database_path).transition(
            transition, now=NOW + timedelta(seconds=48)
        )
    assert denied.value.code == "ORCHESTRATION_TRANSITION_DENIED"
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_tasks SET state='succeeded',revision=revision+1 "
                "WHERE task_id=?",
                (command["task_id"],),
            )
    receipt = service.complete(command, now=NOW + timedelta(seconds=48))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_completions_v3 SET authority='grant'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_completions_v3")
        assert connection.execute(
            "SELECT completion_id FROM orchestration_task_completions_v3"
        ).fetchone() == (receipt["completion_id"],)
