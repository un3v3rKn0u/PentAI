from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.orchestration_attempt import OrchestrationAttemptService
from pentai_core.orchestration_retry import (
    OrchestrationRetryError,
    OrchestrationRetryService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_failure import setup as failure_setup


def setup(
    tmp_path: Path, *, failure_class: str = "coordination_timeout"
) -> tuple[OrchestrationRetryService, dict[str, object], dict[str, object]]:
    failures, failure_command = failure_setup(tmp_path)
    failure_command["failure_class"] = failure_class
    failure = failures.record(failure_command, now=NOW)
    attempt_command = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": failure["assessment_id"],
        "plan_id": failure["plan_id"],
        "expected_plan_revision": failure["resulting_plan_revision"],
        "task_id": failure["task_id"],
        "expected_task_revision": failure["resulting_task_revision"],
        "agent_id": failure["agent_id"],
        "capability_manifest_id": failure["capability_manifest_id"],
        "manifest_revision": failure["manifest_revision"],
        "budget_reservation_id": failure["budget_reservation_id"],
        "budget_account_version": failure["budget_account_version"],
        "approval_consumption_id": failure["approval_consumption_id"],
        "lease_consumption_id": failure["lease_consumption_id"],
        "policy_bundle_id": failure["policy_bundle_id"],
        "policy_hash": failure["policy_hash"],
        "worker_id": failure["worker_id"],
        "expected_worker_version": failure["worker_version"],
        "lease_generation": failure["lease_generation"],
        "fencing_token": failure["fencing_token"],
        "expected_recovery_generation": failure["recovery_generation"],
        "checkpoint_id": failure["checkpoint_id"],
        "checkpoint_sequence": failure["checkpoint_sequence"],
        "checkpoint_digest": failure["checkpoint_digest"],
        "failure_id": failure["failure_id"],
        "failure_receipt_digest": "sha256:" + content_hash(failure),
        "attempt_number": 1,
        "purpose": "register_failed_validation_attempt",
        "requested_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    attempts = OrchestrationAttemptService(failures.authorization)
    attempt = attempts.register(attempt_command, now=NOW)
    service = OrchestrationRetryService(failures.authorization)
    policy = service.issue_policy(
        assessment_id=attempt["assessment_id"],
        policy_bundle_id=attempt["policy_bundle_id"],
        policy_hash=attempt["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW,
    )
    command: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "expected_plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "expected_task_revision": attempt["task_revision"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "retry_policy_id": policy["retry_policy_id"],
        "retry_policy_revision": policy["revision"],
        "retry_policy_digest": policy["policy_digest"],
        "purpose": "evaluate_validation_retry",
        "requested_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return service, command, policy


def test_issues_closed_policy_and_eligible_non_activating_decision(tmp_path: Path) -> None:
    service, command, policy = setup(tmp_path)
    assert contract_issues(policy, "orchestration-retry-policy-v1.schema.json") == ()
    replayed_policy = service.issue_policy(
        assessment_id=policy["assessment_id"],
        policy_bundle_id=policy["policy_bundle_id"],
        policy_hash=policy["policy_hash"],
        expires_at=NOW + timedelta(minutes=2),
        now=NOW,
    )
    assert replayed_policy == policy
    with closing(sqlite3.connect(service.database_path)) as connection:
        budget_before = connection.execute(
            """SELECT account_version, amounts_json FROM orchestration_task_budget_reservations
            WHERE reservation_id=(SELECT budget_reservation_id FROM orchestration_task_attempts
            WHERE attempt_id=?)""",
            (command["attempt_id"],),
        ).fetchone()
    decision = service.evaluate(command, now=NOW)
    assert contract_issues(decision, "orchestration-retry-decision-v1.schema.json") == ()
    assert decision["outcome"] == "eligible"
    assert decision["proposed_attempt_number"] == 2
    assert decision["earliest_retry_at"] == (NOW + timedelta(seconds=5)).isoformat().replace(
        "+00:00", "Z"
    )
    assert decision["retry_units_consumed"] == 0
    assert decision["authority"] == "none" and decision["execution_enabled"] is False
    assert service.evaluate(command, now=NOW) == decision
    with closing(sqlite3.connect(service.database_path)) as connection:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id=?",
            (command["task_id"],),
        ).fetchone()
        budget_after = connection.execute(
            """SELECT account_version, amounts_json FROM orchestration_task_budget_reservations
            WHERE reservation_id=(SELECT budget_reservation_id FROM orchestration_task_attempts
            WHERE attempt_id=?)""",
            (command["attempt_id"],),
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1
    assert task == ("failed", command["expected_task_revision"])
    assert budget_after == budget_before


def test_closed_policy_denies_checkpoint_stall_without_caller_override(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path, failure_class="checkpoint_stalled")
    decision = service.evaluate(command, now=NOW)
    assert decision["outcome"] == "denied"
    assert decision["reason_code"] == "RETRY_DENIED_MANUAL_REVIEW_REQUIRED"
    assert decision["earliest_retry_at"] is None
    override = copy.deepcopy(command)
    override["retryable"] = True
    with pytest.raises(OrchestrationRetryError) as denied:
        service.evaluate(override, now=NOW)
    assert denied.value.code == "ORCHESTRATION_RETRY_EVALUATION_MALFORMED"


def test_malformed_stale_and_cross_binding_inputs_deny(tmp_path: Path) -> None:
    cases = (
        ({"attempt_digest": "sha256:" + "0" * 64}, "ORCHESTRATION_RETRY_ATTEMPT_INVALID"),
        ({"assessment_id": str(uuid4())}, "ORCHESTRATION_RETRY_ATTEMPT_INVALID"),
        ({"retry_policy_digest": "sha256:" + "0" * 64}, "ORCHESTRATION_RETRY_POLICY_INVALID"),
        ({"authority": "grant"}, "ORCHESTRATION_RETRY_EVALUATION_MALFORMED"),
        (
            {"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
            "ORCHESTRATION_RETRY_EVALUATION_STALE",
        ),
    )
    for index, (changes, code) in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryError) as denied:
            service.evaluate(command, now=NOW)
        assert denied.value.code == code


def test_policy_expiry_conflict_safety_worker_and_budget_invalidation_deny(
    tmp_path: Path,
) -> None:
    service, command, policy = setup(tmp_path / "policy")
    with pytest.raises(OrchestrationRetryError) as conflict:
        service.issue_policy(
            assessment_id=policy["assessment_id"],
            policy_bundle_id=policy["policy_bundle_id"],
            policy_hash=policy["policy_hash"],
            expires_at=NOW + timedelta(minutes=3),
            now=NOW,
        )
    assert conflict.value.code == "ORCHESTRATION_RETRY_POLICY_IDENTITY_CONFLICT"
    with pytest.raises(OrchestrationRetryError) as expired:
        service.evaluate(command, now=NOW + timedelta(minutes=3))
    assert expired.value.code == "ORCHESTRATION_RETRY_EVALUATION_STALE"

    safety_service, safety_command, _ = setup(tmp_path / "safety")
    with closing(sqlite3.connect(safety_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status='paused', generation=generation+1"
        )
    with pytest.raises(OrchestrationRetryError) as safety:
        safety_service.evaluate(safety_command, now=NOW)
    assert safety.value.code == "ORCHESTRATION_RETRY_SECURITY_DENIED"

    worker_service, worker_command, _ = setup(tmp_path / "worker")
    with closing(sqlite3.connect(worker_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE worker_runtime_instances SET status='termination_requested',
            version=version+1 WHERE worker_id=(SELECT worker_id FROM orchestration_task_leases
            LIMIT 1)"""
        )
    with pytest.raises(OrchestrationRetryError) as worker:
        worker_service.evaluate(worker_command, now=NOW)
    assert worker.value.code == "ORCHESTRATION_RETRY_SECURITY_DENIED"

    budget_service, budget_command, _ = setup(tmp_path / "budget")
    with closing(sqlite3.connect(budget_service.database_path)) as connection, connection:
        connection.execute(
            """UPDATE orchestration_task_budget_reservations SET state='released',
            released_at=?, release_reason='recovery'""",
            (NOW.isoformat(),),
        )
    with pytest.raises(OrchestrationRetryError) as budget:
        budget_service.evaluate(budget_command, now=NOW)
    assert budget.value.code == "ORCHESTRATION_RETRY_SECURITY_DENIED"


def test_changed_replay_concurrency_and_storage_mutation_deny(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    service.evaluate(command, now=NOW)
    conflict = copy.deepcopy(command)
    conflict["expires_at"] = (NOW + timedelta(seconds=30)).isoformat()
    with pytest.raises(OrchestrationRetryError) as reused:
        service.evaluate(conflict, now=NOW)
    assert reused.value.code == "ORCHESTRATION_RETRY_EVALUATION_IDENTITY_CONFLICT"

    other, contender, _ = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(contender), copy.deepcopy(contender))
    contenders[1]["command_id"] = str(uuid4())

    def evaluate(candidate: dict[str, object]) -> str:
        try:
            return str(other.evaluate(candidate, now=NOW)["decision_id"])
        except OrchestrationRetryError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(evaluate, contenders))
    assert sum(value.startswith("ORCHESTRATION_RETRY_") for value in outcomes) == 1
    with closing(sqlite3.connect(service.database_path)) as connection:
        decision_id = connection.execute(
            "SELECT decision_id FROM orchestration_retry_decisions"
        ).fetchone()[0]
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_retry_decisions SET authority='grant' WHERE decision_id=?",
            (decision_id,),
        )
