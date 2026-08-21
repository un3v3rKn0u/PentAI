from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pentai_core.migrate import migrate
from pentai_core.orchestration import DurablePlanGraphService
from pentai_core.orchestration_approval import (
    OrchestrationApprovalError,
    OrchestrationApprovalService,
)
from pentai_policy import canonical_json
from pentai_policy.document import contract_issues

from scripts.owned_fixture_authority import prepare_owned_fixture_session

NOW = datetime.now(UTC).replace(microsecond=0)
PLAN = "33333333-3333-4333-8333-333333333333"
TASK = "44444444-4444-4444-8444-444444444444"


def setup(tmp_path: Path) -> tuple[OrchestrationApprovalService, dict[str, Any]]:
    database = tmp_path / "approval.db"
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
        "plan_id": PLAN,
        "assessment_id": assessment_id,
        "idempotency_key": "synthetic-approval-plan-0001",
        "revision": 1,
        "state": "active",
        "tasks": [
            {
                "task_id": TASK,
                "task_type": "validation",
                "objective": "Review synthetic readiness metadata.",
                "input_refs": [],
                "requires_human_approval": True,
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
    DurablePlanGraphService(database).create(graph)
    return OrchestrationApprovalService(authorization), {
        "assessment_id": assessment_id,
        "plan_id": PLAN,
        "expected_plan_revision": 1,
        "task_id": TASK,
        "expected_task_revision": 1,
        "policy_bundle_id": policy_id,
        "policy_hash": policy_hash,
    }


def test_approved_condition_is_signed_audited_and_non_authoritative(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection:
        grant_count = connection.execute("SELECT count(*) FROM action_grants").fetchone()[0]
    assert contract_issues(request, "orchestration-task-approval-request-v1.schema.json") == ()
    decision = service.decide(
        request["request_id"],
        decision="approved",
        reason="Synthetic review complete.",
        explicit_confirmation=True,
        approver_id="human://local/test-reviewer",
        now=NOW,
    )
    assert contract_issues(decision, "orchestration-task-approval-decision-v1.schema.json") == ()
    unsigned = {key: value for key, value in decision.items() if key != "signature"}
    assert service.authorization.policy_signer is not None
    assert service.authorization.policy_signer.verify(
        canonical_json(unsigned).encode(),
        decision["signature"]["value"],
        decision["signature"]["key_id"],
    )
    assert decision["authority"] == "none" and decision["execution_enabled"] is False
    with closing(sqlite3.connect(service.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?", (TASK,)
        ).fetchone()
        assert (task["state"], task["revision"]) == ("awaiting_human", 1)
        assert connection.execute("SELECT count(*) FROM action_grants").fetchone()[0] == grant_count
        assert service.authorization.verify_audit_chain()["valid"] is True


def test_rejection_cancels_single_task_plan(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)
    decision = service.decide(
        request["request_id"],
        decision="rejected",
        reason="Synthetic rejection.",
        explicit_confirmation=True,
        approver_id="human://local/test-reviewer",
        now=NOW,
    )
    assert decision["resulting_task_state"] == "cancelled"
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute(
                "SELECT state FROM orchestration_plans WHERE plan_id = ?", (PLAN,)
            ).fetchone()[0]
            == "cancelled"
        )


def test_input_confirmation_expiry_and_fencing_deny(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)
    cases = (
        (
            {
                "decision": "maybe",
                "reason": "x",
                "explicit_confirmation": True,
                "approver_id": "human://test",
                "now": NOW,
            },
            "ORCHESTRATION_APPROVAL_DECISION_INVALID",
        ),
        (
            {
                "decision": "approved",
                "reason": "x",
                "explicit_confirmation": False,
                "approver_id": "human://test",
                "now": NOW,
            },
            "ORCHESTRATION_APPROVAL_CONFIRMATION_REQUIRED",
        ),
        (
            {
                "decision": "approved",
                "reason": " ",
                "explicit_confirmation": True,
                "approver_id": "human://test",
                "now": NOW,
            },
            "ORCHESTRATION_APPROVAL_REASON_INVALID",
        ),
        (
            {
                "decision": "approved",
                "reason": "x",
                "explicit_confirmation": True,
                "approver_id": " ",
                "now": NOW,
            },
            "ORCHESTRATION_APPROVAL_ACTOR_INVALID",
        ),
        (
            {
                "decision": "approved",
                "reason": "x",
                "explicit_confirmation": True,
                "approver_id": "human://test",
                "now": NOW + timedelta(minutes=16),
            },
            "ORCHESTRATION_APPROVAL_REQUEST_STALE",
        ),
    )
    for arguments, code in cases:
        with pytest.raises(OrchestrationApprovalError) as raised:
            service.decide(request["request_id"], **arguments)
        assert raised.value.code == code
    stale = copy.deepcopy(binding)
    stale["expected_task_revision"] = 2
    with pytest.raises(OrchestrationApprovalError) as fenced:
        service.create_request(**stale, now=NOW)
    assert fenced.value.code == "ORCHESTRATION_APPROVAL_TASK_FENCED"


def test_exact_replay_is_idempotent_conflict_and_changed_state_deny(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)
    arguments = {
        "decision": "approved",
        "reason": "Synthetic review complete.",
        "explicit_confirmation": True,
        "approver_id": "human://local/test-reviewer",
        "now": NOW,
    }
    first = service.decide(request["request_id"], **arguments)
    assert service.decide(request["request_id"], **arguments) == first
    changed = dict(arguments, reason="Changed reason.")
    with pytest.raises(OrchestrationApprovalError) as conflict:
        service.decide(request["request_id"], **changed)
    assert conflict.value.code == "ORCHESTRATION_APPROVAL_IDENTITY_CONFLICT"
    DurablePlanGraphService(service.database_path).transition(
        {
            "schema_version": "1.0.0",
            "command_id": "55555555-5555-4555-8555-555555555555",
            "plan_id": PLAN,
            "assessment_id": binding["assessment_id"],
            "task_id": TASK,
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
            "target_state": "cancelled",
            "requested_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        now=NOW,
    )
    with pytest.raises(OrchestrationApprovalError) as stale:
        service.decide(request["request_id"], **arguments)
    assert stale.value.code == "ORCHESTRATION_APPROVAL_REPLAY_STALE"


def test_concurrent_exact_decisions_are_idempotent_and_records_immutable(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)

    def decide(_: int) -> dict[str, Any]:
        return service.decide(
            request["request_id"],
            decision="approved",
            reason="Synthetic concurrent review.",
            explicit_confirmation=True,
            approver_id="human://local/test-reviewer",
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(decide, range(2)))
    assert outcomes[0] == outcomes[1]
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_task_approval_requests")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_task_approval_decisions SET decision='rejected'"
            )


def test_cancelled_task_and_missing_signer_deny(tmp_path: Path) -> None:
    service, binding = setup(tmp_path)
    request = service.create_request(**binding, now=NOW)
    DurablePlanGraphService(service.database_path).transition(
        {
            "schema_version": "1.0.0",
            "command_id": "66666666-6666-4666-8666-666666666666",
            "plan_id": PLAN,
            "assessment_id": binding["assessment_id"],
            "task_id": TASK,
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
            "target_state": "cancelled",
            "requested_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        now=NOW,
    )
    with pytest.raises(OrchestrationApprovalError) as cancelled:
        service.decide(
            request["request_id"],
            decision="approved",
            reason="Too late.",
            explicit_confirmation=True,
            approver_id="human://test",
            now=NOW,
        )
    assert cancelled.value.code == "ORCHESTRATION_APPROVAL_PLAN_FENCED"
    service.authorization.policy_signer = None
    with pytest.raises(OrchestrationApprovalError) as signer:
        service.decide(
            request["request_id"],
            decision="approved",
            reason="No signer.",
            explicit_confirmation=True,
            approver_id="human://test",
            now=NOW,
        )
    assert signer.value.code == "ORCHESTRATION_APPROVAL_SIGNER_UNAVAILABLE"
