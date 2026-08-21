from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.agent_intent import AgentActionIntentService, AgentIntentError
from pentai_core.migrate import migrate
from pentai_core.orchestration import DurablePlanGraphService
from pentai_policy import canonicalize_url, content_hash
from pentai_policy.document import contract_issues

from scripts.owned_fixture_authority import prepare_owned_fixture_session

NOW = datetime.now(UTC).replace(microsecond=0)
PLAN_ID = "11111111-1111-4111-8111-111111111111"
TASK_ID = "22222222-2222-4222-8222-222222222222"


def setup(tmp_path: Path) -> tuple[AgentActionIntentService, dict[str, object]]:
    database = tmp_path / "agent-intent.db"
    migrate(database)
    authorization, session = prepare_owned_fixture_session(
        database_path=database, source_store_path=tmp_path / "sources"
    )
    with closing(sqlite3.connect(database)) as connection:
        engagement_id, policy_id, policy_hash = connection.execute(
            """SELECT e.id, e.active_policy_id, p.content_hash FROM engagements e
            JOIN policy_bundles p ON p.id = e.active_policy_id
            JOIN budget_reservations b ON b.engagement_id = e.id
            WHERE b.reservation_id = ?""",
            (session["reservation_id"],),
        ).fetchone()
    graph = {
        "schema_version": "1.0.0",
        "plan_id": PLAN_ID,
        "assessment_id": engagement_id,
        "idempotency_key": "synthetic-agent-plan-0001",
        "revision": 1,
        "state": "active",
        "tasks": [
            {
                "task_id": TASK_ID,
                "task_type": "validation",
                "objective": "Propose one synthetic supervised validation request.",
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
    plans.transition(
        {
            "schema_version": "1.0.0",
            "command_id": str(uuid4()),
            "plan_id": PLAN_ID,
            "assessment_id": engagement_id,
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
    action = {
        "capability": "network.http.get",
        "target": canonicalize_url("http://192.0.2.10:8080/fixture"),
        "http": {
            "method": "GET",
            "headers_digest": "0" * 64,
            "body_digest": None,
            "follow_redirects": False,
        },
        "impact": "benign",
        "requested_limits": {"timeout_seconds": 5, "maximum_response_bytes": 4096},
    }
    request = {
        "schema_version": "1.0.0",
        "request_id": str(uuid4()),
        "assessment_id": engagement_id,
        "plan_id": PLAN_ID,
        "expected_plan_revision": 2,
        "task_id": TASK_ID,
        "expected_task_revision": 2,
        "agent": {"agent_type": "validation", "agent_id": "agent://validation/fixture"},
        "purpose": "propose_supervised_http_validation",
        "policy_bundle_id": policy_id,
        "policy_hash": policy_hash,
        "input_sha256": "sha256:" + "a" * 64,
        "action_sha256": "sha256:" + content_hash(action),
        "action": action,
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "delegation_requested": False,
        "authority": "none",
        "execution_enabled": False,
    }
    return AgentActionIntentService(authorization), request


def test_converts_to_pending_intent_with_exact_provenance_and_audit(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    intent = service.convert(request, now=NOW)
    assert contract_issues(intent, "action-intent-v1.schema.json") == ()
    assert intent["actor"] == {"actor_type": "agent", "actor_id": "agent://validation/fixture"}
    assert intent["task_id"] == TASK_ID
    with closing(sqlite3.connect(service.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM policy_evaluations WHERE intent_id = ?",
                (intent["intent_id"],),
            ).fetchone()[0]
            == 0
        )
        link = connection.execute("SELECT * FROM agent_action_intent_links").fetchone()
        assert link["authority"] == "none" and link["execution_enabled"] == 0
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM action_grants WHERE intent_id = ?", (intent["intent_id"],)
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'agent.action_intent_created'"
            ).fetchone()[0]
            == 1
        )
    assert service.authorization.verify_audit_chain()["valid"] is True


def test_malformed_unsupported_secret_command_and_tampering_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    cases = []
    for key, value in (("authority", "grant"), ("delegation_requested", True)):
        changed = copy.deepcopy(request)
        changed[key] = value
        cases.append((changed, "AGENT_INTENT_REQUEST_MALFORMED"))
    unknown = copy.deepcopy(request)
    unknown["command"] = "curl synthetic"
    cases.append((unknown, "AGENT_INTENT_REQUEST_MALFORMED"))
    secret = copy.deepcopy(request)
    secret["secret_value"] = 42
    cases.append((secret, "AGENT_INTENT_REQUEST_MALFORMED"))
    unsupported = copy.deepcopy(request)
    unsupported["action"]["capability"] = "network.http.head"
    cases.append((unsupported, "AGENT_INTENT_REQUEST_MALFORMED"))
    tampered = copy.deepcopy(request)
    tampered["action"]["impact"] = "passive"
    cases.append((tampered, "AGENT_INTENT_ACTION_TAMPERED"))
    for document, code in cases:
        with pytest.raises(AgentIntentError) as raised:
            service.convert(document, now=NOW)
        assert raised.value.code == code


def test_scope_policy_plan_task_revision_state_and_expiry_deny(tmp_path: Path) -> None:
    cases = (
        ("assessment_id", str(uuid4()), "AGENT_INTENT_POLICY_INVALID"),
        ("policy_hash", "f" * 64, "AGENT_INTENT_POLICY_STALE"),
        ("plan_id", str(uuid4()), "AGENT_INTENT_PLAN_MISMATCH"),
        ("expected_plan_revision", 1, "AGENT_INTENT_PLAN_FENCED"),
        ("task_id", str(uuid4()), "AGENT_INTENT_TASK_MISMATCH"),
        ("expected_task_revision", 1, "AGENT_INTENT_TASK_FENCED"),
    )
    for field, value, code in cases:
        service, request = setup(tmp_path / str(uuid4()))
        request[field] = value
        with pytest.raises(AgentIntentError) as raised:
            service.convert(request, now=NOW)
        assert raised.value.code == code
    service, request = setup(tmp_path / "stale")
    request["expires_at"] = NOW.isoformat()
    with pytest.raises(AgentIntentError) as stale:
        service.convert(request, now=NOW)
    assert stale.value.code == "AGENT_INTENT_REQUEST_STALE"


def test_replay_conflict_and_concurrency_are_atomic(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    first = service.convert(request, now=NOW)
    assert service.convert(request, now=NOW) == first
    conflict = copy.deepcopy(request)
    conflict["input_sha256"] = "sha256:" + "b" * 64
    with pytest.raises(AgentIntentError) as raised:
        service.convert(conflict, now=NOW)
    assert raised.value.code == "AGENT_INTENT_REQUEST_IDENTITY_CONFLICT"
    other, contender = setup(tmp_path / "concurrent")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: other.convert(contender, now=NOW), range(2)))
    assert results[0] == results[1]


def test_cancelled_task_safety_pause_and_recovery_state_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE safety_state SET global_status = 'paused', generation = generation + 1"
        )
    with pytest.raises(AgentIntentError) as paused:
        service.convert(request, now=NOW)
    assert paused.value.code == "AGENT_INTENT_SAFETY_DENIED"

    cancelled_service, cancelled_request = setup(tmp_path / "cancelled")
    plans = DurablePlanGraphService(cancelled_service.database_path)
    for plan_revision, task_revision, target in ((2, 2, "cancelling"), (3, 3, "cancelled")):
        plans.transition(
            {
                "schema_version": "1.0.0",
                "command_id": str(uuid4()),
                "plan_id": PLAN_ID,
                "assessment_id": cancelled_request["assessment_id"],
                "task_id": TASK_ID,
                "expected_plan_revision": plan_revision,
                "expected_task_revision": task_revision,
                "target_state": target,
                "requested_at": NOW.isoformat(),
                "authority": "none",
                "execution_enabled": False,
            },
            now=NOW,
        )
    cancelled_request["expected_plan_revision"] = 4
    cancelled_request["expected_task_revision"] = 4
    with pytest.raises(AgentIntentError) as cancelled:
        cancelled_service.convert(cancelled_request, now=NOW)
    assert cancelled.value.code == "AGENT_INTENT_PLAN_FENCED"

    recovered_service, recovered_request = setup(tmp_path / "recovered")
    DurablePlanGraphService(recovered_service.database_path).recover(now=NOW)
    recovered_request["expected_plan_revision"] = 3
    recovered_request["expected_task_revision"] = 3
    with pytest.raises(AgentIntentError) as recovered:
        recovered_service.convert(recovered_request, now=NOW)
    assert recovered.value.code == "AGENT_INTENT_PLAN_FENCED"


def test_provenance_and_intent_history_are_immutable(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    intent = service.convert(request, now=NOW)
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("UPDATE agent_action_intent_links SET authority = 'grant'")
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("DELETE FROM action_intents WHERE intent_id = ?", (intent["intent_id"],))
