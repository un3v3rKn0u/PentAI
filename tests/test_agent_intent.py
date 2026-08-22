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
from pentai_core.agent_intent import AgentActionIntentService, AgentIntentError
from pentai_core.orchestration import DurablePlanGraphService
from pentai_policy import canonicalize_url, content_hash
from pentai_policy.document import contract_issues, parse_time
from test_orchestration_budget import NOW as BUDGET_NOW
from test_orchestration_budget import PLAN_ID, TASK_ID
from test_orchestration_budget import setup as budget_setup

NOW = BUDGET_NOW


def setup(
    tmp_path: Path, *, maximum_timeout_seconds: int = 30
) -> tuple[AgentActionIntentService, dict[str, Any]]:
    budget_service, budget_request = budget_setup(tmp_path)
    authorization = budget_service.authorization
    engagement_id = budget_request["assessment_id"]
    policy_id = budget_request["policy_bundle_id"]
    policy_hash = budget_request["policy_hash"]
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
    service = AgentActionIntentService(authorization)
    manifest = service.issue_capability_manifest(
        assessment_id=engagement_id,
        plan_id=PLAN_ID,
        expected_plan_revision=2,
        task_id=TASK_ID,
        expected_task_revision=2,
        agent_id="agent://validation/fixture",
        policy_bundle_id=policy_id,
        policy_hash=policy_hash,
        maximum_timeout_seconds=maximum_timeout_seconds,
        now=NOW,
    )
    request = {
        "schema_version": "2.0.0",
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
        "capability_manifest_id": manifest["manifest_id"],
        "expected_manifest_revision": manifest["manifest_revision"],
        "input_sha256": "sha256:" + "a" * 64,
        "action_sha256": "sha256:" + content_hash(action),
        "action": action,
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "delegation_requested": False,
        "authority": "none",
        "execution_enabled": False,
    }
    return service, request


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
        assert link["capability_manifest_id"] == request["capability_manifest_id"]
        assert link["capability_manifest_revision"] == 1
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


def test_trusted_core_issues_immutable_non_authoritative_manifest(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
            (request["capability_manifest_id"],),
        ).fetchone()
        assert row is not None
        manifest = json.loads(row["manifest_json"])
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM audit_events
                WHERE action = 'orchestration.task_capability_manifest_issued'
                AND subject_id = ?""",
                (request["capability_manifest_id"],),
            ).fetchone()[0]
            == 1
        )
    assert contract_issues(manifest, "task-capability-manifest-v1.schema.json") == ()
    assert manifest["manifest_id"] == request["capability_manifest_id"]
    assert manifest["authority"] == "none"
    assert manifest["execution_enabled"] is False
    assert service.authorization.verify_audit_chain()["valid"] is True
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE task_capability_manifests SET delegation_allowed = 1"
        )
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("DELETE FROM task_capability_manifests")


def test_v1_and_missing_unknown_or_mismatched_manifest_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    legacy = copy.deepcopy(request)
    legacy["schema_version"] = "1.0.0"
    legacy.pop("capability_manifest_id")
    legacy.pop("expected_manifest_revision")
    with pytest.raises(AgentIntentError) as required:
        service.convert(legacy, now=NOW)
    assert required.value.code == "AGENT_INTENT_CAPABILITY_MANIFEST_REQUIRED"

    cases = (
        ("capability_manifest_id", str(uuid4()), "AGENT_INTENT_MANIFEST_MISSING"),
        ("expected_manifest_revision", 2, "AGENT_INTENT_REQUEST_MALFORMED"),
    )
    for field, value, code in cases:
        changed = copy.deepcopy(request)
        changed[field] = value
        with pytest.raises(AgentIntentError) as raised:
            service.convert(changed, now=NOW)
        assert raised.value.code == code

    changed = copy.deepcopy(request)
    changed["agent"]["agent_id"] = "agent://validation/other"
    with pytest.raises(AgentIntentError) as mismatch:
        service.convert(changed, now=NOW)
    assert mismatch.value.code == "AGENT_INTENT_MANIFEST_MISMATCH"


def test_manifest_limits_and_expiry_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        manifest = json.loads(
            connection.execute(
                "SELECT manifest_json FROM task_capability_manifests"
            ).fetchone()[0]
        )
    request["created_at"] = (NOW + timedelta(minutes=14)).isoformat()
    request["expires_at"] = (NOW + timedelta(minutes=16)).isoformat()
    with pytest.raises(AgentIntentError) as stale:
        service.convert(request, now=NOW + timedelta(minutes=15))
    assert stale.value.code == "AGENT_INTENT_MANIFEST_STALE"
    assert parse_time(manifest["expires_at"]) <= NOW + timedelta(minutes=15)

    limited_service, limited_request = setup(
        tmp_path / "limited", maximum_timeout_seconds=4
    )
    with pytest.raises(AgentIntentError) as exceeded:
        limited_service.convert(limited_request, now=NOW)
    assert exceeded.value.code == "AGENT_INTENT_MANIFEST_LIMIT_EXCEEDED"


def test_manifest_issuance_replay_and_conflict_are_deterministic(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    arguments: dict[str, Any] = {
        "assessment_id": str(request["assessment_id"]),
        "plan_id": PLAN_ID,
        "expected_plan_revision": 2,
        "task_id": TASK_ID,
        "expected_task_revision": 2,
        "agent_id": "agent://validation/fixture",
        "policy_bundle_id": str(request["policy_bundle_id"]),
        "policy_hash": str(request["policy_hash"]),
        "now": NOW,
    }
    first = service.issue_capability_manifest(**arguments)
    assert service.issue_capability_manifest(**arguments) == first
    with pytest.raises(AgentIntentError) as conflict:
        service.issue_capability_manifest(**arguments, maximum_timeout_seconds=4)
    assert conflict.value.code == "TASK_CAPABILITY_IDENTITY_CONFLICT"


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
