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
from pentai_core.ai_provider_configuration_snapshot import ProviderConfigurationSnapshotService
from pentai_core.ai_provider_registry_activation import ProviderRegistryActivationService
from pentai_core.ai_provider_registry_snapshot import ProviderRegistrySnapshotService
from pentai_core.local_model_intent import (
    CAPABILITY,
    MODEL_ID,
    PROVIDER_ID,
    LocalModelIntentError,
    LocalModelIntentService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW, PLAN_ID, TASK_ID
from test_orchestration_budget import setup as budget_setup


def setup(tmp_path: Path) -> tuple[LocalModelIntentService, dict[str, Any]]:
    budget, budget_request = budget_setup(tmp_path)
    authorization = budget.authorization
    registry_service = ProviderRegistrySnapshotService(authorization)
    activation_service = ProviderRegistryActivationService(authorization)
    configuration_service = ProviderConfigurationSnapshotService(authorization)
    registry = {
        "schema_version": "1.0.0",
        "registry_id": str(uuid4()),
        "revision": 1,
        "providers": [
            {
                "provider_id": PROVIDER_ID,
                "provider_type": "local_runtime",
                "models": [MODEL_ID],
                "allowed_input_classifications": ["public", "confidential"],
                "state": "enabled",
            }
        ],
        "budget_ceilings": {
            "max_input_tokens": 4096,
            "max_output_tokens": 1024,
            "max_requests": 4,
            "max_cost_microusd": 0,
            "max_runtime_seconds": 120,
        },
        "remote_providers_enabled": False,
        "configured_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "execution_enabled": False,
    }
    registry_receipt = registry_service.produce(
        registry,
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )
    activation = activation_service.activate(
        registry_receipt["snapshot_id"],
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )
    configuration = {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "local_runtime",
        "provider_id": PROVIDER_ID,
        "model_id": MODEL_ID,
        "secret_ref": None,
        "privacy_classification": "local_device",
        "allowed_input_classifications": ["public", "confidential"],
        "budgets": {
            "max_input_tokens": 4096,
            "max_output_tokens": 1024,
            "max_requests": 4,
            "max_cost_microusd": 0,
            "max_runtime_seconds": 120,
        },
        "remote_provider_opt_in": False,
        "configured_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=6)).isoformat(),
        "execution_enabled": False,
    }
    configuration_receipt = configuration_service.produce(
        activation["activation_id"],
        configuration,
        secret_reference=None,
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )
    service = LocalModelIntentService(authorization)
    manifest = service.issue_capability_manifest(
        assessment_id=budget_request["assessment_id"],
        plan_id=PLAN_ID,
        expected_plan_revision=2,
        task_id=TASK_ID,
        expected_task_revision=2,
        agent_id="agent://validation/local-model",
        policy_bundle_id=budget_request["policy_bundle_id"],
        policy_hash=budget_request["policy_hash"],
        configuration_snapshot_id=configuration_receipt["snapshot_id"],
        configuration_snapshot_digest=configuration_receipt["snapshot_digest"],
        maximum_input_tokens=1024,
        maximum_output_tokens=256,
        maximum_runtime_seconds=30,
        now=NOW,
    )
    action = {
        "capability": CAPABILITY,
        "configuration_snapshot_id": configuration_receipt["snapshot_id"],
        "configuration_snapshot_digest": configuration_receipt["snapshot_digest"],
        "provider_id": PROVIDER_ID,
        "model_id": MODEL_ID,
        "requested_limits": {
            "maximum_input_tokens": 512,
            "maximum_output_tokens": 128,
            "maximum_runtime_seconds": 15,
        },
    }
    request = {
        "schema_version": "1.0.0",
        "request_id": str(uuid4()),
        "assessment_id": budget_request["assessment_id"],
        "plan_id": PLAN_ID,
        "expected_plan_revision": 2,
        "task_id": TASK_ID,
        "expected_task_revision": 2,
        "capability_manifest_id": manifest["manifest_id"],
        "expected_manifest_revision": 1,
        "agent": {
            "agent_type": "validation",
            "agent_id": "agent://validation/local-model",
        },
        "purpose": "propose_supervised_local_model_generation",
        "policy_bundle_id": budget_request["policy_bundle_id"],
        "policy_hash": budget_request["policy_hash"],
        "input_sha256": "sha256:" + "a" * 64,
        "input_classification": "confidential",
        "action_sha256": "sha256:" + content_hash(action),
        "action": action,
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "delegation_requested": False,
        "authority": "none",
        "execution_enabled": False,
    }
    return service, request


def test_creates_pending_local_model_intent_without_execution_authority(
    tmp_path: Path,
) -> None:
    service, request = setup(tmp_path)
    intent = service.convert(request, now=NOW)

    assert contract_issues(intent, "action-intent-v2.schema.json") == ()
    assert intent["capability"] == CAPABILITY
    assert intent["local_model"]["provider_id"] == PROVIDER_ID
    assert intent["local_model"]["model_id"] == MODEL_ID
    assert intent["authority"] == "none"
    assert intent["execution_enabled"] is False
    assert "prompt" not in json.dumps(intent)
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM policy_evaluations WHERE intent_id=?",
                (intent["intent_id"],),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM action_grants WHERE intent_id=?",
                (intent["intent_id"],),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM agent_local_model_intent_links_v1"
            ).fetchone()[0]
            == 1
        )
    assert service.authorization.verify_audit_chain()["valid"] is True


def test_manifest_and_intent_replay_are_exact_and_concurrent(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    first = service.convert(request, now=NOW)
    assert service.convert(request, now=NOW) == first
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.convert(request, now=NOW), range(2)))
    assert results == [first, first]

    changed = copy.deepcopy(request)
    changed["input_sha256"] = "sha256:" + "b" * 64
    with pytest.raises(LocalModelIntentError) as conflict:
        service.convert(changed, now=NOW)
    assert conflict.value.code == "LOCAL_MODEL_INTENT_IDENTITY_CONFLICT"


def test_malformed_tampered_payload_and_substitution_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    cases: list[tuple[dict[str, Any], str]] = []
    for field in ("prompt", "response", "model_path", "url", "command", "payload"):
        changed = copy.deepcopy(request)
        changed[field] = "synthetic but forbidden"
        cases.append((changed, "LOCAL_MODEL_INTENT_REQUEST_MALFORMED"))
    model = copy.deepcopy(request)
    model["action"]["model_id"] = "caller/model"
    cases.append((model, "LOCAL_MODEL_INTENT_REQUEST_MALFORMED"))
    provider = copy.deepcopy(request)
    provider["action"]["provider_id"] = "caller-runtime"
    cases.append((provider, "LOCAL_MODEL_INTENT_REQUEST_MALFORMED"))
    authority = copy.deepcopy(request)
    authority["authority"] = "grant"
    cases.append((authority, "LOCAL_MODEL_INTENT_REQUEST_MALFORMED"))
    tampered = copy.deepcopy(request)
    tampered["action"]["requested_limits"]["maximum_output_tokens"] = 64
    cases.append((tampered, "LOCAL_MODEL_INTENT_ACTION_TAMPERED"))
    for document, code in cases:
        with pytest.raises(LocalModelIntentError) as raised:
            service.convert(document, now=NOW)
        assert raised.value.code == code


def test_stale_scope_safety_limits_and_direct_mutation_deny(tmp_path: Path) -> None:
    service, request = setup(tmp_path)
    exceeded = copy.deepcopy(request)
    exceeded["action"]["requested_limits"]["maximum_runtime_seconds"] = 31
    exceeded["action_sha256"] = "sha256:" + content_hash(exceeded["action"])
    with pytest.raises(LocalModelIntentError) as limit:
        service.convert(exceeded, now=NOW)
    assert limit.value.code == "LOCAL_MODEL_MANIFEST_LIMIT_EXCEEDED"

    wrong_scope = copy.deepcopy(request)
    wrong_scope["assessment_id"] = str(uuid4())
    with pytest.raises(LocalModelIntentError):
        service.convert(wrong_scope, now=NOW)

    paused_service, paused = setup(tmp_path / "paused")
    with closing(sqlite3.connect(paused_service.database_path)) as connection, connection:
        connection.execute("UPDATE safety_state SET global_status='paused'")
    with pytest.raises(LocalModelIntentError) as denied:
        paused_service.convert(paused, now=NOW)
    assert denied.value.code == "LOCAL_MODEL_INTENT_SAFETY_DENIED"

    intent = service.convert(request, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE agent_local_model_intent_links_v1 SET authority='none'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM agent_local_model_intent_links_v1 WHERE intent_id=?",
                (intent["intent_id"],),
            )
