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
from pentai_core.authorization import DomainError
from pentai_core.local_model_intent import (
    CAPABILITY,
    MODEL_ID,
    PROVIDER_ID,
    LocalModelIntentError,
    LocalModelIntentService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_authorization_slice import manifest_for
from test_orchestration_budget import NOW, PLAN_ID, TASK_ID
from test_orchestration_budget import setup as budget_setup


def _activate_local_policy(
    service: LocalModelIntentService,
    budget_request: dict[str, Any],
    *,
    effect: str = "allow",
) -> None:
    with closing(sqlite3.connect(service.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (budget_request["assessment_id"],)
        ).fetchone()
        source = connection.execute(
            "SELECT * FROM source_documents WHERE program_id=? ORDER BY retrieved_at LIMIT 1",
            (engagement["program_id"],),
        ).fetchone()
    candidate = manifest_for(dict(engagement), dict(source))
    candidate["schema_version"] = "3.0.0"
    techniques = candidate["techniques"]
    assert isinstance(techniques, dict)
    techniques["allowed_capabilities"] = ["network.http.get"]
    if effect == "allow":
        techniques["allowed_capabilities"].append(CAPABILITY)
    elif effect == "deny":
        techniques["denied_capabilities"] = [CAPABILITY]
    else:
        techniques["conditional_capabilities"] = [
            {
                "capability": CAPABILITY,
                "approval_type": "local_model_generation",
                "conditions": ["human review required"],
            }
        ]
    version = service.authorization.save_manifest(budget_request["assessment_id"], candidate)
    policy = service.authorization.compile_policy(version["id"])
    service.authorization.approve_policy(
        policy["id"], approver_id="synthetic-local-policy-reviewer"
    )
    service.authorization.activate_policy(
        policy["id"], actor_id="synthetic-local-policy-reviewer"
    )
    budget_request["policy_bundle_id"] = policy["id"]
    budget_request["policy_hash"] = policy["content_hash"]


def setup(
    tmp_path: Path, *, policy_effect: str | None = None
) -> tuple[LocalModelIntentService, dict[str, Any]]:
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
    if policy_effect is not None:
        _activate_local_policy(service, budget_request, effect=policy_effect)
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


def test_evaluates_exact_local_model_intent_without_grant_authority(tmp_path: Path) -> None:
    service, request = setup(tmp_path, policy_effect="allow")
    intent = service.convert(request, now=NOW)
    decision = service.evaluate(intent["intent_id"], now=NOW)

    assert contract_issues(decision, "policy-decision-v2.schema.json") == ()
    assert decision["outcome"] == "allow"
    assert decision["reason_code"] == "EXPLICIT_ALLOW"
    assert decision["authority"] == "none"
    assert decision["grant_enabled"] is False
    assert decision["execution_enabled"] is False
    assert service.evaluate(intent["intent_id"], now=NOW) == decision
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM local_model_policy_evaluations_v2 WHERE intent_id=?",
            (intent["intent_id"],),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM action_grants WHERE intent_id=?", (intent["intent_id"],)
        ).fetchone()[0] == 0
    with pytest.raises(DomainError) as grant:
        service.authorization.mint_action_grant(decision["decision_id"])
    assert grant.value.code == "DECISION_NOT_FOUND"


@pytest.mark.parametrize(
    ("effect", "outcome", "reason"),
    [
        ("deny", "deny", "EXPLICIT_DENY"),
        ("conditional", "approval_required", "APPROVAL_REQUIRED"),
    ],
)
def test_local_model_policy_effects_are_closed(
    tmp_path: Path, effect: str, outcome: str, reason: str
) -> None:
    service, request = setup(tmp_path, policy_effect=effect)
    intent = service.convert(request, now=NOW)
    decision = service.evaluate(intent["intent_id"], now=NOW)
    assert decision["outcome"] == outcome
    assert decision["reason_code"] == reason
    assert ("required_approval_type" in decision) is (effect == "conditional")


def test_local_model_evaluation_replay_is_serialized(tmp_path: Path) -> None:
    service, request = setup(tmp_path, policy_effect="allow")
    intent = service.convert(request, now=NOW)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.evaluate(intent["intent_id"], now=NOW), range(2)))
    assert results[0] == results[1]


def test_local_model_evaluation_denies_stale_state_and_direct_storage(tmp_path: Path) -> None:
    service, request = setup(tmp_path, policy_effect="allow")
    intent = service.convert(request, now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute("UPDATE safety_state SET global_status='paused'")
    with pytest.raises(LocalModelIntentError) as paused:
        service.evaluate(intent["intent_id"], now=NOW)
    assert paused.value.code == "LOCAL_MODEL_EVALUATION_STATE_STALE"
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute("UPDATE safety_state SET global_status='active'")
    decision = service.evaluate(intent["intent_id"], now=NOW)
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE local_model_policy_evaluations_v2 SET outcome='deny' "
                "WHERE decision_id=?",
                (decision["decision_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM local_model_policy_evaluations_v2 WHERE decision_id=?",
                (decision["decision_id"],),
            )


def test_local_model_evaluation_denies_task_policy_and_expiry_changes(tmp_path: Path) -> None:
    task_service, task_request = setup(tmp_path / "task", policy_effect="allow")
    task_intent = task_service.convert(task_request, now=NOW)
    with closing(sqlite3.connect(task_service.database_path)) as connection, connection:
        connection.execute(
            "UPDATE orchestration_tasks SET state='cancelling',revision=revision+1 "
            "WHERE task_id=?",
            (TASK_ID,),
        )
    with pytest.raises(LocalModelIntentError) as task_stale:
        task_service.evaluate(task_intent["intent_id"], now=NOW)
    assert task_stale.value.code == "LOCAL_MODEL_EVALUATION_STATE_STALE"

    policy_service, policy_request = setup(tmp_path / "policy", policy_effect="allow")
    policy_intent = policy_service.convert(policy_request, now=NOW)
    policy_service.authorization.revoke_policy(
        policy_request["policy_bundle_id"],
        actor_id="synthetic-local-policy-reviewer",
        reason="synthetic revocation",
    )
    with pytest.raises(LocalModelIntentError) as policy_stale:
        policy_service.evaluate(policy_intent["intent_id"], now=NOW)
    assert policy_stale.value.code == "LOCAL_MODEL_EVALUATION_STATE_STALE"

    expired_service, expired_request = setup(tmp_path / "expired", policy_effect="allow")
    expired_intent = expired_service.convert(expired_request, now=NOW)
    with pytest.raises(LocalModelIntentError) as expired:
        expired_service.evaluate(expired_intent["intent_id"], now=NOW + timedelta(minutes=3))
    assert expired.value.code == "LOCAL_MODEL_EVALUATION_EXPIRED"


def test_local_model_evaluation_storage_rejects_caller_selected_outcome(tmp_path: Path) -> None:
    service, request = setup(tmp_path, policy_effect="allow")
    intent = service.convert(request, now=NOW)
    decision = service.evaluate(intent["intent_id"], now=NOW)
    forged = copy.deepcopy(decision)
    forged["decision_id"] = str(uuid4())
    forged["outcome"] = "deny"
    forged["reason_code"] = "EXPLICIT_DENY"
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="binding is invalid"):
            connection.execute(
                """INSERT INTO local_model_policy_evaluations_v2(
                decision_id,intent_id,intent_hash,assessment_id,plan_id,plan_revision,
                task_id,task_revision,policy_bundle_id,policy_hash,policy_epoch,
                capability_manifest_id,configuration_snapshot_id,
                configuration_snapshot_digest,outcome,decision_json,decided_at,
                expires_at,authority,grant_enabled,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'none',0,0)""",
                (
                    forged["decision_id"],
                    forged["intent_id"],
                    forged["intent_hash"],
                    forged["assessment_id"],
                    forged["plan_id"],
                    forged["plan_revision"],
                    forged["task_id"],
                    forged["task_revision"],
                    forged["policy_bundle_id"],
                    forged["policy_hash"],
                    forged["policy_epoch"],
                    forged["capability_manifest_id"],
                    forged["configuration_snapshot_id"],
                    forged["configuration_snapshot_digest"],
                    forged["outcome"],
                    json.dumps(forged),
                    forged["decided_at"],
                    forged["expires_at"],
                ),
            )


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
