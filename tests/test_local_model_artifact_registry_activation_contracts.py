from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.local_model_artifact_manifest import (
    resolve_built_in_local_model_artifact_manifest,
)
from pentai_core.migrate import migrate
from pentai_policy.document import contract_issues


def command() -> dict[str, Any]:
    manifest = resolve_built_in_local_model_artifact_manifest()
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "manifest_id": manifest.manifest_id,
        "manifest_revision": manifest.manifest_revision,
        "manifest_digest": manifest.manifest_digest,
        "requester": {
            "actor_type": "human",
            "actor_id": "test-session",
            "session_id": str(uuid4()),
        },
        "authentication_context": "local_core_authenticated_session",
        "purpose": "activate_local_model_artifact_registry",
        "requested_at": "2026-09-14T10:00:00Z",
        "expires_at": "2026-09-14T10:05:00Z",
        "review_period_days": 180,
        "activation_enabled": False,
        "verification_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def receipt(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "activation_id": str(uuid4()),
        "command_id": source["command_id"],
        "command_digest": "sha256:" + "a" * 64,
        "manifest_id": source["manifest_id"],
        "manifest_revision": source["manifest_revision"],
        "manifest_digest": source["manifest_digest"],
        "requester": source["requester"],
        "authentication_context": source["authentication_context"],
        "state": "active",
        "review_period_days": 180,
        "activated_at": "2026-09-14T10:00:01Z",
        "expires_at": "2027-03-13T10:00:01Z",
        "verification_enabled": False,
        "revocation_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_contracts_bind_exact_built_in_manifest_without_authority() -> None:
    source = command()
    assert not contract_issues(
        source, "local-model-artifact-registry-activation-command-v1.schema.json"
    )
    assert not contract_issues(
        receipt(source),
        "local-model-artifact-registry-activation-receipt-v1.schema.json",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("manifest_id", "caller-manifest"),
        ("manifest_revision", 2),
        ("manifest_digest", "sha256:" + "b" * 64),
        ("authentication_context", "caller_assertion"),
        ("purpose", "verify_or_execute"),
        ("review_period_days", 181),
        ("activation_enabled", True),
        ("verification_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ),
)
def test_command_rejects_substitution_and_privilege(
    field: str, value: object
) -> None:
    malformed = command()
    malformed[field] = value
    assert contract_issues(
        malformed, "local-model-artifact-registry-activation-command-v1.schema.json"
    )


def test_receipt_rejects_downstream_behavior_and_payloads() -> None:
    for field in ("verification_enabled", "revocation_enabled", "execution_enabled"):
        malformed = receipt(command())
        malformed[field] = True
        assert contract_issues(
            malformed,
            "local-model-artifact-registry-activation-receipt-v1.schema.json",
        )
    for field in ("path", "artifact", "prompt", "grant", "diagnostic"):
        malformed = receipt(command())
        malformed[field] = "forbidden"
        assert contract_issues(
            malformed,
            "local-model-artifact-registry-activation-receipt-v1.schema.json",
        )


def test_storage_is_empty_immutable_and_has_no_producer(tmp_path: Path) -> None:
    database = tmp_path / "pentai.db"
    migrate(database)
    source = command()
    result = receipt(source)
    with sqlite3.connect(database) as connection:
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }
        assert {
            "local_model_artifact_registry_activations_v1_binding_valid",
            "local_model_artifact_registry_activations_v1_producer_disabled",
            "local_model_artifact_registry_activations_v1_immutable",
            "local_model_artifact_registry_activations_v1_no_delete",
        } <= triggers
        assert connection.execute(
            "SELECT COUNT(*) FROM local_model_artifact_registry_activations_v1"
        ).fetchone() == (0,)
        with pytest.raises(
            sqlite3.IntegrityError,
            match="local model artifact registry activation producer is disabled",
        ):
            connection.execute(
                """INSERT INTO local_model_artifact_registry_activations_v1(
                activation_id,receipt_digest,command_id,command_digest,manifest_id,
                manifest_revision,manifest_digest,actor_id,session_id,command_json,
                receipt_json,activated_at,expires_at,state,review_period_days,
                verification_enabled,revocation_enabled,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'active',180,0,0,'none',0)""",
                (
                    result["activation_id"],
                    "sha256:" + "b" * 64,
                    source["command_id"],
                    result["command_digest"],
                    source["manifest_id"],
                    source["manifest_revision"],
                    source["manifest_digest"],
                    source["requester"]["actor_id"],
                    source["requester"]["session_id"],
                    json.dumps(source),
                    json.dumps(result),
                    result["activated_at"],
                    result["expires_at"],
                ),
            )
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_binding_guard_precedes_disabled_producer(tmp_path: Path) -> None:
    database = tmp_path / "pentai.db"
    migrate(database)
    source = command()
    result = receipt(source)
    result["manifest_digest"] = "sha256:" + "c" * 64
    with sqlite3.connect(database) as connection, pytest.raises(
        sqlite3.IntegrityError,
        match="local model artifact registry activation binding is invalid",
    ):
        connection.execute(
            """INSERT INTO local_model_artifact_registry_activations_v1(
            activation_id,receipt_digest,command_id,command_digest,manifest_id,
            manifest_revision,manifest_digest,actor_id,session_id,command_json,
            receipt_json,activated_at,expires_at,state,review_period_days,
            verification_enabled,revocation_enabled,authority,execution_enabled)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'active',180,0,0,'none',0)""",
            (
                result["activation_id"], "sha256:" + "b" * 64,
                source["command_id"], result["command_digest"], source["manifest_id"],
                source["manifest_revision"], source["manifest_digest"],
                source["requester"]["actor_id"], source["requester"]["session_id"],
                json.dumps(source), json.dumps(result), result["activated_at"],
                result["expires_at"],
            ),
        )
