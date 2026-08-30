from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.ai_provider_configuration_snapshot import (
    ProviderConfigurationSnapshotError,
    ProviderConfigurationSnapshotService,
)
from pentai_core.ai_provider_registry_activation import ProviderRegistryActivationService
from pentai_core.ai_provider_registry_snapshot import ProviderRegistrySnapshotService
from pentai_core.authorization import AuthorizationService
from pentai_core.migrate import migrate
from pentai_policy.document import contract_issues
from test_ai_provider_registry_snapshot import registry

NOW = datetime(2026, 8, 30, 12, 30, tzinfo=UTC)


def setup(
    tmp_path: Path,
) -> tuple[
    ProviderRegistrySnapshotService,
    ProviderRegistryActivationService,
    ProviderConfigurationSnapshotService,
]:
    database = tmp_path / "provider-configuration-snapshot.db"
    migrate(database)
    authorization = AuthorizationService(database)
    return (
        ProviderRegistrySnapshotService(authorization),
        ProviderRegistryActivationService(authorization),
        ProviderConfigurationSnapshotService(authorization),
    )


def active_lineage(
    snapshots: ProviderRegistrySnapshotService,
    activations: ProviderRegistryActivationService,
) -> dict[str, Any]:
    snapshot = snapshots.produce(
        registry(),
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )
    return activations.activate(
        snapshot["snapshot_id"],
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )


def configuration(*, remote: bool = True) -> dict[str, Any]:
    provider_id = "remote-synthetic" if remote else "local-synthetic"
    return {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": provider_id,
        "model_id": "synthetic-model-v1" if remote else "synthetic-local-q4",
        "secret_ref": (f"secretref://provider/{provider_id}/{uuid4()}" if remote else None),
        "privacy_classification": "remote_third_party" if remote else "local_device",
        "allowed_input_classifications": (
            ["public", "internal"] if remote else ["public", "confidential"]
        ),
        "budgets": {
            "max_input_tokens": 8_000,
            "max_output_tokens": 2_000,
            "max_requests": 10,
            "max_cost_microusd": 250_000 if remote else 0,
            "max_runtime_seconds": 120,
        },
        "remote_provider_opt_in": remote,
        "configured_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "execution_enabled": False,
    }


def secret_reference(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "secret_ref": document["secret_ref"],
        "configuration_id": document["configuration_id"],
        "provider_id": document["provider_id"],
        "purpose": "provider_authentication",
        "state": "active",
        "created_at": (NOW - timedelta(days=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=8)).isoformat(),
        "revoked_at": None,
        "resolution_enabled": False,
    }


def produce(
    service: ProviderConfigurationSnapshotService,
    activation_id: str,
    document: dict[str, Any],
    *,
    command_id: str | None = None,
    session_id: str | None = None,
    secret: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return service.produce(
        activation_id,
        document,
        secret_reference=secret,
        command_id=command_id or str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=session_id or str(uuid4()),
        now=NOW,
    )


def test_produces_inactive_snapshot_without_secret_or_authority(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    document = configuration()
    raw_reference = document["secret_ref"]
    receipt = produce(
        producer,
        activation["activation_id"],
        document,
        secret=secret_reference(document),
    )

    assert (
        contract_issues(receipt, "ai-provider-configuration-snapshot-receipt-v2.schema.json") == ()
    )
    assert receipt["state"] == "inactive"
    assert receipt["meter_binding_enabled"] is False
    assert receipt["authority"] == "none"
    assert receipt["execution_enabled"] is False

    with closing(sqlite3.connect(producer.database_path)) as connection:
        stored = "\n".join(
            value
            for row in connection.execute(
                """SELECT command_json,receipt_json FROM
                ai_provider_configuration_snapshot_productions_v1"""
            )
            for value in row
        )
        snapshot_json = connection.execute(
            "SELECT snapshot_json FROM ai_provider_configuration_snapshots_v1"
        ).fetchone()[0]
        assert raw_reference not in stored
        assert raw_reference not in snapshot_json
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 0
        outbox = json.loads(
            connection.execute(
                "SELECT payload_json FROM outbox ORDER BY rowid DESC LIMIT 1"
            ).fetchone()[0]
        )
        assert set(outbox) == {"event_hash", "occurred_at", "subject_id"}


def test_local_snapshot_requires_no_secret_metadata(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    receipt = produce(producer, activation["activation_id"], configuration(remote=False))
    assert receipt["provider_type"] == "local_runtime"
    assert receipt["secret_reference_digest"] is None


def test_replay_is_exact_and_same_session_only(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    document = configuration()
    secret = secret_reference(document)
    command_id = str(uuid4())
    session_id = str(uuid4())
    first = produce(
        producer,
        activation["activation_id"],
        document,
        command_id=command_id,
        session_id=session_id,
        secret=secret,
    )
    assert (
        produce(
            producer,
            activation["activation_id"],
            document,
            command_id=command_id,
            session_id=session_id,
            secret=secret,
        )
        == first
    )
    with pytest.raises(ProviderConfigurationSnapshotError) as changed:
        produce(
            producer,
            activation["activation_id"],
            document,
            command_id=command_id,
            secret=secret,
        )
    assert changed.value.code == "AI_PROVIDER_CONFIGURATION_IDENTITY_CONFLICT"


def test_invalid_lineage_configuration_secret_and_safety_deny(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    unknown = configuration()
    unknown["model_id"] = "unsupported-model"
    with pytest.raises(ProviderConfigurationSnapshotError) as model_error:
        produce(
            producer,
            activation["activation_id"],
            unknown,
            secret=secret_reference(unknown),
        )
    assert model_error.value.code == "AI_MODEL_UNKNOWN"

    document = configuration()
    revoked = secret_reference(document)
    revoked["state"] = "revoked"
    revoked["revoked_at"] = NOW.isoformat()
    with pytest.raises(ProviderConfigurationSnapshotError) as revoked_error:
        produce(producer, activation["activation_id"], document, secret=revoked)
    assert revoked_error.value.code == "AI_SECRET_REFERENCE_REVOKED"

    producer.authorization.set_global_safety(
        status="paused", reason="synthetic pause", actor_id="test-session"
    )
    with pytest.raises(ProviderConfigurationSnapshotError) as paused:
        produce(
            producer,
            activation["activation_id"],
            document,
            secret=secret_reference(document),
        )
    assert paused.value.code == "AI_PROVIDER_CONFIGURATION_SAFETY_PAUSED"


def test_competing_configuration_identity_has_one_winner(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    document = configuration()
    alternatives = [copy.deepcopy(document), copy.deepcopy(document)]
    alternatives[1]["budgets"]["max_requests"] = 9

    def attempt(candidate: dict[str, Any]) -> str:
        try:
            produce(
                producer,
                activation["activation_id"],
                candidate,
                secret=secret_reference(candidate),
            )
            return "ok"
        except ProviderConfigurationSnapshotError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, alternatives))
    assert results.count("ok") == 1
    assert results.count("AI_PROVIDER_CONFIGURATION_PRODUCTION_CONFLICT") == 1


def test_direct_storage_bypass_and_mutation_remain_denied(tmp_path: Path) -> None:
    snapshots, activations, producer = setup(tmp_path)
    activation = active_lineage(snapshots, activations)
    with closing(sqlite3.connect(producer.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="not current|binding is invalid"):
            connection.execute(
                """INSERT INTO ai_provider_configuration_snapshot_productions_v1(
                command_id,command_digest,snapshot_id,snapshot_digest,configuration_id,
                configuration_hash,activation_id,activation_receipt_digest,
                registry_snapshot_id,registry_snapshot_digest,
                registry_snapshot_receipt_digest,registry_id,registry_revision,
                registry_digest,providers_digest,provider_type,provider_id,model_id,
                secret_reference_digest,actor_id,session_id,command_json,receipt_json,
                receipt_digest,recorded_at,production_enabled,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'none',0)""",
                (
                    str(uuid4()),
                    "sha256:" + "1" * 64,
                    str(uuid4()),
                    "sha256:" + "2" * 64,
                    str(uuid4()),
                    "3" * 64,
                    activation["activation_id"],
                    "sha256:" + "4" * 64,
                    activation["snapshot_id"],
                    "sha256:" + "5" * 64,
                    "sha256:" + "6" * 64,
                    activation["registry_id"],
                    1,
                    "sha256:" + "7" * 64,
                    "sha256:" + "8" * 64,
                    "approved_remote",
                    "remote-synthetic",
                    "synthetic-model-v1",
                    "sha256:" + "9" * 64,
                    "test-session",
                    str(uuid4()),
                    "{}",
                    "{}",
                    "sha256:" + "a" * 64,
                    NOW.isoformat(),
                ),
            )

    document = configuration()
    receipt = produce(
        producer,
        activation["activation_id"],
        document,
        secret=secret_reference(document),
    )
    with closing(sqlite3.connect(producer.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """UPDATE ai_provider_configuration_snapshots_v1 SET state='inactive'
                WHERE snapshot_id=?""",
                (receipt["snapshot_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM ai_provider_configuration_snapshot_productions_v1 WHERE command_id=?",
                (receipt["command_id"],),
            )
