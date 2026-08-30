from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.ai_provider_registry_activation import (
    ProviderRegistryActivationError,
    ProviderRegistryActivationService,
)
from pentai_core.ai_provider_registry_snapshot import ProviderRegistrySnapshotService
from pentai_core.authorization import AuthorizationService
from pentai_core.migrate import migrate
from pentai_policy.document import contract_issues
from test_ai_provider_registry_snapshot import registry

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def setup(
    tmp_path: Path,
) -> tuple[ProviderRegistrySnapshotService, ProviderRegistryActivationService]:
    database = tmp_path / "registry-activation.db"
    migrate(database)
    authorization = AuthorizationService(database)
    return (
        ProviderRegistrySnapshotService(authorization),
        ProviderRegistryActivationService(authorization),
    )


def produce(
    snapshots: ProviderRegistrySnapshotService,
    *,
    registry_id: str | None = None,
    revision: int = 1,
) -> dict[str, object]:
    return snapshots.produce(
        registry(registry_id=registry_id, revision=revision),
        command_id=str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=str(uuid4()),
        now=NOW,
    )


def activate(
    activations: ProviderRegistryActivationService,
    snapshot_id: str,
    *,
    command_id: str | None = None,
    session_id: str | None = None,
    now: datetime = NOW,
) -> dict[str, object]:
    return activations.activate(
        snapshot_id,
        command_id=command_id or str(uuid4()),
        requested_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=session_id or str(uuid4()),
        now=now,
    )


def test_activates_exact_current_snapshot_without_downstream_authority(
    tmp_path: Path,
) -> None:
    snapshots, activations = setup(tmp_path)
    snapshot = produce(snapshots)
    receipt = activate(activations, str(snapshot["snapshot_id"]))
    assert contract_issues(receipt, "ai-provider-registry-activation-receipt-v1.schema.json") == ()
    assert receipt["state"] == "active"
    assert receipt["configuration_snapshot_enabled"] is False
    assert receipt["revocation_enabled"] is False
    assert receipt["authority"] == "none"
    assert receipt["execution_enabled"] is False

    with closing(sqlite3.connect(activations.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM ai_provider_registry_activations_v1").fetchone()
        assert row is not None
        assert row["snapshot_id"] == snapshot["snapshot_id"]
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 0
        outbox = [
            json.loads(value)
            for (value,) in connection.execute("SELECT payload_json FROM outbox ORDER BY rowid")
        ]
        assert len(outbox) == 2
        assert set(outbox[-1]) == {"event_hash", "occurred_at", "subject_id"}


def test_replay_requires_same_command_and_authenticated_session(tmp_path: Path) -> None:
    snapshots, activations = setup(tmp_path)
    snapshot = produce(snapshots)
    command_id = str(uuid4())
    session_id = str(uuid4())
    first = activate(
        activations,
        str(snapshot["snapshot_id"]),
        command_id=command_id,
        session_id=session_id,
    )
    assert (
        activate(
            activations,
            str(snapshot["snapshot_id"]),
            command_id=command_id,
            session_id=session_id,
        )
        == first
    )
    with pytest.raises(ProviderRegistryActivationError) as changed:
        activate(
            activations,
            str(snapshot["snapshot_id"]),
            command_id=command_id,
        )
    assert changed.value.code == "AI_PROVIDER_REGISTRY_ACTIVATION_IDENTITY_CONFLICT"


def test_latest_snapshot_safety_and_source_are_required(tmp_path: Path) -> None:
    snapshots, activations = setup(tmp_path)
    registry_id = str(uuid4())
    older = produce(snapshots, registry_id=registry_id, revision=1)
    latest = produce(snapshots, registry_id=registry_id, revision=2)
    with pytest.raises(ProviderRegistryActivationError) as superseded:
        activate(activations, str(older["snapshot_id"]))
    assert superseded.value.code == "AI_PROVIDER_REGISTRY_SNAPSHOT_SUPERSEDED"

    activations.authorization.set_global_safety(
        status="paused", reason="synthetic pause", actor_id="test-session"
    )
    with pytest.raises(ProviderRegistryActivationError) as paused:
        activate(activations, str(latest["snapshot_id"]))
    assert paused.value.code == "AI_PROVIDER_REGISTRY_SAFETY_PAUSED"

    activations.authorization.set_global_safety(
        status="active", reason="synthetic resume", actor_id="test-session"
    )
    with pytest.raises(ProviderRegistryActivationError) as source:
        activations.activate(
            str(latest["snapshot_id"]),
            command_id=str(uuid4()),
            requested_at=NOW.isoformat(),
            expires_at=(NOW + timedelta(minutes=5)).isoformat(),
            authenticated_actor_id="caller-selected",
            authenticated_session_id=str(uuid4()),
            now=NOW,
        )
    assert source.value.code == "AI_PROVIDER_REGISTRY_SOURCE_INVALID"


def test_competing_current_activations_have_one_winner(tmp_path: Path) -> None:
    snapshots, activations = setup(tmp_path)
    snapshot_ids = [str(produce(snapshots)["snapshot_id"]) for _ in range(2)]

    def attempt(snapshot_id: str) -> str:
        try:
            activate(activations, snapshot_id)
            return "ok"
        except ProviderRegistryActivationError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, snapshot_ids))
    assert results.count("ok") == 1
    assert results.count("AI_PROVIDER_REGISTRY_ALREADY_ACTIVE") == 1


def test_direct_storage_and_mutation_remain_denied(tmp_path: Path) -> None:
    snapshots, activations = setup(tmp_path)
    snapshot = produce(snapshots)
    with closing(sqlite3.connect(activations.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="not current"):
            connection.execute(
                """INSERT INTO ai_provider_registry_activations_v1(
                activation_id,receipt_digest,command_id,command_digest,snapshot_id,
                snapshot_digest,snapshot_receipt_digest,registry_id,registry_revision,
                registry_digest,providers_digest,actor_id,session_id,command_json,
                receipt_json,activated_at,expires_at,state,configuration_snapshot_enabled,
                revocation_enabled,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',0,0,'none',0)""",
                (
                    str(uuid4()),
                    "sha256:" + "1" * 64,
                    str(uuid4()),
                    "sha256:" + "2" * 64,
                    snapshot["snapshot_id"],
                    snapshot["snapshot_digest"],
                    "sha256:" + "3" * 64,
                    snapshot["registry_id"],
                    snapshot["registry_revision"],
                    snapshot["registry_digest"],
                    snapshot["providers_digest"],
                    "test-session",
                    str(uuid4()),
                    "{}",
                    "{}",
                    NOW.isoformat(),
                    (NOW + timedelta(days=1)).isoformat(),
                ),
            )

    receipt = activate(activations, str(snapshot["snapshot_id"]))
    with closing(sqlite3.connect(activations.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """UPDATE ai_provider_registry_activations_v1 SET state='active'
                WHERE activation_id=?""",
                (receipt["activation_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM ai_provider_registry_activations_v1 WHERE activation_id=?",
                (receipt["activation_id"],),
            )
