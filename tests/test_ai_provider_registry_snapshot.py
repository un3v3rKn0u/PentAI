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
from pentai_core.ai_provider_registry_snapshot import (
    ProviderRegistrySnapshotError,
    ProviderRegistrySnapshotService,
)
from pentai_core.authorization import AuthorizationService
from pentai_core.migrate import migrate
from pentai_policy import content_hash
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)


def registry(*, registry_id: str | None = None, revision: int = 1) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "registry_id": registry_id or str(uuid4()),
        "revision": revision,
        "providers": [
            {
                "provider_id": "remote-synthetic",
                "provider_type": "approved_remote",
                "models": ["synthetic-model-v1"],
                "allowed_input_classifications": ["public", "internal"],
                "state": "enabled",
            },
            {
                "provider_id": "local-synthetic",
                "provider_type": "local_runtime",
                "models": ["synthetic-local-q4"],
                "allowed_input_classifications": ["public", "confidential"],
                "state": "enabled",
            },
        ],
        "budget_ceilings": {
            "max_input_tokens": 16000,
            "max_output_tokens": 4000,
            "max_requests": 20,
            "max_cost_microusd": 500000,
            "max_runtime_seconds": 300,
        },
        "remote_providers_enabled": True,
        "configured_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=14)).isoformat(),
        "execution_enabled": False,
    }


def service(tmp_path: Path) -> ProviderRegistrySnapshotService:
    database = tmp_path / "registry-snapshot.db"
    migrate(database)
    return ProviderRegistrySnapshotService(AuthorizationService(database))


def produce(
    producer: ProviderRegistrySnapshotService,
    document: dict[str, Any],
    *,
    command_id: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    return producer.produce(
        document,
        command_id=command_id or str(uuid4()),
        requested_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        authenticated_actor_id="test-session",
        authenticated_session_id=session_id or str(uuid4()),
        now=NOW,
    )


def test_produces_one_inactive_authenticated_snapshot_without_authority(
    tmp_path: Path,
) -> None:
    producer = service(tmp_path)
    document = registry()
    document_copy = copy.deepcopy(document)
    receipt = produce(producer, document)

    assert contract_issues(
        receipt, "ai-provider-registry-snapshot-receipt-v2.schema.json"
    ) == ()
    assert receipt["state"] == "inactive"
    assert receipt["activation_enabled"] is False
    assert receipt["revocation_enabled"] is False
    assert receipt["authority"] == "none"
    assert receipt["execution_enabled"] is False
    assert document == document_copy

    with closing(sqlite3.connect(producer.database_path)) as connection:
        connection.row_factory = sqlite3.Row
        snapshot = connection.execute(
            "SELECT * FROM ai_provider_registry_snapshots_v1"
        ).fetchone()
        production = connection.execute(
            "SELECT * FROM ai_provider_registry_snapshot_productions_v1"
        ).fetchone()
        assert snapshot is not None and production is not None
        assert snapshot["snapshot_id"] == receipt["snapshot_id"]
        assert snapshot["snapshot_digest"] == receipt["snapshot_digest"]
        assert production["actor_id"] == "test-session"
        assert production["session_id"] == receipt["requester"]["session_id"]
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
        outbox = json.loads(
            connection.execute("SELECT payload_json FROM outbox").fetchone()[0]
        )
        assert set(outbox) == {"event_hash", "occurred_at", "subject_id"}


def test_byte_equivalent_replay_requires_same_authenticated_session(tmp_path: Path) -> None:
    producer = service(tmp_path)
    document = registry()
    command_id = str(uuid4())
    session_id = str(uuid4())
    first = produce(
        producer, document, command_id=command_id, session_id=session_id
    )
    assert (
        produce(producer, document, command_id=command_id, session_id=session_id)
        == first
    )

    changed = copy.deepcopy(document)
    changed["budget_ceilings"]["max_requests"] = 19
    with pytest.raises(ProviderRegistrySnapshotError) as conflict:
        produce(producer, changed, command_id=command_id, session_id=session_id)
    assert conflict.value.code == "AI_PROVIDER_REGISTRY_IDENTITY_CONFLICT"
    with pytest.raises(ProviderRegistrySnapshotError) as impersonated:
        produce(producer, document, command_id=command_id)
    assert impersonated.value.code == "AI_PROVIDER_REGISTRY_IDENTITY_CONFLICT"


def test_revision_history_is_monotonic_and_fork_free(tmp_path: Path) -> None:
    producer = service(tmp_path)
    registry_id = str(uuid4())
    produce(producer, registry(registry_id=registry_id, revision=2))
    for revision in (1, 2):
        with pytest.raises(ProviderRegistrySnapshotError) as rollback:
            produce(producer, registry(registry_id=registry_id, revision=revision))
        assert rollback.value.code == "AI_PROVIDER_REGISTRY_REVISION_ROLLBACK"
    third = produce(producer, registry(registry_id=registry_id, revision=3))
    assert third["registry_revision"] == 3


def test_concurrent_competing_revision_has_one_winner(tmp_path: Path) -> None:
    producer = service(tmp_path)
    registry_id = str(uuid4())
    documents = [registry(registry_id=registry_id, revision=1) for _ in range(2)]
    documents[1]["budget_ceilings"]["max_requests"] = 19

    def attempt(document: dict[str, Any]) -> str:
        try:
            produce(producer, document)
            return "ok"
        except ProviderRegistrySnapshotError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, documents))
    assert results.count("ok") == 1
    assert results.count("AI_PROVIDER_REGISTRY_REVISION_ROLLBACK") == 1


def test_stale_privacy_unsafe_and_paused_production_deny(tmp_path: Path) -> None:
    producer = service(tmp_path)
    stale = registry()
    stale["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    with pytest.raises(ProviderRegistrySnapshotError) as stale_error:
        produce(producer, stale)
    assert stale_error.value.code == "AI_PROVIDER_REGISTRY_STALE"

    unsafe = registry()
    unsafe["providers"][0]["allowed_input_classifications"] = ["secret"]
    with pytest.raises(ProviderRegistrySnapshotError) as unsafe_error:
        produce(producer, unsafe)
    assert unsafe_error.value.code == "AI_PROVIDER_REGISTRY_PRIVACY_DENIED"

    producer.authorization.set_global_safety(
        status="paused", reason="synthetic safety pause", actor_id="test-session"
    )
    with pytest.raises(ProviderRegistrySnapshotError) as paused:
        produce(producer, registry())
    assert paused.value.code == "AI_PROVIDER_REGISTRY_SAFETY_PAUSED"


def test_source_command_and_replay_integrity_default_deny(tmp_path: Path) -> None:
    producer = service(tmp_path)
    document = registry()
    command_id = str(uuid4())
    session_id = str(uuid4())
    receipt = produce(
        producer, document, command_id=command_id, session_id=session_id
    )
    with pytest.raises(ProviderRegistrySnapshotError) as source:
        producer.produce(
            document,
            command_id=str(uuid4()),
            requested_at=NOW.isoformat(),
            expires_at=(NOW + timedelta(minutes=5)).isoformat(),
            authenticated_actor_id="caller-selected",
            authenticated_session_id=session_id,
            now=NOW,
        )
    assert source.value.code == "AI_PROVIDER_REGISTRY_SOURCE_INVALID"

    with closing(sqlite3.connect(producer.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """UPDATE ai_provider_registry_snapshot_productions_v1
                SET receipt_digest=? WHERE command_id=?""",
                ("sha256:" + "0" * 64, command_id),
            )
    # Immutable storage prevents the tamper before replay can observe it.
    with closing(sqlite3.connect(producer.database_path)) as connection:
        stored = connection.execute(
            """SELECT receipt_digest FROM ai_provider_registry_snapshot_productions_v1
            WHERE command_id=?""",
            (command_id,),
        ).fetchone()[0]
    assert stored == "sha256:" + content_hash(receipt)
    assert (
        produce(producer, document, command_id=command_id, session_id=session_id)
        == receipt
    )


def test_direct_storage_cannot_create_or_mutate_snapshot(tmp_path: Path) -> None:
    producer = service(tmp_path)
    with closing(sqlite3.connect(producer.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="authenticated.*required"):
            connection.execute(
                """INSERT INTO ai_provider_registry_snapshots_v1(
                snapshot_id,registry_id,registry_revision,registry_digest,
                providers_digest,snapshot_json,snapshot_digest,recorded_at,state,
                activation_enabled,revocation_enabled,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,'inactive',0,0,'none',0)""",
                (
                    str(uuid4()),
                    str(uuid4()),
                    1,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                    "{}",
                    "sha256:" + "3" * 64,
                    NOW.isoformat(),
                ),
            )

    receipt = produce(producer, registry())
    with closing(sqlite3.connect(producer.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE ai_provider_registry_snapshots_v1 SET state='inactive' WHERE snapshot_id=?",
                (receipt["snapshot_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM ai_provider_registry_snapshots_v1 WHERE snapshot_id=?",
                (receipt["snapshot_id"],),
            )
