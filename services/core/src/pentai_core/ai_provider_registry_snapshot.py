from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_registry import (
    ProviderRegistryError,
    derive_provider_registry_digests,
)
from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_LIFETIME = timedelta(minutes=5)
_NAMESPACE = UUID("8f29d9a8-c949-44d8-ae79-f10b7d7d9c18")


class ProviderRegistrySnapshotError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProviderRegistrySnapshotService:
    """Record authenticated inactive provider provenance without activating it."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def produce(
        self,
        registry: dict[str, Any],
        *,
        command_id: str,
        requested_at: str,
        expires_at: str,
        authenticated_actor_id: str,
        authenticated_session_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        actor_id = _actor(authenticated_actor_id)
        session_id = _uuid(authenticated_session_id, "AI_PROVIDER_REGISTRY_SOURCE_INVALID")
        normalized_command_id = _uuid(
            command_id, "AI_PROVIDER_REGISTRY_COMMAND_INVALID"
        )
        _validate_command_time(requested_at, expires_at, instant)
        try:
            digests = derive_provider_registry_digests(registry, now=instant)
        except ProviderRegistryError as error:
            raise ProviderRegistrySnapshotError(error.code, str(error)) from error
        normalized_registry = cast(
            dict[str, Any], json.loads(digests.normalized_registry_json)
        )
        registry_id = normalized_registry["registry_id"]
        registry_revision = normalized_registry["revision"]
        snapshot_id = str(
            uuid5(
                _NAMESPACE,
                f"snapshot:{registry_id}:{registry_revision}:{digests.registry_digest}",
            )
        )
        command = {
            "schema_version": "1.0.0",
            "command_id": normalized_command_id,
            "snapshot_id": snapshot_id,
            "registry_id": registry_id,
            "registry_revision": registry_revision,
            "registry_digest": digests.registry_digest,
            "providers_digest": digests.providers_digest,
            "requester": {
                "actor_type": "human",
                "actor_id": actor_id,
                "session_id": session_id,
            },
            "authentication_context": "local_core_authenticated_session",
            "purpose": "record_provider_registry_snapshot",
            "requested_at": _timestamp(parse_time(requested_at)),
            "expires_at": _timestamp(parse_time(expires_at)),
            "production_enabled": False,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(command, "ai-provider-registry-snapshot-command-v1.schema.json"):
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_COMMAND_INVALID", "snapshot command is invalid"
            )
        command_digest = "sha256:" + content_hash(command)
        try:
            self.authorization._require_storage_safe()
        except DomainError as error:
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_STORAGE_UNSAFE",
                "storage safety denies snapshot production",
            ) from error
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_safe(connection)
            replay = connection.execute(
                """SELECT command_digest,receipt_json,receipt_digest,actor_id,session_id
                FROM ai_provider_registry_snapshot_productions_v1 WHERE command_id=?""",
                (normalized_command_id,),
            ).fetchone()
            if replay is not None:
                return self._replay(
                    connection,
                    replay,
                    command_digest=command_digest,
                    actor_id=actor_id,
                    session_id=session_id,
                    instant=instant,
                )
            self._require_monotonic(
                connection,
                registry_id=registry_id,
                registry_revision=registry_revision,
            )
            recorded_at = _timestamp(instant)
            snapshot = {
                "schema_version": "1.0.0",
                "snapshot_id": snapshot_id,
                "registry_id": registry_id,
                "registry_revision": registry_revision,
                "registry_digest": digests.registry_digest,
                "providers": normalized_registry["providers"],
                "providers_digest": digests.providers_digest,
                "budget_ceilings": normalized_registry["budget_ceilings"],
                "remote_providers_enabled": normalized_registry[
                    "remote_providers_enabled"
                ],
                "configured_at": normalized_registry["configured_at"],
                "expires_at": normalized_registry["expires_at"],
                "snapshotted_at": recorded_at,
                "state": "inactive",
                "activation_enabled": False,
                "revocation_enabled": False,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(snapshot, "ai-provider-registry-snapshot-v1.schema.json"):
                raise ProviderRegistrySnapshotError(
                    "AI_PROVIDER_REGISTRY_SNAPSHOT_INVALID", "snapshot result is invalid"
                )
            snapshot_digest = "sha256:" + content_hash(snapshot)
            receipt = {
                "schema_version": "2.0.0",
                "snapshot_id": snapshot_id,
                "snapshot_digest": snapshot_digest,
                "command_id": normalized_command_id,
                "command_digest": command_digest,
                "registry_id": registry_id,
                "registry_revision": registry_revision,
                "registry_digest": digests.registry_digest,
                "providers_digest": digests.providers_digest,
                "requester": command["requester"],
                "authentication_context": "local_core_authenticated_session",
                "state": "inactive",
                "activation_enabled": False,
                "revocation_enabled": False,
                "production_enabled": False,
                "recorded_at": recorded_at,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(
                receipt, "ai-provider-registry-snapshot-receipt-v2.schema.json"
            ):
                raise ProviderRegistrySnapshotError(
                    "AI_PROVIDER_REGISTRY_RECEIPT_INVALID", "snapshot receipt is invalid"
                )
            try:
                connection.execute("PRAGMA defer_foreign_keys = ON")
                connection.execute(
                    """INSERT INTO ai_provider_registry_snapshot_productions_v1(
                    command_id,command_digest,snapshot_id,registry_id,registry_revision,
                    registry_digest,providers_digest,actor_id,session_id,command_json,
                    receipt_json,receipt_digest,recorded_at,production_enabled,authority,
                    execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,'none',0)""",
                    (
                        normalized_command_id,
                        command_digest,
                        snapshot_id,
                        registry_id,
                        registry_revision,
                        digests.registry_digest,
                        digests.providers_digest,
                        actor_id,
                        session_id,
                        canonical_json(command),
                        canonical_json(receipt),
                        "sha256:" + content_hash(receipt),
                        recorded_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO ai_provider_registry_snapshots_v1(
                    snapshot_id,registry_id,registry_revision,registry_digest,
                    providers_digest,snapshot_json,snapshot_digest,recorded_at,state,
                    activation_enabled,revocation_enabled,authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,'inactive',0,0,'none',0)""",
                    (
                        snapshot_id,
                        registry_id,
                        registry_revision,
                        digests.registry_digest,
                        digests.providers_digest,
                        canonical_json(snapshot),
                        snapshot_digest,
                        recorded_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ProviderRegistrySnapshotError(
                    "AI_PROVIDER_REGISTRY_PRODUCTION_CONFLICT",
                    "snapshot production conflicts with durable history",
                ) from error
            audit = append_audit_event(
                connection,
                action="ai.provider_registry_snapshot_recorded",
                subject_type="ai_provider_registry_snapshot",
                subject_id=snapshot_id,
                actor_type="human",
                actor_id=actor_id,
                data=receipt,
                occurred_at=recorded_at,
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'ai_provider_registry_snapshot',?,
                'ai.provider_registry_snapshot_recorded',?)""",
                (
                    str(uuid4()),
                    snapshot_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": recorded_at,
                            "subject_id": snapshot_id,
                        }
                    ),
                ),
            )
        return receipt

    @staticmethod
    def _require_safe(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        if row is None or row["global_status"] != "active":
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_SAFETY_PAUSED", "global safety denies production"
            )

    @staticmethod
    def _require_monotonic(
        connection: sqlite3.Connection, *, registry_id: str, registry_revision: int
    ) -> None:
        row = connection.execute(
            """SELECT MAX(registry_revision) AS latest_revision
            FROM ai_provider_registry_snapshots_v1 WHERE registry_id=?""",
            (registry_id,),
        ).fetchone()
        latest = row["latest_revision"] if row is not None else None
        if latest is not None and registry_revision <= latest:
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_REVISION_ROLLBACK",
                "registry revision does not advance durable history",
            )

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        command_digest: str,
        actor_id: str,
        session_id: str,
        instant: datetime,
    ) -> dict[str, Any]:
        if (
            row["command_digest"] != command_digest
            or row["actor_id"] != actor_id
            or row["session_id"] != session_id
        ):
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_IDENTITY_CONFLICT", "changed replay is denied"
            )
        try:
            receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        except (json.JSONDecodeError, TypeError) as error:
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_REPLAY_FENCED", "replay integrity is invalid"
            ) from error
        snapshot = connection.execute(
            """SELECT snapshot_json,snapshot_digest FROM ai_provider_registry_snapshots_v1
            WHERE snapshot_id=?""",
            (receipt.get("snapshot_id"),),
        ).fetchone()
        if (
            row["receipt_digest"] != "sha256:" + content_hash(receipt)
            or contract_issues(
                receipt, "ai-provider-registry-snapshot-receipt-v2.schema.json"
            )
            or snapshot is None
        ):
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_REPLAY_FENCED", "replay integrity is invalid"
            )
        try:
            snapshot_document = cast(
                dict[str, Any], json.loads(snapshot["snapshot_json"])
            )
            snapshot_current = parse_time(snapshot_document["expires_at"]) > instant
            snapshot_integrity = (
                snapshot["snapshot_digest"]
                == "sha256:" + content_hash(snapshot_document)
                and snapshot["snapshot_digest"] == receipt["snapshot_digest"]
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_REPLAY_FENCED", "replay integrity is invalid"
            ) from error
        if not snapshot_integrity or not snapshot_current:
            raise ProviderRegistrySnapshotError(
                "AI_PROVIDER_REGISTRY_REPLAY_FENCED", "replay is no longer current"
            )
        return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ProviderRegistrySnapshotError(
            "AI_PROVIDER_REGISTRY_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _validate_command_time(requested_at: str, expires_at: str, instant: datetime) -> None:
    try:
        requested = parse_time(requested_at)
        expires = parse_time(expires_at)
    except (TypeError, ValueError) as error:
        raise ProviderRegistrySnapshotError(
            "AI_PROVIDER_REGISTRY_COMMAND_INVALID", "command time is invalid"
        ) from error
    if (
        requested > instant
        or instant - requested > _MAX_COMMAND_AGE
        or expires <= instant
        or expires <= requested
        or expires - requested > _MAX_COMMAND_LIFETIME
    ):
        raise ProviderRegistrySnapshotError(
            "AI_PROVIDER_REGISTRY_COMMAND_STALE", "command validity is stale"
        )


def _actor(value: str) -> str:
    if value not in {"local-desktop-session", "test-session"}:
        raise ProviderRegistrySnapshotError(
            "AI_PROVIDER_REGISTRY_SOURCE_INVALID", "authenticated source is invalid"
        )
    return value


def _uuid(value: str, code: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ProviderRegistrySnapshotError(code, "identity is invalid") from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
