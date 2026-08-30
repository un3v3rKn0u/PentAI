from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_LIFETIME = timedelta(minutes=5)
_NAMESPACE = UUID("59831228-ec90-4186-ab3f-378913db703e")


class ProviderRegistryActivationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProviderRegistryActivationService:
    """Activate exact registry provenance without enabling provider behavior."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def activate(
        self,
        snapshot_id: str,
        *,
        command_id: str,
        requested_at: str,
        expires_at: str,
        authenticated_actor_id: str,
        authenticated_session_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        normalized_snapshot_id = _uuid(snapshot_id, "AI_PROVIDER_REGISTRY_ACTIVATION_INVALID")
        normalized_command_id = _uuid(command_id, "AI_PROVIDER_REGISTRY_ACTIVATION_INVALID")
        actor_id = _actor(authenticated_actor_id)
        session_id = _uuid(authenticated_session_id, "AI_PROVIDER_REGISTRY_SOURCE_INVALID")
        _validate_command_time(requested_at, expires_at, instant)
        try:
            self.authorization._require_storage_safe()
        except DomainError as error:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_STORAGE_UNSAFE",
                "storage safety denies registry activation",
            ) from error

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_safe(connection)
            lineage = self._lineage(connection, normalized_snapshot_id, instant)
            if parse_time(expires_at) > parse_time(lineage["snapshot_expires_at"]):
                raise ProviderRegistryActivationError(
                    "AI_PROVIDER_REGISTRY_ACTIVATION_STALE",
                    "activation command outlives the registry snapshot",
                )
            command = self._command(
                lineage,
                command_id=normalized_command_id,
                actor_id=actor_id,
                session_id=session_id,
                requested_at=requested_at,
                expires_at=expires_at,
            )
            command_digest = "sha256:" + content_hash(command)
            replay = connection.execute(
                """SELECT command_digest,receipt_json,receipt_digest,actor_id,session_id
                FROM ai_provider_registry_activations_v1 WHERE command_id=?""",
                (normalized_command_id,),
            ).fetchone()
            if replay is not None:
                return self._replay(
                    replay,
                    command_digest=command_digest,
                    actor_id=actor_id,
                    session_id=session_id,
                    instant=instant,
                )
            self._require_available(connection, instant)
            activation_id = str(
                uuid5(
                    _NAMESPACE,
                    f"activation:{lineage['snapshot_id']}:{lineage['snapshot_digest']}",
                )
            )
            activated_at = _timestamp(instant)
            receipt = {
                "schema_version": "1.0.0",
                "activation_id": activation_id,
                "command_id": normalized_command_id,
                "command_digest": command_digest,
                "snapshot_id": lineage["snapshot_id"],
                "snapshot_digest": lineage["snapshot_digest"],
                "snapshot_receipt_digest": lineage["snapshot_receipt_digest"],
                "registry_id": lineage["registry_id"],
                "registry_revision": lineage["registry_revision"],
                "registry_digest": lineage["registry_digest"],
                "providers_digest": lineage["providers_digest"],
                "requester": command["requester"],
                "authentication_context": "local_core_authenticated_session",
                "state": "active",
                "configuration_snapshot_enabled": False,
                "revocation_enabled": False,
                "activated_at": activated_at,
                "expires_at": lineage["snapshot_expires_at"],
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(receipt, "ai-provider-registry-activation-receipt-v1.schema.json"):
                raise ProviderRegistryActivationError(
                    "AI_PROVIDER_REGISTRY_ACTIVATION_INVALID",
                    "registry activation receipt is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO ai_provider_registry_activations_v1(
                    activation_id,receipt_digest,command_id,command_digest,snapshot_id,
                    snapshot_digest,snapshot_receipt_digest,registry_id,registry_revision,
                    registry_digest,providers_digest,actor_id,session_id,command_json,
                    receipt_json,activated_at,expires_at,state,configuration_snapshot_enabled,
                    revocation_enabled,authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',0,0,'none',0)""",
                    (
                        activation_id,
                        "sha256:" + content_hash(receipt),
                        normalized_command_id,
                        command_digest,
                        lineage["snapshot_id"],
                        lineage["snapshot_digest"],
                        lineage["snapshot_receipt_digest"],
                        lineage["registry_id"],
                        lineage["registry_revision"],
                        lineage["registry_digest"],
                        lineage["providers_digest"],
                        actor_id,
                        session_id,
                        canonical_json(command),
                        canonical_json(receipt),
                        activated_at,
                        lineage["snapshot_expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ProviderRegistryActivationError(
                    "AI_PROVIDER_REGISTRY_ACTIVATION_CONFLICT",
                    "registry activation conflicts with current durable state",
                ) from error
            audit = append_audit_event(
                connection,
                action="ai.provider_registry_activated",
                subject_type="ai_provider_registry_activation",
                subject_id=activation_id,
                actor_type="human",
                actor_id=actor_id,
                data=receipt,
                occurred_at=activated_at,
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'ai_provider_registry_activation',?,
                'ai.provider_registry_activated',?)""",
                (
                    str(uuid4()),
                    activation_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": activated_at,
                            "subject_id": activation_id,
                        }
                    ),
                ),
            )
        return receipt

    @staticmethod
    def _lineage(
        connection: sqlite3.Connection, snapshot_id: str, instant: datetime
    ) -> dict[str, Any]:
        row = connection.execute(
            """SELECT s.*,p.receipt_json AS production_receipt_json,
            p.receipt_digest AS snapshot_receipt_digest
            FROM ai_provider_registry_snapshots_v1 s
            JOIN ai_provider_registry_snapshot_productions_v1 p
              ON p.snapshot_id=s.snapshot_id
            WHERE s.snapshot_id=?""",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_SNAPSHOT_NOT_FOUND",
                "registry snapshot lineage is missing",
            )
        try:
            snapshot = cast(dict[str, Any], json.loads(row["snapshot_json"]))
            production = cast(dict[str, Any], json.loads(row["production_receipt_json"]))
            current = parse_time(snapshot["expires_at"]) > instant
            intact = (
                row["snapshot_digest"] == "sha256:" + content_hash(snapshot)
                and row["snapshot_receipt_digest"] == "sha256:" + content_hash(production)
                and production["snapshot_id"] == row["snapshot_id"]
                and production["snapshot_digest"] == row["snapshot_digest"]
                and production["registry_digest"] == row["registry_digest"]
                and production["providers_digest"] == row["providers_digest"]
                and not contract_issues(snapshot, "ai-provider-registry-snapshot-v1.schema.json")
                and not contract_issues(
                    production, "ai-provider-registry-snapshot-receipt-v2.schema.json"
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_LINEAGE_INVALID",
                "registry snapshot lineage is invalid",
            ) from error
        if not intact:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_LINEAGE_INVALID",
                "registry snapshot lineage is invalid",
            )
        if not current:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_SNAPSHOT_STALE",
                "registry snapshot is no longer current",
            )
        newer = connection.execute(
            """SELECT 1 FROM ai_provider_registry_snapshots_v1
            WHERE registry_id=? AND registry_revision>? LIMIT 1""",
            (row["registry_id"], row["registry_revision"]),
        ).fetchone()
        if newer is not None:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_SNAPSHOT_SUPERSEDED",
                "registry snapshot is not the latest revision",
            )
        return {
            "snapshot_id": row["snapshot_id"],
            "snapshot_digest": row["snapshot_digest"],
            "snapshot_receipt_digest": row["snapshot_receipt_digest"],
            "registry_id": row["registry_id"],
            "registry_revision": row["registry_revision"],
            "registry_digest": row["registry_digest"],
            "providers_digest": row["providers_digest"],
            "snapshot_expires_at": snapshot["expires_at"],
        }

    @staticmethod
    def _command(
        lineage: dict[str, Any],
        *,
        command_id: str,
        actor_id: str,
        session_id: str,
        requested_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        command = {
            "schema_version": "1.0.0",
            "command_id": command_id,
            "snapshot_id": lineage["snapshot_id"],
            "snapshot_digest": lineage["snapshot_digest"],
            "snapshot_receipt_digest": lineage["snapshot_receipt_digest"],
            "registry_id": lineage["registry_id"],
            "registry_revision": lineage["registry_revision"],
            "registry_digest": lineage["registry_digest"],
            "providers_digest": lineage["providers_digest"],
            "requester": {
                "actor_type": "human",
                "actor_id": actor_id,
                "session_id": session_id,
            },
            "authentication_context": "local_core_authenticated_session",
            "purpose": "activate_provider_registry_snapshot",
            "requested_at": _timestamp(parse_time(requested_at)),
            "expires_at": _timestamp(parse_time(expires_at)),
            "activation_enabled": False,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(command, "ai-provider-registry-activation-command-v1.schema.json"):
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_ACTIVATION_INVALID",
                "registry activation command is invalid",
            )
        return command

    @staticmethod
    def _require_available(connection: sqlite3.Connection, instant: datetime) -> None:
        active = connection.execute(
            """SELECT 1 FROM ai_provider_registry_activations_v1
            WHERE julianday(expires_at)>julianday(?) LIMIT 1""",
            (_timestamp(instant),),
        ).fetchone()
        if active is not None:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_ALREADY_ACTIVE",
                "a current provider registry activation already exists",
            )

    @staticmethod
    def _require_safe(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        if row is None or row["global_status"] != "active":
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_SAFETY_PAUSED",
                "global safety denies registry activation",
            )

    @staticmethod
    def _replay(
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
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_ACTIVATION_IDENTITY_CONFLICT",
                "changed activation replay is denied",
            )
        try:
            receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
            intact = (
                row["receipt_digest"] == "sha256:" + content_hash(receipt)
                and not contract_issues(
                    receipt, "ai-provider-registry-activation-receipt-v1.schema.json"
                )
                and parse_time(receipt["expires_at"]) > instant
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_ACTIVATION_REPLAY_FENCED",
                "activation replay integrity is invalid",
            ) from error
        if not intact:
            raise ProviderRegistryActivationError(
                "AI_PROVIDER_REGISTRY_ACTIVATION_REPLAY_FENCED",
                "activation replay is no longer current",
            )
        return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ProviderRegistryActivationError(
            "AI_PROVIDER_REGISTRY_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _validate_command_time(requested_at: str, expires_at: str, instant: datetime) -> None:
    try:
        requested = parse_time(requested_at)
        expires = parse_time(expires_at)
    except (TypeError, ValueError) as error:
        raise ProviderRegistryActivationError(
            "AI_PROVIDER_REGISTRY_ACTIVATION_INVALID",
            "activation command time is invalid",
        ) from error
    if (
        requested > instant
        or instant - requested > _MAX_COMMAND_AGE
        or expires <= instant
        or expires <= requested
        or expires - requested > _MAX_COMMAND_LIFETIME
    ):
        raise ProviderRegistryActivationError(
            "AI_PROVIDER_REGISTRY_ACTIVATION_STALE",
            "activation command validity is stale",
        )


def _actor(value: str) -> str:
    if value not in {"local-desktop-session", "test-session"}:
        raise ProviderRegistryActivationError(
            "AI_PROVIDER_REGISTRY_SOURCE_INVALID",
            "authenticated source is invalid",
        )
    return value


def _uuid(value: str, code: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ProviderRegistryActivationError(code, "identity is invalid") from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
