from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_config import (
    ProviderConfigurationError,
    ProviderPolicy,
    validate_provider_configuration,
)
from pentai_core.ai_provider_registry import ProviderRegistryError, build_provider_policy
from pentai_core.ai_secret_reference import SecretReferenceError, validate_secret_reference
from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_LIFETIME = timedelta(minutes=5)
_NAMESPACE = UUID("4f18b160-798c-44bd-907c-fe544d2fd76b")


class ProviderConfigurationSnapshotError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProviderConfigurationSnapshotService:
    """Persist inactive configuration provenance without enabling provider behavior."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def produce(
        self,
        activation_id: str,
        configuration: dict[str, Any],
        *,
        secret_reference: dict[str, Any] | None,
        command_id: str,
        requested_at: str,
        expires_at: str,
        authenticated_actor_id: str,
        authenticated_session_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        normalized_activation_id = _uuid(
            activation_id, "AI_PROVIDER_CONFIGURATION_ACTIVATION_INVALID"
        )
        normalized_command_id = _uuid(command_id, "AI_PROVIDER_CONFIGURATION_COMMAND_INVALID")
        actor_id = _actor(authenticated_actor_id)
        session_id = _uuid(authenticated_session_id, "AI_PROVIDER_CONFIGURATION_SOURCE_INVALID")
        _validate_command_time(requested_at, expires_at, instant)
        configuration_document = _copy_document(
            configuration, "AI_PROVIDER_CONFIGURATION_MALFORMED"
        )
        secret_document = (
            None
            if secret_reference is None
            else _copy_document(secret_reference, "AI_SECRET_REFERENCE_MALFORMED")
        )
        try:
            self.authorization._require_storage_safe()
        except DomainError as error:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_STORAGE_UNSAFE",
                "storage safety denies configuration snapshot production",
            ) from error

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_safe(connection)
            lineage = self._lineage(connection, normalized_activation_id, instant)
            policy = self._policy(lineage, instant)
            try:
                validate_provider_configuration(configuration_document, policy=policy, now=instant)
            except ProviderConfigurationError as error:
                raise ProviderConfigurationSnapshotError(error.code, str(error)) from error
            secret_digest = self._secret_digest(
                configuration_document,
                secret_document,
                policy=policy,
                instant=instant,
            )
            if parse_time(expires_at) > parse_time(
                configuration_document["expires_at"]
            ) or parse_time(expires_at) > parse_time(lineage["activation_expires_at"]):
                raise ProviderConfigurationSnapshotError(
                    "AI_PROVIDER_CONFIGURATION_COMMAND_STALE",
                    "configuration command outlives its trusted lineage",
                )
            configuration_hash = content_hash(configuration_document)
            snapshot_id = str(
                uuid5(
                    _NAMESPACE,
                    "configuration-snapshot:"
                    f"{lineage['activation_id']}:{configuration_document['configuration_id']}:"
                    f"{configuration_hash}",
                )
            )
            command = self._command(
                lineage,
                configuration_document,
                command_id=normalized_command_id,
                snapshot_id=snapshot_id,
                configuration_hash=configuration_hash,
                secret_reference_digest=secret_digest,
                actor_id=actor_id,
                session_id=session_id,
                requested_at=requested_at,
                expires_at=expires_at,
            )
            command_digest = "sha256:" + content_hash(command)
            replay = connection.execute(
                """SELECT command_digest,receipt_json,receipt_digest,actor_id,session_id
                FROM ai_provider_configuration_snapshot_productions_v1
                WHERE command_id=?""",
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

            recorded_at = _timestamp(instant)
            snapshot = {
                "schema_version": "1.0.0",
                "snapshot_id": snapshot_id,
                "configuration_id": configuration_document["configuration_id"],
                "configuration_hash": configuration_hash,
                "registry_id": lineage["registry_id"],
                "registry_revision": lineage["registry_revision"],
                "provider_type": configuration_document["provider_type"],
                "provider_id": configuration_document["provider_id"],
                "model_id": configuration_document["model_id"],
                "privacy_classification": configuration_document["privacy_classification"],
                "allowed_input_classifications": configuration_document[
                    "allowed_input_classifications"
                ],
                "budgets": configuration_document["budgets"],
                "remote_provider_opt_in": configuration_document["remote_provider_opt_in"],
                "secret_reference_state": (
                    "present_digest_only" if secret_digest is not None else "absent"
                ),
                "secret_reference_digest": secret_digest,
                "configured_at": configuration_document["configured_at"],
                "expires_at": configuration_document["expires_at"],
                "snapshotted_at": recorded_at,
                "state": "inactive",
                "meter_binding_enabled": False,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(snapshot, "ai-provider-configuration-snapshot-v1.schema.json"):
                raise ProviderConfigurationSnapshotError(
                    "AI_PROVIDER_CONFIGURATION_SNAPSHOT_INVALID",
                    "configuration snapshot result is invalid",
                )
            snapshot_digest = "sha256:" + content_hash(snapshot)
            receipt = self._receipt(
                command,
                snapshot_digest=snapshot_digest,
                command_digest=command_digest,
                recorded_at=recorded_at,
            )
            try:
                connection.execute("PRAGMA defer_foreign_keys = ON")
                self._insert_production(
                    connection,
                    command,
                    receipt,
                    snapshot_digest=snapshot_digest,
                    command_digest=command_digest,
                    recorded_at=recorded_at,
                )
                connection.execute(
                    """INSERT INTO ai_provider_configuration_snapshots_v1(
                    snapshot_id,configuration_id,configuration_hash,registry_id,
                    registry_revision,provider_type,provider_id,model_id,snapshot_json,
                    snapshot_digest,recorded_at,state,meter_binding_enabled,authority,
                    execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,'inactive',0,'none',0)""",
                    (
                        snapshot_id,
                        configuration_document["configuration_id"],
                        configuration_hash,
                        lineage["registry_id"],
                        lineage["registry_revision"],
                        configuration_document["provider_type"],
                        configuration_document["provider_id"],
                        configuration_document["model_id"],
                        canonical_json(snapshot),
                        snapshot_digest,
                        recorded_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ProviderConfigurationSnapshotError(
                    "AI_PROVIDER_CONFIGURATION_PRODUCTION_CONFLICT",
                    "configuration snapshot production conflicts with durable history",
                ) from error
            audit = append_audit_event(
                connection,
                action="ai.provider_configuration_snapshot_recorded",
                subject_type="ai_provider_configuration_snapshot",
                subject_id=snapshot_id,
                actor_type="human",
                actor_id=actor_id,
                data=receipt,
                occurred_at=recorded_at,
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'ai_provider_configuration_snapshot',?,
                'ai.provider_configuration_snapshot_recorded',?)""",
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
    def _lineage(
        connection: sqlite3.Connection, activation_id: str, instant: datetime
    ) -> dict[str, Any]:
        row = connection.execute(
            """SELECT a.*,s.snapshot_json AS registry_snapshot_json,
            s.snapshot_digest AS registry_snapshot_digest,
            p.receipt_json AS registry_production_receipt_json,
            p.receipt_digest AS registry_snapshot_receipt_digest
            FROM ai_provider_registry_activations_v1 a
            JOIN ai_provider_registry_snapshots_v1 s ON s.snapshot_id=a.snapshot_id
            JOIN ai_provider_registry_snapshot_productions_v1 p
              ON p.snapshot_id=s.snapshot_id
            WHERE a.activation_id=?""",
            (activation_id,),
        ).fetchone()
        if row is None:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_ACTIVATION_NOT_FOUND",
                "registry activation lineage is missing",
            )
        try:
            activation = cast(dict[str, Any], json.loads(row["receipt_json"]))
            snapshot = cast(dict[str, Any], json.loads(row["registry_snapshot_json"]))
            production = cast(dict[str, Any], json.loads(row["registry_production_receipt_json"]))
            intact = (
                row["receipt_digest"] == "sha256:" + content_hash(activation)
                and row["registry_snapshot_digest"] == "sha256:" + content_hash(snapshot)
                and row["registry_snapshot_receipt_digest"] == "sha256:" + content_hash(production)
                and not contract_issues(
                    activation, "ai-provider-registry-activation-receipt-v1.schema.json"
                )
                and not contract_issues(snapshot, "ai-provider-registry-snapshot-v1.schema.json")
                and not contract_issues(
                    production, "ai-provider-registry-snapshot-receipt-v2.schema.json"
                )
                and activation["activation_id"] == row["activation_id"]
                and activation["snapshot_id"] == row["snapshot_id"]
                and activation["snapshot_digest"] == row["registry_snapshot_digest"]
                and activation["snapshot_receipt_digest"] == row["registry_snapshot_receipt_digest"]
                and activation["configuration_snapshot_enabled"] is False
                and activation["state"] == "active"
                and production["snapshot_id"] == row["snapshot_id"]
                and production["snapshot_digest"] == row["registry_snapshot_digest"]
                and snapshot["registry_digest"] == row["registry_digest"]
                and snapshot["providers_digest"] == row["providers_digest"]
                and parse_time(activation["expires_at"]) > instant
                and parse_time(snapshot["expires_at"]) > instant
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_LINEAGE_INVALID",
                "registry activation lineage is invalid",
            ) from error
        if not intact:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_LINEAGE_INVALID",
                "registry activation lineage is invalid",
            )
        return {
            "activation_id": row["activation_id"],
            "activation_receipt_digest": row["receipt_digest"],
            "activation_expires_at": activation["expires_at"],
            "registry_snapshot_id": row["snapshot_id"],
            "registry_snapshot_digest": row["registry_snapshot_digest"],
            "registry_snapshot_receipt_digest": row["registry_snapshot_receipt_digest"],
            "registry_id": row["registry_id"],
            "registry_revision": row["registry_revision"],
            "registry_digest": row["registry_digest"],
            "providers_digest": row["providers_digest"],
            "registry_snapshot": snapshot,
        }

    @staticmethod
    def _policy(lineage: dict[str, Any], instant: datetime) -> ProviderPolicy:
        snapshot = lineage["registry_snapshot"]
        registry = {
            "schema_version": "1.0.0",
            "registry_id": snapshot["registry_id"],
            "revision": snapshot["registry_revision"],
            "providers": snapshot["providers"],
            "budget_ceilings": snapshot["budget_ceilings"],
            "remote_providers_enabled": snapshot["remote_providers_enabled"],
            "configured_at": snapshot["configured_at"],
            "expires_at": snapshot["expires_at"],
            "execution_enabled": False,
        }
        try:
            return build_provider_policy(registry, now=instant)
        except ProviderRegistryError as error:
            raise ProviderConfigurationSnapshotError(error.code, str(error)) from error

    @staticmethod
    def _secret_digest(
        configuration: dict[str, Any],
        secret_reference: dict[str, Any] | None,
        *,
        policy: ProviderPolicy,
        instant: datetime,
    ) -> str | None:
        if configuration["provider_type"] == "local_runtime":
            if secret_reference is not None or configuration["secret_ref"] is not None:
                raise ProviderConfigurationSnapshotError(
                    "AI_SECRET_REFERENCE_UNSUPPORTED",
                    "local runtime configuration cannot carry secret metadata",
                )
            return None
        if secret_reference is None:
            raise ProviderConfigurationSnapshotError(
                "AI_SECRET_REFERENCE_REQUIRED",
                "remote provider configuration requires exact secret metadata",
            )
        try:
            validate_secret_reference(
                secret_reference,
                configuration=configuration,
                policy=policy,
                now=instant,
            )
        except SecretReferenceError as error:
            raise ProviderConfigurationSnapshotError(error.code, str(error)) from error
        return "sha256:" + content_hash(configuration["secret_ref"])

    @staticmethod
    def _command(
        lineage: dict[str, Any],
        configuration: dict[str, Any],
        *,
        command_id: str,
        snapshot_id: str,
        configuration_hash: str,
        secret_reference_digest: str | None,
        actor_id: str,
        session_id: str,
        requested_at: str,
        expires_at: str,
    ) -> dict[str, Any]:
        command = {
            "schema_version": "1.0.0",
            "command_id": command_id,
            "snapshot_id": snapshot_id,
            "configuration_id": configuration["configuration_id"],
            "configuration_hash": configuration_hash,
            "activation_id": lineage["activation_id"],
            "activation_receipt_digest": lineage["activation_receipt_digest"],
            "registry_snapshot_id": lineage["registry_snapshot_id"],
            "registry_snapshot_digest": lineage["registry_snapshot_digest"],
            "registry_snapshot_receipt_digest": lineage["registry_snapshot_receipt_digest"],
            "registry_id": lineage["registry_id"],
            "registry_revision": lineage["registry_revision"],
            "registry_digest": lineage["registry_digest"],
            "providers_digest": lineage["providers_digest"],
            "provider_type": configuration["provider_type"],
            "provider_id": configuration["provider_id"],
            "model_id": configuration["model_id"],
            "secret_reference_digest": secret_reference_digest,
            "requester": {
                "actor_type": "human",
                "actor_id": actor_id,
                "session_id": session_id,
            },
            "authentication_context": "local_core_authenticated_session",
            "purpose": "record_provider_configuration_snapshot",
            "requested_at": _timestamp(parse_time(requested_at)),
            "expires_at": _timestamp(parse_time(expires_at)),
            "production_enabled": False,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(command, "ai-provider-configuration-snapshot-command-v1.schema.json"):
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_COMMAND_INVALID",
                "configuration snapshot command is invalid",
            )
        return command

    @staticmethod
    def _receipt(
        command: dict[str, Any],
        *,
        snapshot_digest: str,
        command_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        receipt = {
            **{
                key: command[key]
                for key in (
                    "snapshot_id",
                    "configuration_id",
                    "configuration_hash",
                    "activation_id",
                    "activation_receipt_digest",
                    "registry_snapshot_id",
                    "registry_snapshot_digest",
                    "registry_snapshot_receipt_digest",
                    "registry_id",
                    "registry_revision",
                    "registry_digest",
                    "providers_digest",
                    "provider_type",
                    "provider_id",
                    "model_id",
                    "secret_reference_digest",
                    "requester",
                    "authentication_context",
                )
            },
            "schema_version": "2.0.0",
            "snapshot_digest": snapshot_digest,
            "command_id": command["command_id"],
            "command_digest": command_digest,
            "state": "inactive",
            "meter_binding_enabled": False,
            "production_enabled": False,
            "recorded_at": recorded_at,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(receipt, "ai-provider-configuration-snapshot-receipt-v2.schema.json"):
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_RECEIPT_INVALID",
                "configuration snapshot receipt is invalid",
            )
        return receipt

    @staticmethod
    def _insert_production(
        connection: sqlite3.Connection,
        command: dict[str, Any],
        receipt: dict[str, Any],
        *,
        snapshot_digest: str,
        command_digest: str,
        recorded_at: str,
    ) -> None:
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
                command["command_id"],
                command_digest,
                command["snapshot_id"],
                snapshot_digest,
                command["configuration_id"],
                command["configuration_hash"],
                command["activation_id"],
                command["activation_receipt_digest"],
                command["registry_snapshot_id"],
                command["registry_snapshot_digest"],
                command["registry_snapshot_receipt_digest"],
                command["registry_id"],
                command["registry_revision"],
                command["registry_digest"],
                command["providers_digest"],
                command["provider_type"],
                command["provider_id"],
                command["model_id"],
                command["secret_reference_digest"],
                command["requester"]["actor_id"],
                command["requester"]["session_id"],
                canonical_json(command),
                canonical_json(receipt),
                "sha256:" + content_hash(receipt),
                recorded_at,
            ),
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
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_IDENTITY_CONFLICT",
                "changed configuration snapshot replay is denied",
            )
        try:
            receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
            snapshot_row = connection.execute(
                """SELECT snapshot_json,snapshot_digest
                FROM ai_provider_configuration_snapshots_v1 WHERE snapshot_id=?""",
                (receipt["snapshot_id"],),
            ).fetchone()
            if snapshot_row is None:
                raise ValueError("snapshot missing")
            snapshot = cast(dict[str, Any], json.loads(snapshot_row["snapshot_json"]))
            intact = (
                row["receipt_digest"] == "sha256:" + content_hash(receipt)
                and snapshot_row["snapshot_digest"] == "sha256:" + content_hash(snapshot)
                and receipt["snapshot_digest"] == snapshot_row["snapshot_digest"]
                and not contract_issues(
                    receipt,
                    "ai-provider-configuration-snapshot-receipt-v2.schema.json",
                )
                and not contract_issues(
                    snapshot, "ai-provider-configuration-snapshot-v1.schema.json"
                )
                and parse_time(snapshot["expires_at"]) > instant
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_REPLAY_FENCED",
                "configuration snapshot replay integrity is invalid",
            ) from error
        if not intact:
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_REPLAY_FENCED",
                "configuration snapshot replay is no longer current",
            )
        return receipt

    @staticmethod
    def _require_safe(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        if row is None or row["global_status"] != "active":
            raise ProviderConfigurationSnapshotError(
                "AI_PROVIDER_CONFIGURATION_SAFETY_PAUSED",
                "global safety denies configuration snapshot production",
            )


def _copy_document(document: dict[str, Any], code: str) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], json.loads(canonical_json(document)))
    except (TypeError, ValueError) as error:
        raise ProviderConfigurationSnapshotError(code, "document is malformed") from error


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ProviderConfigurationSnapshotError(
            "AI_PROVIDER_CONFIGURATION_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _validate_command_time(requested_at: str, expires_at: str, instant: datetime) -> None:
    try:
        requested = parse_time(requested_at)
        expires = parse_time(expires_at)
    except (TypeError, ValueError) as error:
        raise ProviderConfigurationSnapshotError(
            "AI_PROVIDER_CONFIGURATION_COMMAND_INVALID",
            "configuration command time is invalid",
        ) from error
    if (
        requested > instant
        or instant - requested > _MAX_COMMAND_AGE
        or expires <= instant
        or expires <= requested
        or expires - requested > _MAX_COMMAND_LIFETIME
    ):
        raise ProviderConfigurationSnapshotError(
            "AI_PROVIDER_CONFIGURATION_COMMAND_STALE",
            "configuration command validity is stale",
        )


def _actor(value: str) -> str:
    if value not in {"local-desktop-session", "test-session"}:
        raise ProviderConfigurationSnapshotError(
            "AI_PROVIDER_CONFIGURATION_SOURCE_INVALID",
            "authenticated source is invalid",
        )
    return value


def _uuid(value: str, code: str) -> str:
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ProviderConfigurationSnapshotError(code, "identity is invalid") from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
