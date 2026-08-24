from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.agent_intent import AgentActionIntentService, AgentIntentError
from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction
from pentai_core.orchestration_retry_activation import (
    OrchestrationRetryActivationError,
    OrchestrationRetryActivationService,
)

_MAX_LIFETIME = timedelta(minutes=15)
_NAMESPACE = UUID("1f74dfce-134f-42d2-a58b-29fb00c783b8")


class OrchestrationRetryManifestError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryManifestService:
    """Issue retry-bound ready manifests without making work runnable."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._activations = OrchestrationRetryActivationService(authorization)

    def issue(
        self,
        *,
        activation_id: str,
        activation_digest: str,
        assessment_id: str,
        plan_id: str,
        expected_plan_revision: int,
        task_id: str,
        expected_task_revision: int,
        agent_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        maximum_impact: str = "benign",
        maximum_timeout_seconds: int = 30,
        maximum_response_bytes: int = 1_048_576,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        self.authorization._require_storage_safe()
        try:
            verified = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_POLICY_INVALID", "policy is invalid"
            ) from error
        if verified["status"] != "active" or verified["content_hash"] != policy_hash:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_POLICY_STALE", "policy is stale"
            )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            activation = self._load_activation(
                connection,
                activation_id=activation_id,
                activation_digest=activation_digest,
                assessment_id=assessment_id,
                plan_id=plan_id,
                plan_revision=expected_plan_revision,
                task_id=task_id,
                task_revision=expected_task_revision,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                instant=instant,
            )
            try:
                AgentActionIntentService._revalidate_binding(
                    connection,
                    assessment_id=assessment_id,
                    plan_id=plan_id,
                    plan_revision=expected_plan_revision,
                    task_id=task_id,
                    task_revision=expected_task_revision,
                    policy_bundle_id=policy_bundle_id,
                    policy_hash=policy_hash,
                    instant=instant,
                    task_state="ready",
                )
            except AgentIntentError as error:
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_SECURITY_DENIED", "current security state denies issuance"
                ) from error
            issued_at = _timestamp(instant)
            expires_at = _timestamp(
                min(
                    instant + _MAX_LIFETIME,
                    parse_time(verified["policy"]["validity"]["not_after"]),
                    parse_time(activation["schedule_expires_at"]),
                )
            )
            manifest_id = str(uuid5(_NAMESPACE, "retry-manifest:" + activation_id))
            manifest = {
                "schema_version": "3.0.0",
                "manifest_id": manifest_id,
                "manifest_revision": 1,
                "assessment_id": assessment_id,
                "plan_id": plan_id,
                "plan_revision": expected_plan_revision,
                "task_id": task_id,
                "task_revision": expected_task_revision,
                "task_state": "ready",
                "task_type": "validation",
                "agent_id": agent_id,
                "policy_bundle_id": policy_bundle_id,
                "policy_hash": policy_hash,
                "retry_activation_id": activation_id,
                "retry_activation_digest": activation_digest,
                "retry_attempt_id": activation["attempt_id"],
                "retry_attempt_digest": activation["attempt_digest"],
                "retry_budget_consumption_id": activation["retry_budget_consumption_id"],
                "allowed_purposes": ["propose_supervised_http_validation"],
                "allowed_capabilities": ["network.http.get"],
                "limits": {
                    "maximum_impact": maximum_impact,
                    "maximum_timeout_seconds": maximum_timeout_seconds,
                    "maximum_response_bytes": maximum_response_bytes,
                },
                "issued_at": issued_at,
                "expires_at": expires_at,
                "issued_by": "pentai-core",
                "delegation_allowed": False,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(manifest, "task-capability-manifest-v3.schema.json"):
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_MANIFEST_MALFORMED", "retry manifest is malformed"
                )
            manifest_hash = content_hash(manifest)
            existing = connection.execute(
                "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
            if existing is not None:
                stored = cast(dict[str, Any], json.loads(existing["manifest_json"]))
                if existing["manifest_hash"] != manifest_hash:
                    raise OrchestrationRetryManifestError(
                        "RETRY_CAPABILITY_IDENTITY_CONFLICT", "retry manifest conflicts"
                    )
                self._validate_replay(connection, stored, activation, instant)
                return copy.deepcopy(stored)
            try:
                connection.execute(
                    """INSERT INTO task_capability_manifests(
                    manifest_id, manifest_revision, assessment_id, plan_id, plan_revision,
                    task_id, task_revision, agent_id, policy_bundle_id, policy_hash,
                    manifest_json, manifest_hash, issued_at, expires_at, issued_by,
                    delegation_allowed, authority, execution_enabled, task_state,
                    retry_activation_id, retry_activation_digest, retry_attempt_id,
                    retry_attempt_digest, retry_budget_consumption_id)
                    VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pentai-core', 0,
                    'none', 0, 'ready', ?, ?, ?, ?, ?)""",
                    (
                        manifest_id,
                        assessment_id,
                        plan_id,
                        expected_plan_revision,
                        task_id,
                        expected_task_revision,
                        agent_id,
                        policy_bundle_id,
                        policy_hash,
                        canonical_json(manifest),
                        manifest_hash,
                        issued_at,
                        expires_at,
                        activation_id,
                        activation_digest,
                        activation["attempt_id"],
                        activation["attempt_digest"],
                        activation["retry_budget_consumption_id"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_CONFLICT", "retry manifest storage conflicts"
                ) from error
            _audit(connection, manifest)
        return copy.deepcopy(manifest)

    def _load_activation(
        self,
        connection: sqlite3.Connection,
        *,
        activation_id: str,
        activation_digest: str,
        assessment_id: str,
        plan_id: str,
        plan_revision: int,
        task_id: str,
        task_revision: int,
        policy_bundle_id: str,
        policy_hash: str,
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_activations WHERE activation_id = ?",
            (activation_id,),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_MISSING", "retry activation is missing"
            )
        try:
            activation = self._activations._load_receipt(row)
            self._activations._validate_replay(connection, activation, instant)
        except OrchestrationRetryActivationError as error:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_INVALID", "retry activation is invalid"
            ) from error
        if (
            activation["activation_digest"] != activation_digest
            or activation["assessment_id"] != assessment_id
            or activation["plan_id"] != plan_id
            or activation["resulting_plan_revision"] != plan_revision
            or activation["task_id"] != task_id
            or activation["resulting_task_revision"] != task_revision
            or activation["policy_bundle_id"] != policy_bundle_id
            or activation["policy_hash"] != policy_hash
            or activation["resulting_plan_state"] != "active"
            or activation["resulting_task_state"] != "ready"
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_MISMATCH", "retry activation binding mismatches"
            )
        return activation

    @staticmethod
    def _validate_replay(
        connection: sqlite3.Connection,
        manifest: dict[str, Any],
        activation: dict[str, Any],
        instant: datetime,
    ) -> None:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id = ?",
            (manifest["task_id"],),
        ).fetchone()
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id = ?",
            (manifest["plan_id"],),
        ).fetchone()
        if (
            contract_issues(manifest, "task-capability-manifest-v3.schema.json")
            or manifest["retry_activation_digest"] != activation["activation_digest"]
            or task is None
            or plan is None
            or (task["state"], task["revision"])
            != ("ready", manifest["task_revision"])
            or (plan["state"], plan["revision"])
            != ("active", manifest["plan_revision"])
            or parse_time(manifest["expires_at"]) <= instant
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_REPLAY_FENCED", "retry manifest replay is stale"
            )


def _audit(connection: sqlite3.Connection, manifest: dict[str, Any]) -> None:
    event = append_audit_event(
        connection,
        action="orchestration.retry_capability_manifest_issued",
        subject_type="task_capability_manifest",
        subject_id=manifest["manifest_id"],
        actor_type="service",
        actor_id="pentai-core",
        data=manifest,
        occurred_at=manifest["issued_at"],
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'task_capability_manifest', ?,
        'orchestration.retry_capability_manifest_issued', ?)""",
        (
            str(uuid4()),
            manifest["manifest_id"],
            canonical_json(
                {"event_hash": event["event_hash"], "subject_id": manifest["manifest_id"]}
            ),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryManifestError(
            "RETRY_CAPABILITY_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
