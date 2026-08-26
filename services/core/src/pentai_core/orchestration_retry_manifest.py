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
from pentai_core.orchestration_retry_schedule import OrchestrationRetryScheduleError

_MAX_LIFETIME = timedelta(minutes=15)
_MAX_REQUEST_AGE = timedelta(minutes=1)
_MAX_REQUEST_VALIDITY = timedelta(minutes=5)
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

    def issue_v4(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "task-capability-manifest-request-v4.schema.json"):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_REQUEST_MALFORMED", "retry manifest request is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        request_expires_at = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_REQUEST_AGE
            or request_expires_at <= instant
            or request_expires_at <= requested_at
            or request_expires_at - requested_at > _MAX_REQUEST_VALIDITY
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_REQUEST_STALE", "retry manifest request is stale"
            )
        self.authorization._require_storage_safe()
        try:
            verified = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_POLICY_INVALID", "policy is invalid"
            ) from error
        if verified["status"] != "active" or verified["content_hash"] != document["policy_hash"]:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_POLICY_STALE", "policy is stale"
            )
        request_digest = "sha256:" + content_hash(document)
        manifest_id = str(uuid5(_NAMESPACE, "retry-manifest-v4:" + document["retry_activation_id"]))
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM task_capability_manifests_v4 WHERE request_id=?",
                (document["request_id"],),
            ).fetchone()
            if replay is not None and replay["request_digest"] != request_digest:
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_IDENTITY_CONFLICT", "retry manifest conflicts"
                )
            activation, schedule, agent_id = self._load_activation_v2(connection, document, instant)
            if replay is not None:
                manifest = self._load_manifest_v4(replay)
                self._validate_replay_v4(connection, manifest, activation, schedule, instant)
                return copy.deepcopy(manifest)

            existing = connection.execute(
                """SELECT 1 FROM task_capability_manifests_v4
                WHERE retry_activation_id=? OR retry_schedule_id=? OR retry_attempt_id=?""",
                (
                    document["retry_activation_id"],
                    schedule["schedule_id"],
                    schedule["attempt_id"],
                ),
            ).fetchone()
            if existing is not None:
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_ALREADY_ISSUED", "retry manifest was already issued"
                )
            issued_at = _timestamp(instant)
            expires_at = _timestamp(
                min(
                    instant + _MAX_LIFETIME,
                    request_expires_at,
                    parse_time(verified["policy"]["validity"]["not_after"]),
                    parse_time(schedule["expires_at"]),
                )
            )
            manifest = _manifest_v4(
                document,
                activation,
                schedule,
                agent_id,
                manifest_id,
                request_digest,
                issued_at,
                expires_at,
            )
            if contract_issues(manifest, "task-capability-manifest-v4.schema.json"):
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_MANIFEST_MALFORMED", "retry manifest is malformed"
                )
            try:
                connection.execute(
                    """INSERT INTO task_capability_manifests_v4 (
                    manifest_id, manifest_revision, request_id, request_digest,
                    assessment_id, plan_id, plan_revision, task_id, task_revision,
                    agent_id, policy_bundle_id, policy_hash, retry_activation_id,
                    retry_schedule_id, retry_attempt_id, retry_budget_consumption_id,
                    manifest_json, manifest_hash, issued_at, expires_at, issued_by,
                    delegation_allowed, authority, execution_enabled)
                    VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'pentai-core', 0, 'none', 0)""",
                    (
                        manifest_id,
                        document["request_id"],
                        request_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["agent_id"],
                        document["policy_bundle_id"],
                        document["policy_hash"],
                        document["retry_activation_id"],
                        schedule["schedule_id"],
                        schedule["attempt_id"],
                        schedule["retry_budget_consumption_id"],
                        canonical_json(manifest),
                        content_hash(manifest),
                        issued_at,
                        expires_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryManifestError(
                    "RETRY_CAPABILITY_CONFLICT", "retry manifest storage conflicts"
                ) from error
            _audit(connection, manifest)
        return copy.deepcopy(manifest)

    def _load_activation_v2(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_activations_v2 WHERE activation_id=?",
            (document["retry_activation_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_MISSING", "retry activation is missing"
            )
        try:
            activation = self._activations._load_receipt_v2(row)
            self._activations._validate_replay_v2(connection, activation, instant)
        except OrchestrationRetryActivationError as error:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_INVALID", "retry activation is invalid"
            ) from error
        schedule_row = connection.execute(
            "SELECT * FROM orchestration_retry_schedules_v2 WHERE schedule_id=?",
            (activation["schedule_id"],),
        ).fetchone()
        if schedule_row is None:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_SCHEDULE_MISSING", "retry schedule is missing"
            )
        try:
            schedule = self._activations._schedules._load_receipt_v2(schedule_row)
        except OrchestrationRetryScheduleError as error:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_SCHEDULE_INVALID", "retry schedule is invalid"
            ) from error
        manifest_row = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id=?",
            (schedule["capability_manifest_id"],),
        ).fetchone()
        if manifest_row is None:
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_LINEAGE_MANIFEST_MISSING",
                "prior lineage manifest is missing",
            )
        lineage_manifest = cast(dict[str, Any], json.loads(manifest_row["manifest_json"]))
        if (
            contract_issues(lineage_manifest, "task-capability-manifest-v3.schema.json")
            or manifest_row["manifest_hash"] != content_hash(lineage_manifest)
            or ("sha256:" + manifest_row["manifest_hash"]) != schedule["capability_manifest_digest"]
            or lineage_manifest["agent_id"] != document["agent_id"]
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_AGENT_MISMATCH",
                "trusted retry agent lineage mismatches",
            )
        if (
            activation["activation_digest"] != document["retry_activation_digest"]
            or activation["assessment_id"] != document["assessment_id"]
            or activation["plan_id"] != document["plan_id"]
            or activation["resulting_plan_revision"] != document["expected_plan_revision"]
            or activation["task_id"] != document["task_id"]
            or activation["resulting_task_revision"] != document["expected_task_revision"]
            or activation["policy_bundle_id"] != document["policy_bundle_id"]
            or activation["policy_hash"] != document["policy_hash"]
            or activation["attempt_number"] != 3
            or activation["resulting_plan_state"] != "active"
            or activation["resulting_task_state"] != "ready"
            or schedule["schedule_id"] != activation["schedule_id"]
            or schedule["schedule_digest"] != activation["schedule_digest"]
            or schedule["attempt_id"] != activation["attempt_id"]
            or schedule["attempt_digest"] != activation["attempt_digest"]
            or schedule["attempt_number"] != 3
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_ACTIVATION_MISMATCH",
                "retry activation binding mismatches",
            )
        return activation, schedule, lineage_manifest["agent_id"]

    @staticmethod
    def _load_manifest_v4(row: sqlite3.Row) -> dict[str, Any]:
        manifest = cast(dict[str, Any], json.loads(row["manifest_json"]))
        if (
            contract_issues(manifest, "task-capability-manifest-v4.schema.json")
            or row["manifest_hash"] != content_hash(manifest)
            or manifest["manifest_id"] != row["manifest_id"]
            or manifest["request_id"] != row["request_id"]
            or manifest["request_digest"] != row["request_digest"]
            or manifest["retry_activation_id"] != row["retry_activation_id"]
            or manifest["retry_schedule_id"] != row["retry_schedule_id"]
            or manifest["retry_attempt_id"] != row["retry_attempt_id"]
            or manifest["retry_budget_consumption_id"] != row["retry_budget_consumption_id"]
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_MANIFEST_INVALID", "retry manifest is invalid"
            )
        return manifest

    @staticmethod
    def _validate_replay_v4(
        connection: sqlite3.Connection,
        manifest: dict[str, Any],
        activation: dict[str, Any],
        schedule: dict[str, Any],
        instant: datetime,
    ) -> None:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id=?",
            (manifest["task_id"],),
        ).fetchone()
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id=?",
            (manifest["plan_id"],),
        ).fetchone()
        if (
            manifest["retry_activation_digest"] != activation["activation_digest"]
            or manifest["retry_schedule_digest"] != schedule["schedule_digest"]
            or task is None
            or plan is None
            or (task["state"], task["revision"]) != ("ready", manifest["task_revision"])
            or (plan["state"], plan["revision"]) != ("active", manifest["plan_revision"])
            or parse_time(manifest["expires_at"]) <= instant
        ):
            raise OrchestrationRetryManifestError(
                "RETRY_CAPABILITY_REPLAY_FENCED", "retry manifest replay is stale"
            )

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
            or (task["state"], task["revision"]) != ("ready", manifest["task_revision"])
            or (plan["state"], plan["revision"]) != ("active", manifest["plan_revision"])
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


def _manifest_v4(
    command: dict[str, Any],
    activation: dict[str, Any],
    schedule: dict[str, Any],
    agent_id: str,
    manifest_id: str,
    request_digest: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": "4.0.0",
        "manifest_id": manifest_id,
        "manifest_revision": 1,
        "request_id": command["request_id"],
        "request_digest": request_digest,
        "assessment_id": activation["assessment_id"],
        "plan_id": activation["plan_id"],
        "plan_revision": activation["resulting_plan_revision"],
        "task_id": activation["task_id"],
        "task_revision": activation["resulting_task_revision"],
        "task_state": "ready",
        "task_type": "validation",
        "agent_id": agent_id,
        "policy_bundle_id": activation["policy_bundle_id"],
        "policy_hash": activation["policy_hash"],
        "retry_policy_id": schedule["retry_policy_id"],
        "retry_policy_digest": schedule["retry_policy_digest"],
        "retry_activation_id": activation["activation_id"],
        "retry_activation_digest": activation["activation_digest"],
        "retry_schedule_id": schedule["schedule_id"],
        "retry_schedule_digest": schedule["schedule_digest"],
        "retry_attempt_id": schedule["attempt_id"],
        "retry_attempt_digest": schedule["attempt_digest"],
        "attempt_number": 3,
        "prior_retry_budget_consumption_id": schedule["prior_retry_budget_consumption_id"],
        "retry_budget_consumption_id": schedule["retry_budget_consumption_id"],
        "approval_consumption_id": schedule["approval_consumption_id"],
        "worker_id": schedule["worker_id"],
        "worker_version": schedule["worker_version"],
        "lease_generation": schedule["lease_generation"],
        "fencing_token": schedule["fencing_token"],
        "recovery_generation": schedule["recovery_generation"],
        "allowed_purposes": ["propose_supervised_http_validation"],
        "allowed_capabilities": ["network.http.get"],
        "limits": copy.deepcopy(command["limits"]),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "issued_by": "pentai-core",
        "delegation_allowed": False,
        "authority": "none",
        "execution_enabled": False,
    }


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryManifestError("RETRY_CAPABILITY_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
