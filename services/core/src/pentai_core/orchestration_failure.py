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

from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction
from pentai_core.orchestration import DurablePlanGraphService
from pentai_core.orchestration_checkpoint import (
    OrchestrationCheckpointError,
    OrchestrationCheckpointService,
)

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("f8499277-28f1-47ba-9958-8a4ad8acda75")


class OrchestrationFailureError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationFailureService:
    """Consume a closed failure record without retry, dispatch, or authority."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._checkpoints = OrchestrationCheckpointService(authorization)

    def record(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        failure_version = document.get("schema_version")
        if not isinstance(failure_version, str):
            failure_version = ""
        schema = {
            "1.0.0": "orchestration-task-failure-command-v1.schema.json",
            "2.0.0": "orchestration-task-failure-command-v2.schema.json",
        }.get(failure_version, "orchestration-task-failure-command-v1.schema.json")
        if contract_issues(document, schema):
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_MALFORMED", "failure command is malformed"
            )
        if not _checkpoint_tuple_valid(document):
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_CHECKPOINT_AMBIGUOUS",
                "checkpoint binding is ambiguous",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        expires_at = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > _MAX_VALIDITY
        ):
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_STALE", "failure command validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        failure_id = str(uuid5(_NAMESPACE, "failure:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json FROM orchestration_task_failures
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationFailureError(
                        "ORCHESTRATION_FAILURE_IDENTITY_CONFLICT",
                        "failure command identity conflicts",
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                current = connection.execute(
                    """SELECT p.revision AS plan_revision, t.revision AS task_revision,
                    t.state AS task_state FROM orchestration_plans p
                    JOIN orchestration_tasks t ON t.plan_id = p.plan_id
                    WHERE p.plan_id = ? AND t.task_id = ?""",
                    (receipt["plan_id"], receipt["task_id"]),
                ).fetchone()
                if (
                    current is None
                    or current["plan_revision"] != receipt["resulting_plan_revision"]
                    or current["task_revision"] != receipt["resulting_task_revision"]
                    or current["task_state"] != "failed"
                ):
                    raise OrchestrationFailureError(
                        "ORCHESTRATION_FAILURE_REPLAY_FENCED",
                        "failure replay is no longer current",
                    )
                if failure_version == "2.0.0":
                    self._validate_retry_replay(connection, receipt, instant)
                return receipt
            try:
                self._checkpoints._validate_current(connection, document, instant)
            except OrchestrationCheckpointError as error:
                raise OrchestrationFailureError(
                    "ORCHESTRATION_FAILURE_SECURITY_DENIED",
                    "current security state denies failure consumption",
                ) from error
            self._validate_checkpoint_head(connection, document, failure_version)
            timestamp = _timestamp(instant)
            receipt = _receipt(document, failure_id, command_digest, timestamp)
            if contract_issues(
                receipt,
                "orchestration-task-failure-receipt-"
                f"v{2 if failure_version == '2.0.0' else 1}.schema.json",
            ):
                raise OrchestrationFailureError(
                    "ORCHESTRATION_FAILURE_RESULT_INVALID", "failure result is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_task_failures(
                    failure_id, command_id, command_digest, assessment_id, plan_id,
                    expected_plan_revision, resulting_plan_revision, task_id,
                    expected_task_revision, resulting_task_revision, lease_consumption_id,
                    checkpoint_id, failure_class, receipt_json, receipt_hash, recorded_at,
                    authority, execution_enabled, capability_manifest_digest,
                    budget_request_digest, retry_activation_id, retry_activation_digest,
                    retry_attempt_id, retry_attempt_digest, retry_budget_consumption_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0,
                    ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        failure_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        receipt["resulting_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        receipt["resulting_task_revision"],
                        document["lease_consumption_id"],
                        document["checkpoint_id"],
                        document["failure_class"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        timestamp,
                        document.get("capability_manifest_digest"),
                        document.get("budget_request_digest"),
                        document.get("retry_activation_id"),
                        document.get("retry_activation_digest"),
                        document.get("retry_attempt_id"),
                        document.get("retry_attempt_digest"),
                        document.get("retry_budget_consumption_id"),
                    ),
                )
                connection.execute(
                    """UPDATE orchestration_tasks
                    SET state = 'failed', revision = revision + 1, updated_at = ?
                    WHERE plan_id = ? AND task_id = ? AND state = 'running' AND revision = ?""",
                    (
                        timestamp,
                        document["plan_id"],
                        document["task_id"],
                        document["expected_task_revision"],
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise OrchestrationFailureError(
                        "ORCHESTRATION_FAILURE_TASK_FENCED", "running task is not current"
                    )
                DurablePlanGraphService._refresh_dependents(
                    connection, document["plan_id"], timestamp
                )
                plan_state = DurablePlanGraphService._plan_state(connection, document["plan_id"])
                connection.execute(
                    """UPDATE orchestration_plans
                    SET state = ?, revision = revision + 1, updated_at = ?
                    WHERE plan_id = ? AND state = 'active' AND revision = ?""",
                    (
                        plan_state,
                        timestamp,
                        document["plan_id"],
                        document["expected_plan_revision"],
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] != 1:
                    raise OrchestrationFailureError(
                        "ORCHESTRATION_FAILURE_PLAN_FENCED", "active plan is not current"
                    )
            except sqlite3.IntegrityError as error:
                raise OrchestrationFailureError(
                    "ORCHESTRATION_FAILURE_CONFLICT", "failure consumption conflicts"
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.task_failure_recorded",
                subject_type="orchestration_task_failure",
                subject_id=failure_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=timestamp,
            )
            connection.execute(
                """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type,
                payload_json) VALUES (?, 'orchestration_task_failure', ?,
                'orchestration.task_failure_recorded', ?)""",
                (
                    str(uuid4()),
                    failure_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": timestamp,
                            "subject_id": failure_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    def _validate_retry_replay(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        try:
            policy = self.authorization.get_policy(
                receipt["assessment_id"], receipt["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_REPLAY_FENCED",
                "failure replay policy is no longer current",
            ) from error
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (receipt["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id=?",
            (receipt["worker_id"],),
        ).fetchone()
        fence = connection.execute(
            "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?",
            (receipt["task_id"],),
        ).fetchone()
        manifest = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id=?",
            (receipt["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations WHERE reservation_id=?",
            (receipt["budget_reservation_id"],),
        ).fetchone()
        if (
            policy["status"] != "active"
            or policy["content_hash"] != receipt["policy_hash"]
            or parse_time(policy["policy"]["validity"]["not_after"]) <= instant
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != receipt["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != receipt["worker_version"]
            or worker["execution_enabled"] != 0
            or fence is None
            or fence["current_lease_generation"] != receipt["lease_generation"]
            or fence["recovery_generation"] != receipt["recovery_generation"]
            or manifest is None
            or manifest["manifest_hash"] != receipt["capability_manifest_digest"][7:]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget["account_version"] != receipt["budget_account_version"]
            or budget["request_digest"] != receipt["budget_request_digest"]
            or budget["state"] != "reserved"
            or parse_time(budget["expires_at"]) <= instant
        ):
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_REPLAY_FENCED",
                "failure replay security bindings are no longer current",
            )

    @staticmethod
    def _validate_checkpoint_head(
        connection: sqlite3.Connection, document: dict[str, Any], failure_version: str
    ) -> None:
        head = connection.execute(
            """SELECT checkpoint_id, sequence, checkpoint_digest, receipt_json
            FROM orchestration_task_checkpoints
            WHERE task_id = ? AND task_revision = ? ORDER BY sequence DESC LIMIT 1""",
            (document["task_id"], document["expected_task_revision"]),
        ).fetchone()
        expected = (
            (None, None, None)
            if head is None
            else (head["checkpoint_id"], head["sequence"], head["checkpoint_digest"])
        )
        supplied = (
            document["checkpoint_id"],
            document["checkpoint_sequence"],
            document["checkpoint_digest"],
        )
        head_version = None if head is None else json.loads(head["receipt_json"])["schema_version"]
        expected_version = "2.0.0" if failure_version == "2.0.0" else "1.0.0"
        if supplied != expected or (head is not None and head_version != expected_version):
            raise OrchestrationFailureError(
                "ORCHESTRATION_FAILURE_CHECKPOINT_FENCED",
                "checkpoint head is stale or mismatched",
            )


def _checkpoint_tuple_valid(document: dict[str, Any]) -> bool:
    values = (
        document["checkpoint_id"],
        document["checkpoint_sequence"],
        document["checkpoint_digest"],
    )
    return all(value is None for value in values) or all(value is not None for value in values)


def _receipt(
    document: dict[str, Any], failure_id: str, command_digest: str, timestamp: str
) -> dict[str, Any]:
    receipt = {
        "schema_version": document["schema_version"],
        "failure_id": failure_id,
        "command_id": document["command_id"],
        "command_digest": command_digest,
        "assessment_id": document["assessment_id"],
        "plan_id": document["plan_id"],
        "expected_plan_revision": document["expected_plan_revision"],
        "resulting_plan_revision": document["expected_plan_revision"] + 1,
        "task_id": document["task_id"],
        "expected_task_revision": document["expected_task_revision"],
        "resulting_task_revision": document["expected_task_revision"] + 1,
        "agent_id": document["agent_id"],
        "capability_manifest_id": document["capability_manifest_id"],
        "manifest_revision": document["manifest_revision"],
        "budget_reservation_id": document["budget_reservation_id"],
        "budget_account_version": document["budget_account_version"],
        "approval_consumption_id": document["approval_consumption_id"],
        "lease_consumption_id": document["lease_consumption_id"],
        "lease_consumption_digest": document["lease_consumption_digest"],
        "policy_bundle_id": document["policy_bundle_id"],
        "policy_hash": document["policy_hash"],
        "worker_id": document["worker_id"],
        "worker_version": document["expected_worker_version"],
        "lease_generation": document["lease_generation"],
        "fencing_token": document["fencing_token"],
        "recovery_generation": document["expected_recovery_generation"],
        "checkpoint_id": document["checkpoint_id"],
        "checkpoint_sequence": document["checkpoint_sequence"],
        "checkpoint_digest": document["checkpoint_digest"],
        "failure_class": document["failure_class"],
        "purpose": document["purpose"],
        "recorded_at": timestamp,
        "resulting_task_state": "failed",
        "failure_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    if document["schema_version"] == "2.0.0":
        for field in (
            "capability_manifest_digest",
            "budget_request_digest",
            "retry_activation_id",
            "retry_activation_digest",
            "retry_attempt_id",
            "retry_attempt_digest",
            "retry_budget_consumption_id",
        ):
            receipt[field] = document[field]
    receipt["failure_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "failure_digest"}
    )
    return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationFailureError("ORCHESTRATION_FAILURE_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
