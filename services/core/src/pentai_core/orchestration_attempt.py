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

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("2710f951-c448-4e84-9f0c-a90bbb3f9aef")


class OrchestrationAttemptError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationAttemptService:
    """Register immutable failed-attempt identity without retry or activation."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def register(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-attempt-command-v1.schema.json"):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_MALFORMED", "attempt command is malformed"
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
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_STALE", "attempt command validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        attempt_id = str(uuid5(_NAMESPACE, "attempt:" + document["failure_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json FROM orchestration_task_attempts
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationAttemptError(
                        "ORCHESTRATION_ATTEMPT_IDENTITY_CONFLICT",
                        "attempt command identity conflicts",
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                self._validate_replay(connection, receipt)
                self._validate_current(connection, _document_from_receipt(receipt), instant)
                return receipt
            failure = self._validate_current(connection, document, instant)
            timestamp = _timestamp(instant)
            receipt = _receipt(document, failure, attempt_id, command_digest, timestamp)
            if contract_issues(
                receipt, "orchestration-task-attempt-receipt-v1.schema.json"
            ):
                raise OrchestrationAttemptError(
                    "ORCHESTRATION_ATTEMPT_RESULT_INVALID", "attempt receipt is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_task_attempts VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        attempt_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["failure_id"],
                        document["failure_receipt_digest"],
                        document["lease_consumption_id"],
                        document["budget_reservation_id"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationAttemptError(
                    "ORCHESTRATION_ATTEMPT_CONFLICT", "attempt identity conflicts"
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.task_attempt_registered",
                subject_type="orchestration_task_attempt",
                subject_id=attempt_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=timestamp,
            )
            connection.execute(
                """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type,
                payload_json) VALUES (?, 'orchestration_task_attempt', ?,
                'orchestration.task_attempt_registered', ?)""",
                (
                    str(uuid4()),
                    attempt_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": timestamp,
                            "subject_id": attempt_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    @staticmethod
    def _validate_replay(
        connection: sqlite3.Connection, receipt: dict[str, Any]
    ) -> None:
        current = connection.execute(
            """SELECT p.revision AS plan_revision, t.revision AS task_revision,
            t.state AS task_state FROM orchestration_plans p JOIN orchestration_tasks t
            ON t.plan_id = p.plan_id WHERE p.plan_id = ? AND t.task_id = ?""",
            (receipt["plan_id"], receipt["task_id"]),
        ).fetchone()
        if (
            current is None
            or current["plan_revision"] != receipt["plan_revision"]
            or current["task_revision"] != receipt["task_revision"]
            or current["task_state"] != "failed"
        ):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_REPLAY_FENCED", "attempt replay is no longer current"
            )

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        failure_row = connection.execute(
            "SELECT * FROM orchestration_task_failures WHERE failure_id = ?",
            (document["failure_id"],),
        ).fetchone()
        if failure_row is None:
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_FAILURE_MISSING", "typed failure is missing"
            )
        failure = json.loads(failure_row["receipt_json"])
        full_digest = "sha256:" + content_hash(failure)
        if (
            contract_issues(failure, "orchestration-task-failure-receipt-v1.schema.json")
            or failure_row["receipt_hash"] != content_hash(failure)
            or full_digest != document["failure_receipt_digest"]
        ):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_FAILURE_INVALID", "typed failure is invalid"
            )
        exact = (
            failure["assessment_id"] == document["assessment_id"]
            and failure["plan_id"] == document["plan_id"]
            and failure["resulting_plan_revision"] == document["expected_plan_revision"]
            and failure["task_id"] == document["task_id"]
            and failure["resulting_task_revision"] == document["expected_task_revision"]
            and failure["agent_id"] == document["agent_id"]
            and failure["capability_manifest_id"] == document["capability_manifest_id"]
            and failure["manifest_revision"] == document["manifest_revision"]
            and failure["budget_reservation_id"] == document["budget_reservation_id"]
            and failure["budget_account_version"] == document["budget_account_version"]
            and failure["approval_consumption_id"] == document["approval_consumption_id"]
            and failure["lease_consumption_id"] == document["lease_consumption_id"]
            and failure["policy_bundle_id"] == document["policy_bundle_id"]
            and failure["policy_hash"] == document["policy_hash"]
            and failure["worker_id"] == document["worker_id"]
            and failure["worker_version"] == document["expected_worker_version"]
            and failure["lease_generation"] == document["lease_generation"]
            and failure["fencing_token"] == document["fencing_token"]
            and failure["recovery_generation"] == document["expected_recovery_generation"]
            and failure["checkpoint_id"] == document["checkpoint_id"]
            and failure["checkpoint_sequence"] == document["checkpoint_sequence"]
            and failure["checkpoint_digest"] == document["checkpoint_digest"]
        )
        if not exact:
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_BINDING_MISMATCH", "attempt binding mismatches"
            )
        self._validate_security_state(connection, document, failure, instant)
        return cast(dict[str, Any], failure)

    def _validate_security_state(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        failure: dict[str, Any],
        instant: datetime,
    ) -> None:
        try:
            policy = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_POLICY_INVALID", "policy is invalid"
            ) from error
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (document["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (document["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? AND task_id = ?",
            (document["plan_id"], document["task_id"]),
        ).fetchone()
        if (
            policy["status"] != "active"
            or policy["content_hash"] != document["policy_hash"]
            or parse_time(policy["policy"]["validity"]["not_after"]) <= instant
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != document["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
            or plan is None
            or plan["assessment_id"] != document["assessment_id"]
            or plan["revision"] != document["expected_plan_revision"]
            or task is None
            or task["state"] != "failed"
            or task["revision"] != document["expected_task_revision"]
            or task["task_type"] != "validation"
        ):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_SECURITY_DENIED", "current security state denies"
            )
        manifest = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
            (document["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            """SELECT * FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (document["budget_reservation_id"],),
        ).fetchone()
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id = ?",
            (document["worker_id"],),
        ).fetchone()
        fence = connection.execute(
            "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
            (document["task_id"],),
        ).fetchone()
        lease_consumption = connection.execute(
            """SELECT * FROM orchestration_task_lease_consumptions
            WHERE consumption_id = ?""",
            (document["lease_consumption_id"],),
        ).fetchone()
        manifest_json = None if manifest is None else json.loads(manifest["manifest_json"])
        budget_json = None if budget is None else json.loads(budget["receipt_json"])
        lease_json = (
            None if lease_consumption is None else json.loads(lease_consumption["receipt_json"])
        )
        approval_valid = True
        if document["approval_consumption_id"] is not None:
            approval = connection.execute(
                """SELECT * FROM orchestration_task_approval_consumptions
                WHERE consumption_id = ?""",
                (document["approval_consumption_id"],),
            ).fetchone()
            approval_valid = (
                approval is not None
                and approval["task_id"] == document["task_id"]
                and approval["policy_hash"] == document["policy_hash"]
                and parse_time(approval["approval_expires_at"]) > instant
            )
        if (
            manifest is None
            or manifest_json is None
            or contract_issues(manifest_json, "task-capability-manifest-v2.schema.json")
            or manifest["manifest_hash"] != content_hash(manifest_json)
            or manifest["manifest_revision"] != document["manifest_revision"]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget_json is None
            or contract_issues(
                budget_json, "orchestration-task-budget-reservation-v2.schema.json"
            )
            or budget["state"] != "reserved"
            or budget["account_version"] != document["budget_account_version"]
            or parse_time(budget["expires_at"]) <= instant
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != document["expected_worker_version"]
            or worker["execution_enabled"] != 0
            or fence is None
            or fence["current_lease_generation"] != document["lease_generation"]
            or fence["recovery_generation"] != document["expected_recovery_generation"]
            or lease_consumption is None
            or lease_json is None
            or lease_consumption["receipt_hash"] != content_hash(lease_json)
            or lease_json["fencing_token"] != document["fencing_token"]
            or not approval_valid
        ):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_PREREQUISITE_INVALID",
                "attempt prerequisite is invalid",
            )
        self._validate_checkpoint(connection, failure)

    @staticmethod
    def _validate_checkpoint(
        connection: sqlite3.Connection, failure: dict[str, Any]
    ) -> None:
        if failure["checkpoint_id"] is None:
            checkpoint = connection.execute(
                """SELECT 1 FROM orchestration_task_checkpoints
                WHERE task_id = ? AND task_revision = ? LIMIT 1""",
                (failure["task_id"], failure["expected_task_revision"]),
            ).fetchone()
            if checkpoint is not None:
                raise OrchestrationAttemptError(
                    "ORCHESTRATION_ATTEMPT_CHECKPOINT_INVALID",
                    "checkpoint lineage is ambiguous",
                )
            return
        checkpoint = connection.execute(
            """SELECT * FROM orchestration_task_checkpoints WHERE checkpoint_id = ?""",
            (failure["checkpoint_id"],),
        ).fetchone()
        if (
            checkpoint is None
            or checkpoint["task_id"] != failure["task_id"]
            or checkpoint["task_revision"] != failure["expected_task_revision"]
            or checkpoint["sequence"] != failure["checkpoint_sequence"]
            or checkpoint["checkpoint_digest"] != failure["checkpoint_digest"]
        ):
            raise OrchestrationAttemptError(
                "ORCHESTRATION_ATTEMPT_CHECKPOINT_INVALID", "checkpoint lineage is invalid"
            )


def _receipt(
    document: dict[str, Any],
    failure: dict[str, Any],
    attempt_id: str,
    command_digest: str,
    timestamp: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "1.0.0",
        "attempt_id": attempt_id,
        "command_id": document["command_id"],
        "command_digest": command_digest,
        "assessment_id": document["assessment_id"],
        "plan_id": document["plan_id"],
        "plan_revision": document["expected_plan_revision"],
        "task_id": document["task_id"],
        "task_revision": document["expected_task_revision"],
        "agent_id": document["agent_id"],
        "capability_manifest_id": document["capability_manifest_id"],
        "manifest_revision": document["manifest_revision"],
        "budget_reservation_id": document["budget_reservation_id"],
        "budget_account_version": document["budget_account_version"],
        "approval_consumption_id": document["approval_consumption_id"],
        "lease_consumption_id": document["lease_consumption_id"],
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
        "failure_id": document["failure_id"],
        "failure_receipt_digest": document["failure_receipt_digest"],
        "failure_class": failure["failure_class"],
        "attempt_number": 1,
        "attempt_state": "failed",
        "purpose": document["purpose"],
        "registered_at": timestamp,
        "attempt_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["attempt_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "attempt_digest"}
    )
    return receipt


def _document_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": receipt["assessment_id"],
        "plan_id": receipt["plan_id"],
        "expected_plan_revision": receipt["plan_revision"],
        "task_id": receipt["task_id"],
        "expected_task_revision": receipt["task_revision"],
        "agent_id": receipt["agent_id"],
        "capability_manifest_id": receipt["capability_manifest_id"],
        "manifest_revision": receipt["manifest_revision"],
        "budget_reservation_id": receipt["budget_reservation_id"],
        "budget_account_version": receipt["budget_account_version"],
        "approval_consumption_id": receipt["approval_consumption_id"],
        "lease_consumption_id": receipt["lease_consumption_id"],
        "policy_bundle_id": receipt["policy_bundle_id"],
        "policy_hash": receipt["policy_hash"],
        "worker_id": receipt["worker_id"],
        "expected_worker_version": receipt["worker_version"],
        "lease_generation": receipt["lease_generation"],
        "fencing_token": receipt["fencing_token"],
        "expected_recovery_generation": receipt["recovery_generation"],
        "checkpoint_id": receipt["checkpoint_id"],
        "checkpoint_sequence": receipt["checkpoint_sequence"],
        "checkpoint_digest": receipt["checkpoint_digest"],
        "failure_id": receipt["failure_id"],
        "failure_receipt_digest": receipt["failure_receipt_digest"],
    }


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationAttemptError("ORCHESTRATION_ATTEMPT_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
