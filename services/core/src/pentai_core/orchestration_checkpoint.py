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
_NAMESPACE = UUID("c692faaf-e714-428a-b9c5-117c8e930bf9")


class OrchestrationCheckpointError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationCheckpointService:
    """Persist metadata-only progress without dispatch, authority, or state change."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def record(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(
            document, "orchestration-task-checkpoint-command-v1.schema.json"
        ):
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_MALFORMED", "checkpoint command is malformed"
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
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_STALE", "checkpoint validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        checkpoint_id = str(uuid5(_NAMESPACE, "checkpoint:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json FROM orchestration_task_checkpoints
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationCheckpointError(
                        "ORCHESTRATION_CHECKPOINT_IDENTITY_CONFLICT",
                        "checkpoint command identity conflicts",
                    )
                return cast(dict[str, Any], json.loads(replay["receipt_json"]))
            self._validate_current(connection, document, instant)
            head = connection.execute(
                """SELECT sequence, checkpoint_digest, receipt_json
                FROM orchestration_task_checkpoints WHERE task_id = ? AND task_revision = ?
                ORDER BY sequence DESC LIMIT 1""",
                (document["task_id"], document["expected_task_revision"]),
            ).fetchone()
            expected_sequence = 1 if head is None else int(head["sequence"]) + 1
            expected_previous = None if head is None else head["checkpoint_digest"]
            if (
                document["sequence"] != expected_sequence
                or document["previous_checkpoint_digest"] != expected_previous
            ):
                raise OrchestrationCheckpointError(
                    "ORCHESTRATION_CHECKPOINT_SEQUENCE_FENCED",
                    "checkpoint sequence or predecessor is stale",
                )
            if head is not None:
                previous = json.loads(head["receipt_json"])
                if document["progress_percent"] < previous["progress_percent"]:
                    raise OrchestrationCheckpointError(
                        "ORCHESTRATION_CHECKPOINT_PROGRESS_ROLLBACK",
                        "checkpoint progress cannot decrease",
                    )
            receipt = {
                "schema_version": "1.0.0",
                "checkpoint_id": checkpoint_id,
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
                "lease_consumption_digest": document["lease_consumption_digest"],
                "policy_bundle_id": document["policy_bundle_id"],
                "policy_hash": document["policy_hash"],
                "worker_id": document["worker_id"],
                "worker_version": document["expected_worker_version"],
                "lease_generation": document["lease_generation"],
                "fencing_token": document["fencing_token"],
                "recovery_generation": document["expected_recovery_generation"],
                "sequence": document["sequence"],
                "previous_checkpoint_digest": document["previous_checkpoint_digest"],
                "progress_percent": document["progress_percent"],
                "status": document["status"],
                "purpose": document["purpose"],
                "created_at": _timestamp(instant),
                "checkpoint_digest": "",
                "authority": "none",
                "execution_enabled": False,
            }
            receipt["checkpoint_digest"] = "sha256:" + content_hash(
                {key: value for key, value in receipt.items() if key != "checkpoint_digest"}
            )
            if contract_issues(
                receipt, "orchestration-task-checkpoint-receipt-v1.schema.json"
            ):
                raise OrchestrationCheckpointError(
                    "ORCHESTRATION_CHECKPOINT_RESULT_INVALID", "checkpoint result is invalid"
                )
            connection.execute(
                """INSERT INTO orchestration_task_checkpoints VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                (
                    checkpoint_id,
                    document["command_id"],
                    command_digest,
                    document["assessment_id"],
                    document["plan_id"],
                    document["expected_plan_revision"],
                    document["task_id"],
                    document["expected_task_revision"],
                    document["lease_consumption_id"],
                    document["sequence"],
                    document["previous_checkpoint_digest"],
                    receipt["checkpoint_digest"],
                    canonical_json(receipt),
                    receipt["created_at"],
                ),
            )
            audit = append_audit_event(
                connection,
                action="orchestration.task_checkpointed",
                subject_type="orchestration_task_checkpoint",
                subject_id=checkpoint_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=receipt["created_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type,
                payload_json) VALUES (?, 'orchestration_task_checkpoint', ?,
                'orchestration.task_checkpointed', ?)""",
                (
                    str(uuid4()),
                    checkpoint_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": receipt["created_at"],
                            "subject_id": checkpoint_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        try:
            policy = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_POLICY_INVALID", "policy is invalid"
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
        ):
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_SAFETY_DENIED", "security state denies"
            )
        if (
            plan is None
            or plan["assessment_id"] != document["assessment_id"]
            or plan["state"] != "active"
            or plan["revision"] != document["expected_plan_revision"]
            or task is None
            or task["assessment_id"] != document["assessment_id"]
            or task["state"] != "running"
            or task["revision"] != document["expected_task_revision"]
            or task["task_type"] != "validation"
        ):
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_TASK_FENCED", "running task is not current"
            )
        consumption = connection.execute(
            """SELECT * FROM orchestration_task_lease_consumptions
            WHERE consumption_id = ?""",
            (document["lease_consumption_id"],),
        ).fetchone()
        if consumption is None:
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_CONSUMPTION_MISSING",
                "lease consumption is missing",
            )
        consumption_receipt = json.loads(consumption["receipt_json"])
        consumption_digest = "sha256:" + content_hash(consumption_receipt)
        exact = (
            consumption_digest == document["lease_consumption_digest"]
            and consumption["receipt_hash"] == content_hash(consumption_receipt)
            and consumption["assessment_id"] == document["assessment_id"]
            and consumption["plan_id"] == document["plan_id"]
            and consumption["resulting_plan_revision"]
            == document["expected_plan_revision"]
            and consumption["task_id"] == document["task_id"]
            and consumption["resulting_task_revision"]
            == document["expected_task_revision"]
            and consumption_receipt["agent_id"] == document["agent_id"]
            and consumption_receipt["capability_manifest_id"]
            == document["capability_manifest_id"]
            and consumption_receipt["manifest_revision"] == document["manifest_revision"]
            and consumption_receipt["budget_reservation_id"]
            == document["budget_reservation_id"]
            and consumption_receipt["budget_account_version"]
            == document["budget_account_version"]
            and consumption_receipt["approval_consumption_id"]
            == document["approval_consumption_id"]
            and consumption_receipt["policy_bundle_id"] == document["policy_bundle_id"]
            and consumption_receipt["policy_hash"] == document["policy_hash"]
            and consumption_receipt["worker_id"] == document["worker_id"]
            and consumption_receipt["worker_version"]
            == document["expected_worker_version"]
            and consumption_receipt["lease_generation"] == document["lease_generation"]
            and consumption_receipt["fencing_token"] == document["fencing_token"]
            and consumption_receipt["recovery_generation"]
            == document["expected_recovery_generation"]
        )
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id = ?",
            (document["worker_id"],),
        ).fetchone()
        fence = connection.execute(
            "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
            (document["task_id"],),
        ).fetchone()
        manifest = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
            (document["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            """SELECT * FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (document["budget_reservation_id"],),
        ).fetchone()
        manifest_document = None if manifest is None else json.loads(manifest["manifest_json"])
        budget_document = None if budget is None else json.loads(budget["receipt_json"])
        if (
            not exact
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != document["expected_worker_version"]
            or worker["execution_enabled"] != 0
            or fence is None
            or fence["current_lease_generation"] != document["lease_generation"]
            or fence["recovery_generation"] != document["expected_recovery_generation"]
            or manifest is None
            or manifest_document is None
            or manifest["manifest_revision"] != document["manifest_revision"]
            or content_hash(manifest_document) != manifest["manifest_hash"]
            or contract_issues(manifest_document, "task-capability-manifest-v2.schema.json")
            or manifest_document["task_state"] != "ready"
            or manifest_document["assessment_id"] != document["assessment_id"]
            or manifest_document["plan_id"] != document["plan_id"]
            or manifest_document["task_id"] != document["task_id"]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget_document is None
            or budget["account_version"] != document["budget_account_version"]
            or contract_issues(
                budget_document,
                "orchestration-task-budget-reservation-v2.schema.json",
            )
            or budget_document["task_state"] != "ready"
            or budget_document["reservation_id"] != budget["reservation_id"]
            or budget_document["assessment_id"] != document["assessment_id"]
            or budget_document["plan_id"] != document["plan_id"]
            or budget_document["task_id"] != document["task_id"]
            or budget["state"] != "reserved"
            or parse_time(budget["expires_at"]) <= instant
        ):
            raise OrchestrationCheckpointError(
                "ORCHESTRATION_CHECKPOINT_BINDING_MISMATCH",
                "checkpoint security binding mismatches",
            )
        return {"consumption": consumption_receipt}


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationCheckpointError(
            "ORCHESTRATION_CHECKPOINT_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
