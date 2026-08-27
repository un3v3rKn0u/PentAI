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
_NAMESPACE = UUID("f8b64a82-ffb7-4b95-87a7-8bc90a97df4f")


class OrchestrationCheckpointV3Error(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationCheckpointV3Service:
    """Record inert attempt-three progress against one spent lease lineage."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def record(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-checkpoint-command-v3.schema.json"):
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_MALFORMED", "checkpoint command is malformed"
            )
        instant = _instant(now)
        requested_at, expires_at = (
            parse_time(document["requested_at"]),
            parse_time(document["expires_at"]),
        )
        if (
            requested_at > instant
            or instant - requested_at > _MAX_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > _MAX_VALIDITY
        ):
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_STALE", "checkpoint validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        checkpoint_id = str(uuid5(_NAMESPACE, "checkpoint-v3:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json
                FROM orchestration_task_checkpoints_v3 WHERE command_id=?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationCheckpointV3Error(
                        "ORCHESTRATION_CHECKPOINT_V3_IDENTITY_CONFLICT",
                        "checkpoint identity conflicts",
                    )
                self._validate_current(connection, document, instant)
                return cast(dict[str, Any], json.loads(replay["receipt_json"]))
            consumption = self._validate_current(connection, document, instant)
            head = connection.execute(
                """SELECT sequence, checkpoint_digest, receipt_json
                FROM orchestration_task_checkpoints_v3
                WHERE task_id=? AND task_revision=? ORDER BY sequence DESC LIMIT 1""",
                (document["task_id"], document["expected_task_revision"]),
            ).fetchone()
            expected_sequence = 1 if head is None else int(head["sequence"]) + 1
            expected_previous = None if head is None else head["checkpoint_digest"]
            if (
                document["sequence"] != expected_sequence
                or document["previous_checkpoint_digest"] != expected_previous
            ):
                raise OrchestrationCheckpointV3Error(
                    "ORCHESTRATION_CHECKPOINT_V3_SEQUENCE_FENCED",
                    "checkpoint sequence or predecessor is stale",
                )
            if (
                head is not None
                and document["progress_percent"]
                < json.loads(head["receipt_json"])["progress_percent"]
            ):
                raise OrchestrationCheckpointV3Error(
                    "ORCHESTRATION_CHECKPOINT_V3_PROGRESS_ROLLBACK",
                    "checkpoint progress cannot decrease",
                )
            receipt = self._receipt(
                document, consumption, checkpoint_id, command_digest, _timestamp(instant)
            )
            if contract_issues(receipt, "orchestration-task-checkpoint-receipt-v3.schema.json"):
                raise OrchestrationCheckpointV3Error(
                    "ORCHESTRATION_CHECKPOINT_V3_RESULT_INVALID", "checkpoint result is invalid"
                )
            connection.execute(
                """INSERT INTO orchestration_task_checkpoints_v3
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'none',0)""",
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
                action="orchestration.attempt_three_task_checkpointed",
                subject_type="orchestration_task_checkpoint",
                subject_id=checkpoint_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=receipt["created_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'orchestration_task_checkpoint',?,
                'orchestration.attempt_three_task_checkpointed',?)""",
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
        return receipt

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        try:
            policy = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_POLICY_INVALID", "policy is invalid"
            ) from error
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (document["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id=?", (document["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
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
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_SAFETY_DENIED", "security state denies"
            )
        if (
            plan is None
            or (plan["assessment_id"], plan["state"], plan["revision"])
            != (document["assessment_id"], "active", document["expected_plan_revision"])
            or task is None
            or (task["assessment_id"], task["state"], task["revision"], task["task_type"])
            != (
                document["assessment_id"],
                "running",
                document["expected_task_revision"],
                "validation",
            )
        ):
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_TASK_FENCED", "running task is not current"
            )
        row = connection.execute(
            "SELECT * FROM orchestration_task_lease_consumptions_v3 WHERE consumption_id=?",
            (document["lease_consumption_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_CONSUMPTION_MISSING", "lease consumption is missing"
            )
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        if (
            contract_issues(receipt, "orchestration-task-lease-consumption-receipt-v3.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or document["lease_consumption_digest"] != "sha256:" + content_hash(receipt)
        ):
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_CONSUMPTION_INVALID", "lease consumption is invalid"
            )
        mapping = {
            "expected_plan_revision": "resulting_plan_revision",
            "expected_task_revision": "resulting_task_revision",
            "expected_worker_version": "worker_version",
            "expected_recovery_generation": "recovery_generation",
            "lease_consumption_id": "consumption_id",
        }
        ignored = {
            "schema_version",
            "command_id",
            "sequence",
            "previous_checkpoint_digest",
            "progress_percent",
            "status",
            "purpose",
            "requested_at",
            "expires_at",
            "authority",
            "execution_enabled",
            "lease_consumption_digest",
        }
        for key, value in document.items():
            if key in ignored:
                continue
            receipt_key = mapping.get(key, key)
            if receipt.get(receipt_key) != value:
                raise OrchestrationCheckpointV3Error(
                    "ORCHESTRATION_CHECKPOINT_V3_BINDING_MISMATCH", "checkpoint lineage mismatches"
                )
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id=?", (document["worker_id"],)
        ).fetchone()
        fence = connection.execute(
            "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?", (document["task_id"],)
        ).fetchone()
        manifest = connection.execute(
            "SELECT * FROM task_capability_manifests_v4 WHERE manifest_id=?",
            (document["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations_v4 WHERE reservation_id=?",
            (document["budget_reservation_id"],),
        ).fetchone()
        account = (
            None
            if budget is None
            else connection.execute(
                "SELECT * FROM orchestration_budget_accounts WHERE account_id=?",
                (budget["account_id"],),
            ).fetchone()
        )
        if (
            worker is None
            or (worker["status"], worker["version"], worker["execution_enabled"])
            != ("running", document["expected_worker_version"], 0)
            or fence is None
            or fence["current_lease_generation"] != document["lease_generation"]
            or fence["recovery_generation"] != document["expected_recovery_generation"]
            or manifest is None
            or manifest["manifest_hash"] != document["capability_manifest_digest"][7:]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget["request_digest"] != document["budget_request_digest"]
            or budget["account_version"] != document["budget_account_version"]
            or budget["state"] != "reserved"
            or parse_time(budget["expires_at"]) <= instant
            or account is None
            or account["version"] != document["budget_account_version"]
        ):
            raise OrchestrationCheckpointV3Error(
                "ORCHESTRATION_CHECKPOINT_V3_BINDING_MISMATCH",
                "current security binding mismatches",
            )
        return receipt

    @staticmethod
    def _receipt(
        document: dict[str, Any],
        consumption: dict[str, Any],
        checkpoint_id: str,
        command_digest: str,
        created_at: str,
    ) -> dict[str, Any]:
        receipt = {
            key: value
            for key, value in document.items()
            if key
            not in {
                "requested_at",
                "expires_at",
                "expected_plan_revision",
                "expected_task_revision",
                "expected_worker_version",
                "expected_recovery_generation",
            }
        }
        receipt.update(
            {
                "checkpoint_id": checkpoint_id,
                "command_digest": command_digest,
                "plan_revision": document["expected_plan_revision"],
                "task_revision": document["expected_task_revision"],
                "worker_version": document["expected_worker_version"],
                "recovery_generation": document["expected_recovery_generation"],
                "created_at": created_at,
                "checkpoint_digest": "",
            }
        )
        receipt["checkpoint_digest"] = "sha256:" + content_hash(
            {k: v for k, v in receipt.items() if k != "checkpoint_digest"}
        )
        return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationCheckpointV3Error(
            "ORCHESTRATION_CHECKPOINT_V3_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
