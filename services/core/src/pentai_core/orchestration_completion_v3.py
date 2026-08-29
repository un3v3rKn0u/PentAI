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
from pentai_core.orchestration_checkpoint_v3 import (
    OrchestrationCheckpointV3Error,
    OrchestrationCheckpointV3Service,
)

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("d0f05b39-bff5-4f22-84d6-4eb0e314c12e")


class OrchestrationCompletionV3Error(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationCompletionV3Service:
    """Consume one attempt-three success as coordination metadata only."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._checkpoints = OrchestrationCheckpointV3Service(authorization)

    def complete(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-completion-command-v3.schema.json"):
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_MALFORMED",
                "completion command is malformed",
            )
        if not _checkpoint_tuple_valid(document):
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_CHECKPOINT_AMBIGUOUS",
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
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_STALE", "completion validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        completion_id = str(uuid5(_NAMESPACE, "completion-v3:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest,receipt_json,receipt_hash
                FROM orchestration_task_completions_v3 WHERE command_id=?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationCompletionV3Error(
                        "ORCHESTRATION_COMPLETION_V3_IDENTITY_CONFLICT",
                        "completion identity conflicts",
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                if replay["receipt_hash"] != content_hash(receipt) or receipt.get(
                    "completion_digest"
                ) != "sha256:" + content_hash(
                    {key: value for key, value in receipt.items() if key != "completion_digest"}
                ):
                    raise OrchestrationCompletionV3Error(
                        "ORCHESTRATION_COMPLETION_V3_REPLAY_FENCED",
                        "completion replay integrity is invalid",
                    )
                self._validate_replay(connection, receipt, instant)
                return receipt
            try:
                self._checkpoints._validate_current(
                    connection, _checkpoint_security_probe(document), instant
                )
            except OrchestrationCheckpointV3Error as error:
                raise OrchestrationCompletionV3Error(
                    "ORCHESTRATION_COMPLETION_V3_SECURITY_DENIED",
                    "current security state denies completion",
                ) from error
            self._validate_checkpoint_head(connection, document)
            recorded_at = _timestamp(instant)
            receipt = _receipt(document, completion_id, command_digest, recorded_at)
            if contract_issues(
                receipt, "orchestration-task-completion-receipt-v3.schema.json"
            ):
                raise OrchestrationCompletionV3Error(
                    "ORCHESTRATION_COMPLETION_V3_RESULT_INVALID",
                    "completion result is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_task_completions_v3(
                    completion_id,command_id,command_digest,assessment_id,plan_id,
                    expected_plan_revision,resulting_plan_revision,task_id,
                    expected_task_revision,resulting_task_revision,retry_attempt_id,
                    lease_consumption_id,checkpoint_id,receipt_json,receipt_hash,
                    recorded_at,authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                    (
                        completion_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        receipt["resulting_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        receipt["resulting_task_revision"],
                        document["retry_attempt_id"],
                        document["lease_consumption_id"],
                        document["checkpoint_id"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        recorded_at,
                    ),
                )
                task_update = connection.execute(
                    """UPDATE orchestration_tasks SET state='succeeded',revision=revision+1,
                    updated_at=? WHERE plan_id=? AND task_id=? AND state='running'
                    AND revision=?""",
                    (
                        recorded_at,
                        document["plan_id"],
                        document["task_id"],
                        document["expected_task_revision"],
                    ),
                )
                if task_update.rowcount != 1:
                    raise OrchestrationCompletionV3Error(
                        "ORCHESTRATION_COMPLETION_V3_CONFLICT",
                        "running task is no longer current",
                    )
                DurablePlanGraphService._refresh_dependents(
                    connection, document["plan_id"], recorded_at
                )
                plan_state = DurablePlanGraphService._plan_state(
                    connection, document["plan_id"]
                )
                plan_update = connection.execute(
                    """UPDATE orchestration_plans SET state=?,revision=revision+1,
                    updated_at=? WHERE plan_id=? AND state='active' AND revision=?""",
                    (
                        plan_state,
                        recorded_at,
                        document["plan_id"],
                        document["expected_plan_revision"],
                    ),
                )
                if plan_update.rowcount != 1:
                    raise OrchestrationCompletionV3Error(
                        "ORCHESTRATION_COMPLETION_V3_CONFLICT",
                        "active plan is no longer current",
                    )
            except sqlite3.IntegrityError as error:
                raise OrchestrationCompletionV3Error(
                    "ORCHESTRATION_COMPLETION_V3_CONFLICT",
                    "completion consumption conflicts",
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.attempt_three_task_completed",
                subject_type="orchestration_task_completion",
                subject_id=completion_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=recorded_at,
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'orchestration_task_completion',?,
                'orchestration.attempt_three_task_completed',?)""",
                (
                    str(uuid4()),
                    completion_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": recorded_at,
                            "subject_id": completion_id,
                        }
                    ),
                ),
            )
        return receipt

    @staticmethod
    def _validate_checkpoint_head(
        connection: sqlite3.Connection, document: dict[str, Any]
    ) -> None:
        head = connection.execute(
            """SELECT checkpoint_id,sequence,checkpoint_digest,receipt_json
            FROM orchestration_task_checkpoints_v3 WHERE task_id=? AND task_revision=?
            ORDER BY sequence DESC LIMIT 1""",
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
        if supplied != expected or (
            head is not None and json.loads(head["receipt_json"])["schema_version"] != "3.0.0"
        ):
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_CHECKPOINT_FENCED",
                "checkpoint head is stale or mismatched",
            )

    def _validate_replay(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        if contract_issues(receipt, "orchestration-task-completion-receipt-v3.schema.json"):
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_REPLAY_FENCED",
                "completion replay is invalid",
            )
        try:
            policy = self.authorization.get_policy(
                receipt["assessment_id"], receipt["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_REPLAY_FENCED",
                "completion replay policy is stale",
            ) from error
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (receipt["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id=?", (receipt["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (receipt["plan_id"], receipt["task_id"]),
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
            "SELECT * FROM task_capability_manifests_v4 WHERE manifest_id=?",
            (receipt["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations_v4 WHERE reservation_id=?",
            (receipt["budget_reservation_id"],),
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
            policy["status"] != "active"
            or policy["content_hash"] != receipt["policy_hash"]
            or parse_time(policy["policy"]["validity"]["not_after"]) <= instant
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != receipt["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
            or plan is None
            or plan["revision"] != receipt["resulting_plan_revision"]
            or plan["state"] not in {"active", "completed"}
            or DurablePlanGraphService._plan_state(connection, receipt["plan_id"])
            != plan["state"]
            or task is None
            or (task["state"], task["revision"])
            != ("succeeded", receipt["resulting_task_revision"])
            or worker is None
            or (worker["status"], worker["version"], worker["execution_enabled"])
            != ("running", receipt["worker_version"], 0)
            or fence is None
            or fence["current_lease_generation"] != receipt["lease_generation"]
            or fence["recovery_generation"] != receipt["recovery_generation"]
            or manifest is None
            or manifest["manifest_hash"] != receipt["capability_manifest_digest"][7:]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget["request_digest"] != receipt["budget_request_digest"]
            or budget["account_version"] != receipt["budget_account_version"]
            or budget["state"] != "reserved"
            or parse_time(budget["expires_at"]) <= instant
            or account is None
            or account["version"] != receipt["budget_account_version"]
        ):
            raise OrchestrationCompletionV3Error(
                "ORCHESTRATION_COMPLETION_V3_REPLAY_FENCED",
                "completion replay security bindings are stale",
            )


def _checkpoint_tuple_valid(document: dict[str, Any]) -> bool:
    values = (
        document["checkpoint_id"],
        document["checkpoint_sequence"],
        document["checkpoint_digest"],
    )
    return all(value is None for value in values) or all(value is not None for value in values)


def _checkpoint_security_probe(document: dict[str, Any]) -> dict[str, Any]:
    probe = {
        key: value
        for key, value in document.items()
        if key not in {"checkpoint_id", "checkpoint_sequence", "checkpoint_digest"}
    }
    probe.update(
        {
            "sequence": 1,
            "previous_checkpoint_digest": None,
            "progress_percent": 0,
            "status": "started",
            "purpose": "record_attempt_three_validation_progress",
        }
    )
    return probe


def _receipt(
    document: dict[str, Any], completion_id: str, command_digest: str, recorded_at: str
) -> dict[str, Any]:
    receipt = {
        key: value
        for key, value in document.items()
        if key
        not in {
            "requested_at",
            "expires_at",
            "expected_worker_version",
            "expected_recovery_generation",
        }
    }
    receipt.update(
        {
            "completion_id": completion_id,
            "command_digest": command_digest,
            "resulting_plan_revision": document["expected_plan_revision"] + 1,
            "resulting_task_revision": document["expected_task_revision"] + 1,
            "worker_version": document["expected_worker_version"],
            "recovery_generation": document["expected_recovery_generation"],
            "recorded_at": recorded_at,
            "resulting_task_state": "succeeded",
            "completion_digest": "",
        }
    )
    receipt["completion_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "completion_digest"}
    )
    return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationCompletionV3Error(
            "ORCHESTRATION_COMPLETION_V3_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
