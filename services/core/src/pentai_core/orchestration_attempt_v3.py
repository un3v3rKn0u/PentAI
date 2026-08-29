from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService
from pentai_core.database import transaction
from pentai_core.orchestration_failure_v3 import (
    OrchestrationFailureV3Error,
    OrchestrationFailureV3Service,
)

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)


class OrchestrationAttemptV3Error(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationAttemptV3Service:
    """Register the existing terminal attempt-three identity as failed."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._failures = OrchestrationFailureV3Service(authorization)

    def register(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-attempt-command-v3.schema.json"):
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_MALFORMED", "failed-attempt command is malformed"
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
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_STALE", "failed-attempt command is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_retry_failed_attempts_v3 WHERE command_id=?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationAttemptV3Error(
                        "ORCHESTRATION_ATTEMPT_V3_IDENTITY_CONFLICT",
                        "failed-attempt command identity conflicts",
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                self._validate_receipt(replay, receipt)
                self._validate_current(connection, document, instant)
                return copy.deepcopy(receipt)
            failure = self._validate_current(connection, document, instant)
            receipt = _receipt(document, failure, command_digest, _timestamp(instant))
            if contract_issues(receipt, "orchestration-task-attempt-receipt-v3.schema.json"):
                raise OrchestrationAttemptV3Error(
                    "ORCHESTRATION_ATTEMPT_V3_RESULT_INVALID", "failed-attempt result is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_failed_attempts_v3(
                    attempt_id,command_id,command_digest,assessment_id,plan_id,plan_revision,
                    task_id,task_revision,failure_id,failure_receipt_digest,receipt_json,
                    receipt_hash,registered_at,authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                    (
                        document["retry_attempt_id"],
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["failure_id"],
                        document["failure_receipt_digest"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        receipt["registered_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationAttemptV3Error(
                    "ORCHESTRATION_ATTEMPT_V3_CONFLICT", "failed-attempt identity conflicts"
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.attempt_three_failed_attempt_registered",
                subject_type="orchestration_retry_failed_attempt",
                subject_id=document["retry_attempt_id"],
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=receipt["registered_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'orchestration_retry_failed_attempt',?,
                'orchestration.attempt_three_failed_attempt_registered',?)""",
                (
                    str(uuid4()),
                    document["retry_attempt_id"],
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": receipt["registered_at"],
                            "subject_id": document["retry_attempt_id"],
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        failure_row = connection.execute(
            "SELECT * FROM orchestration_task_failures_v3 WHERE failure_id=?",
            (document["failure_id"],),
        ).fetchone()
        attempt_row = connection.execute(
            "SELECT * FROM orchestration_retry_attempts_v2 WHERE attempt_id=?",
            (document["retry_attempt_id"],),
        ).fetchone()
        if failure_row is None or attempt_row is None:
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_LINEAGE_MISSING", "failed-attempt lineage is missing"
            )
        failure = cast(dict[str, Any], json.loads(failure_row["receipt_json"]))
        attempt = cast(dict[str, Any], json.loads(attempt_row["receipt_json"]))
        if (
            contract_issues(failure, "orchestration-task-failure-receipt-v3.schema.json")
            or contract_issues(attempt, "orchestration-retry-attempt-receipt-v2.schema.json")
            or failure_row["receipt_hash"] != content_hash(failure)
            or attempt_row["receipt_hash"] != content_hash(attempt)
            or document["failure_receipt_digest"] != "sha256:" + content_hash(failure)
            or document["retry_attempt_digest"] != attempt["attempt_digest"]
        ):
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_LINEAGE_INVALID", "failed-attempt lineage is invalid"
            )
        if (
            failure["retry_attempt_id"] != attempt["attempt_id"]
            or failure["retry_attempt_digest"] != attempt["attempt_digest"]
            or failure["attempt_number"] != 3
            or attempt["attempt_number"] != 3
            or attempt["attempt_state"] != "registered"
            or any(failure[key] != document[key] for key in ("assessment_id", "plan_id", "task_id"))
            or failure["resulting_plan_revision"] != document["expected_plan_revision"]
            or failure["resulting_task_revision"] != document["expected_task_revision"]
        ):
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_BINDING_MISMATCH", "failed-attempt binding mismatches"
            )
        try:
            self._failures._validate_replay(connection, failure, instant)
        except OrchestrationFailureV3Error as error:
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_SECURITY_DENIED",
                "current security state denies failed-attempt registration",
            ) from error
        return failure

    @staticmethod
    def _validate_receipt(row: sqlite3.Row, receipt: dict[str, Any]) -> None:
        expected = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "attempt_digest"}
        )
        if (
            contract_issues(receipt, "orchestration-task-attempt-receipt-v3.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["attempt_digest"] != expected
            or receipt["attempt_id"] != row["attempt_id"]
            or receipt["failure_id"] != row["failure_id"]
        ):
            raise OrchestrationAttemptV3Error(
                "ORCHESTRATION_ATTEMPT_V3_RESULT_INVALID", "failed-attempt result is invalid"
            )


def _receipt(
    document: dict[str, Any], failure: dict[str, Any], command_digest: str, registered_at: str
) -> dict[str, Any]:
    copied = (
        "assessment_id",
        "plan_id",
        "task_id",
        "agent_id",
        "retry_policy_id",
        "retry_policy_digest",
        "retry_activation_id",
        "retry_activation_digest",
        "retry_schedule_id",
        "retry_schedule_digest",
        "prior_retry_budget_consumption_id",
        "retry_budget_consumption_id",
        "capability_manifest_id",
        "capability_manifest_digest",
        "budget_reservation_id",
        "budget_request_digest",
        "budget_account_version",
        "approval_consumption_id",
        "worker_id",
        "worker_version",
        "lease_id",
        "lease_consumption_id",
        "lease_consumption_digest",
        "lease_generation",
        "fencing_token",
        "recovery_generation",
        "checkpoint_id",
        "checkpoint_sequence",
        "checkpoint_digest",
        "failure_class",
    )
    receipt = {key: failure[key] for key in copied}
    receipt.update(
        {
            "schema_version": "3.0.0",
            "attempt_id": document["retry_attempt_id"],
            "command_id": document["command_id"],
            "command_digest": command_digest,
            "plan_revision": document["expected_plan_revision"],
            "task_revision": document["expected_task_revision"],
            "retry_attempt_digest": document["retry_attempt_digest"],
            "failure_id": document["failure_id"],
            "failure_receipt_digest": document["failure_receipt_digest"],
            "attempt_number": 3,
            "attempt_state": "failed",
            "terminal_retry_ceiling": 3,
            "purpose": document["purpose"],
            "registered_at": registered_at,
            "attempt_digest": "",
            "authority": "none",
            "execution_enabled": False,
        }
    )
    receipt["attempt_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "attempt_digest"}
    )
    return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationAttemptV3Error("ORCHESTRATION_ATTEMPT_V3_CLOCK_INVALID", "clock invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
