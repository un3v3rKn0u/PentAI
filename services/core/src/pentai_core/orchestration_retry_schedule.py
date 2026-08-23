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
from pentai_core.authorization import AuthorizationService
from pentai_core.database import transaction
from pentai_core.orchestration_retry_attempt import (
    OrchestrationRetryAttemptError,
    OrchestrationRetryAttemptService,
)

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("22a6a39d-8b32-43ec-a807-77f6cfebfb7a")


class OrchestrationRetryScheduleError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryScheduleService:
    """Register immutable retry timing without activating orchestration work."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._attempts = OrchestrationRetryAttemptService(authorization)

    def register(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-retry-schedule-command-v1.schema.json"):
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_COMMAND_MALFORMED",
                "retry schedule command is malformed",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        expires_at = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_COMMAND_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > _MAX_COMMAND_VALIDITY
        ):
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_COMMAND_STALE",
                "retry schedule command is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        schedule_id = str(uuid5(_NAMESPACE, "retry-schedule:" + document["attempt_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_retry_schedules WHERE command_id = ?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryScheduleError(
                        "ORCHESTRATION_RETRY_SCHEDULE_IDENTITY_CONFLICT",
                        "retry schedule identity conflicts",
                    )
                receipt = self._load_receipt(replay)
                attempt = self._validate_attempt(connection, document, instant)
                if (
                    receipt["attempt_id"] != attempt["attempt_id"]
                    or receipt["attempt_digest"] != attempt["attempt_digest"]
                    or receipt["scheduled_for"] != attempt["earliest_retry_at"]
                ):
                    raise OrchestrationRetryScheduleError(
                        "ORCHESTRATION_RETRY_SCHEDULE_REPLAY_FENCED",
                        "retry schedule replay is no longer current",
                    )
                return copy.deepcopy(receipt)

            attempt = self._validate_attempt(connection, document, instant)
            existing = connection.execute(
                """SELECT command_id FROM orchestration_retry_schedules
                WHERE attempt_id = ? OR retry_budget_consumption_id = ?
                OR (task_id = ? AND schedule_revision = 1)""",
                (
                    attempt["attempt_id"],
                    attempt["retry_budget_consumption_id"],
                    attempt["task_id"],
                ),
            ).fetchone()
            if existing is not None:
                raise OrchestrationRetryScheduleError(
                    "ORCHESTRATION_RETRY_SCHEDULE_ALREADY_REGISTERED",
                    "retry schedule was already registered",
                )
            receipt = _receipt(
                document,
                attempt,
                schedule_id,
                command_digest,
                _timestamp(instant),
            )
            if contract_issues(receipt, "orchestration-retry-schedule-receipt-v1.schema.json"):
                raise OrchestrationRetryScheduleError(
                    "ORCHESTRATION_RETRY_SCHEDULE_RECEIPT_INVALID",
                    "retry schedule receipt is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_schedules (
                    schedule_id, command_id, command_digest, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, attempt_id,
                    retry_budget_consumption_id, schedule_revision, schedule_state,
                    scheduled_for, expires_at, receipt_json, receipt_hash, registered_at,
                    authority, execution_enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'registered', ?, ?, ?, ?, ?,
                    'none', 0)""",
                    (
                        schedule_id,
                        document["command_id"],
                        command_digest,
                        attempt["assessment_id"],
                        attempt["plan_id"],
                        attempt["plan_revision"],
                        attempt["task_id"],
                        attempt["task_revision"],
                        attempt["attempt_id"],
                        attempt["retry_budget_consumption_id"],
                        receipt["scheduled_for"],
                        receipt["expires_at"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        receipt["registered_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryScheduleError(
                    "ORCHESTRATION_RETRY_SCHEDULE_CONFLICT",
                    "retry schedule registration conflicts",
                ) from error
            _audit(connection, schedule_id, receipt)
        return copy.deepcopy(receipt)

    def _validate_attempt(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_attempts WHERE attempt_id = ?",
            (document["attempt_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISSING",
                "retry attempt is missing",
            )
        try:
            attempt = self._attempts._load_receipt(row)
        except OrchestrationRetryAttemptError as error:
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_INVALID",
                "retry attempt is invalid",
            ) from error
        if (
            attempt["attempt_digest"] != document["attempt_digest"]
            or attempt["assessment_id"] != document["assessment_id"]
            or attempt["plan_id"] != document["plan_id"]
            or attempt["plan_revision"] != document["expected_plan_revision"]
            or attempt["task_id"] != document["task_id"]
            or attempt["task_revision"] != document["expected_task_revision"]
            or attempt["attempt_number"] != 2
            or attempt["attempt_state"] != "registered"
            or parse_time(attempt["registered_at"]) > parse_time(document["requested_at"])
            or parse_time(attempt["earliest_retry_at"]) > instant
            or parse_time(attempt["earliest_retry_at"]) > parse_time(document["requested_at"])
        ):
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_ATTEMPT_MISMATCH",
                "retry attempt binding mismatches",
            )
        validation = {
            "schema_version": "1.0.0",
            "command_id": attempt["command_id"],
            "assessment_id": attempt["assessment_id"],
            "plan_id": attempt["plan_id"],
            "expected_plan_revision": attempt["plan_revision"],
            "task_id": attempt["task_id"],
            "expected_task_revision": attempt["task_revision"],
            "prior_attempt_id": attempt["prior_attempt_id"],
            "prior_attempt_digest": attempt["prior_attempt_digest"],
            "retry_budget_consumption_id": attempt["retry_budget_consumption_id"],
            "retry_budget_consumption_digest": attempt["retry_budget_consumption_digest"],
            "attempt_number": 2,
            "purpose": "register_validation_retry_attempt",
            "requested_at": document["requested_at"],
            "expires_at": document["expires_at"],
            "authority": "none",
            "execution_enabled": False,
        }
        try:
            self._attempts._validate_current(connection, validation, attempt, instant)
        except OrchestrationRetryAttemptError as error:
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_SECURITY_DENIED",
                "current security state denies retry scheduling",
            ) from error
        return attempt

    @staticmethod
    def _load_receipt(row: sqlite3.Row) -> dict[str, Any]:
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "schedule_digest"}
        )
        if (
            contract_issues(receipt, "orchestration-retry-schedule-receipt-v1.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["schedule_digest"] != expected_digest
            or receipt["schedule_id"] != row["schedule_id"]
            or receipt["command_id"] != row["command_id"]
            or receipt["command_digest"] != row["command_digest"]
            or receipt["attempt_id"] != row["attempt_id"]
            or receipt["retry_budget_consumption_id"] != row["retry_budget_consumption_id"]
            or receipt["schedule_revision"] != row["schedule_revision"]
            or receipt["schedule_state"] != row["schedule_state"]
            or receipt["scheduled_for"] != row["scheduled_for"]
            or receipt["expires_at"] != row["expires_at"]
            or receipt["registered_at"] != row["registered_at"]
        ):
            raise OrchestrationRetryScheduleError(
                "ORCHESTRATION_RETRY_SCHEDULE_RECEIPT_INVALID",
                "retry schedule receipt is invalid",
            )
        return receipt


def _receipt(
    command: dict[str, Any],
    attempt: dict[str, Any],
    schedule_id: str,
    command_digest: str,
    registered_at: str,
) -> dict[str, Any]:
    copied = (
        "assessment_id", "plan_id", "plan_revision", "task_id", "task_revision",
        "agent_id", "attempt_id", "attempt_digest", "attempt_number", "prior_attempt_id",
        "failure_id", "failure_receipt_digest", "checkpoint_id", "checkpoint_digest",
        "lease_consumption_id", "worker_id", "worker_version", "lease_generation",
        "fencing_token", "recovery_generation", "capability_manifest_id",
        "manifest_revision", "budget_account_id", "budget_reservation_id",
        "budget_account_version", "approval_consumption_id", "policy_bundle_id",
        "policy_hash", "retry_policy_id", "retry_policy_revision", "retry_policy_digest",
        "eligibility_decision_id", "eligibility_decision_digest",
        "retry_budget_consumption_id", "retry_budget_consumption_digest",
    )
    receipt = {key: attempt[key] for key in copied}
    receipt.update(
        {
            "schema_version": "1.0.0",
            "schedule_id": schedule_id,
            "command_id": command["command_id"],
            "command_digest": command_digest,
            "schedule_revision": 1,
            "schedule_state": "registered",
            "scheduled_for": attempt["earliest_retry_at"],
            "expires_at": command["expires_at"],
            "purpose": command["purpose"],
            "registered_at": registered_at,
            "schedule_digest": "",
            "authority": "none",
            "execution_enabled": False,
        }
    )
    receipt["schedule_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "schedule_digest"}
    )
    return receipt


def _audit(connection: sqlite3.Connection, schedule_id: str, receipt: dict[str, Any]) -> None:
    event = append_audit_event(
        connection,
        action="orchestration.retry_schedule_registered",
        subject_type="orchestration_retry_schedule",
        subject_id=schedule_id,
        actor_type="service",
        actor_id="pentai-core",
        data=receipt,
        occurred_at=receipt["registered_at"],
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_retry_schedule', ?,
        'orchestration.retry_schedule_registered', ?)""",
        (
            str(uuid4()),
            schedule_id,
            canonical_json({"event_hash": event["event_hash"], "subject_id": schedule_id}),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryScheduleError(
            "ORCHESTRATION_RETRY_SCHEDULE_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
