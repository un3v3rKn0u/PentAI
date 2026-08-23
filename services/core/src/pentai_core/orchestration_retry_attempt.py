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
from pentai_core.orchestration_retry_budget import (
    OrchestrationRetryBudgetError,
    OrchestrationRetryBudgetService,
)

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("63baaceb-c1fc-480a-af30-b8fbd8b352e5")


class OrchestrationRetryAttemptError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryAttemptService:
    """Register immutable, non-activating identity for retry attempt two."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._budget = OrchestrationRetryBudgetService(authorization)

    def register(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-retry-attempt-command-v1.schema.json"):
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_COMMAND_MALFORMED",
                "retry attempt command is malformed",
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
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_COMMAND_STALE",
                "retry attempt command is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        attempt_id = str(
            uuid5(_NAMESPACE, "retry-attempt:" + document["retry_budget_consumption_id"])
        )
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_retry_attempts WHERE command_id = ?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryAttemptError(
                        "ORCHESTRATION_RETRY_ATTEMPT_IDENTITY_CONFLICT",
                        "retry attempt identity conflicts",
                    )
                receipt = self._load_receipt(replay)
                self._validate_current(connection, document, receipt, instant)
                return copy.deepcopy(receipt)

            consumption, prior_attempt, decision = self._validate_consumption(
                connection, document, instant
            )
            existing = connection.execute(
                """SELECT command_id FROM orchestration_retry_attempts
                WHERE prior_attempt_id = ? OR retry_budget_consumption_id = ?
                OR (task_id = ? AND attempt_number = 2)""",
                (
                    prior_attempt["attempt_id"],
                    consumption["consumption_id"],
                    prior_attempt["task_id"],
                ),
            ).fetchone()
            if existing is not None:
                raise OrchestrationRetryAttemptError(
                    "ORCHESTRATION_RETRY_ATTEMPT_ALREADY_REGISTERED",
                    "retry attempt was already registered",
                )
            receipt = _receipt(
                document,
                consumption,
                prior_attempt,
                decision,
                attempt_id,
                command_digest,
                _timestamp(instant),
            )
            if contract_issues(receipt, "orchestration-retry-attempt-receipt-v1.schema.json"):
                raise OrchestrationRetryAttemptError(
                    "ORCHESTRATION_RETRY_ATTEMPT_RECEIPT_INVALID",
                    "retry attempt receipt is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_attempts (
                    attempt_id, command_id, command_digest, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, prior_attempt_id,
                    retry_budget_consumption_id, attempt_number, attempt_state,
                    receipt_json, receipt_hash, registered_at, authority, execution_enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, 'registered', ?, ?, ?,
                    'none', 0)""",
                    (
                        attempt_id,
                        document["command_id"],
                        command_digest,
                        prior_attempt["assessment_id"],
                        prior_attempt["plan_id"],
                        prior_attempt["plan_revision"],
                        prior_attempt["task_id"],
                        prior_attempt["task_revision"],
                        prior_attempt["attempt_id"],
                        consumption["consumption_id"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        receipt["registered_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryAttemptError(
                    "ORCHESTRATION_RETRY_ATTEMPT_CONFLICT",
                    "retry attempt registration conflicts",
                ) from error
            _audit(connection, attempt_id, receipt)
        return copy.deepcopy(receipt)

    def _validate_consumption(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        row = connection.execute(
            """SELECT * FROM orchestration_retry_budget_consumptions
            WHERE consumption_id = ?""",
            (document["retry_budget_consumption_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_MISSING",
                "retry budget consumption is missing",
            )
        try:
            consumption = self._budget._load_receipt(row)
        except OrchestrationRetryBudgetError as error:
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_INVALID",
                "retry budget consumption is invalid",
            ) from error
        if (
            consumption["receipt_digest"] != document["retry_budget_consumption_digest"]
            or consumption["assessment_id"] != document["assessment_id"]
            or consumption["plan_id"] != document["plan_id"]
            or consumption["plan_revision"] != document["expected_plan_revision"]
            or consumption["task_id"] != document["task_id"]
            or consumption["task_revision"] != document["expected_task_revision"]
            or consumption["attempt_id"] != document["prior_attempt_id"]
            or consumption["attempt_digest"] != document["prior_attempt_digest"]
            or consumption["proposed_attempt_number"] != document["attempt_number"]
            or consumption["consumed_retry_units"] != 1
            or parse_time(consumption["consumed_at"]) > instant
            or parse_time(document["requested_at"]) < parse_time(consumption["consumed_at"])
        ):
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_CONSUMPTION_MISMATCH",
                "retry budget consumption binding mismatches",
            )
        validation = _consumption_validation_document(consumption)
        try:
            self._budget._validate_replay(connection, validation, consumption, instant)
        except OrchestrationRetryBudgetError as error:
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_SECURITY_DENIED",
                "current security state denies retry attempt registration",
            ) from error
        prior_row = connection.execute(
            "SELECT * FROM orchestration_task_attempts WHERE attempt_id = ?",
            (document["prior_attempt_id"],),
        ).fetchone()
        decision_row = connection.execute(
            "SELECT * FROM orchestration_retry_decisions WHERE decision_id = ?",
            (consumption["eligibility_decision_id"],),
        ).fetchone()
        if prior_row is None or decision_row is None:
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_LINEAGE_MISSING",
                "retry attempt lineage is missing",
            )
        prior_attempt = cast(dict[str, Any], json.loads(prior_row["receipt_json"]))
        decision = cast(dict[str, Any], json.loads(decision_row["decision_json"]))
        expected_prior_digest = "sha256:" + content_hash(
            {key: value for key, value in prior_attempt.items() if key != "attempt_digest"}
        )
        if (
            contract_issues(prior_attempt, "orchestration-task-attempt-receipt-v1.schema.json")
            or prior_row["receipt_hash"] != content_hash(prior_attempt)
            or prior_attempt["attempt_id"] != prior_row["attempt_id"]
            or prior_attempt["attempt_digest"] != expected_prior_digest
            or prior_attempt["attempt_digest"] != document["prior_attempt_digest"]
            or prior_attempt["attempt_number"] + 1 != document["attempt_number"]
            or decision_row["decision_hash"] != content_hash(decision)
            or decision["decision_digest"] != consumption["eligibility_decision_digest"]
            or decision["outcome"] != "eligible"
            or decision["proposed_attempt_number"] != document["attempt_number"]
            or decision["earliest_retry_at"] is None
            or parse_time(decision["earliest_retry_at"]) > instant
            or parse_time(document["expires_at"]) > parse_time(decision["expires_at"])
        ):
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_LINEAGE_INVALID",
                "retry attempt lineage is invalid",
            )
        return consumption, prior_attempt, decision

    def _validate_current(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        receipt: dict[str, Any],
        instant: datetime,
    ) -> None:
        consumption, prior_attempt, _ = self._validate_consumption(connection, document, instant)
        if (
            receipt["retry_budget_consumption_id"] != consumption["consumption_id"]
            or receipt["prior_attempt_id"] != prior_attempt["attempt_id"]
            or receipt["attempt_number"] != prior_attempt["attempt_number"] + 1
        ):
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_REPLAY_FENCED",
                "retry attempt replay is no longer current",
            )

    @staticmethod
    def _load_receipt(row: sqlite3.Row) -> dict[str, Any]:
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "attempt_digest"}
        )
        if (
            contract_issues(receipt, "orchestration-retry-attempt-receipt-v1.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["attempt_digest"] != expected_digest
            or receipt["attempt_id"] != row["attempt_id"]
            or receipt["command_id"] != row["command_id"]
            or receipt["command_digest"] != row["command_digest"]
            or receipt["assessment_id"] != row["assessment_id"]
            or receipt["plan_id"] != row["plan_id"]
            or receipt["plan_revision"] != row["plan_revision"]
            or receipt["task_id"] != row["task_id"]
            or receipt["task_revision"] != row["task_revision"]
            or receipt["prior_attempt_id"] != row["prior_attempt_id"]
            or receipt["retry_budget_consumption_id"] != row["retry_budget_consumption_id"]
            or receipt["attempt_number"] != row["attempt_number"]
            or receipt["attempt_state"] != row["attempt_state"]
            or receipt["registered_at"] != row["registered_at"]
        ):
            raise OrchestrationRetryAttemptError(
                "ORCHESTRATION_RETRY_ATTEMPT_RECEIPT_INVALID",
                "retry attempt receipt is invalid",
            )
        return receipt


def _consumption_validation_document(consumption: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": consumption["assessment_id"],
        "plan_id": consumption["plan_id"],
        "expected_plan_revision": consumption["plan_revision"],
        "task_id": consumption["task_id"],
        "expected_task_revision": consumption["task_revision"],
        "attempt_id": consumption["attempt_id"],
        "attempt_digest": consumption["attempt_digest"],
        "eligibility_decision_id": consumption["eligibility_decision_id"],
        "eligibility_decision_digest": consumption["eligibility_decision_digest"],
        "retry_policy_id": consumption["retry_policy_id"],
        "retry_policy_revision": consumption["retry_policy_revision"],
        "retry_policy_digest": consumption["retry_policy_digest"],
        "budget_reservation_id": consumption["budget_reservation_id"],
        "expected_budget_account_version": consumption["budget_account_version_before"],
        "proposed_attempt_number": consumption["proposed_attempt_number"],
    }


def _receipt(
    command: dict[str, Any],
    consumption: dict[str, Any],
    prior_attempt: dict[str, Any],
    decision: dict[str, Any],
    attempt_id: str,
    command_digest: str,
    registered_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "1.0.0",
        "attempt_id": attempt_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": prior_attempt["assessment_id"],
        "plan_id": prior_attempt["plan_id"],
        "plan_revision": prior_attempt["plan_revision"],
        "task_id": prior_attempt["task_id"],
        "task_revision": prior_attempt["task_revision"],
        "agent_id": prior_attempt["agent_id"],
        "prior_attempt_id": prior_attempt["attempt_id"],
        "prior_attempt_digest": prior_attempt["attempt_digest"],
        "failure_id": prior_attempt["failure_id"],
        "failure_receipt_digest": prior_attempt["failure_receipt_digest"],
        "failure_class": prior_attempt["failure_class"],
        "checkpoint_id": prior_attempt["checkpoint_id"],
        "checkpoint_digest": prior_attempt["checkpoint_digest"],
        "lease_consumption_id": prior_attempt["lease_consumption_id"],
        "worker_id": prior_attempt["worker_id"],
        "worker_version": prior_attempt["worker_version"],
        "lease_generation": prior_attempt["lease_generation"],
        "fencing_token": prior_attempt["fencing_token"],
        "recovery_generation": prior_attempt["recovery_generation"],
        "capability_manifest_id": prior_attempt["capability_manifest_id"],
        "manifest_revision": prior_attempt["manifest_revision"],
        "budget_account_id": consumption["budget_account_id"],
        "budget_reservation_id": prior_attempt["budget_reservation_id"],
        "budget_reservation_account_version": prior_attempt["budget_account_version"],
        "budget_account_version": consumption["budget_account_version_after"],
        "approval_consumption_id": prior_attempt["approval_consumption_id"],
        "policy_bundle_id": prior_attempt["policy_bundle_id"],
        "policy_hash": prior_attempt["policy_hash"],
        "retry_policy_id": consumption["retry_policy_id"],
        "retry_policy_revision": consumption["retry_policy_revision"],
        "retry_policy_digest": consumption["retry_policy_digest"],
        "eligibility_decision_id": consumption["eligibility_decision_id"],
        "eligibility_decision_digest": consumption["eligibility_decision_digest"],
        "retry_budget_consumption_id": consumption["consumption_id"],
        "retry_budget_consumption_digest": consumption["receipt_digest"],
        "attempt_number": 2,
        "attempt_state": "registered",
        "earliest_retry_at": decision["earliest_retry_at"],
        "purpose": command["purpose"],
        "registered_at": registered_at,
        "attempt_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["attempt_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "attempt_digest"}
    )
    return receipt


def _audit(connection: sqlite3.Connection, attempt_id: str, receipt: dict[str, Any]) -> None:
    event = append_audit_event(
        connection,
        action="orchestration.retry_attempt_registered",
        subject_type="orchestration_retry_attempt",
        subject_id=attempt_id,
        actor_type="service",
        actor_id="pentai-core",
        data=receipt,
        occurred_at=receipt["registered_at"],
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_retry_attempt', ?,
        'orchestration.retry_attempt_registered', ?)""",
        (
            str(uuid4()),
            attempt_id,
            canonical_json({"event_hash": event["event_hash"], "subject_id": attempt_id}),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryAttemptError(
            "ORCHESTRATION_RETRY_ATTEMPT_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
