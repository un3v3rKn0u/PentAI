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
from pentai_core.orchestration_retry import (
    OrchestrationRetryError,
    OrchestrationRetryService,
)

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("6d737a5a-4e73-4c98-9adf-9f89b8f0dccc")


class OrchestrationRetryBudgetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryBudgetService:
    """Atomically consume one reserved retry unit without activating work."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._retry = OrchestrationRetryService(authorization)

    def consume(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(
            document, "orchestration-retry-budget-consumption-command-v1.schema.json"
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_COMMAND_MALFORMED",
                "retry budget consumption command is malformed",
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
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_COMMAND_STALE",
                "retry budget consumption command is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        consumption_id = str(uuid5(_NAMESPACE, "retry-budget:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT * FROM orchestration_retry_budget_consumptions
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryBudgetError(
                        "ORCHESTRATION_RETRY_BUDGET_IDENTITY_CONFLICT",
                        "retry budget consumption identity conflicts",
                    )
                receipt = self._load_receipt(replay)
                self._validate_replay(connection, document, receipt, instant)
                return copy.deepcopy(receipt)

            decision, attempt, policy = self._validate_decision(connection, document, instant)
            existing = connection.execute(
                """SELECT command_id FROM orchestration_retry_budget_consumptions
                WHERE eligibility_decision_id = ? OR attempt_id = ?
                OR (task_id = ? AND proposed_attempt_number = ?)""",
                (
                    decision["decision_id"],
                    attempt["attempt_id"],
                    attempt["task_id"],
                    decision["proposed_attempt_number"],
                ),
            ).fetchone()
            if existing is not None:
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_ALREADY_CONSUMED",
                    "retry budget was already consumed",
                )
            reservation, account, reserved_units, prior_consumed = self._load_budget(
                connection, document, decision, attempt, instant
            )
            if prior_consumed >= reserved_units:
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_EXHAUSTED",
                    "reserved retry capacity is exhausted",
                )
            version_before = int(account["version"])
            version_after = version_before + 1
            if version_after > 2**63 - 1:
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_VERSION_OVERFLOW",
                    "budget account version cannot advance",
                )
            remaining = reserved_units - prior_consumed - 1
            receipt = _receipt(
                document,
                decision,
                attempt,
                policy,
                reservation,
                consumption_id,
                command_digest,
                version_before,
                version_after,
                reserved_units,
                remaining,
                _timestamp(instant),
            )
            if contract_issues(
                receipt, "orchestration-retry-budget-consumption-receipt-v1.schema.json"
            ):
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_RECEIPT_INVALID",
                    "retry budget consumption receipt is invalid",
                )
            updated = connection.execute(
                """UPDATE orchestration_budget_accounts SET version = ?
                WHERE account_id = ? AND version = ?""",
                (version_after, reservation["account_id"], version_before),
            )
            if updated.rowcount != 1:
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_VERSION_FENCED",
                    "budget account version is fenced",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_budget_consumptions (
                    consumption_id, command_id, command_digest, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, attempt_id,
                    eligibility_decision_id, retry_policy_id, budget_account_id,
                    budget_reservation_id, proposed_attempt_number,
                    budget_account_version_before, budget_account_version_after,
                    consumed_retry_units, remaining_retry_units, receipt_json,
                    receipt_hash, consumed_at, authority, execution_enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, 1, ?, ?, ?, ?,
                    'none', 0)""",
                    (
                        consumption_id,
                        document["command_id"],
                        command_digest,
                        attempt["assessment_id"],
                        attempt["plan_id"],
                        attempt["plan_revision"],
                        attempt["task_id"],
                        attempt["task_revision"],
                        attempt["attempt_id"],
                        decision["decision_id"],
                        policy["retry_policy_id"],
                        reservation["account_id"],
                        reservation["reservation_id"],
                        version_before,
                        version_after,
                        remaining,
                        canonical_json(receipt),
                        content_hash(receipt),
                        receipt["consumed_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryBudgetError(
                    "ORCHESTRATION_RETRY_BUDGET_CONFLICT",
                    "retry budget consumption conflicts",
                ) from error
            _audit(connection, consumption_id, receipt)
        return copy.deepcopy(receipt)

    def _validate_decision(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_decisions WHERE decision_id = ?",
            (document["eligibility_decision_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_DECISION_MISSING",
                "retry eligibility decision is missing",
            )
        decision = cast(dict[str, Any], json.loads(row["decision_json"]))
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in decision.items() if key != "decision_digest"}
        )
        if (
            contract_issues(decision, "orchestration-retry-decision-v1.schema.json")
            or row["decision_hash"] != content_hash(decision)
            or decision["decision_digest"] != expected_digest
            or decision["decision_digest"] != document["eligibility_decision_digest"]
            or decision["outcome"] != "eligible"
            or decision["retry_units_consumed"] != 0
            or decision["proposed_attempt_number"] != document["proposed_attempt_number"]
            or decision["assessment_id"] != document["assessment_id"]
            or decision["plan_id"] != document["plan_id"]
            or decision["plan_revision"] != document["expected_plan_revision"]
            or decision["task_id"] != document["task_id"]
            or decision["task_revision"] != document["expected_task_revision"]
            or decision["attempt_id"] != document["attempt_id"]
            or decision["attempt_digest"] != document["attempt_digest"]
            or decision["retry_policy_id"] != document["retry_policy_id"]
            or decision["retry_policy_revision"] != document["retry_policy_revision"]
            or decision["retry_policy_digest"] != document["retry_policy_digest"]
            or decision["budget_reservation_id"] != document["budget_reservation_id"]
            or parse_time(decision["expires_at"]) <= instant
            or decision["earliest_retry_at"] is None
            or parse_time(decision["earliest_retry_at"]) > instant
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_DECISION_INVALID",
                "retry eligibility decision is invalid",
            )
        evaluation = {
            "attempt_id": document["attempt_id"],
            "attempt_digest": document["attempt_digest"],
            "assessment_id": document["assessment_id"],
            "plan_id": document["plan_id"],
            "expected_plan_revision": document["expected_plan_revision"],
            "task_id": document["task_id"],
            "expected_task_revision": document["expected_task_revision"],
            "retry_policy_id": document["retry_policy_id"],
            "retry_policy_revision": document["retry_policy_revision"],
            "retry_policy_digest": document["retry_policy_digest"],
        }
        try:
            attempt = self._retry._load_attempt(connection, evaluation)
            self._retry._validate_current_attempt(connection, attempt, instant)
            policy = self._retry._load_policy(connection, evaluation, attempt, instant)
        except OrchestrationRetryError as error:
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_SECURITY_DENIED",
                "current retry security state denies consumption",
            ) from error
        if not _decision_matches_attempt(decision, attempt, policy):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_LINEAGE_INVALID",
                "retry decision lineage is invalid",
            )
        return decision, attempt, policy

    @staticmethod
    def _load_budget(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        decision: dict[str, Any],
        attempt: dict[str, Any],
        instant: datetime,
    ) -> tuple[sqlite3.Row, sqlite3.Row, int, int]:
        reservation = connection.execute(
            """SELECT * FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (document["budget_reservation_id"],),
        ).fetchone()
        if reservation is None:
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_RESERVATION_MISSING",
                "budget reservation is missing",
            )
        reservation_receipt = json.loads(reservation["receipt_json"])
        amounts = json.loads(reservation["amounts_json"])
        if (
            contract_issues(
                reservation_receipt,
                "orchestration-task-budget-reservation-v2.schema.json",
            )
            or reservation_receipt["reservation_id"] != reservation["reservation_id"]
            or reservation_receipt["request_id"] != reservation["request_id"]
            or reservation_receipt["request_digest"] != reservation["request_digest"]
            or reservation_receipt["account_id"] != reservation["account_id"]
            or reservation_receipt["account_version"] != reservation["account_version"]
            or reservation_receipt["assessment_id"] != reservation["assessment_id"]
            or reservation_receipt["plan_id"] != reservation["plan_id"]
            or reservation_receipt["plan_revision"] != reservation["plan_revision"]
            or reservation_receipt["task_id"] != reservation["task_id"]
            or reservation_receipt["task_revision"] != reservation["task_revision"]
            or reservation_receipt["agent_id"] != reservation["agent_id"]
            or reservation_receipt["capability_manifest_id"]
            != reservation["capability_manifest_id"]
            or reservation_receipt["manifest_revision"] != reservation["manifest_revision"]
            or reservation_receipt["policy_bundle_id"] != reservation["policy_bundle_id"]
            or reservation_receipt["policy_hash"] != reservation["policy_hash"]
            or reservation_receipt["purpose"] != reservation["purpose"]
            or reservation_receipt["created_at"] != reservation["created_at"]
            or reservation_receipt["expires_at"] != reservation["expires_at"]
            or reservation["state"] != "reserved"
            or reservation_receipt["state"] != "reserved"
            or reservation_receipt["amounts"] != amounts
            or reservation["task_state"] != "ready"
            or reservation_receipt["task_state"] != "ready"
            or reservation["assessment_id"] != attempt["assessment_id"]
            or reservation["plan_id"] != attempt["plan_id"]
            or reservation["task_id"] != attempt["task_id"]
            or reservation["agent_id"] != attempt["agent_id"]
            or reservation["capability_manifest_id"] != attempt["capability_manifest_id"]
            or reservation["manifest_revision"] != attempt["manifest_revision"]
            or reservation["policy_bundle_id"] != attempt["policy_bundle_id"]
            or reservation["policy_hash"] != attempt["policy_hash"]
            or reservation["account_version"] != attempt["budget_account_version"]
            or reservation["account_version"] != decision["budget_account_version"]
            or parse_time(reservation["expires_at"]) <= instant
            or not isinstance(amounts.get("retries"), int)
            or isinstance(amounts.get("retries"), bool)
            or amounts["retries"] < 1
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_RESERVATION_INVALID",
                "budget reservation is invalid",
            )
        account = connection.execute(
            "SELECT * FROM orchestration_budget_accounts WHERE account_id = ?",
            (reservation["account_id"],),
        ).fetchone()
        if (
            account is None
            or account["assessment_id"] != attempt["assessment_id"]
            or account["policy_bundle_id"] != attempt["policy_bundle_id"]
            or account["policy_hash"] != attempt["policy_hash"]
            or parse_time(account["expires_at"]) <= instant
            or account["version"] != document["expected_budget_account_version"]
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_VERSION_FENCED",
                "budget account is stale or mismatched",
            )
        consumed = connection.execute(
            """SELECT COALESCE(SUM(consumed_retry_units), 0)
            FROM orchestration_retry_budget_consumptions WHERE budget_reservation_id = ?""",
            (reservation["reservation_id"],),
        ).fetchone()[0]
        return reservation, account, int(amounts["retries"]), int(consumed)

    @staticmethod
    def _load_receipt(row: sqlite3.Row) -> dict[str, Any]:
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "receipt_digest"}
        )
        if (
            contract_issues(
                receipt, "orchestration-retry-budget-consumption-receipt-v1.schema.json"
            )
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["receipt_digest"] != expected_digest
            or receipt["consumption_id"] != row["consumption_id"]
            or receipt["command_id"] != row["command_id"]
            or receipt["command_digest"] != row["command_digest"]
            or receipt["assessment_id"] != row["assessment_id"]
            or receipt["plan_id"] != row["plan_id"]
            or receipt["plan_revision"] != row["plan_revision"]
            or receipt["task_id"] != row["task_id"]
            or receipt["task_revision"] != row["task_revision"]
            or receipt["attempt_id"] != row["attempt_id"]
            or receipt["eligibility_decision_id"] != row["eligibility_decision_id"]
            or receipt["retry_policy_id"] != row["retry_policy_id"]
            or receipt["budget_account_id"] != row["budget_account_id"]
            or receipt["budget_reservation_id"] != row["budget_reservation_id"]
            or receipt["proposed_attempt_number"] != row["proposed_attempt_number"]
            or receipt["budget_account_version_before"] != row["budget_account_version_before"]
            or receipt["budget_account_version_after"] != row["budget_account_version_after"]
            or receipt["consumed_retry_units"] != row["consumed_retry_units"]
            or receipt["remaining_retry_units"] != row["remaining_retry_units"]
            or receipt["consumed_at"] != row["consumed_at"]
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_RECEIPT_INVALID",
                "retry budget consumption receipt is invalid",
            )
        return receipt

    def _validate_replay(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        receipt: dict[str, Any],
        instant: datetime,
    ) -> None:
        decision, attempt, _ = self._validate_decision(connection, document, instant)
        reservation = connection.execute(
            """SELECT state FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (receipt["budget_reservation_id"],),
        ).fetchone()
        account = connection.execute(
            "SELECT version FROM orchestration_budget_accounts WHERE account_id = ?",
            (receipt["budget_account_id"],),
        ).fetchone()
        if (
            receipt["eligibility_decision_id"] != decision["decision_id"]
            or receipt["attempt_id"] != attempt["attempt_id"]
            or reservation is None
            or reservation["state"] != "reserved"
            or account is None
            or account["version"] != receipt["budget_account_version_after"]
        ):
            raise OrchestrationRetryBudgetError(
                "ORCHESTRATION_RETRY_BUDGET_REPLAY_FENCED",
                "retry budget consumption replay is no longer current",
            )


def _decision_matches_attempt(
    decision: dict[str, Any], attempt: dict[str, Any], policy: dict[str, Any]
) -> bool:
    fields = (
        "assessment_id",
        "plan_id",
        "task_id",
        "attempt_id",
        "attempt_digest",
        "failure_id",
        "failure_receipt_digest",
        "failure_class",
        "checkpoint_id",
        "checkpoint_digest",
        "lease_consumption_id",
        "worker_id",
        "worker_version",
        "lease_generation",
        "fencing_token",
        "recovery_generation",
        "capability_manifest_id",
        "manifest_revision",
        "budget_reservation_id",
        "budget_account_version",
        "approval_consumption_id",
        "policy_bundle_id",
        "policy_hash",
    )
    return (
        all(decision[field] == attempt[field] for field in fields)
        and decision["plan_revision"] == attempt["plan_revision"]
        and decision["task_revision"] == attempt["task_revision"]
        and decision["retry_policy_id"] == policy["retry_policy_id"]
        and decision["retry_policy_revision"] == policy["revision"]
        and decision["retry_policy_digest"] == policy["policy_digest"]
    )


def _receipt(
    command: dict[str, Any],
    decision: dict[str, Any],
    attempt: dict[str, Any],
    policy: dict[str, Any],
    reservation: sqlite3.Row,
    consumption_id: str,
    command_digest: str,
    version_before: int,
    version_after: int,
    reserved_units: int,
    remaining_units: int,
    consumed_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "1.0.0",
        "consumption_id": consumption_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "task_revision": attempt["task_revision"],
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "failure_id": attempt["failure_id"],
        "failure_receipt_digest": attempt["failure_receipt_digest"],
        "checkpoint_id": attempt["checkpoint_id"],
        "checkpoint_digest": attempt["checkpoint_digest"],
        "lease_consumption_id": attempt["lease_consumption_id"],
        "worker_id": attempt["worker_id"],
        "worker_version": attempt["worker_version"],
        "lease_generation": attempt["lease_generation"],
        "fencing_token": attempt["fencing_token"],
        "recovery_generation": attempt["recovery_generation"],
        "capability_manifest_id": attempt["capability_manifest_id"],
        "manifest_revision": attempt["manifest_revision"],
        "budget_account_id": reservation["account_id"],
        "budget_reservation_id": reservation["reservation_id"],
        "budget_reservation_account_version": reservation["account_version"],
        "budget_account_version_before": version_before,
        "budget_account_version_after": version_after,
        "reserved_retry_units": reserved_units,
        "consumed_retry_units": 1,
        "remaining_retry_units": remaining_units,
        "approval_consumption_id": attempt["approval_consumption_id"],
        "policy_bundle_id": attempt["policy_bundle_id"],
        "policy_hash": attempt["policy_hash"],
        "retry_policy_id": policy["retry_policy_id"],
        "retry_policy_revision": policy["revision"],
        "retry_policy_digest": policy["policy_digest"],
        "eligibility_decision_id": decision["decision_id"],
        "eligibility_decision_digest": decision["decision_digest"],
        "proposed_attempt_number": decision["proposed_attempt_number"],
        "purpose": command["purpose"],
        "consumed_at": consumed_at,
        "receipt_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["receipt_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    return receipt


def _audit(connection: sqlite3.Connection, consumption_id: str, receipt: dict[str, Any]) -> None:
    event = append_audit_event(
        connection,
        action="orchestration.retry_budget_consumed",
        subject_type="orchestration_retry_budget",
        subject_id=consumption_id,
        actor_type="service",
        actor_id="pentai-core",
        data=receipt,
        occurred_at=receipt["consumed_at"],
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_retry_budget', ?,
        'orchestration.retry_budget_consumed', ?)""",
        (
            str(uuid4()),
            consumption_id,
            canonical_json({"event_hash": event["event_hash"], "subject_id": consumption_id}),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryBudgetError(
            "ORCHESTRATION_RETRY_BUDGET_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
