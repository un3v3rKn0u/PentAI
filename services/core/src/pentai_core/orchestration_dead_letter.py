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
from pentai_core.orchestration_terminal import (
    OrchestrationTerminalConsumptionService,
    OrchestrationTerminalError,
    OrchestrationTerminalService,
)

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("f353c4ee-7587-4ad9-9af4-05b26715bac2")


class OrchestrationDeadLetterError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationDeadLetterRegistrationService:
    """Register inert metadata for one exact terminally consumed task."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._terminal = OrchestrationTerminalConsumptionService(authorization)
        self._decisions = OrchestrationTerminalService(authorization)

    def register(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(
            document, "orchestration-dead-letter-registration-command-v1.schema.json"
        ):
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_MALFORMED",
                "dead-letter registration command is malformed",
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
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_STALE",
                "dead-letter registration validity is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        registration_id = str(
            uuid5(_NAMESPACE, "register:" + document["terminal_consumption_id"])
        )
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_dead_letter_registrations WHERE command_id=?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationDeadLetterError(
                        "ORCHESTRATION_DEAD_LETTER_REGISTRATION_IDENTITY_CONFLICT",
                        "dead-letter registration command identity conflicts",
                    )
                receipt = self._stored_receipt(replay)
                self._validate_current(connection, document, instant)
                return copy.deepcopy(receipt)

            consumption, decision = self._validate_current(connection, document, instant)
            registered_at = _timestamp(instant)
            receipt = _receipt(
                document,
                consumption,
                decision,
                registration_id,
                command_digest,
                registered_at,
            )
            if contract_issues(
                receipt, "orchestration-dead-letter-registration-receipt-v1.schema.json"
            ):
                raise OrchestrationDeadLetterError(
                    "ORCHESTRATION_DEAD_LETTER_REGISTRATION_RESULT_INVALID",
                    "dead-letter registration result is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_dead_letter_registrations(
                    registration_id,command_id,command_digest,assessment_id,plan_id,
                    plan_revision,task_id,task_revision,terminal_consumption_id,
                    terminal_consumption_digest,terminal_decision_id,
                    terminal_decision_digest,receipt_json,receipt_hash,registered_at,
                    authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                    (
                        registration_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["terminal_consumption_id"],
                        document["terminal_consumption_digest"],
                        consumption["terminal_decision_id"],
                        consumption["terminal_decision_digest"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        registered_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationDeadLetterError(
                    "ORCHESTRATION_DEAD_LETTER_REGISTRATION_CONFLICT",
                    "dead-letter registration conflicts",
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.dead_letter_registered",
                subject_type="orchestration_dead_letter_registration",
                subject_id=registration_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=registered_at,
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'orchestration_dead_letter_registration',?,
                'orchestration.dead_letter_registered',?)""",
                (
                    str(uuid4()),
                    registration_id,
                    canonical_json(
                        {
                            "delivery_enabled": False,
                            "event_hash": audit["event_hash"],
                            "occurred_at": registered_at,
                            "subject_id": registration_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    def _validate_current(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        consumption_row = connection.execute(
            "SELECT * FROM orchestration_terminal_consumptions WHERE consumption_id=?",
            (document["terminal_consumption_id"],),
        ).fetchone()
        if consumption_row is None:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_MISSING",
                "terminal consumption is missing",
            )
        try:
            consumption = cast(
                dict[str, Any], json.loads(consumption_row["receipt_json"])
            )
            self._terminal._validate_receipt(consumption_row, consumption)
        except (json.JSONDecodeError, OrchestrationTerminalError) as error:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_INVALID",
                "terminal consumption is invalid",
            ) from error
        if (
            any(
                consumption_row[key] != consumption[key]
                for key in (
                    "consumption_id",
                    "command_id",
                    "command_digest",
                    "assessment_id",
                    "plan_id",
                    "plan_revision",
                    "task_id",
                    "expected_task_revision",
                    "resulting_task_revision",
                    "terminal_decision_id",
                    "terminal_decision_digest",
                )
            )
            or consumption_row["authority"] != "none"
            or consumption_row["execution_enabled"] != 0
        ):
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_INVALID",
                "terminal consumption is invalid",
            )
        decision_row = connection.execute(
            "SELECT * FROM orchestration_terminal_dispositions WHERE decision_id=?",
            (consumption["terminal_decision_id"],),
        ).fetchone()
        if decision_row is None:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_MISSING",
                "terminal decision is missing",
            )
        try:
            decision = cast(dict[str, Any], json.loads(decision_row["decision_json"]))
            self._decisions._validate_decision(decision_row, decision)
        except (json.JSONDecodeError, OrchestrationTerminalError) as error:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_INVALID",
                "terminal decision is invalid",
            ) from error
        if (
            document["terminal_consumption_digest"]
            != "sha256:" + consumption_row["receipt_hash"]
            or any(
                document[key] != consumption[key]
                for key in ("assessment_id", "plan_id", "task_id")
            )
            or document["expected_plan_revision"] != consumption["plan_revision"]
            or document["expected_task_revision"]
            != consumption["resulting_task_revision"]
            or consumption["resulting_task_state"] != "dead_letter"
            or consumption["queue_enabled"] is not False
            or consumption["operator_review_enabled"] is not False
            or consumption["terminal_decision_digest"]
            != "sha256:" + decision_row["decision_hash"]
            or decision["attempt_number"] != 3
            or decision["maximum_attempts"] != 3
            or decision["additional_attempts_permitted"] != 0
            or decision["outcome"] != "dead_letter_eligible"
            or decision["reason_code"] != "retry_ceiling_exhausted"
            or decision["queue_enabled"] is not False
            or decision["operator_review_enabled"] is not False
        ):
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_BINDING_MISMATCH",
                "dead-letter registration binding mismatches",
            )
        try:
            self._terminal._validate_current(
                connection,
                decision,
                instant,
                expected_task_state="dead_letter",
                expected_task_revision=consumption["resulting_task_revision"],
            )
        except OrchestrationTerminalError as error:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_SECURITY_DENIED",
                "current security state denies dead-letter registration",
            ) from error
        return consumption, decision

    @staticmethod
    def _stored_receipt(row: sqlite3.Row) -> dict[str, Any]:
        try:
            receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        except json.JSONDecodeError as error:
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_RESULT_INVALID",
                "dead-letter registration result is invalid",
            ) from error
        expected = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "receipt_digest"}
        )
        if (
            contract_issues(
                receipt, "orchestration-dead-letter-registration-receipt-v1.schema.json"
            )
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["receipt_digest"] != expected
            or receipt["registration_id"] != row["registration_id"]
            or any(
                receipt[key] != row[key]
                for key in (
                    "registration_id",
                    "command_id",
                    "command_digest",
                    "assessment_id",
                    "plan_id",
                    "plan_revision",
                    "task_id",
                    "task_revision",
                    "terminal_consumption_id",
                    "terminal_consumption_digest",
                    "terminal_decision_id",
                    "terminal_decision_digest",
                )
            )
            or row["authority"] != "none"
            or row["execution_enabled"] != 0
        ):
            raise OrchestrationDeadLetterError(
                "ORCHESTRATION_DEAD_LETTER_REGISTRATION_RESULT_INVALID",
                "dead-letter registration result is invalid",
            )
        return receipt


def _receipt(
    command: dict[str, Any],
    consumption: dict[str, Any],
    decision: dict[str, Any],
    registration_id: str,
    command_digest: str,
    registered_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "1.0.0",
        "registration_id": registration_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": consumption["assessment_id"],
        "plan_id": consumption["plan_id"],
        "plan_revision": consumption["plan_revision"],
        "task_id": consumption["task_id"],
        "task_revision": consumption["resulting_task_revision"],
        "task_state": "dead_letter",
        "terminal_consumption_id": consumption["consumption_id"],
        "terminal_consumption_digest": command["terminal_consumption_digest"],
        "terminal_decision_id": consumption["terminal_decision_id"],
        "terminal_decision_digest": consumption["terminal_decision_digest"],
        "attempt_number": decision["attempt_number"],
        "maximum_attempts": decision["maximum_attempts"],
        "outcome": "dead_letter_registered",
        "reason_code": decision["reason_code"],
        "registration_state": "registered",
        "retention_mode": "immutable_history",
        "delivery_enabled": False,
        "claim_enabled": False,
        "acknowledgement_enabled": False,
        "retry_enabled": False,
        "deletion_enabled": False,
        "cleanup_enabled": False,
        "operator_review_enabled": False,
        "purpose": command["purpose"],
        "registered_at": registered_at,
        "receipt_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["receipt_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    return receipt


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationDeadLetterError(
            "ORCHESTRATION_DEAD_LETTER_REGISTRATION_CLOCK_INVALID", "clock invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
