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
from pentai_core.orchestration_failure_v3 import (
    OrchestrationFailureV3Error,
    OrchestrationFailureV3Service,
)

_MAX_AGE = timedelta(minutes=1)
_MAX_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("96a74053-ae22-4b85-ae06-58dc5e8083a5")


class OrchestrationTerminalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationTerminalService:
    """Record inert dead-letter eligibility at the closed attempt ceiling."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._failures = OrchestrationFailureV3Service(authorization)

    def decide(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(
            document, "orchestration-terminal-disposition-command-v1.schema.json"
        ):
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_MALFORMED", "terminal command is malformed"
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
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_STALE", "terminal command validity is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        decision_id = str(uuid5(_NAMESPACE, "terminal:" + document["failed_attempt_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_terminal_dispositions WHERE command_id=?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationTerminalError(
                        "ORCHESTRATION_TERMINAL_IDENTITY_CONFLICT",
                        "terminal command identity conflicts",
                    )
                decision = cast(dict[str, Any], json.loads(replay["decision_json"]))
                self._validate_decision(replay, decision)
                self._validate_current(connection, document, instant)
                return copy.deepcopy(decision)
            failed_attempt = self._validate_current(connection, document, instant)
            decision = _decision(
                document, failed_attempt, decision_id, command_digest, _timestamp(instant)
            )
            if contract_issues(
                decision, "orchestration-terminal-disposition-decision-v1.schema.json"
            ):
                raise OrchestrationTerminalError(
                    "ORCHESTRATION_TERMINAL_RESULT_INVALID", "terminal decision is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_terminal_dispositions(
                    decision_id,command_id,command_digest,assessment_id,plan_id,
                    plan_revision,task_id,task_revision,failed_attempt_id,
                    failed_attempt_digest,failure_id,failure_receipt_digest,
                    retry_policy_id,retry_policy_digest,outcome,
                    reason_code,decision_json,decision_hash,decided_at,authority,
                    execution_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                    (
                        decision_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["failed_attempt_id"],
                        document["failed_attempt_digest"],
                        decision["failure_id"],
                        decision["failure_receipt_digest"],
                        document["retry_policy_id"],
                        document["retry_policy_digest"],
                        decision["outcome"],
                        decision["reason_code"],
                        canonical_json(decision),
                        content_hash(decision),
                        decision["decided_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationTerminalError(
                    "ORCHESTRATION_TERMINAL_CONFLICT", "terminal decision conflicts"
                ) from error
            audit = append_audit_event(
                connection,
                action="orchestration.terminal_disposition_decided",
                subject_type="orchestration_terminal_disposition",
                subject_id=decision_id,
                actor_type="service",
                actor_id="pentai-core",
                data=decision,
                occurred_at=decision["decided_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json)
                VALUES (?,'orchestration_terminal_disposition',?,
                'orchestration.terminal_disposition_decided',?)""",
                (
                    str(uuid4()),
                    decision_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": decision["decided_at"],
                            "subject_id": decision_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(decision)

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        attempt_row = connection.execute(
            "SELECT * FROM orchestration_retry_failed_attempts_v3 WHERE attempt_id=?",
            (document["failed_attempt_id"],),
        ).fetchone()
        policy_row = connection.execute(
            "SELECT * FROM orchestration_retry_policies_v2 WHERE retry_policy_id=?",
            (document["retry_policy_id"],),
        ).fetchone()
        if attempt_row is None or policy_row is None:
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_LINEAGE_MISSING", "terminal lineage is missing"
            )
        failed_attempt = cast(dict[str, Any], json.loads(attempt_row["receipt_json"]))
        policy = cast(dict[str, Any], json.loads(policy_row["policy_json"]))
        failure_row = connection.execute(
            "SELECT * FROM orchestration_task_failures_v3 WHERE failure_id=?",
            (failed_attempt["failure_id"],),
        ).fetchone()
        if failure_row is None:
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_LINEAGE_MISSING", "terminal failure is missing"
            )
        failure = cast(dict[str, Any], json.loads(failure_row["receipt_json"]))
        if (
            contract_issues(
                failed_attempt, "orchestration-task-attempt-receipt-v3.schema.json"
            )
            or contract_issues(policy, "orchestration-retry-policy-v2.schema.json")
            or contract_issues(failure, "orchestration-task-failure-receipt-v3.schema.json")
            or attempt_row["receipt_hash"] != content_hash(failed_attempt)
            or policy_row["policy_digest"] != policy["policy_digest"]
            or failure_row["receipt_hash"] != content_hash(failure)
            or document["failed_attempt_digest"] != "sha256:" + content_hash(failed_attempt)
            or document["retry_policy_digest"] != policy["policy_digest"]
        ):
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_LINEAGE_INVALID", "terminal lineage is invalid"
            )
        if (
            any(
                failed_attempt[key] != document[key]
                for key in ("assessment_id", "plan_id", "task_id")
            )
            or failed_attempt["plan_revision"] != document["expected_plan_revision"]
            or failed_attempt["task_revision"] != document["expected_task_revision"]
            or failed_attempt["retry_policy_id"] != document["retry_policy_id"]
            or failed_attempt["retry_policy_digest"] != document["retry_policy_digest"]
            or failed_attempt["attempt_number"] != 3
            or failed_attempt["attempt_state"] != "failed"
            or failed_attempt["terminal_retry_ceiling"] != 3
            or policy["maximum_attempts"] != 3
            or failure["failure_id"] != failed_attempt["failure_id"]
            or "sha256:" + content_hash(failure) != failed_attempt["failure_receipt_digest"]
            or parse_time(policy["expires_at"]) <= instant
        ):
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_BINDING_MISMATCH", "terminal binding mismatches"
            )
        try:
            self._failures._validate_replay(connection, failure, instant)
        except OrchestrationFailureV3Error as error:
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_SECURITY_DENIED",
                "current security state denies terminal disposition",
            ) from error
        return failed_attempt

    @staticmethod
    def _validate_decision(row: sqlite3.Row, decision: dict[str, Any]) -> None:
        expected = "sha256:" + content_hash(
            {key: value for key, value in decision.items() if key != "decision_digest"}
        )
        if (
            contract_issues(
                decision, "orchestration-terminal-disposition-decision-v1.schema.json"
            )
            or row["decision_hash"] != content_hash(decision)
            or decision["decision_digest"] != expected
            or decision["decision_id"] != row["decision_id"]
            or decision["failed_attempt_id"] != row["failed_attempt_id"]
        ):
            raise OrchestrationTerminalError(
                "ORCHESTRATION_TERMINAL_RESULT_INVALID", "terminal decision is invalid"
            )


def _decision(
    command: dict[str, Any],
    attempt: dict[str, Any],
    decision_id: str,
    command_digest: str,
    decided_at: str,
) -> dict[str, Any]:
    decision = {
        "schema_version": "1.0.0",
        "decision_id": decision_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": attempt["assessment_id"],
        "plan_id": attempt["plan_id"],
        "plan_revision": attempt["plan_revision"],
        "task_id": attempt["task_id"],
        "task_revision": attempt["task_revision"],
        "failed_attempt_id": attempt["attempt_id"],
        "failed_attempt_digest": command["failed_attempt_digest"],
        "failure_id": attempt["failure_id"],
        "failure_receipt_digest": attempt["failure_receipt_digest"],
        "failure_class": attempt["failure_class"],
        "retry_policy_id": attempt["retry_policy_id"],
        "retry_policy_digest": attempt["retry_policy_digest"],
        "attempt_number": 3,
        "maximum_attempts": 3,
        "additional_attempts_permitted": 0,
        "outcome": "dead_letter_eligible",
        "reason_code": "retry_ceiling_exhausted",
        "dead_letter_transition_enabled": False,
        "queue_enabled": False,
        "operator_review_enabled": False,
        "purpose": command["purpose"],
        "decided_at": decided_at,
        "decision_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    decision["decision_digest"] = "sha256:" + content_hash(
        {key: value for key, value in decision.items() if key != "decision_digest"}
    )
    return decision


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationTerminalError("ORCHESTRATION_TERMINAL_CLOCK_INVALID", "clock invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
