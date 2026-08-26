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
from pentai_core.orchestration_retry_schedule import (
    OrchestrationRetryScheduleError,
    OrchestrationRetryScheduleService,
)

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_VALIDITY = timedelta(minutes=5)
_NAMESPACE = UUID("63594431-d731-4e3e-9ff0-97a44e4fe824")


class OrchestrationRetryActivationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryActivationService:
    """Consume an inert retry schedule into readiness without execution authority."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._schedules = OrchestrationRetryScheduleService(authorization)

    def consume(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if document.get("schema_version") == "2.0.0":
            return self._consume_v2(document, now=now)
        if contract_issues(document, "orchestration-retry-activation-command-v1.schema.json"):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_MALFORMED",
                "retry activation command is malformed",
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
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_STALE",
                "retry activation command is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        activation_id = str(uuid5(_NAMESPACE, "retry-activation:" + document["schedule_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_retry_activations WHERE command_id = ?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryActivationError(
                        "ORCHESTRATION_RETRY_ACTIVATION_IDENTITY_CONFLICT",
                        "retry activation identity conflicts",
                    )
                receipt = self._load_receipt(replay)
                self._validate_replay(connection, receipt, instant)
                return copy.deepcopy(receipt)

            schedule = self._load_schedule(connection, document)
            if parse_time(schedule["scheduled_for"]) > instant:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_PREMATURE",
                    "retry schedule is not due",
                )
            if parse_time(schedule["expires_at"]) <= instant:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_EXPIRED",
                    "retry schedule is expired",
                )
            self._validate_current(connection, document, schedule, instant)
            if (
                connection.execute(
                    """SELECT 1 FROM orchestration_retry_activations
                WHERE schedule_id = ? OR attempt_id = ?""",
                    (schedule["schedule_id"], schedule["attempt_id"]),
                ).fetchone()
                is not None
            ):
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_ALREADY_CONSUMED",
                    "retry schedule was already consumed",
                )
            activated_at = _timestamp(instant)
            receipt = _receipt(document, schedule, activation_id, command_digest, activated_at)
            if contract_issues(receipt, "orchestration-retry-activation-receipt-v1.schema.json"):
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_RECEIPT_INVALID",
                    "retry activation receipt is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_activations (
                    activation_id, command_id, command_digest, assessment_id, plan_id,
                    expected_plan_revision, resulting_plan_revision, task_id,
                    expected_task_revision, resulting_task_revision, schedule_id, attempt_id,
                    receipt_json, receipt_hash, activated_at, authority, execution_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        activation_id,
                        document["command_id"],
                        command_digest,
                        schedule["assessment_id"],
                        schedule["plan_id"],
                        schedule["plan_revision"],
                        schedule["plan_revision"] + 1,
                        schedule["task_id"],
                        schedule["task_revision"],
                        schedule["task_revision"] + 1,
                        schedule["schedule_id"],
                        schedule["attempt_id"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        activated_at,
                    ),
                )
                connection.execute(
                    """UPDATE orchestration_tasks SET state = 'ready', revision = revision + 1,
                    updated_at = ? WHERE plan_id = ? AND task_id = ? AND revision = ?
                    AND state = 'failed'""",
                    (
                        activated_at,
                        schedule["plan_id"],
                        schedule["task_id"],
                        schedule["task_revision"],
                    ),
                )
                connection.execute(
                    """UPDATE orchestration_plans SET state = 'active', revision = revision + 1,
                    updated_at = ? WHERE plan_id = ? AND revision = ? AND state = 'failed'""",
                    (activated_at, schedule["plan_id"], schedule["plan_revision"]),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_CONFLICT",
                    "retry activation conflicts",
                ) from error
            _audit(connection, activation_id, receipt)
        return copy.deepcopy(receipt)

    def _consume_v2(self, document: dict[str, Any], *, now: datetime | None) -> dict[str, Any]:
        if contract_issues(document, "orchestration-retry-activation-command-v2.schema.json"):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_MALFORMED",
                "retry activation command is malformed",
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
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_COMMAND_STALE",
                "retry activation command is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        activation_id = str(uuid5(_NAMESPACE, "retry-activation-v2:" + document["schedule_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_retry_activations_v2 WHERE command_id=?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryActivationError(
                        "ORCHESTRATION_RETRY_ACTIVATION_IDENTITY_CONFLICT",
                        "retry activation identity conflicts",
                    )
                receipt = self._load_receipt_v2(replay)
                self._validate_replay_v2(connection, receipt, instant)
                return copy.deepcopy(receipt)

            schedule = self._load_schedule_v2(connection, document)
            if parse_time(schedule["scheduled_for"]) > instant:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_PREMATURE",
                    "retry schedule is not due",
                )
            if parse_time(schedule["expires_at"]) <= instant:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_EXPIRED",
                    "retry schedule is expired",
                )
            self._validate_current_v2(connection, document, schedule, instant)
            if (
                connection.execute(
                    "SELECT 1 FROM orchestration_retry_activations_v2 "
                    "WHERE schedule_id=? OR attempt_id=?",
                    (schedule["schedule_id"], schedule["attempt_id"]),
                ).fetchone()
                is not None
            ):
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_ALREADY_CONSUMED",
                    "retry schedule was already consumed",
                )
            activated_at = _timestamp(instant)
            receipt = _receipt_v2(document, schedule, activation_id, command_digest, activated_at)
            if contract_issues(receipt, "orchestration-retry-activation-receipt-v2.schema.json"):
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_RECEIPT_INVALID",
                    "retry activation receipt is invalid",
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_activations_v2 (
                    activation_id, command_id, command_digest, assessment_id, plan_id,
                    expected_plan_revision, resulting_plan_revision, task_id,
                    expected_task_revision, resulting_task_revision, schedule_id, attempt_id,
                    receipt_json, receipt_hash, activated_at, authority, execution_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        activation_id,
                        document["command_id"],
                        command_digest,
                        schedule["assessment_id"],
                        schedule["plan_id"],
                        schedule["plan_revision"],
                        schedule["plan_revision"] + 1,
                        schedule["task_id"],
                        schedule["task_revision"],
                        schedule["task_revision"] + 1,
                        schedule["schedule_id"],
                        schedule["attempt_id"],
                        canonical_json(receipt),
                        content_hash(receipt),
                        activated_at,
                    ),
                )
                task_result = connection.execute(
                    """UPDATE orchestration_tasks SET state='ready', revision=revision+1,
                    updated_at=? WHERE plan_id=? AND task_id=? AND revision=?
                    AND state='failed'""",
                    (
                        activated_at,
                        schedule["plan_id"],
                        schedule["task_id"],
                        schedule["task_revision"],
                    ),
                )
                plan_result = connection.execute(
                    """UPDATE orchestration_plans SET state='active', revision=revision+1,
                    updated_at=? WHERE plan_id=? AND revision=? AND state='failed'""",
                    (activated_at, schedule["plan_id"], schedule["plan_revision"]),
                )
                if task_result.rowcount != 1 or plan_result.rowcount != 1:
                    raise sqlite3.IntegrityError("retry activation state changed")
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryActivationError(
                    "ORCHESTRATION_RETRY_ACTIVATION_CONFLICT",
                    "retry activation conflicts",
                ) from error
            _audit(connection, activation_id, receipt)
        return copy.deepcopy(receipt)

    def _load_schedule_v2(
        self, connection: sqlite3.Connection, document: dict[str, Any]
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_schedules_v2 WHERE schedule_id=?",
            (document["schedule_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISSING",
                "retry schedule is missing",
            )
        try:
            schedule = self._schedules._load_receipt_v2(row)
        except OrchestrationRetryScheduleError as error:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_INVALID",
                "retry schedule is invalid",
            ) from error
        if (
            schedule["schedule_digest"] != document["schedule_digest"]
            or schedule["assessment_id"] != document["assessment_id"]
            or schedule["plan_id"] != document["plan_id"]
            or schedule["plan_revision"] != document["expected_plan_revision"]
            or schedule["task_id"] != document["task_id"]
            or schedule["task_revision"] != document["expected_task_revision"]
            or schedule["attempt_id"] != document["attempt_id"]
            or schedule["attempt_digest"] != document["attempt_digest"]
            or schedule["attempt_number"] != 3
            or schedule["schedule_state"] != "registered"
            or parse_time(schedule["registered_at"]) > parse_time(document["requested_at"])
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISMATCH",
                "retry schedule binding mismatches",
            )
        return schedule

    def _validate_current_v2(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        schedule: dict[str, Any],
        instant: datetime,
    ) -> None:
        validation = {
            "schema_version": "2.0.0",
            "command_id": schedule["command_id"],
            "assessment_id": schedule["assessment_id"],
            "plan_id": schedule["plan_id"],
            "expected_plan_revision": schedule["plan_revision"],
            "task_id": schedule["task_id"],
            "expected_task_revision": schedule["task_revision"],
            "attempt_id": schedule["attempt_id"],
            "attempt_digest": schedule["attempt_digest"],
            "purpose": "register_validation_retry_schedule_three",
            "requested_at": document["requested_at"],
            "expires_at": document["expires_at"],
            "authority": "none",
            "execution_enabled": False,
        }
        try:
            attempt, decision = self._schedules._validate_attempt_v2(
                connection, validation, instant
            )
        except OrchestrationRetryScheduleError as error:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SECURITY_DENIED",
                "current security state denies retry activation",
            ) from error
        if (
            attempt["retry_budget_consumption_id"] != schedule["retry_budget_consumption_id"]
            or decision["decision_id"] != schedule["eligibility_decision_id"]
            or decision["decision_digest"] != schedule["eligibility_decision_digest"]
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_LINEAGE_MISMATCH",
                "retry activation lineage mismatches",
            )

    def _validate_replay_v2(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (receipt["plan_id"], receipt["task_id"]),
        ).fetchone()
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id=?",
            (receipt["plan_id"],),
        ).fetchone()
        schedule_row = connection.execute(
            "SELECT * FROM orchestration_retry_schedules_v2 WHERE schedule_id=?",
            (receipt["schedule_id"],),
        ).fetchone()
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (receipt["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id=? AND engagement_id=?",
            (receipt["policy_bundle_id"], receipt["assessment_id"]),
        ).fetchone()
        try:
            schedule = (
                self._schedules._load_receipt_v2(schedule_row) if schedule_row is not None else None
            )
        except OrchestrationRetryScheduleError:
            schedule = None
        manifest = budget = account = worker = fence = None
        approval_valid = True
        if schedule is not None:
            manifest = connection.execute(
                "SELECT * FROM task_capability_manifests WHERE manifest_id=?",
                (schedule["capability_manifest_id"],),
            ).fetchone()
            budget = connection.execute(
                "SELECT * FROM orchestration_task_budget_reservations WHERE reservation_id=?",
                (schedule["lineage_budget_reservation_id"],),
            ).fetchone()
            account = connection.execute(
                "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
                (schedule["budget_account_id"],),
            ).fetchone()
            worker = connection.execute(
                "SELECT * FROM worker_runtime_instances WHERE worker_id=?",
                (schedule["worker_id"],),
            ).fetchone()
            fence = connection.execute(
                "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?",
                (schedule["task_id"],),
            ).fetchone()
            if schedule["approval_consumption_id"] is not None:
                approval = connection.execute(
                    "SELECT approval_expires_at FROM orchestration_task_approval_consumptions "
                    "WHERE consumption_id=?",
                    (schedule["approval_consumption_id"],),
                ).fetchone()
                approval_valid = (
                    approval is not None and parse_time(approval["approval_expires_at"]) > instant
                )
        if (
            task is None
            or plan is None
            or (task["state"], task["revision"]) != ("ready", receipt["resulting_task_revision"])
            or (plan["state"], plan["revision"]) != ("active", receipt["resulting_plan_revision"])
            or schedule is None
            or schedule["schedule_digest"] != receipt["schedule_digest"]
            or parse_time(schedule["expires_at"]) <= instant
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != receipt["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
            or policy is None
            or policy["content_hash"] != receipt["policy_hash"]
            or policy["revoked_at"] is not None
            or manifest is None
            or manifest["manifest_hash"] != schedule["capability_manifest_digest"][7:]
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget["state"] != "reserved"
            or budget["request_digest"] != schedule["budget_request_digest"]
            or parse_time(budget["expires_at"]) <= instant
            or account is None
            or account["version"] != schedule["budget_account_version"]
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != schedule["worker_version"]
            or fence is None
            or fence["current_lease_generation"] != schedule["lease_generation"]
            or fence["recovery_generation"] != schedule["recovery_generation"]
            or not approval_valid
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_REPLAY_FENCED",
                "retry activation replay is no longer current",
            )

    @staticmethod
    def _load_receipt_v2(row: sqlite3.Row) -> dict[str, Any]:
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        expected = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "activation_digest"}
        )
        if (
            contract_issues(receipt, "orchestration-retry-activation-receipt-v2.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["activation_digest"] != expected
            or receipt["activation_id"] != row["activation_id"]
            or receipt["command_digest"] != row["command_digest"]
            or receipt["schedule_id"] != row["schedule_id"]
            or receipt["attempt_id"] != row["attempt_id"]
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_RECEIPT_INVALID",
                "retry activation receipt is invalid",
            )
        return receipt

    def _load_schedule(
        self, connection: sqlite3.Connection, document: dict[str, Any]
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_schedules WHERE schedule_id = ?",
            (document["schedule_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISSING",
                "retry schedule is missing",
            )
        try:
            schedule = self._schedules._load_receipt(row)
        except OrchestrationRetryScheduleError as error:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_INVALID",
                "retry schedule is invalid",
            ) from error
        if (
            schedule["schedule_digest"] != document["schedule_digest"]
            or schedule["assessment_id"] != document["assessment_id"]
            or schedule["plan_id"] != document["plan_id"]
            or schedule["plan_revision"] != document["expected_plan_revision"]
            or schedule["task_id"] != document["task_id"]
            or schedule["task_revision"] != document["expected_task_revision"]
            or schedule["attempt_id"] != document["attempt_id"]
            or schedule["attempt_digest"] != document["attempt_digest"]
            or schedule["schedule_state"] != "registered"
            or parse_time(schedule["registered_at"]) > parse_time(document["requested_at"])
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SCHEDULE_MISMATCH",
                "retry schedule binding mismatches",
            )
        return schedule

    def _validate_current(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        schedule: dict[str, Any],
        instant: datetime,
    ) -> None:
        validation = {
            "schema_version": "1.0.0",
            "command_id": schedule["command_id"],
            "assessment_id": schedule["assessment_id"],
            "plan_id": schedule["plan_id"],
            "expected_plan_revision": schedule["plan_revision"],
            "task_id": schedule["task_id"],
            "expected_task_revision": schedule["task_revision"],
            "attempt_id": schedule["attempt_id"],
            "attempt_digest": schedule["attempt_digest"],
            "purpose": "register_validation_retry_schedule",
            "requested_at": document["requested_at"],
            "expires_at": document["expires_at"],
            "authority": "none",
            "execution_enabled": False,
        }
        try:
            attempt = self._schedules._validate_attempt(connection, validation, instant)
        except OrchestrationRetryScheduleError as error:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_SECURITY_DENIED",
                "current security state denies retry activation",
            ) from error
        if attempt["retry_budget_consumption_id"] != schedule["retry_budget_consumption_id"]:
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_LINEAGE_MISMATCH",
                "retry activation lineage mismatches",
            )

    def _validate_replay(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE plan_id = ? AND task_id = ?",
            (receipt["plan_id"], receipt["task_id"]),
        ).fetchone()
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id = ?",
            (receipt["plan_id"],),
        ).fetchone()
        schedule_row = connection.execute(
            "SELECT * FROM orchestration_retry_schedules WHERE schedule_id = ?",
            (receipt["schedule_id"],),
        ).fetchone()
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (receipt["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id = ? AND engagement_id = ?",
            (receipt["policy_bundle_id"], receipt["assessment_id"]),
        ).fetchone()
        if schedule_row is None:
            schedule = None
        else:
            try:
                schedule = self._schedules._load_receipt(schedule_row)
            except OrchestrationRetryScheduleError:
                schedule = None
        manifest = None
        budget = None
        account = None
        worker = None
        fence = None
        approval_valid = True
        if schedule is not None:
            manifest = connection.execute(
                "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
                (schedule["capability_manifest_id"],),
            ).fetchone()
            budget = connection.execute(
                """SELECT * FROM orchestration_task_budget_reservations
                WHERE reservation_id = ?""",
                (schedule["budget_reservation_id"],),
            ).fetchone()
            account = connection.execute(
                "SELECT version FROM orchestration_budget_accounts WHERE account_id = ?",
                (schedule["budget_account_id"],),
            ).fetchone()
            worker = connection.execute(
                "SELECT * FROM worker_runtime_instances WHERE worker_id = ?",
                (schedule["worker_id"],),
            ).fetchone()
            fence = connection.execute(
                "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
                (schedule["task_id"],),
            ).fetchone()
            if schedule["approval_consumption_id"] is not None:
                approval = connection.execute(
                    """SELECT approval_expires_at FROM orchestration_task_approval_consumptions
                    WHERE consumption_id = ?""",
                    (schedule["approval_consumption_id"],),
                ).fetchone()
                approval_valid = (
                    approval is not None and parse_time(approval["approval_expires_at"]) > instant
                )
        if (
            task is None
            or plan is None
            or (task["state"], task["revision"]) != ("ready", receipt["resulting_task_revision"])
            or (plan["state"], plan["revision"]) != ("active", receipt["resulting_plan_revision"])
            or schedule is None
            or schedule["schedule_digest"] != receipt["schedule_digest"]
            or parse_time(schedule["expires_at"]) <= instant
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != receipt["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
            or policy is None
            or policy["content_hash"] != receipt["policy_hash"]
            or policy["revoked_at"] is not None
            or manifest is None
            or parse_time(manifest["expires_at"]) <= instant
            or budget is None
            or budget["state"] != "reserved"
            or parse_time(budget["expires_at"]) <= instant
            or account is None
            or account["version"] != schedule["budget_account_version"]
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != schedule["worker_version"]
            or fence is None
            or fence["current_lease_generation"] != schedule["lease_generation"]
            or fence["recovery_generation"] != schedule["recovery_generation"]
            or not approval_valid
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_REPLAY_FENCED",
                "retry activation replay is no longer current",
            )

    @staticmethod
    def _load_receipt(row: sqlite3.Row) -> dict[str, Any]:
        receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        expected = "sha256:" + content_hash(
            {key: value for key, value in receipt.items() if key != "activation_digest"}
        )
        if (
            contract_issues(receipt, "orchestration-retry-activation-receipt-v1.schema.json")
            or row["receipt_hash"] != content_hash(receipt)
            or receipt["activation_digest"] != expected
            or receipt["activation_id"] != row["activation_id"]
            or receipt["command_digest"] != row["command_digest"]
            or receipt["schedule_id"] != row["schedule_id"]
            or receipt["attempt_id"] != row["attempt_id"]
        ):
            raise OrchestrationRetryActivationError(
                "ORCHESTRATION_RETRY_ACTIVATION_RECEIPT_INVALID",
                "retry activation receipt is invalid",
            )
        return receipt


def _receipt(
    command: dict[str, Any],
    schedule: dict[str, Any],
    activation_id: str,
    command_digest: str,
    activated_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "1.0.0",
        "activation_id": activation_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": schedule["assessment_id"],
        "plan_id": schedule["plan_id"],
        "expected_plan_revision": schedule["plan_revision"],
        "resulting_plan_revision": schedule["plan_revision"] + 1,
        "resulting_plan_state": "active",
        "task_id": schedule["task_id"],
        "expected_task_revision": schedule["task_revision"],
        "resulting_task_revision": schedule["task_revision"] + 1,
        "schedule_id": schedule["schedule_id"],
        "schedule_digest": schedule["schedule_digest"],
        "attempt_id": schedule["attempt_id"],
        "attempt_digest": schedule["attempt_digest"],
        "attempt_number": 2,
        "retry_budget_consumption_id": schedule["retry_budget_consumption_id"],
        "policy_bundle_id": schedule["policy_bundle_id"],
        "policy_hash": schedule["policy_hash"],
        "recovery_generation": schedule["recovery_generation"],
        "scheduled_for": schedule["scheduled_for"],
        "schedule_expires_at": schedule["expires_at"],
        "purpose": command["purpose"],
        "resulting_task_state": "ready",
        "activated_at": activated_at,
        "activation_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["activation_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "activation_digest"}
    )
    return receipt


def _receipt_v2(
    command: dict[str, Any],
    schedule: dict[str, Any],
    activation_id: str,
    command_digest: str,
    activated_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "2.0.0",
        "activation_id": activation_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": schedule["assessment_id"],
        "plan_id": schedule["plan_id"],
        "expected_plan_revision": schedule["plan_revision"],
        "resulting_plan_revision": schedule["plan_revision"] + 1,
        "resulting_plan_state": "active",
        "task_id": schedule["task_id"],
        "expected_task_revision": schedule["task_revision"],
        "resulting_task_revision": schedule["task_revision"] + 1,
        "schedule_id": schedule["schedule_id"],
        "schedule_digest": schedule["schedule_digest"],
        "attempt_id": schedule["attempt_id"],
        "attempt_digest": schedule["attempt_digest"],
        "attempt_number": 3,
        "retry_budget_consumption_id": schedule["retry_budget_consumption_id"],
        "eligibility_decision_id": schedule["eligibility_decision_id"],
        "policy_bundle_id": schedule["policy_bundle_id"],
        "policy_hash": schedule["policy_hash"],
        "retry_policy_id": schedule["retry_policy_id"],
        "retry_policy_digest": schedule["retry_policy_digest"],
        "recovery_generation": schedule["recovery_generation"],
        "scheduled_for": schedule["scheduled_for"],
        "schedule_expires_at": schedule["expires_at"],
        "purpose": command["purpose"],
        "resulting_task_state": "ready",
        "activated_at": activated_at,
        "activation_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    receipt["activation_digest"] = "sha256:" + content_hash(
        {key: value for key, value in receipt.items() if key != "activation_digest"}
    )
    return receipt


def _audit(connection: sqlite3.Connection, activation_id: str, receipt: dict[str, Any]) -> None:
    event = append_audit_event(
        connection,
        action="orchestration.retry_schedule_consumed",
        subject_type="orchestration_retry_activation",
        subject_id=activation_id,
        actor_type="service",
        actor_id="pentai-core",
        data=receipt,
        occurred_at=receipt["activated_at"],
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_retry_activation', ?,
        'orchestration.retry_schedule_consumed', ?)""",
        (
            str(uuid4()),
            activation_id,
            canonical_json({"event_hash": event["event_hash"], "subject_id": activation_id}),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryActivationError(
            "ORCHESTRATION_RETRY_ACTIVATION_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
