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
from pentai_core.orchestration_attempt import (
    OrchestrationAttemptError,
    OrchestrationAttemptService,
    _document_from_receipt,
)

_MAX_COMMAND_AGE = timedelta(minutes=1)
_MAX_COMMAND_VALIDITY = timedelta(minutes=5)
_MAX_POLICY_VALIDITY = timedelta(hours=1)
_NAMESPACE = UUID("76cd6583-af6c-4ec7-a070-954980518afd")
_ELIGIBLE = ["coordination_timeout", "runtime_unavailable", "worker_process_failed"]
_BACKOFF_SECONDS = [5, 30]


class OrchestrationRetryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationRetryService:
    """Issue closed retry policy and record non-activating eligibility decisions."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path
        self._attempts = OrchestrationAttemptService(authorization)

    def issue_policy(
        self,
        *,
        assessment_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        expiry = _instant(expires_at)
        if expiry <= instant or expiry - instant > _MAX_POLICY_VALIDITY:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_STALE", "retry policy validity is stale"
            )
        try:
            active = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_SECURITY_DENIED", "active policy is invalid"
            ) from error
        self.authorization._require_storage_safe()
        retry_policy_id = str(
            uuid5(_NAMESPACE, f"retry-policy:{assessment_id}:{policy_bundle_id}:{policy_hash}")
        )
        policy = {
            "schema_version": "1.0.0",
            "retry_policy_id": retry_policy_id,
            "revision": 1,
            "assessment_id": assessment_id,
            "policy_bundle_id": policy_bundle_id,
            "policy_hash": policy_hash,
            "task_type": "validation",
            "failure_contract_version": "1.0.0",
            "attempt_contract_version": "1.0.0",
            "maximum_attempts": 3,
            "eligible_failure_classes": _ELIGIBLE,
            "backoff_seconds": _BACKOFF_SECONDS,
            "issued_at": _timestamp(instant),
            "expires_at": _timestamp(expiry),
            "issued_by": "pentai-core",
            "policy_digest": "",
            "authority": "none",
            "execution_enabled": False,
        }
        policy["policy_digest"] = "sha256:" + content_hash(
            {key: value for key, value in policy.items() if key != "policy_digest"}
        )
        if contract_issues(policy, "orchestration-retry-policy-v1.schema.json"):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_INVALID", "retry policy is invalid"
            )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (assessment_id,)
            ).fetchone()
            safety = connection.execute(
                "SELECT global_status FROM safety_state WHERE singleton_id = 1"
            ).fetchone()
            if (
                active["status"] != "active"
                or active["content_hash"] != policy_hash
                or engagement is None
                or engagement["status"] != "active"
                or engagement["active_policy_id"] != policy_bundle_id
                or parse_time(engagement["expires_at"]) <= instant
                or expiry > parse_time(engagement["expires_at"])
                or expiry > parse_time(active["policy"]["validity"]["not_after"])
                or safety is None
                or safety["global_status"] != "active"
            ):
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_POLICY_SECURITY_DENIED",
                    "current security state denies retry policy",
                )
            existing = connection.execute(
                """SELECT policy_json FROM orchestration_retry_policies
                WHERE retry_policy_id = ?""",
                (retry_policy_id,),
            ).fetchone()
            if existing is not None:
                stored = json.loads(existing["policy_json"])
                if stored != policy:
                    raise OrchestrationRetryError(
                        "ORCHESTRATION_RETRY_POLICY_IDENTITY_CONFLICT",
                        "retry policy identity conflicts",
                    )
                return cast(dict[str, Any], stored)
            connection.execute(
                """INSERT INTO orchestration_retry_policies VALUES
                (?, ?, ?, ?, 1, ?, ?, ?, ?, 'none', 0)""",
                (
                    retry_policy_id,
                    assessment_id,
                    policy_bundle_id,
                    policy_hash,
                    canonical_json(policy),
                    policy["policy_digest"],
                    policy["issued_at"],
                    policy["expires_at"],
                ),
            )
            _audit(connection, "orchestration.retry_policy_issued", retry_policy_id, policy)
        return copy.deepcopy(policy)

    def issue_policy_v2(
        self,
        *,
        assessment_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Issue the closed policy prerequisite for retry-bound failed attempts."""
        instant = _instant(now)
        expiry = _instant(expires_at)
        if expiry <= instant or expiry - instant > _MAX_POLICY_VALIDITY:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_STALE", "retry policy validity is stale"
            )
        try:
            active = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_SECURITY_DENIED", "active policy is invalid"
            ) from error
        self.authorization._require_storage_safe()
        retry_policy_id = str(
            uuid5(_NAMESPACE, f"retry-policy-v2:{assessment_id}:{policy_bundle_id}:{policy_hash}")
        )
        policy = {
            "schema_version": "2.0.0",
            "retry_policy_id": retry_policy_id,
            "revision": 1,
            "assessment_id": assessment_id,
            "policy_bundle_id": policy_bundle_id,
            "policy_hash": policy_hash,
            "task_type": "validation",
            "failure_contract_version": "2.0.0",
            "attempt_contract_version": "2.0.0",
            "maximum_attempts": 3,
            "eligible_failure_classes": _ELIGIBLE,
            "backoff_seconds": _BACKOFF_SECONDS,
            "issued_at": _timestamp(instant),
            "expires_at": _timestamp(expiry),
            "issued_by": "pentai-core",
            "policy_digest": "",
            "authority": "none",
            "execution_enabled": False,
        }
        policy["policy_digest"] = "sha256:" + content_hash(
            {key: value for key, value in policy.items() if key != "policy_digest"}
        )
        if contract_issues(policy, "orchestration-retry-policy-v2.schema.json"):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_INVALID", "retry policy is invalid"
            )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (assessment_id,)
            ).fetchone()
            safety = connection.execute(
                "SELECT global_status FROM safety_state WHERE singleton_id = 1"
            ).fetchone()
            if (
                active["status"] != "active"
                or active["content_hash"] != policy_hash
                or engagement is None
                or engagement["status"] != "active"
                or engagement["active_policy_id"] != policy_bundle_id
                or parse_time(engagement["expires_at"]) <= instant
                or expiry > parse_time(engagement["expires_at"])
                or expiry > parse_time(active["policy"]["validity"]["not_after"])
                or safety is None
                or safety["global_status"] != "active"
            ):
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_POLICY_SECURITY_DENIED",
                    "current security state denies retry policy",
                )
            existing = connection.execute(
                """SELECT policy_json FROM orchestration_retry_policies_v2
                WHERE retry_policy_id = ?""",
                (retry_policy_id,),
            ).fetchone()
            if existing is not None:
                stored = json.loads(existing["policy_json"])
                if stored != policy:
                    raise OrchestrationRetryError(
                        "ORCHESTRATION_RETRY_POLICY_IDENTITY_CONFLICT",
                        "retry policy identity conflicts",
                    )
                return cast(dict[str, Any], stored)
            connection.execute(
                """INSERT INTO orchestration_retry_policies_v2 VALUES
                (?, ?, ?, ?, 1, ?, ?, ?, ?, 'none', 0)""",
                (
                    retry_policy_id,
                    assessment_id,
                    policy_bundle_id,
                    policy_hash,
                    canonical_json(policy),
                    policy["policy_digest"],
                    policy["issued_at"],
                    policy["expires_at"],
                ),
            )
            _audit(connection, "orchestration.retry_policy_v2_issued", retry_policy_id, policy)
        return copy.deepcopy(policy)

    def evaluate(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if document.get("schema_version") == "2.0.0":
            return self._evaluate_retry_attempt(document, now=now)
        if contract_issues(document, "orchestration-retry-evaluation-command-v1.schema.json"):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_EVALUATION_MALFORMED",
                "retry evaluation command is malformed",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        command_expiry = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_COMMAND_AGE
            or command_expiry <= instant
            or command_expiry <= requested_at
            or command_expiry - requested_at > _MAX_COMMAND_VALIDITY
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_EVALUATION_STALE", "retry evaluation is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        decision_id = str(uuid5(_NAMESPACE, "retry-decision:" + document["attempt_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, decision_json FROM orchestration_retry_decisions
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryError(
                        "ORCHESTRATION_RETRY_EVALUATION_IDENTITY_CONFLICT",
                        "retry evaluation identity conflicts",
                    )
                decision = cast(dict[str, Any], json.loads(replay["decision_json"]))
                attempt = self._load_attempt(connection, document)
                self._validate_current_attempt(connection, attempt, instant)
                self._load_policy(connection, document, attempt, instant)
                return decision
            attempt = self._load_attempt(connection, document)
            self._validate_current_attempt(connection, attempt, instant)
            policy = self._load_policy(connection, document, attempt, instant)
            outcome, reason = self._outcome(connection, attempt, policy)
            expiry = self._decision_expiry(connection, attempt, policy, command_expiry)
            earliest = (
                _timestamp(parse_time(attempt["registered_at"]) + timedelta(seconds=5))
                if outcome == "eligible"
                else None
            )
            decision = _decision(
                document,
                attempt,
                policy,
                decision_id,
                command_digest,
                outcome,
                reason,
                earliest,
                _timestamp(instant),
                _timestamp(expiry),
            )
            if contract_issues(decision, "orchestration-retry-decision-v1.schema.json"):
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_DECISION_INVALID", "retry decision is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_decisions (
                    decision_id, command_id, command_digest, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, attempt_id, retry_policy_id,
                    retry_policy_revision, outcome, reason_code, decision_json,
                    decision_hash, decided_at, expires_at, authority, execution_enabled
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        decision_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["attempt_id"],
                        document["retry_policy_id"],
                        outcome,
                        reason,
                        canonical_json(decision),
                        content_hash(decision),
                        decision["decided_at"],
                        decision["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_EVALUATION_CONFLICT",
                    "retry evaluation conflicts",
                ) from error
            _audit(connection, "orchestration.retry_evaluated", decision_id, decision)
        return copy.deepcopy(decision)

    def _evaluate_retry_attempt(
        self, document: dict[str, Any], *, now: datetime | None
    ) -> dict[str, Any]:
        if contract_issues(document, "orchestration-retry-evaluation-command-v2.schema.json"):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_EVALUATION_MALFORMED",
                "retry evaluation command is malformed",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        command_expiry = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_COMMAND_AGE
            or command_expiry <= instant
            or command_expiry <= requested_at
            or command_expiry - requested_at > _MAX_COMMAND_VALIDITY
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_EVALUATION_STALE", "retry evaluation is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        decision_id = str(uuid5(_NAMESPACE, "retry-decision-v2:" + document["attempt_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT * FROM orchestration_retry_decisions_v2
                WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationRetryError(
                        "ORCHESTRATION_RETRY_EVALUATION_IDENTITY_CONFLICT",
                        "retry evaluation identity conflicts",
                    )
                decision = cast(dict[str, Any], json.loads(replay["decision_json"]))
                attempt = self._load_retry_failed_attempt(connection, document, instant)
                self._load_policy_v2(connection, document, attempt, instant)
                if replay["decision_hash"] != content_hash(decision):
                    raise OrchestrationRetryError(
                        "ORCHESTRATION_RETRY_DECISION_INVALID", "retry decision is invalid"
                    )
                return copy.deepcopy(decision)
            attempt = self._load_retry_failed_attempt(connection, document, instant)
            policy = self._load_policy_v2(connection, document, attempt, instant)
            outcome, reason = self._retry_attempt_outcome(connection, attempt, policy)
            expiry = self._decision_expiry(connection, attempt, policy, command_expiry)
            earliest = (
                _timestamp(
                    parse_time(attempt["registered_at"])
                    + timedelta(seconds=policy["backoff_seconds"][1])
                )
                if outcome == "eligible"
                else None
            )
            decision = _retry_attempt_decision(
                document,
                attempt,
                policy,
                decision_id,
                command_digest,
                outcome,
                reason,
                earliest,
                _timestamp(instant),
                _timestamp(expiry),
            )
            if contract_issues(decision, "orchestration-retry-decision-v2.schema.json"):
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_DECISION_INVALID", "retry decision is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_retry_decisions_v2 VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        decision_id,
                        document["command_id"],
                        command_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["attempt_id"],
                        document["retry_policy_id"],
                        outcome,
                        reason,
                        canonical_json(decision),
                        content_hash(decision),
                        decision["decided_at"],
                        decision["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationRetryError(
                    "ORCHESTRATION_RETRY_EVALUATION_CONFLICT",
                    "retry evaluation conflicts",
                ) from error
            _audit(connection, "orchestration.retry_evaluated_v2", decision_id, decision)
        return copy.deepcopy(decision)

    def _load_retry_failed_attempt(
        self,
        connection: sqlite3.Connection,
        document: dict[str, Any],
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_failed_attempts WHERE attempt_id = ?",
            (document["attempt_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_ATTEMPT_MISSING", "attempt is missing"
            )
        attempt = cast(dict[str, Any], json.loads(row["receipt_json"]))
        if (
            contract_issues(attempt, "orchestration-task-attempt-receipt-v2.schema.json")
            or row["receipt_hash"] != content_hash(attempt)
            or attempt["attempt_digest"] != document["attempt_digest"]
            or attempt["assessment_id"] != document["assessment_id"]
            or attempt["plan_id"] != document["plan_id"]
            or attempt["plan_revision"] != document["expected_plan_revision"]
            or attempt["task_id"] != document["task_id"]
            or attempt["task_revision"] != document["expected_task_revision"]
            or attempt["attempt_number"] != 2
            or attempt["attempt_state"] != "failed"
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_ATTEMPT_INVALID", "attempt binding is invalid"
            )
        try:
            self._attempts._validate_retry_current(
                connection, _retry_document_from_receipt(attempt), instant
            )
        except OrchestrationAttemptError as error:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_SECURITY_DENIED",
                "current attempt security state denies",
            ) from error
        return attempt

    @staticmethod
    def _load_policy_v2(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        attempt: dict[str, Any],
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_policies_v2 WHERE retry_policy_id = ?",
            (document["retry_policy_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_MISSING", "retry policy is missing"
            )
        policy = cast(dict[str, Any], json.loads(row["policy_json"]))
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in policy.items() if key != "policy_digest"}
        )
        if (
            contract_issues(policy, "orchestration-retry-policy-v2.schema.json")
            or row["policy_digest"] != policy["policy_digest"]
            or policy["policy_digest"] != expected_digest
            or policy["retry_policy_id"] != document["retry_policy_id"]
            or policy["revision"] != document["retry_policy_revision"]
            or policy["policy_digest"] != document["retry_policy_digest"]
            or policy["assessment_id"] != attempt["assessment_id"]
            or policy["policy_bundle_id"] != attempt["policy_bundle_id"]
            or policy["policy_hash"] != attempt["policy_hash"]
            or policy["failure_contract_version"] != "2.0.0"
            or policy["attempt_contract_version"] != "2.0.0"
            or parse_time(policy["expires_at"]) <= instant
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_INVALID", "retry policy is invalid"
            )
        return policy

    @staticmethod
    def _retry_attempt_outcome(
        connection: sqlite3.Connection,
        attempt: dict[str, Any],
        policy: dict[str, Any],
    ) -> tuple[str, str]:
        if attempt["attempt_number"] >= policy["maximum_attempts"]:
            return "denied", "RETRY_DENIED_ATTEMPT_LIMIT"
        consumption = connection.execute(
            """SELECT * FROM orchestration_retry_budget_consumptions
            WHERE consumption_id = ?""",
            (attempt["retry_budget_consumption_id"],),
        ).fetchone()
        if consumption is None:
            return "denied", "RETRY_DENIED_CAPACITY_UNAVAILABLE"
        receipt = json.loads(consumption["receipt_json"])
        if (
            consumption["receipt_hash"] != content_hash(receipt)
            or receipt["consumption_id"] != attempt["retry_budget_consumption_id"]
            or receipt["assessment_id"] != attempt["assessment_id"]
            or receipt["plan_id"] != attempt["plan_id"]
            or receipt["task_id"] != attempt["task_id"]
            or receipt["remaining_retry_units"] < 1
        ):
            return "denied", "RETRY_DENIED_CAPACITY_UNAVAILABLE"
        if attempt["failure_class"] not in policy["eligible_failure_classes"]:
            return "denied", "RETRY_DENIED_MANUAL_REVIEW_REQUIRED"
        return "eligible", "RETRY_ELIGIBLE_TRANSIENT_FAILURE"

    def _load_attempt(
        self, connection: sqlite3.Connection, document: dict[str, Any]
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_task_attempts WHERE attempt_id = ?",
            (document["attempt_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_ATTEMPT_MISSING", "attempt is missing"
            )
        attempt = json.loads(row["receipt_json"])
        if (
            contract_issues(attempt, "orchestration-task-attempt-receipt-v1.schema.json")
            or row["receipt_hash"] != content_hash(attempt)
            or attempt["attempt_digest"] != document["attempt_digest"]
            or attempt["assessment_id"] != document["assessment_id"]
            or attempt["plan_id"] != document["plan_id"]
            or attempt["plan_revision"] != document["expected_plan_revision"]
            or attempt["task_id"] != document["task_id"]
            or attempt["task_revision"] != document["expected_task_revision"]
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_ATTEMPT_INVALID", "attempt binding is invalid"
            )
        return cast(dict[str, Any], attempt)

    def _validate_current_attempt(
        self, connection: sqlite3.Connection, attempt: dict[str, Any], instant: datetime
    ) -> None:
        try:
            self._attempts._validate_current(connection, _document_from_receipt(attempt), instant)
        except OrchestrationAttemptError as error:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_SECURITY_DENIED",
                "current attempt security state denies",
            ) from error

    @staticmethod
    def _load_policy(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        attempt: dict[str, Any],
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM orchestration_retry_policies WHERE retry_policy_id = ?",
            (document["retry_policy_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_MISSING", "retry policy is missing"
            )
        policy = json.loads(row["policy_json"])
        expected_digest = "sha256:" + content_hash(
            {key: value for key, value in policy.items() if key != "policy_digest"}
        )
        if (
            contract_issues(policy, "orchestration-retry-policy-v1.schema.json")
            or row["policy_digest"] != policy["policy_digest"]
            or policy["policy_digest"] != expected_digest
            or policy["retry_policy_id"] != document["retry_policy_id"]
            or policy["revision"] != document["retry_policy_revision"]
            or policy["policy_digest"] != document["retry_policy_digest"]
            or policy["assessment_id"] != attempt["assessment_id"]
            or policy["policy_bundle_id"] != attempt["policy_bundle_id"]
            or policy["policy_hash"] != attempt["policy_hash"]
            or parse_time(policy["expires_at"]) <= instant
        ):
            raise OrchestrationRetryError(
                "ORCHESTRATION_RETRY_POLICY_INVALID", "retry policy is invalid"
            )
        return cast(dict[str, Any], policy)

    @staticmethod
    def _outcome(
        connection: sqlite3.Connection,
        attempt: dict[str, Any],
        policy: dict[str, Any],
    ) -> tuple[str, str]:
        if attempt["attempt_number"] >= policy["maximum_attempts"]:
            return "denied", "RETRY_DENIED_ATTEMPT_LIMIT"
        budget = connection.execute(
            """SELECT state, amounts_json FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (attempt["budget_reservation_id"],),
        ).fetchone()
        if budget is None or budget["state"] != "reserved":
            return "denied", "RETRY_DENIED_CAPACITY_UNAVAILABLE"
        amounts = json.loads(budget["amounts_json"])
        if amounts["retries"] < 1:
            return "denied", "RETRY_DENIED_CAPACITY_UNAVAILABLE"
        if attempt["failure_class"] not in policy["eligible_failure_classes"]:
            return "denied", "RETRY_DENIED_MANUAL_REVIEW_REQUIRED"
        return "eligible", "RETRY_ELIGIBLE_TRANSIENT_FAILURE"

    @staticmethod
    def _decision_expiry(
        connection: sqlite3.Connection,
        attempt: dict[str, Any],
        policy: dict[str, Any],
        command_expiry: datetime,
    ) -> datetime:
        deadlines = [command_expiry, parse_time(policy["expires_at"])]
        engagement = connection.execute(
            "SELECT expires_at FROM engagements WHERE id = ?", (attempt["assessment_id"],)
        ).fetchone()
        manifest = connection.execute(
            "SELECT expires_at FROM task_capability_manifests WHERE manifest_id = ?",
            (attempt["capability_manifest_id"],),
        ).fetchone()
        budget = connection.execute(
            """SELECT expires_at FROM orchestration_task_budget_reservations
            WHERE reservation_id = ?""",
            (attempt["budget_reservation_id"],),
        ).fetchone()
        assert engagement is not None and manifest is not None and budget is not None
        deadlines.extend(
            [
                parse_time(engagement["expires_at"]),
                parse_time(manifest["expires_at"]),
                parse_time(budget["expires_at"]),
            ]
        )
        if attempt["approval_consumption_id"] is not None:
            approval = connection.execute(
                """SELECT approval_expires_at FROM orchestration_task_approval_consumptions
                WHERE consumption_id = ?""",
                (attempt["approval_consumption_id"],),
            ).fetchone()
            assert approval is not None
            deadlines.append(parse_time(approval["approval_expires_at"]))
        return min(deadlines)


def _decision(
    command: dict[str, Any],
    attempt: dict[str, Any],
    policy: dict[str, Any],
    decision_id: str,
    command_digest: str,
    outcome: str,
    reason: str,
    earliest: str | None,
    decided_at: str,
    expires_at: str,
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
        "attempt_id": attempt["attempt_id"],
        "attempt_digest": attempt["attempt_digest"],
        "failure_id": attempt["failure_id"],
        "failure_receipt_digest": attempt["failure_receipt_digest"],
        "failure_class": attempt["failure_class"],
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
        "budget_reservation_id": attempt["budget_reservation_id"],
        "budget_account_version": attempt["budget_account_version"],
        "approval_consumption_id": attempt["approval_consumption_id"],
        "policy_bundle_id": attempt["policy_bundle_id"],
        "policy_hash": attempt["policy_hash"],
        "retry_policy_id": policy["retry_policy_id"],
        "retry_policy_revision": policy["revision"],
        "retry_policy_digest": policy["policy_digest"],
        "outcome": outcome,
        "reason_code": reason,
        "current_attempt_number": 1,
        "proposed_attempt_number": 2,
        "earliest_retry_at": earliest,
        "retry_units_consumed": 0,
        "purpose": command["purpose"],
        "decided_at": decided_at,
        "expires_at": expires_at,
        "decision_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    decision["decision_digest"] = "sha256:" + content_hash(
        {key: value for key, value in decision.items() if key != "decision_digest"}
    )
    return decision


def _retry_document_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "command_id": receipt["command_id"],
        "assessment_id": receipt["assessment_id"],
        "plan_id": receipt["plan_id"],
        "expected_plan_revision": receipt["plan_revision"],
        "task_id": receipt["task_id"],
        "expected_task_revision": receipt["task_revision"],
        "agent_id": receipt["agent_id"],
        "capability_manifest_id": receipt["capability_manifest_id"],
        "capability_manifest_digest": receipt["capability_manifest_digest"],
        "manifest_revision": receipt["manifest_revision"],
        "budget_reservation_id": receipt["budget_reservation_id"],
        "budget_request_digest": receipt["budget_request_digest"],
        "budget_account_version": receipt["budget_account_version"],
        "retry_activation_id": receipt["retry_activation_id"],
        "retry_activation_digest": receipt["retry_activation_digest"],
        "retry_attempt_id": receipt["attempt_id"],
        "retry_attempt_digest": receipt["retry_attempt_digest"],
        "retry_budget_consumption_id": receipt["retry_budget_consumption_id"],
        "approval_consumption_id": receipt["approval_consumption_id"],
        "lease_consumption_id": receipt["lease_consumption_id"],
        "policy_bundle_id": receipt["policy_bundle_id"],
        "policy_hash": receipt["policy_hash"],
        "worker_id": receipt["worker_id"],
        "expected_worker_version": receipt["worker_version"],
        "lease_generation": receipt["lease_generation"],
        "fencing_token": receipt["fencing_token"],
        "expected_recovery_generation": receipt["recovery_generation"],
        "checkpoint_id": receipt["checkpoint_id"],
        "checkpoint_sequence": receipt["checkpoint_sequence"],
        "checkpoint_digest": receipt["checkpoint_digest"],
        "failure_id": receipt["failure_id"],
        "failure_receipt_digest": receipt["failure_receipt_digest"],
        "failure_class": receipt["failure_class"],
        "attempt_number": 2,
        "purpose": "register_failed_retry_validation_attempt",
        "requested_at": receipt["registered_at"],
        "expires_at": receipt["registered_at"],
        "authority": "none",
        "execution_enabled": False,
    }


def _retry_attempt_decision(
    command: dict[str, Any],
    attempt: dict[str, Any],
    policy: dict[str, Any],
    decision_id: str,
    command_digest: str,
    outcome: str,
    reason: str,
    earliest: str | None,
    decided_at: str,
    expires_at: str,
) -> dict[str, Any]:
    decision = {
        "schema_version": "2.0.0",
        "decision_id": decision_id,
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
        "failure_class": attempt["failure_class"],
        "checkpoint_id": attempt["checkpoint_id"],
        "checkpoint_digest": attempt["checkpoint_digest"],
        "lease_consumption_id": attempt["lease_consumption_id"],
        "worker_id": attempt["worker_id"],
        "worker_version": attempt["worker_version"],
        "lease_generation": attempt["lease_generation"],
        "fencing_token": attempt["fencing_token"],
        "recovery_generation": attempt["recovery_generation"],
        "capability_manifest_id": attempt["capability_manifest_id"],
        "capability_manifest_digest": attempt["capability_manifest_digest"],
        "manifest_revision": attempt["manifest_revision"],
        "budget_reservation_id": attempt["budget_reservation_id"],
        "budget_request_digest": attempt["budget_request_digest"],
        "budget_account_version": attempt["budget_account_version"],
        "approval_consumption_id": attempt["approval_consumption_id"],
        "policy_bundle_id": attempt["policy_bundle_id"],
        "policy_hash": attempt["policy_hash"],
        "retry_activation_id": attempt["retry_activation_id"],
        "retry_activation_digest": attempt["retry_activation_digest"],
        "retry_budget_consumption_id": attempt["retry_budget_consumption_id"],
        "retry_policy_id": policy["retry_policy_id"],
        "retry_policy_revision": policy["revision"],
        "retry_policy_digest": policy["policy_digest"],
        "outcome": outcome,
        "reason_code": reason,
        "current_attempt_number": 2,
        "proposed_attempt_number": 3,
        "earliest_retry_at": earliest,
        "retry_units_consumed": 0,
        "purpose": command["purpose"],
        "decided_at": decided_at,
        "expires_at": expires_at,
        "decision_digest": "",
        "authority": "none",
        "execution_enabled": False,
    }
    decision["decision_digest"] = "sha256:" + content_hash(
        {key: value for key, value in decision.items() if key != "decision_digest"}
    )
    return decision


def _audit(
    connection: sqlite3.Connection, action: str, subject_id: str, data: dict[str, Any]
) -> None:
    occurred_at = cast(str, data.get("decided_at", data.get("issued_at")))
    event = append_audit_event(
        connection,
        action=action,
        subject_type="orchestration_retry",
        subject_id=subject_id,
        actor_type="service",
        actor_id="pentai-core",
        data=data,
        occurred_at=occurred_at,
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_retry', ?, ?, ?)""",
        (
            str(uuid4()),
            subject_id,
            action,
            canonical_json({"event_hash": event["event_hash"], "subject_id": subject_id}),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationRetryError("ORCHESTRATION_RETRY_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
