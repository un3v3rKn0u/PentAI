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

_MAX_LIFETIME = timedelta(minutes=15)
_NAMESPACE = UUID("28c82fbb-f067-41fc-9548-e74c24225a47")


class OrchestrationApprovalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationApprovalService:
    """Approve task readiness without approving an action or creating authority."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def create_request(
        self,
        *,
        assessment_id: str,
        plan_id: str,
        expected_plan_revision: int,
        task_id: str,
        expected_task_revision: int,
        policy_bundle_id: str,
        policy_hash: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        self.authorization._require_storage_safe()
        verified_policy = self._verified_policy(assessment_id, policy_bundle_id, policy_hash)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._validate_current(
                connection,
                assessment_id=assessment_id,
                plan_id=plan_id,
                plan_revision=expected_plan_revision,
                task_id=task_id,
                task_revision=expected_task_revision,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                instant=instant,
                required_state="awaiting_human",
            )
            request_id = str(
                uuid5(_NAMESPACE, f"request:{plan_id}:{task_id}:{expected_task_revision}")
            )
            requested_at = _timestamp(instant)
            expires_at = _timestamp(
                min(
                    instant + _MAX_LIFETIME,
                    parse_time(verified_policy["policy"]["validity"]["not_after"]),
                )
            )
            parameters_digest = "sha256:" + content_hash(
                {
                    "task_type": task["task_type"],
                    "objective": task["objective"],
                    "input_refs": json.loads(task["input_refs_json"]),
                    "requires_human_approval": True,
                }
            )
            document = {
                "schema_version": "1.0.0",
                "request_id": request_id,
                "assessment_id": assessment_id,
                "plan_id": plan_id,
                "plan_revision": expected_plan_revision,
                "task_id": task_id,
                "task_revision": expected_task_revision,
                "task_type": task["task_type"],
                "policy_bundle_id": policy_bundle_id,
                "policy_hash": policy_hash,
                "purpose": "authorize_task_readiness",
                "requested_capability": "orchestration.task.ready",
                "parameters_digest": parameters_digest,
                "requested_at": requested_at,
                "expires_at": expires_at,
                "requires_human_approval": True,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(document, "orchestration-task-approval-request-v1.schema.json"):
                raise OrchestrationApprovalError(
                    "ORCHESTRATION_APPROVAL_REQUEST_INVALID", "approval request is invalid"
                )
            digest = "sha256:" + content_hash(document)
            existing = connection.execute(
                """SELECT request_digest, document_json
                FROM orchestration_task_approval_requests WHERE request_id = ?""",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != digest:
                    raise OrchestrationApprovalError(
                        "ORCHESTRATION_APPROVAL_IDENTITY_CONFLICT",
                        "approval request identity conflicts",
                    )
                return cast(dict[str, Any], json.loads(existing["document_json"]))
            connection.execute(
                """INSERT INTO orchestration_task_approval_requests VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                (
                    request_id,
                    digest,
                    assessment_id,
                    plan_id,
                    expected_plan_revision,
                    task_id,
                    expected_task_revision,
                    task["task_type"],
                    policy_bundle_id,
                    policy_hash,
                    document["purpose"],
                    document["requested_capability"],
                    parameters_digest,
                    requested_at,
                    expires_at,
                    canonical_json(document),
                ),
            )
            _record(connection, "orchestration.task_approval_requested", request_id, document)
        return copy.deepcopy(document)

    def decide(
        self,
        request_id: str,
        *,
        decision: str,
        reason: str,
        explicit_confirmation: bool,
        approver_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_DECISION_INVALID", "decision is invalid"
            )
        if explicit_confirmation is not True:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_CONFIRMATION_REQUIRED",
                "explicit human confirmation is required",
            )
        normalized_reason = reason.strip()
        normalized_actor = approver_id.strip()
        if not 1 <= len(normalized_reason) <= 1000:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_REASON_INVALID", "reason is invalid"
            )
        if not 1 <= len(normalized_actor) <= 128:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_ACTOR_INVALID", "human actor is invalid"
            )
        if self.authorization.policy_signer is None:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_SIGNER_UNAVAILABLE", "approval signer is unavailable"
            )
        instant = _instant(now)
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            request_row = connection.execute(
                "SELECT * FROM orchestration_task_approval_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if request_row is None:
                raise OrchestrationApprovalError(
                    "ORCHESTRATION_APPROVAL_REQUEST_MISSING", "approval request is missing"
                )
            request_document = json.loads(request_row["document_json"])
            if (
                contract_issues(
                    request_document, "orchestration-task-approval-request-v1.schema.json"
                )
                or "sha256:" + content_hash(request_document) != request_row["request_digest"]
            ):
                raise OrchestrationApprovalError(
                    "ORCHESTRATION_APPROVAL_REQUEST_INVALID", "approval request is invalid"
                )
            self._verified_policy(
                request_document["assessment_id"],
                request_document["policy_bundle_id"],
                request_document["policy_hash"],
            )
            existing = connection.execute(
                """SELECT document_json, content_hash
                FROM orchestration_task_approval_decisions WHERE request_id = ?""",
                (request_id,),
            ).fetchone()
            if existing is not None:
                stored = cast(dict[str, Any], json.loads(existing["document_json"]))
                self._validate_decision_replay(
                    connection,
                    stored,
                    decision=decision,
                    reason=normalized_reason,
                    approver_id=normalized_actor,
                    content_hash_value=existing["content_hash"],
                    instant=instant,
                    signer=self.authorization.policy_signer,
                )
                return stored
            requested_at = parse_time(request_document["requested_at"])
            expires_at = parse_time(request_document["expires_at"])
            if (
                requested_at > instant
                or instant - requested_at > _MAX_LIFETIME
                or expires_at <= instant
                or expires_at <= requested_at
            ):
                raise OrchestrationApprovalError(
                    "ORCHESTRATION_APPROVAL_REQUEST_STALE", "approval request is stale"
                )
            self._validate_current(
                connection,
                assessment_id=request_document["assessment_id"],
                plan_id=request_document["plan_id"],
                plan_revision=request_document["plan_revision"],
                task_id=request_document["task_id"],
                task_revision=request_document["task_revision"],
                policy_bundle_id=request_document["policy_bundle_id"],
                policy_hash=request_document["policy_hash"],
                instant=instant,
                required_state="awaiting_human",
            )
            resulting_state = "awaiting_human" if decision == "approved" else "cancelled"
            revision_increment = 0 if decision == "approved" else 1
            decided_at = _timestamp(instant)
            document: dict[str, Any] = {
                "schema_version": "1.0.0",
                "decision_id": str(uuid5(_NAMESPACE, "decision:" + request_id)),
                "request_id": request_id,
                "request_digest": request_row["request_digest"],
                "assessment_id": request_document["assessment_id"],
                "plan_id": request_document["plan_id"],
                "plan_revision": request_document["plan_revision"] + revision_increment,
                "task_id": request_document["task_id"],
                "task_revision": request_document["task_revision"] + revision_increment,
                "policy_bundle_id": request_document["policy_bundle_id"],
                "policy_hash": request_document["policy_hash"],
                "decision": decision,
                "reason": normalized_reason,
                "approver": {"actor_type": "human", "actor_id": normalized_actor},
                "authentication_context": "trusted_core_caller_assertion",
                "explicit_confirmation": True,
                "decided_at": decided_at,
                "expires_at": request_document["expires_at"],
                "resulting_task_state": resulting_state,
                "authority": "none",
                "execution_enabled": False,
            }
            document["signature"] = {
                "algorithm": "Ed25519",
                "key_id": self.authorization.policy_signer.key_id,
                "value": self.authorization.policy_signer.sign(canonical_json(document).encode()),
            }
            if contract_issues(document, "orchestration-task-approval-decision-v1.schema.json"):
                raise OrchestrationApprovalError(
                    "ORCHESTRATION_APPROVAL_RESULT_INVALID", "approval decision is invalid"
                )
            connection.execute(
                """INSERT INTO orchestration_task_approval_decisions VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                (
                    document["decision_id"],
                    request_id,
                    request_row["request_digest"],
                    decision,
                    normalized_actor,
                    decided_at,
                    document["expires_at"],
                    resulting_state,
                    canonical_json(document),
                    content_hash(document),
                ),
            )
            if decision == "rejected":
                connection.execute(
                    """UPDATE orchestration_tasks SET state = 'cancelled', revision = revision + 1,
                    updated_at = ? WHERE task_id = ? AND revision = ?""",
                    (decided_at, request_document["task_id"], request_document["task_revision"]),
                )
                plan_state = _plan_state(connection, request_document["plan_id"])
                connection.execute(
                    """UPDATE orchestration_plans SET revision = revision + 1, updated_at = ?,
                    state = ? WHERE plan_id = ? AND revision = ?""",
                    (
                        decided_at,
                        plan_state,
                        request_document["plan_id"],
                        request_document["plan_revision"],
                    ),
                )
            _record(
                connection,
                "orchestration.task_approval_approved"
                if decision == "approved"
                else "orchestration.task_approval_rejected",
                request_id,
                document,
                actor_id=normalized_actor,
                actor_type="human",
            )
        return copy.deepcopy(document)

    def _verified_policy(
        self, assessment_id: str, policy_bundle_id: str, policy_hash: str
    ) -> dict[str, Any]:
        try:
            policy = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as exc:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_POLICY_STALE", "policy is stale"
            ) from exc
        if policy["content_hash"] != policy_hash or policy["status"] != "active":
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_POLICY_STALE", "policy is stale"
            )
        return policy

    @staticmethod
    def _validate_decision_replay(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        *,
        decision: str,
        reason: str,
        approver_id: str,
        content_hash_value: str,
        instant: datetime,
        signer: Any,
    ) -> None:
        unsigned = {key: value for key, value in document.items() if key != "signature"}
        if (
            contract_issues(document, "orchestration-task-approval-decision-v1.schema.json")
            or content_hash(document) != content_hash_value
            or not signer.verify(
                canonical_json(unsigned).encode(),
                document["signature"]["value"],
                document["signature"]["key_id"],
            )
            or document["decision"] != decision
            or document["reason"] != reason
            or document["approver"]["actor_id"] != approver_id
        ):
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_IDENTITY_CONFLICT", "decision identity conflicts"
            )
        plan = connection.execute(
            "SELECT revision, state FROM orchestration_plans WHERE plan_id = ?",
            (document["plan_id"],),
        ).fetchone()
        task = connection.execute(
            "SELECT revision, state FROM orchestration_tasks WHERE task_id = ?",
            (document["task_id"],),
        ).fetchone()
        if (
            plan is None
            or task is None
            or plan["revision"] != document["plan_revision"]
            or task["revision"] != document["task_revision"]
            or task["state"] != document["resulting_task_state"]
            or (plan["state"] != "active" and document["resulting_task_state"] == "awaiting_human")
            or parse_time(document["expires_at"]) <= instant
        ):
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_REPLAY_STALE", "decision replay is stale"
            )

    @staticmethod
    def _validate_current(
        connection: sqlite3.Connection,
        *,
        assessment_id: str,
        plan_id: str,
        plan_revision: int,
        task_id: str,
        task_revision: int,
        policy_bundle_id: str,
        policy_hash: str,
        instant: datetime,
        required_state: str,
    ) -> sqlite3.Row:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (assessment_id,)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id = ? AND engagement_id = ?",
            (policy_bundle_id, assessment_id),
        ).fetchone()
        if (
            engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != policy_bundle_id
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
        ):
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_SAFETY_DENIED", "assessment safety denies"
            )
        if (
            policy is None
            or policy["content_hash"] != policy_hash
            or policy["activated_at"] is None
            or policy["revoked_at"] is not None
        ):
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_POLICY_STALE", "policy is stale"
            )
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? AND task_id = ?",
            (plan_id, task_id),
        ).fetchone()
        if plan is None or plan["assessment_id"] != assessment_id:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_PLAN_MISMATCH", "plan binding mismatches"
            )
        if plan["state"] != "active" or plan["revision"] != plan_revision:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_PLAN_FENCED", "plan is not current"
            )
        if task is None or task["assessment_id"] != assessment_id:
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_TASK_MISMATCH", "task binding mismatches"
            )
        if (
            task["revision"] != task_revision
            or task["state"] != required_state
            or not task["requires_human_approval"]
        ):
            raise OrchestrationApprovalError(
                "ORCHESTRATION_APPROVAL_TASK_FENCED", "task is not awaiting approval"
            )
        return cast(sqlite3.Row, task)


def _plan_state(connection: sqlite3.Connection, plan_id: str) -> str:
    states = [
        str(row[0])
        for row in connection.execute(
            "SELECT state FROM orchestration_tasks WHERE plan_id = ?", (plan_id,)
        )
    ]
    if all(state == "succeeded" for state in states):
        return "completed"
    if all(state in {"cancelled", "succeeded", "failed"} for state in states):
        return "failed" if "failed" in states else "cancelled"
    return "active"


def _record(
    connection: sqlite3.Connection,
    action: str,
    subject_id: str,
    data: dict[str, Any],
    *,
    actor_id: str = "pentai-core",
    actor_type: str = "service",
) -> None:
    occurred_at = data.get("decided_at") or data["requested_at"]
    event = append_audit_event(
        connection,
        action=action,
        subject_type="orchestration_task_approval",
        subject_id=subject_id,
        actor_type=actor_type,
        actor_id=actor_id,
        data=data,
        occurred_at=occurred_at,
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_task_approval', ?, ?, ?)""",
        (
            str(uuid4()),
            subject_id,
            action,
            canonical_json(
                {
                    "event_hash": event["event_hash"],
                    "occurred_at": occurred_at,
                    "subject_id": subject_id,
                }
            ),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise OrchestrationApprovalError("ORCHESTRATION_APPROVAL_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
