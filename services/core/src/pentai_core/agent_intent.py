from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import CanonicalizationError, canonical_json, canonicalize_url, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

MAX_REQUEST_LIFETIME = timedelta(minutes=5)
_INTENT_NAMESPACE = UUID("9a60a844-e45a-49f1-9606-b7a923057ce6")


class AgentIntentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AgentActionIntentService:
    """Convert one typed agent proposal into a pending immutable ActionIntent."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path = authorization.database_path

    def convert(self, request: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(request)
        if contract_issues(document, "agent-action-intent-request-v1.schema.json"):
            raise AgentIntentError("AGENT_INTENT_REQUEST_MALFORMED", "agent request is malformed")
        instant = _instant(now)
        created_at = parse_time(document["created_at"])
        expires_at = parse_time(document["expires_at"])
        if (
            created_at > instant
            or instant - created_at > MAX_REQUEST_LIFETIME
            or expires_at <= instant
            or expires_at <= created_at
            or expires_at - created_at > MAX_REQUEST_LIFETIME
        ):
            raise AgentIntentError("AGENT_INTENT_REQUEST_STALE", "agent request is stale")
        action_digest = "sha256:" + content_hash(document["action"])
        if action_digest != document["action_sha256"]:
            raise AgentIntentError("AGENT_INTENT_ACTION_TAMPERED", "action digest does not match")
        try:
            canonical_target = canonicalize_url(document["action"]["target"]["canonical_url"])
        except CanonicalizationError as error:
            raise AgentIntentError("AGENT_INTENT_TARGET_INVALID", "target is invalid") from error
        if canonical_target != document["action"]["target"]:
            raise AgentIntentError("AGENT_INTENT_TARGET_AMBIGUOUS", "target is not canonical")

        self.authorization._require_storage_safe()
        try:
            verified_policy = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise AgentIntentError("AGENT_INTENT_POLICY_INVALID", "policy is invalid") from error
        policy = verified_policy["policy"]
        if (
            verified_policy["status"] != "active"
            or verified_policy["content_hash"] != document["policy_hash"]
            or parse_time(policy["validity"]["not_before"]) > instant
            or parse_time(policy["validity"]["not_after"]) <= instant
        ):
            raise AgentIntentError("AGENT_INTENT_POLICY_STALE", "policy is stale")

        request_digest = "sha256:" + content_hash(document)
        intent_id = str(uuid5(_INTENT_NAMESPACE, document["request_id"]))
        intent = {
            "schema_version": "1.0.0",
            "intent_id": intent_id,
            "assessment_id": document["assessment_id"],
            "task_id": document["task_id"],
            "policy_hash": document["policy_hash"],
            "actor": {"actor_type": "agent", "actor_id": document["agent"]["agent_id"]},
            "capability": document["action"]["capability"],
            "target": copy.deepcopy(document["action"]["target"]),
            "http": copy.deepcopy(document["action"]["http"]),
            "parameters_digest": content_hash(document["action"]),
            "impact": document["action"]["impact"],
            "requested_limits": copy.deepcopy(document["action"]["requested_limits"]),
            "created_at": document["created_at"],
            "expires_at": document["expires_at"],
            "idempotency_key": f"agent-intent:{document['request_id']}",
        }
        if contract_issues(intent, "action-intent-v1.schema.json"):
            raise AgentIntentError("AGENT_INTENT_RESULT_INVALID", "generated intent is invalid")

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._revalidate_state(connection, document, instant)
            replay = connection.execute(
                "SELECT * FROM agent_action_intent_links WHERE request_id = ?",
                (document["request_id"],),
            ).fetchone()
            if replay is not None:
                if replay["request_digest"] != request_digest:
                    raise AgentIntentError(
                        "AGENT_INTENT_REQUEST_IDENTITY_CONFLICT", "request identity was reused"
                    )
                stored = connection.execute(
                    "SELECT intent_json FROM action_intents WHERE intent_id = ?",
                    (replay["intent_id"],),
                ).fetchone()
                if stored is None:
                    raise AgentIntentError("AGENT_INTENT_STORED_STATE_INVALID", "intent is missing")
                return cast(dict[str, Any], json.loads(str(stored["intent_json"])))
            intent_hash = content_hash(intent)
            try:
                connection.execute(
                    """INSERT INTO action_intents(
                    intent_id, engagement_id, policy_bundle_id, policy_hash,
                    idempotency_key, intent_hash, intent_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        intent_id,
                        document["assessment_id"],
                        document["policy_bundle_id"],
                        document["policy_hash"],
                        intent["idempotency_key"],
                        intent_hash,
                        canonical_json(intent),
                        intent["created_at"],
                    ),
                )
                connection.execute(
                    """INSERT INTO agent_action_intent_links VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                    (
                        document["request_id"],
                        request_digest,
                        intent_id,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["agent"]["agent_id"],
                        document["purpose"],
                        document["policy_bundle_id"],
                        document["policy_hash"],
                        document["input_sha256"],
                        document["action_sha256"],
                        document["created_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise AgentIntentError(
                    "AGENT_INTENT_IDENTITY_CONFLICT", "intent identity conflicts"
                ) from error
            _record(connection, intent, document)
        return copy.deepcopy(intent)

    @staticmethod
    def _revalidate_state(
        connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> None:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (document["assessment_id"],)
        ).fetchone()
        global_state = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        if (
            engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != document["policy_bundle_id"]
            or parse_time(str(engagement["expires_at"])) <= instant
            or global_state is None
            or global_state["global_status"] != "active"
        ):
            raise AgentIntentError("AGENT_INTENT_SAFETY_DENIED", "assessment safety denies")
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id = ? AND engagement_id = ?",
            (document["policy_bundle_id"], document["assessment_id"]),
        ).fetchone()
        if (
            policy is None
            or policy["content_hash"] != document["policy_hash"]
            or policy["activated_at"] is None
            or policy["revoked_at"] is not None
        ):
            raise AgentIntentError("AGENT_INTENT_POLICY_STALE", "policy is stale")
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (document["plan_id"],)
        ).fetchone()
        if plan is None or plan["assessment_id"] != document["assessment_id"]:
            raise AgentIntentError("AGENT_INTENT_PLAN_MISMATCH", "plan does not match")
        if plan["state"] != "active" or plan["revision"] != document["expected_plan_revision"]:
            raise AgentIntentError("AGENT_INTENT_PLAN_FENCED", "plan is not current")
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE task_id = ? AND plan_id = ?",
            (document["task_id"], document["plan_id"]),
        ).fetchone()
        if task is None:
            raise AgentIntentError("AGENT_INTENT_TASK_MISMATCH", "task does not match")
        if task["revision"] != document["expected_task_revision"]:
            raise AgentIntentError("AGENT_INTENT_TASK_FENCED", "task is stale")
        if task["state"] != "running" or task["task_type"] != "validation":
            raise AgentIntentError("AGENT_INTENT_TASK_DENIED", "task cannot propose actions")


def _record(
    connection: sqlite3.Connection, intent: dict[str, Any], request: dict[str, Any]
) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    occurred_at = request["created_at"]
    data = {
        "plan_id": request["plan_id"],
        "plan_revision": request["expected_plan_revision"],
        "task_id": request["task_id"],
        "task_revision": request["expected_task_revision"],
        "policy_hash": request["policy_hash"],
        "capability": intent["capability"],
        "pending_policy_evaluation": True,
        "authority": "none",
        "execution_enabled": False,
    }
    event = {
        "event_id": str(uuid4()),
        "occurred_at": occurred_at,
        "actor_type": "agent",
        "actor_id": request["agent"]["agent_id"],
        "action": "agent.action_intent_created",
        "subject_type": "action_intent",
        "subject_id": intent["intent_id"],
        "data": data,
        "previous_hash": previous_hash,
    }
    event_hash = content_hash(event)
    connection.execute(
        """INSERT INTO audit_events(event_id, occurred_at, actor_type, actor_id, action,
        subject_type, subject_id, data_json, previous_hash, event_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event["event_id"],
            occurred_at,
            event["actor_type"],
            event["actor_id"],
            event["action"],
            event["subject_type"],
            event["subject_id"],
            canonical_json(data),
            previous_hash,
            event_hash,
        ),
    )
    connection.execute(
        """INSERT INTO outbox(
        id, aggregate_type, aggregate_id, event_type, payload_json
        ) VALUES (?, ?, ?, ?, ?)""",
        (
            str(uuid4()),
            "action_intent",
            intent["intent_id"],
            "agent.action_intent_created",
            canonical_json(
                {
                    "event_hash": event_hash,
                    "occurred_at": occurred_at,
                    "subject_id": intent["intent_id"],
                }
            ),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise AgentIntentError("AGENT_INTENT_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)
