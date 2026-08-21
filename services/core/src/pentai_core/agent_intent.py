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
MAX_MANIFEST_LIFETIME = timedelta(minutes=15)
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

    def issue_capability_manifest(
        self,
        *,
        assessment_id: str,
        plan_id: str,
        expected_plan_revision: int,
        task_id: str,
        expected_task_revision: int,
        agent_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        maximum_impact: str = "benign",
        maximum_timeout_seconds: int = 30,
        maximum_response_bytes: int = 1_048_576,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        issued_at = _timestamp(instant)
        expires_at = _timestamp(instant + MAX_MANIFEST_LIFETIME)
        manifest_id = str(
            uuid5(
                _INTENT_NAMESPACE,
                f"manifest:{plan_id}:{task_id}:{expected_task_revision}:{agent_id}",
            )
        )
        manifest = {
            "schema_version": "1.0.0",
            "manifest_id": manifest_id,
            "manifest_revision": 1,
            "assessment_id": assessment_id,
            "plan_id": plan_id,
            "plan_revision": expected_plan_revision,
            "task_id": task_id,
            "task_revision": expected_task_revision,
            "task_type": "validation",
            "agent_id": agent_id,
            "policy_bundle_id": policy_bundle_id,
            "policy_hash": policy_hash,
            "allowed_purposes": ["propose_supervised_http_validation"],
            "allowed_capabilities": ["network.http.get"],
            "limits": {
                "maximum_impact": maximum_impact,
                "maximum_timeout_seconds": maximum_timeout_seconds,
                "maximum_response_bytes": maximum_response_bytes,
            },
            "issued_at": issued_at,
            "expires_at": expires_at,
            "issued_by": "pentai-core",
            "delegation_allowed": False,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(manifest, "task-capability-manifest-v1.schema.json"):
            raise AgentIntentError(
                "TASK_CAPABILITY_MANIFEST_MALFORMED", "capability manifest is malformed"
            )
        self.authorization._require_storage_safe()
        try:
            verified = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise AgentIntentError("TASK_CAPABILITY_POLICY_INVALID", "policy is invalid") from error
        if verified["status"] != "active" or verified["content_hash"] != policy_hash:
            raise AgentIntentError("TASK_CAPABILITY_POLICY_STALE", "policy is stale")
        policy_expiry = parse_time(verified["policy"]["validity"]["not_after"])
        if policy_expiry <= instant:
            raise AgentIntentError("TASK_CAPABILITY_POLICY_STALE", "policy is stale")
        expires_at = _timestamp(min(instant + MAX_MANIFEST_LIFETIME, policy_expiry))
        manifest["expires_at"] = expires_at
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._revalidate_binding(
                connection,
                assessment_id=assessment_id,
                plan_id=plan_id,
                plan_revision=expected_plan_revision,
                task_id=task_id,
                task_revision=expected_task_revision,
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                instant=instant,
            )
            existing = connection.execute(
                """SELECT manifest_hash, manifest_json
                FROM task_capability_manifests WHERE manifest_id = ?""",
                (manifest_id,),
            ).fetchone()
            manifest_hash = content_hash(manifest)
            if existing is not None:
                if existing["manifest_hash"] != manifest_hash:
                    raise AgentIntentError(
                        "TASK_CAPABILITY_IDENTITY_CONFLICT", "manifest identity conflicts"
                    )
                return cast(dict[str, Any], json.loads(str(existing["manifest_json"])))
            connection.execute(
                """INSERT INTO task_capability_manifests VALUES
                (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pentai-core', 0, 'none', 0)""",
                (
                    manifest_id,
                    assessment_id,
                    plan_id,
                    expected_plan_revision,
                    task_id,
                    expected_task_revision,
                    agent_id,
                    policy_bundle_id,
                    policy_hash,
                    canonical_json(manifest),
                    manifest_hash,
                    issued_at,
                    expires_at,
                ),
            )
            _record_manifest(connection, manifest)
        return copy.deepcopy(manifest)

    def convert(self, request: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(request)
        if document.get("schema_version") == "1.0.0":
            raise AgentIntentError(
                "AGENT_INTENT_CAPABILITY_MANIFEST_REQUIRED",
                "request v2 capability manifest is required",
            )
        if contract_issues(document, "agent-action-intent-request-v2.schema.json"):
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
            self._revalidate_manifest(connection, document, instant)
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
                    """INSERT INTO agent_action_intent_links(
                    request_id, request_digest, intent_id, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, agent_id, purpose,
                    policy_bundle_id, policy_hash, input_sha256, action_sha256,
                    created_at, authority, execution_enabled, capability_manifest_id,
                    capability_manifest_revision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0, ?, ?)""",
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
                        document["capability_manifest_id"],
                        document["expected_manifest_revision"],
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

    @staticmethod
    def _revalidate_binding(
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
    ) -> None:
        document = {
            "assessment_id": assessment_id,
            "plan_id": plan_id,
            "expected_plan_revision": plan_revision,
            "task_id": task_id,
            "expected_task_revision": task_revision,
            "policy_bundle_id": policy_bundle_id,
            "policy_hash": policy_hash,
        }
        AgentActionIntentService._revalidate_state(connection, document, instant)

    @staticmethod
    def _revalidate_manifest(
        connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> None:
        row = connection.execute(
            """SELECT manifest_json FROM task_capability_manifests
            WHERE manifest_id = ? AND manifest_revision = ?""",
            (document["capability_manifest_id"], document["expected_manifest_revision"]),
        ).fetchone()
        if row is None:
            raise AgentIntentError(
                "AGENT_INTENT_MANIFEST_MISSING", "capability manifest is missing"
            )
        manifest = json.loads(str(row["manifest_json"]))
        if contract_issues(manifest, "task-capability-manifest-v1.schema.json"):
            raise AgentIntentError(
                "AGENT_INTENT_MANIFEST_INVALID", "capability manifest is invalid"
            )
        exact = (
            manifest["assessment_id"] == document["assessment_id"]
            and manifest["plan_id"] == document["plan_id"]
            and manifest["plan_revision"] == document["expected_plan_revision"]
            and manifest["task_id"] == document["task_id"]
            and manifest["task_revision"] == document["expected_task_revision"]
            and manifest["agent_id"] == document["agent"]["agent_id"]
            and manifest["policy_bundle_id"] == document["policy_bundle_id"]
            and manifest["policy_hash"] == document["policy_hash"]
            and document["purpose"] in manifest["allowed_purposes"]
            and document["action"]["capability"] in manifest["allowed_capabilities"]
        )
        if not exact:
            raise AgentIntentError("AGENT_INTENT_MANIFEST_MISMATCH", "manifest binding mismatches")
        if parse_time(manifest["expires_at"]) <= instant:
            raise AgentIntentError("AGENT_INTENT_MANIFEST_STALE", "capability manifest is stale")
        impact_rank = {"passive": 0, "benign": 1}
        limits = manifest["limits"]
        requested = document["action"]["requested_limits"]
        if (
            impact_rank[document["action"]["impact"]] > impact_rank[limits["maximum_impact"]]
            or requested["timeout_seconds"] > limits["maximum_timeout_seconds"]
            or requested["maximum_response_bytes"] > limits["maximum_response_bytes"]
        ):
            raise AgentIntentError(
                "AGENT_INTENT_MANIFEST_LIMIT_EXCEEDED", "manifest limits exceeded"
            )


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


def _record_manifest(connection: sqlite3.Connection, manifest: dict[str, Any]) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    data = {
        "assessment_id": manifest["assessment_id"],
        "plan_id": manifest["plan_id"],
        "plan_revision": manifest["plan_revision"],
        "task_id": manifest["task_id"],
        "task_revision": manifest["task_revision"],
        "manifest_revision": manifest["manifest_revision"],
        "policy_hash": manifest["policy_hash"],
        "allowed_purposes": manifest["allowed_purposes"],
        "allowed_capabilities": manifest["allowed_capabilities"],
        "authority": "none",
        "execution_enabled": False,
    }
    event = {
        "event_id": str(uuid4()),
        "occurred_at": manifest["issued_at"],
        "actor_type": "service",
        "actor_id": "pentai-core",
        "action": "orchestration.task_capability_manifest_issued",
        "subject_type": "task_capability_manifest",
        "subject_id": manifest["manifest_id"],
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
            event["occurred_at"],
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
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, ?, ?, ?, ?)""",
        (
            str(uuid4()),
            "task_capability_manifest",
            manifest["manifest_id"],
            "orchestration.task_capability_manifest_issued",
            canonical_json(
                {
                    "event_hash": event_hash,
                    "occurred_at": manifest["issued_at"],
                    "subject_id": manifest["manifest_id"],
                }
            ),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise AgentIntentError("AGENT_INTENT_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
