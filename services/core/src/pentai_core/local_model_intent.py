from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

PROVIDER_ID = "llama.cpp"
MODEL_ID = "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M"
CAPABILITY = "ai.local.generate"
PURPOSE = "propose_supervised_local_model_generation"
MAX_REQUEST_LIFETIME = timedelta(minutes=5)
MAX_MANIFEST_LIFETIME = timedelta(minutes=15)
_NAMESPACE = UUID("d9edb143-e578-430c-a165-b08567364553")


class LocalModelIntentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LocalModelIntentService:
    """Create pending local-model intents without granting or executing them."""

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
        configuration_snapshot_id: str,
        configuration_snapshot_digest: str,
        maximum_input_tokens: int,
        maximum_output_tokens: int,
        maximum_runtime_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        self._require_storage_safe()
        policy_expiry = self._policy_expiry(
            assessment_id, policy_bundle_id, policy_hash, instant
        )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._revalidate_task(
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
            configuration = self._configuration(
                connection,
                configuration_snapshot_id,
                configuration_snapshot_digest,
                instant,
            )
            configured_limits = configuration["budgets"]
            requested_limits = {
                "maximum_input_tokens": maximum_input_tokens,
                "maximum_output_tokens": maximum_output_tokens,
                "maximum_runtime_seconds": maximum_runtime_seconds,
            }
            if (
                maximum_input_tokens > configured_limits["max_input_tokens"]
                or maximum_output_tokens > configured_limits["max_output_tokens"]
                or maximum_runtime_seconds > configured_limits["max_runtime_seconds"]
            ):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_MANIFEST_LIMIT_EXCEEDED",
                    "local model manifest exceeds configuration ceilings",
                )
            issued_at = _timestamp(instant)
            expires_at = _timestamp(
                min(
                    instant + MAX_MANIFEST_LIFETIME,
                    policy_expiry,
                    parse_time(configuration["expires_at"]),
                )
            )
            manifest_id = str(
                uuid5(
                    _NAMESPACE,
                    f"manifest:{plan_id}:{task_id}:{expected_task_revision}:{agent_id}:"
                    f"{configuration_snapshot_id}",
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
                "configuration_snapshot_id": configuration_snapshot_id,
                "configuration_snapshot_digest": configuration_snapshot_digest,
                "provider_id": PROVIDER_ID,
                "model_id": MODEL_ID,
                "allowed_purpose": PURPOSE,
                "allowed_capability": CAPABILITY,
                "allowed_input_classifications": configuration[
                    "allowed_input_classifications"
                ],
                "limits": requested_limits,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "issued_by": "pentai-core",
                "delegation_allowed": False,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(manifest, "local-model-capability-manifest-v1.schema.json"):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_MANIFEST_MALFORMED", "local model manifest is malformed"
                )
            manifest_hash = content_hash(manifest)
            replay = connection.execute(
                "SELECT manifest_hash,manifest_json FROM local_model_capability_manifests_v1 "
                "WHERE manifest_id=?",
                (manifest_id,),
            ).fetchone()
            if replay is not None:
                if replay["manifest_hash"] != manifest_hash:
                    raise LocalModelIntentError(
                        "LOCAL_MODEL_MANIFEST_IDENTITY_CONFLICT",
                        "local model manifest identity conflicts",
                    )
                return cast(dict[str, Any], json.loads(str(replay["manifest_json"])))
            connection.execute(
                """INSERT INTO local_model_capability_manifests_v1(
                manifest_id,manifest_hash,assessment_id,plan_id,plan_revision,task_id,
                task_revision,agent_id,policy_bundle_id,policy_hash,
                configuration_snapshot_id,configuration_snapshot_digest,manifest_json,
                issued_at,expires_at,authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                (
                    manifest_id,
                    manifest_hash,
                    assessment_id,
                    plan_id,
                    expected_plan_revision,
                    task_id,
                    expected_task_revision,
                    agent_id,
                    policy_bundle_id,
                    policy_hash,
                    configuration_snapshot_id,
                    configuration_snapshot_digest,
                    canonical_json(manifest),
                    issued_at,
                    expires_at,
                ),
            )
            self._audit(
                connection,
                action="orchestration.local_model_capability_manifest_issued",
                subject_type="local_model_capability_manifest",
                subject_id=manifest_id,
                actor_type="service",
                actor_id="pentai-core",
                occurred_at=issued_at,
                data={
                    "assessment_id": assessment_id,
                    "plan_id": plan_id,
                    "plan_revision": expected_plan_revision,
                    "task_id": task_id,
                    "task_revision": expected_task_revision,
                    "configuration_snapshot_id": configuration_snapshot_id,
                    "capability": CAPABILITY,
                    "authority": "none",
                    "execution_enabled": False,
                },
            )
        return copy.deepcopy(manifest)

    def convert(self, request: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = copy.deepcopy(request)
        if contract_issues(document, "agent-local-model-intent-request-v1.schema.json"):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_REQUEST_MALFORMED",
                "local model intent request is malformed",
            )
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
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_REQUEST_STALE", "local model intent request is stale"
            )
        if "sha256:" + content_hash(document["action"]) != document["action_sha256"]:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_ACTION_TAMPERED", "local model action digest mismatches"
            )
        self._require_storage_safe()
        self._policy_expiry(
            document["assessment_id"],
            document["policy_bundle_id"],
            document["policy_hash"],
            instant,
        )
        request_digest = "sha256:" + content_hash(document)
        intent_id = str(uuid5(_NAMESPACE, f"intent:{document['request_id']}"))
        action = document["action"]
        intent = {
            "schema_version": "2.0.0",
            "intent_id": intent_id,
            "assessment_id": document["assessment_id"],
            "task_id": document["task_id"],
            "policy_hash": document["policy_hash"],
            "actor": {"actor_type": "agent", "actor_id": document["agent"]["agent_id"]},
            "capability": CAPABILITY,
            "local_model": {
                "configuration_snapshot_id": action["configuration_snapshot_id"],
                "configuration_snapshot_digest": action["configuration_snapshot_digest"],
                "provider_id": PROVIDER_ID,
                "model_id": MODEL_ID,
            },
            "input_sha256": document["input_sha256"],
            "input_classification": document["input_classification"],
            "parameters_digest": content_hash(action),
            "requested_limits": copy.deepcopy(action["requested_limits"]),
            "created_at": document["created_at"],
            "expires_at": document["expires_at"],
            "idempotency_key": f"local-model-intent:{document['request_id']}",
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(intent, "action-intent-v2.schema.json"):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_RESULT_INVALID", "local model intent result is invalid"
            )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._revalidate_task(
                connection,
                assessment_id=document["assessment_id"],
                plan_id=document["plan_id"],
                plan_revision=document["expected_plan_revision"],
                task_id=document["task_id"],
                task_revision=document["expected_task_revision"],
                policy_bundle_id=document["policy_bundle_id"],
                policy_hash=document["policy_hash"],
                instant=instant,
            )
            configuration = self._configuration(
                connection,
                action["configuration_snapshot_id"],
                action["configuration_snapshot_digest"],
                instant,
            )
            self._revalidate_manifest(connection, document, configuration, instant)
            replay = connection.execute(
                "SELECT request_digest,intent_id FROM agent_local_model_intent_links_v1 "
                "WHERE request_id=?",
                (document["request_id"],),
            ).fetchone()
            if replay is not None:
                if replay["request_digest"] != request_digest:
                    raise LocalModelIntentError(
                        "LOCAL_MODEL_INTENT_IDENTITY_CONFLICT",
                        "local model request identity conflicts",
                    )
                stored = connection.execute(
                    "SELECT intent_json FROM action_intents WHERE intent_id=?",
                    (replay["intent_id"],),
                ).fetchone()
                if stored is None:
                    raise LocalModelIntentError(
                        "LOCAL_MODEL_INTENT_STORED_STATE_INVALID",
                        "stored local model intent is missing",
                    )
                return cast(dict[str, Any], json.loads(str(stored["intent_json"])))
            try:
                connection.execute(
                    """INSERT INTO action_intents(
                    intent_id,engagement_id,policy_bundle_id,policy_hash,idempotency_key,
                    intent_hash,intent_json,created_at) VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        intent_id,
                        document["assessment_id"],
                        document["policy_bundle_id"],
                        document["policy_hash"],
                        intent["idempotency_key"],
                        content_hash(intent),
                        canonical_json(intent),
                        document["created_at"],
                    ),
                )
                connection.execute(
                    """INSERT INTO agent_local_model_intent_links_v1(
                    request_id,request_digest,intent_id,assessment_id,plan_id,plan_revision,
                    task_id,task_revision,agent_id,capability_manifest_id,
                    configuration_snapshot_id,configuration_snapshot_digest,input_sha256,
                    action_sha256,created_at,authority,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
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
                        document["capability_manifest_id"],
                        action["configuration_snapshot_id"],
                        action["configuration_snapshot_digest"],
                        document["input_sha256"],
                        document["action_sha256"],
                        document["created_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_INTENT_IDENTITY_CONFLICT",
                    "local model intent identity conflicts",
                ) from error
            self._audit(
                connection,
                action="agent.local_model_action_intent_created",
                subject_type="action_intent",
                subject_id=intent_id,
                actor_type="agent",
                actor_id=document["agent"]["agent_id"],
                occurred_at=document["created_at"],
                data={
                    "plan_id": document["plan_id"],
                    "plan_revision": document["expected_plan_revision"],
                    "task_id": document["task_id"],
                    "task_revision": document["expected_task_revision"],
                    "configuration_snapshot_id": action["configuration_snapshot_id"],
                    "capability": CAPABILITY,
                    "pending_policy_evaluation": True,
                    "authority": "none",
                    "execution_enabled": False,
                },
            )
        return copy.deepcopy(intent)

    def _require_storage_safe(self) -> None:
        try:
            self.authorization._require_storage_safe()
        except DomainError as error:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_STORAGE_UNSAFE", "storage safety denies"
            ) from error

    def _policy_expiry(
        self,
        assessment_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        instant: datetime,
    ) -> datetime:
        try:
            verified = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_POLICY_INVALID", "policy is invalid"
            ) from error
        policy = verified["policy"]
        expiry = parse_time(policy["validity"]["not_after"])
        if (
            verified["status"] != "active"
            or verified["content_hash"] != policy_hash
            or parse_time(policy["validity"]["not_before"]) > instant
            or expiry <= instant
        ):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_POLICY_STALE", "policy is stale"
            )
        return expiry

    @staticmethod
    def _revalidate_task(
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
        assessment = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (assessment_id,)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id=? AND engagement_id=?",
            (policy_bundle_id, assessment_id),
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id=?", (plan_id,)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (plan_id, task_id),
        ).fetchone()
        if (
            assessment is None
            or assessment["status"] != "active"
            or assessment["active_policy_id"] != policy_bundle_id
            or parse_time(str(assessment["expires_at"])) <= instant
            or safety is None
            or safety["global_status"] != "active"
        ):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_SAFETY_DENIED", "assessment safety denies"
            )
        if (
            policy is None
            or policy["content_hash"] != policy_hash
            or policy["activated_at"] is None
            or policy["revoked_at"] is not None
        ):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_POLICY_STALE", "policy is stale"
            )
        if plan is None or plan["assessment_id"] != assessment_id:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_PLAN_MISMATCH", "plan does not match"
            )
        if plan["state"] != "active" or plan["revision"] != plan_revision:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_PLAN_FENCED", "plan is stale"
            )
        if task is None or task["assessment_id"] != assessment_id:
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_TASK_MISMATCH", "task does not match"
            )
        if (
            task["state"] != "running"
            or task["revision"] != task_revision
            or task["task_type"] != "validation"
        ):
            raise LocalModelIntentError(
                "LOCAL_MODEL_INTENT_TASK_DENIED", "task cannot propose local model work"
            )

    @staticmethod
    def _configuration(
        connection: sqlite3.Connection,
        snapshot_id: str,
        snapshot_digest: str,
        instant: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            """SELECT c.snapshot_json,c.snapshot_digest,a.expires_at AS activation_expires_at
            FROM ai_provider_configuration_snapshots_v1 AS c
            JOIN ai_provider_configuration_snapshot_productions_v1 AS p
              ON p.snapshot_id=c.snapshot_id AND p.snapshot_digest=c.snapshot_digest
            JOIN ai_provider_registry_activations_v1 AS a
              ON a.activation_id=p.activation_id
            WHERE c.snapshot_id=? AND c.snapshot_digest=?
              AND c.provider_type='local_runtime' AND c.provider_id=? AND c.model_id=?
              AND c.state='inactive' AND c.authority='none' AND c.execution_enabled=0
              AND a.state='active' AND a.authority='none' AND a.execution_enabled=0""",
            (snapshot_id, snapshot_digest, PROVIDER_ID, MODEL_ID),
        ).fetchone()
        if row is None:
            raise LocalModelIntentError(
                "LOCAL_MODEL_CONFIGURATION_MISMATCH",
                "local model configuration does not match",
            )
        document = cast(dict[str, Any], json.loads(str(row["snapshot_json"])))
        if (
            contract_issues(document, "ai-provider-configuration-snapshot-v1.schema.json")
            or parse_time(document["expires_at"]) <= instant
            or parse_time(str(row["activation_expires_at"])) <= instant
        ):
            raise LocalModelIntentError(
                "LOCAL_MODEL_CONFIGURATION_STALE", "local model configuration is stale"
            )
        return document

    @staticmethod
    def _revalidate_manifest(
        connection: sqlite3.Connection,
        document: dict[str, Any],
        configuration: dict[str, Any],
        instant: datetime,
    ) -> None:
        row = connection.execute(
            "SELECT manifest_json FROM local_model_capability_manifests_v1 "
            "WHERE manifest_id=?",
            (document["capability_manifest_id"],),
        ).fetchone()
        if row is None:
            raise LocalModelIntentError(
                "LOCAL_MODEL_MANIFEST_MISSING", "local model manifest is missing"
            )
        manifest = cast(dict[str, Any], json.loads(str(row["manifest_json"])))
        action = document["action"]
        exact = (
            not contract_issues(manifest, "local-model-capability-manifest-v1.schema.json")
            and manifest["assessment_id"] == document["assessment_id"]
            and manifest["plan_id"] == document["plan_id"]
            and manifest["plan_revision"] == document["expected_plan_revision"]
            and manifest["task_id"] == document["task_id"]
            and manifest["task_revision"] == document["expected_task_revision"]
            and manifest["agent_id"] == document["agent"]["agent_id"]
            and manifest["policy_bundle_id"] == document["policy_bundle_id"]
            and manifest["policy_hash"] == document["policy_hash"]
            and manifest["configuration_snapshot_id"]
            == action["configuration_snapshot_id"]
            and manifest["configuration_snapshot_digest"]
            == action["configuration_snapshot_digest"]
            and manifest["allowed_purpose"] == document["purpose"]
            and manifest["allowed_capability"] == action["capability"]
            and document["input_classification"]
            in manifest["allowed_input_classifications"]
            and configuration["snapshot_id"] == action["configuration_snapshot_id"]
        )
        if not exact:
            raise LocalModelIntentError(
                "LOCAL_MODEL_MANIFEST_MISMATCH", "local model manifest binding mismatches"
            )
        if parse_time(manifest["expires_at"]) <= instant:
            raise LocalModelIntentError(
                "LOCAL_MODEL_MANIFEST_STALE", "local model manifest is stale"
            )
        requested = action["requested_limits"]
        allowed = manifest["limits"]
        if any(requested[key] > allowed[key] for key in requested):
            raise LocalModelIntentError(
                "LOCAL_MODEL_MANIFEST_LIMIT_EXCEEDED", "local model limits exceeded"
            )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        subject_type: str,
        subject_id: str,
        actor_type: str,
        actor_id: str,
        occurred_at: str,
        data: dict[str, Any],
    ) -> None:
        event = append_audit_event(
            connection,
            action=action,
            subject_type=subject_type,
            subject_id=subject_id,
            actor_type=actor_type,
            actor_id=actor_id,
            data=data,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO outbox(id,aggregate_type,aggregate_id,event_type,payload_json) "
            "VALUES (?,?,?,?,?)",
            (
                str(uuid4()),
                subject_type,
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
        raise LocalModelIntentError("LOCAL_MODEL_INTENT_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
