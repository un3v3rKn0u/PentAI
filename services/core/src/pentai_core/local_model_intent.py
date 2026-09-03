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
from pentai_core.policy_signing import policy_signature_payload

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

    def evaluate(self, intent_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Evaluate one stored local-model intent without minting execution authority."""
        instant = _instant(now)
        self._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT ai.*, l.request_id,l.plan_id,l.plan_revision,l.task_id,l.task_revision,
                l.agent_id,l.capability_manifest_id,l.configuration_snapshot_id,
                l.configuration_snapshot_digest,m.manifest_hash,m.manifest_json,
                p.manifest_version_id,p.schema_version AS policy_schema_version,
                p.policy_json,p.signature,p.signer_key_id,p.activated_at,p.revoked_at,
                mv.content_hash AS manifest_version_hash,
                mv.schema_version AS manifest_schema_version,
                mv.validation_status AS manifest_validation_status,mv.version_number,
                e.active_policy_id,e.revocation_epoch,e.status AS assessment_status,
                e.expires_at AS assessment_expires_at,s.global_status,
                op.state AS plan_state,op.revision AS current_plan_revision,
                ot.state AS task_state,ot.revision AS current_task_revision,ot.task_type,
                c.snapshot_json,c.snapshot_digest,
                a.activated_at AS registry_activated_at,
                a.expires_at AS registry_activation_expires_at
                FROM action_intents ai
                JOIN agent_local_model_intent_links_v1 l ON l.intent_id=ai.intent_id
                JOIN local_model_capability_manifests_v1 m ON m.manifest_id=l.capability_manifest_id
                JOIN policy_bundles p ON p.id=ai.policy_bundle_id
                JOIN manifest_versions mv ON mv.id=p.manifest_version_id
                JOIN engagements e ON e.id=ai.engagement_id
                CROSS JOIN safety_state s
                JOIN orchestration_plans op ON op.plan_id=l.plan_id
                JOIN orchestration_tasks ot ON ot.plan_id=l.plan_id AND ot.task_id=l.task_id
                JOIN ai_provider_configuration_snapshots_v1 c
                  ON c.snapshot_id=l.configuration_snapshot_id
                JOIN ai_provider_configuration_snapshot_productions_v1 cp
                  ON cp.snapshot_id=c.snapshot_id AND cp.snapshot_digest=c.snapshot_digest
                JOIN ai_provider_registry_activations_v1 a ON a.activation_id=cp.activation_id
                WHERE ai.intent_id=? AND c.provider_type='local_runtime'
                  AND c.provider_id=? AND c.model_id=? AND c.state='inactive'
                  AND c.authority='none' AND c.execution_enabled=0
                  AND a.state='active' AND a.authority='none' AND a.execution_enabled=0""",
                (intent_id, PROVIDER_ID, MODEL_ID),
            ).fetchone()
            if row is None:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_INTENT_NOT_FOUND", "local model intent does not exist"
                )
            try:
                intent = cast(dict[str, Any], json.loads(str(row["intent_json"])))
                manifest = cast(dict[str, Any], json.loads(str(row["manifest_json"])))
                policy = cast(dict[str, Any], json.loads(str(row["policy_json"])))
                configuration = cast(dict[str, Any], json.loads(str(row["snapshot_json"])))
            except (TypeError, json.JSONDecodeError) as error:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_STORED_STATE_INVALID",
                    "stored local model evaluation lineage is malformed",
                ) from error

            latest_manifest = connection.execute(
                "SELECT id FROM manifest_versions WHERE engagement_id=? "
                "ORDER BY version_number DESC LIMIT 1",
                (row["engagement_id"],),
            ).fetchone()
            signature = policy.get("signature", {})
            unsigned_policy = {
                key: value
                for key, value in policy.items()
                if key not in {"content_hash", "signature"}
            }
            if (
                contract_issues(intent, "action-intent-v2.schema.json")
                or content_hash(intent) != row["intent_hash"]
                or intent["intent_id"] != row["intent_id"]
                or intent["assessment_id"] != row["engagement_id"]
                or intent["task_id"] != row["task_id"]
                or intent["policy_hash"] != row["policy_hash"]
                or intent["local_model"]["configuration_snapshot_id"]
                != row["configuration_snapshot_id"]
                or intent["local_model"]["configuration_snapshot_digest"]
                != row["configuration_snapshot_digest"]
                or contract_issues(manifest, "local-model-capability-manifest-v1.schema.json")
                or content_hash(manifest) != row["manifest_hash"]
                or manifest["manifest_id"] != row["capability_manifest_id"]
                or manifest["assessment_id"] != row["engagement_id"]
                or manifest["plan_id"] != row["plan_id"]
                or manifest["plan_revision"] != row["plan_revision"]
                or manifest["task_id"] != row["task_id"]
                or manifest["task_revision"] != row["task_revision"]
                or manifest["agent_id"] != row["agent_id"]
                or manifest["policy_bundle_id"] != row["policy_bundle_id"]
                or manifest["policy_hash"] != row["policy_hash"]
                or manifest["configuration_snapshot_id"] != row["configuration_snapshot_id"]
                or manifest["configuration_snapshot_digest"]
                != row["configuration_snapshot_digest"]
                or manifest["provider_id"] != PROVIDER_ID
                or manifest["model_id"] != MODEL_ID
                or manifest["allowed_capability"] != CAPABILITY
                or intent["input_classification"] not in manifest["allowed_input_classifications"]
                or any(
                    intent["requested_limits"][key] > manifest["limits"][key]
                    for key in intent["requested_limits"]
                )
                or contract_issues(
                    configuration, "ai-provider-configuration-snapshot-v1.schema.json"
                )
                or row["snapshot_digest"] != row["configuration_snapshot_digest"]
                or intent["input_classification"]
                not in configuration["allowed_input_classifications"]
                or intent["requested_limits"]["maximum_input_tokens"]
                > configuration["budgets"]["max_input_tokens"]
                or intent["requested_limits"]["maximum_output_tokens"]
                > configuration["budgets"]["max_output_tokens"]
                or intent["requested_limits"]["maximum_runtime_seconds"]
                > configuration["budgets"]["max_runtime_seconds"]
            ):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_LINEAGE_MISMATCH",
                    "local model evaluation lineage mismatches",
                )
            if (
                row["policy_schema_version"] != "2.0.0"
                or contract_issues(policy, "policy-ir-v2.schema.json")
                or policy.get("content_hash") != row["policy_hash"]
                or content_hash(
                    {"policy": unsigned_policy, "signer_key_id": signature.get("key_id")}
                )
                != row["policy_hash"]
                or signature.get("algorithm") != "Ed25519"
                or signature.get("key_id") != row["signer_key_id"]
                or signature.get("value") != row["signature"]
                or self.authorization.policy_signer is None
                or not self.authorization.policy_signer.verify(
                    policy_signature_payload("2.0.0", row["policy_hash"]),
                    str(signature.get("value", "")),
                    str(signature.get("key_id", "")),
                )
            ):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_POLICY_INVALID", "active policy is invalid"
                )
            if (
                row["assessment_status"] != "active"
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["global_status"] != "active"
                or row["activated_at"] is None
                or row["revoked_at"] is not None
                or row["manifest_schema_version"] != "3.0.0"
                or row["manifest_validation_status"] != "valid"
                or latest_manifest is None
                or latest_manifest["id"] != row["manifest_version_id"]
                or policy["manifest_hash"] != row["manifest_version_hash"]
                or row["plan_state"] != "active"
                or row["current_plan_revision"] != row["plan_revision"]
                or row["task_state"] != "running"
                or row["current_task_revision"] != row["task_revision"]
                or row["task_type"] != "validation"
            ):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_STATE_STALE", "evaluation state is stale"
                )
            expiries = [
                parse_time(intent["expires_at"]),
                parse_time(manifest["expires_at"]),
                parse_time(policy["validity"]["not_after"]),
                parse_time(configuration["expires_at"]),
                parse_time(str(row["registry_activation_expires_at"])),
                parse_time(str(row["assessment_expires_at"])),
            ]
            if (
                parse_time(intent["created_at"]) > instant
                or parse_time(manifest["issued_at"]) > instant
                or parse_time(policy["validity"]["not_before"]) > instant
                or parse_time(configuration["configured_at"]) > instant
                or parse_time(str(row["registry_activated_at"])) > instant
                or min(expiries) <= instant
            ):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_EXPIRED", "evaluation lineage is expired"
                )
            rules = [
                rule for rule in policy["capability_rules"] if rule["capability"] == CAPABILITY
            ]
            if len(rules) != 1:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_POLICY_AMBIGUOUS",
                    "local model policy rule is ambiguous",
                )
            rule = rules[0]
            outcomes = {
                "allow": ("allow", "EXPLICIT_ALLOW"),
                "deny": ("deny", "EXPLICIT_DENY"),
                "conditional": ("approval_required", "APPROVAL_REQUIRED"),
            }
            try:
                outcome, reason_code = outcomes[rule["effect"]]
            except KeyError as error:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_POLICY_AMBIGUOUS",
                    "local model policy effect is unsupported",
                ) from error
            decided_at = _timestamp(instant)
            decision_id = str(uuid5(_NAMESPACE, f"decision:{intent_id}:{row['policy_hash']}"))
            decision: dict[str, Any] = {
                "schema_version": "2.0.0",
                "decision_id": decision_id,
                "intent_id": intent_id,
                "intent_hash": row["intent_hash"],
                "assessment_id": row["engagement_id"],
                "plan_id": row["plan_id"],
                "plan_revision": row["plan_revision"],
                "task_id": row["task_id"],
                "task_revision": row["task_revision"],
                "policy_bundle_id": row["policy_bundle_id"],
                "policy_hash": row["policy_hash"],
                "policy_epoch": row["revocation_epoch"],
                "manifest_version_id": row["manifest_version_id"],
                "manifest_hash": row["manifest_version_hash"],
                "capability_manifest_id": row["capability_manifest_id"],
                "capability_manifest_hash": row["manifest_hash"],
                "configuration_snapshot_id": row["configuration_snapshot_id"],
                "configuration_snapshot_digest": row["configuration_snapshot_digest"],
                "capability": CAPABILITY,
                "outcome": outcome,
                "reason_code": reason_code,
                "evaluated_rule_id": rule["rule_id"],
                "requested_limits": copy.deepcopy(intent["requested_limits"]),
                "decided_at": decided_at,
                "expires_at": _timestamp(min(expiries)),
                "evaluator": {
                    "name": "pentai-local-model-policy-evaluator",
                    "version": "1.0.0",
                    "canonicalization_version": "1.0.0",
                },
                "authority": "none",
                "grant_enabled": False,
                "execution_enabled": False,
            }
            if outcome == "approval_required":
                approval_types = {
                    condition.get("approval_type") for condition in rule.get("conditions", [])
                }
                if len(approval_types) != 1 or None in approval_types:
                    raise LocalModelIntentError(
                        "LOCAL_MODEL_EVALUATION_POLICY_AMBIGUOUS",
                        "local model approval requirement is ambiguous",
                    )
                decision["required_approval_type"] = approval_types.pop()
            if contract_issues(decision, "policy-decision-v2.schema.json"):
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_RESULT_INVALID", "policy decision is invalid"
                )
            existing = connection.execute(
                "SELECT decision_json FROM local_model_policy_evaluations_v2 WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if existing is not None:
                return cast(dict[str, Any], json.loads(str(existing["decision_json"])))
            decision_json = canonical_json(decision)
            try:
                connection.execute(
                    """INSERT INTO local_model_policy_evaluations_v2(
                    decision_id,intent_id,intent_hash,assessment_id,plan_id,
                    plan_revision,task_id,task_revision,policy_bundle_id,policy_hash,policy_epoch,
                    capability_manifest_id,configuration_snapshot_id,
                    configuration_snapshot_digest,outcome,decision_json,decided_at,expires_at,
                    authority,grant_enabled,execution_enabled)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0,0)""",
                    (
                        decision_id,
                        intent_id,
                        row["intent_hash"],
                        row["engagement_id"],
                        row["plan_id"],
                        row["plan_revision"],
                        row["task_id"],
                        row["task_revision"],
                        row["policy_bundle_id"],
                        row["policy_hash"],
                        row["revocation_epoch"],
                        row["capability_manifest_id"],
                        row["configuration_snapshot_id"],
                        row["configuration_snapshot_digest"],
                        outcome,
                        decision_json,
                        decided_at,
                        decision["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LocalModelIntentError(
                    "LOCAL_MODEL_EVALUATION_STATE_CHANGED",
                    "local model evaluation state changed",
                ) from error
            self._audit(
                connection,
                action="policy.local_model_evaluation",
                subject_type="action_intent",
                subject_id=intent_id,
                actor_type="service",
                actor_id="pentai-local-model-policy-evaluator",
                occurred_at=decided_at,
                data={
                    "decision_id": decision_id,
                    "outcome": outcome,
                    "reason_code": reason_code,
                    "policy_hash": row["policy_hash"],
                    "authority": "none",
                    "grant_enabled": False,
                    "execution_enabled": False,
                },
            )
            return copy.deepcopy(decision)

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
