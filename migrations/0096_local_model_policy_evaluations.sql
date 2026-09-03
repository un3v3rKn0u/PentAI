CREATE TABLE local_model_policy_evaluations_v2 (
    decision_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE REFERENCES action_intents(intent_id),
    intent_hash TEXT NOT NULL CHECK(length(intent_hash)=64),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK(plan_revision > 0),
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
    policy_epoch INTEGER NOT NULL CHECK(policy_epoch >= 0),
    capability_manifest_id TEXT NOT NULL REFERENCES local_model_capability_manifests_v1(manifest_id),
    configuration_snapshot_id TEXT NOT NULL REFERENCES ai_provider_configuration_snapshots_v1(snapshot_id),
    configuration_snapshot_digest TEXT NOT NULL CHECK(length(configuration_snapshot_digest)=71),
    outcome TEXT NOT NULL CHECK(outcome IN ('allow','deny','approval_required')),
    decision_json TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    grant_enabled INTEGER NOT NULL CHECK(grant_enabled=0),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER local_model_policy_evaluations_v2_binding_valid
BEFORE INSERT ON local_model_policy_evaluations_v2
WHEN json_extract(NEW.decision_json,'$.schema_version') IS NOT '2.0.0'
 OR json_extract(NEW.decision_json,'$.decision_id') IS NOT NEW.decision_id
 OR json_extract(NEW.decision_json,'$.intent_id') IS NOT NEW.intent_id
 OR json_extract(NEW.decision_json,'$.intent_hash') IS NOT NEW.intent_hash
 OR json_extract(NEW.decision_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.decision_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.decision_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.decision_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.decision_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.decision_json,'$.policy_bundle_id') IS NOT NEW.policy_bundle_id
 OR json_extract(NEW.decision_json,'$.policy_hash') IS NOT NEW.policy_hash
 OR json_extract(NEW.decision_json,'$.policy_epoch') IS NOT NEW.policy_epoch
 OR json_extract(NEW.decision_json,'$.capability_manifest_id') IS NOT NEW.capability_manifest_id
 OR json_extract(NEW.decision_json,'$.configuration_snapshot_id') IS NOT NEW.configuration_snapshot_id
 OR json_extract(NEW.decision_json,'$.configuration_snapshot_digest') IS NOT NEW.configuration_snapshot_digest
 OR json_extract(NEW.decision_json,'$.capability') IS NOT 'ai.local.generate'
 OR json_extract(NEW.decision_json,'$.outcome') IS NOT NEW.outcome
 OR json_extract(NEW.decision_json,'$.decided_at') IS NOT NEW.decided_at
 OR json_extract(NEW.decision_json,'$.expires_at') IS NOT NEW.expires_at
 OR json_extract(NEW.decision_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.decision_json,'$.grant_enabled') IS NOT 0
 OR json_extract(NEW.decision_json,'$.execution_enabled') IS NOT 0
 OR json_type(NEW.decision_json,'$.requested_limits') IS NOT 'object'
 OR NOT EXISTS (
    SELECT 1 FROM action_intents ai
    JOIN agent_local_model_intent_links_v1 l ON l.intent_id=ai.intent_id
    JOIN local_model_capability_manifests_v1 m ON m.manifest_id=l.capability_manifest_id
    JOIN policy_bundles p ON p.id=ai.policy_bundle_id
    JOIN manifest_versions mv ON mv.id=p.manifest_version_id
    JOIN engagements e ON e.id=ai.engagement_id
    JOIN json_each(json_extract(p.policy_json,'$.capability_rules')) rule
    WHERE ai.intent_id=NEW.intent_id AND ai.intent_hash=NEW.intent_hash
      AND ai.engagement_id=NEW.assessment_id AND ai.policy_bundle_id=NEW.policy_bundle_id
      AND ai.policy_hash=NEW.policy_hash AND l.plan_id=NEW.plan_id
      AND l.plan_revision=NEW.plan_revision AND l.task_id=NEW.task_id
      AND l.task_revision=NEW.task_revision AND l.capability_manifest_id=NEW.capability_manifest_id
      AND l.configuration_snapshot_id=NEW.configuration_snapshot_id
      AND l.configuration_snapshot_digest=NEW.configuration_snapshot_digest
      AND m.manifest_hash=json_extract(NEW.decision_json,'$.capability_manifest_hash')
      AND json(json_extract(ai.intent_json,'$.requested_limits'))
          = json(json_extract(NEW.decision_json,'$.requested_limits'))
      AND e.revocation_epoch=NEW.policy_epoch AND e.active_policy_id=NEW.policy_bundle_id
      AND p.activated_at IS NOT NULL AND p.revoked_at IS NULL
      AND p.schema_version='2.0.0'
      AND mv.id=json_extract(NEW.decision_json,'$.manifest_version_id')
      AND mv.content_hash=json_extract(NEW.decision_json,'$.manifest_hash')
      AND json_extract(rule.value,'$.rule_id')=json_extract(NEW.decision_json,'$.evaluated_rule_id')
      AND json_extract(rule.value,'$.capability')='ai.local.generate'
      AND (
        (json_extract(rule.value,'$.effect')='allow' AND NEW.outcome='allow'
         AND json_extract(NEW.decision_json,'$.reason_code')='EXPLICIT_ALLOW')
        OR (json_extract(rule.value,'$.effect')='deny' AND NEW.outcome='deny'
         AND json_extract(NEW.decision_json,'$.reason_code')='EXPLICIT_DENY')
        OR (json_extract(rule.value,'$.effect')='conditional'
         AND NEW.outcome='approval_required'
         AND json_extract(NEW.decision_json,'$.reason_code')='APPROVAL_REQUIRED'
         AND EXISTS (
           SELECT 1 FROM json_each(json_extract(rule.value,'$.conditions')) condition
           WHERE json_extract(condition.value,'$.approval_type')
             = json_extract(NEW.decision_json,'$.required_approval_type')
         ))
      )
 )
BEGIN SELECT RAISE(ABORT,'local model policy decision binding is invalid'); END;

CREATE TRIGGER local_model_policy_evaluations_v2_immutable
BEFORE UPDATE ON local_model_policy_evaluations_v2
BEGIN SELECT RAISE(ABORT,'local model policy decisions are immutable'); END;

CREATE TRIGGER local_model_policy_evaluations_v2_no_delete
BEFORE DELETE ON local_model_policy_evaluations_v2
BEGIN SELECT RAISE(ABORT,'local model policy decisions cannot be deleted'); END;
