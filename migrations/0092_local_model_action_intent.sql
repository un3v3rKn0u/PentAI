CREATE TABLE local_model_capability_manifests_v1 (
    manifest_id TEXT PRIMARY KEY,
    manifest_hash TEXT NOT NULL UNIQUE CHECK(length(manifest_hash)=64),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK(plan_revision > 0),
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    agent_id TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
    configuration_snapshot_id TEXT NOT NULL
        REFERENCES ai_provider_configuration_snapshots_v1(snapshot_id),
    configuration_snapshot_digest TEXT NOT NULL CHECK(length(configuration_snapshot_digest)=71),
    manifest_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(plan_id,task_id,task_revision,agent_id,configuration_snapshot_id),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER local_model_capability_manifests_v1_binding_valid
BEFORE INSERT ON local_model_capability_manifests_v1
WHEN json_extract(NEW.manifest_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.manifest_json,'$.manifest_id') IS NOT NEW.manifest_id
 OR json_extract(NEW.manifest_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.manifest_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.manifest_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.manifest_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.manifest_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.manifest_json,'$.agent_id') IS NOT NEW.agent_id
 OR json_extract(NEW.manifest_json,'$.policy_bundle_id') IS NOT NEW.policy_bundle_id
 OR json_extract(NEW.manifest_json,'$.policy_hash') IS NOT NEW.policy_hash
 OR json_extract(NEW.manifest_json,'$.configuration_snapshot_id')
      IS NOT NEW.configuration_snapshot_id
 OR json_extract(NEW.manifest_json,'$.configuration_snapshot_digest')
      IS NOT NEW.configuration_snapshot_digest
 OR json_extract(NEW.manifest_json,'$.provider_id') IS NOT 'llama.cpp'
 OR json_extract(NEW.manifest_json,'$.model_id')
      IS NOT 'Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M'
 OR json_extract(NEW.manifest_json,'$.allowed_purpose')
      IS NOT 'propose_supervised_local_model_generation'
 OR json_extract(NEW.manifest_json,'$.allowed_capability') IS NOT 'ai.local.generate'
 OR json_extract(NEW.manifest_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.manifest_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
     SELECT 1 FROM ai_provider_configuration_snapshots_v1 AS c
     WHERE c.snapshot_id=NEW.configuration_snapshot_id
       AND c.snapshot_digest=NEW.configuration_snapshot_digest
       AND c.provider_type='local_runtime'
       AND c.provider_id='llama.cpp'
       AND c.model_id='Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M'
       AND c.state='inactive'
       AND c.authority='none'
       AND c.execution_enabled=0
 )
BEGIN SELECT RAISE(ABORT,'local model capability manifest binding is invalid'); END;

CREATE TRIGGER local_model_capability_manifests_v1_immutable
BEFORE UPDATE ON local_model_capability_manifests_v1
BEGIN SELECT RAISE(ABORT,'local model capability manifests are immutable'); END;

CREATE TRIGGER local_model_capability_manifests_v1_no_delete
BEFORE DELETE ON local_model_capability_manifests_v1
BEGIN SELECT RAISE(ABORT,'local model capability manifests cannot be deleted'); END;

CREATE TABLE agent_local_model_intent_links_v1 (
    request_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
    intent_id TEXT NOT NULL UNIQUE REFERENCES action_intents(intent_id),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK(plan_revision > 0),
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    agent_id TEXT NOT NULL,
    capability_manifest_id TEXT NOT NULL
        REFERENCES local_model_capability_manifests_v1(manifest_id),
    configuration_snapshot_id TEXT NOT NULL
        REFERENCES ai_provider_configuration_snapshots_v1(snapshot_id),
    configuration_snapshot_digest TEXT NOT NULL CHECK(length(configuration_snapshot_digest)=71),
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=71),
    action_sha256 TEXT NOT NULL CHECK(length(action_sha256)=71),
    created_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER agent_local_model_intent_links_v1_binding_valid
BEFORE INSERT ON agent_local_model_intent_links_v1
WHEN NOT EXISTS (
    SELECT 1 FROM local_model_capability_manifests_v1 AS m
    JOIN ai_provider_configuration_snapshots_v1 AS c
      ON c.snapshot_id=m.configuration_snapshot_id
    WHERE m.manifest_id=NEW.capability_manifest_id
      AND m.assessment_id=NEW.assessment_id
      AND m.plan_id=NEW.plan_id
      AND m.plan_revision=NEW.plan_revision
      AND m.task_id=NEW.task_id
      AND m.task_revision=NEW.task_revision
      AND m.agent_id=NEW.agent_id
      AND m.configuration_snapshot_id=NEW.configuration_snapshot_id
      AND m.configuration_snapshot_digest=NEW.configuration_snapshot_digest
      AND c.snapshot_digest=NEW.configuration_snapshot_digest
      AND c.provider_type='local_runtime'
      AND c.provider_id='llama.cpp'
      AND c.model_id='Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M'
 )
BEGIN SELECT RAISE(ABORT,'local model action intent binding is invalid'); END;

CREATE TRIGGER agent_local_model_intent_links_v1_immutable
BEFORE UPDATE ON agent_local_model_intent_links_v1
BEGIN SELECT RAISE(ABORT,'local model action intent provenance is immutable'); END;

CREATE TRIGGER agent_local_model_intent_links_v1_no_delete
BEFORE DELETE ON agent_local_model_intent_links_v1
BEGIN SELECT RAISE(ABORT,'local model action intent provenance cannot be deleted'); END;
