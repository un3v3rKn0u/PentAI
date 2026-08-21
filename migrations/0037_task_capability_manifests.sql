CREATE TABLE task_capability_manifests (
    manifest_id TEXT PRIMARY KEY, manifest_revision INTEGER NOT NULL CHECK (manifest_revision = 1),
    assessment_id TEXT NOT NULL REFERENCES engagements(id), plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL, task_id TEXT NOT NULL, task_revision INTEGER NOT NULL,
    agent_id TEXT NOT NULL, policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64), manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL UNIQUE CHECK (length(manifest_hash) = 64),
    issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, issued_by TEXT NOT NULL CHECK (issued_by = 'pentai-core'),
    delegation_allowed INTEGER NOT NULL CHECK (delegation_allowed = 0), authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(plan_id, task_id, task_revision, agent_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);
CREATE TRIGGER task_capability_manifests_immutable BEFORE UPDATE ON task_capability_manifests
BEGIN SELECT RAISE(ABORT, 'task capability manifests are immutable'); END;
CREATE TRIGGER task_capability_manifests_no_delete BEFORE DELETE ON task_capability_manifests
BEGIN SELECT RAISE(ABORT, 'task capability manifests cannot be deleted'); END;

ALTER TABLE agent_action_intent_links ADD COLUMN capability_manifest_id TEXT REFERENCES task_capability_manifests(manifest_id);
ALTER TABLE agent_action_intent_links ADD COLUMN capability_manifest_revision INTEGER;
