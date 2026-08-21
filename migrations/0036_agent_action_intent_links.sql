CREATE TABLE agent_action_intent_links (
    request_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    intent_id TEXT NOT NULL UNIQUE REFERENCES action_intents(intent_id),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK (plan_revision >= 1),
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK (task_revision >= 1),
    agent_id TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose = 'propose_supervised_http_validation'),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 71),
    action_sha256 TEXT NOT NULL CHECK (length(action_sha256) = 71),
    created_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER agent_action_intent_links_immutable BEFORE UPDATE ON agent_action_intent_links
BEGIN SELECT RAISE(ABORT, 'agent action intent provenance is immutable'); END;
CREATE TRIGGER agent_action_intent_links_no_delete BEFORE DELETE ON agent_action_intent_links
BEGIN SELECT RAISE(ABORT, 'agent action intent provenance cannot be deleted'); END;
