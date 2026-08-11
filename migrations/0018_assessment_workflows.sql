CREATE TABLE assessment_workflows (
    workflow_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('planned', 'ready', 'running', 'paused', 'completed', 'cancelled')
    ),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finalized_at TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(engagement_id, idempotency_key)
);

CREATE INDEX assessment_workflows_by_status
ON assessment_workflows(engagement_id, status);

CREATE TABLE workflow_tasks (
    task_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    parent_task_id TEXT REFERENCES workflow_tasks(task_id),
    task_kind TEXT NOT NULL CHECK (
        task_kind IN ('manual_checkpoint', 'supervised_action', 'evidence_capture', 'report_draft')
    ),
    state TEXT NOT NULL CHECK (state IN ('queued', 'cancelled')),
    idempotency_key TEXT NOT NULL,
    input_refs_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    dispatch_enabled INTEGER NOT NULL CHECK (dispatch_enabled = 0),
    external_effect_enabled INTEGER NOT NULL CHECK (external_effect_enabled = 0),
    UNIQUE(workflow_id, idempotency_key)
);

CREATE INDEX workflow_tasks_by_state ON workflow_tasks(workflow_id, state);

CREATE TRIGGER assessment_workflows_identity_immutable
BEFORE UPDATE OF workflow_id, engagement_id, policy_bundle_id, idempotency_key,
    created_at, execution_enabled
ON assessment_workflows
BEGIN
    SELECT RAISE(ABORT, 'assessment workflow identity is immutable');
END;

CREATE TRIGGER assessment_workflows_transition
BEFORE UPDATE OF status, version, updated_at, started_at, finalized_at
ON assessment_workflows
WHEN NEW.version != OLD.version + 1 OR NOT (
    (OLD.status = 'planned' AND NEW.status IN ('ready', 'cancelled'))
    OR (OLD.status = 'ready' AND NEW.status IN ('running', 'cancelled'))
    OR (OLD.status = 'running' AND NEW.status IN ('paused', 'completed', 'cancelled'))
    OR (OLD.status = 'paused' AND NEW.status IN ('running', 'cancelled'))
)
OR (NEW.status IN ('completed', 'cancelled') AND NEW.finalized_at IS NULL)
OR (NEW.status NOT IN ('completed', 'cancelled') AND NEW.finalized_at IS NOT NULL)
OR (NEW.status IN ('running', 'paused', 'completed') AND NEW.started_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'assessment workflow transition is invalid');
END;

CREATE TRIGGER assessment_workflows_no_delete
BEFORE DELETE ON assessment_workflows
BEGIN
    SELECT RAISE(ABORT, 'assessment workflow history cannot be deleted');
END;

CREATE TRIGGER workflow_tasks_identity_immutable
BEFORE UPDATE OF task_id, workflow_id, parent_task_id, task_kind,
    idempotency_key, input_refs_json, created_at, dispatch_enabled,
    external_effect_enabled
ON workflow_tasks
BEGIN
    SELECT RAISE(ABORT, 'workflow task identity is immutable');
END;

CREATE TRIGGER workflow_tasks_transition
BEFORE UPDATE OF state, finalized_at ON workflow_tasks
WHEN OLD.state != 'queued' OR NEW.state != 'cancelled' OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'workflow task transition is invalid');
END;

CREATE TRIGGER workflow_tasks_no_delete
BEFORE DELETE ON workflow_tasks
BEGIN
    SELECT RAISE(ABORT, 'workflow task history cannot be deleted');
END;
