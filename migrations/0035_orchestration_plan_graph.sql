CREATE TABLE orchestration_plans (
    plan_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    creation_digest TEXT NOT NULL CHECK (length(creation_digest) = 71),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state TEXT NOT NULL CHECK (state IN ('active', 'completed', 'cancelled', 'failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(assessment_id, idempotency_key)
);

CREATE TABLE orchestration_tasks (
    task_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES orchestration_plans(plan_id),
    assessment_id TEXT NOT NULL,
    task_type TEXT NOT NULL CHECK (task_type IN ('scope', 'rules_of_engagement', 'evidence', 'validation', 'reporting')),
    objective TEXT NOT NULL CHECK (length(objective) BETWEEN 1 AND 512),
    input_refs_json TEXT NOT NULL,
    requires_human_approval INTEGER NOT NULL CHECK (requires_human_approval IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('blocked', 'awaiting_human', 'ready', 'running', 'cancelling', 'cancelled', 'succeeded', 'failed')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(plan_id, task_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id)
);

CREATE UNIQUE INDEX orchestration_plans_identity ON orchestration_plans(plan_id, assessment_id);

CREATE TABLE orchestration_dependencies (
    plan_id TEXT NOT NULL REFERENCES orchestration_plans(plan_id),
    assessment_id TEXT NOT NULL,
    predecessor_task_id TEXT NOT NULL,
    successor_task_id TEXT NOT NULL,
    dependency_type TEXT NOT NULL CHECK (dependency_type = 'requires_success'),
    PRIMARY KEY(plan_id, predecessor_task_id, successor_task_id, dependency_type),
    CHECK (predecessor_task_id != successor_task_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, predecessor_task_id) REFERENCES orchestration_tasks(plan_id, task_id),
    FOREIGN KEY(plan_id, successor_task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TABLE orchestration_commands (
    command_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES orchestration_plans(plan_id),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER orchestration_plans_identity_immutable
BEFORE UPDATE OF plan_id, assessment_id, idempotency_key, creation_digest, created_at,
    authority, execution_enabled
ON orchestration_plans BEGIN SELECT RAISE(ABORT, 'orchestration plan identity is immutable'); END;
CREATE TRIGGER orchestration_plans_version_fenced
BEFORE UPDATE ON orchestration_plans
WHEN NEW.revision != OLD.revision + 1
    OR OLD.state != 'active'
    OR NEW.state NOT IN ('active', 'completed', 'cancelled', 'failed')
BEGIN SELECT RAISE(ABORT, 'orchestration plan revision is invalid'); END;
CREATE TRIGGER orchestration_plans_no_delete BEFORE DELETE ON orchestration_plans
BEGIN SELECT RAISE(ABORT, 'orchestration plan history cannot be deleted'); END;

CREATE TRIGGER orchestration_tasks_identity_immutable
BEFORE UPDATE OF task_id, plan_id, assessment_id, task_type, objective, input_refs_json,
    requires_human_approval, created_at, authority, execution_enabled
ON orchestration_tasks BEGIN SELECT RAISE(ABORT, 'orchestration task identity is immutable'); END;
CREATE TRIGGER orchestration_tasks_version_fenced
BEFORE UPDATE ON orchestration_tasks
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state = 'blocked' AND NEW.state IN ('ready', 'awaiting_human', 'cancelled'))
    OR (OLD.state = 'ready' AND NEW.state IN ('running', 'cancelled'))
    OR (OLD.state = 'awaiting_human' AND NEW.state = 'cancelled')
    OR (OLD.state = 'running' AND NEW.state IN ('cancelling', 'succeeded', 'failed'))
    OR (OLD.state = 'cancelling' AND NEW.state IN ('cancelled', 'failed'))
)
BEGIN SELECT RAISE(ABORT, 'orchestration task revision is invalid'); END;
CREATE TRIGGER orchestration_tasks_no_delete BEFORE DELETE ON orchestration_tasks
BEGIN SELECT RAISE(ABORT, 'orchestration task history cannot be deleted'); END;
CREATE TRIGGER orchestration_dependencies_immutable BEFORE UPDATE ON orchestration_dependencies
BEGIN SELECT RAISE(ABORT, 'orchestration dependency is immutable'); END;
CREATE TRIGGER orchestration_dependencies_no_delete BEFORE DELETE ON orchestration_dependencies
BEGIN SELECT RAISE(ABORT, 'orchestration dependency history cannot be deleted'); END;
CREATE TRIGGER orchestration_commands_immutable BEFORE UPDATE ON orchestration_commands
BEGIN SELECT RAISE(ABORT, 'orchestration command is immutable'); END;
CREATE TRIGGER orchestration_commands_no_delete BEFORE DELETE ON orchestration_commands
BEGIN SELECT RAISE(ABORT, 'orchestration command history cannot be deleted'); END;
