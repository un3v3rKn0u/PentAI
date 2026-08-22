CREATE TABLE orchestration_task_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    lease_consumption_id TEXT NOT NULL REFERENCES orchestration_task_lease_consumptions(consumption_id),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    previous_checkpoint_digest TEXT,
    checkpoint_digest TEXT NOT NULL UNIQUE CHECK (length(checkpoint_digest) = 71),
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, task_revision, sequence),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);
CREATE TRIGGER orchestration_task_checkpoints_immutable BEFORE UPDATE ON orchestration_task_checkpoints
BEGIN SELECT RAISE(ABORT, 'orchestration task checkpoint is immutable'); END;
CREATE TRIGGER orchestration_task_checkpoints_no_delete BEFORE DELETE ON orchestration_task_checkpoints
BEGIN SELECT RAISE(ABORT, 'orchestration task checkpoints cannot be deleted'); END;
