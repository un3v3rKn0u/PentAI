CREATE TABLE orchestration_retry_schedules (
    schedule_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_attempts(attempt_id),
    retry_budget_consumption_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_budget_consumptions(consumption_id),
    schedule_revision INTEGER NOT NULL CHECK (schedule_revision = 1),
    schedule_state TEXT NOT NULL CHECK (schedule_state = 'registered'),
    scheduled_for TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, schedule_revision),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_schedules_immutable
BEFORE UPDATE ON orchestration_retry_schedules
BEGIN SELECT RAISE(ABORT, 'orchestration retry schedule is immutable'); END;

CREATE TRIGGER orchestration_retry_schedules_no_delete
BEFORE DELETE ON orchestration_retry_schedules
BEGIN SELECT RAISE(ABORT, 'orchestration retry schedules cannot be deleted'); END;
