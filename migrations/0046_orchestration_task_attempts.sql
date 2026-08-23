CREATE TABLE orchestration_task_attempts (
    attempt_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number = 1),
    failure_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_failures(failure_id),
    failure_receipt_digest TEXT NOT NULL CHECK (length(failure_receipt_digest) = 71),
    lease_consumption_id TEXT NOT NULL REFERENCES orchestration_task_lease_consumptions(consumption_id),
    budget_reservation_id TEXT NOT NULL REFERENCES orchestration_task_budget_reservations(reservation_id),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, attempt_number),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_attempts_immutable BEFORE UPDATE ON orchestration_task_attempts
BEGIN SELECT RAISE(ABORT, 'orchestration task attempt is immutable'); END;
CREATE TRIGGER orchestration_task_attempts_no_delete BEFORE DELETE ON orchestration_task_attempts
BEGIN SELECT RAISE(ABORT, 'orchestration task attempts cannot be deleted'); END;
