CREATE TABLE orchestration_retry_failed_attempts (
    attempt_id TEXT PRIMARY KEY REFERENCES orchestration_retry_attempts(attempt_id),
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    failure_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_failures(failure_id),
    failure_receipt_digest TEXT NOT NULL CHECK (length(failure_receipt_digest) = 71),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, attempt_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_failed_attempts_binding_valid
BEFORE INSERT ON orchestration_retry_failed_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM orchestration_retry_attempts a
    JOIN orchestration_task_failures f ON f.failure_id = NEW.failure_id
    WHERE a.attempt_id = NEW.attempt_id
      AND a.assessment_id = NEW.assessment_id
      AND a.plan_id = NEW.plan_id
      AND a.task_id = NEW.task_id
      AND a.attempt_number = 2
      AND a.attempt_state = 'registered'
      AND f.assessment_id = NEW.assessment_id
      AND f.plan_id = NEW.plan_id
      AND f.resulting_plan_revision = NEW.plan_revision
      AND f.task_id = NEW.task_id
      AND f.resulting_task_revision = NEW.task_revision
      AND f.retry_attempt_id = NEW.attempt_id
      AND ('sha256:' || f.receipt_hash) = NEW.failure_receipt_digest
      AND json_extract(f.receipt_json, '$.schema_version') = '2.0.0'
      AND json_extract(NEW.receipt_json, '$.schema_version') = '2.0.0'
      AND json_extract(NEW.receipt_json, '$.attempt_id') = NEW.attempt_id
      AND json_extract(NEW.receipt_json, '$.attempt_number') = 2
      AND json_extract(NEW.receipt_json, '$.attempt_state') = 'failed'
      AND json_extract(NEW.receipt_json, '$.failure_id') = NEW.failure_id
      AND json_extract(NEW.receipt_json, '$.failure_receipt_digest')
          = NEW.failure_receipt_digest
      AND json_extract(NEW.receipt_json, '$.authority') = 'none'
      AND json_extract(NEW.receipt_json, '$.execution_enabled') = 0
)
BEGIN SELECT RAISE(ABORT, 'retry failed-attempt binding is invalid'); END;

CREATE TRIGGER orchestration_retry_failed_attempts_immutable
BEFORE UPDATE ON orchestration_retry_failed_attempts
BEGIN SELECT RAISE(ABORT, 'retry failed attempts are immutable'); END;

CREATE TRIGGER orchestration_retry_failed_attempts_no_delete
BEFORE DELETE ON orchestration_retry_failed_attempts
BEGIN SELECT RAISE(ABORT, 'retry failed attempts cannot be deleted'); END;
