CREATE TABLE orchestration_retry_attempts_v2 (
    attempt_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    prior_attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_failed_attempts(attempt_id),
    retry_budget_consumption_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_budget_consumptions_v2(consumption_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number = 3),
    attempt_state TEXT NOT NULL CHECK (attempt_state = 'registered'),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, attempt_number),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_attempts_v2_binding_valid
BEFORE INSERT ON orchestration_retry_attempts_v2
WHEN json_extract(NEW.receipt_json, '$.schema_version') IS NOT '2.0.0'
  OR json_extract(NEW.receipt_json, '$.attempt_id') IS NOT NEW.attempt_id
  OR json_extract(NEW.receipt_json, '$.command_id') IS NOT NEW.command_id
  OR json_extract(NEW.receipt_json, '$.command_digest') IS NOT NEW.command_digest
  OR json_extract(NEW.receipt_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.receipt_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.receipt_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.receipt_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.receipt_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.receipt_json, '$.prior_attempt_id') IS NOT NEW.prior_attempt_id
  OR json_extract(NEW.receipt_json, '$.retry_budget_consumption_id') IS NOT NEW.retry_budget_consumption_id
  OR json_extract(NEW.receipt_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.receipt_json, '$.attempt_state') IS NOT 'registered'
  OR json_extract(NEW.receipt_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.receipt_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_retry_budget_consumptions_v2 c
      JOIN orchestration_retry_failed_attempts a ON a.attempt_id = c.attempt_id
      WHERE c.consumption_id = NEW.retry_budget_consumption_id
        AND c.attempt_id = NEW.prior_attempt_id
        AND c.assessment_id = NEW.assessment_id
        AND c.plan_id = NEW.plan_id
        AND c.task_id = NEW.task_id
        AND c.proposed_attempt_number = 3
        AND c.consumed_retry_units = 1
        AND json_extract(NEW.receipt_json, '$.retry_budget_consumption_digest')
            = json_extract(c.receipt_json, '$.receipt_digest')
        AND json_extract(NEW.receipt_json, '$.prior_attempt_digest')
            = json_extract(a.receipt_json, '$.attempt_digest')
  )
BEGIN SELECT RAISE(ABORT, 'retry attempt v2 binding is invalid'); END;

CREATE TRIGGER orchestration_retry_attempts_v2_immutable
BEFORE UPDATE ON orchestration_retry_attempts_v2
BEGIN SELECT RAISE(ABORT, 'orchestration retry attempt v2 is immutable'); END;

CREATE TRIGGER orchestration_retry_attempts_v2_no_delete
BEFORE DELETE ON orchestration_retry_attempts_v2
BEGIN SELECT RAISE(ABORT, 'orchestration retry attempts v2 cannot be deleted'); END;
