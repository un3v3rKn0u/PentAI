CREATE TABLE orchestration_retry_schedules_v2 (
    schedule_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_attempts_v2(attempt_id),
    retry_budget_consumption_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_budget_consumptions_v2(consumption_id),
    eligibility_decision_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_decisions_v2(decision_id),
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

CREATE TRIGGER orchestration_retry_schedules_v2_binding_valid
BEFORE INSERT ON orchestration_retry_schedules_v2
WHEN json_extract(NEW.receipt_json, '$.schema_version') IS NOT '2.0.0'
  OR json_extract(NEW.receipt_json, '$.schedule_id') IS NOT NEW.schedule_id
  OR json_extract(NEW.receipt_json, '$.command_id') IS NOT NEW.command_id
  OR json_extract(NEW.receipt_json, '$.command_digest') IS NOT NEW.command_digest
  OR json_extract(NEW.receipt_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.receipt_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.receipt_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.receipt_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.receipt_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.receipt_json, '$.attempt_id') IS NOT NEW.attempt_id
  OR json_extract(NEW.receipt_json, '$.retry_budget_consumption_id') IS NOT NEW.retry_budget_consumption_id
  OR json_extract(NEW.receipt_json, '$.eligibility_decision_id') IS NOT NEW.eligibility_decision_id
  OR json_extract(NEW.receipt_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.receipt_json, '$.schedule_revision') IS NOT 1
  OR json_extract(NEW.receipt_json, '$.schedule_state') IS NOT 'registered'
  OR json_extract(NEW.receipt_json, '$.scheduled_for') IS NOT NEW.scheduled_for
  OR json_extract(NEW.receipt_json, '$.expires_at') IS NOT NEW.expires_at
  OR json_extract(NEW.receipt_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.receipt_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_retry_attempts_v2 a
      JOIN orchestration_retry_budget_consumptions_v2 c
        ON c.consumption_id = NEW.retry_budget_consumption_id
      JOIN orchestration_retry_decisions_v2 d
        ON d.decision_id = NEW.eligibility_decision_id
      WHERE a.attempt_id = NEW.attempt_id
        AND a.retry_budget_consumption_id = c.consumption_id
        AND c.eligibility_decision_id = d.decision_id
        AND a.assessment_id = NEW.assessment_id
        AND a.plan_id = NEW.plan_id
        AND a.task_id = NEW.task_id
        AND a.attempt_number = 3
        AND d.outcome = 'eligible'
        AND json_extract(d.decision_json, '$.proposed_attempt_number') = 3
        AND NEW.scheduled_for = json_extract(d.decision_json, '$.earliest_retry_at')
        AND json_extract(NEW.receipt_json, '$.attempt_digest')
            = json_extract(a.receipt_json, '$.attempt_digest')
        AND json_extract(NEW.receipt_json, '$.retry_budget_consumption_digest')
            = json_extract(c.receipt_json, '$.receipt_digest')
        AND json_extract(NEW.receipt_json, '$.eligibility_decision_digest')
            = json_extract(d.decision_json, '$.decision_digest')
  )
BEGIN SELECT RAISE(ABORT, 'retry schedule v2 binding is invalid'); END;

CREATE TRIGGER orchestration_retry_schedules_v2_immutable
BEFORE UPDATE ON orchestration_retry_schedules_v2
BEGIN SELECT RAISE(ABORT, 'orchestration retry schedule v2 is immutable'); END;

CREATE TRIGGER orchestration_retry_schedules_v2_no_delete
BEFORE DELETE ON orchestration_retry_schedules_v2
BEGIN SELECT RAISE(ABORT, 'orchestration retry schedules v2 cannot be deleted'); END;
