CREATE TABLE orchestration_retry_decisions_v2 (
    decision_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_failed_attempts(attempt_id),
    retry_policy_id TEXT NOT NULL REFERENCES orchestration_retry_policies_v2(retry_policy_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('eligible', 'denied')),
    reason_code TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    decision_hash TEXT NOT NULL UNIQUE CHECK (length(decision_hash) = 64),
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_decisions_v2_binding_valid
BEFORE INSERT ON orchestration_retry_decisions_v2
WHEN json_extract(NEW.decision_json, '$.schema_version') IS NOT '2.0.0'
  OR json_extract(NEW.decision_json, '$.decision_id') IS NOT NEW.decision_id
  OR json_extract(NEW.decision_json, '$.command_id') IS NOT NEW.command_id
  OR json_extract(NEW.decision_json, '$.command_digest') IS NOT NEW.command_digest
  OR json_extract(NEW.decision_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.decision_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.decision_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.decision_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.decision_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.decision_json, '$.attempt_id') IS NOT NEW.attempt_id
  OR json_extract(NEW.decision_json, '$.retry_policy_id') IS NOT NEW.retry_policy_id
  OR json_extract(NEW.decision_json, '$.outcome') IS NOT NEW.outcome
  OR json_extract(NEW.decision_json, '$.reason_code') IS NOT NEW.reason_code
  OR json_extract(NEW.decision_json, '$.decided_at') IS NOT NEW.decided_at
  OR json_extract(NEW.decision_json, '$.expires_at') IS NOT NEW.expires_at
  OR json_extract(NEW.decision_json, '$.current_attempt_number') IS NOT 2
  OR json_extract(NEW.decision_json, '$.proposed_attempt_number') IS NOT 3
  OR json_extract(NEW.decision_json, '$.retry_units_consumed') IS NOT 0
  OR json_extract(NEW.decision_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.decision_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_retry_failed_attempts a
      JOIN orchestration_retry_policies_v2 p ON p.retry_policy_id = NEW.retry_policy_id
      WHERE a.attempt_id = NEW.attempt_id
        AND a.assessment_id = NEW.assessment_id
        AND a.plan_id = NEW.plan_id
        AND a.plan_revision = NEW.plan_revision
        AND a.task_id = NEW.task_id
        AND a.task_revision = NEW.task_revision
        AND p.assessment_id = NEW.assessment_id
        AND json_extract(a.receipt_json, '$.schema_version') = '2.0.0'
        AND json_extract(p.policy_json, '$.schema_version') = '2.0.0'
        AND json_extract(NEW.decision_json, '$.attempt_digest')
            = json_extract(a.receipt_json, '$.attempt_digest')
        AND json_extract(NEW.decision_json, '$.retry_policy_digest') = p.policy_digest
  )
BEGIN SELECT RAISE(ABORT, 'retry decision v2 binding is invalid'); END;

CREATE TRIGGER orchestration_retry_decisions_v2_immutable
BEFORE UPDATE ON orchestration_retry_decisions_v2
BEGIN SELECT RAISE(ABORT, 'retry decision v2 is immutable'); END;

CREATE TRIGGER orchestration_retry_decisions_v2_no_delete
BEFORE DELETE ON orchestration_retry_decisions_v2
BEGIN SELECT RAISE(ABORT, 'retry decisions v2 cannot be deleted'); END;
