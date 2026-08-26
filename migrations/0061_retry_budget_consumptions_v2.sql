CREATE TABLE orchestration_retry_budget_consumptions_v2 (
    consumption_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_failed_attempts(attempt_id),
    eligibility_decision_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_decisions_v2(decision_id),
    retry_policy_id TEXT NOT NULL REFERENCES orchestration_retry_policies_v2(retry_policy_id),
    prior_retry_budget_consumption_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_budget_consumptions(consumption_id),
    budget_account_id TEXT NOT NULL REFERENCES orchestration_budget_accounts(account_id),
    capacity_budget_reservation_id TEXT NOT NULL REFERENCES orchestration_task_budget_reservations(reservation_id),
    proposed_attempt_number INTEGER NOT NULL CHECK (proposed_attempt_number = 3),
    budget_account_version_before INTEGER NOT NULL CHECK (budget_account_version_before >= 3),
    budget_account_version_after INTEGER NOT NULL CHECK (budget_account_version_after = budget_account_version_before + 1),
    consumed_retry_units INTEGER NOT NULL CHECK (consumed_retry_units = 1),
    remaining_retry_units INTEGER NOT NULL CHECK (remaining_retry_units >= 0),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    consumed_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, proposed_attempt_number),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_budget_consumptions_v2_binding_valid
BEFORE INSERT ON orchestration_retry_budget_consumptions_v2
WHEN json_extract(NEW.receipt_json, '$.schema_version') IS NOT '2.0.0'
  OR json_extract(NEW.receipt_json, '$.consumption_id') IS NOT NEW.consumption_id
  OR json_extract(NEW.receipt_json, '$.command_id') IS NOT NEW.command_id
  OR json_extract(NEW.receipt_json, '$.command_digest') IS NOT NEW.command_digest
  OR json_extract(NEW.receipt_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.receipt_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.receipt_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.receipt_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.receipt_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.receipt_json, '$.attempt_id') IS NOT NEW.attempt_id
  OR json_extract(NEW.receipt_json, '$.eligibility_decision_id') IS NOT NEW.eligibility_decision_id
  OR json_extract(NEW.receipt_json, '$.retry_policy_id') IS NOT NEW.retry_policy_id
  OR json_extract(NEW.receipt_json, '$.prior_retry_budget_consumption_id') IS NOT NEW.prior_retry_budget_consumption_id
  OR json_extract(NEW.receipt_json, '$.budget_account_id') IS NOT NEW.budget_account_id
  OR json_extract(NEW.receipt_json, '$.capacity_budget_reservation_id') IS NOT NEW.capacity_budget_reservation_id
  OR json_extract(NEW.receipt_json, '$.budget_account_version_before') IS NOT NEW.budget_account_version_before
  OR json_extract(NEW.receipt_json, '$.budget_account_version_after') IS NOT NEW.budget_account_version_after
  OR json_extract(NEW.receipt_json, '$.proposed_attempt_number') IS NOT 3
  OR json_extract(NEW.receipt_json, '$.consumed_retry_units') IS NOT 1
  OR json_extract(NEW.receipt_json, '$.remaining_retry_units') IS NOT NEW.remaining_retry_units
  OR json_extract(NEW.receipt_json, '$.previous_consumed_retry_units') IS NOT 1
  OR json_extract(NEW.receipt_json, '$.reserved_retry_units')
       IS NOT json_extract(NEW.receipt_json, '$.previous_consumed_retry_units')
              + json_extract(NEW.receipt_json, '$.consumed_retry_units')
              + json_extract(NEW.receipt_json, '$.remaining_retry_units')
  OR json_extract(NEW.receipt_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.receipt_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_retry_decisions_v2 d
      JOIN orchestration_retry_failed_attempts a ON a.attempt_id = NEW.attempt_id
      JOIN orchestration_retry_policies_v2 p ON p.retry_policy_id = NEW.retry_policy_id
      JOIN orchestration_retry_budget_consumptions c
        ON c.consumption_id = NEW.prior_retry_budget_consumption_id
      WHERE d.decision_id = NEW.eligibility_decision_id
        AND d.outcome = 'eligible'
        AND d.attempt_id = NEW.attempt_id
        AND d.retry_policy_id = NEW.retry_policy_id
        AND a.assessment_id = NEW.assessment_id
        AND a.plan_id = NEW.plan_id
        AND a.task_id = NEW.task_id
        AND p.assessment_id = NEW.assessment_id
        AND c.budget_account_id = NEW.budget_account_id
        AND c.budget_reservation_id = NEW.capacity_budget_reservation_id
        AND json_extract(NEW.receipt_json, '$.reserved_retry_units')
            = json_extract(c.receipt_json, '$.reserved_retry_units')
        AND json_extract(NEW.receipt_json, '$.previous_consumed_retry_units')
            = json_extract(c.receipt_json, '$.consumed_retry_units')
        AND json_extract(NEW.receipt_json, '$.remaining_retry_units')
            = json_extract(c.receipt_json, '$.remaining_retry_units') - 1
        AND json_extract(NEW.receipt_json, '$.eligibility_decision_digest')
            = json_extract(d.decision_json, '$.decision_digest')
        AND json_extract(NEW.receipt_json, '$.attempt_digest')
            = json_extract(a.receipt_json, '$.attempt_digest')
        AND json_extract(NEW.receipt_json, '$.retry_policy_digest') = p.policy_digest
  )
BEGIN SELECT RAISE(ABORT, 'retry budget consumption v2 binding is invalid'); END;

CREATE TRIGGER orchestration_retry_budget_consumptions_v2_immutable
BEFORE UPDATE ON orchestration_retry_budget_consumptions_v2
BEGIN SELECT RAISE(ABORT, 'retry budget consumption v2 is immutable'); END;

CREATE TRIGGER orchestration_retry_budget_consumptions_v2_no_delete
BEFORE DELETE ON orchestration_retry_budget_consumptions_v2
BEGIN SELECT RAISE(ABORT, 'retry budget consumptions v2 cannot be deleted'); END;
