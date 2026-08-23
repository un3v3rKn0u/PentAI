CREATE TABLE orchestration_retry_budget_consumptions (
    consumption_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_attempts(attempt_id),
    eligibility_decision_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_decisions(decision_id),
    retry_policy_id TEXT NOT NULL REFERENCES orchestration_retry_policies(retry_policy_id),
    budget_account_id TEXT NOT NULL REFERENCES orchestration_budget_accounts(account_id),
    budget_reservation_id TEXT NOT NULL REFERENCES orchestration_task_budget_reservations(reservation_id),
    proposed_attempt_number INTEGER NOT NULL CHECK (proposed_attempt_number = 2),
    budget_account_version_before INTEGER NOT NULL CHECK (budget_account_version_before >= 2),
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

CREATE TRIGGER orchestration_retry_budget_consumptions_immutable
BEFORE UPDATE ON orchestration_retry_budget_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration retry budget consumption is immutable'); END;

CREATE TRIGGER orchestration_retry_budget_consumptions_no_delete
BEFORE DELETE ON orchestration_retry_budget_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration retry budget consumptions cannot be deleted'); END;
