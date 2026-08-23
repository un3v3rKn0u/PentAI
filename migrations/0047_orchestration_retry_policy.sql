CREATE TABLE orchestration_retry_policies (
    retry_policy_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    revision INTEGER NOT NULL CHECK (revision = 1),
    policy_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL UNIQUE CHECK (length(policy_digest) = 71),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(assessment_id, policy_bundle_id, policy_hash, revision)
);

CREATE TABLE orchestration_retry_decisions (
    decision_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_attempts(attempt_id),
    retry_policy_id TEXT NOT NULL REFERENCES orchestration_retry_policies(retry_policy_id),
    retry_policy_revision INTEGER NOT NULL CHECK (retry_policy_revision = 1),
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

CREATE TRIGGER orchestration_retry_policies_immutable BEFORE UPDATE ON orchestration_retry_policies
BEGIN SELECT RAISE(ABORT, 'orchestration retry policy is immutable'); END;
CREATE TRIGGER orchestration_retry_policies_no_delete BEFORE DELETE ON orchestration_retry_policies
BEGIN SELECT RAISE(ABORT, 'orchestration retry policies cannot be deleted'); END;
CREATE TRIGGER orchestration_retry_decisions_immutable BEFORE UPDATE ON orchestration_retry_decisions
BEGIN SELECT RAISE(ABORT, 'orchestration retry decision is immutable'); END;
CREATE TRIGGER orchestration_retry_decisions_no_delete BEFORE DELETE ON orchestration_retry_decisions
BEGIN SELECT RAISE(ABORT, 'orchestration retry decisions cannot be deleted'); END;
