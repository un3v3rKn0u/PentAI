CREATE TABLE orchestration_task_approval_requests (
    request_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL UNIQUE CHECK (length(request_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    task_type TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    purpose TEXT NOT NULL CHECK (purpose = 'authorize_task_readiness'),
    requested_capability TEXT NOT NULL CHECK (requested_capability = 'orchestration.task.ready'),
    parameters_digest TEXT NOT NULL CHECK (length(parameters_digest) = 71),
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(plan_id, task_id, task_revision),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TABLE orchestration_task_approval_decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_approval_requests(request_id),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    approver_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resulting_task_state TEXT NOT NULL CHECK (resulting_task_state IN ('awaiting_human', 'cancelled')),
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER orchestration_task_approval_requests_immutable
BEFORE UPDATE ON orchestration_task_approval_requests
BEGIN SELECT RAISE(ABORT, 'orchestration task approval requests are immutable'); END;
CREATE TRIGGER orchestration_task_approval_requests_no_delete
BEFORE DELETE ON orchestration_task_approval_requests
BEGIN SELECT RAISE(ABORT, 'orchestration task approval requests cannot be deleted'); END;
CREATE TRIGGER orchestration_task_approval_decisions_immutable
BEFORE UPDATE ON orchestration_task_approval_decisions
BEGIN SELECT RAISE(ABORT, 'orchestration task approval decisions are immutable'); END;
CREATE TRIGGER orchestration_task_approval_decisions_no_delete
BEFORE DELETE ON orchestration_task_approval_decisions
BEGIN SELECT RAISE(ABORT, 'orchestration task approval decisions cannot be deleted'); END;
