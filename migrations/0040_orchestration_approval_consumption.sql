CREATE TABLE orchestration_task_approval_consumptions (
    consumption_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_approval_requests(request_id),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    decision_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_approval_decisions(decision_id),
    decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    expected_plan_revision INTEGER NOT NULL,
    resulting_plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    expected_task_revision INTEGER NOT NULL,
    resulting_task_revision INTEGER NOT NULL,
    task_type TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    purpose TEXT NOT NULL CHECK (purpose = 'authorize_task_readiness'),
    requested_capability TEXT NOT NULL CHECK (requested_capability = 'orchestration.task.ready'),
    parameters_digest TEXT NOT NULL CHECK (length(parameters_digest) = 71),
    actor_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    approval_expires_at TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_approval_consumptions_valid
BEFORE INSERT ON orchestration_task_approval_consumptions
WHEN NOT EXISTS (
    SELECT 1 FROM orchestration_task_approval_requests r
    JOIN orchestration_task_approval_decisions d ON d.request_id = r.request_id
    JOIN orchestration_plans p ON p.plan_id = r.plan_id
    JOIN orchestration_tasks t ON t.plan_id = r.plan_id AND t.task_id = r.task_id
    WHERE r.request_id = NEW.request_id
      AND r.request_digest = NEW.request_digest
      AND d.decision_id = NEW.decision_id
      AND ('sha256:' || d.content_hash) = NEW.decision_digest
      AND d.request_digest = r.request_digest
      AND d.decision = 'approved'
      AND d.resulting_task_state = 'awaiting_human'
      AND r.assessment_id = NEW.assessment_id
      AND r.plan_id = NEW.plan_id
      AND r.plan_revision = NEW.expected_plan_revision
      AND NEW.resulting_plan_revision = NEW.expected_plan_revision + 1
      AND r.task_id = NEW.task_id
      AND r.task_revision = NEW.expected_task_revision
      AND NEW.resulting_task_revision = NEW.expected_task_revision + 1
      AND r.task_type = NEW.task_type
      AND r.policy_bundle_id = NEW.policy_bundle_id
      AND r.policy_hash = NEW.policy_hash
      AND r.purpose = NEW.purpose
      AND r.requested_capability = NEW.requested_capability
      AND r.parameters_digest = NEW.parameters_digest
      AND d.approver_id = NEW.actor_id
      AND d.expires_at = NEW.approval_expires_at
      AND p.assessment_id = NEW.assessment_id
      AND p.revision = NEW.expected_plan_revision
      AND p.state = 'active'
      AND t.assessment_id = NEW.assessment_id
      AND t.revision = NEW.expected_task_revision
      AND t.state = 'awaiting_human'
      AND t.requires_human_approval = 1
)
BEGIN SELECT RAISE(ABORT, 'orchestration task approval consumption is invalid'); END;

CREATE TRIGGER orchestration_task_approval_consumptions_immutable
BEFORE UPDATE ON orchestration_task_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration task approval consumption is immutable'); END;
CREATE TRIGGER orchestration_task_approval_consumptions_no_delete
BEFORE DELETE ON orchestration_task_approval_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration task approval consumption cannot be deleted'); END;

DROP TRIGGER orchestration_tasks_version_fenced;
CREATE TRIGGER orchestration_tasks_version_fenced
BEFORE UPDATE ON orchestration_tasks
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state = 'blocked' AND NEW.state IN ('ready', 'awaiting_human', 'cancelled'))
    OR (OLD.state = 'ready' AND NEW.state IN ('running', 'cancelled'))
    OR (OLD.state = 'awaiting_human' AND NEW.state = 'cancelled')
    OR (
        OLD.state = 'awaiting_human' AND NEW.state = 'ready'
        AND EXISTS (
            SELECT 1 FROM orchestration_task_approval_consumptions c
            JOIN orchestration_task_approval_requests r ON r.request_id = c.request_id
            JOIN orchestration_task_approval_decisions d ON d.decision_id = c.decision_id
            WHERE c.plan_id = OLD.plan_id
              AND c.task_id = OLD.task_id
              AND c.assessment_id = OLD.assessment_id
              AND c.expected_task_revision = OLD.revision
              AND c.resulting_task_revision = NEW.revision
              AND c.expected_plan_revision = (
                  SELECT revision FROM orchestration_plans WHERE plan_id = OLD.plan_id
              )
              AND c.resulting_plan_revision = (
                  SELECT revision + 1 FROM orchestration_plans WHERE plan_id = OLD.plan_id
              )
              AND r.plan_id = OLD.plan_id
              AND r.task_id = OLD.task_id
              AND r.task_revision = OLD.revision
              AND r.request_digest = c.request_digest
              AND d.request_id = r.request_id
              AND d.request_digest = r.request_digest
              AND d.decision = 'approved'
              AND d.resulting_task_state = 'awaiting_human'
              AND ('sha256:' || d.content_hash) = c.decision_digest
        )
    )
    OR (OLD.state = 'running' AND NEW.state IN ('cancelling', 'succeeded', 'failed'))
    OR (OLD.state = 'cancelling' AND NEW.state IN ('cancelled', 'failed'))
)
BEGIN SELECT RAISE(ABORT, 'orchestration task revision is invalid'); END;
