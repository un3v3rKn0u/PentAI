CREATE TABLE orchestration_task_lease_consumptions (
    consumption_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    expected_plan_revision INTEGER NOT NULL,
    resulting_plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    expected_task_revision INTEGER NOT NULL,
    resulting_task_revision INTEGER NOT NULL,
    lease_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_leases(lease_id),
    lease_generation INTEGER NOT NULL,
    fencing_token INTEGER NOT NULL,
    recovery_generation INTEGER NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    consumed_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_lease_consumptions_immutable
BEFORE UPDATE ON orchestration_task_lease_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration task lease consumption is immutable'); END;
CREATE TRIGGER orchestration_task_lease_consumptions_no_delete
BEFORE DELETE ON orchestration_task_lease_consumptions
BEGIN SELECT RAISE(ABORT, 'orchestration task lease consumption cannot be deleted'); END;

DROP TRIGGER orchestration_tasks_version_fenced;
CREATE TRIGGER orchestration_tasks_version_fenced
BEFORE UPDATE ON orchestration_tasks
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state = 'blocked' AND NEW.state IN ('ready', 'awaiting_human', 'cancelled'))
    OR (OLD.state = 'ready' AND NEW.state = 'cancelled')
    OR (
        OLD.state = 'ready' AND NEW.state = 'running'
        AND EXISTS (
            SELECT 1 FROM orchestration_task_lease_consumptions c
            JOIN orchestration_task_leases l ON l.lease_id = c.lease_id
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
              AND l.task_id = OLD.task_id
              AND l.task_revision = OLD.revision
              AND l.state = 'active'
              AND l.lease_generation = c.lease_generation
              AND l.fencing_token = c.fencing_token
              AND l.recovery_generation = c.recovery_generation
        )
    )
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
