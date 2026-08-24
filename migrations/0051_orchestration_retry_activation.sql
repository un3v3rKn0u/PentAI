CREATE TABLE orchestration_retry_activations (
    activation_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    expected_plan_revision INTEGER NOT NULL,
    resulting_plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    expected_task_revision INTEGER NOT NULL,
    resulting_task_revision INTEGER NOT NULL,
    schedule_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_schedules(schedule_id),
    attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_attempts(attempt_id),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
    activated_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_retry_activations_valid
BEFORE INSERT ON orchestration_retry_activations
WHEN NOT EXISTS (
    SELECT 1 FROM orchestration_retry_schedules s
    JOIN orchestration_retry_attempts a ON a.attempt_id = s.attempt_id
    JOIN orchestration_plans p ON p.plan_id = s.plan_id
    JOIN orchestration_tasks t ON t.plan_id = s.plan_id AND t.task_id = s.task_id
    WHERE s.schedule_id = NEW.schedule_id AND a.attempt_id = NEW.attempt_id
      AND s.assessment_id = NEW.assessment_id AND s.plan_id = NEW.plan_id
      AND s.plan_revision = NEW.expected_plan_revision
      AND s.task_id = NEW.task_id AND s.task_revision = NEW.expected_task_revision
      AND NEW.resulting_plan_revision = NEW.expected_plan_revision + 1
      AND NEW.resulting_task_revision = NEW.expected_task_revision + 1
      AND p.assessment_id = NEW.assessment_id AND p.state = 'failed'
      AND p.revision = NEW.expected_plan_revision
      AND t.assessment_id = NEW.assessment_id AND t.state = 'failed'
      AND t.revision = NEW.expected_task_revision
)
BEGIN SELECT RAISE(ABORT, 'orchestration retry activation is invalid'); END;

CREATE TRIGGER orchestration_retry_activations_immutable BEFORE UPDATE ON orchestration_retry_activations
BEGIN SELECT RAISE(ABORT, 'orchestration retry activation is immutable'); END;
CREATE TRIGGER orchestration_retry_activations_no_delete BEFORE DELETE ON orchestration_retry_activations
BEGIN SELECT RAISE(ABORT, 'orchestration retry activations cannot be deleted'); END;

DROP TRIGGER orchestration_plans_version_fenced;
CREATE TRIGGER orchestration_plans_version_fenced
BEFORE UPDATE ON orchestration_plans
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state = 'active' AND NEW.state IN ('active', 'completed', 'cancelled', 'failed'))
    OR (OLD.state = 'failed' AND NEW.state = 'active' AND EXISTS (
        SELECT 1 FROM orchestration_retry_activations a
        WHERE a.plan_id = OLD.plan_id AND a.assessment_id = OLD.assessment_id
          AND a.expected_plan_revision = OLD.revision
          AND a.resulting_plan_revision = NEW.revision
    ))
)
BEGIN SELECT RAISE(ABORT, 'orchestration plan revision is invalid'); END;

DROP TRIGGER orchestration_tasks_version_fenced;
CREATE TRIGGER orchestration_tasks_version_fenced
BEFORE UPDATE ON orchestration_tasks
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state = 'blocked' AND NEW.state IN ('ready', 'awaiting_human', 'cancelled'))
    OR (OLD.state = 'ready' AND NEW.state = 'cancelled')
    OR (OLD.state = 'ready' AND NEW.state = 'running' AND EXISTS (
        SELECT 1 FROM orchestration_task_lease_consumptions c JOIN orchestration_task_leases l ON l.lease_id = c.lease_id
        WHERE c.plan_id = OLD.plan_id AND c.task_id = OLD.task_id AND c.assessment_id = OLD.assessment_id
          AND c.expected_task_revision = OLD.revision AND c.resulting_task_revision = NEW.revision
          AND c.expected_plan_revision = (SELECT revision FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND c.resulting_plan_revision = (SELECT revision + 1 FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND l.task_id = OLD.task_id AND l.task_revision = OLD.revision AND l.state = 'active'
          AND l.lease_generation = c.lease_generation AND l.fencing_token = c.fencing_token
          AND l.recovery_generation = c.recovery_generation
    ))
    OR (OLD.state = 'awaiting_human' AND NEW.state = 'cancelled')
    OR (OLD.state = 'awaiting_human' AND NEW.state = 'ready' AND EXISTS (
        SELECT 1 FROM orchestration_task_approval_consumptions c
        JOIN orchestration_task_approval_requests r ON r.request_id = c.request_id
        JOIN orchestration_task_approval_decisions d ON d.decision_id = c.decision_id
        WHERE c.plan_id = OLD.plan_id AND c.task_id = OLD.task_id AND c.assessment_id = OLD.assessment_id
          AND c.expected_task_revision = OLD.revision AND c.resulting_task_revision = NEW.revision
          AND c.expected_plan_revision = (SELECT revision FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND c.resulting_plan_revision = (SELECT revision + 1 FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND r.plan_id = OLD.plan_id AND r.task_id = OLD.task_id AND r.task_revision = OLD.revision
          AND r.request_digest = c.request_digest AND d.request_id = r.request_id
          AND d.request_digest = r.request_digest AND d.decision = 'approved'
          AND d.resulting_task_state = 'awaiting_human' AND ('sha256:' || d.content_hash) = c.decision_digest
    ))
    OR (OLD.state = 'running' AND NEW.state IN ('cancelling', 'succeeded'))
    OR (OLD.state = 'running' AND NEW.state = 'failed' AND (
        EXISTS (SELECT 1 FROM orchestration_task_failures f WHERE f.plan_id = OLD.plan_id
          AND f.task_id = OLD.task_id AND f.assessment_id = OLD.assessment_id
          AND f.expected_task_revision = OLD.revision AND f.resulting_task_revision = NEW.revision
          AND f.expected_plan_revision = (SELECT revision FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND f.resulting_plan_revision = (SELECT revision + 1 FROM orchestration_plans WHERE plan_id = OLD.plan_id))
        OR EXISTS (SELECT 1 FROM orchestration_task_recovery_failures r WHERE r.plan_id = OLD.plan_id
          AND r.task_id = OLD.task_id AND r.expected_task_revision = OLD.revision
          AND r.resulting_task_revision = NEW.revision)
    ))
    OR (OLD.state = 'failed' AND NEW.state = 'ready' AND EXISTS (
        SELECT 1 FROM orchestration_retry_activations a
        JOIN orchestration_retry_schedules s ON s.schedule_id = a.schedule_id
        WHERE a.plan_id = OLD.plan_id AND a.task_id = OLD.task_id AND a.assessment_id = OLD.assessment_id
          AND a.expected_task_revision = OLD.revision AND a.resulting_task_revision = NEW.revision
          AND a.expected_plan_revision = (SELECT revision FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND a.resulting_plan_revision = (SELECT revision + 1 FROM orchestration_plans WHERE plan_id = OLD.plan_id)
          AND s.attempt_id = a.attempt_id AND s.task_id = OLD.task_id
    ))
    OR (OLD.state = 'cancelling' AND NEW.state IN ('cancelled', 'failed'))
)
BEGIN SELECT RAISE(ABORT, 'orchestration task revision is invalid'); END;
