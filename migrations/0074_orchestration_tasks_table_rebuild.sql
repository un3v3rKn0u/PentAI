-- pentai: table-rebuild
ALTER TABLE orchestration_tasks RENAME TO orchestration_tasks_old;

CREATE TABLE orchestration_tasks (
    task_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES orchestration_plans(plan_id),
    assessment_id TEXT NOT NULL,
    task_type TEXT NOT NULL CHECK (task_type IN ('scope', 'rules_of_engagement', 'evidence', 'validation', 'reporting')),
    objective TEXT NOT NULL CHECK (length(objective) BETWEEN 1 AND 512),
    input_refs_json TEXT NOT NULL,
    requires_human_approval INTEGER NOT NULL CHECK (requires_human_approval IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('blocked', 'awaiting_human', 'ready', 'running', 'cancelling', 'cancelled', 'succeeded', 'failed', 'dead_letter')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(plan_id, task_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id)
);

INSERT INTO orchestration_tasks(
    task_id,plan_id,assessment_id,task_type,objective,input_refs_json,
    requires_human_approval,state,revision,created_at,updated_at,authority,
    execution_enabled
)
SELECT task_id,plan_id,assessment_id,task_type,objective,input_refs_json,
       requires_human_approval,state,revision,created_at,updated_at,authority,
       execution_enabled
FROM orchestration_tasks_old;

DROP TABLE orchestration_tasks_old;

CREATE TRIGGER orchestration_tasks_identity_immutable
BEFORE UPDATE OF task_id, plan_id, assessment_id, task_type, objective, input_refs_json,
    requires_human_approval, created_at, authority, execution_enabled
ON orchestration_tasks BEGIN SELECT RAISE(ABORT, 'orchestration task identity is immutable'); END;

CREATE TRIGGER orchestration_tasks_no_delete BEFORE DELETE ON orchestration_tasks
BEGIN SELECT RAISE(ABORT, 'orchestration task history cannot be deleted'); END;

CREATE TRIGGER orchestration_tasks_dead_letter_insert_disabled
BEFORE INSERT ON orchestration_tasks WHEN NEW.state='dead_letter'
BEGIN SELECT RAISE(ABORT, 'orchestration dead-letter insertion is disabled'); END;

CREATE TRIGGER orchestration_tasks_version_fenced
BEFORE UPDATE ON orchestration_tasks
WHEN NEW.revision != OLD.revision + 1 OR NOT (
    (OLD.state='blocked' AND NEW.state IN ('ready','awaiting_human','cancelled'))
    OR (OLD.state='ready' AND NEW.state='cancelled')
    OR (OLD.state='ready' AND NEW.state='running' AND (
        EXISTS (
            SELECT 1 FROM orchestration_task_lease_consumptions c
            JOIN orchestration_task_leases l ON l.lease_id=c.lease_id
            WHERE c.plan_id=OLD.plan_id AND c.task_id=OLD.task_id
              AND c.assessment_id=OLD.assessment_id AND c.expected_task_revision=OLD.revision
              AND c.resulting_task_revision=NEW.revision
              AND c.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
              AND c.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
              AND l.task_id=OLD.task_id AND l.task_revision=OLD.revision AND l.state='active'
              AND l.lease_generation=c.lease_generation AND l.fencing_token=c.fencing_token
              AND l.recovery_generation=c.recovery_generation
              AND ((json_extract(c.receipt_json,'$.schema_version')='1.0.0'
                    AND json_extract(l.state_json,'$.schema_version')='1.0.0'
                    AND c.retry_activation_id IS NULL)
                OR (json_extract(c.receipt_json,'$.schema_version')='2.0.0'
                    AND json_extract(l.state_json,'$.schema_version')='2.0.0'
                    AND c.retry_activation_id=l.retry_activation_id
                    AND c.retry_activation_digest=l.retry_activation_digest
                    AND c.retry_attempt_id=l.retry_attempt_id
                    AND c.retry_attempt_digest=l.retry_attempt_digest
                    AND c.retry_budget_consumption_id=l.retry_budget_consumption_id
                    AND c.capability_manifest_digest=l.capability_manifest_digest
                    AND c.budget_request_digest=l.budget_request_digest))
        ) OR EXISTS (
            SELECT 1 FROM orchestration_task_lease_consumptions_v3 c
            JOIN orchestration_task_leases_v3 l ON l.lease_id=c.lease_id
            WHERE c.plan_id=OLD.plan_id AND c.task_id=OLD.task_id
              AND c.assessment_id=OLD.assessment_id AND c.expected_task_revision=OLD.revision
              AND c.resulting_task_revision=NEW.revision
              AND c.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
              AND c.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
              AND l.task_id=OLD.task_id AND l.task_revision=OLD.revision AND l.state='active'
              AND l.lease_generation=c.lease_generation AND l.fencing_token=c.fencing_token
              AND l.recovery_generation=c.recovery_generation
              AND json_extract(c.receipt_json,'$.schema_version')='3.0.0'
              AND json_extract(l.state_json,'$.schema_version')='3.0.0'
        )
    ))
    OR (OLD.state='awaiting_human' AND NEW.state='cancelled')
    OR (OLD.state='awaiting_human' AND NEW.state='ready' AND EXISTS (
        SELECT 1 FROM orchestration_task_approval_consumptions c
        JOIN orchestration_task_approval_requests r ON r.request_id=c.request_id
        JOIN orchestration_task_approval_decisions d ON d.decision_id=c.decision_id
        WHERE c.plan_id=OLD.plan_id AND c.task_id=OLD.task_id
          AND c.assessment_id=OLD.assessment_id AND c.expected_task_revision=OLD.revision
          AND c.resulting_task_revision=NEW.revision
          AND c.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
          AND c.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
          AND r.plan_id=OLD.plan_id AND r.task_id=OLD.task_id AND r.task_revision=OLD.revision
          AND r.request_digest=c.request_digest AND d.request_id=r.request_id
          AND d.request_digest=r.request_digest AND d.decision='approved'
          AND d.resulting_task_state='awaiting_human'
          AND ('sha256:'||d.content_hash)=c.decision_digest))
    OR (OLD.state='running' AND NEW.state IN ('cancelling','succeeded'))
    OR (OLD.state='running' AND NEW.state='failed' AND (
        EXISTS (SELECT 1 FROM orchestration_task_failures f WHERE f.plan_id=OLD.plan_id
          AND f.task_id=OLD.task_id AND f.assessment_id=OLD.assessment_id
          AND f.expected_task_revision=OLD.revision AND f.resulting_task_revision=NEW.revision
          AND f.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
          AND f.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id))
        OR EXISTS (SELECT 1 FROM orchestration_task_failures_v3 f WHERE f.plan_id=OLD.plan_id
          AND f.task_id=OLD.task_id AND f.assessment_id=OLD.assessment_id
          AND f.expected_task_revision=OLD.revision AND f.resulting_task_revision=NEW.revision
          AND f.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
          AND f.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
          AND json_extract(f.receipt_json,'$.schema_version')='3.0.0'
          AND json_extract(f.receipt_json,'$.attempt_number')=3)
        OR EXISTS (SELECT 1 FROM orchestration_task_recovery_failures r WHERE r.plan_id=OLD.plan_id
          AND r.task_id=OLD.task_id AND r.expected_task_revision=OLD.revision
          AND r.resulting_task_revision=NEW.revision)))
    OR (OLD.state='failed' AND NEW.state='ready' AND (
        EXISTS (SELECT 1 FROM orchestration_retry_activations a
          JOIN orchestration_retry_schedules s ON s.schedule_id=a.schedule_id
          WHERE a.plan_id=OLD.plan_id AND a.task_id=OLD.task_id AND a.assessment_id=OLD.assessment_id
            AND a.expected_task_revision=OLD.revision AND a.resulting_task_revision=NEW.revision
            AND a.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
            AND a.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
            AND s.attempt_id=a.attempt_id AND s.task_id=OLD.task_id)
        OR EXISTS (SELECT 1 FROM orchestration_retry_activations_v2 a
          JOIN orchestration_retry_schedules_v2 s ON s.schedule_id=a.schedule_id
          WHERE a.plan_id=OLD.plan_id AND a.task_id=OLD.task_id AND a.assessment_id=OLD.assessment_id
            AND a.expected_task_revision=OLD.revision AND a.resulting_task_revision=NEW.revision
            AND a.expected_plan_revision=(SELECT revision FROM orchestration_plans WHERE plan_id=OLD.plan_id)
            AND a.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans WHERE plan_id=OLD.plan_id)
            AND s.attempt_id=a.attempt_id AND s.task_id=OLD.task_id)))
    OR (OLD.state='cancelling' AND NEW.state IN ('cancelled','failed'))
)
BEGIN SELECT RAISE(ABORT, 'orchestration task revision is invalid'); END;
