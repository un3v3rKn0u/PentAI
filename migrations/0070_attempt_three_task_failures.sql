CREATE TABLE orchestration_task_failures_v3 (
    failure_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    expected_plan_revision INTEGER NOT NULL,
    resulting_plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    expected_task_revision INTEGER NOT NULL,
    resulting_task_revision INTEGER NOT NULL,
    lease_consumption_id TEXT NOT NULL REFERENCES orchestration_task_lease_consumptions_v3(consumption_id),
    checkpoint_id TEXT REFERENCES orchestration_task_checkpoints_v3(checkpoint_id),
    failure_class TEXT NOT NULL CHECK (failure_class IN (
        'checkpoint_stalled','coordination_timeout','runtime_unavailable','worker_process_failed'
    )),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash)=64),
    recorded_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority='none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled=0),
    UNIQUE(task_id, expected_task_revision),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_failures_v3_binding_valid
BEFORE INSERT ON orchestration_task_failures_v3
WHEN json_extract(NEW.receipt_json,'$.schema_version') IS NOT '3.0.0'
 OR json_extract(NEW.receipt_json,'$.failure_id') IS NOT NEW.failure_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.expected_plan_revision') IS NOT NEW.expected_plan_revision
 OR json_extract(NEW.receipt_json,'$.resulting_plan_revision') IS NOT NEW.resulting_plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.expected_task_revision') IS NOT NEW.expected_task_revision
 OR json_extract(NEW.receipt_json,'$.resulting_task_revision') IS NOT NEW.resulting_task_revision
 OR json_extract(NEW.receipt_json,'$.lease_consumption_id') IS NOT NEW.lease_consumption_id
 OR json_extract(NEW.receipt_json,'$.checkpoint_id') IS NOT NEW.checkpoint_id
 OR json_extract(NEW.receipt_json,'$.failure_class') IS NOT NEW.failure_class
 OR json_extract(NEW.receipt_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.resulting_task_state') IS NOT 'failed'
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
 OR NEW.resulting_plan_revision != NEW.expected_plan_revision+1
 OR NEW.resulting_task_revision != NEW.expected_task_revision+1
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_task_lease_consumptions_v3 c
   LEFT JOIN orchestration_task_checkpoints_v3 k ON k.checkpoint_id=NEW.checkpoint_id
   WHERE c.consumption_id=NEW.lease_consumption_id
    AND c.assessment_id=NEW.assessment_id AND c.plan_id=NEW.plan_id
    AND c.resulting_plan_revision=NEW.expected_plan_revision
    AND c.task_id=NEW.task_id AND c.resulting_task_revision=NEW.expected_task_revision
    AND json_extract(c.receipt_json,'$.schema_version')='3.0.0'
    AND json_extract(c.receipt_json,'$.attempt_number')=3
    AND json_extract(NEW.receipt_json,'$.lease_consumption_digest')='sha256:'||c.receipt_hash
    AND json_extract(NEW.receipt_json,'$.retry_attempt_id')=json_extract(c.receipt_json,'$.retry_attempt_id')
    AND ((NEW.checkpoint_id IS NULL
      AND json_extract(NEW.receipt_json,'$.checkpoint_sequence') IS NULL
      AND json_extract(NEW.receipt_json,'$.checkpoint_digest') IS NULL
      AND NOT EXISTS (SELECT 1 FROM orchestration_task_checkpoints_v3 h
        WHERE h.task_id=NEW.task_id AND h.task_revision=NEW.expected_task_revision))
     OR (k.task_id=NEW.task_id AND k.task_revision=NEW.expected_task_revision
      AND json_extract(k.receipt_json,'$.schema_version')='3.0.0'
      AND k.sequence=json_extract(NEW.receipt_json,'$.checkpoint_sequence')
      AND k.checkpoint_digest=json_extract(NEW.receipt_json,'$.checkpoint_digest')
      AND NOT EXISTS (SELECT 1 FROM orchestration_task_checkpoints_v3 h
        WHERE h.task_id=NEW.task_id AND h.task_revision=NEW.expected_task_revision
          AND h.sequence>k.sequence)))
 )
BEGIN SELECT RAISE(ABORT, 'attempt-three failure binding is invalid'); END;

CREATE TRIGGER orchestration_task_failures_v3_immutable BEFORE UPDATE ON orchestration_task_failures_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three failure is immutable'); END;
CREATE TRIGGER orchestration_task_failures_v3_no_delete BEFORE DELETE ON orchestration_task_failures_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three failures cannot be deleted'); END;

DROP TRIGGER orchestration_tasks_version_fenced;
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
