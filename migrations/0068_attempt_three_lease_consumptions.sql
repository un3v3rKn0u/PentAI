CREATE TABLE orchestration_task_lease_consumptions_v3 (
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
    lease_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_leases_v3(lease_id),
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

CREATE TRIGGER orchestration_task_lease_consumptions_v3_binding_valid
BEFORE INSERT ON orchestration_task_lease_consumptions_v3
WHEN json_extract(NEW.receipt_json, '$.schema_version') IS NOT '3.0.0'
  OR json_extract(NEW.receipt_json, '$.consumption_id') IS NOT NEW.consumption_id
  OR json_extract(NEW.receipt_json, '$.command_id') IS NOT NEW.command_id
  OR json_extract(NEW.receipt_json, '$.command_digest') IS NOT NEW.command_digest
  OR json_extract(NEW.receipt_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.receipt_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.receipt_json, '$.expected_plan_revision') IS NOT NEW.expected_plan_revision
  OR json_extract(NEW.receipt_json, '$.resulting_plan_revision') IS NOT NEW.resulting_plan_revision
  OR json_extract(NEW.receipt_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.receipt_json, '$.expected_task_revision') IS NOT NEW.expected_task_revision
  OR json_extract(NEW.receipt_json, '$.resulting_task_revision') IS NOT NEW.resulting_task_revision
  OR json_extract(NEW.receipt_json, '$.lease_id') IS NOT NEW.lease_id
  OR json_extract(NEW.receipt_json, '$.lease_generation') IS NOT NEW.lease_generation
  OR json_extract(NEW.receipt_json, '$.fencing_token') IS NOT NEW.fencing_token
  OR json_extract(NEW.receipt_json, '$.recovery_generation') IS NOT NEW.recovery_generation
  OR json_extract(NEW.receipt_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.receipt_json, '$.resulting_task_state') IS NOT 'running'
  OR json_extract(NEW.receipt_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.receipt_json, '$.execution_enabled') IS NOT 0
  OR NEW.resulting_plan_revision != NEW.expected_plan_revision + 1
  OR NEW.resulting_task_revision != NEW.expected_task_revision + 1
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_task_leases_v3 l
      JOIN task_capability_manifests_v4 m ON m.manifest_id=l.capability_manifest_id
      JOIN orchestration_task_budget_reservations_v4 b
        ON b.reservation_id=l.budget_reservation_id
      JOIN orchestration_retry_activations_v2 a ON a.activation_id=l.retry_activation_id
      JOIN orchestration_retry_attempts_v2 r ON r.attempt_id=l.retry_attempt_id
      WHERE l.lease_id=NEW.lease_id AND l.assessment_id=NEW.assessment_id
        AND l.plan_id=NEW.plan_id AND l.plan_revision=NEW.expected_plan_revision
        AND l.task_id=NEW.task_id AND l.task_revision=NEW.expected_task_revision
        AND l.state='active' AND l.lease_version=1
        AND l.lease_generation=NEW.lease_generation
        AND l.fencing_token=NEW.fencing_token
        AND l.recovery_generation=NEW.recovery_generation
        AND json_extract(l.state_json, '$.schema_version')='3.0.0'
        AND json_extract(NEW.receipt_json, '$.capability_manifest_id')=m.manifest_id
        AND json_extract(NEW.receipt_json, '$.capability_manifest_digest')='sha256:'||m.manifest_hash
        AND json_extract(NEW.receipt_json, '$.budget_reservation_id')=b.reservation_id
        AND json_extract(NEW.receipt_json, '$.budget_request_digest')=b.request_digest
        AND json_extract(NEW.receipt_json, '$.retry_activation_id')=a.activation_id
        AND json_extract(NEW.receipt_json, '$.retry_attempt_id')=r.attempt_id
        AND json_extract(NEW.receipt_json, '$.worker_id')=l.worker_id
        AND json_extract(NEW.receipt_json, '$.worker_version')=l.worker_version
        AND json_extract(NEW.receipt_json, '$.policy_bundle_id')=l.policy_bundle_id
        AND json_extract(NEW.receipt_json, '$.policy_hash')=l.policy_hash
  )
BEGIN SELECT RAISE(ABORT, 'attempt-three lease consumption binding is invalid'); END;

CREATE TRIGGER orchestration_task_lease_consumptions_v3_immutable
BEFORE UPDATE ON orchestration_task_lease_consumptions_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three lease consumption is immutable'); END;
CREATE TRIGGER orchestration_task_lease_consumptions_v3_no_delete
BEFORE DELETE ON orchestration_task_lease_consumptions_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three lease consumption cannot be deleted'); END;

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
