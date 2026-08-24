ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN capability_manifest_digest TEXT CHECK (
    capability_manifest_digest IS NULL OR length(capability_manifest_digest) = 71
);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN budget_request_digest TEXT CHECK (
    budget_request_digest IS NULL OR length(budget_request_digest) = 71
);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN retry_activation_id TEXT REFERENCES orchestration_retry_activations(activation_id);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN retry_activation_digest TEXT CHECK (
    retry_activation_digest IS NULL OR length(retry_activation_digest) = 71
);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN retry_attempt_id TEXT REFERENCES orchestration_retry_attempts(attempt_id);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN retry_attempt_digest TEXT CHECK (
    retry_attempt_digest IS NULL OR length(retry_attempt_digest) = 71
);
ALTER TABLE orchestration_task_lease_consumptions
ADD COLUMN retry_budget_consumption_id TEXT
REFERENCES orchestration_retry_budget_consumptions(consumption_id);

CREATE UNIQUE INDEX orchestration_retry_lease_consumption_activation_unique
ON orchestration_task_lease_consumptions(retry_activation_id)
WHERE retry_activation_id IS NOT NULL;

CREATE TRIGGER orchestration_retry_lease_consumption_fields_complete
BEFORE INSERT ON orchestration_task_lease_consumptions
WHEN (json_extract(NEW.receipt_json, '$.schema_version') = '2.0.0')
       != (NEW.retry_activation_id IS NOT NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.capability_manifest_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.budget_request_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_activation_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_id IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_budget_consumption_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'retry lease consumption fields are incomplete'); END;

CREATE TRIGGER orchestration_retry_lease_consumption_binding_valid
BEFORE INSERT ON orchestration_task_lease_consumptions
WHEN NEW.retry_activation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM orchestration_task_leases l
    JOIN orchestration_retry_activations a ON a.activation_id = NEW.retry_activation_id
    JOIN task_capability_manifests m ON m.manifest_id = l.capability_manifest_id
    JOIN orchestration_task_budget_reservations b
      ON b.reservation_id = l.budget_reservation_id
    WHERE l.lease_id = NEW.lease_id
      AND l.assessment_id = NEW.assessment_id
      AND l.plan_id = NEW.plan_id AND l.plan_revision = NEW.expected_plan_revision
      AND l.task_id = NEW.task_id AND l.task_revision = NEW.expected_task_revision
      AND l.state = 'active'
      AND json_extract(l.state_json, '$.schema_version') = '2.0.0'
      AND l.capability_manifest_digest = NEW.capability_manifest_digest
      AND l.budget_request_digest = NEW.budget_request_digest
      AND l.retry_activation_id = NEW.retry_activation_id
      AND l.retry_activation_digest = NEW.retry_activation_digest
      AND l.retry_attempt_id = NEW.retry_attempt_id
      AND l.retry_attempt_digest = NEW.retry_attempt_digest
      AND l.retry_budget_consumption_id = NEW.retry_budget_consumption_id
      AND m.manifest_hash = substr(NEW.capability_manifest_digest, 8)
      AND json_extract(m.manifest_json, '$.schema_version') = '3.0.0'
      AND b.request_digest = NEW.budget_request_digest
      AND json_extract(b.receipt_json, '$.schema_version') = '3.0.0'
      AND a.attempt_id = NEW.retry_attempt_id
      AND json_extract(a.receipt_json, '$.activation_digest') = NEW.retry_activation_digest
      AND json_extract(NEW.receipt_json, '$.retry_activation_id') = NEW.retry_activation_id
      AND json_extract(NEW.receipt_json, '$.retry_attempt_id') = NEW.retry_attempt_id
      AND json_extract(NEW.receipt_json, '$.retry_budget_consumption_id')
          = NEW.retry_budget_consumption_id
)
BEGIN SELECT RAISE(ABORT, 'retry lease consumption binding is invalid'); END;

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
              AND (
                  (
                      json_extract(c.receipt_json, '$.schema_version') = '1.0.0'
                      AND json_extract(l.state_json, '$.schema_version') = '1.0.0'
                      AND c.retry_activation_id IS NULL
                  ) OR (
                      json_extract(c.receipt_json, '$.schema_version') = '2.0.0'
                      AND json_extract(l.state_json, '$.schema_version') = '2.0.0'
                      AND c.retry_activation_id = l.retry_activation_id
                      AND c.retry_activation_digest = l.retry_activation_digest
                      AND c.retry_attempt_id = l.retry_attempt_id
                      AND c.retry_attempt_digest = l.retry_attempt_digest
                      AND c.retry_budget_consumption_id = l.retry_budget_consumption_id
                      AND c.capability_manifest_digest = l.capability_manifest_digest
                      AND c.budget_request_digest = l.budget_request_digest
                  )
              )
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
