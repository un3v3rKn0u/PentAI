ALTER TABLE orchestration_task_checkpoints
ADD COLUMN capability_manifest_digest TEXT CHECK (
    capability_manifest_digest IS NULL OR length(capability_manifest_digest) = 71
);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN budget_request_digest TEXT CHECK (
    budget_request_digest IS NULL OR length(budget_request_digest) = 71
);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN retry_activation_id TEXT REFERENCES orchestration_retry_activations(activation_id);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN retry_activation_digest TEXT CHECK (
    retry_activation_digest IS NULL OR length(retry_activation_digest) = 71
);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN retry_attempt_id TEXT REFERENCES orchestration_retry_attempts(attempt_id);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN retry_attempt_digest TEXT CHECK (
    retry_attempt_digest IS NULL OR length(retry_attempt_digest) = 71
);
ALTER TABLE orchestration_task_checkpoints
ADD COLUMN retry_budget_consumption_id TEXT
REFERENCES orchestration_retry_budget_consumptions(consumption_id);

CREATE TRIGGER orchestration_retry_checkpoint_fields_complete
BEFORE INSERT ON orchestration_task_checkpoints
WHEN (json_extract(NEW.receipt_json, '$.schema_version') = '2.0.0')
       != (NEW.retry_activation_id IS NOT NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.capability_manifest_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.budget_request_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_activation_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_id IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_budget_consumption_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'retry checkpoint fields are incomplete'); END;

CREATE TRIGGER orchestration_retry_checkpoint_binding_valid
BEFORE INSERT ON orchestration_task_checkpoints
WHEN NEW.retry_activation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM orchestration_task_lease_consumptions c
    JOIN task_capability_manifests m
      ON m.manifest_id = json_extract(c.receipt_json, '$.capability_manifest_id')
    JOIN orchestration_task_budget_reservations b
      ON b.reservation_id = json_extract(c.receipt_json, '$.budget_reservation_id')
    WHERE c.consumption_id = NEW.lease_consumption_id
      AND c.assessment_id = NEW.assessment_id
      AND c.plan_id = NEW.plan_id AND c.resulting_plan_revision = NEW.plan_revision
      AND c.task_id = NEW.task_id AND c.resulting_task_revision = NEW.task_revision
      AND json_extract(c.receipt_json, '$.schema_version') = '2.0.0'
      AND c.capability_manifest_digest = NEW.capability_manifest_digest
      AND c.budget_request_digest = NEW.budget_request_digest
      AND c.retry_activation_id = NEW.retry_activation_id
      AND c.retry_activation_digest = NEW.retry_activation_digest
      AND c.retry_attempt_id = NEW.retry_attempt_id
      AND c.retry_attempt_digest = NEW.retry_attempt_digest
      AND c.retry_budget_consumption_id = NEW.retry_budget_consumption_id
      AND m.manifest_hash = substr(NEW.capability_manifest_digest, 8)
      AND json_extract(m.manifest_json, '$.schema_version') = '3.0.0'
      AND b.request_digest = NEW.budget_request_digest
      AND json_extract(b.receipt_json, '$.schema_version') = '3.0.0'
      AND json_extract(NEW.receipt_json, '$.retry_activation_id') = NEW.retry_activation_id
      AND json_extract(NEW.receipt_json, '$.retry_attempt_id') = NEW.retry_attempt_id
      AND json_extract(NEW.receipt_json, '$.retry_budget_consumption_id')
          = NEW.retry_budget_consumption_id
)
BEGIN SELECT RAISE(ABORT, 'retry checkpoint binding is invalid'); END;
