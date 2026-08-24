ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN capability_manifest_digest TEXT CHECK (
    capability_manifest_digest IS NULL OR length(capability_manifest_digest) = 71
);
ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN retry_activation_id TEXT REFERENCES orchestration_retry_activations(activation_id);
ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN retry_activation_digest TEXT CHECK (
    retry_activation_digest IS NULL OR length(retry_activation_digest) = 71
);
ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN retry_attempt_id TEXT REFERENCES orchestration_retry_attempts(attempt_id);
ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN retry_attempt_digest TEXT CHECK (
    retry_attempt_digest IS NULL OR length(retry_attempt_digest) = 71
);
ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN retry_budget_consumption_id TEXT
REFERENCES orchestration_retry_budget_consumptions(consumption_id);

CREATE UNIQUE INDEX orchestration_retry_budget_reservation_activation_unique
ON orchestration_task_budget_reservations(retry_activation_id)
WHERE retry_activation_id IS NOT NULL;

CREATE TRIGGER orchestration_retry_budget_reservation_fields_immutable
BEFORE UPDATE OF capability_manifest_digest, retry_activation_id, retry_activation_digest,
    retry_attempt_id, retry_attempt_digest, retry_budget_consumption_id
ON orchestration_task_budget_reservations
BEGIN SELECT RAISE(ABORT, 'retry budget reservation binding is immutable'); END;

CREATE TRIGGER orchestration_retry_budget_reservation_fields_complete
BEFORE INSERT ON orchestration_task_budget_reservations
WHEN (json_extract(NEW.receipt_json, '$.schema_version') = '3.0.0')
       != (NEW.retry_activation_id IS NOT NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.capability_manifest_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_activation_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_id IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_budget_consumption_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'retry budget reservation fields are incomplete'); END;

CREATE TRIGGER orchestration_retry_budget_reservation_binding_valid
BEFORE INSERT ON orchestration_task_budget_reservations
WHEN NEW.retry_activation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM task_capability_manifests m
    JOIN orchestration_retry_activations a ON a.activation_id = NEW.retry_activation_id
    JOIN orchestration_retry_attempts ra ON ra.attempt_id = a.attempt_id
    JOIN orchestration_tasks t ON t.plan_id = a.plan_id AND t.task_id = a.task_id
    JOIN orchestration_plans p ON p.plan_id = a.plan_id
    WHERE m.manifest_id = NEW.capability_manifest_id
      AND m.manifest_revision = NEW.manifest_revision
      AND m.manifest_hash = substr(NEW.capability_manifest_digest, 8)
      AND m.retry_activation_id = NEW.retry_activation_id
      AND m.retry_activation_digest = NEW.retry_activation_digest
      AND m.retry_attempt_id = NEW.retry_attempt_id
      AND m.retry_attempt_digest = NEW.retry_attempt_digest
      AND m.retry_budget_consumption_id = NEW.retry_budget_consumption_id
      AND a.attempt_id = NEW.retry_attempt_id
      AND json_extract(a.receipt_json, '$.activation_digest') = NEW.retry_activation_digest
      AND json_extract(ra.receipt_json, '$.attempt_digest') = NEW.retry_attempt_digest
      AND ra.retry_budget_consumption_id = NEW.retry_budget_consumption_id
      AND a.assessment_id = NEW.assessment_id
      AND a.plan_id = NEW.plan_id AND a.resulting_plan_revision = NEW.plan_revision
      AND a.task_id = NEW.task_id AND a.resulting_task_revision = NEW.task_revision
      AND p.assessment_id = NEW.assessment_id AND p.state = 'active'
      AND p.revision = NEW.plan_revision
      AND t.assessment_id = NEW.assessment_id AND t.state = 'ready'
      AND t.revision = NEW.task_revision
      AND NEW.task_state = 'ready'
      AND NEW.purpose = 'reserve_validation_task_budget'
      AND json_extract(NEW.receipt_json, '$.schema_version') = '3.0.0'
      AND json_extract(NEW.receipt_json, '$.retry_activation_id') = NEW.retry_activation_id
      AND json_extract(NEW.receipt_json, '$.retry_budget_consumption_id') = NEW.retry_budget_consumption_id
)
BEGIN SELECT RAISE(ABORT, 'retry budget reservation binding is invalid'); END;
