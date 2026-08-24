ALTER TABLE orchestration_task_leases
ADD COLUMN capability_manifest_digest TEXT CHECK (
    capability_manifest_digest IS NULL OR length(capability_manifest_digest) = 71
);
ALTER TABLE orchestration_task_leases
ADD COLUMN budget_request_digest TEXT CHECK (
    budget_request_digest IS NULL OR length(budget_request_digest) = 71
);
ALTER TABLE orchestration_task_leases
ADD COLUMN retry_activation_id TEXT REFERENCES orchestration_retry_activations(activation_id);
ALTER TABLE orchestration_task_leases
ADD COLUMN retry_activation_digest TEXT CHECK (
    retry_activation_digest IS NULL OR length(retry_activation_digest) = 71
);
ALTER TABLE orchestration_task_leases
ADD COLUMN retry_attempt_id TEXT REFERENCES orchestration_retry_attempts(attempt_id);
ALTER TABLE orchestration_task_leases
ADD COLUMN retry_attempt_digest TEXT CHECK (
    retry_attempt_digest IS NULL OR length(retry_attempt_digest) = 71
);
ALTER TABLE orchestration_task_leases
ADD COLUMN retry_budget_consumption_id TEXT
REFERENCES orchestration_retry_budget_consumptions(consumption_id);

CREATE UNIQUE INDEX orchestration_retry_task_lease_activation_unique
ON orchestration_task_leases(retry_activation_id)
WHERE retry_activation_id IS NOT NULL;

CREATE TRIGGER orchestration_retry_task_lease_fields_immutable
BEFORE UPDATE OF capability_manifest_digest, budget_request_digest,
    retry_activation_id, retry_activation_digest, retry_attempt_id,
    retry_attempt_digest, retry_budget_consumption_id
ON orchestration_task_leases
BEGIN SELECT RAISE(ABORT, 'retry task lease binding is immutable'); END;

CREATE TRIGGER orchestration_retry_task_lease_fields_complete
BEFORE INSERT ON orchestration_task_leases
WHEN (json_extract(NEW.state_json, '$.schema_version') = '2.0.0')
       != (NEW.retry_activation_id IS NOT NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.capability_manifest_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.budget_request_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_activation_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_id IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_budget_consumption_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'retry task lease fields are incomplete'); END;

CREATE TRIGGER orchestration_retry_task_lease_binding_valid
BEFORE INSERT ON orchestration_task_leases
WHEN NEW.retry_activation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM task_capability_manifests m
    JOIN orchestration_task_budget_reservations b
      ON b.reservation_id = NEW.budget_reservation_id
    JOIN orchestration_retry_activations a ON a.activation_id = NEW.retry_activation_id
    WHERE m.manifest_id = NEW.capability_manifest_id
      AND m.manifest_revision = NEW.manifest_revision
      AND m.manifest_hash = substr(NEW.capability_manifest_digest, 8)
      AND b.capability_manifest_id = m.manifest_id
      AND b.capability_manifest_digest = NEW.capability_manifest_digest
      AND b.retry_activation_id = NEW.retry_activation_id
      AND b.retry_activation_digest = NEW.retry_activation_digest
      AND b.retry_attempt_id = NEW.retry_attempt_id
      AND b.retry_attempt_digest = NEW.retry_attempt_digest
      AND b.retry_budget_consumption_id = NEW.retry_budget_consumption_id
      AND json_extract(b.receipt_json, '$.schema_version') = '3.0.0'
      AND b.request_digest = NEW.budget_request_digest
      AND a.assessment_id = NEW.assessment_id
      AND a.plan_id = NEW.plan_id AND a.resulting_plan_revision = NEW.plan_revision
      AND a.task_id = NEW.task_id AND a.resulting_task_revision = NEW.task_revision
      AND a.attempt_id = NEW.retry_attempt_id
      AND json_extract(a.receipt_json, '$.activation_digest') = NEW.retry_activation_digest
      AND NEW.state = 'active'
      AND json_extract(NEW.state_json, '$.schema_version') = '2.0.0'
      AND json_extract(NEW.state_json, '$.retry_activation_id') = NEW.retry_activation_id
      AND json_extract(NEW.state_json, '$.retry_budget_consumption_id') = NEW.retry_budget_consumption_id
)
BEGIN SELECT RAISE(ABORT, 'retry task lease binding is invalid'); END;
