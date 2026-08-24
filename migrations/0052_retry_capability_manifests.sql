ALTER TABLE task_capability_manifests
ADD COLUMN retry_activation_id TEXT REFERENCES orchestration_retry_activations(activation_id);
ALTER TABLE task_capability_manifests
ADD COLUMN retry_activation_digest TEXT CHECK (
    retry_activation_digest IS NULL OR length(retry_activation_digest) = 71
);
ALTER TABLE task_capability_manifests
ADD COLUMN retry_attempt_id TEXT REFERENCES orchestration_retry_attempts(attempt_id);
ALTER TABLE task_capability_manifests
ADD COLUMN retry_attempt_digest TEXT CHECK (
    retry_attempt_digest IS NULL OR length(retry_attempt_digest) = 71
);
ALTER TABLE task_capability_manifests
ADD COLUMN retry_budget_consumption_id TEXT
REFERENCES orchestration_retry_budget_consumptions(consumption_id);

CREATE UNIQUE INDEX task_capability_manifests_retry_activation_unique
ON task_capability_manifests(retry_activation_id)
WHERE retry_activation_id IS NOT NULL;

CREATE TRIGGER task_capability_manifests_retry_binding_valid
BEFORE INSERT ON task_capability_manifests
WHEN NEW.retry_activation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM orchestration_retry_activations a
    JOIN orchestration_retry_attempts ra ON ra.attempt_id = a.attempt_id
    JOIN orchestration_tasks t ON t.plan_id = a.plan_id AND t.task_id = a.task_id
    JOIN orchestration_plans p ON p.plan_id = a.plan_id
    WHERE a.activation_id = NEW.retry_activation_id
      AND json_extract(a.receipt_json, '$.activation_digest') = NEW.retry_activation_digest
      AND a.attempt_id = NEW.retry_attempt_id
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
      AND json_extract(NEW.manifest_json, '$.schema_version') = '3.0.0'
      AND json_extract(NEW.manifest_json, '$.retry_activation_id') = NEW.retry_activation_id
      AND json_extract(NEW.manifest_json, '$.retry_activation_digest') = NEW.retry_activation_digest
      AND json_extract(NEW.manifest_json, '$.retry_attempt_id') = NEW.retry_attempt_id
      AND json_extract(NEW.manifest_json, '$.retry_attempt_digest') = NEW.retry_attempt_digest
      AND json_extract(NEW.manifest_json, '$.retry_budget_consumption_id') = NEW.retry_budget_consumption_id
)
BEGIN SELECT RAISE(ABORT, 'retry capability manifest binding is invalid'); END;

CREATE TRIGGER task_capability_manifests_retry_fields_complete
BEFORE INSERT ON task_capability_manifests
WHEN (json_extract(NEW.manifest_json, '$.schema_version') = '3.0.0')
       != (NEW.retry_activation_id IS NOT NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_activation_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_id IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_attempt_digest IS NULL)
  OR (NEW.retry_activation_id IS NULL) != (NEW.retry_budget_consumption_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'retry capability manifest fields are incomplete'); END;
