ALTER TABLE task_capability_manifests
ADD COLUMN task_state TEXT NOT NULL DEFAULT 'running'
CHECK (task_state IN ('ready', 'running'));

CREATE TRIGGER task_capability_manifest_state_immutable
BEFORE UPDATE OF task_state ON task_capability_manifests
BEGIN SELECT RAISE(ABORT, 'task capability manifest state binding is immutable'); END;

ALTER TABLE orchestration_task_budget_reservations
ADD COLUMN task_state TEXT NOT NULL DEFAULT 'running'
CHECK (task_state IN ('ready', 'running'));

CREATE TRIGGER orchestration_task_budget_state_immutable
BEFORE UPDATE OF task_state ON orchestration_task_budget_reservations
BEGIN SELECT RAISE(ABORT, 'orchestration task budget state binding is immutable'); END;
