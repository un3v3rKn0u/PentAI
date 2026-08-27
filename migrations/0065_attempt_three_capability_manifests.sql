CREATE TABLE task_capability_manifests_v4 (
    manifest_id TEXT PRIMARY KEY,
    manifest_revision INTEGER NOT NULL CHECK (manifest_revision = 1),
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    retry_activation_id TEXT NOT NULL UNIQUE
        REFERENCES orchestration_retry_activations_v2(activation_id),
    retry_schedule_id TEXT NOT NULL UNIQUE
        REFERENCES orchestration_retry_schedules_v2(schedule_id),
    retry_attempt_id TEXT NOT NULL UNIQUE
        REFERENCES orchestration_retry_attempts_v2(attempt_id),
    retry_budget_consumption_id TEXT NOT NULL UNIQUE
        REFERENCES orchestration_retry_budget_consumptions_v2(consumption_id),
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL UNIQUE CHECK (length(manifest_hash) = 64),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    issued_by TEXT NOT NULL CHECK (issued_by = 'pentai-core'),
    delegation_allowed INTEGER NOT NULL CHECK (delegation_allowed = 0),
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(plan_id, task_id, task_revision, agent_id),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER task_capability_manifests_v4_binding_valid
BEFORE INSERT ON task_capability_manifests_v4
WHEN json_extract(NEW.manifest_json, '$.schema_version') IS NOT '4.0.0'
  OR json_extract(NEW.manifest_json, '$.manifest_id') IS NOT NEW.manifest_id
  OR json_extract(NEW.manifest_json, '$.manifest_revision') IS NOT 1
  OR json_extract(NEW.manifest_json, '$.request_id') IS NOT NEW.request_id
  OR json_extract(NEW.manifest_json, '$.request_digest') IS NOT NEW.request_digest
  OR json_extract(NEW.manifest_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.manifest_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.manifest_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.manifest_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.manifest_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.manifest_json, '$.task_state') IS NOT 'ready'
  OR json_extract(NEW.manifest_json, '$.task_type') IS NOT 'validation'
  OR json_extract(NEW.manifest_json, '$.agent_id') IS NOT NEW.agent_id
  OR json_extract(NEW.manifest_json, '$.policy_bundle_id') IS NOT NEW.policy_bundle_id
  OR json_extract(NEW.manifest_json, '$.policy_hash') IS NOT NEW.policy_hash
  OR json_extract(NEW.manifest_json, '$.retry_activation_id') IS NOT NEW.retry_activation_id
  OR json_extract(NEW.manifest_json, '$.retry_schedule_id') IS NOT NEW.retry_schedule_id
  OR json_extract(NEW.manifest_json, '$.retry_attempt_id') IS NOT NEW.retry_attempt_id
  OR json_extract(NEW.manifest_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.manifest_json, '$.retry_budget_consumption_id')
       IS NOT NEW.retry_budget_consumption_id
  OR json_extract(NEW.manifest_json, '$.issued_by') IS NOT 'pentai-core'
  OR json_extract(NEW.manifest_json, '$.delegation_allowed') IS NOT 0
  OR json_extract(NEW.manifest_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.manifest_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM orchestration_retry_activations_v2 ac
      JOIN orchestration_retry_schedules_v2 s ON s.schedule_id = ac.schedule_id
      JOIN orchestration_retry_attempts_v2 a ON a.attempt_id = ac.attempt_id
      JOIN orchestration_retry_budget_consumptions_v2 c
        ON c.consumption_id = s.retry_budget_consumption_id
      JOIN orchestration_plans p ON p.plan_id = ac.plan_id
      JOIN orchestration_tasks t ON t.plan_id = ac.plan_id AND t.task_id = ac.task_id
      WHERE ac.activation_id = NEW.retry_activation_id
        AND ac.schedule_id = NEW.retry_schedule_id
        AND ac.attempt_id = NEW.retry_attempt_id
        AND s.retry_budget_consumption_id = NEW.retry_budget_consumption_id
        AND a.attempt_number = 3
        AND ac.assessment_id = NEW.assessment_id
        AND ac.plan_id = NEW.plan_id
        AND ac.resulting_plan_revision = NEW.plan_revision
        AND ac.task_id = NEW.task_id
        AND ac.resulting_task_revision = NEW.task_revision
        AND p.assessment_id = NEW.assessment_id
        AND p.state = 'active' AND p.revision = NEW.plan_revision
        AND t.assessment_id = NEW.assessment_id
        AND t.state = 'ready' AND t.revision = NEW.task_revision
        AND json_extract(NEW.manifest_json, '$.retry_activation_digest')
            = json_extract(ac.receipt_json, '$.activation_digest')
        AND json_extract(NEW.manifest_json, '$.retry_schedule_digest')
            = json_extract(s.receipt_json, '$.schedule_digest')
        AND json_extract(NEW.manifest_json, '$.retry_attempt_digest')
            = json_extract(a.receipt_json, '$.attempt_digest')
        AND json_extract(NEW.manifest_json, '$.retry_policy_id')
            = json_extract(s.receipt_json, '$.retry_policy_id')
        AND json_extract(NEW.manifest_json, '$.retry_policy_digest')
            = json_extract(s.receipt_json, '$.retry_policy_digest')
        AND json_extract(NEW.manifest_json, '$.prior_retry_budget_consumption_id')
            = json_extract(s.receipt_json, '$.prior_retry_budget_consumption_id')
        AND json_extract(NEW.manifest_json, '$.retry_budget_consumption_id')
            = json_extract(s.receipt_json, '$.retry_budget_consumption_id')
        AND json_extract(NEW.manifest_json, '$.approval_consumption_id')
            IS json_extract(s.receipt_json, '$.approval_consumption_id')
        AND json_extract(NEW.manifest_json, '$.worker_id')
            = json_extract(s.receipt_json, '$.worker_id')
        AND json_extract(NEW.manifest_json, '$.worker_version')
            = json_extract(s.receipt_json, '$.worker_version')
        AND json_extract(NEW.manifest_json, '$.lease_generation')
            = json_extract(s.receipt_json, '$.lease_generation')
        AND json_extract(NEW.manifest_json, '$.fencing_token')
            = json_extract(s.receipt_json, '$.fencing_token')
        AND json_extract(NEW.manifest_json, '$.recovery_generation')
            = json_extract(s.receipt_json, '$.recovery_generation')
        AND json_extract(NEW.manifest_json, '$.allowed_purposes')
            = json('["propose_supervised_http_validation"]')
        AND json_extract(NEW.manifest_json, '$.allowed_capabilities')
            = json('["network.http.get"]')
  )
BEGIN SELECT RAISE(ABORT, 'attempt-three capability manifest binding is invalid'); END;

CREATE TRIGGER task_capability_manifests_v4_immutable
BEFORE UPDATE ON task_capability_manifests_v4
BEGIN SELECT RAISE(ABORT, 'attempt-three capability manifests are immutable'); END;

CREATE TRIGGER task_capability_manifests_v4_no_delete
BEFORE DELETE ON task_capability_manifests_v4
BEGIN SELECT RAISE(ABORT, 'attempt-three capability manifests cannot be deleted'); END;
