CREATE TABLE orchestration_task_budget_reservations_v4 (
    reservation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    account_id TEXT NOT NULL REFERENCES orchestration_budget_accounts(account_id),
    account_version INTEGER NOT NULL,
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    capability_manifest_id TEXT NOT NULL UNIQUE REFERENCES task_capability_manifests_v4(manifest_id),
    retry_activation_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_activations_v2(activation_id),
    retry_attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_attempts_v2(attempt_id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    purpose TEXT NOT NULL CHECK (purpose = 'reserve_attempt_three_validation_task_budget'),
    amounts_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'released')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    release_reason TEXT NOT NULL CHECK (release_reason IN ('none', 'cancelled', 'expired', 'recovery')),
    receipt_json TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_budget_reservations_v4_binding_valid
BEFORE INSERT ON orchestration_task_budget_reservations_v4
WHEN json_extract(NEW.receipt_json, '$.schema_version') IS NOT '4.0.0'
  OR json_extract(NEW.receipt_json, '$.reservation_id') IS NOT NEW.reservation_id
  OR json_extract(NEW.receipt_json, '$.request_id') IS NOT NEW.request_id
  OR json_extract(NEW.receipt_json, '$.request_digest') IS NOT NEW.request_digest
  OR json_extract(NEW.receipt_json, '$.account_id') IS NOT NEW.account_id
  OR json_extract(NEW.receipt_json, '$.account_version') IS NOT NEW.account_version
  OR json_extract(NEW.receipt_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.receipt_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.receipt_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.receipt_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.receipt_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.receipt_json, '$.task_state') IS NOT 'ready'
  OR json_extract(NEW.receipt_json, '$.agent_id') IS NOT NEW.agent_id
  OR json_extract(NEW.receipt_json, '$.capability_manifest_id') IS NOT NEW.capability_manifest_id
  OR json_extract(NEW.receipt_json, '$.retry_activation_id') IS NOT NEW.retry_activation_id
  OR json_extract(NEW.receipt_json, '$.retry_attempt_id') IS NOT NEW.retry_attempt_id
  OR json_extract(NEW.receipt_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.receipt_json, '$.policy_bundle_id') IS NOT NEW.policy_bundle_id
  OR json_extract(NEW.receipt_json, '$.policy_hash') IS NOT NEW.policy_hash
  OR json_extract(NEW.receipt_json, '$.purpose') IS NOT NEW.purpose
  OR json_extract(NEW.receipt_json, '$.amounts') != json(NEW.amounts_json)
  OR json_extract(NEW.receipt_json, '$.state') IS NOT NEW.state
  OR json_extract(NEW.receipt_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.receipt_json, '$.execution_enabled') IS NOT 0
  OR json_extract(NEW.receipt_json, '$.amounts.retries') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM task_capability_manifests_v4 m
      JOIN orchestration_retry_activations_v2 a ON a.activation_id = m.retry_activation_id
      JOIN orchestration_plans p ON p.plan_id = m.plan_id
      JOIN orchestration_tasks t ON t.plan_id = m.plan_id AND t.task_id = m.task_id
      WHERE m.manifest_id = NEW.capability_manifest_id
        AND m.retry_activation_id = NEW.retry_activation_id
        AND m.retry_attempt_id = NEW.retry_attempt_id
        AND m.assessment_id = NEW.assessment_id
        AND m.plan_id = NEW.plan_id AND m.plan_revision = NEW.plan_revision
        AND m.task_id = NEW.task_id AND m.task_revision = NEW.task_revision
        AND m.agent_id = NEW.agent_id
        AND m.policy_bundle_id = NEW.policy_bundle_id AND m.policy_hash = NEW.policy_hash
        AND a.resulting_plan_revision = NEW.plan_revision
        AND a.resulting_task_revision = NEW.task_revision
        AND p.state = 'active' AND p.revision = NEW.plan_revision
        AND t.state = 'ready' AND t.revision = NEW.task_revision
  )
BEGIN SELECT RAISE(ABORT, 'attempt-three budget reservation binding is invalid'); END;

CREATE TRIGGER orchestration_task_budget_reservations_v4_immutable_identity
BEFORE UPDATE OF reservation_id, request_id, request_digest, account_id, assessment_id,
    plan_id, plan_revision, task_id, task_revision, agent_id, capability_manifest_id,
    retry_activation_id, retry_attempt_id, policy_bundle_id, policy_hash, purpose, amounts_json,
    created_at, expires_at, authority, execution_enabled
ON orchestration_task_budget_reservations_v4
BEGIN SELECT RAISE(ABORT, 'attempt-three budget reservation identity is immutable'); END;

CREATE TRIGGER orchestration_task_budget_reservations_v4_no_delete
BEFORE DELETE ON orchestration_task_budget_reservations_v4
BEGIN SELECT RAISE(ABORT, 'attempt-three budget reservations cannot be deleted'); END;
