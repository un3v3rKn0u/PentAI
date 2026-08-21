CREATE TABLE orchestration_budget_accounts (
    account_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    configuration_id TEXT NOT NULL,
    configuration_hash TEXT NOT NULL CHECK (length(configuration_hash) = 64),
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK (registry_revision >= 1),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    ceilings_json TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(assessment_id, configuration_id, registry_id, registry_revision,
        policy_bundle_id, policy_hash)
);

CREATE TABLE orchestration_task_budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    account_id TEXT NOT NULL REFERENCES orchestration_budget_accounts(account_id),
    account_version INTEGER NOT NULL CHECK (account_version >= 2),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    capability_manifest_id TEXT NOT NULL REFERENCES task_capability_manifests(manifest_id),
    manifest_revision INTEGER NOT NULL CHECK (manifest_revision = 1),
    policy_bundle_id TEXT NOT NULL,
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    purpose TEXT NOT NULL CHECK (purpose = 'reserve_validation_task_budget'),
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

CREATE TRIGGER orchestration_budget_accounts_identity_immutable
BEFORE UPDATE OF account_id, assessment_id, configuration_id, configuration_hash,
    registry_id, registry_revision, policy_bundle_id, policy_hash, ceilings_json,
    created_at, expires_at, authority, execution_enabled
ON orchestration_budget_accounts
BEGIN SELECT RAISE(ABORT, 'orchestration budget account identity is immutable'); END;

CREATE TRIGGER orchestration_budget_accounts_no_delete
BEFORE DELETE ON orchestration_budget_accounts
BEGIN SELECT RAISE(ABORT, 'orchestration budget accounts cannot be deleted'); END;

CREATE TRIGGER orchestration_task_budget_reservation_identity_immutable
BEFORE UPDATE OF reservation_id, request_id, request_digest, account_id, assessment_id,
    plan_id, plan_revision, task_id, task_revision, agent_id, capability_manifest_id,
    manifest_revision, policy_bundle_id, policy_hash, purpose, amounts_json, created_at,
    expires_at, authority, execution_enabled
ON orchestration_task_budget_reservations
BEGIN SELECT RAISE(ABORT, 'orchestration task budget identity is immutable'); END;

CREATE TRIGGER orchestration_task_budget_reservations_no_delete
BEFORE DELETE ON orchestration_task_budget_reservations
BEGIN SELECT RAISE(ABORT, 'orchestration task budget reservations cannot be deleted'); END;
