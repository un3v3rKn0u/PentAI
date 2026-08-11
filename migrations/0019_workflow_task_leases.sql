CREATE TABLE workflow_task_lifecycles (
    task_id TEXT PRIMARY KEY REFERENCES workflow_tasks(task_id),
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'leased', 'retry_wait', 'succeeded', 'dead_letter', 'cancelled')
    ),
    version INTEGER NOT NULL CHECK (version >= 1),
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    next_attempt_at TEXT,
    lease_owner TEXT,
    lease_token_hash TEXT,
    lease_expires_at TEXT,
    last_error_code TEXT,
    updated_at TEXT NOT NULL,
    finalized_at TEXT,
    dispatch_enabled INTEGER NOT NULL CHECK (dispatch_enabled = 0),
    external_effect_enabled INTEGER NOT NULL CHECK (external_effect_enabled = 0),
    CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL
         AND length(lease_token_hash) = 64 AND lease_expires_at IS NOT NULL)
        OR (state != 'leased' AND lease_owner IS NULL AND lease_token_hash IS NULL
            AND lease_expires_at IS NULL)
    ),
    CHECK (
        (state IN ('succeeded', 'dead_letter', 'cancelled') AND finalized_at IS NOT NULL)
        OR (state NOT IN ('succeeded', 'dead_letter', 'cancelled') AND finalized_at IS NULL)
    ),
    CHECK (attempt_count <= max_attempts),
    CHECK (
        (state = 'retry_wait' AND next_attempt_at IS NOT NULL)
        OR (state != 'retry_wait' AND next_attempt_at IS NULL)
    )
);

INSERT INTO workflow_task_lifecycles(
    task_id, state, version, attempt_count, max_attempts, updated_at,
    finalized_at, dispatch_enabled, external_effect_enabled
)
SELECT task_id, state, 1, 0, 3, created_at, finalized_at, 0, 0
FROM workflow_tasks;

CREATE INDEX workflow_task_lifecycles_claimable
ON workflow_task_lifecycles(state, next_attempt_at, updated_at);

CREATE TABLE workflow_task_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workflow_tasks(task_id),
    task_version INTEGER NOT NULL CHECK (task_version >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    progress INTEGER NOT NULL CHECK (progress BETWEEN 0 AND 100),
    output_refs_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, sequence)
);

CREATE TABLE workflow_task_receipts (
    receipt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workflow_tasks(task_id),
    operation TEXT NOT NULL CHECK (operation IN ('complete', 'fail')),
    idempotency_key TEXT NOT NULL,
    lease_token_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, operation, idempotency_key)
);

CREATE TRIGGER workflow_task_lifecycles_identity_immutable
BEFORE UPDATE OF task_id, max_attempts, dispatch_enabled, external_effect_enabled
ON workflow_task_lifecycles
BEGIN
    SELECT RAISE(ABORT, 'workflow task lifecycle identity is immutable');
END;

CREATE TRIGGER workflow_task_lifecycles_version_fenced
BEFORE UPDATE ON workflow_task_lifecycles
WHEN NEW.version != OLD.version + 1 OR NOT (
    (OLD.state IN ('queued', 'retry_wait') AND NEW.state IN ('leased', 'cancelled'))
    OR (OLD.state = 'leased' AND NEW.state IN (
        'leased', 'retry_wait', 'succeeded', 'dead_letter', 'cancelled'
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'workflow task lifecycle transition is invalid');
END;

CREATE TRIGGER workflow_task_lifecycles_no_delete
BEFORE DELETE ON workflow_task_lifecycles
BEGIN
    SELECT RAISE(ABORT, 'workflow task lifecycle history cannot be deleted');
END;

CREATE TRIGGER workflow_task_checkpoints_immutable
BEFORE UPDATE ON workflow_task_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'workflow task checkpoint is immutable');
END;

CREATE TRIGGER workflow_task_checkpoints_no_delete
BEFORE DELETE ON workflow_task_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'workflow task checkpoint history cannot be deleted');
END;

CREATE TRIGGER workflow_task_receipts_immutable
BEFORE UPDATE ON workflow_task_receipts
BEGIN
    SELECT RAISE(ABORT, 'workflow task receipt is immutable');
END;

CREATE TRIGGER workflow_task_receipts_no_delete
BEFORE DELETE ON workflow_task_receipts
BEGIN
    SELECT RAISE(ABORT, 'workflow task receipt history cannot be deleted');
END;
