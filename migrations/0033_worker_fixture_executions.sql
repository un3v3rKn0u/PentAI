CREATE UNIQUE INDEX worker_network_attachment_version_identity
ON worker_network_attachments(worker_id, version);

CREATE TABLE worker_fixture_executions (
    claim_id TEXT PRIMARY KEY REFERENCES gateway_fixture_execution_claims(claim_id),
    worker_id TEXT NOT NULL REFERENCES worker_network_attachments(worker_id),
    attachment_version INTEGER NOT NULL,
    container_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('prepared', 'completed', 'failed')),
    prepared_at TEXT NOT NULL,
    finalized_at TEXT,
    failure_reason TEXT,
    external_execution_enabled INTEGER NOT NULL DEFAULT 0 CHECK (external_execution_enabled = 0),
    FOREIGN KEY(worker_id, attachment_version)
        REFERENCES worker_network_attachments(worker_id, version)
);

CREATE UNIQUE INDEX worker_fixture_execution_active_worker
ON worker_fixture_executions(worker_id)
WHERE status = 'prepared';

CREATE TRIGGER worker_fixture_execution_identity_immutable
BEFORE UPDATE OF claim_id, worker_id, attachment_version, container_id, prepared_at,
    external_execution_enabled
ON worker_fixture_executions
BEGIN
    SELECT RAISE(ABORT, 'worker fixture execution identity is immutable');
END;

CREATE TRIGGER worker_fixture_execution_status_transition
BEFORE UPDATE OF status, finalized_at, failure_reason ON worker_fixture_executions
WHEN OLD.status != 'prepared'
    OR NEW.status NOT IN ('completed', 'failed')
    OR NEW.finalized_at IS NULL
    OR (NEW.status = 'completed' AND NEW.failure_reason IS NOT NULL)
    OR (NEW.status = 'failed' AND (NEW.failure_reason IS NULL OR length(NEW.failure_reason) > 256))
BEGIN
    SELECT RAISE(ABORT, 'worker fixture execution transition is invalid');
END;

CREATE TRIGGER worker_fixture_execution_no_delete
BEFORE DELETE ON worker_fixture_executions
BEGIN
    SELECT RAISE(ABORT, 'worker fixture execution cannot be deleted');
END;
