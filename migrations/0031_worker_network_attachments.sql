CREATE TABLE worker_network_attachments (
    worker_id TEXT PRIMARY KEY REFERENCES worker_runtime_instances(worker_id),
    attachment_attestation_id TEXT NOT NULL UNIQUE,
    runtime_version INTEGER NOT NULL CHECK (runtime_version >= 1),
    container_id TEXT NOT NULL,
    worker_gateway_network_id TEXT NOT NULL,
    gateway_container_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('prepared', 'attached', 'failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    failure_reason TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    version INTEGER NOT NULL CHECK (version >= 1),
    CHECK (
        (status = 'failed' AND failure_reason IS NOT NULL)
        OR (status != 'failed' AND failure_reason IS NULL)
    )
);

CREATE INDEX worker_network_attachment_recovery_queue
ON worker_network_attachments(status, worker_id);

CREATE TRIGGER worker_network_attachment_identity_immutable
BEFORE UPDATE OF worker_id, attachment_attestation_id, runtime_version, container_id,
    worker_gateway_network_id, gateway_container_id, created_at, execution_enabled
ON worker_network_attachments
BEGIN
    SELECT RAISE(ABORT, 'worker attachment identity is immutable');
END;

CREATE TRIGGER worker_network_attachment_version_fenced
BEFORE UPDATE ON worker_network_attachments
WHEN NEW.version != OLD.version + 1
BEGIN
    SELECT RAISE(ABORT, 'worker attachment version transition is invalid');
END;

CREATE TRIGGER worker_network_attachment_status_transition
BEFORE UPDATE OF status ON worker_network_attachments
WHEN OLD.status != NEW.status AND NOT (
    (OLD.status = 'prepared' AND NEW.status IN ('attached', 'failed'))
    OR (OLD.status = 'attached' AND NEW.status = 'failed')
)
BEGIN
    SELECT RAISE(ABORT, 'worker attachment status transition is invalid');
END;

CREATE TRIGGER worker_network_attachment_transition_required
BEFORE UPDATE ON worker_network_attachments
WHEN OLD.status = NEW.status
BEGIN
    SELECT RAISE(ABORT, 'worker attachment update requires a status transition');
END;

CREATE TRIGGER worker_network_attachment_no_delete
BEFORE DELETE ON worker_network_attachments
BEGIN
    SELECT RAISE(ABORT, 'worker attachment history cannot be deleted');
END;
