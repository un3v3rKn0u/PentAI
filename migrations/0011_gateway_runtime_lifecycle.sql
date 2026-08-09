CREATE TABLE gateway_runtime_instances (
    runtime_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE REFERENCES gateway_sessions(session_id),
    containment_attestation_id TEXT NOT NULL,
    oci_runtime TEXT NOT NULL CHECK (oci_runtime IN ('docker', 'podman')),
    oci_runtime_instance_id TEXT NOT NULL,
    gateway_network_id TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    container_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('launching', 'running', 'terminated', 'failed')),
    created_at TEXT NOT NULL,
    last_checked_at TEXT,
    finalized_at TEXT,
    termination_reason TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER gateway_runtime_identity_immutable
BEFORE UPDATE OF session_id, containment_attestation_id, oci_runtime,
    oci_runtime_instance_id, gateway_network_id, image_digest, container_id,
    created_at, execution_enabled
ON gateway_runtime_instances
WHEN OLD.container_id IS NOT NULL OR NEW.container_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gateway runtime identity is immutable');
END;

CREATE TRIGGER gateway_runtime_no_delete
BEFORE DELETE ON gateway_runtime_instances
BEGIN
    SELECT RAISE(ABORT, 'gateway runtime history cannot be deleted');
END;

CREATE TRIGGER gateway_runtime_status_transition
BEFORE UPDATE OF status ON gateway_runtime_instances
WHEN OLD.status != NEW.status AND NOT (
    (OLD.status = 'launching' AND NEW.status IN ('running', 'terminated', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('terminated', 'failed'))
    OR (OLD.status = 'failed' AND NEW.status = 'terminated')
)
BEGIN
    SELECT RAISE(ABORT, 'gateway runtime status transition is invalid');
END;
