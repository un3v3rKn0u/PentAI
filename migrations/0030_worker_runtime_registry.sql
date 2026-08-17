CREATE TABLE worker_runtime_instances (
    worker_id TEXT PRIMARY KEY,
    containment_attestation_id TEXT NOT NULL,
    oci_runtime TEXT NOT NULL CHECK (oci_runtime IN ('docker', 'podman')),
    runtime_instance_id TEXT NOT NULL,
    worker_gateway_network_id TEXT NOT NULL,
    image_digest TEXT NOT NULL CHECK (
        length(image_digest) = 71
        AND substr(image_digest, 1, 7) = 'sha256:'
        AND substr(image_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    container_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (
        status IN ('launching', 'running', 'termination_requested', 'terminated', 'failed')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    termination_reason TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    version INTEGER NOT NULL CHECK (version >= 1)
);

CREATE UNIQUE INDEX worker_runtime_active_identity
ON worker_runtime_instances(runtime_instance_id, worker_gateway_network_id)
WHERE status IN ('launching', 'running', 'termination_requested', 'failed');

CREATE INDEX worker_runtime_recovery_queue
ON worker_runtime_instances(status, worker_id);

CREATE TRIGGER worker_runtime_identity_immutable
BEFORE UPDATE OF worker_id, containment_attestation_id, oci_runtime,
    runtime_instance_id, worker_gateway_network_id, image_digest, created_at,
    execution_enabled
ON worker_runtime_instances
BEGIN
    SELECT RAISE(ABORT, 'worker runtime identity is immutable');
END;

CREATE TRIGGER worker_runtime_container_once
BEFORE UPDATE OF container_id ON worker_runtime_instances
WHEN OLD.container_id IS NOT NULL OR NEW.container_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'worker container identity is immutable');
END;

CREATE TRIGGER worker_runtime_version_fenced
BEFORE UPDATE ON worker_runtime_instances
WHEN NEW.version != OLD.version + 1
BEGIN
    SELECT RAISE(ABORT, 'worker runtime version transition is invalid');
END;

CREATE TRIGGER worker_runtime_status_transition
BEFORE UPDATE OF status ON worker_runtime_instances
WHEN OLD.status != NEW.status AND NOT (
    (OLD.status = 'launching' AND NEW.status IN ('running', 'termination_requested', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('termination_requested', 'failed'))
    OR (OLD.status = 'termination_requested' AND NEW.status IN ('terminated', 'failed'))
    OR (OLD.status = 'failed' AND NEW.status IN ('termination_requested', 'terminated'))
)
BEGIN
    SELECT RAISE(ABORT, 'worker runtime status transition is invalid');
END;

CREATE TRIGGER worker_runtime_no_delete
BEFORE DELETE ON worker_runtime_instances
BEGIN
    SELECT RAISE(ABORT, 'worker runtime history cannot be deleted');
END;
