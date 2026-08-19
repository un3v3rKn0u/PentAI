ALTER TABLE worker_runtime_instances
ADD COLUMN gateway_container_id TEXT;

ALTER TABLE worker_runtime_instances
ADD COLUMN attachment_mode TEXT NOT NULL DEFAULT 'deferred'
CHECK (attachment_mode IN ('deferred', 'podman_direct'));

CREATE TRIGGER worker_runtime_direct_attachment_identity
BEFORE INSERT ON worker_runtime_instances
WHEN (NEW.attachment_mode = 'podman_direct'
      AND (NEW.gateway_container_id IS NULL OR NEW.oci_runtime != 'podman'))
  OR (NEW.attachment_mode = 'deferred' AND NEW.gateway_container_id IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'worker direct attachment identity is invalid');
END;

CREATE TRIGGER worker_runtime_direct_attachment_immutable
BEFORE UPDATE OF gateway_container_id, attachment_mode
ON worker_runtime_instances
BEGIN
    SELECT RAISE(ABORT, 'worker direct attachment identity is immutable');
END;
