CREATE TABLE worker_attachment_recoveries (
    worker_id TEXT PRIMARY KEY REFERENCES worker_network_attachments(worker_id),
    attachment_version INTEGER NOT NULL CHECK (attachment_version >= 1),
    recovered_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome = 'worker_terminated'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER worker_attachment_recovery_immutable
BEFORE UPDATE ON worker_attachment_recoveries
BEGIN
    SELECT RAISE(ABORT, 'worker attachment recovery is immutable');
END;

CREATE TRIGGER worker_attachment_recovery_no_delete
BEFORE DELETE ON worker_attachment_recoveries
BEGIN
    SELECT RAISE(ABORT, 'worker attachment recovery cannot be deleted');
END;
