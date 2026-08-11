CREATE TABLE evidence_deletions (
    deletion_id TEXT PRIMARY KEY,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN ('original', 'redaction')),
    artifact_id TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    retention_days INTEGER NOT NULL CHECK (retention_days >= 1),
    retention_deadline TEXT NOT NULL,
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    request_hash TEXT NOT NULL UNIQUE CHECK (length(request_hash) = 64),
    status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'completed')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 3),
    started_at TEXT,
    completed_at TEXT,
    blob_disposition TEXT CHECK (
        blob_disposition IN ('unlinked', 'already_absent', 'retained_shared')
    ),
    forensic_erase_guaranteed INTEGER NOT NULL CHECK (forensic_erase_guaranteed = 0),
    UNIQUE(artifact_type, artifact_id),
    CHECK (
        (status = 'pending' AND version = 1 AND started_at IS NULL
         AND completed_at IS NULL AND blob_disposition IS NULL)
        OR (status = 'processing' AND version = 2 AND started_at IS NOT NULL
            AND completed_at IS NULL AND blob_disposition IS NULL)
        OR (status = 'completed' AND version = 3 AND started_at IS NOT NULL
            AND completed_at IS NOT NULL AND blob_disposition IS NOT NULL)
    )
);

CREATE INDEX evidence_deletions_by_state
ON evidence_deletions(status, requested_at, deletion_id);

CREATE TRIGGER evidence_deletions_identity_immutable
BEFORE UPDATE OF deletion_id, artifact_type, artifact_id, policy_bundle_id, sha256,
    retention_days, retention_deadline, reason, requested_by, requested_at,
    request_hash, forensic_erase_guaranteed
ON evidence_deletions
BEGIN
    SELECT RAISE(ABORT, 'evidence deletion identity is immutable');
END;

CREATE TRIGGER evidence_deletions_transition
BEFORE UPDATE OF status, version, started_at, completed_at, blob_disposition
ON evidence_deletions
WHEN NOT (
    (OLD.status = 'pending' AND OLD.version = 1
     AND NEW.status = 'processing' AND NEW.version = 2
     AND NEW.started_at IS NOT NULL AND NEW.completed_at IS NULL
     AND NEW.blob_disposition IS NULL)
    OR (OLD.status = 'processing' AND OLD.version = 2
        AND NEW.status = 'completed' AND NEW.version = 3
        AND NEW.started_at = OLD.started_at AND NEW.completed_at IS NOT NULL
        AND NEW.blob_disposition IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'evidence deletion transition is invalid');
END;

CREATE TRIGGER evidence_deletions_no_delete
BEFORE DELETE ON evidence_deletions
BEGIN
    SELECT RAISE(ABORT, 'evidence deletion history cannot be deleted');
END;
