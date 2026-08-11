CREATE TABLE evidence_objects (
    evidence_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    execution_trace_id TEXT REFERENCES execution_traces(trace_id),
    idempotency_key TEXT NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (
        evidence_kind IN ('note', 'http_metadata', 'response_excerpt', 'screenshot',
                          'imported_file', 'tool_output')
    ),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    storage_ref TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 2097152),
    media_type TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (
        classification IN ('internal', 'restricted')
    ),
    encryption_version TEXT NOT NULL CHECK (encryption_version = 'aes-256-gcm-hkdf-v1'),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(workflow_id, idempotency_key)
);

CREATE INDEX evidence_objects_by_workflow
ON evidence_objects(workflow_id, created_at, evidence_id);

CREATE INDEX evidence_objects_by_digest ON evidence_objects(sha256);

CREATE TABLE evidence_custody_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
    action TEXT NOT NULL CHECK (action IN ('stored', 'metadata_accessed', 'content_accessed')),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('human', 'service')),
    actor_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
);

CREATE INDEX evidence_custody_by_object
ON evidence_custody_events(evidence_id, sequence);

CREATE TRIGGER evidence_objects_immutable
BEFORE UPDATE ON evidence_objects
BEGIN
    SELECT RAISE(ABORT, 'evidence originals are immutable');
END;

CREATE TRIGGER evidence_objects_no_delete
BEFORE DELETE ON evidence_objects
BEGIN
    SELECT RAISE(ABORT, 'evidence originals cannot be deleted');
END;

CREATE TRIGGER evidence_custody_immutable
BEFORE UPDATE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'evidence custody events are immutable');
END;

CREATE TRIGGER evidence_custody_no_delete
BEFORE DELETE ON evidence_custody_events
BEGIN
    SELECT RAISE(ABORT, 'evidence custody events cannot be deleted');
END;

CREATE TRIGGER evidence_custody_chain_guard
BEFORE INSERT ON evidence_custody_events
WHEN (
    NOT EXISTS (SELECT 1 FROM evidence_custody_events WHERE evidence_id = NEW.evidence_id)
    AND NEW.previous_hash IS NOT NULL
) OR (
    EXISTS (SELECT 1 FROM evidence_custody_events WHERE evidence_id = NEW.evidence_id)
    AND NEW.previous_hash IS NOT (
        SELECT event_hash FROM evidence_custody_events
        WHERE evidence_id = NEW.evidence_id ORDER BY sequence DESC LIMIT 1
    )
)
BEGIN
    SELECT RAISE(ABORT, 'evidence custody chain head does not match');
END;
