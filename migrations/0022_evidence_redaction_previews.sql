CREATE TABLE evidence_derivatives (
    derivative_id TEXT PRIMARY KEY,
    parent_evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    derivative_kind TEXT NOT NULL CHECK (derivative_kind = 'redaction'),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    storage_ref TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 2097152),
    media_type TEXT NOT NULL CHECK (media_type = 'text/plain'),
    classification TEXT NOT NULL CHECK (classification IN ('public', 'internal')),
    encryption_version TEXT NOT NULL CHECK (encryption_version = 'aes-256-gcm-hkdf-v1'),
    redactions_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(parent_evidence_id, idempotency_key)
);

CREATE INDEX evidence_derivatives_by_parent
ON evidence_derivatives(parent_evidence_id, created_at, derivative_id);

CREATE TABLE evidence_derivative_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    derivative_id TEXT NOT NULL REFERENCES evidence_derivatives(derivative_id),
    action TEXT NOT NULL CHECK (action IN ('stored', 'previewed')),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('human', 'service')),
    actor_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
);

CREATE INDEX evidence_derivative_events_by_object
ON evidence_derivative_events(derivative_id, sequence);

CREATE TRIGGER evidence_derivatives_immutable
BEFORE UPDATE ON evidence_derivatives
BEGIN
    SELECT RAISE(ABORT, 'evidence derivatives are immutable');
END;

CREATE TRIGGER evidence_derivatives_no_delete
BEFORE DELETE ON evidence_derivatives
BEGIN
    SELECT RAISE(ABORT, 'evidence derivatives cannot be deleted');
END;

CREATE TRIGGER evidence_derivative_events_immutable
BEFORE UPDATE ON evidence_derivative_events
BEGIN
    SELECT RAISE(ABORT, 'evidence derivative events are immutable');
END;

CREATE TRIGGER evidence_derivative_events_no_delete
BEFORE DELETE ON evidence_derivative_events
BEGIN
    SELECT RAISE(ABORT, 'evidence derivative events cannot be deleted');
END;

CREATE TRIGGER evidence_derivative_events_chain_guard
BEFORE INSERT ON evidence_derivative_events
WHEN (
    NOT EXISTS (
        SELECT 1 FROM evidence_derivative_events WHERE derivative_id = NEW.derivative_id
    ) AND NEW.previous_hash IS NOT NULL
) OR (
    EXISTS (
        SELECT 1 FROM evidence_derivative_events WHERE derivative_id = NEW.derivative_id
    ) AND NEW.previous_hash IS NOT (
        SELECT event_hash FROM evidence_derivative_events
        WHERE derivative_id = NEW.derivative_id ORDER BY sequence DESC LIMIT 1
    )
)
BEGIN
    SELECT RAISE(ABORT, 'evidence derivative event chain head does not match');
END;
