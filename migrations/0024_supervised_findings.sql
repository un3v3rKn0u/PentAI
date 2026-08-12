CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('candidate', 'scope_reviewed', 'duplicate_reviewed',
                  'validated', 'report_ready', 'closed', 'rejected')
    ),
    version INTEGER NOT NULL CHECK (version >= 1),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN ('informational', 'low', 'medium', 'high', 'critical')
    ),
    cvss_vector TEXT NOT NULL,
    cvss_score REAL NOT NULL CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    cwe TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    validation_status TEXT NOT NULL CHECK (
        validation_status IN ('unverified', 'confirmed', 'not_reproduced',
                              'false_positive', 'needs_retest')
    ),
    duplicate_status TEXT NOT NULL CHECK (
        duplicate_status IN ('pending', 'clear', 'duplicate')
    ),
    duplicate_of TEXT REFERENCES findings(finding_id),
    affected_asset_rule_ids_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    reproduction TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,
    references_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(workflow_id, idempotency_key),
    CHECK (
        (duplicate_status = 'duplicate' AND duplicate_of IS NOT NULL
         AND duplicate_of != finding_id)
        OR (duplicate_status != 'duplicate' AND duplicate_of IS NULL)
    )
);

CREATE INDEX findings_by_workflow_state
ON findings(workflow_id, state, updated_at, finding_id);

CREATE INDEX findings_by_fingerprint ON findings(engagement_id, fingerprint);

CREATE TABLE finding_versions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id TEXT NOT NULL UNIQUE,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    version INTEGER NOT NULL CHECK (version >= 1),
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    transition_reason TEXT NOT NULL,
    author_type TEXT NOT NULL CHECK (author_type = 'human'),
    author_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(finding_id, version)
);

CREATE INDEX finding_versions_by_finding
ON finding_versions(finding_id, version);

CREATE TRIGGER findings_identity_immutable
BEFORE UPDATE OF finding_id, workflow_id, engagement_id, policy_bundle_id,
    idempotency_key, created_by, created_at, fingerprint
ON findings
BEGIN
    SELECT RAISE(ABORT, 'finding identity is immutable');
END;

CREATE TRIGGER findings_transition_guard
BEFORE UPDATE ON findings
WHEN NEW.version != OLD.version + 1 OR NOT EXISTS (
    SELECT 1 FROM finding_versions v
    WHERE v.finding_id = NEW.finding_id AND v.version = NEW.version
      AND v.content_hash = NEW.content_hash AND v.document_json = NEW.document_json
) OR NOT (
    (OLD.state = 'candidate' AND NEW.state IN ('scope_reviewed', 'rejected'))
    OR (OLD.state = 'scope_reviewed' AND NEW.state IN ('duplicate_reviewed', 'rejected'))
    OR (OLD.state = 'duplicate_reviewed' AND NEW.state IN ('validated', 'rejected'))
    OR (OLD.state = 'validated' AND NEW.state IN ('report_ready', 'duplicate_reviewed'))
    OR (OLD.state = 'report_ready' AND NEW.state IN ('closed', 'validated'))
)
BEGIN
    SELECT RAISE(ABORT, 'finding transition is invalid');
END;

CREATE TRIGGER finding_versions_chain_guard
BEFORE INSERT ON finding_versions
WHEN (
    NOT EXISTS (SELECT 1 FROM finding_versions WHERE finding_id = NEW.finding_id)
    AND NEW.version != 1
) OR (
    EXISTS (SELECT 1 FROM finding_versions WHERE finding_id = NEW.finding_id)
    AND NEW.version != (
        SELECT MAX(version) + 1 FROM finding_versions WHERE finding_id = NEW.finding_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'finding version chain is invalid');
END;

CREATE TRIGGER findings_no_delete
BEFORE DELETE ON findings
BEGIN
    SELECT RAISE(ABORT, 'finding history cannot be deleted');
END;

CREATE TRIGGER finding_versions_immutable
BEFORE UPDATE ON finding_versions
BEGIN
    SELECT RAISE(ABORT, 'finding versions are immutable');
END;

CREATE TRIGGER finding_versions_no_delete
BEFORE DELETE ON finding_versions
BEGIN
    SELECT RAISE(ABORT, 'finding versions cannot be deleted');
END;
