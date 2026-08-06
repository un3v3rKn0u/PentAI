CREATE TABLE programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT,
    program_url TEXT,
    status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'archived')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE source_documents (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id),
    authority TEXT NOT NULL,
    reference TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    effective_at TEXT,
    content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
    encrypted_blob_ref TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE engagements (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id),
    status TEXT NOT NULL CHECK (
        status IN ('draft', 'approved', 'active', 'paused', 'expired', 'revoked')
    ),
    effective_from TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    timezone TEXT NOT NULL,
    active_policy_id TEXT,
    revocation_epoch INTEGER NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE manifest_versions (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    schema_version TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    supersedes_id TEXT REFERENCES manifest_versions(id)
);

CREATE TABLE policy_bundles (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    manifest_version_id TEXT NOT NULL REFERENCES manifest_versions(id),
    schema_version TEXT NOT NULL,
    compiler_version TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    signature TEXT,
    signer_key_id TEXT,
    activated_at TEXT,
    revoked_at TEXT
);

CREATE UNIQUE INDEX one_active_policy_per_engagement
ON policy_bundles(engagement_id)
WHERE activated_at IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    signature TEXT
);

CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TEXT
);
