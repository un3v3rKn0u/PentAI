CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    approval_type TEXT NOT NULL CHECK (approval_type = 'policy_activation'),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    manifest_version_id TEXT NOT NULL REFERENCES manifest_versions(id),
    manifest_hash TEXT NOT NULL CHECK (length(manifest_hash) = 64),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    approver_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    invalidated_at TEXT,
    document_json TEXT NOT NULL
);

CREATE INDEX approvals_exact_policy
ON approvals(policy_bundle_id, manifest_hash, policy_hash, decision);

CREATE TABLE policy_evaluations (
    decision_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    intent_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER immutable_active_policy_update
BEFORE UPDATE OF policy_json, content_hash, manifest_version_id, schema_version, compiler_version
ON policy_bundles
WHEN OLD.activated_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'activated policy bundles are immutable');
END;

CREATE TRIGGER immutable_active_policy_delete
BEFORE DELETE ON policy_bundles
WHEN OLD.activated_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'activated policy bundles are immutable');
END;

CREATE TRIGGER immutable_approved_manifest_update
BEFORE UPDATE OF document_json, content_hash, engagement_id, schema_version
ON manifest_versions
WHEN EXISTS (
    SELECT 1 FROM approvals
    WHERE approvals.manifest_version_id = OLD.id
      AND approvals.decision = 'approved'
      AND approvals.invalidated_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'approved manifest versions are immutable');
END;

CREATE TRIGGER immutable_approved_manifest_delete
BEFORE DELETE ON manifest_versions
WHEN EXISTS (
    SELECT 1 FROM approvals
    WHERE approvals.manifest_version_id = OLD.id
      AND approvals.decision = 'approved'
)
BEGIN
    SELECT RAISE(ABORT, 'approved manifest versions are immutable');
END;
