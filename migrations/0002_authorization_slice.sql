CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    approval_type TEXT NOT NULL CHECK (approval_type = 'policy_activation'),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    manifest_version_id TEXT NOT NULL REFERENCES manifest_versions(id),
    manifest_hash TEXT NOT NULL CHECK (length(manifest_hash) = 64),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    approver_actor_id TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    signature_json TEXT NOT NULL
);

ALTER TABLE manifest_versions ADD COLUMN validation_status TEXT NOT NULL DEFAULT 'draft'
    CHECK (validation_status IN ('draft', 'invalid', 'valid', 'superseded'));
ALTER TABLE manifest_versions ADD COLUMN validation_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE policy_bundles ADD COLUMN status TEXT NOT NULL DEFAULT 'awaiting_approval'
    CHECK (status IN ('awaiting_approval', 'active', 'rejected', 'revoked', 'expired'));

CREATE UNIQUE INDEX one_approval_per_policy_hash
ON approvals(policy_hash)
WHERE decision = 'approved' AND revoked_at IS NULL;

CREATE TRIGGER immutable_active_manifest
BEFORE UPDATE OF document_json, content_hash ON manifest_versions
WHEN EXISTS (
    SELECT 1 FROM policy_bundles
    WHERE policy_bundles.manifest_version_id = OLD.id
      AND policy_bundles.activated_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'active manifest versions are immutable');
END;

CREATE TRIGGER immutable_active_policy
BEFORE UPDATE OF policy_json, content_hash, manifest_version_id ON policy_bundles
WHEN OLD.activated_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'active policy bundles are immutable');
END;
