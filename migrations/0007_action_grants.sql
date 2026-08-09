CREATE TABLE action_intents (
    intent_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    idempotency_key TEXT NOT NULL,
    intent_hash TEXT NOT NULL UNIQUE CHECK (length(intent_hash) = 64),
    intent_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(engagement_id, idempotency_key)
);

CREATE TABLE action_grants (
    grant_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL UNIQUE REFERENCES action_intents(intent_id),
    decision_id TEXT NOT NULL UNIQUE REFERENCES policy_evaluations(decision_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
    audience TEXT NOT NULL,
    grant_json TEXT NOT NULL,
    grant_hash TEXT NOT NULL UNIQUE CHECK (length(grant_hash) = 64),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX action_grants_current
ON action_grants(engagement_id, policy_hash, revocation_epoch, expires_at, used_at, revoked_at);

CREATE TRIGGER immutable_action_intent_update
BEFORE UPDATE ON action_intents
BEGIN
    SELECT RAISE(ABORT, 'action intents are immutable');
END;

CREATE TRIGGER immutable_action_intent_delete
BEFORE DELETE ON action_intents
BEGIN
    SELECT RAISE(ABORT, 'action intents are immutable');
END;

CREATE TRIGGER immutable_policy_evaluation_update
BEFORE UPDATE ON policy_evaluations
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER immutable_policy_evaluation_delete
BEFORE DELETE ON policy_evaluations
BEGIN
    SELECT RAISE(ABORT, 'policy decisions are immutable');
END;

CREATE TRIGGER immutable_action_grant_authority
BEFORE UPDATE OF
    grant_id, intent_id, decision_id, engagement_id, policy_bundle_id,
    policy_hash, revocation_epoch, audience, grant_json, grant_hash,
    issued_at, expires_at
ON action_grants
BEGIN
    SELECT RAISE(ABORT, 'action grant authority is immutable');
END;

CREATE TRIGGER immutable_action_grant_delete
BEFORE DELETE ON action_grants
BEGIN
    SELECT RAISE(ABORT, 'action grants are immutable');
END;
