CREATE TABLE network_attestations (
    attestation_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL,
    route_profile_id TEXT NOT NULL,
    source_ipv4 TEXT,
    source_ipv6 TEXT,
    resolver_mode TEXT NOT NULL CHECK (resolver_mode IN ('tunnel_resolver', 'approved_resolver')),
    resolver_id TEXT NOT NULL,
    observations_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('valid', 'invalidated')),
    invalidated_at TEXT
);

CREATE INDEX network_attestations_engagement_idx
ON network_attestations(engagement_id, observed_at DESC);

CREATE TABLE destination_authorizations (
    authorization_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES action_grants(grant_id),
    attestation_id TEXT NOT NULL REFERENCES network_attestations(attestation_id),
    candidate_url TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    decision_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER network_attestations_immutable
BEFORE UPDATE OF engagement_id, policy_bundle_id, policy_hash, route_profile_id,
    source_ipv4, source_ipv6, resolver_mode, resolver_id, observations_json,
    observed_at, expires_at
ON network_attestations
BEGIN
    SELECT RAISE(ABORT, 'network attestation identity is immutable');
END;

CREATE TRIGGER network_attestations_status_transition
BEFORE UPDATE OF status, invalidated_at ON network_attestations
WHEN OLD.status != 'valid' OR NEW.status != 'invalidated' OR NEW.invalidated_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'network attestation status transition is invalid');
END;

CREATE TRIGGER network_attestations_no_delete
BEFORE DELETE ON network_attestations
BEGIN
    SELECT RAISE(ABORT, 'network attestation cannot be deleted');
END;

CREATE TRIGGER destination_authorizations_immutable
BEFORE UPDATE ON destination_authorizations
BEGIN
    SELECT RAISE(ABORT, 'destination authorization is immutable');
END;

CREATE TRIGGER destination_authorizations_no_delete
BEFORE DELETE ON destination_authorizations
BEGIN
    SELECT RAISE(ABORT, 'destination authorization cannot be deleted');
END;
