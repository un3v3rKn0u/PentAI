CREATE TABLE network_profile_proposals (
    proposal_id TEXT PRIMARY KEY,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    route_profile_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'expired')),
    created_at TEXT NOT NULL
);

CREATE TABLE network_profiles (
    profile_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE REFERENCES network_profile_proposals(proposal_id),
    route_profile_id TEXT NOT NULL,
    route_interface TEXT NOT NULL,
    route_gateway TEXT,
    resolver_mode TEXT NOT NULL CHECK (resolver_mode IN ('tunnel_resolver', 'approved_resolver')),
    resolver_id TEXT NOT NULL,
    resolver_addresses_json TEXT NOT NULL,
    registered_source_ipv4_json TEXT NOT NULL,
    registered_source_ipv6_json TEXT NOT NULL,
    ipv6_mode TEXT NOT NULL CHECK (ipv6_mode IN ('disabled', 'approved_only')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    confirmed_by TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    CHECK (
        (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE UNIQUE INDEX one_active_network_profile
ON network_profiles((1)) WHERE status = 'active';

CREATE TRIGGER network_profile_proposals_identity_immutable
BEFORE UPDATE OF document_json, content_hash, route_profile_id, observed_at, expires_at, created_at
ON network_profile_proposals
BEGIN
    SELECT RAISE(ABORT, 'network profile proposal identity is immutable');
END;

CREATE TRIGGER network_profile_proposals_status_transition
BEFORE UPDATE OF status ON network_profile_proposals
WHEN OLD.status != NEW.status AND NOT (
    OLD.status = 'pending' AND NEW.status IN ('confirmed', 'expired')
)
BEGIN
    SELECT RAISE(ABORT, 'network profile proposal status transition is invalid');
END;

CREATE TRIGGER network_profiles_identity_immutable
BEFORE UPDATE OF proposal_id, route_profile_id, route_interface, route_gateway,
    resolver_mode, resolver_id, resolver_addresses_json, registered_source_ipv4_json,
    registered_source_ipv6_json, ipv6_mode, confirmed_by, confirmed_at, execution_enabled
ON network_profiles
BEGIN
    SELECT RAISE(ABORT, 'network profile identity is immutable');
END;

CREATE TRIGGER network_profiles_status_transition
BEFORE UPDATE OF status, revoked_at, revocation_reason ON network_profiles
WHEN OLD.status != 'active' OR NEW.status != 'revoked'
    OR NEW.revoked_at IS NULL OR NEW.revocation_reason IS NULL
BEGIN
    SELECT RAISE(ABORT, 'network profile status transition is invalid');
END;

CREATE TRIGGER network_profile_proposals_no_delete
BEFORE DELETE ON network_profile_proposals
BEGIN
    SELECT RAISE(ABORT, 'network profile proposal history cannot be deleted');
END;

CREATE TRIGGER network_profiles_no_delete
BEFORE DELETE ON network_profiles
BEGIN
    SELECT RAISE(ABORT, 'network profile history cannot be deleted');
END;
