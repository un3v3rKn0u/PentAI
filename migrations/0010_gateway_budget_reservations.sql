CREATE TABLE budget_accounts (
    engagement_id TEXT PRIMARY KEY REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    request_limit INTEGER NOT NULL CHECK (request_limit > 0),
    reserved_requests INTEGER NOT NULL DEFAULT 0 CHECK (reserved_requests >= 0),
    committed_requests INTEGER NOT NULL DEFAULT 0 CHECK (committed_requests >= 0),
    connection_limit INTEGER NOT NULL CHECK (connection_limit > 0),
    active_connections INTEGER NOT NULL DEFAULT 0 CHECK (active_connections >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES action_grants(grant_id),
    destination_authorization_id TEXT NOT NULL UNIQUE
        REFERENCES destination_authorizations(authorization_id),
    request_count INTEGER NOT NULL CHECK (request_count = 1),
    response_bytes_limit INTEGER NOT NULL CHECK (response_bytes_limit > 0),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'committed', 'released')),
    reserved_at TEXT NOT NULL,
    finalized_at TEXT
);

CREATE TABLE gateway_sessions (
    session_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL UNIQUE REFERENCES budget_reservations(reservation_id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES action_grants(grant_id),
    attestation_id TEXT NOT NULL REFERENCES network_attestations(attestation_id),
    destination_authorization_id TEXT NOT NULL UNIQUE
        REFERENCES destination_authorizations(authorization_id),
    status TEXT NOT NULL CHECK (status IN ('prepared', 'closed', 'aborted')),
    prepared_at TEXT NOT NULL,
    finalized_at TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER budget_reservations_identity_immutable
BEFORE UPDATE OF engagement_id, policy_bundle_id, grant_id,
    destination_authorization_id, request_count, response_bytes_limit, reserved_at
ON budget_reservations
BEGIN
    SELECT RAISE(ABORT, 'budget reservation identity is immutable');
END;

CREATE TRIGGER budget_reservations_no_delete
BEFORE DELETE ON budget_reservations
BEGIN
    SELECT RAISE(ABORT, 'budget reservation cannot be deleted');
END;

CREATE TRIGGER budget_reservations_status_transition
BEFORE UPDATE OF status, finalized_at ON budget_reservations
WHEN OLD.status != 'reserved'
    OR NEW.status NOT IN ('committed', 'released')
    OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'budget reservation status transition is invalid');
END;

CREATE TRIGGER gateway_sessions_identity_immutable
BEFORE UPDATE OF reservation_id, grant_id, attestation_id,
    destination_authorization_id, prepared_at, execution_enabled
ON gateway_sessions
BEGIN
    SELECT RAISE(ABORT, 'gateway session identity is immutable');
END;

CREATE TRIGGER gateway_sessions_no_delete
BEFORE DELETE ON gateway_sessions
BEGIN
    SELECT RAISE(ABORT, 'gateway session cannot be deleted');
END;

CREATE TRIGGER gateway_sessions_status_transition
BEFORE UPDATE OF status, finalized_at ON gateway_sessions
WHEN OLD.status != 'prepared'
    OR NEW.status NOT IN ('closed', 'aborted')
    OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gateway session status transition is invalid');
END;
