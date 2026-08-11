CREATE TABLE gateway_request_starts (
    start_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE REFERENCES gateway_sessions(session_id),
    reservation_id TEXT NOT NULL UNIQUE REFERENCES budget_reservations(reservation_id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES action_grants(grant_id),
    committed_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('committed', 'cancelled')),
    finalized_at TEXT,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER gateway_request_starts_identity_immutable
BEFORE UPDATE OF start_id, session_id, reservation_id, grant_id,
    committed_at, deadline_at, execution_enabled
ON gateway_request_starts
BEGIN
    SELECT RAISE(ABORT, 'gateway request start identity is immutable');
END;

CREATE TRIGGER gateway_request_starts_status_transition
BEFORE UPDATE OF status, finalized_at ON gateway_request_starts
WHEN OLD.status != 'committed'
    OR NEW.status != 'cancelled'
    OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gateway request start status transition is invalid');
END;

CREATE TRIGGER gateway_request_starts_no_delete
BEFORE DELETE ON gateway_request_starts
BEGIN
    SELECT RAISE(ABORT, 'gateway request start cannot be deleted');
END;
