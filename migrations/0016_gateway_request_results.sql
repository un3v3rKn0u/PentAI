CREATE TABLE gateway_request_results (
    result_id TEXT PRIMARY KEY,
    start_id TEXT NOT NULL UNIQUE REFERENCES gateway_request_starts(start_id),
    session_id TEXT NOT NULL UNIQUE REFERENCES gateway_sessions(session_id),
    reservation_id TEXT NOT NULL UNIQUE REFERENCES budget_reservations(reservation_id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES action_grants(grant_id),
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'completed', 'deadline_exceeded', 'response_limit_exceeded',
            'transport_error'
        )
    ),
    observed_response_bytes INTEGER NOT NULL CHECK (observed_response_bytes >= 0),
    retained_response_bytes INTEGER NOT NULL CHECK (
        retained_response_bytes >= 0
        AND retained_response_bytes <= observed_response_bytes
    ),
    deadline_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER gateway_request_results_immutable
BEFORE UPDATE ON gateway_request_results
BEGIN
    SELECT RAISE(ABORT, 'gateway request result is immutable');
END;

CREATE TRIGGER gateway_request_results_no_delete
BEFORE DELETE ON gateway_request_results
BEGIN
    SELECT RAISE(ABORT, 'gateway request result cannot be deleted');
END;
