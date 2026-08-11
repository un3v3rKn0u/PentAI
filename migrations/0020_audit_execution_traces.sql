CREATE TRIGGER audit_events_immutable
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events cannot be deleted');
END;

CREATE TRIGGER audit_events_chain_guard
BEFORE INSERT ON audit_events
WHEN length(NEW.event_hash) != 64
    OR (
        (SELECT COUNT(*) FROM audit_events) = 0
        AND NEW.previous_hash IS NOT NULL
    )
    OR (
        (SELECT COUNT(*) FROM audit_events) > 0
        AND NEW.previous_hash IS NOT (
            SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'audit chain head does not match');
END;

CREATE TABLE execution_traces (
    trace_id TEXT PRIMARY KEY,
    result_id TEXT NOT NULL UNIQUE REFERENCES gateway_request_results(result_id),
    start_id TEXT NOT NULL UNIQUE REFERENCES gateway_request_starts(start_id),
    execution_claim_id TEXT NOT NULL UNIQUE
        REFERENCES gateway_fixture_execution_claims(claim_id),
    intent_id TEXT NOT NULL REFERENCES action_intents(intent_id),
    decision_id TEXT NOT NULL REFERENCES policy_evaluations(decision_id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    grant_id TEXT NOT NULL UNIQUE REFERENCES action_grants(grant_id),
    runtime_id TEXT NOT NULL UNIQUE REFERENCES gateway_runtime_instances(runtime_id),
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id),
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    created_at TEXT NOT NULL,
    external_target_enabled INTEGER NOT NULL CHECK (external_target_enabled = 0)
);

CREATE TRIGGER execution_traces_immutable
BEFORE UPDATE ON execution_traces
BEGIN
    SELECT RAISE(ABORT, 'execution traces are immutable');
END;

CREATE TRIGGER execution_traces_no_delete
BEFORE DELETE ON execution_traces
BEGIN
    SELECT RAISE(ABORT, 'execution traces cannot be deleted');
END;
