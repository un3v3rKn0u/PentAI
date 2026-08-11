CREATE TABLE gateway_fixture_execution_claims (
    claim_id TEXT PRIMARY KEY,
    start_id TEXT NOT NULL UNIQUE REFERENCES gateway_request_starts(start_id),
    runtime_id TEXT NOT NULL UNIQUE REFERENCES gateway_runtime_instances(runtime_id),
    containment_attestation_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('claimed', 'completed', 'abandoned')),
    claimed_at TEXT NOT NULL,
    finalized_at TEXT
);

CREATE TRIGGER gateway_fixture_execution_claims_identity_immutable
BEFORE UPDATE OF claim_id, start_id, runtime_id, containment_attestation_id, claimed_at
ON gateway_fixture_execution_claims
BEGIN
    SELECT RAISE(ABORT, 'gateway fixture execution claim identity is immutable');
END;

CREATE TRIGGER gateway_fixture_execution_claims_status_transition
BEFORE UPDATE OF status, finalized_at ON gateway_fixture_execution_claims
WHEN OLD.status != 'claimed'
    OR NEW.status NOT IN ('completed', 'abandoned')
    OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gateway fixture execution claim transition is invalid');
END;

CREATE TRIGGER gateway_fixture_execution_claims_no_delete
BEFORE DELETE ON gateway_fixture_execution_claims
BEGIN
    SELECT RAISE(ABORT, 'gateway fixture execution claim cannot be deleted');
END;
