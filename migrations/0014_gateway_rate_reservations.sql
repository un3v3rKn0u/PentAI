CREATE TABLE gateway_rate_buckets (
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    bucket_key TEXT NOT NULL,
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    refill_rate REAL NOT NULL CHECK (refill_rate > 0),
    capacity INTEGER NOT NULL CHECK (capacity > 0),
    tokens REAL NOT NULL CHECK (tokens >= 0 AND tokens <= capacity),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (engagement_id, bucket_key)
);

CREATE TABLE gateway_rate_reservations (
    reservation_id TEXT PRIMARY KEY REFERENCES budget_reservations(reservation_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    host_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'committed', 'released')),
    reserved_at TEXT NOT NULL,
    finalized_at TEXT
);

CREATE TRIGGER gateway_rate_buckets_identity_immutable
BEFORE UPDATE OF engagement_id, bucket_key ON gateway_rate_buckets
BEGIN
    SELECT RAISE(ABORT, 'gateway rate bucket identity is immutable');
END;

CREATE TRIGGER gateway_rate_buckets_no_delete
BEFORE DELETE ON gateway_rate_buckets
BEGIN
    SELECT RAISE(ABORT, 'gateway rate bucket cannot be deleted');
END;

CREATE TRIGGER gateway_rate_reservations_identity_immutable
BEFORE UPDATE OF reservation_id, engagement_id, policy_bundle_id, host_key, reserved_at
ON gateway_rate_reservations
BEGIN
    SELECT RAISE(ABORT, 'gateway rate reservation identity is immutable');
END;

CREATE TRIGGER gateway_rate_reservations_status_transition
BEFORE UPDATE OF status, finalized_at ON gateway_rate_reservations
WHEN OLD.status != 'reserved'
    OR NEW.status NOT IN ('committed', 'released')
    OR NEW.finalized_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gateway rate reservation status transition is invalid');
END;

CREATE TRIGGER gateway_rate_reservations_no_delete
BEFORE DELETE ON gateway_rate_reservations
BEGIN
    SELECT RAISE(ABORT, 'gateway rate reservation cannot be deleted');
END;
