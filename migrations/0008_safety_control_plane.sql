CREATE TABLE safety_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    global_status TEXT NOT NULL CHECK (global_status IN ('active', 'paused', 'stopped')),
    reason TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

INSERT INTO safety_state(
    singleton_id, global_status, reason, generation, updated_at, updated_by
) VALUES (1, 'active', 'initial local state', 0, CURRENT_TIMESTAMP, 'migration');

CREATE TRIGGER safety_state_no_delete
BEFORE DELETE ON safety_state
BEGIN
    SELECT RAISE(ABORT, 'safety state cannot be deleted');
END;
