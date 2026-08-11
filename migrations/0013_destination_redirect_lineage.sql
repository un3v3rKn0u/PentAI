ALTER TABLE destination_authorizations
ADD COLUMN parent_authorization_id TEXT
    REFERENCES destination_authorizations(authorization_id);

ALTER TABLE destination_authorizations
ADD COLUMN redirect_count INTEGER NOT NULL DEFAULT 0
    CHECK (redirect_count BETWEEN 0 AND 10);

CREATE UNIQUE INDEX destination_authorizations_one_child
ON destination_authorizations(parent_authorization_id)
WHERE parent_authorization_id IS NOT NULL;

CREATE INDEX destination_authorizations_lineage
ON destination_authorizations(grant_id, redirect_count, created_at);
