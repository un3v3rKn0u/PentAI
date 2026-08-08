ALTER TABLE source_documents ADD COLUMN blob_status TEXT NOT NULL DEFAULT 'legacy_missing';
ALTER TABLE source_documents ADD COLUMN encryption_version TEXT;
ALTER TABLE source_documents ADD COLUMN plaintext_size INTEGER;

CREATE TRIGGER validate_encrypted_source_blob_insert
BEFORE INSERT ON source_documents
WHEN NEW.blob_status != 'available'
    OR NEW.encryption_version != 'aes-256-gcm-v1'
    OR NEW.plaintext_size IS NULL
    OR NEW.plaintext_size < 1
    OR NEW.encrypted_blob_ref NOT LIKE 'encrypted-source:v1:%'
BEGIN
    SELECT RAISE(ABORT, 'encrypted source blob metadata is invalid');
END;
