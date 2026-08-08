ALTER TABLE source_documents ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'pasted_text';
ALTER TABLE source_documents ADD COLUMN media_type TEXT NOT NULL DEFAULT 'text/plain';
ALTER TABLE source_documents ADD COLUMN source_version TEXT;

CREATE INDEX source_documents_identity
ON source_documents(program_id, authority, reference, content_hash);

CREATE TRIGGER validate_source_document_insert
BEFORE INSERT ON source_documents
WHEN NEW.authority NOT IN (
        'contract', 'program_staff', 'program_page', 'platform_rule', 'internal_note'
    )
    OR NEW.source_kind NOT IN ('pasted_text', 'file', 'url')
    OR length(trim(NEW.reference)) = 0
    OR length(trim(NEW.media_type)) = 0
BEGIN
    SELECT RAISE(ABORT, 'invalid source provenance');
END;

CREATE TRIGGER immutable_source_document_update
BEFORE UPDATE ON source_documents
BEGIN
    SELECT RAISE(ABORT, 'source documents are immutable');
END;

CREATE TRIGGER immutable_source_document_delete
BEFORE DELETE ON source_documents
BEGIN
    SELECT RAISE(ABORT, 'source documents are immutable');
END;
