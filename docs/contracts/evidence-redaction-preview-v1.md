# Evidence redaction and inactive preview v1

## Outcome and safety boundary

`EvidenceRedaction` is an immutable encrypted derivative of one immutable original.
The core loads and authenticates the source, accepts only ordered non-overlapping
Unicode-codepoint ranges, and replaces every selected range with the fixed literal
`[REDACTED]`. The caller cannot upload derivative bytes or claim unrelated provenance.

Only UTF-8 `text/*`, JSON, XML, and XHTML originals are supported. Binary formats,
invalid UTF-8, out-of-range or overlapping spans, unknown reasons, unsafe control
characters, unchanged output, and ambiguous idempotent replay fail closed. A derivative
may be classified `public` or `internal` only after an explicit human confirmation;
the confirmer and time are immutable provenance. Originals retain their immutable
`internal` or `restricted` classification.

## Preview behavior

The authenticated preview route accepts only a derivative identifier. Original IDs
and unknown IDs are denied. It authenticates and rehashes the encrypted derivative,
returns at most 65,536 Unicode characters inside an `application/json` response, and
fixes `render_mode` to `plain_text`, `media_type` to `text/plain`, and
`active_content_disabled` to true. HTML, XML, JSON, scripts, links, images, and other
active input are never rendered or interpreted by the core.

Consumers must render the returned string as text, never as HTML. A future Evidence UI
must preserve this rule and add a sandbox boundary before the project claims general
file or image preview support.

Every source read, derivative store, and preview is custody- and audit-linked without
including content. Database triggers prohibit mutation/deletion and enforce a
per-derivative event-chain head.

## Compatibility, rollback, and deferrals

Migration `0022_evidence_redaction_previews.sql` is additive. Existing originals and
consumers remain valid. Older binaries may ignore derivative tables and encrypted
blobs. Rollback requires a verified pre-migration backup rather than deletion of
immutable history.

Retention configuration and manual secure deletion remain deferred because deletion
requires separate authorization, backup, crash-recovery, shared-blob reference, and
failure tests. PDF/image parsing, original previews, annotations, exports, model
routing, findings, reports, and UI rendering are also outside this slice.
