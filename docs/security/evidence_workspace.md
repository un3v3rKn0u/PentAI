# Supervised Evidence workspace

The Evidence workspace is a presentation layer over authenticated evidence-original,
redaction, and preview contracts. An operator captures a bounded note or local file for
one exact workflow, with an optional exact execution-trace UUID. The browser reads at
most 2 MiB of selected bytes and sends base64 content to the loopback core; it never
sends a local filesystem path. The core remains authoritative for workflow/policy
linkage, trace identity, media type, classification, encryption, custody, and storage.

Original content is never returned or rendered. Metadata lookup displays only kind,
classification, size, policy identity, and a shortened digest. For supported text media,
the operator supplies explicit Unicode-codepoint ranges and reasons and confirms the
derivative classification. The server derives the redacted bytes from the authenticated
original; the UI cannot upload or claim derivative content.

Preview is available only by derivative UUID. Before display, the UI requires the core
response to assert `plain_text`, `text/plain`, and `active_content_disabled: true`.
React renders the returned string inside a text node in `pre`; it is never assigned as
HTML. Binary originals, original-content preview, deletion, download, model routing,
execution authority, and external submission are absent from this workspace slice.
