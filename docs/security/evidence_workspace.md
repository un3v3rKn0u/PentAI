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
HTML.

Retention deletion is isolated in a collapsed warning control. The operator chooses the
displayed original or current redaction and must review its exact UUID and full SHA-256,
provide a bounded reason, and explicitly confirm permanent encrypted-content deletion.
The UI cannot supply or shorten a retention deadline. The core verifies the digest and
policy deadline, protects shared blobs, preserves custody metadata and audit history, and
recovers interrupted deletion work. The result reports the encrypted-blob disposition
and never claims forensic secure erase.

Binary originals, original-content preview, download, model routing, execution authority,
and external submission are absent from this workspace slice.
