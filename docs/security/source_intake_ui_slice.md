# Phase 1 supervised source-intake UI

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

After an operator explicitly selects a Program, the dedicated Intake workspace offers
three explicit source modes:
pasted text, a native webview file chooser, and guarded URL acquisition. It displays
immutable source history and SHA-256 provenance, then uses the selected source to create
a provenance-linked manifest draft. No import starts automatically or retries in the
background.

Every import mode also accepts an optional effective timestamp and bounded source-version
label. History displays authority, retrieval time, effective time, reference, and digest,
and requires an explicit exact-source selection before that source becomes the reviewed
manifest input. Changing the reviewed source clears derived manifest and policy state.

## Safety and failure states

The file chooser accepts only the approved extensions. The UI checks the selected
`File.size`, reads browser-mediated bytes without obtaining a filesystem path, checks
the resulting byte length again, derives the claimed media type from the basename, and
sends base64 bytes to the bounded core API. The core remains the authority for every
filename, size, media, encoding, structure, encryption, and persistence decision.

URL acquisition begins only after the operator selects URL mode and submits the form;
all DNS, pinning, redirect, TLS, response, and media enforcement remains in the core.
The UI distinguishes empty, loading, denied, degraded, error, and recovered/ready
states. Refresh is an explicit recovery action. An intake request is atomic, so a pause
state is not applicable; there is no queue or background worker to pause.

Input preparation is isolated from authenticated submission. It preserves the selected
authority and exact text or URL, while file preparation returns only the basename,
derived allowlisted media type, and bounded base64 bytes. The selected immutable program
identity is added only by the application boundary immediately before the core request.

## Compatibility and rollback

This is an additive UI over versioned `/api/v1` endpoints and needs no migration. It can
be rolled back without altering imported source rows or encrypted blobs. The existing
manifest, approval, policy simulation, and audit workflow remains available. This slice
does not add ActionGrants, assessment networking, rendering, crawling, or autonomous
testing.
