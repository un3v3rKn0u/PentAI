# Phase 1 bounded file-source import

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The authenticated local API accepts a bounded base64 file payload and provenance
metadata, validates it without opening a caller-supplied filesystem path, and persists
the original through the authenticated encrypted source store. Successful imports use
`source_kind=file`, an immutable `file:<filename>` reference, a SHA-256 content hash,
and the existing hash-chained `source.imported` audit event.

## Accepted files

The maximum decoded payload is 2 MiB. Accepted media type and extension pairs are:

- `text/plain`: `.txt`
- `text/markdown`: `.md`, `.markdown`
- `text/html`: `.htm`, `.html`
- `application/json`: `.json`
- `application/pdf`: `.pdf`

Text, Markdown, HTML, and JSON must be UTF-8 and contain no NUL bytes. JSON must parse.
PDF input must begin with the PDF signature. These checks establish a conservative
storage boundary; they do not claim that a document is safe to render or parse.

## Failure behavior

Imports fail closed for invalid base64, empty or oversized content, path-bearing or
invalid filenames, unknown/mismatched media types, binary text, malformed UTF-8/JSON,
invalid PDF signatures, missing Programs, unavailable encryption, or blob-integrity
failure. Rejected content is not recorded as an imported source.

The core never receives or opens a local path, so symlink, device, directory, and
path-replacement risks are excluded from this boundary. A future Tauri file-picker
command must read the explicitly selected regular file with its own bounded and
race-resistant checks before sending bytes to this endpoint.

Preview, active-content rendering, document extraction, URL acquisition, and
target-facing networking remain unavailable.
