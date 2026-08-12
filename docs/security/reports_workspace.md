# Supervised Reports workspace

The Reports workspace is a presentation layer over the authenticated local report
contracts. The operator must enter one assessment workflow and exact finding or
coverage UUIDs. Client-side parsing rejects empty, malformed, duplicate, or oversized
selections; the core remains authoritative and revalidates all policy, evidence,
coverage, finding, integrity, and lifecycle rules.

Draft review displays the immutable classification, policy identity, artifact sizes,
and shortened digests. Artifact bytes are not embedded into the DOM or fetched through
an unauthenticated link. Export-ready approval requires a non-empty human reason and an
explicit checkbox, then sends the exact `draft` status to the core approval boundary.

After approval, the desktop-only directory picker can select one existing local folder.
The operator chooses one of the four approved formats and explicitly acknowledges that
the output is restricted plaintext under local OS custody. The UI sends the exact
report kind, format, selected directory, and confirmation to the authenticated core,
then displays only the immutable filename, size, and shortened digest receipt.

The UI has no caller-controlled filename, artifact-body rendering, upload, submission,
email, or background-retry control. Browser development mode cannot supply a directory
without the desktop dialog capability. Errors display stable core codes without
reflecting report content or credentials.
