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

The UI has no download, destination, upload, submission, or background-retry control.
Errors display stable core codes without reflecting report content or credentials.
