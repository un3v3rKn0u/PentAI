# Supervised Findings workspace

The Findings workspace is a presentation layer over the authenticated `finding-v1`
contract. An operator loads findings for one exact assessment workflow or creates a
candidate using explicit policy asset-rule and available evidence UUIDs. Client-side
parsing rejects empty, malformed, duplicate, or oversized UUID selections; the core
remains authoritative for workflow state, policy scope, evidence custody, CVSS score
and severity, CWE, content bounds, and idempotency.

The workspace lists only core-returned finding documents and exposes next states from
the contract lifecycle. Every transition submits the currently displayed immutable
version, a non-empty human reason, and explicit duplicate and validation outcomes.
Stale versions and skipped reviews remain default-denied by the core. Duplicate identity
is sent only when the operator explicitly selects a duplicate outcome.

The UI does not calculate or silently correct CVSS, propose duplicates, create evidence,
approve report export, issue execution authority, or submit a finding externally. It
displays stable core error codes without reflecting evidence or report content.
