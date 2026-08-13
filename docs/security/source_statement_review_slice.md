# Phase 1 source-statement review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Supervised Intake now records bounded exact source statements and separate restrictive
candidate interpretations. Every statement cites one selected immutable source ID and
content hash and one authorization-bearing manifest field category. The pending manifest
preserves these records as `candidate` data for later review.

## Safety and compatibility

Empty statement sets, unknown sources, stale hashes, unsupported field paths, duplicate
statements, and text over 500 characters fail closed. The core independently checks each
statement's source identity and digest against the manifest source set. Existing manifests
may omit the optional statement list.

Statements never populate manifest fields, compile into Policy IR rules, resolve source
conflicts, approve a manifest, activate policy, issue a grant, access encrypted originals,
or create a network effect. The operator must separately complete every structured review,
and the core remains authoritative for provenance, validation, compilation, and activation.

This first slice is deterministic and operator-confirmed. Future AI-assisted extraction
may propose the same candidate structure only after model-data classification and sandbox
boundaries exist; it must not receive additional authority.
