# Phase 1 fixture cleanup OCI inspection binding

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Cleanup recovery now inspects the complete OCI container object after exact-name discovery.
Before deletion it requires a canonical 64-character container ID, the exact claim-derived
name, the pinned image digest as the actual runtime image, exactly one attachment to the
durable managed network, and the complete ownership/runtime label set.

Removal targets the verified immutable container ID rather than the discoverable name.
Recovery then repeats exact-name discovery and must prove absence before continuing.

## Safety and compatibility

Unexpected images, extra or missing networks, malformed IDs, name aliases, missing object
structure, and label mismatch pause global safety without deletion. Docker's leading slash
and Podman's plain canonical name forms are both accepted; no other alias is allowed.

This is still an owned TEST-NET proof and trusts the configured OCI inspection boundary.
General transports require independently trustworthy runtime measurement before activation.

The follow-on cleanup audit slice now records hash-chained evidence only after verified
removal or verified prior absence, before authorization later abandons the claim.
