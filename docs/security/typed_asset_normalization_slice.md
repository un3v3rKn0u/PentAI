# Phase 1 typed asset normalization review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint now selects one of the manifest v2 asset
types: domain, wildcard domain, URL, IPv4, IPv6, or CIDR. It performs narrow local syntax
normalization, copies the explicit type and value into the pending draft, and includes
`include_apex` only for wildcard domains. Wildcard apex authority defaults to false and
must be deliberately selected.

The authenticated core remains authoritative for IDNA, percent encoding, URL/path
boundaries, strict IP and network canonicalization, CIDR host bits, matcher
contradictions, network IPv6 compatibility, policy compilation, and activation.

## Safety and failure states

Unknown types, wildcard syntax presented as an exact domain, ambiguous dotted-decimal
IPv4, credential-bearing or fragmented URLs, invalid IP literals, and out-of-range CIDR
prefixes deny draft construction. Switching type clears the current value so an earlier
domain cannot silently become a different matcher. URL user information is never
accepted as scope authority.

This slice constructs only one explicitly allowed reviewed asset and adds no discovery,
DNS lookup, network access, policy authority, grant, or execution capability.

## Compatibility and rollback

All six asset types and wildcard apex semantics already exist in manifest v2 and the
policy canonicalizers, so no contract or migration changes are required. Existing
single-domain drafts remain compatible. Rolling back this UI slice leaves persisted
source, manifest, and policy history unchanged.
