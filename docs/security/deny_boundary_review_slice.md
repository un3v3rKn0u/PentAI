# Phase 1 explicit deny-boundary review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint can add one optional typed out-of-scope
boundary alongside the reviewed allow asset. The boundary supports the existing domain,
wildcard-domain, URL, IPv4, IPv6, and CIDR types and retains explicit wildcard-apex
semantics. It is emitted as an independent `effect: deny` manifest row with exact source
provenance and no allow-only ports, paths, or ownership claim.

This makes a principal excluded boundary visible in the normalized draft rather than
relying only on global discovered-asset and third-party defaults. The authenticated core
remains authoritative for canonical matcher overlap, deny precedence, contradictions,
policy compilation, and activation.

## Safety and failure states

Selecting a deny boundary requires both a recognized type and a non-empty valid value.
Partial input denies draft construction. An exact type-and-canonical-value duplicate of
the allow rule is rejected locally instead of producing contradictory authority. Changing
the deny type clears its previous value, and wildcard apex denial remains explicit.

This slice supports one deny row only. It adds no discovery, scope expansion, policy
authority, network access, grant, or execution capability.

## Compatibility and rollback

Manifest v2 already supports multiple allow/deny assets and the selected typed matchers,
so no schema or migration change is required. Drafts without an explicit deny boundary
remain unchanged. Rolling back this UI slice leaves source, manifest, and policy history
intact.
