# Phase 1 supervised Network Profiles workspace

**Status:** Implemented; sole-maintainer security review recorded

The Network Profiles workspace presents the existing authenticated profile lifecycle as
an explicit supervised boundary. Local route discovery creates only a short-lived,
non-authoritative proposal. Activation requires confirmation of the displayed route and
resolver plus at least one registered public IPv4 address. Resolver modes are allowlisted
and the core remains authoritative for address validation, proposal freshness, uniqueness,
and persistence.

Active profiles display their immutable identity and confirmed settings. Revocation is
bound to the exact profile and requires a non-empty, bounded reason. Multiple active
profiles are shown as ambiguous and blocked. Every state states that configuration is not
network attestation or execution authority.

This slice changes no schema, migration, policy semantics, network adapter, observer,
socket, gateway, or execution behavior. Rollback restores the inline presentation while
leaving durable profile records unchanged.
