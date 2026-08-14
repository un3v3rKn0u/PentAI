# Phase 1 gateway execution claim integrity

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Every gateway fixture execution claim is now signed by the core authority over a
domain-separated canonical representation of every claim field. The fixture transport
requires both schema validity and successful authority verification before reading claim
bounds or invoking the OCI runtime.

Mutation of the response ceiling or any other signed field after issuance therefore fails
closed with no runtime command. Missing signing configuration also prevents claim issuance.
The private key remains encapsulated by the authority, while producer, verifier, and tests
share one canonical payload function to prevent serialization drift.

## Safety and compatibility

The claim remains single-use and bound to the durable request start and finalization path.
The schema change is fail-closed because unsigned fixture claims were never a public or
production contract. The hosted owned-fixture harness supplies the authority verifier
directly to the transport. General gateway execution and external targets remain disabled.
