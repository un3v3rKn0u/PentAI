# Phase 1 signed gateway claim contract v2

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

The required execution-claim signature now has its own major contract version. The
historical unsigned v1 schema is restored unchanged, while the active authority and
transport produce and accept only signed v2 claims. The signature payload is explicitly
domain-separated as v2.

This preserves compatibility for historical v1 documents without allowing them through
the active launch boundary. A regression test validates both contracts independently and
proves that neither version is accepted by the other schema.

## Safety and compatibility

Unsigned or mislabeled claims fail schema validation before signature verification or an
OCI call. No database migration is required because the durable claim ledger stores claim
identity and lifecycle fields rather than the returned contract document. Rollback can
disable the fixture coordinator while retaining both schemas and immutable ledger history.

The change corrects contract versioning only. General gateway execution, public targets,
and verification inside the isolated probe remain disabled or deferred.
