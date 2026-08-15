# Phase 1 public-only gateway claim verification

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Fixture transport launch no longer calls back into the authorization service that owns the
private Ed25519 signing key. The authority exports a dedicated verification object containing
only the corresponding public key, and the transport validates the signed v2 claim locally
before deriving bounds or invoking OCI.

The signer retains its established verification API for existing internal consumers, but
the execution boundary receives no signing method or private key. Tests prove the exported
verifier validates the trusted key, cannot sign, rejects another key, rejects tampering, and
prevents any runtime call on failure.

## Safety and compatibility

The signed v2 claim schema and persisted claim ledger are unchanged, so no contract version
or database migration is required. Missing signing configuration prevents the authority from
exporting verification material. Rollback disables the fixture coordinator and retains the
signed claim and ledger history.

This is still host-side verification for the owned TEST-NET fixture. Independent verification
inside the isolated probe, key rotation, general gateway authority, and external targets remain
deferred.
