# Phase 1 account-use review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Supervised Intake now distinguishes unauthenticated-only work from explicitly approved
test-account references. References are bounded identifiers, not usernames, passwords,
tokens, cookies, or other credential material. Shared accounts are denied and credential
handling is fixed to an external secret-store boundary.

The reviewed constraint carries from manifest provenance into signed Policy IR. The
deterministic evaluator denies an account reference in unauthenticated mode and denies a
missing or unlisted reference when approved-test-account mode is selected.

## Safety and compatibility

Blank test-account lists, references with credential-like punctuation, and references
that conflict with unauthenticated mode fail closed. Existing manifests and policies may
omit the optional constraint for compatibility; every new supervised Intake draft
records it explicitly.

This slice stores no secrets, reads no credential store, performs no login, and enables
no request, grant, or network effect. Resolving identifiers to secrets and safely
injecting credentials remain separate execution boundaries. Rollback affects reviewed
draft construction and newly compiled policy constraints only.
