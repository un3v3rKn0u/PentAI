# ADR 0002: Source encryption and key custody

**Status:** Proposed; implementation complete locally, cross-platform review pending

## Context

Phase 1 must retain authoritative source originals without storing their plaintext or
encryption key in SQLite, repository files, logs, command arguments, or application
configuration. Loss, ambiguity, or corruption of the key must disable source import
rather than silently fall back to plaintext.

## Decision

- The Tauri desktop owns a random 256-bit source master key stored under the fixed OS
  credential-service identity `local.pentai.desktop/source-encryption-key-v1`.
- macOS Keychain, Windows Credential Manager, and Linux Secret Service are accessed
  through the pinned Rust `keyring` dependency. Failure or ambiguous lookup aborts
  desktop startup; only a definite missing-entry result permits key creation.
- The key is delivered to the owned core child through a one-use stdin pipe. It is not
  placed in command arguments, environment variables, the database, or a file. The
  desktop zeroizes its encoded copy after delivery.
- The core accepts a 32-byte base64url key and uses AES-256-GCM with a fresh 96-bit
  nonce for each object. The plaintext SHA-256 digest is authenticated as associated
  data and determines the content-addressed blob path.
- Blob writes use a same-directory exclusive temporary file, file synchronization,
  atomic rename, and directory synchronization. Database provenance is committed only
  after a complete authenticated blob exists.
- Stored blobs are authenticated and rehashed on read. Missing, malformed, tampered,
  wrong-key, and digest-mismatched blobs fail closed.

## Compatibility and recovery

Migration `0005_encrypted_source_blobs.sql` retains existing source rows as
`legacy_missing`; it never claims that Phase 0 content-addressed placeholders are
encrypted objects. New rows must declare `available`, `aes-256-gcm-v1`, and their
plaintext size.

Application rollback can ignore the additive columns and encrypted object directory.
The master key must be included in platform credential-store migration and backup
procedures; copying blobs and SQLite without the credential does not make originals
recoverable. Key rotation and backup/export are deferred and block production release.

## Consequences and verification boundary

This design adds native credential-service and cryptographic dependencies. Local
macOS compilation and core cryptographic tests do not prove Windows Credential Manager
or Linux Secret Service behavior. Packaged lifecycle tests on all three operating
systems and a manual locked/unavailable credential-store test are required before the
control is approved cross-platform.
