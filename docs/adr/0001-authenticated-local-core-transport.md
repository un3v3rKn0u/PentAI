# ADR 0001: Authenticated desktop-to-core transport

- **Status:** Accepted for Phase 0 implementation
- **Date:** 2026-08-07
- **Owners:** Desktop and Core maintainers
- **Engineering acceptance:** Implemented and merged in PR #15
- **Security Lead approval:** `un3v3rKn0u`, 2026-08-08
- **Independent security approval:** Pending before Phase 0 exit

## Context

PentAI's FastAPI core can approve and activate authorization policy. A loopback bind is
not an authentication boundary: other local processes and browser content can reach a
loopback listener. The desktop must therefore own the core process and establish a
fresh authenticated channel for every launch.

## Decision

The packaged Tauri application owns exactly one core child process.

1. Tauri obtains 32 bytes from the operating system CSPRNG and encodes them as an
   unpadded base64url launch credential. The credential is never durable.
2. Tauri reserves a dynamic IPv4 loopback port, starts the core with the selected host,
   port, database path, environment, and credential in the child environment, then
   performs an authenticated readiness request with a 12-second bound.
3. A startup error, early child exit, port collision, migration failure, or failed
   authenticated readiness prevents the workbench from becoming usable.
4. Tauri provides the API base URL and credential to its own webview through the
   `core_bootstrap` command. They are kept only in UI memory. Production has no
   hard-coded port or credential fallback.
5. Every functional `/api/v1/*` request, including health, readiness, safety state, and
   reads, requires `Authorization: Bearer <credential>`. Validation uses a
   constant-time comparison and failures use one uniform response.
6. Preflight `OPTIONS` requests may be answered without the credential but expose no
   application data or mutation. Production CORS origins are limited to Tauri origins;
   Vite origins are added only in development.
7. The authenticated session is represented by the server-side
   `local-desktop-session` principal. Approval and activation do not accept an actor ID
   as authority from request content.
8. On normal desktop exit Tauri terminates and reaps its owned core. The operating
   system also closes the inherited process environment when the child exits.

## Packaging

Development launches the core with the repository `.venv` interpreter and an explicit
module path. Each native build first freezes the core into a target-triple-suffixed
`pentai-core` executable. Tauri's `externalBin` packaging places that executable beside
the desktop executable. The build embeds the sidecar SHA-256 digest, and the desktop
verifies it before spawn. A missing or mismatched packaged executable is a fatal
bootstrap error. `PENTAI_CORE_EXECUTABLE` is an explicit development-only override; it
is ignored by release builds and is not read by the UI.

Native sidecar build and lifecycle smoke jobs run on Windows, macOS, and Ubuntu CI.
Production developer signing, notarization where applicable, and independent review
remain required before a distributable build is approved.

Hosted CI evidence is recorded by immutable run URL in the Phase 0 exit-gate record;
the workflow configuration alone is not cross-platform evidence.

## Credential lifetime and storage

The launch credential exists only in Tauri memory, the child environment, and webview
memory for the lifetime of one desktop launch. It is regenerated on every launch and
is never written to the database, audit ledger, application logs, or operating-system
credential store. A keychain is appropriate for future durable secrets, but not for
this ephemeral credential.

Storing the launch credential in an OS credential store would extend its lifetime and
create recoverable state without improving the stated per-launch possession boundary.
The broader roadmap item for proving secure storage of future durable secrets is
therefore a proposed deferral, not a completed item, and requires Product Owner and
Security Lead approval in `docs/security/phase0_approvals.md`.

Product Owner and Security Lead `un3v3rKn0u` approved that deferral on 2026-08-08. The
same-role holder is not an independent reviewer, so independent security approval of
this ADR remains pending.

## Security limitations

This boundary protects against ordinary unrelated local processes and web content that
do not have the credential. It does not protect against a malicious administrator,
same-user process inspection/debugging, compromise of the Tauri process or webview, a
replaced signed application/core binary, or an operating system compromise. Binary
platform signing and hardening remain separate release controls.

## Consequences

- Directly launching the core without a valid credential fails.
- Standalone UI development requires explicit development-only connection variables.
- Core startup becomes part of desktop startup and migration failure is fail-closed.
- ActionGrant or target-network work remains prohibited until cross-platform lifecycle
  CI passes and the boundary receives independent security review.
