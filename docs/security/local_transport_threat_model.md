# Local transport threat model

**Owner roles:** Desktop Maintainer and Core Maintainer<br>
**Engineering acceptance:** Implemented in PR #15<br>
**Security Lead approval:** `un3v3rKn0u`, 2026-08-08<br>
**Security review:** Sole-maintainer review approved (non-independent), 2026-08-08

## Scope and assets

This model covers the Tauri desktop, its React webview, the owned FastAPI core process,
the loopback connection between them, the launch credential, and bootstrap metadata.
The primary assets are approval authority, policy activation state, provenance and
audit data, and the ability to keep execution disabled when bootstrap is invalid.

## Trust boundaries

- Operating system to the signed PentAI desktop and packaged core binaries.
- Tauri host process to the core child environment and loopback listener.
- Tauri IPC to webview memory.
- Webview HTTP client to authenticated core middleware.
- Core process to SQLite storage.

## Threats and controls

| Threat or misuse case | Impact | Control | Remaining work |
|---|---|---|---|
| Unrelated local process calls the API | Approval impersonation or policy mutation | Per-launch 256-bit credential on every API route; constant-time validation; packaged lifecycle smoke passed on Windows, macOS, and Ubuntu | Same-user process hardening remains outside Phase 0 |
| Caller submits a forged actor ID | False human attribution | Actor authority removed from request models and bound to the authenticated server-side session | Add future OS-user confirmation for stronger human identity |
| Token leaks through logs, errors, audits, URLs, or persistence | Session takeover | No access log, uniform errors, header transport, in-memory bootstrap, no audit/database storage; packaged output is checked | Platform review of crash reporting and diagnostics |
| Process occupies or races the selected port | Core substitution or denial of service | Dynamic loopback selection plus credential-authenticated readiness; failed bind/readiness is fatal; collision smoke passed on Windows, macOS, and Ubuntu | Crash/orphan and additional platform hardening remain future work |
| Rogue process returns fake readiness | Desktop connects to substituted core | Readiness requires the unpredictable launch credential; packaged sidecar SHA-256 is verified before spawn | Production platform signing |
| Browser origin abuses CORS | Unauthorized requests from web content | Narrow production origins, narrow methods/headers, bearer credential still required | Validate platform webview origin behavior in packaged tests |
| Core migration or startup fails | UI operates against partial state | Bounded readiness and fail-closed desktop setup | Add user-safe bootstrap failure screen |
| Desktop exits but core remains | Stale credential and API remain usable | Desktop owns, kills, and reaps the child on normal exit | Crash/orphan containment test per platform |
| Malicious same-user process reads child environment or webview memory | Credential theft | Explicitly outside the Phase 0 local-process boundary | OS sandboxing/hardening decision |
| Administrator or OS compromise | Full boundary bypass | Explicit non-goal for this control | Platform security and incident controls |
| Packaged core binary is replaced | Arbitrary privileged local service | Packaged executable required, no production Python fallback, build-embedded sidecar SHA-256 verification | Production platform signing and notarization |

## Abuse-case assertions

1. Missing, malformed, empty, stale, or incorrect credentials receive the same 401.
2. Authentication happens before request parsing or domain lookup.
3. Health and readiness disclose nothing without authentication.
4. Invalid bootstrap state exposes no authorization workflow controls.
5. A production web build has no default port or credential.
6. Credential material never enters an audit event or persisted domain object.
7. Failure to prove authenticated readiness prevents desktop startup.

## Review gate

The local transport boundary passed its Phase 0 review under the documented
sole-maintainer exception after packaged Windows, macOS, and Ubuntu lifecycle tests
passed. The review is non-independent. This document does not approve ActionGrant
issuance, target networking, production signing, or release.
