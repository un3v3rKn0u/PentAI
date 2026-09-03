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
| Caller forges or delegates an orchestration approval identity | Approval impersonation, proxy approval, cross-session reuse, or false provenance | Closed approval API bodies omit identity fields; middleware-derived principal and fresh per-process session UUID are persisted in request/decision v2 and must match on decision/replay | Current transport represents one desktop actor; multi-user and OS-user identity remain future work |
| Caller forges registry snapshot provenance | Provider/model provenance substitution or rollback | Registry snapshot bodies omit actor, session, digest, state, and authority claims; trusted core derives canonical digests, binds the middleware principal/session, enforces monotonic revision, and stores only inactive immutable provenance | Registry signing governance, activation, and revocation remain future work |
| Caller forges provider-configuration snapshot provenance | Provider/model, privacy, budget, secret-reference, or activation-lineage substitution | Closed request bodies omit actor, session, digests, state, privilege, and authority; trusted core revalidates the current registry activation and configuration, derives all durable metadata, stores only the opaque reference digest, and storage-gates the exact inactive snapshot | Registry revocation, meter attestation, secret resolution, provider execution, and accounting remain future work |
| Caller substitutes a local runtime, model, capability, or limits | Unreviewed model execution or budget widening | Trusted core fixes the exact `llama.cpp`/Qwen selection, derives the manifest from current durable configuration and registry lineage, intersects limits, and stores only a pending metadata-only ActionIntent v2 | Grant, supervised adapter, artifact verification, execution receipt, and usage measurement remain future work |
| Caller injects an unsupported local-model policy capability or runtime claim | Policy widening or implementation substitution | Manifest v3 accepts one closed local capability, rejects runtime-specific fields and conflicting effects, and trusted core revalidates, compiles, and signs Policy IR v2 under a separate domain; content remains immutable and activation requires exact Approval v2 lineage | Grants and execution remain future work |
| Caller substitutes Policy IR v2 approval identity or lineage | Cross-policy activation or privilege escalation | Activation revalidates the exact current Manifest v3, Policy IR v2 and Approval v2 durable lineage and both signatures; storage permits only the exact approved inactive-to-active edge and later fail-closed revocation | Grants and execution remain disabled |
| Caller substitutes local-model intent or policy-evaluation lineage | A decision for stale, cross-scope, or widened model work | Evaluation loads the immutable intent by ID, revalidates the exact current policy, manifest, task, configuration, registry, limits, safety, epoch, and expiry, and stores a no-authority PolicyDecision v2 in a separate immutable table | Approval consumption, grants, artifact verification, and execution remain future work |
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
8. Orchestration approval request bodies cannot supply actor, role, delegation, proxy,
   or authentication-context claims; the server-derived principal is the only identity.
9. Provider-registry snapshot request bodies cannot supply actor, session, canonical
   digest, snapshot state, activation, revocation, privilege, or authority claims.
10. Provider-configuration snapshot request bodies cannot supply actor, session,
    canonical digests, snapshot state, meter eligibility, privilege, or authority;
    opaque secret references never enter audit, outbox, or durable snapshot records.
11. Local-model intent requests cannot supply runtime/model identity, capability,
    routing, prompt content, privilege, authority, or execution enablement; direct
    storage mutation and cross-lineage substitution deny.
12. Local-model policy input cannot select a runtime, model, artifact, command, path,
    implementation behavior, or execution authority; unsupported and conflicting
    capability rules deny before Policy IR v2 compilation.
13. Policy IR v2 signatures use a version-separated domain; direct mutation, deletion,
    mismatched approval, or any activation outside the exact guarded lifecycle denies.
14. Policy Activation Approval v2 cannot accept caller identity or lineage, cannot
    outlive its policy, and can activate only its exact current Policy IR v2 lineage.
15. Active Policy IR v2 remains coordination-only; evaluation cannot grant model
    execution, provider/plugin access, or network effects.
16. PolicyDecision v2 evaluation is metadata-only. Its allow outcome cannot be consumed
    by ActionGrant v1 and cannot authorize a model, process, provider, or network effect.

## Review gate

The local transport boundary passed its Phase 0 review under the documented
sole-maintainer exception after packaged Windows, macOS, and Ubuntu lifecycle tests
passed. The review is non-independent. This document does not approve ActionGrant
issuance, target networking, production signing, or release.
