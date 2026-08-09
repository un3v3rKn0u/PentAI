# ADR 0005: Block Linux distribution for the GTK/glib advisory

**Status:** Accepted for pre-release development<br>
**Date:** 2026-08-09<br>
**Decision owner:** Sole maintainer and Security Lead (`un3v3rKn0u`)<br>
**Review:** Sole-maintainer security review — non-independent

## Context

Dependabot alert 1 reports `GHSA-wrw7-89jp-8q8g` in transitive `glib` 0.18.5. The
affected iterator implementation can cause undefined behavior and optimized-build
null dereferences. The first patched release is `glib` 0.20.0.

PentAI does not depend on `glib` directly. Tauri 2.11.5 depends on GTK 0.18, which
requires `glib ^0.18`; Cargo therefore rejects a direct update to 0.20. Tauri's Linux
WebKit/GTK backend remains useful for development compatibility tests, but an
unpatched runtime dependency is not acceptable in a distributed security product.

## Decision

PentAI retains Linux desktop smoke builds but introduces an explicit
`release-distribution` Cargo feature. The build script rejects that feature for every
Linux target with stable code
`PENTAI-LINUX-RELEASE-BLOCKED-GHSA-WRW7-89JP-8Q8G`. Hosted Ubuntu CI proves the gate
continues to reject the distribution configuration for the intended reason.

macOS and Windows distribution remain independently gated by signing, notarization,
and the other release requirements. Core, policy, UI, and synthetic local development
may continue; this decision grants no target-facing authority.

## Rejected alternatives

- Forcing `glib` 0.20 is impossible because it violates GTK's declared dependency.
- Vendoring or privately forking the GTK/glib stack creates a large, long-lived
  security-maintenance burden for a one-line upstream repair.
- Dismissing the alert without an enforceable product boundary would conceal rather
  than contain the risk.
- Removing Ubuntu smoke tests would reduce visibility and cross-platform evidence.

## Removal criteria

The gate may be removed only when all of the following are true:

1. The supported Tauri/GTK dependency graph resolves `glib` 0.20 or later, or an
   authoritative advisory record identifies another patched compatible version.
2. RustSec and Dependabot no longer report this advisory for the lockfile.
3. Ubuntu check, test, release bundle, and packaged lifecycle checks pass.
4. The complete dependency diff receives the required security review.

## Residual risk

Linux development builds still contain the affected transitive library and must use
synthetic local fixtures only. This self-authored review is non-independent and does
not authorize Linux distribution, production use, or external assurance.
