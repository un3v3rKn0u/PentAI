# PentAI

PentAI is a local-first desktop assistant for supervised, authorized HTTP/HTTPS security assessments.

This repository includes the first local-only authorization vertical slice: program and
source intake, provenance hashing, Manifest v2 validation/versioning, deterministic
Policy IR v1 compilation, exact human approval, immutable activation, ActionIntent
simulation, and tamper-evident audit. Target-facing network execution is not implemented.

## Safety boundary

The architecture follows one rule:

> AI may propose and interpret; deterministic policy and isolated infrastructure decide and enforce.

See:

- `docs/product/mvp_requirements.md`
- `docs/security/security_invariants.md`
- `docs/contracts/`
- `schemas/v1/`
- `docs/security/authorization_vertical_slice.md`
- `docs/adr/0001-authenticated-local-core-transport.md`
- `docs/security/local_transport_threat_model.md`
- `docs/security/phase0_traceability.md`
- `docs/security/phase0_approvals.md`
- `docs/release_process.md`
- `.github/SECURITY.md`

## Repository layout

```text
apps/desktop/       Tauri desktop shell
apps/ui/            React/TypeScript interface
services/core/      FastAPI local service
packages/policy/    Canonicalization and future policy engine
migrations/         SQLite schema migrations
schemas/v1/         Versioned JSON contracts
tests/              Policy/canonicalization corpus and tests
docs/               Product, security, and contract documents
.github/workflows/  Automated checks and cross-platform smoke builds
```

## Local development

### Authenticated desktop and core

```text
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
pnpm install
pnpm --filter @pentai/ui build
.venv/bin/python scripts/build_core_sidecar.py
cargo run --manifest-path apps/desktop/Cargo.toml
```

The desktop generates a fresh credential, selects a loopback port, starts the core,
waits for authenticated readiness, passes connection state to the UI, and terminates
the child on exit. The core intentionally refuses standalone startup without a launch
credential.

The sidecar build is native: run it on each target operating system before compiling
or bundling the desktop application.

### Standalone UI development

```text
VITE_PENTAI_CORE_URL=<explicit-development-url> \
VITE_PENTAI_LAUNCH_CREDENTIAL=<current-launch-credential> \
pnpm --filter @pentai/ui dev
```

These variables are recognized only by Vite development builds. Production obtains
bootstrap state exclusively through Tauri.

### Tests

After installing the declared development environment, run the Python and contract suite:

```text
.venv/bin/pytest
.venv/bin/python scripts/validate_contracts.py
```

`pytest` includes the Hypothesis canonicalization properties and regression corpus.
The full local verification matrix is documented in `docs/security/phase0_status.md`.

Security vulnerabilities should be reported privately through the repository's
**Security → Advisories → Report a vulnerability** flow. Do not open a public issue
containing vulnerability details, credentials, target data, or assessment evidence.

## Current limitations

- No target-facing network execution.
- No egress gateway or container broker yet.
- No AI agent runtime yet.
- No external tools or plugins.
- No report submission.
- No ActionGrant issuance; the policy workbench is a decision simulator only.

These are deliberate Phase 0 constraints.
