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

### Core service

```text
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pentai_core.migrate
.venv/bin/uvicorn pentai_core.main:app --reload --host 127.0.0.1 --port 8741
```

### UI

```text
corepack enable
pnpm install
pnpm --filter @pentai/ui dev
```

### Tests

The deterministic standard-library suite runs without installing third-party packages:

```text
PYTHONPATH=packages/policy/src:services/core/src python3 -m unittest discover -s tests -p "test_*.py"
python3 scripts/validate_contracts.py
```

The full test command after development dependencies are installed is:

```text
pytest
```

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
