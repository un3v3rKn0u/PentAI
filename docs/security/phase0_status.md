# Phase 0 status and exit gate

**As of:** 2026-08-08<br>
**Decision owner:** Security Lead<br>
**Current decision:** Phase 0 does **not** formally pass; independent review pending

This record distinguishes implementation, local verification, hosted cross-platform
verification, and human approval. A merge or green workflow is engineering evidence;
it is not an independent approval.

## Evidence baseline

- Authorization vertical slice merged as PR #14 (`dfa614d`).
- Authenticated desktop-to-core bootstrap and packaged lifecycle merged as PR #15
  (`393d08f`).
- PR #15 [Desktop smoke run](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448196)
  passed packaged lifecycle jobs on
  [macOS](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448196/job/93000504700),
  [Windows](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448196/job/93000504722), and
  [Ubuntu](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448196/job/93000504776).
- The same PR head passed [Quality](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448392),
  [CodeQL](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448016),
  [dependency review](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448121), and
  [Rust audit](https://github.com/un3v3rKn0u/PentAI/actions/runs/31219448411).
- Merged `main` at `393d08f` passed
  [Quality](https://github.com/un3v3rKn0u/PentAI/actions/runs/31263500631),
  [CodeQL](https://github.com/un3v3rKn0u/PentAI/actions/runs/31263500617), and
  [Rust audit](https://github.com/un3v3rKn0u/PentAI/actions/runs/31263500621).
- PR #16 passed [Python and contracts](https://github.com/un3v3rKn0u/PentAI/actions/runs/31264656875/job/93120740023),
  including the Hypothesis suite, plus UI, SQLite migration, dependency review, and
  Python/JavaScript CodeQL checks. Its
  [Desktop smoke run](https://github.com/un3v3rKn0u/PentAI/actions/runs/31264656859)
  passed on Windows, macOS, and Ubuntu.

## Safety-area status

| Safety area | Implemented | Locally verified | Cross-platform verified | Approved | Remaining gate |
|---|---:|---:|---:|---:|---|
| Authenticated desktop-to-core bootstrap | Yes | Yes | Windows/macOS/Ubuntu, PR #15 | Security Lead approved | Independent security approval |
| Packaged core ownership and lifecycle | Yes | Yes on macOS | Windows/macOS/Ubuntu, PR #15 | Security Lead approved | Independent security approval |
| Sidecar provenance | SHA-256 before spawn | Yes | Windows/macOS/Ubuntu, PR #15 | No release approval | Developer signing/notarization remains a release control |
| Authorization vertical slice | Yes | Yes | Ubuntu Quality; desktop boundary on three OSes | Security Lead approved Phase 0 slice | Independent security approval; Phase 1 enforcement deferred |
| Contract compatibility and ownership | Seven schemas plus Approval 1.1 | Yes | Ubuntu Quality | Product Owner and Security Lead approved | Independent security review |
| Canonicalization | Domain/wildcard/URL/IP/CIDR/port/path | Yes, including Hypothesis | Ubuntu Python CI; branch lifecycle green on three OSes | Security Lead approved | Independent security approval |
| Ephemeral launch credential storage | In-memory by design | Yes | Lifecycle smoke on three OSes | Security Lead approved ADR | Independent approval of ADR |
| Durable-secret OS credential store | No durable secret exists | Not applicable to launch credential | No | Product Owner and Security Lead approved deferral | None for deferral; future proof remains deferred |
| Threat/abuse model | Local transport baseline | Controls linked to tests | Boundary smoke on three OSes | Security Lead accepted owner mapping | Independent security review |
| Security invariants | Full owner/evidence/gap mapping | Phase 0 evidence classified | Boundary evidence only | Security Lead approved | Independent Security Reviewer approval |

## Local trust-boundary conclusions

- Every `/api/v1/*` route requires the current per-launch bearer credential.
- The authenticated principal is server-side; display identifiers are not authority.
- Missing, malformed, incorrect, and absent credentials receive uniform denial.
- Desktop startup waits for authenticated readiness and fails closed.
- Normal desktop shutdown terminates and reaps the owned core.
- Packaged sidecar smoke covers unauthenticated and incorrect credentials,
  authenticated shutdown, port collision, and credential-output checks.
- The sidecar digest is embedded at desktop build time and verified before execution.

## Current local validation

On macOS with Python 3.13, Node 20, pnpm 9.15, and Rust 1.97: Ruff lint and formatting,
strict mypy, pytest (61 tests and 85 subtests), seven-contract validation, all three
migration tests, pip-audit, pnpm audit/typecheck/test/build (10 UI tests), Cargo format,
check, and tests (3 Rust tests), native packaged-core build/lifecycle smoke, and wheel
schema/migration resource checks passed. `cargo audit` found no vulnerability failures
and reported 17 allowed unmaintained/unsound transitive warnings; the hosted Rust audit
also passes. Local results are not cross-platform evidence.

`INV-AUTH-005` is verified only for the Phase 0 local session boundary: an automated
caller cannot assert an actor ID to approve or activate a policy, and the caller must
possess the desktop launch credential. That credential proves session possession, not
strong human identity or user presence. The invariant is therefore not marked fully
verified for the future Phase 1 action pipeline.

## Phase 0 exit-gate matrix

| Criterion | Evidence | Owner | Approval status | Blocker |
|---|---|---|---|---|
| Every authorization-critical schema has an owner and compatibility policy | `docs/contracts/README.md`; contract validator; wheel resource test | Contract Maintainer and per-schema owner | Product Owner and Security Lead approved | Independent security review required by repository policy |
| Canonicalizers pass IDNA, wildcard, URL-boundary, CIDR, encoded-path, and IP edge properties | `test_canonicalize.py`; malicious regression fixture; PR #16 Python CI | Policy Maintainer | Security Lead approved engineering evidence | Independent review |
| Local API inaccessible without launch credential | PR #15 auth tests and three-platform packaged smoke | Core Security Maintainer | Security Lead approved | Independent security approval |
| Threat model has no unowned critical threats | Every local-transport threat has maintainer roles; full invariant matrix assigns roles | Security Lead | Security Lead accepted owner mapping | Independent security review |
| Security team approves initial invariants | Register and full traceability matrix prepared | Security Lead | Security Lead approved | Independent Security Reviewer approval required by repository policy |
| Durable-secret credential-store roadmap decision is resolved | ADR explains why ephemeral launch credentials must not be durable | Product Owner and Security Lead | Product Owner and Security Lead approved deferral | None |

## Formal decision

Phase 0 remains **blocked at its exit gate**. Product Owner and Security Lead approvals
are complete, but both roles are held by the repository's only reviewer. The remaining
gate is independent security approval of the invariants, canonicalization, contract
ownership baseline, threat model, and local transport boundary. This decision does not claim artifact signing,
notarization, ActionGrant issuance, gateway enforcement, worker isolation, or any
target-facing network capability exists.
