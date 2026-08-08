# Phase 0 approval record

**Status:** Approved under the sole-maintainer exception; Phase 0 exit authorized<br>
**Record owner:** Security Lead<br>
**Last reconciled:** 2026-08-08

Product Owner, Security Lead, and sole-maintainer security-review decisions are
recorded below. The security review is explicitly non-independent and uses the
exception in `GIT_WORKFLOW.md` because the same person holds all three roles.

| Document / decision | Engineering acceptance | Required approval | Current status |
|---|---|---|---|
| MVP requirements v1.0.0: scope, personas, use cases, and non-goals | Implemented baseline reviewed through repository history | Product Owner and Security Lead | Product Owner and Security Lead approved |
| Security invariant register v1.0.0 and Phase 0 verification/deferment mapping | Test-linked engineering baseline | Security Lead and Security Reviewer | Approved under sole-maintainer exception; non-independent |
| ADR 0001: ephemeral per-launch authenticated local transport | Implemented by PR #15; three-platform hosted CI evidence recorded | Desktop Maintainer, Core Maintainer, Security Reviewer | Approved under sole-maintainer exception; non-independent |
| Local transport threat model and abuse cases | Controls implemented and tested by PR #15 | Threat owners and Security Reviewer | Approved under sole-maintainer exception; non-independent |
| Abuse-case inventory in the local transport threat model | Automated negative tests exist | QA and Security Test Lead, Security Reviewer | Approved under sole-maintainer exception; non-independent |
| Durable-secret credential-store Phase 0 deliverable | Ephemeral launch credential deliberately requires no durable store | Product Owner and Security Lead must approve deferral until a durable secret exists | Product Owner and Security Lead approved deferral |

## Recorded approvals

### Product Owner approval — 2026-08-08

- **Approver identity:** `un3v3rKn0u`
- **Role:** Product Owner
- **Decision:** Approved
- **Scope:** Phase 0 MVP scope, personas, authorized use cases, explicit non-goals,
  and deferral of OS credential-store validation until PentAI introduces a durable
  secret.
- **Evidence reviewed:** PR #16 change set; the Phase 0 exit-gate matrix; local
  validation results; and successful PR #16 Python, UI, migration, CodeQL, dependency
  review, and Windows/macOS/Ubuntu packaged lifecycle checks.
- **Limitations:** This is Product Owner approval only. It is not Security Lead or
  independent security approval and does not approve the security invariant baseline,
  ADR 0001 security decision, threat/abuse model, ActionGrant issuance, target-facing
  networking, gateway enforcement, worker isolation, artifact signing, notarization,
  or production release.
- **Recorded statement:** `un3v3rKn0u`, acting as Product Owner, approves the Phase 0
  product changes and the documented credential-store deferral within the limitations
  above.

### Security Lead approval — 2026-08-08

- **Approver identity:** `un3v3rKn0u`
- **Role:** Security Lead
- **Decision:** Approved
- **Scope:** Security invariant register v1.0.0 and Phase 0 traceability mapping; ADR
  0001 authenticated local transport; local-transport threat model and abuse cases;
  assignment of critical-threat owner roles; authorization-critical schema ownership
  baseline; canonicalization v1 behavior and verification; and deferral of OS
  credential-store validation until PentAI introduces a durable secret.
- **Evidence reviewed:** Merged PRs #14, #15, and #16; the Phase 0 exit-gate and
  invariant traceability matrices; local validation results; and successful Python,
  UI, migration, CodeQL, dependency, and Windows/macOS/Ubuntu packaged lifecycle CI.
- **Independence:** Not independent. The approver is also Product Owner, repository
  owner, and the only reviewer.
- **Limitations:** This approval covers the implemented Phase 0 local trust boundary,
  authorization simulation, safety contracts, and documented deferrals. It does not
  approve ActionGrant issuance, target-facing networking, gateway enforcement, worker
  isolation, artifact signing, notarization, production release, or any deferred Phase
  1 enforcement. It does not satisfy the independent security-review requirement in
  `GIT_WORKFLOW.md`.
- **Recorded statement:** `un3v3rKn0u`, acting as Security Lead, approves the Phase 0
  security baseline and credential-store deferral within the scope and limitations
  above.

### Sole-maintainer security review — non-independent — 2026-08-08

- **Reviewer identity:** `un3v3rKn0u`
- **Roles disclosed:** Security Reviewer, Product Owner, Security Lead, repository
  owner, change author, and sole maintainer.
- **Decision:** Approved under the sole-maintainer exception in `GIT_WORKFLOW.md`.
- **Scope:** Merged PRs #16 and #17; canonicalization implementation and tests;
  authenticated local API boundary; security invariants and traceability;
  authorization-critical schemas; ADR 0001; threat and abuse model; credential-store
  deferral; CI evidence; and the Phase 0 exit-gate matrix.
- **Evidence reviewed:** Complete PR #16 and #17 changes; the local validation matrix
  in `phase0_status.md`; passing PR #16 Windows, macOS, and Ubuntu packaged lifecycle
  jobs; and passing Quality, CodeQL, dependency-review, migration, UI, Python,
  contract, and Rust checks recorded by those PRs.
- **Findings:** No unresolved material security findings within the Phase 0 scope.
- **Independence:** Not independent. The reviewer is the sole maintainer and authored
  or approved the reviewed work.
- **Residual risk accepted:** Reduced governance assurance from the absence of a
  second human reviewer. This exception does not reduce technical test requirements.
- **Limitations and exclusions:** Deferred Phase 1 enforcement, ActionGrant issuance,
  gateway enforcement, worker isolation, target-facing networking, artifact signing,
  notarization, key custody, destructive migration approval, disclosure decisions
  involving another party, and production release are not approved.
- **Recorded statement:** `un3v3rKn0u` confirmed the complete sole-maintainer review
  statement on 2026-08-08 and accepted its disclosed residual governance risk.

Engineering acceptance, role approval, and this non-independent security review are
separate records. A future external requirement for independent or dual-control
approval is not satisfied by this exception.
