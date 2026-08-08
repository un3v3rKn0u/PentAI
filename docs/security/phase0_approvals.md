# Phase 0 approval record

**Status:** Required approvals pending<br>
**Record owner:** Security Lead<br>
**Last reconciled:** 2026-08-08

No formal human approval is recorded in the repository. Merged engineering work and
green CI are acceptance evidence, not approval by an independent security reviewer.

| Document / decision | Engineering acceptance | Required approval | Current status |
|---|---|---|---|
| MVP requirements v1.0.0: scope, personas, use cases, and non-goals | Implemented baseline reviewed through repository history | Product Owner and Security Lead | Pending |
| Security invariant register v1.0.0 and Phase 0 verification/deferment mapping | Test-linked engineering baseline | Security Lead plus independent Security Reviewer | Pending |
| ADR 0001: ephemeral per-launch authenticated local transport | Implemented by PR #15; three-platform hosted CI evidence recorded | Desktop Maintainer, Core Maintainer, independent Security Reviewer | Maintainer implementation accepted; independent approval pending |
| Local transport threat model and abuse cases | Controls implemented and tested by PR #15 | Threat owners and independent Security Reviewer | Pending |
| Abuse-case inventory in the local transport threat model | Automated negative tests exist | QA and Security Test Lead, independent Security Reviewer | Pending |
| Durable-secret credential-store Phase 0 deliverable | Ephemeral launch credential deliberately requires no durable store | Product Owner and Security Lead must approve deferral until a durable secret exists | Proposed deferral; not approved |

## Prepared approval text

The following text is intentionally **not effective** until an authorized human supplies
their identity, role, decision, date, scope, limitations, and evidence reviewed:

> I approve the Phase 0 MVP scope/non-goals, security invariant baseline and
> traceability mapping, ADR 0001 local-transport decision, local-transport threat and
> abuse-case model, and the deferral of OS credential-store validation until PentAI
> introduces a durable secret. This approval covers only the implemented Phase 0 local
> trust boundary and authorization simulation. It does not approve ActionGrant
> issuance, target-facing networking, gateway enforcement, worker isolation, artifact
> signing, notarization, or production release.

Approval records must append: approver name, accountable role, independence from the
change author, decision date, commit reviewed, CI run URLs, limitations, and any
follow-up conditions. Engineering acceptance and independent security approval must be
recorded as separate entries.
