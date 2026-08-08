# Phase 0 security invariant traceability

**Status:** Engineering baseline; independent security approval pending<br>
**Accountable register owner:** Security Lead<br>
**Verification evidence owner:** QA and Security Test Lead<br>
**Last reconciled:** 2026-08-08

This matrix maps every registered invariant. “Phase 0 verified” means the safety
contract or existing Phase 0 boundary has automated evidence; it does not claim that a
deferred Phase 1 component exists. “Deferred” is a release boundary, not a passing test.

| Invariant | Authoritative enforcing component | Accountable owner role | Existing automated evidence | Missing verification / boundary | Approval status |
|---|---|---|---|---|---|
| INV-AUTH-001 | Execution Broker | Execution Safety Lead | Policy inactive/expired/revoked tests in `test_authorization_slice.py` | Broker, signatures, and target execution are Phase 1 | Deferred; not fully verified |
| INV-AUTH-002 | Core domain service | Core Maintainer | Policy hash, immutable records, and migration tests | Grant/execution/evidence linkage is Phase 1 | Phase 0 slice verified; security approval pending |
| INV-AUTH-003 | Policy evaluator | Policy Maintainer | Golden decision corpus, negative tests, canonicalization properties | Gateway integration is Phase 1 | Phase 0 evaluator verified; security approval pending |
| INV-AUTH-004 | Policy evaluator | Policy Maintainer | Deny precedence and path-boundary tests | Gateway parity is Phase 1 | Phase 0 evaluator verified; security approval pending |
| INV-AUTH-005 | Approval service and capability authorization | Core Security Maintainer | Actor-forgery, exact approval, immutable activation, authenticated-route tests | Strong OS user presence is not implemented; local session proves possession, not a named human | Phase 0 local boundary verified; independent approval pending |
| INV-GRANT-001 | Gateway | Gateway Maintainer | Schema validation only | Issuance, signatures, expiry, audience, replay, and gateway do not exist | Phase 1 deferred |
| INV-GRANT-002 | Gateway and Execution Broker | Execution Safety Lead | Intent immutability and policy-hash tests | Grant comparison and execution do not exist | Phase 1 deferred |
| INV-GRANT-003 | Policy evaluator | Policy Maintainer | Conditional capability cannot become allow | Typed action approval integration is incomplete | Partially verified; Phase 1 deferred |
| INV-GRANT-004 | Core and Gateway | Core Maintainer | Revocation epoch contract and policy-revocation tests | Grant invalidation and mid-flight checks do not exist | Phase 1 deferred |
| INV-SCOPE-001 | Canonicalization package | Policy Maintainer | Fixture, property, idempotence, malicious-input, and differential tests | Runtime DNS/redirect inputs await gateway | Phase 0 canonicalizers verified; security approval pending |
| INV-SCOPE-002 | Policy compiler and evaluator | Policy Maintainer | Ambiguous manifest, wildcard/apex, encoded-path, port, and precedence tests | Runtime network ambiguity checks await gateway | Phase 0 compiler/evaluator verified; Phase 1 enforcement deferred |
| INV-SCOPE-003 | Gateway | Gateway Maintainer | Runtime-check requirements in decision tests | DNS, CNAME, redirect, SNI, Host, and resolved-IP enforcement do not exist | Phase 1 deferred |
| INV-SCOPE-004 | Policy evaluator | Policy Maintainer | Default-deny/out-of-scope decision tests | Discovery pipeline does not exist | Contract verified; Phase 1 deferred |
| INV-NET-001 | OS/container network isolation | Platform Isolation Lead | No target-facing networking is present | Gateway, worker isolation, and bypass suite do not exist | Phase 1 deferred; execution prohibited |
| INV-NET-002 | Network Attestation Service and Gateway | Network Safety Lead | Contract validation only | Attestation and live route-change tests do not exist | Phase 1 deferred |
| INV-NET-003 | Gateway and OS/container rules | Network Safety Lead | Contract validation only | Controlled DNS and bypass tests do not exist | Phase 1 deferred |
| INV-NET-004 | Gateway/network namespace | Platform Isolation Lead | IPv4-mapped IPv6 canonicalization regression/property tests | Worker IPv6 containment does not exist | Canonical edge verified; enforcement deferred |
| INV-NET-005 | Policy/budget service | Execution Safety Lead | Budget contract validation only | Atomic reservation and race tests do not exist | Phase 1 deferred |
| INV-AGENT-001 | Core capability model | Agent Runtime Lead | Authenticated principal and actor-forgery negative tests | Agent runtime and full capability inventory do not exist | Phase 0 boundary partially verified; Phase 1 deferred |
| INV-AGENT-002 | Agent runtime | Agent Runtime Lead | ActionIntent schema validation | Agent-to-intent pipeline does not exist | Phase 1 deferred |
| INV-AGENT-003 | Agent runtime and deterministic action pipeline | Agent Runtime Lead | No agent runtime is exposed | Prompt-injection suite and action pipeline do not exist | Phase 1 deferred |
| INV-AGENT-004 | Context builder and provider adapter | Data Protection Lead | No provider integration is exposed | Classification/canary/trace tests do not exist | Phase 1 deferred |
| INV-ISO-001 | Process/container isolation | Platform Isolation Lead | Packaged core ownership/lifecycle smoke | Worker/plugin isolation and secret-broker boundaries do not exist | Local core boundary verified; worker boundary deferred |
| INV-ISO-002 | Plugin Manager and Execution Broker | Plugin Security Lead | Sidecar digest verification tests | Plugin/tool pinning does not exist | Sidecar provenance verified; Phase 1 deferred |
| INV-ISO-003 | Execution Broker | Platform Isolation Lead | No workers exist | Sandbox conformance suite does not exist | Phase 1 deferred |
| INV-DATA-001 | Schema validation and secret broker | Data Protection Lead | Contract validation and launch-credential non-persistence/output tests | Secret broker and model-trace scanning do not exist | Ephemeral credential verified; broader control deferred |
| INV-DATA-002 | Evidence service | Evidence and Reporting Lead | No evidence service exists | API, filesystem, digest, and provenance tests do not exist | Phase 1 deferred |
| INV-DATA-003 | Domain services with transactional outbox | Audit Integrity Lead | Policy/approval/activation audit tests | Grants, execution, evidence, reports, and outbox are incomplete | Phase 0 authorization slice verified; broader control deferred |
| INV-DATA-004 | Audit and export services | Audit Integrity Lead | Authorization audit-chain mutation tests | Export digests and full ledger coverage do not exist | Phase 0 audit slice verified; broader control deferred |
| INV-DATA-005 | Core health gate | Core Maintainer | Migration failure blocks readiness | Disk-full, evidence failure, encryption-key, and integrity fault injection is absent | Partially verified; Phase 1 deferred |
| INV-REL-001 | Grant ledger and gateway | Execution Safety Lead | Database uniqueness/idempotency constraints only | Grants and external effects do not exist | Phase 1 deferred |
| INV-REL-002 | Recovery Coordinator | Reliability Lead | Core lifecycle and migration recovery smoke | Grant revocation, route/DNS/public-IP recovery checks do not exist | Bootstrap verified; Phase 1 deferred |
| INV-REL-003 | Core health and policy evaluator | Reliability Lead | Expiry and timezone tests | Clock-trust/uncertainty detection does not exist | Partially verified; Phase 1 deferred |
| INV-USER-001 | Core and Gateway direct control path | Execution Safety Lead | UI safety-state display only | Emergency stop and hung-worker tests do not exist | Phase 1 deferred |
| INV-USER-002 | Approval API and UI | Product Safety Lead | Exact policy approval and UI workbench tests | Per-action approval UI/API does not exist | Policy activation slice verified; Phase 1 deferred |
| INV-USER-003 | Report service capability set | Evidence and Reporting Lead | No submission endpoint exists | Reviewed export state and API-surface tests do not exist | Non-goal enforced by absence; Phase 1 export work deferred |

## Approval interpretation

Engineering acceptance is evidenced by merged pull requests #14 and #15 plus passing
checks. It is not independent security approval. The Security Lead owns the register;
an independent Security Reviewer must approve the baseline and the local-transport
boundary before the Phase 0 exit gate can pass. Deferred Phase 1 rows remain open and
must not be represented as implemented capabilities.
