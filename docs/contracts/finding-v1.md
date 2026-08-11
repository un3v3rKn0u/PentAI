# Supervised finding contract v1

`finding-v1.schema.json` records one human-created finding for an assessment workflow
and its exact policy bundle. Creation accepts only allow-rule identifiers present in
that immutable policy and non-deleted evidence from the same workflow and policy.
Neither evidence, AI output, nor a finding grants execution authority.

The service deterministically verifies CVSS 3.1 base vectors and recomputes the score;
severity must match the calculated band. CWE, confidence, affected assets, evidence,
reproduction, impact, remediation, and HTTPS/URN references are bounded and typed. A
stable fingerprint supports duplicate review without automatically declaring two
findings equivalent.

Every finding begins as `candidate` and only a human may advance it through:

`candidate → scope_reviewed → duplicate_reviewed → validated → report_ready → closed`

Reviewed rejection is allowed before validation when the finding is a confirmed
duplicate, false positive, or not reproduced. Validation requires a confirmed,
non-duplicate result. Retest moves a validated finding back to duplicate review, and a
report-ready finding back to validation. Expected versions fence stale writes.

Migration `0024_supervised_findings.sql` is additive. The current record and every full
document version are content hashed; version rows are append-only and chained in order,
and database triggers require the next immutable version before updating current state.
Creation and every transition append audit events. Rollback requires a verified
pre-migration backup because older binaries do not understand or protect these records.

This contract does not render finding content, calculate program-specific severity,
perform automatic duplicate matching, generate reports, or approve export. Those remain
separate supervised slices.
