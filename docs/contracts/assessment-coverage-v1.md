# Supervised assessment coverage contract v1

`assessment-coverage-v1.schema.json` records an immutable human assertion about one
policy-authorized asset-rule and capability-rule pair during an assessment workflow.
It preserves the exact workflow policy, ordered testing interval, outcome, evidence,
limitations, notes, recorder, and audit linkage.

Claims that testing occurred (`tested_no_findings` or `finding_identified`) require at
least one available evidence object from the same workflow and policy. `blocked` and
`not_tested` are explicit gaps. Every record sets `coverage_complete` to `false`:
individual entries cannot claim exhaustive assessment coverage.

Migration `0026_assessment_coverage.sql` is additive. Records are immutable and cannot
be deleted. This slice does not calculate a coverage matrix, decide sufficiency,
generate a “No Findings” report, approve an export, or submit externally.
