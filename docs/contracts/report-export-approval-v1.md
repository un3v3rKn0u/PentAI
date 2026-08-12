# Explicit report export approval contract v1

`report-export-approval-v1.schema.json` records one immutable authenticated-human
approval for one exact findings or No Findings draft. The approval binds the report's
stored content hash, all four artifact digests, workflow, policy, expected `draft`
status, review reason, approver, and decision time.

The operation requires an explicit boolean confirmation and recomputes every artifact
digest inside one immediate transaction. Missing, malformed, changed, incomplete,
already-approved, or ambiguous report state denies. A successful record makes only the
exact bound draft `export_ready`; it does not mutate immutable draft history and never
enables external submission.

Migration `0028_report_export_approvals.sql` is additive. Approval records cannot be
updated or deleted. File export, destination selection, and platform submission remain
separate capabilities.
