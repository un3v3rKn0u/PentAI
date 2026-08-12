# Supervised report draft contract v1

`report-draft-v1.schema.json` records one immutable, human-requested report draft for
an assessment workflow. Generation snapshots only findings currently in
`report_ready`, with their exact version and content hash, and binds the result to the
workflow's immutable policy bundle. Missing, stale, foreign, duplicate, rejected, or
otherwise unready findings deny the complete operation.

Every successful request deterministically renders Markdown, escaped inactive HTML,
canonical JSON, and a minimal text-only PDF. Each bounded artifact is stored locally,
content-digested, classified `restricted`, and audit-linked. The draft status is never approval or export
authority. PentAI exposes no submission transport, and a caller cannot supply rendered
content.

Migration `0025_report_drafts.sql` is additive and makes draft metadata and artifacts
immutable. Rollback requires a verified pre-migration backup because older binaries do
not protect these rows. Human report approval/export, rich styling, screenshots,
coverage-aware “No Findings” reports, and automatic platform submission remain separate
slices.
