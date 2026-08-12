# Coverage-aware No Findings report draft contract v1

`no-findings-report-draft-v1.schema.json` records a restricted, immutable,
human-requested draft that states no findings were identified within an explicit
coverage boundary. It snapshots exact immutable coverage record hashes, evidence
references, testing intervals, policy identity, and every declared limitation.

Generation requires a completed workflow and exactly one selected latest
`tested_no_findings` record for every allowed policy asset/capability pair. Missing,
blocked, untested, finding-bearing, stale, ambiguous, foreign, or evidence-unavailable
coverage denies the entire request. Any unresolved non-rejected finding also denies.

Migration `0027_no_findings_report_drafts.sql` is additive and makes draft metadata and
four bounded artifacts immutable. Drafts do not assert exhaustive security. A later
approval record may bind an exact draft as export-ready, but no file-export or external
submission capability exists.
