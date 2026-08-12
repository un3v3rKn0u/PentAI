# Phase 1 supervised report coverage workspace

**Status:** Implemented; sole-maintainer security review recorded

The Reports workspace now records and reloads immutable assessment coverage for one exact
workflow. Each request binds an allowed policy asset rule, capability rule, capability,
ordered testing interval, outcome, available evidence, explicit limitations, and human
notes. Tested outcomes require evidence; blocked and not-tested outcomes remain explicit
gaps.

Every response must match the exact workflow and assert `coverage_complete: false`.
Individual records can be selected for a No Findings draft, but the core independently
revalidates latest-record coverage for every allowed asset/capability pair and denies gaps,
stale records, missing evidence, or unresolved findings.

This slice adds no schema, migration, inference, execution, export approval, upload, or
submission authority. Rollback restores manual coverage-ID entry without changing durable
coverage or report records.
