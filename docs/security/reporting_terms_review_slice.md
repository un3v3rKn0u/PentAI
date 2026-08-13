# Phase 1 reporting-terms review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Supervised Intake now reviews the submission channel, required report fields, evidence
rules, and disclosure timeline. Human approval remains mandatory and automatic submission
remains disabled in every generated manifest.

## Safety and compatibility

Blank or overlong channels and timelines, empty required-field lists, and empty evidence
rules deny draft construction. These terms do not submit, export, or disclose anything.
Manifest v2 already defines the fields, so no schema or migration is required. Existing
callers retain manual, human-approved, non-automatic reporting defaults. Rollback affects
draft presentation only.

The core remains authoritative for manifest validation, report approval, export, and any
future submission boundary.
