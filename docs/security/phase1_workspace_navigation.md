# Phase 1 workspace navigation

**Status:** Implemented; sole-maintainer security review recorded

The authenticated local workbench now exposes the eight required Phase 1 areas through
one explicit navigation control: Dashboard, Programs, Intake, Assessments, Evidence,
Findings, Reports, and Logs. Navigation uses native buttons, identifies the current
destination with `aria-current="page"`, and retains a visible keyboard focus indicator.

Inactive workspaces remain mounted but are hidden from rendering and the accessibility
tree. This preserves supervised draft form state without duplicating requests or moving
authority between workspaces. Network setup, policy lifecycle, and non-executing
authorization evaluation remain grouped under Assessments because they are prerequisites
and controls for that workflow.

The global safety banner, authenticated-core failure state, and policy-state legend remain
outside the selected workspace and therefore remain visible across navigation. Selecting
a destination performs no core request and grants no policy, execution, export, network,
or submission authority.

This slice adds no schema, migration, persistence, contract, or compatibility change.
Rollback restores the previous single scrolling layout without changing durable records.
