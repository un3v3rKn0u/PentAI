# Phase 1 multi-row scope review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint can review up to 50 independently typed
allow and deny asset rows. Every row must cite one immutable source selected in the same
review bundle. Allow rows retain explicit paths and ports; deny rows cannot carry those
authority-granting fields. At least one allow row is required.

The resulting manifest uses the existing version 2 asset contract. Each row receives an
independent identity and preserves its exact source reference. The authenticated core
continues to canonicalize the completed manifest and remains authoritative for semantic
contradictions, policy compilation, approval, and activation.

## Safety and failure states

Empty lists, more than 50 rows, duplicate reviewed-source identifiers, unknown row source
references, malformed typed values, incomplete allow authority, deny rows containing allow
fields, deny-only reviews, and duplicate canonical type/value pairs all deny draft
construction. Changing a row type clears its prior target; changing an allow row to deny
clears paths and ports.

This slice adds no discovery, authority inference, network access, policy activation,
grant, or execution behavior.

## Compatibility and rollback

Manifest v2 already supports multiple typed allow and deny assets, so no schema or
migration change is required. The manifest builder retains compatibility with the prior
single-row normalization shape for existing callers and tests. Rolling back the UI slice
does not alter persisted source, manifest, or policy history.
