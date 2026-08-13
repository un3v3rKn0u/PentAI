# Phase 1 data-handling review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint now reviews real-user-data handling,
retention, remote-AI classification, and bounded redaction rules. Storage remains fixed to
the existing `local_encrypted` contract value. The default review avoids and stops on real
user data and permits no remote-AI disclosure.

The authenticated core remains authoritative for manifest validation, evidence retention,
redaction derivation, deletion, policy activation, and any future model-data boundary.

## Safety and failure states

Retention must be an explicit positive integer. Allowing minimal real-user data requires
an explicit positive maximum-record ceiling; avoid-and-stop rejects that allowance rather
than retaining hidden stale authority. Unknown classifications and overlong redaction
rules deny draft construction. Redaction rules are instructions, not proof that stored or
exported content has been transformed.

This slice adds no evidence access, remote AI, storage destination, deletion, network,
grant, or execution behavior.

## Compatibility and rollback

Manifest v2 already defines these data-handling fields, so no schema or migration change
is required. Existing builder callers without a complete review retain avoid-and-stop,
seven-day retention, local encryption, and no remote AI. Rolling back the UI does not
alter persisted source, evidence, manifest, policy, retention, or deletion history.
