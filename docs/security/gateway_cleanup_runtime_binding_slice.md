# Phase 1 fixture cleanup runtime binding

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Fixture launches now bind their container identity to the durable gateway runtime ID,
pinned image digest, and managed internal network as fixed labels. Cleanup recovery reloads
those values by joining each unfinished execution claim to its immutable runtime record.

Removal requires all runtime bindings plus the existing PentAI ownership, fixed role, and
execution-claim labels to match exactly. Missing runtime history, invalid identities,
mutable image references, network mismatch, or partial labels pause global safety without
issuing deletion.

## Safety and compatibility

The host adapter derives every label from the validated execution claim; callers cannot
override them. Cleanup accepts additional runtime labels but requires the complete PentAI
binding set. Already-absent containers remain idempotent success.

This remains an owned TEST-NET proof. General transports require equivalent durable
runtime/effect binding and independently trustworthy runtime measurement before activation.
