# Supervised Logs workspace

The Logs workspace is a read-only presentation layer over the authenticated `/audit`
endpoint. The core returns the append-only event sequence together with a fresh complete
hash-chain verification. An invalid verification result is rendered as an alert and the
UI explicitly warns that the displayed events must not be trusted.

Filtering is bounded to 128 characters and happens only in webview memory. It searches
the contract-defined event, action, actor, and subject identity fields; arbitrary event
`data` is neither searched nor rendered, reducing accidental disclosure of sensitive
operational detail. Selecting an event reveals its exact timestamp, identities, full
event hash, and previous hash without adding interpretation or authority.

The workspace cannot mutate, delete, replay, export, or submit events. It adds no API,
schema, migration, persistence, network, or execution behavior. Rollback restores the
previous compact audit presentation without affecting the immutable ledger.
