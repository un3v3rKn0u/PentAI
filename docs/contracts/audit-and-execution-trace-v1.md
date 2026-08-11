# Audit event and execution trace v1

## AuditEvent

`AuditEvent` is the public representation of each privileged ledger row. Its hash is
calculated over event identity, time, actor, action, subject, canonical data, and the
previous event hash. Sequence is database-assigned and is verified separately so
removal or reordering fails validation.

Migration `0020_audit_execution_traces.sql` makes existing audit rows immutable,
denies deletion, and rejects inserts that do not extend the current chain head. Core
startup validates every row's contract, canonical hash, previous hash, and contiguous
sequence before recovery can append events or any supervisor can start. Malformed or
unverifiable legacy state denies startup.

## ExecutionTrace

An `ExecutionTrace` is created in the same transaction that finalizes the only enabled
effect: the isolated owned TEST-NET HTTP fixture. All identifiers are derived from
durable foreign-key joins, never from the finalization caller. The trace links:

- immutable action intent and deterministic policy decision;
- active policy bundle/hash and every evaluated rule identifier;
- consumed single-use grant and committed request start;
- one-use execution claim and digest-pinned runtime/tool version;
- immutable bounded gateway result as the output reference; and
- the finalization audit event.

The trace is content-hashed and database-immutable. It contains identifiers and
bounded accounting metadata, not response content, credentials, or evidence bodies.
`external_target_enabled` is fixed to false.

## Compatibility and rollback

Both contracts begin at `1.0.0` and reject unknown fields. Migration `0020` is
additive except for protections placed on the existing ledger; legitimate writers
already append at the current head and remain compatible. The new authenticated trace
route is additive. Application rollback may ignore retained traces, but the migration
must not be destructively reversed because doing so would remove tamper protections.

Future target-facing HTTP execution remains prohibited. Before it can be enabled, it
must produce an equivalent trace using a reviewed compatible contract version and
link evidence outputs without placing sensitive content in the audit ledger.
