# Gateway Budget Reservations and Prepared Sessions

This slice creates durable gateway-session authority without enabling networking.
Preparation requires a current, unused, signed gateway grant and an immutable allowed
destination decision tied to a valid attestation. A single immediate database
transaction reserves one total request and one concurrent connection, persists the
reservation and session, and appends its audit event.

The same transaction now reserves one token from both the policy's global and
canonical-host token buckets. Buckets use the policy refill rates and burst capacity,
persist their last trusted wall-clock timestamp, and deny concurrent oversubscription
or clock rollback. A prepared session has not caused an external effect, so abort,
pause, stop, and startup recovery return its rate tokens without exceeding capacity.

## Safety properties

- Conditional counter updates prevent total-request or concurrency oversubscription.
- Unique grant and destination bindings prevent replay or duplicate reservations.
- Response capacity is the lower of policy and grant limits.
- Global and per-host rate tokens are reserved atomically with total and concurrency
  capacity; failure of either bucket rolls the complete transaction back.
- The canonical host comes from the immutable allowed destination decision, never a
  caller-supplied rate key.
- Prepared sessions carry `execution_enabled: false`; no transition can enable them.
- Abort releases reserved request/concurrency capacity but never erases history.
- Pause, stop, policy replacement/revocation, and startup recovery abort prepared
  sessions and release their outstanding reservations in the same safety transaction.
- Committed request counters cannot be released. The committed transition is deferred
  until an isolated gateway can prove an external action actually started.

## Compatibility and rollback

Migrations `0010_gateway_budget_reservations.sql` and
`0014_gateway_rate_reservations.sql` are additive. Existing grants and
destination decisions remain readable but gain no reservation automatically. Rollback
leaves immutable reservation/session history unused. It cannot restore revoked grants
or invalidated attestations. Older prepared reservations have no rate record and are
released compatibly; new code requires rate state for every new preparation.

## Deferred enforcement

Request-start token commitment, deadlines, actual response-byte accounting, gateway
sockets, atomic grant consumption at connection start, worker containment, and
active-session termination are deferred. This contract is not target-facing execution
authority.
