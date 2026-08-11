# Gateway Response Accounting and Finalization

This slice completes the durable lifecycle for a committed, non-networking gateway
request. A bounded reader retains no more than the authorized response limit and
observes at most one additional byte as proof that the limit was crossed. It checks
the committed deadline before accepting every chunk and again at completion.

The core accepts only a typed internal measurement. In one immediate transaction it
re-derives deadline and byte-limit outcomes from durable authority, stores an immutable
`GatewayRequestResult`, closes the gateway session, releases exactly one concurrency
slot, and appends the audit event. The committed request and rate tokens remain
irreversible.

## Safety properties

- Missing, cancelled, closed, replayed, malformed, contradictory, or unverifiable
  accounting is denied without partial state changes.
- A completion at or after the committed deadline is always `deadline_exceeded`.
- A backward clock movement is untrusted and denies finalization input.
- An observed byte beyond the limit is always `response_limit_exceeded`; more than one
  proof byte is rejected as a gateway control failure.
- Completed responses must retain exactly the observed byte count. No response body is
  persisted by this contract. Partial and failed responses use the same accounting
  rule unless the single overflow proof byte caused finalization.
- Completion cannot predate the committed request start.
- Unique start/session/reservation/grant bindings prevent duplicate finalization.
- Result identity and accounting are immutable and cannot be deleted.
- Every result retains grant, reservation, session, start, deadline, and audit linkage.
- `execution_enabled` remains false throughout this slice.

## Compatibility and rollback

Migration `0016_gateway_request_results.sql` and contract
`gateway-request-result-v1.schema.json` are additive. Existing committed starts gain
no fabricated result. Older producers and readers remain compatible because no prior
table or contract changes. Rollback may stop producing results and leave the additive
history unused; it cannot safely reopen a closed session, restore a concurrency slot,
unconsume a grant, or refund committed request/rate capacity.

## Deferred enforcement

The reader is transport-independent and tests use only in-memory synthetic chunks. It
cannot interrupt a blocked transport by itself; the future isolated gateway must apply
the same absolute deadline to connect, TLS, writes, reads, and redirect handling. OCI
gateway HTTP sockets, TLS validation, controlled live resolution, response parsing,
evidence persistence, and target-facing effects remain prohibited and deferred.
