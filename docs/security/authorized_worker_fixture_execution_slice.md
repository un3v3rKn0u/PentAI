# Phase 1 authorized worker HTTP fixture execution

**Status:** Implemented for the owned TEST-NET fixture; external execution remains disabled

## Outcome

PentAI can now bind the existing signed, single-use gateway fixture claim to one exact durable
attached worker before any worker process is invoked. The binding requires the claim, running
gateway container, attached worker/gateway identity, running worker container, and immutable
attachment version to agree. It is persisted and audited before the effect.

The worker transport uses OCI `exec` against that exact container and invokes only the
digest-pinned probe's existing signed-claim verifier. The destination, method, Host value, path,
response ceiling, and deadline remain fixed by the v2 claim. The gateway result is finalized
through the existing authority before the worker binding becomes complete. A crash or timeout
leaves durable recovery state; startup terminates the exact worker before recording failure.

## Compatibility and rollback

Migration `0033_worker_fixture_executions.sql` adds an independent immutable binding table and
one compatibility index. Existing gateway claims and results are unchanged. Older binaries
ignore the new records, so rollback must keep execution disabled until every prepared worker
fixture record is recovered by the newer binary.

This authorizes only the owned HTTP TEST-NET fixture. General HTTP(S), browser automation, and
external destinations remain prohibited.
