# Local-model action-intent boundary v1

## Scope

This boundary selects `llama.cpp` with
`Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M` as the first concrete local
runtime/model pair. It adds an immutable capability manifest and converts one closed,
metadata-only agent request into a pending `ActionIntent` v2. It does not load a model,
accept prompt content, issue a policy decision or grant, or invoke the runtime.

The selection is local-first: it needs no remote credential, secret brokerage,
provider billing, or network authority. A future adapter may authoritatively observe
only request count and elapsed runtime seconds. Token and cost accounting remain
unsupported until a separately reviewed authoritative source exists.

## Authoritative inputs

- The exact runtime and model are constants owned by trusted core.
- Provider/model eligibility and integer ceilings come from the exact current inactive
  provider-configuration snapshot and its active registry lineage.
- Assessment, plan, task, policy, cancellation, and safety state come from current
  durable coordination records.
- The capability manifest is created by trusted core and binds those sources. Agent
  input can only request limits no greater than the manifest and configuration ceilings.
- `input_sha256` identifies future model input without storing prompt or context data.

## Persistence, replay, and recovery

Migration 0092 adds immutable manifest and request-to-intent lineage tables. Storage
triggers require the exact configuration and manifest binding and reject updates or
deletes. The service uses one immediate transaction, deterministic identities, exact
digest comparison, byte-equivalent replay, and changed-replay rejection. Startup
recovery creates or advances nothing; current cancellation, safety, policy, task, and
configuration state are revalidated on replay.

The existing `action_intents` table stores the pending ActionIntent v2. No policy
decision, approval, grant, execution trace, provider request, usage record, evidence,
or external effect is created.

## Compatibility and rollback

ActionIntent v1 and its network consumer remain unchanged. ActionIntent v2 is an
additive local-model-only version and has no execution consumer. Migration 0092 is
forward-additive and idempotent. Downgrading code leaves immutable unknown tables in
place; older code cannot interpret v2 as v1 or execute it. Rollback is therefore to
stop producing v2 while preserving history, not to delete records.

## Deferred work

Policy evaluation for `ai.local.generate`, an ActionGrant version, supervised
`llama.cpp` process composition, model/artifact verification, prompt handling,
authenticated execution receipts, request/runtime usage measurement, cancellation of
an executing process, reconciliation, budget finalization, evidence/reporting, and
Phase 2 demonstrations remain incomplete.
