# ADR 0007: First local-model runtime and model

**Status:** Accepted
**Date:** 2026-09-01

## Context

Phase 2 requires one local-model adapter. The repository had provider provenance,
configuration snapshots, and inert metering prerequisites, but no concrete runtime or
model and no authorization-chain representation for local generation. ActionIntent v1
represents only supervised HTTP requests, so invoking a local model through it would
either misrepresent the effect or bypass the mandatory authorization chain.

## Decision

Select `llama.cpp` and
`Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M` for the first local boundary. Introduce
an additive pending ActionIntent v2 for `ai.local.generate` before implementing the
adapter. The intent contains hashes and bounded integer limits only; it contains no
prompt, response, path, URL, command, secret, authority, or execution enablement.

This slice does not claim that the runtime binary or model artifact is installed or
verified. A later adapter must authenticate its exact implementation and artifact and
may report only usage it directly observes. Initially that is request count and elapsed
runtime seconds; token and monetary usage need separate authoritative semantics.

## Consequences

- Local-first development does not add network, credential, or remote billing scope.
- Existing ActionIntent v1 producers and consumers are unchanged.
- No local execution is reachable until policy, grant, broker, process, receipt, and
  recovery boundaries are independently reviewed and composed.
- The exact model choice is deliberately narrow. Supporting another model or runtime
  requires an additive reviewed version rather than caller-selected substitution.
