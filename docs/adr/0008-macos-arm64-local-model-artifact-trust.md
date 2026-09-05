# ADR 0008: macOS arm64 local-model artifact trust

**Status:** Accepted
**Date:** 2026-09-05
**Assurance:** Local development; sole-maintainer decision — non-independent

## Context

ADR 0007 fixes the first logical local-model pair to `llama.cpp` and
`Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M`, but deliberately leaves executable and
model identity unresolved. A logical runtime name, repository revision, local file,
or locally computed digest is not proof that an artifact is approved. Artifact
verification must have a closed, repository-approved source before it can be designed,
and verification itself must not grant permission to execute.

This decision is limited to macOS on Apple Silicon (`arm64`) for owned local
development. It does not approve distribution, production use, another platform,
artifact installation, ActionGrant v2, model loading, or process launch.

## Decision

### Runtime release and provenance

The approved upstream source is `ggml-org/llama.cpp`. The only approved runtime
release is:

- tag: `b10516`;
- source commit: `b95502ba9aa0eb73a2f4fc8878d7fbe6a847a0b9`;
- archive: `llama-b10516-bin-macos-arm64.tar.gz`;
- archive size: `11089823` bytes; and
- published archive SHA-256:
  `ee3324327d621026ae80c24031670e65fa62a0b23a3a027dbe2f65f240affd30`.

The release is non-prerelease but GitHub reports it as mutable. The Mach-O files have
ad-hoc linker signatures without an Apple Team ID. Neither property is a standalone
trust anchor. Approval is instead bound jointly to the exact source commit, official
release asset, published archive digest, this reviewed component manifest, and the
repository decision chronology. GitHub transport, a tag name, an ad-hoc signature, or
whatever happens to be installed is insufficient alone.

The approved entry point is the thin arm64 Mach-O `llama-cli`. Because it loads
adjacent `@rpath` libraries, the runtime artifact is the complete closed component set
below, not the launcher alone. Sizes and SHA-256 values were derived from the archive
only after its published digest matched.

| Installed regular-file name (archive source) | Bytes | SHA-256 |
|---|---:|---|
| `llama-cli` | 49960 | `e298c3bd3cfec99e62b2a7f091178a4799b44fafa5917fa226a05dac11d94dd6` |
| `libllama-cli-impl.dylib` | 394632 | `aaeb47a5a9367f7b72faf716936a9df67a3596bbfd529e1a6239803b0646b7c2` |
| `libllama-server-impl.dylib` | 9549112 | `5d55fc43a8c43f7cbe0848fbb8af033cb5c173fe5b5cd3b7f07cd277aba9dfdd` |
| `libmtmd.0.dylib` (`libmtmd.0.1.2.dylib`) | 1337744 | `afac5bf0760f4728034e94ce9543a17e17fd6063a116027e4fdec87112a0ecd6` |
| `libllama-common.0.dylib` (`libllama-common.0.1.2.dylib`) | 7931288 | `88a97aafdbb66c2f599252de37d0d0dcc1b8856c87865219220b9cfcb46538ca` |
| `libllama.0.dylib` (`libllama.0.1.2.dylib`) | 2911648 | `905c80dcdcf86c2eba9e5c16d57cefabbc5401b1a8eb135114f4cb609c270ae3` |
| `libggml.0.dylib` (`libggml.0.20.2.dylib`) | 59872 | `ba2c2e16d64f978cb1647b748dd38e22810209dcf893d6d58339a8585b5bc97e` |
| `libggml-base.0.dylib` (`libggml-base.0.20.2.dylib`) | 730280 | `6b8c464537103f8d84378cfd380c778d0caad7e688874fa31ec1153129639e51` |
| `libggml-cpu.0.dylib` (`libggml-cpu.0.20.2.dylib`) | 918064 | `8cb0168cc3103ae992ef52bbb50d4a942cfb058bdaf43041aae198cd58c038f2` |
| `libggml-blas.0.dylib` (`libggml-blas.0.20.2.dylib`) | 58776 | `fab45ce5b26a5b3d61b8b66507a3b0c5957b795ae7540c105f316c56ddcfabb6` |
| `libggml-metal.0.dylib` (`libggml-metal.0.20.2.dylib`) | 900968 | `639977e0cc973aa94ce62cf657fea904835c0de4281a8daa1b7c0d1465f152b1` |
| `libggml-rpc.0.dylib` (`libggml-rpc.0.20.2.dylib`) | 133792 | `a0338158f8be419186a11c0173116e3ee70ba9c55cd3165ecea93bce9146be90` |

The upstream archive uses symlink aliases for versioned libraries. Installation must
copy each table-named archive source's bytes directly to its table-named `@rpath`
regular-file destination. It must not install the versioned source name as a second
file. No symbolic link is approved. Omission, addition, duplicate aliases, or a
different dependency closure denies. Unreferenced generic aliases such as
`libllama.dylib` are not approved. Sealed macOS libraries under `/System/Library` and
`/usr/lib` are platform dependencies, not copied PentAI artifacts.

### Model identity and provenance

The only approved model artifact is:

- publisher/repository: `Qwen/Qwen2.5-Coder-3B-Instruct-GGUF`;
- immutable revision: `aebf6a0f72261b12fb8199bc580fe172fe86c901`;
- filename: `qwen2.5-coder-3b-instruct-q4_k_m.gguf`;
- format: GGUF version 3;
- quantization: `Q4_K_M`;
- exact size: `2104932800` bytes; and
- Hugging Face LFS SHA-256:
  `724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7`.

The revision, filename, size, and LFS digest come from Qwen's official Hugging Face
repository. A bounded read of that exact immutable blob confirmed GGUF magic and
little-endian version 3. A floating branch, selector such as `:Q4_K_M`, mirror,
alternate filename, locally converted file, or digest calculated for an unapproved
file is not authoritative.

### Location, ownership, and filesystem rules

The trusted root is the per-user macOS Application Support directory returned by the
native platform API, extended with `PentAI/artifacts`. It must not be accepted from an
environment variable, command-line option, caller, AI output, request, database row,
or unrestricted configuration. The closed layout beneath that root is:

```text
registry/<revision>/
runtime/llama.cpp/b10516/macos-arm64/
models/qwen2.5-coder-3b-instruct/aebf6a0f72261b12fb8199bc580fe172fe86c901/
```

The artifact root and all application-owned ancestors must be owned by the current
effective user with mode `0700`. Runtime files must be owned by that user with mode
`0500`; registry and model files use mode `0400`. Group/world write bits deny. Only
regular files with link count one are approved. Symlinks, hard links, Finder aliases,
directories in file positions, sockets, devices, FIFOs, path traversal, and writable
intermediate directories deny.

The first boundary supports only a local APFS volume. Network, removable, synthetic,
unknown, or unsupported filesystems deny. A future system-wide root or privileged
installer requires a new ADR.

### Bounded verification and stable identity

The future verifier must use repository-owned paths and open with read-only,
close-on-exec, and no-follow semantics. It must verify regular-file type, link count,
owner, mode, APFS location, exact component size, and digest through the already-open
descriptor. Hashing uses at most a 1 MiB buffer and checks cancellation between reads.
It must never map the entire model solely for verification.

The total runtime closure may not exceed 32 MiB. Each runtime component and the model
must equal its exact approved size; these exact sizes are tighter than the aggregate
ceiling. Unexpected EOF, extra bytes, short reads, truncation, malformed GGUF metadata,
unsupported GGUF version or quantization, or digest mismatch denies.

Device, inode, size, modification time, change time, and birth time where available
must remain stable before and after reading. Path metadata must still identify the
opened file where the platform supports that comparison. Modification, replacement,
or ambiguous filesystem semantics denies. A later launcher must consume the verified
open descriptor or another equally strong reviewed binding; a receipt naming a path
does not authorize reopening it.

### Governance and lifecycle

The repository owner acts as Product Owner, Principal Architect, Security Lead, AI/
Agent Lead, Core Maintainer, Contract Maintainer, and Security Reviewer under the
documented sole-maintainer exception. This decision is explicitly non-independent and
does not satisfy an external independence or dual-control requirement.

Future registry revisions are immutable and monotonically increasing, with exactly one
active revision. Activation, supersession, revocation, and rollback require a new
authenticated, dated owner/security decision. A review expires 180 days after
activation unless revoked earlier. Registry replacement or expiry immediately makes
older verification receipts stale. Rollback may select only an explicitly approved,
retained, unexpired, and non-revoked revision; it never silently falls back.

Startup and recovery create, activate, renew, or advance nothing. Missing or changed
artifacts deny and require fresh explicit verification against the current registry.
Interrupted or cancelled verification produces no receipt. Competing verification of
the same scope/revision must serialize; byte-identical replay may return the same
receipt only while every current lineage and file-identity check still passes.

## Security and compatibility consequences

- This ADR is the authoritative decision source for a future closed, code-owned
  artifact registry. The ADR is not itself runtime configuration and must not be parsed
  dynamically.
- Artifact identity, installation, hashing, or a verification receipt does not create
  policy approval, a grant, eligibility, availability, or execution authority.
- The mandatory `ActionIntent -> PolicyDecision -> ActionGrant -> supervised
  execution` chain is unchanged. ActionGrant v2 and execution remain absent.
- Existing ActionIntent v1/v2, PolicyDecision v1/v2, HTTP behavior, schemas, services,
  persistence, and migrations are unchanged.
- Upgrade requires another reviewed additive registry revision. Rollback or downgrade
  preserves this chronology but disables unsupported verification; it does not delete
  or reinterpret records.
- Persisted verification metadata must be bounded and contain no file contents,
  unrestricted paths, prompts, responses, credentials, signed download URLs, or
  arbitrary diagnostics.

## Deferred work

The code-owned registry contract and compiler, artifact installation, descriptor-based
runtime-closure and GGUF verification, immutable verification receipt, persistence,
startup reconciliation, ActionGrant v2, approval consumption, prompt handling, model
loading, process supervision, execution receipts, metering, accounting, and every
platform except macOS arm64 remain separately reviewed work.
