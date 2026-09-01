# Phase 2 slice security reviews

## 2026-09-01 — Pending local-model ActionIntent v2 boundary

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Additive contracts, trusted-core service, and migration 0092
select exactly `llama.cpp` with
`Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M`, create one immutable capability manifest,
and convert a closed metadata-only request into pending ActionIntent v2. Synthetic tests
cover exact success and replay, concurrency, changed replay, malformed and payload-
bearing requests, runtime/model substitution, stale scope, safety pause, limit widening,
and direct mutation. Contract validation, migration integrity and idempotency, lint,
typing, and repository tests are validation gates for this review.

**Dependency and trust decision:** Existing ActionIntent v1 can authorize only closed
HTTP methods and cannot truthfully represent local model generation. Implementing the
adapter first would bypass the required intent-to-grant chain. Trusted core therefore
owns the exact runtime/model/capability selection and derives configuration, registry,
assessment, plan, task, policy, and limit bindings from durable state. Caller data is
limited to a content digest and narrower integer limits and cannot assert implementation
truth or authority.

**Security, privacy, compatibility, and recovery:** The slice stores no prompt, context,
response, secret, path, URL, command, evidence, diagnostic, or arbitrary payload. It
creates no policy decision, approval, grant, provider request, process, network access,
usage record, budget mutation, or effect. ActionIntent v1 is unchanged; v2 is additive
and has no execution consumer. Immediate transactions, deterministic identities,
immutable storage guards, exact digests, and current-state replay checks deny competing,
changed, stale, cancelled, safety-paused, or cross-lineage use. Recovery creates and
advances nothing. Rollback stops v2 production while preserving immutable history.

**Findings, limitations, and residual risk:** No execution is enabled. Runtime and model
artifact verification, policy evaluation, ActionGrant, supervised process composition,
authenticated execution receipts, cancellation during execution, authoritative request
and elapsed-runtime measurement, accounting, evidence/reporting, remote adapter work,
Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance.

## 2026-08-31 — Manifest-bound runtime-meter production command verification

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Non-persisting trusted-core verification of runtime-meter
implementation command v2 against the authenticated local actor/session, trusted
timezone-aware clock, and exact package-owned manifest registry. Synthetic tests cover
exact internal lineage plus public empty-registry denial, authentication/session and
clock mismatch, stale and invalid windows, and manifest/registry/capability substitution.
The complete diff, contracts, invariants, compatibility, and Phase 2 ordering were
reviewed. No API, migration, storage guard, producer, receipt, or runtime path changes.

**Dependency and trust decision:** PR #253 made exact manifest lineage representable,
but representability alone did not verify it. This slice adds the verifier required
before a producer can be considered. Caller fields remain comparison values only; the
package-owned registry is authoritative. It is empty, so the public verifier cannot
succeed and production remains storage-denied.

**Security, privacy, compatibility, and recovery:** Malformed contracts, mismatched
authentication, invalid clocks, stale windows, unavailable artifacts, and any manifest,
registry, provider-type, or dimension substitution deny with stable codes. The verifier
returns only an existing compiled inert manifest and creates no receipt, capability,
identity, audit event, state transition, authority, or effect. It handles no credentials,
secret references, prompts, provider responses, evidence, usage, pricing, diagnostics,
or arbitrary payloads. No persistence, migration, replay, concurrency, cancellation,
fencing, downgrade, or recovery behavior changes.

**Findings, limitations, and residual risk:** No material finding remains for this
default-denying slice. A reviewed manifest instance, capability production and atomic
storage gating, audit/outbox linkage, identity production, attestation, provider
execution, measurement, accounting, finalization, dispatch, UI, runtime composition,
Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance.

## 2026-08-31 — Manifest-bound runtime-meter capability-production contracts

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Additive production command v2 and receipt v3 contracts bind one
exact manifest identity/revision/digest, implementation artifact digest, built-in
registry digest, implementation capability, authenticated local principal/session, and
bounded validity. Contract tests cover exact synthetic lineage, missing or malformed
bindings, mixed versions, authority escalation, and forbidden payloads. Compatibility
documentation, invariants, the Phase 2 dependency audit, and the complete diff were
reviewed. No API, service, persistence, migration, producer, or runtime path is added.

**Dependency and trust decision:** PR #252 made the code-owned registry the only trusted
manifest lookup source, but production command v1 and receipt v2 cannot bind that source.
The additive versions close that representational gap without reinterpreting old
contracts. Manifest fields in a request are still untrusted; a future producer must
derive them from the package-owned registry. That registry is empty, so production must
remain disabled.

**Security, privacy, compatibility, and recovery:** State and enablement fields remain
closed and non-authoritative. Unknown, missing, malformed, mixed-version, or payload-
bearing input denies. Contracts contain bounded identifiers, hashes, enums, versions,
and timestamps only; credentials, secret references, prompts, provider responses,
evidence, usage, pricing, tokenizer rules, diagnostics, and arbitrary payloads are
excluded. Command v1 and receipt v2 remain unchanged. No durable state, concurrency,
replay, cancellation, fencing, migration, downgrade, or recovery behavior is introduced.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. A reviewed real manifest, producer activation and exact storage gating, meter
identity production, attestation, provider execution, measurement, accounting,
finalization, dispatch, UI, runtime composition, Phase 2 demonstrations, and independent
review remain deferred. The sole maintainer accepts the reduced governance assurance.

## 2026-08-31 — Empty code-owned runtime-meter manifest registry

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Immutable code-owned empty registry, exact selector validation,
artifact-bound lookup, duplicate manifest and implementation/version denial,
order-independent registry digest, stable malformed/ambiguous/unavailable errors,
synthetic tests, compatibility documentation, invariants, Phase 2 dependency audit, and
complete diff. No schema, API, persistence, migration, or runtime producer is added.

**Dependency and trust decision:** PR #251 defined canonical manifest compilation but
supplied no trusted manifest source. Accepting compiled caller documents would preserve
the original trust flaw. This slice makes the repository-owned collection the only
public lookup source and intentionally leaves it empty because no real meter
implementation or reviewed capability claim exists.

**Security, privacy, compatibility, and recovery:** Public values are untrusted exact
selectors, never registration documents. Missing entries and artifact mismatches share
one unavailable result. The registry contains no credentials, secret references,
prompts, provider responses, evidence, targets, usage, pricing, tokenizers, or
diagnostics. It is immutable process code with no persistence, concurrency, replay,
cancellation, fencing, or recovery state. Rollback removes an unused empty boundary.

**Findings, limitations, and residual risk:** No material finding remains for this
default-deny slice. A real reviewed code-owned manifest instance, capability and identity
production, meter attestation, provider execution, measurement, accounting/finalization,
dispatch, UI, Phase 2 demonstrations, and independent review remain deferred. The sole
maintainer accepts the reduced governance assurance for this scope.

## 2026-08-31 — Runtime-meter implementation manifest v1 prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Closed runtime-meter implementation-manifest v1 contract,
deterministic trusted-core compiler, canonical ordering and digest derivation, synthetic
positive/default-deny tests, compatibility documentation, invariants, Phase 2 dependency
audit, and complete diff. No API, persistence, migration, or runtime producer is added.

**Dependency and trust decision:** PR #250 reserved authenticated source and replay
provenance but correctly left capability production denied because authentication does
not prove implementation behavior. This slice defines the canonical artifact-bound
manifest shape a later code-owned registry must supply. Caller documents remain
untrusted, and no manifest instance is declared by this slice.

**Security, privacy, compatibility, and recovery:** The contract stores only bounded
identifiers, a revision, artifact digest, closed enums, and fixed inactive constants. It
excludes credentials, secret references, prompts, provider responses, evidence, targets,
usage, pricing, tokenizers, and diagnostics. Compilation deep-copies and canonicalizes
input without persistence or effects. The additive contract/module can be removed
without data migration; recovery has no durable state to invent or resume.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. A reviewed code-owned manifest instance and registry, capability production,
identity production, meter attestation, provider execution, measurement, accounting/
finalization, dispatch, UI, Phase 2 demonstrations, and independent review remain
deferred. The sole maintainer accepts the reduced governance assurance for this scope.

## 2026-08-31 — Runtime-meter implementation production inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Closed runtime-meter implementation production command v1 and
source-bound receipt v2 contracts, additive migration 0091, deny-all producer and
immutable update/delete guards, exact implementation/provider-type/dimension and local
principal/session binding, synthetic positive/default-deny contract tests, fresh/
additive/idempotent migration tests, compatibility documentation, invariants, Phase 2
dependency audit, and complete diff.

**Dependency and trust decision:** PR #247 established an inert capability shape, but no
authoritative built-in manifest or runtime verifier establishes an implementation's
actual supported provider types and dimensions. This slice reserves authenticated
source and replay provenance only. Authentication does not establish implementation
truth, so capability and identity production remain storage-denied.

**Security, privacy, compatibility, and recovery:** Contracts store bounded identifiers,
closed enums, versions, digests, source identity, and timestamps only. They exclude
credentials, secret references, prompts, provider responses, evidence, targets, usage,
pricing, tokenizers, and diagnostics. Migration 0091 is additive and empty; older
applications ignore it, destructive downgrade after future rows exist is unsupported,
and recovery has no producer from which to invent capability state.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. Authoritative manifest verification, capability production, identity production,
meter attestation, provider execution, measurement, accounting/finalization, dispatch,
UI, Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance for this scope.

## 2026-08-31 — Runtime-meter implementation v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Closed runtime-meter implementation capability and receipt v1
contracts, additive migration 0090, deny-all producer and immutable update/delete
guards, closed provider types and dimensions, synthetic positive/default-deny contract
tests, fresh/additive/idempotent migration tests, compatibility documentation,
invariants, Phase 2 dependency audit, and complete diff.

**Dependency and trust decision:** PR #246 reserved an authenticated meter-identity
production command, but no trusted source establishes which implementation/version may
claim which provider types or dimensions. Activating identity production would otherwise
trust caller-selected capability claims. This slice reserves only the inert capability
shape; authenticated capability and identity production remain separate reviews.

**Security, privacy, compatibility, and recovery:** Contracts store bounded identifiers,
closed enums, versions, digests, and timestamps only. They exclude credentials, secret
references, prompts, provider responses, evidence, targets, usage, pricing, tokenizers,
and diagnostics. Migration 0090 is additive and empty; older applications ignore it,
destructive downgrade after future rows exist is unsupported, and recovery has no
producer from which to invent capability state.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. Authenticated capability production, identity production, meter attestation,
provider execution, measurement, accounting/finalization, dispatch, UI, Phase 2
demonstrations, and independent review remain deferred. The sole maintainer accepts the
reduced governance assurance for this scope.

## 2026-08-30 — Runtime-meter identity production inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Closed runtime-meter production command v1 and source-bound
receipt v2 contracts, additive migration 0089, deny-all producer and immutable
update/delete guards, exact configuration/provider/model and worker/runtime provenance,
closed dimensions, synthetic positive/default-deny contract tests, fresh/additive/
idempotent migration tests, compatibility documentation, invariants, and complete diff.

**Dependency and trust decision:** PR #245 reserved the inactive identity and storage
shape, but repository evidence provides no authenticated production command or replay-
fenced source lineage. This slice reserves only that narrower prerequisite. The future
producer must derive the local principal/session and revalidate current configuration,
worker, containment, cancellation, safety, fencing, and recovery state atomically.

**Security, privacy, compatibility, and recovery:** Contracts bind identifiers, digests,
closed enums, positive versions, and timestamps only. They exclude credentials, secret
references, prompts, provider responses, evidence, targets, usage values, pricing,
tokenizer rules, and diagnostics. Migration 0089 is additive and empty; rollback leaves
an ignored table, destructive downgrade after future rows exist is unsupported, and
recovery has no producer from which to invent state.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. Authenticated identity production, meter attestation, provider execution,
measurement, accounting/finalization, dispatch, UI, Phase 2 demonstrations, and
independent review remain deferred. The sole maintainer accepts the reduced governance
assurance for this scope.

## 2026-08-30 — Runtime-meter identity v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Closed runtime-meter identity and receipt v1 contracts, additive
migration 0088, deny-all producer and immutable update/delete guards, exact configuration-
snapshot and worker-runtime provenance fields, closed supported-dimension names,
synthetic positive/default-deny contract tests, fresh/additive/idempotent migration tests,
compatibility documentation, security invariants, and complete diff.

**Dependency and trust decision:** PR #244 made exact inactive provider-configuration
snapshots durable through an authenticated trusted-core producer. Provider-usage v1
requires a `trusted_runtime_meter`, but no durable meter identity exists. This slice
reserves only the identity shape and persistence boundary; production and attestation
remain denied because repository evidence does not yet define their authenticated
command, lifecycle, or provider-behavior semantics.

**Security, privacy, compatibility, and recovery:** The contracts bind implementation,
configuration snapshot, provider/model, worker/runtime version, containment, image,
closed dimensions, and validity while fixing state inactive and all capability flags
false. They exclude credentials, secret references, prompts, provider data, evidence,
targets, diagnostics, usage values, pricing, and arbitrary payloads. Migration 0088 is
additive and empty; rollback leaves an ignored empty table, destructive downgrade is
unsupported, and recovery has no producer from which to invent state.

**Findings, limitations, and residual risk:** No material finding remains for this inert
slice. Authenticated identity production, meter attestation, configuration binding,
provider execution receipts, pricing/tokenizer/cache/streaming/retry semantics, usage
production, reconciliation/finalization, dispatch, UI, Phase 2 demonstrations, and
independent review remain deferred. The sole maintainer accepts the reduced governance
assurance for this scope.

## 2026-08-30 — Authenticated provider-configuration snapshot production

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, and security
reviewer under the `GIT_WORKFLOW.md` exception. This review is not independent and does
not satisfy dual control.

**Scope and evidence:** Trusted-core configuration-snapshot producer, authenticated
local API composition, migration 0087 exact current-lineage and paired-production
storage predicates, immutable metadata-only audit/outbox linkage, synthetic remote and
local success, replay, concurrency, provider/model, secret revocation, safety,
direct-storage, API, migration, contract, static-analysis, and repository-wide tests,
compatibility documentation, security invariants, threat-model update, and complete diff.

**Dependency and trust decision:** PR #243 supplied the closed source-bound command and
receipt contracts plus an inert deny-all production ledger. Current repository evidence
already supplies authenticated registry production and activation, deterministic policy
compilation, provider-configuration validation, and opaque secret-reference validation.
The selected slice composes only those existing boundaries. The middleware principal
and process session are authoritative; callers cannot select identity, digest, state,
policy meaning, privilege, meter eligibility, or authority.

**Security, privacy, compatibility, and recovery:** Production atomically revalidates
the exact current activation, registry snapshot/receipt digests, provider/model route,
privacy classifications, integer ceilings, validity, safety state, and remote secret
metadata. Only a digest of an opaque secret reference is durable; credentials, prompts,
provider content, evidence, targets, diagnostics, paths, URLs, and arbitrary payloads
remain excluded. Migration 0087 changes only additive producer guards; rollback leaves
immutable rows readable but disables production in older code, and destructive downgrade
is unsupported. Startup recovery cannot invent or resume production.

**Findings, limitations, and residual risk:** No material finding remains for this
non-executing slice. Registry supersession/revocation, secret resolution, meter identity,
provider adapters/execution, pricing/tokenizer semantics, usage measurement,
reconciliation/finalization, dispatch, UI, Phase 2 demonstrations, and independent review
remain deferred. The sole maintainer accepts the reduced governance assurance for this
scope.

## 2026-08-30 — Provider-configuration snapshot production inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, and security reviewer under the
`GIT_WORKFLOW.md` exception. This review is not independent and does not satisfy dual
control.

**Scope and evidence:** Closed provider-configuration snapshot production command v1
and receipt v2 contracts, additive migration 0086, deny-all producer and immutable
update/delete guards, exact registry activation and snapshot-production lineage,
remote secret-reference digest or local absence, synthetic positive/default-deny and
migration tests, compatibility documentation, security invariants, and the complete
diff.

**Dependency and trust decision:** PR #242 made one exact latest registry snapshot
current without enabling downstream behavior. The pre-existing configuration snapshot
v1 contracts do not authenticate a producer, bind command replay identity, or name the
activation receipt that authorizes provenance selection. Enabling their producer would
therefore leave security-critical lineage implicit. This slice reserves that lineage
and source authentication only; production remains storage-denied.

**Security, privacy, compatibility, and recovery:** The contracts exclude caller-
selected activation state, privilege, authority, raw secret references, credentials,
prompts, provider content, evidence, targets, diagnostics, and arbitrary payloads. V1
configuration and snapshot contracts remain unchanged. Migration 0086 is additive and
empty, direct insertion and mutation deny, rollback leaves an unused inert table, and
startup recovery has no producer to invent or resume work.

**Findings, limitations, and residual risk:** No material finding remains for this
inert slice. Authenticated configuration production, registry supersession/revocation,
secret resolution, meters, provider execution, measurement/accounting, dispatch, UI,
Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance for this scope.

## 2026-08-30 — Authenticated provider-registry activation v1

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Authenticated local API composition, trusted-core activation
service, migration 0085 exact storage predicate, immutable audit/outbox linkage,
synthetic success, replay, concurrency, latest-revision, safety, source, API,
direct-storage, migration, contract, and repository-wide validation, documentation,
security invariants, and the complete diff.

**Dependency and trust decision:** PR #241 supplied closed activation contracts and an
inert ledger. PR #240 supplies exact authenticated immutable snapshot production.
Together they permit the narrow consumer to derive every lineage field from storage.
The conservative lifecycle rule allows no competing unexpired activation; replacement,
supersession, and revocation semantics remain deferred rather than inferred.

**Security, privacy, compatibility, and recovery:** Middleware derives principal and
session. Trusted core revalidates snapshot and production receipt hashes, registry
expiry, latest revision, safety, and global activation availability in one immediate
transaction. The record remains metadata-only, non-authoritative, immutable, and
non-executing. It excludes credentials, secret references, prompts, provider output,
evidence, targets, diagnostics, and arbitrary payloads. Migration 0085 preserves rows
and replaces only the producer-denial trigger; application rollback preserves records
but cannot create new ones.

**Findings, limitations, and residual risk:** No material finding remains for this
slice. Explicit revocation, replacement before expiry, expiry recovery,
configuration-snapshot production, meters, provider execution, measurement/accounting,
dispatch, UI, demonstrations, and independent review remain deferred. The sole
maintainer accepts the reduced governance assurance for this scope.

## 2026-08-30 — Provider-registry activation v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed activation command/receipt v1 contracts, additive
migration 0084, deny-all producer and immutable update/delete guards, exact snapshot-
production lineage, contract and migration negative tests, compatibility documentation,
security invariants, and the complete diff.

**Dependency and trust decision:** PR #240 authenticated and persisted inactive registry
snapshots, but repository evidence requires an exact current activated registry before
configuration-snapshot production. Lifecycle production, concurrency, supersession,
revocation, and recovery composition are not yet defined strongly enough to activate
one. This slice therefore reserves only the versioned identity and inert persistence
boundary.

**Security, privacy, compatibility, and recovery:** The contracts bind snapshot and
production-receipt digests, registry revision and canonical digests, authenticated local
principal/session, purpose, and validity while excluding secrets, provider content,
diagnostics, and arbitrary payloads. Direct insertion, update, and deletion deny. The
additive empty migration leaves all earlier contracts and rows unchanged; rollback
leaves an unused table and destructive downgrade is unsupported.

**Findings, limitations, and residual risk:** No material finding remains for this
inert slice. Activation production, one-current-active enforcement, supersession,
revocation, expiry recovery, configuration snapshots, meters, provider execution,
measurement/accounting, dispatch, UI, demonstrations, and independent review remain
deferred. The sole maintainer accepts the reduced governance assurance for this scope.

## 2026-08-30 — Authenticated provider-registry snapshot production

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Authenticated local API composition, deterministic trusted-core
snapshot production, migration 0083 cross-ledger storage predicates, monotonic revision
and replay fencing, immutable audit/outbox linkage, synthetic positive, malformed,
privacy, stale, concurrency, safety, migration, authentication, and direct-storage tests,
compatibility documentation, and the complete diff.

**Dependency and trust decision:** PR #238 reserved server-derived source identity and
the inert production ledger; PR #239 supplied the canonical registry/provider digests.
Those merged prerequisites allow one current registry to be recorded without inventing
activation or signing governance. The endpoint accepts no actor, session, digest,
snapshot state, privilege, or authority claim. Middleware supplies identity and trusted
core derives all persisted security-critical values.

**Security, privacy, compatibility, and recovery:** One immediate transaction inserts
the source-bound production record and matching inactive snapshot under deferred foreign
key and exact storage predicates. Equal/lower competing revisions, changed or
cross-session replay, stale or unsafe registries, global safety pause, and orphan or
direct snapshot writes deny. Records and audit/outbox linkage contain bounded metadata
only and remain `authority: none` and `execution_enabled: false`. No credential, secret
reference, prompt, response, evidence, diagnostic, provider call, network access, or
effect is created. Existing contracts remain version-compatible; rollback leaves
immutable inactive records that older code cannot produce or activate.

**Findings, limitations, and residual risk:** No material finding remains for this
slice. Registry signing governance, activation, revocation, supersession, configuration
snapshots, meter identity, adapters, provider execution, usage/accounting, dispatch,
agents/plugins/UI, Phase 2 demonstrations, and independent review remain deferred. The
sole maintainer accepts the reduced governance assurance for this scope.

## 2026-08-30 — Provider-registry canonical digest prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Pure registry normalization and digest derivation, existing
registry validation and canonical JSON/SHA-256 primitives, synthetic order-equivalence,
semantic-substitution, default-deny, and mutation-isolation tests, compatibility
documentation, security invariants, and the complete diff.

**Dependency and trust decision:** PR #238 supplied authenticated source identity but
left canonical normalization undefined. Snapshot production cannot safely compare its
command, normalized provider list, and complete registry until those digests have one
trusted algorithm. This slice therefore sorts the closed ASCII provider, model, and
classification identifiers only after existing validation succeeds and adds no
persistence or producer behavior.

**Security, privacy, compatibility, and recovery:** Malformed, stale, future-dated,
overlong, duplicate, all-disabled, privacy-unsafe, and execution-enabled registries keep
their existing stable denials. Equivalent ordering produces identical provenance;
semantic changes alter the applicable digest. Inputs are deep-copied. No credentials,
secret references, prompts, responses, evidence, diagnostics, arbitrary payloads,
authority, network access, or durable state are introduced. Existing contracts,
migrations, callers, and recovery behavior remain unchanged; rollback is code-only.

**Findings, limitations, and residual risk:** No material finding remains for this pure
prerequisite. Authenticated producer composition, monotonic revision and rollback/fork
enforcement, source-signing governance, snapshot persistence, activation, revocation,
configuration snapshots, meters, provider execution, measurement, accounting, dispatch,
UI, Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance for this scope.

## 2026-08-29 — Provider-registry snapshot production authentication prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed authenticated production-command v1 and source-bound
receipt v2 contracts, additive migration 0082, deny-all producer enforcement, immutable
update/delete guards, compatibility documentation, and synthetic contract, migration,
storage-denial, integrity, and foreign-key tests.

**Dependency and trust decision:** Registry snapshot v1 lacks authenticated command and
source identity. The repository already derives a local desktop principal and
per-process session from authenticated local-core transport, so this slice reserves that
existing identity without creating new signing authority. ADR 0003's policy/approval
signer is not widened, and registry documents remain unsigned. Canonical normalization,
monotonic revision enforcement, and actual production remain separately reviewed work.

**Security, privacy, and compatibility:** No production record can be inserted. The
contracts and storage exclude registry documents, credentials, secret references,
private keys, signatures, prompts, contexts, provider responses, evidence, targets,
diagnostics, commands, paths, URLs, and arbitrary payloads. Registry and snapshot v1
behavior remains unchanged; receipt v2 is additive and unusable as receipt v1.
Application rollback leaves an empty additive table; destructive downgrade is
unsupported.

**Findings, limitations, and residual risk:** No material finding remains for this inert
prerequisite. Authenticated producer composition, source/signing governance, canonical
normalization, monotonicity and rollback enforcement, activation, revocation,
configuration-snapshot production, meter identity, provider execution, measurement,
accounting, dispatch, UI, demonstrations, and independent review remain deferred. The
sole maintainer accepts the reduced governance assurance for this prerequisite.

## 2026-08-29 — Provider-registry snapshot v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed provider-registry snapshot and receipt contracts,
migration 0081, deny-all producer enforcement, immutable update/delete guards, exact
registry/provider/model digest provenance, compatibility documentation, and synthetic
contract, migration, storage-denial, integrity, and foreign-key tests.

**Dependency and trust decision:** Provider registry v1 is only a pure compiler. PR
#236 reserved configuration-snapshot storage, but its future producer cannot safely
bind a transient caller registry. This slice therefore reserves an inactive normalized
registry snapshot and does not invent activation, revocation, signature authority,
meter identity, adapter behavior, pricing, tokenizer, or accounting semantics.

**Security, privacy, and compatibility:** No snapshot can be produced. Contracts and
storage exclude credentials, secret references, prompts, contexts, provider responses,
evidence, targets, diagnostics, pricing, tokenizer rules, commands, paths, URLs, and
arbitrary payloads. Existing registry/configuration validators and all completion,
reservation, configuration-snapshot, and measurement behavior remain unchanged.
Application rollback leaves an empty additive table; destructive downgrade is
unsupported.

**Findings, limitations, and residual risk:** No material finding remains.
Authenticated snapshot production, source/signature verification, activation,
revocation, rollback protection, configuration-snapshot production, meter identity,
adapter receipts, provider execution, measurement, reconciliation, finalization,
dispatch, runtime composition, UI, demonstrations, and independent review remain
deferred. The sole maintainer accepts the reduced governance assurance for this inert
prerequisite.

## 2026-08-29 — Provider-configuration snapshot v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed provider-configuration snapshot and receipt contracts,
migration 0080, deny-all producer enforcement, immutable update/delete guards, exact
registry/configuration/provider/model provenance, compatibility documentation, and
synthetic contract, migration, storage-denial, integrity, and foreign-key tests.

**Dependency and trust decision:** Current repository code validates provider
configuration and registry policy but has no durable active configuration, provider
adapter, authenticated execution receipt, or runtime meter. This slice therefore
reserves only inactive provenance needed by a future meter and does not activate the
PR #235 measurement producer or invent pricing, tokenizer, cache, streaming, retry,
partial-request, cancellation, or failure accounting semantics.

**Security, privacy, and compatibility:** The contracts and storage exclude raw secret
references and values, prompts, contexts, provider responses, evidence, targets,
diagnostics, pricing, tokenizer rules, commands, paths, URLs, and arbitrary payloads.
Existing pure configuration/registry contracts and all completion, reservation, and
measurement behavior remain unchanged. Application rollback leaves an empty additive
table; destructive downgrade is unsupported.

**Findings, limitations, and residual risk:** No material finding remains. Authenticated
snapshot production, registry activation, meter identity/attestation, adapter execution
receipts, provider execution, usage production, reconciliation, reservation closure,
dispatch, runtime composition, UI, exit demonstrations, and independent review remain
deferred. The sole maintainer accepts the reduced governance assurance for this inert
prerequisite.

## 2026-08-29 — Attempt-three provider-usage v1 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed integer-only usage measurement and receipt contracts,
migration 0079, deny-all producer enforcement, immutable update/delete guards,
completion/reservation/account lineage, compatibility documentation, and synthetic
contract, migration, storage-denial, integrity, and foreign-key tests.

**Dependency and trust decision:** The durable assessment budget account and attempt-
three reservation are authoritative capacity sources, but the repository has no trusted
provider adapter or runtime usage meter. Completion is coordination evidence only.
Accordingly this slice reserves an inert shape and does not accept caller amounts,
fabricate usage, reconcile/debit capacity, or finalize/release the reservation.

**Security, privacy, and compatibility:** The contracts exclude retry units, provider
responses, prompts, evidence, artifacts, findings, diagnostics, targets, credentials,
tokens, commands, paths, URLs, caller prices, and arbitrary payloads. Earlier completion,
reservation, and in-memory AI ledger behavior remains unchanged. Application rollback
leaves an empty additive table; destructive downgrade is unsupported.

**Findings, limitations, and residual risk:** No material finding remains. Trusted
metering, production, reconciliation, debit/settlement, partial-use semantics, budget
finalization, provider execution, dispatch, evidence/reporting, runtime composition, UI,
Phase 2 demonstrations, and independent review remain deferred. The sole maintainer
accepts the reduced governance assurance for this inert prerequisite.

## 2026-08-29 — Attempt-three completion consumption v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Dedicated trusted-core completion consumption, migration 0078,
exact lease-consumption/checkpoint/current-state storage binding, attempt-three generic-
transition fencing, immutable receipt/audit/outbox linkage, contract and compatibility
documentation, and synthetic positive, malformed, mixed-version, replay, concurrency,
security-fence, migration, and storage-bypass tests.

**Security boundaries:** Completion accepts only the exact current running attempt-three
lineage and checkpoint head or complete absence. Policy, assessment, safety, worker,
manifest, reservation/account, lease fence, and recovery state are revalidated in one
immediate transaction. The receipt precedes and storage-gates only the bound success
edge. No output, evidence, provider/plugin data, budget mutation, retry, dispatch,
network, target, ActionIntent, PolicyDecision, ActionGrant, authority, or effect exists.

**Compatibility and state composition:** Earlier-attempt general success remains
available; a generic attempt-three success is denied in trusted core and storage.
Existing graph rules deterministically recompute dependent readiness and set the plan
completed only when every task succeeds. Application rollback disables new consumption
while retaining immutable receipts and the stricter attempt-three storage fence.
Destructive downgrade is unsupported.

**Privacy and recovery:** Durable data is limited to bounded identifiers, hashes,
integers, timestamps, and closed constants. Secrets, raw lease tokens, targets,
assessment content, evidence, prompts, diagnostics, commands, paths, URLs, and arbitrary
payloads are excluded. Recovery cannot invent, duplicate, consume, complete, dispatch,
or resume a completion.

**Findings, limitations, and residual risk:** No material finding remains. Provider-
usage reconciliation, budget finalization, evidence/findings/reporting, worker dispatch,
runtime composition, dead-letter processing, operator workflows, UI, Phase 2 exit
demonstrations, and independent review remain deferred. The sole maintainer accepts the
reduced governance assurance for this narrow non-executing slice.

## 2026-08-29 — Attempt-three completion v3 inert prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This is not independent review and does not satisfy dual control.

**Scope and evidence:** Additive closed completion-v3 command/receipt contracts,
migration 0077, deny-all producer enforcement, immutable update/delete guards,
contract/migration tests, compatibility documentation, and repository-wide security
invariant review. The boundary accepts no output or arbitrary payload and fixes
authority to none and execution to false.

**Dependency decision:** Phase 2 repeatedly identifies successful completion as an
unimplemented sibling of typed failure consumption. The new dead-letter registration
has no authoritative transport, processing, cleanup, or operator-review semantics, so
this slice does not invent them. The selected completion prerequisite is narrower than
a producer: it only reserves version-exact durable shapes for later review.

**Threat review:** Mixed attempts or versions, attempt four, partial checkpoint tuples,
caller-controlled success meaning, output/evidence injection, privilege expansion, and
direct storage production deny. The producer-disabled trigger prevents runtime creation;
immutable guards prevent later mutation or deletion. Existing task/plan state and the
general transition service are unchanged and do not constitute completion-v3 evidence.

**Compatibility, privacy, and rollback:** Existing graph, retry, failure, terminal, and
dead-letter contracts and rows remain unchanged. Only bounded identifiers, hashes,
integers, timestamps, and closed constants are representable. Application rollback
leaves an empty inert table; destructive downgrade is unsupported. A cross-version
attempt-table foreign key is intentionally deferred to the exact future transactional
predicate because adding it caused SQLite parent-key compatibility failures in existing
attempt-three lifecycle tests.

**Findings, limitations, and residual risk:** No independent reviewer participated.
Completion production/consumption, exact storage gating, dependent readiness, plan
completion, budget/provider reconciliation, worker/runtime composition, queue
processing, operator workflows, UI, and Phase 2 demonstrations remain deferred.

## 2026-08-29 — Attempt-three dead-letter registration v1

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Closed registration contracts, migration 0076 immutable storage
guards, trusted-core current-lineage validation, deterministic identity, replay and
concurrency behavior, metadata-only audit/outbox linkage, migration tests, synthetic
positive/default-deny tests, and authorization/privacy boundary review.

**Security boundaries and default deny:** Only the exact current attempt-three terminal-
consumption receipt and authoritative dead-letter task revision can produce one record.
Malformed or mixed versions, caller queue semantics, changed replay, competing
registration, tampered or cross-scope lineage, stale security state, cancellation,
safety pause, worker revocation, fencing changes, and recovery advancement deny. Task
and plan state remain unchanged.

**Compatibility, privacy, migration, and rollback:** The older workflow queue and all
historical orchestration contracts remain unchanged and cannot satisfy this boundary.
Migration 0076 is additive; application rollback disables new registrations while
retaining immutable history, and destructive migration reversal is unsupported. Records
contain bounded identifiers, hashes, closed enums, revisions, and timestamps only—no
secrets, tokens, targets, evidence, prompts, diagnostics, queue/operator payloads, or
provider/plugin output.

**Findings, limitations, and residual risk:** Delivery, claiming, acknowledgement,
retry/deletion/cleanup, operator workflows, completion, dispatch, runtime composition,
providers/plugins, UI, exit demonstrations, and independent review remain deferred.
The non-independent governance risk is accepted only for this non-executing metadata
registration boundary.

## 2026-08-29 — Attempt-three terminal-disposition consumption v1

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Dedicated terminal consumer, migration 0075 producer and exact
task-version predicates, immutable receipt/audit/outbox handling, snapshot-v2
composition, replay and concurrency behavior, migration upgrades, synthetic positive
and default-deny tests, and complete authorization/privacy boundary review.

**Security boundaries and default deny:** Only one exact current attempt-three terminal
decision can create a receipt and advance its bound task from `failed` to `dead_letter`.
The consumer reuses failure-v3 current-security validation across policy, cancellation,
safety, worker, manifest, budget/account, checkpoint, fencing, and recovery state.
General transitions, direct unbacked updates, changed replay, competing consumption,
stale lineage, and mixed versions deny. Plan state/revision remain unchanged.

**Compatibility, privacy, migration, and rollback:** V1/v2/v3 historical lineage and
plan-graph v1 are unchanged. Legacy graph reads fail closed on reachable dead-letter
state; task snapshot v2 is the compatible reader. Migration 0075 is additive but cannot
be safely downgraded after consumption because migration 0074 predecessors cannot
represent the row. Receipts and events contain bounded identifiers, hashes, closed
enums, revisions, and timestamps only; no secrets, tokens, targets, evidence, prompts,
diagnostics, queue/operator payloads, or provider/plugin output are accepted.

**Findings, limitations, and residual risk:** Queue creation/processing, operator review,
completion, dispatch, runtime composition, providers/plugins, UI, exit demonstrations,
and independent review remain deferred. The non-independent governance risk is accepted
only for this non-executing coordination transition.

## 2026-08-29 — Version-exact orchestration task snapshot v2

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Additive task-snapshot v2 contract, read-only trusted-core
serializer, exact terminal-consumption lineage validation, v1 compatibility
documentation, synthetic contract/service tests, and complete authorization and privacy
boundary review.

**Security boundaries and default deny:** State is read only from the authoritative
task table. `dead_letter` requires one matching terminal-consumption receipt with a valid
contract, stored hash, self-digest, decision identity/digest, scope, and revisions.
Missing, ambiguous, malformed, tampered, mixed-version, and cross-scope lineage denies.
The reader performs no write, transition, audit/outbox append, recovery action, queue
operation, notification, dispatch, authority creation, or effect.

**Compatibility, privacy, and rollback:** Plan-graph v1 remains unchanged. The new
contract is a separate opt-in read model; rollback removes only the reader and schema and
changes no database. Snapshots exclude objectives, input references, evidence, prompts,
diagnostics, secrets, tokens, targets, commands, paths, URLs, and provider/plugin output.

**Findings, limitations, and residual risk:** Terminal consumption and its exact
`failed → dead_letter` predicate remain deferred, as do queueing, operator review,
completion, dispatch, runtime composition, providers/plugins, UI, exit demonstrations,
and independent review. The non-independent governance risk is accepted only for this
read-only prerequisite.

## 2026-08-29 — Authoritative dead-letter state representation

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Migration 0074's verified reconstruction of only
`orchestration_tasks`; complete synthetic row, column, constraint, key, foreign-key,
index, trigger, dependent-reference, interruption, integrity, upgrade, and idempotency
tests; ADR and compatibility updates; and review of all state readers and transition
guards.

**Security boundaries and default deny:** `orchestration_tasks.state` remains the sole
authoritative source. The migration adds only representability of `dead_letter`. A new
insert guard denies direct creation, the unchanged version fence denies
`failed → dead_letter`, the general transition service cannot request it, and the PR
#227 terminal-consumption producer remains deny-all. No task/plan row, revision, event,
queue item, notification, authority, or effect is created.

**Compatibility, privacy, migration, and rollback:** Plan-graph v1 is not silently
widened because no reachable runtime row can yet contain the new state; an additive read
contract is required before a later consumer enables it. The rebuild runs atomically
under ADR 0006 and verifies integrity and foreign keys before commit. Synthetic fixtures
contain no secrets, tokens, targets, evidence, prompts, diagnostics, or external data.
Downgrade is unsupported once a future consumer persists the new value.

**Findings, limitations, and residual risk:** Terminal consumption, its versioned runtime
read contract and exact transition predicate, queueing, operator review, completion,
dispatch, runtime composition, providers/plugins, UI, exit demonstrations, and
independent review remain deferred. The non-independent governance risk is accepted only
for this inert state-representation prerequisite.

## 2026-08-29 — Verified SQLite table-rebuild protocol

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Migration-runner transaction handling, an explicit rebuild
directive and filename rule, forbidden migration controls, pre-commit SQLite integrity
and foreign-key verification, rollback/restoration behavior, ADR 0006, compatibility
documentation, and synthetic row/reference/index/trigger preservation and failure tests.

**Security boundaries and default deny:** The protocol changes no schema itself. Only an
explicit `_table_rebuild.sql` migration with the exact first-line directive can enter
the controlled mode. Rebuild SQL cannot control foreign-key enforcement, use
`writable_schema`, or commit itself. Integrity or foreign-key mismatch denies before the
migration version commits, and enforcement is restored after success or failure.

**Compatibility, privacy, migration, and rollback:** Ordinary migrations retain their
existing behavior. No task rows, contracts, state sets, triggers, indexes, or foreign
keys are changed by this slice. Tests use synthetic integer records and contain no
secrets, evidence, targets, prompts, tokens, diagnostics, or external data. Reverting
the code removes future rebuild support; no database downgrade is required because this
slice applies no migration.

**Findings, limitations, and residual risk:** The exact orchestration-task reconstruction
and its complete production-schema inventory remain deferred. So do terminal
consumption, `failed → dead_letter`, queueing, operator review, completion, dispatch,
runtime composition, providers/plugins, UI, exit demonstrations, and independent
review. The non-independent governance risk is accepted only for this migration-safety
prerequisite.

## 2026-08-29 — Terminal-consumption contracts and storage prerequisite

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review.

**Scope and evidence:** Closed terminal-consumption command/receipt contracts, additive
migration 0073, immutable one-to-one decision-bound persistence, contract validation,
migration upgrade/idempotency coverage, compatibility documentation, and storage-bypass
tests. The complete diff, terminal lineage, default-deny guard, migration behavior, and
deferred transition boundary were reviewed separately after implementation.

**Security boundaries and default deny:** Persistence accepts only the exact current
terminal-disposition v1 decision for the matching failed task revision, exhausted
three-attempt ceiling, and disabled transition/queue/review flags. A deny-all insert
trigger keeps the table inert until a reviewed consumer replaces it. Records fix
authority to none and execution disabled. No service produces a record, no task or plan state is
changed, and no queue, notification, dispatch, provider/plugin, network, or external
effect path exists.

**Compatibility, migration, and rollback:** Migration 0073 is additive and leaves the
existing task table, all historical contracts/rows, foreign keys, indexes, and triggers
unchanged. Application rollback leaves an unused additive table; destructive downgrade
after data exists is unsupported. Contracts exclude secrets, tokens, evidence, prompts,
diagnostics, target data, queue payloads, and operator messages.

**Findings, limitations, and residual risk:** Full consumption remains blocked because
SQLite cannot widen the current task-state CHECK without reconstructing a heavily
referenced table, and the repository has no reviewed reconstruction protocol. The
consumer, `failed → dead_letter` state change, audit/outbox linkage, queueing, operator
review, completion, dispatch, runtime composition, UI, exit demonstrations, and
independent review remain deferred. The non-independent governance risk is accepted
only for this inert prerequisite.

## 2026-08-29 — Attempt-three terminal-disposition decision v1

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author, Product Owner, Security Lead, and security reviewer
under the `GIT_WORKFLOW.md` exception. This is not independent review and does not
satisfy dual control.

**Scope and evidence:** Closed command/decision contracts, trusted-core lineage and
current-state validation, additive migration 0072, immutable one-to-one storage,
metadata-only audit/outbox linkage, compatibility documentation, and synthetic positive,
malformed, mixed-version, replay, tampering, concurrency, cancellation, safety, worker,
account, recovery, storage-bypass, fresh-upgrade, additive-upgrade, and idempotency tests.

**Security boundaries and default deny:** Only the exact failed-attempt-v3 receipt and
retry-policy-v2 ceiling of three can produce `dead_letter_eligible` with
`retry_ceiling_exhausted`. Trusted core revalidates the complete failure, checkpoint,
lease, worker, readiness, retry-consumption, policy, account, fencing, cancellation,
safety, and recovery lineage. Missing, stale, mixed, cross-scope, tampered,
changed-replay, or competing inputs deny. Task transition, queueing, operator review,
notification, retry, dispatch, and execution flags remain false; authority remains none.

**Compatibility, privacy, migration, and rollback:** Existing retry decisions and v1/v2
failed-attempt behavior remain unchanged and cannot satisfy this boundary. Contracts and
persistence exclude credentials, raw tokens, evidence, assessment content, prompts,
diagnostics, queue payloads, operator messages, paths, URLs, provider/plugin output,
targets, and arbitrary blobs. Migration 0072 is additive; rollback disables new
decisions while retaining immutable history, and destructive reversal is unsupported.

**Findings, limitations, and residual risk:** No material finding remains. Repository
evidence defines exhausted-attempt dead-letter behavior but no operator-review mapping,
so this slice does not invent one. Dead-letter transition and queueing, completion,
dispatch, runtime composition, providers/plugins, UI, Phase 2 demonstrations, and
independent review remain deferred. The non-independent governance risk is accepted only
for this narrow non-executing slice.

## 2026-08-27 — Attempt-three failed-attempt registration v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This is not independent review and does not satisfy dual control.

**Scope and evidence:** Closed command/receipt v3 contracts, trusted-core derivation and
current-state validation, additive migration 0071, immutable one-to-one storage,
metadata-only audit/outbox linkage, compatibility documentation, and synthetic positive,
malformed, mixed-version, replay, tampering, concurrency, safety, worker, account,
recovery, storage-bypass, fresh-upgrade, additive-upgrade, and idempotency tests.

**Security boundaries and default deny:** Only the existing attempt-three identity and
its exact digest-verified failure-v3 receipt can be linked. Durable policy, activation,
schedule, both retry consumptions, manifest-v4, reservation-v4, approval, worker,
lease-consumption-v3, checkpoint-v3, fencing, and recovery state are revalidated.
Missing, stale, mixed, cross-scope, tampered, changed-replay, or competing inputs deny.
The receipt fixes `authority: none`, disables execution, and cannot transition work,
evaluate retryability, create attempt four, dead-letter, dispatch, or perform an effect.

**Compatibility, privacy, migration, and rollback:** V1/v2 attempt contracts, services,
and immutable rows remain unchanged. Credentials, raw tokens, evidence, assessment
content, prompts, diagnostics, paths, URLs, commands, provider/plugin output, targets,
and arbitrary blobs are excluded. Migration 0071 is additive; application rollback
disables v3 production while retaining history, and destructive reversal is unsupported.

**Findings, limitations, and residual risk:** No material finding remains in this review.
Dead-letter handling, successful completion, dispatch, runtime composition,
providers/plugins, UI, Phase 2 demonstrations, and independent security review remain
deferred. The governance risk of this explicitly non-independent review is accepted only
for this narrow non-executing slice.

## 2026-08-27 — Attempt-three typed failure consumption v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This does not satisfy independent review or dual control.

**Scope and evidence:** Closed failure command/receipt v3 contracts, trusted-core exact
lineage validation, checkpoint-head/absence binding, additive migration 0070, an
immutable v3 failure ledger, exact storage-gated `running`-to-`failed` coordination
transition, metadata-only audit/outbox linkage, compatibility documentation, and
synthetic positive, malformed, mixed-version, replay, tampering, concurrency, safety,
cancellation, worker, account, recovery, transition/storage bypass, upgrade, and
idempotency tests.

**Security boundaries and default deny:** Only lease-consumption v3 for the current
attempt-three task and its exact checkpoint-v3 head or all-null absence can produce a
failure. Policy, manifest-v4, reservation-v4, worker, budget-account, fencing, and
recovery bindings are revalidated. Missing, partial, stale, mixed, cross-scope,
privilege-shaped, changed-replay, or competing inputs deny with stable codes or storage
constraints. The closed class grants no retryability or authority; attempt four is
unsupported and all records remain `authority: none` and execution-disabled.

**Compatibility, privacy, migration, and rollback:** V1/v2 failure contracts, rows, and
services are unchanged and cannot satisfy v3. Credentials, raw tokens, evidence,
assessment content, prompts, diagnostics, paths, URLs, commands, provider/plugin output,
targets, and arbitrary blobs are excluded. Migration 0070 is additive; rollback disables
v3 production while retaining immutable history, and destructive reversal is unsupported.

**Limitations and residual risk:** Failed-attempt terminal projection, dead-letter
handling, successful completion, dispatch, runtime composition, providers/plugins, UI,
Phase 2 demonstrations, and independent review remain deferred. The non-independent
exception is accepted only for this narrow non-executing slice.

## 2026-08-27 — Attempt-three metadata-only checkpoint v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and reviewer under the `GIT_WORKFLOW.md` exception; this
does not satisfy independent review or dual control.

**Scope and evidence:** Closed checkpoint command/receipt v3 contracts, trusted-core
current-lineage validation, additive migration 0069, an immutable version-exact ledger,
predecessor chaining, bounded progress metadata, hash-chained audit/outbox linkage, and
synthetic positive, malformed, mixed-version, replay, tampering, concurrency, ordering,
safety, worker, account, recovery, storage, upgrade, and idempotency tests.

**Security boundaries and default deny:** Only the current running attempt-three task
created by lease-consumption v3 can checkpoint. Exact policy, activation, attempt,
manifest-v4, reservation-v4, worker, lease, budget-account, fencing, and recovery
bindings are revalidated on creation and replay. Missing, stale, mixed, forked,
cross-scope, privilege-shaped, or changed inputs deny with stable codes or database
constraints. Records are metadata-only, `authority: none`, and execution-disabled.

**Compatibility, privacy, rollback, and residual risk:** V1/v2 checkpoint behavior is
unchanged and cannot satisfy v3. Credentials, raw tokens, evidence, prompts, provider or
plugin output, target content, commands, paths, URLs, free-form diagnostics, and blobs
are excluded. Rollback disables production while retaining immutable history; migration
reversal is unsupported. Failure/completion, terminal handling, dispatch, runtime
composition, providers/plugins, UI, exit demonstrations, and independent review remain
deferred.

## 2026-08-27 — Attempt-three lease consumption v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This does not satisfy independent review or dual control.

**Scope and evidence:** Closed consumption command/receipt v3 contracts, additive
migration 0068, trusted-core holder-proof verification, exact storage-gated
`ready`-to-`running` coordination transition, immutable spent-lease ledger,
metadata-only audit/outbox linkage, compatibility documentation, and synthetic positive,
malformed, mixed-version, token-tampering, replay, concurrency, expiry, safety, worker,
account, recovery, direct-transition, direct-storage, fresh-upgrade, additive-upgrade,
and idempotency tests.

**Security boundaries:** Only the exact current lease-v3 holder can consume the same
activation-v2, attempt-three, manifest-v4, reservation-v4, policy, approval, worker,
budget-account, fencing, and recovery lineage. The raw token is compared transiently
with its stored digest and is absent from receipts, storage, audit, outbox, and replay
output. The receipt and resulting `running` state remain `authority: none` and
`execution_enabled: false`; they do not contact or dispatch a worker, invoke a
provider/plugin, create an ActionIntent or grant, access a network, or perform an effect.
Phase 1 authorization remains unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, stale, expired,
token-mismatched, state-digest-mismatched, cross-scope, changed-replay, concurrent,
policy-replaced, safety-paused, cancelled, approval-invalid, worker-revoked,
account-version-stale, fencing-stale, recovery-stale, privilege-shaped, and direct
transition/storage inputs deny through stable codes or exact database constraints.

**Compatibility, privacy, migration, and rollback:** V1/v2 consumption contracts,
tables, rows, and behavior remain unchanged and cannot satisfy v3. Migration 0068 adds
an immutable v3 consumption ledger and extends only the exact task-transition predicate.
Application rollback disables v3 consumption while retaining records; migration reversal
is unsupported. Contracts exclude credentials, persisted raw tokens, evidence,
assessment content, prompts, diagnostics, paths, URLs, commands, provider/plugin output,
target content, and arbitrary blobs.

**Limitations and residual risk:** Worker contact/dispatch, checkpoints,
failure/completion, terminal/dead-letter behavior, runtime composition,
providers/plugins, UI, Phase 2 demonstrations, and independent review remain deferred.
The non-independent exception is accepted only for this narrow, non-executing slice.

## 2026-08-27 — Attempt-three durable task lease v3

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This does not satisfy independent review or dual control.

**Scope and evidence:** Closed acquire/state v3 contracts, additive migration 0067,
trusted-core acquisition and fail-closed recovery, shared monotonic task fencing,
one-time raw-token handling, immutable storage guards, metadata-only audit/outbox
linkage, compatibility documentation, and synthetic positive, malformed, mixed-version,
tampering, replay, concurrency, expiry, safety, worker, account, recovery, direct-storage,
fresh-upgrade, additive-upgrade, and idempotency tests.

**Security boundaries:** Only the exact current activation-v2, attempt-three,
manifest-v4, and reservation-v4 ready lineage can acquire lease v3. Trusted core derives
worker state from the durable registry and advances the shared task fence atomically.
Only the token digest is durable. The record is `authority: none` and
`execution_enabled: false`; it leaves the task ready and cannot contact a worker,
dispatch, invoke a provider/plugin, create an ActionIntent or grant, access a network,
or perform an external effect. Phase 1 authorization remains unchanged.

**Compatibility, privacy, migration, and rollback:** V1/v2 contracts, rows, and behavior
remain unchanged and cannot satisfy v3. Migration 0067 is additive and retains bounded
metadata-only history. Application rollback disables v3 acquisition/recovery while
retaining rows; migration reversal is unsupported. Contracts exclude credentials,
secrets, raw stored tokens, evidence, assessment content, prompts, diagnostics, paths,
URLs, commands, provider/plugin output, target content, and arbitrary blobs.

**Limitations and residual risk:** Lease renewal/release, consumption, the attempt-three
running transition, checkpoints, failure/completion, terminal/dead-letter behavior,
dispatch, runtime composition, providers/plugins, UI, Phase 2 demonstrations, and
independent review remain deferred. The non-independent exception is accepted only for
this narrow, non-executing slice.

## 2026-08-27 — Attempt-three task-budget reservation v4

**Review record:** Sole-maintainer security review — explicitly non-independent. The
repository owner is also author and security reviewer under the `GIT_WORKFLOW.md`
exception. This does not satisfy independent review or dual control.

**Scope and evidence:** Closed request/receipt v4 contracts, additive migration 0066,
trusted-core version-exact reservation and recovery, immutable storage predicates,
metadata-only audit/outbox linkage, compatibility documentation, and synthetic positive,
malformed, mixed-version, retry-shaped, tampering, replay, concurrency, safety, worker,
recovery, direct-storage, fresh-upgrade, additive-upgrade, and idempotency tests.

**Security boundaries:** Only the exact current manifest-v4 and activation-v2 attempt-three
ready lineage can reserve existing assessment capacity. Trusted core derives retry,
approval, worker, fencing, and recovery provenance from durable records. Both consumed
retry units remain charged and v4 requires zero retry capacity. The receipt is
`authority: none` and `execution_enabled: false`; it cannot transition a task, lease,
dispatch, invoke a provider/plugin, create an ActionIntent or grant, access a network,
or perform an external effect. Phase 1 authorization remains unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, stale, expired,
oversized, fractional, overflow-prone, tampered, cross-scope, stale-v3 reuse,
caller-identity, approval-invalid, cancelled, safety-paused, worker-revoked,
recovery-stale, account-version-mismatched, exhausted, replay-conflicting, concurrent,
privilege-shaped, and direct-storage inputs deny through stable codes or exact database
constraints.

**Compatibility, privacy, migration, and rollback:** V1-v3 contracts, rows, and behavior
remain unchanged. Migration 0066 is additive and retains bounded metadata-only history;
application rollback disables v4 creation/recovery while retaining rows, and migration
reversal is unsupported. Contracts exclude secrets, credentials, raw tokens, evidence,
assessment content, prompts, diagnostics, paths, URLs, commands, provider/plugin output,
target content, and arbitrary blobs.

**Limitations and residual risk:** Attempt-three leasing, running transition,
checkpoints, failure/completion, terminal/dead-letter behavior, dispatch, runtime
composition, providers/plugins, UI, Phase 2 demonstrations, and independent review
remain deferred. The non-independent exception is accepted only for this narrow,
non-executing slice.

## 2026-08-26 — Attempt-three TaskCapabilityManifest v4

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer under the `GIT_WORKFLOW.md` exception. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed request/manifest v4 contracts, additive migration 0065,
trusted-core version-exact issuance, immutable storage predicates, metadata-only
audit/outbox linkage, compatibility documentation, and synthetic positive, malformed,
mixed-version, tampering, replay, concurrency, safety, cancellation, worker, recovery,
ActionIntent-denial, direct-storage, upgrade, and idempotency tests.

**Security boundaries:** Only the exact current activation-v2 attempt-three lineage can
produce a v4 manifest. Trusted core revalidates active policy, ready plan/task,
schedule, attempt, consumed capacity, approval, worker, fencing, safety, cancellation,
and recovery state. V4 is `authority: none`, `execution_enabled: false`, and ready-only;
the running-state ActionIntent boundary cannot consume it. No budget mutation, lease,
transition, worker contact, dispatch, provider/plugin call, network authority, or
external effect occurs. Phase 1 authorization is unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, stale, expired,
tampered, cross-scope, attempt-four, prior-manifest reuse, duplicated, forked, competing,
changed-replay, cancelled, safety-paused, worker-revoked, approval-invalid,
recovery-stale, privilege-shaped, and direct-storage inputs deny through stable service
codes or exact database constraints.

**Compatibility, privacy, migration, and rollback:** V1–V3 manifests and rows remain
unchanged. Migration 0065 is additive and retains bounded metadata-only history;
application rollback disables v4 issuance while retaining rows, and migration reversal
is unsupported. Contracts exclude secrets, credentials, raw tokens, evidence,
assessment content, prompts, diagnostics, paths, URLs, commands, provider/plugin output,
target content, and arbitrary blobs.

**Limitations and residual risk:** Attempt-three budget reservation, leasing, running
transition, checkpoints, failure/completion, terminal/dead-letter behavior, dispatch,
runtime composition, providers/plugins, UI, Phase 2 demonstrations, and independent
review remain deferred. The non-independent exception is accepted only for this narrow
non-executing slice.

## 2026-08-26 — Dedicated attempt-three retry activation v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer under the `GIT_WORKFLOW.md` exception. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed activation command/receipt v2 contracts, additive
migration 0064, version-exact trusted-core schedule consumption, exact storage transition
guards, immutable metadata-only audit/outbox linkage, compatibility documentation, and
synthetic positive, malformed, mixed-version, tampering, replay, concurrency, safety,
cancellation, worker, recovery, direct-transition, upgrade, and idempotency tests.

**Security boundaries:** Only the exact current due schedule v2 for attempt three can
advance its failed validation plan/task revisions into active/ready coordination state.
The general transition path remains denied. Activation stays `authority: none` and
`execution_enabled: false`; it issues no readiness prerequisite, lease, assignment,
dispatch, provider/plugin call, network authority, or external effect. Phase 1
authorization remains unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, premature, expired,
tampered, duplicated, competing, changed-replay, cross-scope, stale-revision,
cancelled, safety-paused, worker-revoked, recovery-stale, privilege-shaped, and direct
storage inputs deny through stable service codes or exact database constraints.

**Compatibility, privacy, migration, and rollback:** V1 activation behavior and rows are
unchanged. Migration 0064 is additive and retains bounded metadata-only history;
application rollback disables v2 consumption while retaining its rows, and migration
reversal is unsupported. Contracts exclude secrets, credentials, raw tokens, evidence,
assessment content, prompts, diagnostics, paths, URLs, commands, provider/plugin output,
target content, and arbitrary blobs.

**Limitations and residual risk:** Attempt-three manifest/budget issuance, leasing,
running transition, checkpoints, failure/completion, terminal/dead-letter handling,
dispatch, runtime composition, provider/plugin execution, UI, Phase 2 demonstrations,
and independent review remain deferred. This non-independent review is accepted only for
the narrow non-executing slice.

## 2026-08-26 — Immutable retry-schedule registration v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. The
`GIT_WORKFLOW.md` exception is used. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed attempt-three schedule command/receipt v2 contracts,
additive migration 0063, trusted-core version-exact timing derivation, immutable storage
guards, metadata-only audit/outbox linkage, compatibility documentation, and synthetic
positive, malformed, mixed-version, caller-timing, premature, expiry, digest-tampering,
replay, concurrency, safety, cancellation, worker, recovery, direct-storage, upgrade,
and idempotency tests.

**Security boundaries:** Only the exact current attempt-three receipt may be scheduled.
Trusted core revalidates its complete retry-decision, consumption, failed-attempt,
policy, checkpoint, lease, worker, manifest, budget, approval, cancellation, safety,
fencing, and recovery lineage. Timing is derived from retry-decision v2 and registration
is rejected before that time. The schedule remains `authority: none` and
`execution_enabled: false`; task, attempt, and budget state are unchanged. No attempt
four, activation, readiness record, lease, worker contact, dispatch, provider/plugin
call, network authority, or external effect is created. The Phase 1 authorization chain
is unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, premature, stale,
expired, caller-timed, tampered, cross-scope, predecessor/decision/consumption
mismatched, duplicated, forked, competing, changed-replay, cancelled, safety-paused,
worker-revoked, recovery-stale, privilege-shaped, and direct-storage inputs deny with
stable codes or storage constraints.

**Compatibility, privacy, migration, and rollback:** V1 attempt-two schedule behavior
and rows remain unchanged. Migration 0063 is additive and preserves bounded
metadata-only history. Application rollback disables v2 scheduling while retaining the
row; migration reversal is unsupported. Contracts exclude secrets, credentials, raw
tokens, evidence, assessment content, prompts, diagnostics, paths, URLs, commands,
provider/plugin output, target content, and arbitrary blobs.

**Limitations and residual risk:** Schedule consumption, attempt-three activation,
refreshed manifest/budget prerequisites, later leasing, checkpoint/failure/completion,
terminal/dead-letter handling, dispatch, runtime composition, provider/plugin execution,
UI, Phase 2 demonstrations, and independent review remain deferred. Non-independent
review reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-26 — Immutable retry-attempt registration v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. The
`GIT_WORKFLOW.md` exception is used. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed attempt-three command/receipt v2 contracts, additive
migration 0062, trusted-core version-exact registration, immutable storage guards,
metadata-only audit/outbox linkage, compatibility documentation, and synthetic positive,
malformed, mixed-version, attempt-four, digest-tampering, replay, concurrency, safety,
cancellation, worker, recovery, direct-storage, upgrade, and idempotency tests.

**Security boundaries:** Only the exact current retry-budget-consumption v2 receipt may
derive one attempt-three identity. Complete failed-attempt, decision, retry-capacity,
policy, checkpoint, lease, worker, manifest, approval, fencing, cancellation, safety,
and recovery lineage is revalidated. The record remains `authority: none` and
`execution_enabled: false`; task and budget state are unchanged. No attempt four,
schedule, activation, readiness record, lease, worker contact, dispatch, provider/plugin
call, network authority, or external effect is created. The Phase 1 authorization chain
is unchanged.

**Threats and default deny:** Missing, malformed, mixed-version, stale, expired,
tampered, cross-scope, predecessor/consumption mismatched, skipped, rolled-back,
duplicated, forked, competing, changed-replay, cancelled, safety-paused, worker-revoked,
recovery-stale, privilege-shaped, and direct-storage inputs deny with stable codes or
storage constraints.

**Compatibility, privacy, migration, and rollback:** V1 attempt-two behavior and rows
remain unchanged. Migration 0062 is additive and preserves bounded metadata-only
history. Application rollback disables v2 registration while retaining the row;
migration reversal is unsupported. Contracts exclude secrets, credentials, raw tokens,
evidence, assessment content, prompts, diagnostics, paths, URLs, commands,
provider/plugin output, target content, and arbitrary blobs.

**Limitations and residual risk:** Attempt-three scheduling, activation, refreshed
manifest/budget prerequisites, later leasing, checkpoint/failure/completion,
terminal/dead-letter handling, dispatch, runtime composition, provider/plugin execution,
UI, Phase 2 demonstrations, and independent review remain deferred. Non-independent
review reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-25 — Retry-bound eligibility evaluation v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed evaluation command/decision v2 contracts, migration
0060, version-exact trusted-core evaluation, immutable decision storage, metadata-only
audit/outbox linkage, compatibility documentation, and synthetic outcome, malformed,
mixed-version, digest tampering, replay, concurrency, safety, cancellation, worker,
recovery, direct-storage, migration upgrade, and idempotency tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-GRANT-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, `INV-REL-001`,
and `INV-REL-002`. Trusted core binds one failed-attempt v2 receipt, its complete retry,
failure, checkpoint, lease, worker, manifest, budget, approval, policy, fencing, and
recovery lineage to one exact retry policy v2. Current attempt two, proposed attempt
three, and `[5, 30]` policy timing are derived, not caller supplied.

**Threat/default-deny review:** Missing or mixed versions; stale or excessive validity;
attempt, failure, checkpoint, policy, digest, assessment, plan, task, worker, manifest,
budget, approval, lease, fence, or recovery substitution; changed replay; concurrent
forks; cancellation; safety pause; worker revocation; authority-shaped fields; and
direct storage mutation deny. Security failures cannot be caller-relabeled as transient.

**Compatibility, privacy, migration, and rollback:** V1 evaluation and immutable rows
remain unchanged. Migration 0060 adds a separate v2 decision table; existing rows need
no conversion. Rollback disables v2 evaluation while retaining history, and migration
reversal is unsupported. Stored data is bounded identifiers, hashes, closed enums,
integers, and timestamps—never credentials, secrets, raw tokens, evidence, prompts,
targets, diagnostics, provider/plugin data, paths, URLs, commands, flags, or blobs.

**Limitations and residual risk:** Evaluation only reads remaining capacity from the
prior immutable consumption receipt. It consumes or refunds no capacity, creates no
attempt three, schedules or transitions no task, leases or dispatches no work, contacts
no worker, and authorizes no effect. Attempt-three consumption/lifecycle, terminal
dead-letter changes, completion, Master Orchestrator runtime, UI, providers/plugins,
and exit demonstrations remain deferred. Non-independent review reduces governance
assurance and is accepted only for this non-executing slice.

## 2026-08-25 — Retry-bound retry policy v2 prerequisite

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed retry-policy v2 contract, trusted-core issuance,
migration 0059, immutable version-exact storage, compatibility documentation, and
synthetic issuance, replay, stale validity, identity conflict, safety pause, direct
storage mutation, migration upgrade, and idempotency tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-AGENT-001`
through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, `INV-REL-001`, and
`INV-REL-002`. Trusted core alone issues a policy bound to one active assessment and
signed policy. The record fixes failure/attempt contract v2, maximum attempts three,
closed transient classes, `[5, 30]` integer-second backoff, `authority: none`, and
`execution_enabled: false`.

**Threat/default-deny review:** Stale or excessive validity, inactive assessment or
policy, policy-hash substitution, safety pause, identity conflict, authority-shaped
state, schema-version substitution, mutation, and deletion deny. AI, agents, workers,
plugins, UI, and request bodies cannot select or broaden policy semantics.

**Compatibility, privacy, migration, and rollback:** V1 contract, service behavior,
and immutable rows remain supported. Migration 0059 adds a separate v2 table; existing
rows need no conversion. Rollback disables v2 issuance while retaining history, and
migration reversal is unsupported. Stored data is bounded identifiers, hashes, closed
enums, integers, and timestamps—never secrets, credentials, evidence, prompts, target
content, diagnostics, paths, URLs, commands, flags, provider/plugin data, or raw tokens.

**Limitations and residual risk:** Policy issuance evaluates no retry, reads or consumes
no retry capacity, creates no attempt three, schedules or transitions no task, contacts
or dispatches no worker, and authorizes no effect. Version-exact attempt-two evaluation,
later retry accounting/activation, completion, Master Orchestrator runtime, UI, and
provider/plugin execution remain deferred. Non-independent review reduces governance
assurance and is accepted only for this non-executing prerequisite.

## 2026-08-25 — Retry-bound failed-attempt registration v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed attempt command/receipt v2 contracts, migration 0058,
version-exact trusted-core validation, a separate immutable one-to-one failure-linkage
table, metadata-only audit/outbox linkage, compatibility and plan documentation, and
synthetic success, malformed, mixed-version, numbering, digest tampering, cross-scope,
replay, concurrency, safety, cancellation, worker, recovery, storage-immutability, and
non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-GRANT-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`,
`INV-REL-001`, and `INV-REL-002`. Trusted core links the existing attempt-two identity
to one exact failure-v2 receipt only after revalidating retry activation, consumed retry
unit, v3 manifest/reservation, v2 lease/checkpoint lineage, active policy, worker, fence,
and recovery state. No provider, plugin, worker-contact, gateway, target, secret,
evidence, network, policy-decision, or grant boundary is crossed.

**Threat/default-deny review:** Unknown or mixed versions; caller-created identity or
numbering; attempt three; missing, stale, forked, cross-scope, or digest-substituted
lineage; changed replay; concurrent registration; cancellation; safety pause; policy,
worker, budget, or recovery replacement; authority-shaped fields; and direct storage
mutation deny with stable codes. Failure class comes only from the verified receipt and
cannot be relabeled as retryable.

**Compatibility, privacy, migration, and rollback:** V1 contracts, rows, and behavior
remain supported. Migration 0058 adds a separate immutable linkage table, leaving the
attempt-two creation ledger unchanged. Existing rows need no conversion. Rollback
disables v2 production while retaining history; migration reversal is unsupported.
Stored data is bounded IDs, hashes, revisions, closed classes, and timestamps—never raw
tokens, credentials, secrets, evidence, prompts, diagnostics, provider/plugin payloads,
targets, paths, URLs, commands, or flags.

**Limitations and residual risk:** Registration evaluates no further retry, consumes no
capacity, creates no attempt three, changes no task state, leases or dispatches no work,
contacts no worker, and authorizes no effect. Completion, further retry lineage,
dispatch, Master Orchestrator runtime, UI, and provider/plugin execution remain deferred.
Non-independent review reduces governance assurance and is accepted only for this
non-executing slice.

## 2026-08-25 — Retry-bound typed failure consumption v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed failure command/receipt v2 contracts, migration 0057,
version-exact service validation, dedicated atomic state transition, immutable audit and
outbox linkage, compatibility and plan documentation, and synthetic success, malformed,
mixed-version, tampering, checkpoint-head, replay, concurrency, safety, worker, recovery,
direct-transition, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core records one closed failure only after binding the exact
current running task to its retry activation, attempt two, consumed retry unit, v3
manifest/reservation, v2 lease consumption, optional exact checkpoint-v2 head, active
policy, registered worker, fence, and recovery generation. No provider, plugin,
worker-contact, gateway, target, secret, evidence, network, policy-decision, or grant
boundary is crossed.

**Threat/default-deny review:** Unknown or mixed versions; missing or tampered lineage;
cross-scope substitution; stale or ambiguous checkpoint heads; conflicting replay;
concurrent consumption; stale plan/task/policy/manifest/budget/worker/fence/recovery
state; cancellation; safety pause; expiry; direct transition; and authority-shaped input
deny with stable codes. Free-form diagnostics and caller-declared retryability remain
unrepresentable.

**Compatibility, privacy, migration, and rollback:** V1 contracts, rows, and behavior
remain supported. Migration 0057 adds nullable immutable lineage and exact v2 insert
guards; existing rows need no conversion. Rollback disables v2 production while
retaining history; migration reversal is unsupported. Stored data is bounded IDs,
hashes, revisions, closed classes, and timestamps—never tokens, credentials, secrets,
evidence, prompts, diagnostics, provider/plugin payloads, targets, paths, or URLs.

**Limitations and residual risk:** Failed coordination state declares no retryability and
does not consume capacity, create attempt three, reopen work, complete work, dispatch,
contact workers, execute providers/plugins, or authorize effects. Those boundaries,
Master Orchestrator runtime, and UI remain deferred. Non-independent review reduces
governance assurance and is accepted only for this non-executing slice.

## 2026-08-25 — Retry-bound metadata-only checkpoints v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed checkpoint command/receipt v2 contracts, migration 0056,
version-exact service validation, immutable audit/outbox linkage, compatibility and plan
documentation, and synthetic success, malformed, mixed-version, tampering, ordering,
rollback, fork, replay, concurrency, safety, worker, recovery, storage-immutability, and
non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core records bounded progress only after binding the exact current
running task to its retry activation, attempt two, consumed retry unit, v3 manifest and
reservation, v2 lease consumption, active policy, registered worker, fencing token, and
recovery generation. No provider, plugin, worker-contact, gateway, target, secret,
evidence, network, policy-decision, or grant boundary is crossed.

**Threat/default-deny review:** Unknown or mixed versions; missing or tampered lineage;
cross-scope substitution; sequence gaps, rollback, forks, ambiguous heads, conflicting
replay, concurrent writes, stale plan/task/policy/manifest/budget/worker/fence/recovery
state, cancellation, safety pause, expiry, and authority-shaped input deny with stable
codes. Only closed progress metadata is accepted; artifact and free-form content remain
unrepresentable.

**Compatibility, privacy, migration, and rollback:** V1 contracts, rows, and behavior
remain supported. Migration 0056 adds nullable immutable lineage and an exact v2 insert
guard; existing rows need no conversion. Rollback disables v2 production while retaining
history; migration reversal is unsupported. Stored data is bounded identifiers, hashes,
revisions, closed status, integer progress, and timestamps—never tokens, credentials,
secrets, evidence, prompts, diagnostics, provider/plugin payloads, targets, paths, URLs,
commands, or flags.

**Limitations and residual risk:** Checkpoints do not change task state or create resume,
failure, completion, retry, leasing, dispatch, worker contact, provider/plugin execution,
or effect-specific authorization. Those boundaries, Master Orchestrator runtime, and UI
remain deferred. Non-independent review reduces governance assurance and is accepted
only for this non-executing slice.

## 2026-08-24 — Dedicated retry-bound lease consumption v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed command/receipt v2 contracts, migration 0055, atomic
trusted-core consumption, exact attempt-aware storage guard, immutable audit/outbox
linkage, compatibility documentation, and synthetic success, malformed, mixed-version,
token/digest tampering, cross-lineage, replay, concurrency, cancellation, safety,
worker/recovery fencing, direct-transition, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core revalidates and consumes one exact v2 holder proof bound to
the current retry activation, attempt two, consumed retry unit, v3 manifest/reservation,
policy, worker, fence, and recovery generation. The transaction changes only durable
coordination state. No provider, plugin, worker-contact, gateway, target, secret,
evidence, network, policy-decision, or grant boundary is crossed.

**Threat/default-deny review:** Unknown or mixed versions; wrong token; state, lineage,
or digest substitution; original-attempt reuse; stale plan/task/policy/manifest/budget/
worker/lease/recovery state; cancellation; safety pause; expiry; conflicting replay;
concurrent consumption; direct transition; and authority-shaped input deny with stable
codes. The database predicate requires version-exact immutable provenance and cannot be
used as a general `ready` to `running` allowance. Raw token material is never persisted
or audited.

**Compatibility, privacy, migration, and rollback:** V1 contracts, rows, and behavior
remain supported. Migration 0055 adds nullable immutable consumption lineage and a
version-aware transition predicate; existing rows need no conversion. Rollback disables
v2 consumption while retaining history; migration reversal is unsupported. Stored data
is bounded identifiers, hashes, revisions, states, and timestamps—never raw tokens,
credentials, secrets, evidence, prompts, provider/plugin payloads, targets, paths, or
URLs.

**Limitations and residual risk:** `running` is non-authoritative coordination state.
Retry-attempt checkpoints, failure/completion consumption, worker dispatch/contact,
Master Orchestrator runtime, UI, provider/plugin execution, and effect-specific
authorization remain deferred. Non-independent review reduces governance assurance and
is accepted only for this non-executing slice.

## 2026-08-24 — Retry-bound durable task lease v2

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed acquisition/state v2 contracts, migration 0054, atomic
trusted-core acquisition and fencing composition, one-time raw-token handling, immutable
audit/outbox linkage, compatibility documentation, and synthetic success, malformed,
unsupported/mixed-version, tampering, cross-lineage, replay, concurrency, renewal,
release, expiry, worker, cancellation, safety, budget-account, recovery,
storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core binds coordination ownership to the exact current retry
activation, attempt two, consumed retry unit, TaskCapabilityManifest v3, budget
reservation v3, policy, ready task, registered worker runtime, and recovery generation.
No provider, plugin, worker-contact, gateway, target, secret, evidence, or network
boundary is crossed.

**Threat/default-deny review:** Caller-selected authority or worker properties;
missing/tampered/mixed prerequisites; original-attempt reuse; stale revisions, worker,
policy, safety, cancellation, budget, expiry, or recovery state; cross-scope substitution;
acquisition replay; parallel holders; token mismatch; stale generation/fencing tokens;
and storage mutation deny with stable codes. Only the token digest is persisted; the raw
token is returned once and cannot be replayed from storage or audit.

**Compatibility, privacy, migration, and rollback:** V1 contracts, rows, and consumers
remain unchanged. Migration 0054 adds nullable immutable provenance fields; existing rows
need no conversion. Rollback disables v2 operations and retains history; migration
reversal is unsupported. Stored data is bounded identifiers, hashes, revisions, states,
and timestamps—never raw tokens, secrets, evidence, prompts, diagnostics, provider/plugin
payloads, targets, commands, paths, or URLs.

**Limitations and residual risk:** This slice acquires coordination ownership only. It
does not consume the v2 lease, transition the task to running, contact/dispatch a worker,
checkpoint, complete, invoke providers/plugins, or grant authority. Master Orchestrator
and UI integration and effect-specific authorization remain deferred. Non-independent
review reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-24 — Retry-bound ready-state budget reservation v3

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed request/receipt v3 contracts, migration 0053, atomic
trusted-core reservation composition, immutable audit/outbox linkage, compatibility
documentation, and synthetic success, malformed, unsupported-version, tampering,
cross-lineage, replay, concurrency, expiry, policy, safety, cancellation, recovery,
storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core binds existing assessment capacity to the exact current
retry activation, attempt two, consumed retry unit, TaskCapabilityManifest v3, policy,
plan, and ready task. No provider, plugin, worker, gateway, target, secret, evidence, or
network boundary is crossed.

**Threat/default-deny review:** Caller-selected authority, non-integer or unsupported
amounts, missing/tampered lineage, original-attempt reservation reuse, stale revisions,
cross-scope substitution, policy replacement, cancellation, safety pause, recovery
fencing, expiry, changed replay, competing reservations, account-version races, ceiling
exhaustion, and storage mutation deny with stable codes. The consumed retry unit is
neither refunded nor counted as new capacity.

**Compatibility, privacy, migration, and rollback:** V1/v2 contracts and rows remain
unchanged. Migration 0053 adds nullable immutable provenance fields; existing rows need
no conversion. Rollback disables v3 issuance and retains history; migration reversal is
unsupported. Stored data is bounded identifiers, hashes, integer amounts, revisions,
states, and timestamps—never secrets, evidence, prompts, diagnostics, provider/plugin
payloads, targets, commands, paths, URLs, or raw tokens.

**Limitations and residual risk:** This slice issues only the refreshed retry budget
prerequisite. It does not acquire or consume a later lease, transition the task, assign
or contact a worker, dispatch, complete, invoke providers/plugins, or grant authority.
Master Orchestrator/UI integration and effect-specific authorization remain deferred.
Non-independent review reduces governance assurance and is accepted only for this
non-executing slice.

## 2026-08-24 — Retry-bound task capability manifest v3

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, Product Owner, Principal Architect, Security Lead, AI/Agent Lead,
Core Maintainer, Contract Maintainer, Execution Safety Lead, and Security Reviewer. This
does not satisfy independent review or dual control.

**Scope and evidence:** Closed v3 manifest contract, migration 0052, deterministic
trusted-core issuer, immutable audit/outbox linkage, compatibility documentation, and
synthetic success, malformed, tampering, cross-activation, replay, concurrency, policy,
safety, cancellation, recovery, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and
`INV-REL-002`. Trusted core revalidates the exact activation and its attempt, schedule,
failure, checkpoint, lease, worker, approval, policy, retry-policy, consumed budget,
safety, cancellation, and recovery lineage. No provider, plugin, worker, gateway, target,
secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Caller-selected authority, delegation, capabilities,
unsupported limits, missing/tampered activation, stale or cross-scope attempt lineage,
policy replacement, cancellation, safety pause, recovery fencing, duplicate/forked
issuance, changed replay, concurrency, expiry, and storage mutation deny with stable codes.
The existing converter rejects this ready-state v3 manifest.

**Compatibility, privacy, migration, and rollback:** V1/v2 manifests remain unchanged.
Migration 0052 adds nullable immutable retry provenance; existing rows require no
conversion. Rollback disables v3 issuance and retains history; migration reversal is
unsupported. Stored data is bounded identifiers, hashes, limits, revisions, and
timestamps, never secrets, evidence, prompts, diagnostics, provider/plugin payloads,
targets, commands, paths, URLs, or raw tokens.

**Limitations and residual risk:** This slice issues only the capability half of refreshed
readiness prerequisites. Retry-bound budget reservation, later leases, dispatch,
completion, Master Orchestrator/UI integration, agents, provider/plugin execution, and
effect-specific authorization remain deferred. Non-independent review reduces governance
assurance and is accepted only for this non-executing slice.

## 2026-08-24 — Dedicated orchestration retry activation v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0051, deterministic
trusted-core consumption service, exact storage-fenced plan/task transitions, immutable
audit/outbox linkage, and synthetic success, malformed, tampering, cross-scope, replay,
concurrency, expiry, safety, policy, worker, budget, recovery, storage-immutability,
general-transition denial, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates the exact
schedule and its attempt, failure, checkpoint, lease, worker, manifest, approval, policy,
retry-policy, retry-budget, safety, cancellation, and recovery lineage. No provider,
plugin, worker, gateway, target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Caller-controlled timing, state, worker, budget, privilege,
or authority; missing/tampered schedules; stale or cross-scope lineage; early/expired use;
forks, changed replay, and concurrent consumption; cancellation or safety pause; policy,
worker, budget, approval, or recovery replacement; direct/general transition bypass; and
storage mutation deny with stable codes.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table preserve Phase 1 and existing consumers. Rollback disables consumption
while retaining history; migration reversal is unsupported. Stored data is bounded
identifiers, hashes, enums, revisions, and timestamps, never secrets, evidence, prompts,
diagnostics, commands, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Activation changes coordination readiness only. It
does not issue refreshed ready-state manifests or budgets, acquire a lease, assign/contact
a worker, dispatch, complete, or execute providers/plugins. Master Orchestrator and UI
integration and effect-specific authorization remain deferred. Non-independent review
reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-23 — Immutable non-activating orchestration retry schedule v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0050, deterministic
trusted-core registration service, immutable audit/outbox linkage, and synthetic positive,
malformed, caller-timing/state/worker/budget/authority, ordering, replay, concurrency,
cross-scope, safety, policy, worker, budget, recovery, storage-immutability, and
non-activation tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates the exact
attempt-two receipt and its prior-attempt, failure, checkpoint, lease, worker, manifest,
approval, policy, retry-policy, eligibility, retry-budget, safety, and recovery lineage.
No provider, plugin, worker, gateway, target, secret, evidence, or network boundary is
crossed.

**Threat/default-deny review:** Caller-controlled backoff, delay, wake time, priority,
retryability, classification, state, worker, budget, or authority; missing or tampered
attempts; premature ordering; stale or cross-scope lineage; forks, changed replay, and
competing schedules; cancellation or safety pause; policy, worker, budget, or recovery
replacement; storage mutation; and privilege-shaped input deny with stable codes. Copied
worker identity is historical failed-attempt provenance and cannot assign attempt two.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table leave Phase 1 and existing orchestration consumers unchanged. Rollback
disables new registration while retaining history; migration reversal is unsupported.
Stored data is bounded identifiers, hashes, enums, integer revisions, and timestamps—never
diagnostics, evidence, prompts, paths, URLs, commands, credentials, secrets,
provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** The schedule is historical `registered` coordination
metadata. It cannot reopen or transition tasks, activate attempts, issue manifests or
budgets, acquire leases, dispatch/contact workers, or execute providers/plugins. Activation,
completion, Master Orchestrator/UI integration, and effect-specific authorization remain
deferred. Non-independent review reduces governance assurance and is accepted only for
this non-executing slice.

## 2026-08-23 — Immutable orchestration retry-attempt identity v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0049, deterministic
trusted-core registration service, immutable audit/outbox linkage, and synthetic positive,
malformed, caller-state/schedule/authority, ordering, replay, concurrency, cross-scope,
safety, worker, budget, recovery, storage-immutability, and non-activation tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates the exact
retry-budget consumption and prior-attempt, failure, checkpoint, lease, worker, manifest,
approval, policy, retry-policy, eligibility, budget, safety, and recovery lineage. No
provider, plugin, worker, gateway, target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Caller-controlled numbering, state, retryability, backoff,
schedule, worker, budget, or authority; missing/tampered consumption; premature ordering;
stale/cross-scope lineage; gaps, forks, changed replay, competing registration;
cancellation/safety pause; policy/worker/budget/recovery replacement; storage mutation;
and privilege-shaped input deny with stable codes. Copied prior-worker identity cannot
assign attempt two.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table leave the closed initial-attempt contract, Phase 1, and existing consumers
unchanged. Rollback disables new registration and retains history; migration reversal is
unsupported. Stored data is bounded identifiers, hashes, enums, integer revisions/numbers,
and timestamps—never diagnostics, evidence, prompts, paths, URLs, commands, credentials,
secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Attempt two remains historical `registered` identity.
It cannot reopen tasks, schedule or activate work, acquire leases, dispatch/contact workers,
or execute providers/plugins. Scheduling, activation, completion, Master Orchestrator/UI
integration, and effect-specific authorization remain deferred. Non-independent review
reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-23 — Atomic orchestration retry-budget consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0048, atomic
trusted-core consumption service, immutable sub-ledger and audit/outbox linkage, and
synthetic positive, malformed, denied-decision, caller-override, replay, concurrency,
expiry, cross-scope, version, safety, worker, recovery, immutability, exhaustion, and
non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-NET-005`, `INV-REL-001`, and `INV-REL-002`. Trusted core
revalidates the exact eligibility decision and failed-attempt, failure, checkpoint,
lease, worker, manifest, approval, policy, retry-policy, budget, safety, and recovery
lineage. No provider, plugin, worker, gateway, target, secret, evidence, or network
boundary is crossed.

**Threat/default-deny review:** Caller-controlled retryability, units, remaining
capacity, backoff, or authority; denied or tampered decisions; mixed versions;
stale/cross-scope lineage; changed replay; competing consumption; account-version races;
exhaustion; reservation release; cancellation/safety pause; policy/worker/recovery
replacement; storage mutation; and authority-shaped input deny with stable codes. One
decision cannot create parallel branches or consume twice.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table leave Phase 1, reservation amounts, and existing consumers unchanged.
Rollback disables new consumption and retains the ledger; migration reversal and refunds
are unsupported. Stored data is bounded identifiers, hashes, enums, integer counters and
versions, and timestamps—never diagnostics, evidence, prompts, paths, URLs, commands,
credentials, secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Consumption is non-refundable and non-activating. It
does not create attempt two, reopen tasks, acquire leases, schedule/dispatch work, contact
workers, or execute providers/plugins. Later-attempt identity, activation, completion,
Master Orchestrator/UI integration, and effect-specific authorization remain deferred.
Non-independent review reduces governance assurance and is accepted only for this
non-executing slice.

## 2026-08-23 — Deterministic orchestration retry policy and eligibility v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed policy, evaluation-command, and decision contracts;
migration 0047; deterministic trusted-core service; immutable audit/outbox linkage; and
synthetic positive, malformed, closed-class, replay, concurrency, policy-expiry,
cross-binding, safety, worker, budget, recovery, storage-tampering, integer-boundary,
and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core alone fixes retry
semantics and revalidates the exact immutable attempt/failure/checkpoint/lease, policy,
safety, manifest, budget, approval, worker, and recovery lineage. No provider, plugin,
worker, gateway, target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Caller-controlled retryability, backoff, or next-attempt
fields; wildcard or altered policy; mixed versions; stale/cross-scope lineage; digest
substitution; changed replay; concurrent decisions; cancellation/safety pause;
policy/worker/budget/recovery replacement; authority-shaped input; and storage mutation
deny with stable codes. Security and unlisted failure classes cannot be relabeled as
transient.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable tables leave Phase 1 and existing orchestration consumers unchanged. Rollback
disables new issuance/evaluation and retains history; migration reversal is unsupported.
Stored data is bounded identifiers, hashes, enums, integer counters/backoff, versions,
and timestamps—never diagnostics, evidence, prompts, paths, URLs, commands, credentials,
secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Eligibility checks existing retry capacity but does
not consume it. It cannot create attempt two, reopen tasks, acquire leases, schedule or
dispatch work, contact workers, or execute providers/plugins. Retry-budget consumption,
activation, later-attempt lifecycle, completion, Master Orchestrator/UI integration, and
effect-specific authorization remain deferred. Non-independent review reduces governance
assurance and is accepted only for this non-executing slice.

## 2026-08-23 — Immutable orchestration failed-attempt identity v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0046, deterministic
attempt-registration service, immutable audit/outbox linkage, and synthetic positive,
malformed, numbering, replay, concurrency, failure/checkpoint binding, cross-scope,
safety, worker, budget, recovery-marker, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates the exact
typed failure receipt and current policy, safety, failed task, manifest, budget,
approval, lease consumption, worker, fencing/recovery, and checkpoint lineage. No
provider, plugin, worker, gateway, target, secret, evidence, or network boundary is
crossed.

**Threat/default-deny review:** Missing typed failure, recovery-marker substitution,
unknown/free-form fields, attempt numbers other than one, stale/cross-scope bindings,
failure/checkpoint digest substitution, changed replay, concurrent forks, safety pause,
policy/worker/budget/recovery replacement, authority-shaped input, and storage mutation
deny with stable codes. Attempt identity cannot assert retryability or create authority.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable table; existing Phase 1 workflow attempts and orchestration state are
unchanged. Rollback disables production and retains history; migration reversal is
unsupported. Stored data is bounded identifiers, hashes, closed state, integer attempt
number, versions, and timestamps—never diagnostics, evidence, prompts, paths, URLs,
commands, credentials, secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** This slice registers only the initial failed attempt.
It does not define retry policy, decide eligibility, consume retry capacity, create or
activate a later attempt, reopen tasks, acquire leases, dispatch/contact workers, or
execute providers/plugins. Those boundaries and Master Orchestrator/UI integration
remain deferred. Non-independent review reduces governance assurance and is accepted
only for this non-executing slice.

## 2026-08-22 — Dedicated typed orchestration failure consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. This does not satisfy independent review or dual
control.

**Scope and evidence:** Closed command/receipt contracts, migration 0045, deterministic
failure-consumption service, dedicated storage predicate, immutable recovery markers,
audit/outbox linkage, and synthetic positive, malformed, closed-class, replay,
concurrency, checkpoint-lineage, cross-binding, safety, recovery, immutability, and
non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core revalidates current
policy, safety, running task, manifest, budget, approval, lease consumption, worker,
fence, recovery generation, and checkpoint head. No provider, plugin, worker, gateway,
target, secret, evidence, or network boundary is crossed.

**Threat/default-deny review:** Unknown or free-form failure data, malformed input,
stale/cross-scope bindings, ambiguous or stale checkpoint lineage, changed replay,
concurrent consumption, cancellation, safety pause, policy/worker/recovery replacement,
direct storage mutation, and general transition attempts deny with stable codes. A
failure class cannot assert retryability or create authority.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
immutable tables; migration 0045 intentionally closes general `running` to `failed`
while preserving explicit startup recovery through immutable recovery markers.
Rollback disables production and retains history; it must not reopen the closed edge,
and migration reversal is unsupported. Stored data is bounded identifiers, hashes,
closed classes, versions, and timestamps—never diagnostics, evidence, prompts, paths,
URLs, commands, credentials, secrets, provider/plugin payloads, targets, or raw tokens.

**Limitations and residual risk:** Failure consumption does not create immutable attempt
identity, determine retry eligibility, consume retry budget, schedule/activate retries,
reopen tasks, complete tasks, dispatch/contact workers, or execute providers/plugins.
Those boundaries and Master Orchestrator/UI integration remain deferred. The
non-independent review reduces governance assurance and is accepted only for this
non-executing slice.

## 2026-08-22 — Durable metadata-only orchestration checkpoints v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, Execution Safety Lead, and Security Reviewer. This does not satisfy
independent review or dual control.

**Scope and evidence:** Closed command/receipt contracts, migration 0044, deterministic
checkpoint service, immutable audit/outbox linkage, and synthetic positive, malformed,
replay, conflict, sequence, predecessor, progress rollback, concurrency, cross-worker,
safety, recovery-fencing, storage-immutability, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-DATA-005`, and `INV-REL-001` through `INV-REL-003`. Trusted core
revalidates durable policy, safety, running task, prerequisite, consumption, worker, and
fencing records without contacting any external component.

**Threat/default-deny review:** Unknown/malformed, stale, cross-scope, expired,
authority-shaped, sequence-gapped, forked, predecessor-mismatched, progress-decreasing,
concurrent, worker-revoked, safety-paused, cancelled/terminal, and recovery-stale input
denies with stable codes. Checkpoints cannot alter state or authorize an effect.

**Compatibility, privacy, migration, and rollback:** Additive schemas/service/table;
Phase 1 workflow checkpoints remain unchanged. Rollback disables production and retains
immutable history; migration reversal is unsupported. Only bounded identifiers, hashes,
integer progress, closed status, and timestamps are stored. Artifact references, raw
evidence, prompts, paths, URLs, commands, credentials, secrets, tokens, provider/plugin
content, and targets are excluded.

**Limitations and residual risk:** Artifact references, retries, completion, resume,
dispatch, worker contact, Master Orchestrator runtime, UI, provider/plugin execution,
and effect-specific authorization remain deferred. Non-independent review reduces
governance assurance and is accepted only for this non-executing slice.

## 2026-08-22 — Dedicated orchestration lease consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Closed command/receipt contracts, migration 0043, atomic
lease-consumption service, storage-gated readiness transition, closure of the general
transition edge, immutable receipt/audit/outbox linkage, and synthetic positive,
malformed, token, digest, cross-binding, replay, concurrency, direct-storage,
cancellation, safety, worker-fencing, expiry, recovery, and non-authority tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core consumes an existing
lease after revalidating its exact assessment, policy, plan/task, manifest, budget,
approval, worker, token digest, lease state, and recovery bindings. No provider, model,
plugin, worker, gateway, target, secret, or network boundary is crossed.

**Threat/default-deny review:** General or direct-storage starts, malformed and unknown
contracts, wrong token, tampered state digest, cross-scope substitution, stale plan,
task, worker, lease, fence, or recovery versions, expired/released/recovered leases,
safety pause, cancellation, conflicting replay, concurrent consumption, delegation,
inheritance, wildcard, and authority-shaped input deny with stable codes. Exact replay
returns only the immutable receipt and never repeats the transition or exposes a token.

**Compatibility, privacy, migration, and rollback:** Migration 0043 additively stores
immutable receipts and replaces the transition trigger with the previous rules plus one
exact receipt-backed predicate. Existing running and terminal history remains readable;
general new starts are intentionally closed. Application rollback cannot reopen the
storage edge and retains security history; migration reversal is unsupported. Stored
data is bounded metadata and hashes—never raw tokens, credentials, secrets, evidence,
prompts, provider payloads, targets, or assessment content.

**Limitations and residual risk:** `running` remains coordination state only. Worker
dispatch/contact, checkpoints, retries, completion consumption, Master Orchestrator
runtime, UI, provider/plugin execution, and effect-specific authorization remain
deferred. Non-independent review reduces governance assurance and is accepted only for
this non-executing slice.

## 2026-08-22 — Durable orchestration task leases and worker fencing v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author, AI/Agent Lead, Core Maintainer, Contract Maintainer, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Four closed lease contracts, migration 0042, deterministic
acquire/renew/release/recovery service, one-time raw-token handling, monotonic task
generations/fencing tokens, immutable lifecycle/audit/outbox records, and synthetic
positive, malformed, replay, token, revision, concurrency, worker-revocation, safety,
recovery, storage-tampering, and non-authority tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, `INV-REL-001`, and `INV-REL-002`. Trusted core reads an existing
durable worker-registry identity and exact current readiness prerequisites. It does not
contact or launch that runtime. Models, agents, workers, plugins, UI, retrieved content,
and request bodies cannot assert eligibility, inherit authority, or alter fencing.

**Threat/default-deny review:** Unsupported versions, v1/mixed prerequisites, malformed
or duplicate commands, cross-scope bindings, expired or replaced policy/prerequisites,
cancelled or non-ready tasks, safety pause, worker ineligibility, token mismatch, stale
revision/generation/fence, conflicting replay, concurrent acquisition, and recovery-
stale state deny with stable codes. Only a token digest is persisted; the raw token is
returned once and is absent from audit/outbox data.

**Compatibility, privacy, migration, and rollback:** The contracts, service, and
migration are additive and do not alter the separate Phase 1 workflow lease. Application
rollback disables orchestration lease operations while retaining immutable history;
migration reversal is unsupported. Stored data is bounded metadata, hashes, versions,
state, and timestamps—never credentials, secrets, evidence, prompts, targets, provider
payloads, or raw lease tokens.

**Limitations and residual risk:** A registered `running` worker is used only as durable
identity; no live liveness proof or contact occurs. Dispatch, task-running transition,
checkpoints, retries, completion, Master Orchestrator runtime, UI, provider/plugin
execution, and effect-specific authorization remain deferred. Non-independent review
reduces governance assurance and is accepted only for this non-executing slice.

## 2026-08-22 — Orchestration readiness-bound manifest and budget v2

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, and Security Reviewer. The exception does not satisfy independent review
or dual control.

**Scope and evidence:** Closed v2 capability-manifest and budget request/receipt schemas,
migration 0041 immutable task-state bindings, deterministic ready-state validation,
v1 compatibility, and synthetic positive, malformed, unsupported-state, state mismatch,
replay, concurrency, recovery, cancellation, tampering, and non-authority tests.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-GRANT-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and
`INV-REL-001`. Trusted core may issue preparation metadata for an exact ready task.
Agents, models, plugins, workers, UI, retrieved content, and request bodies cannot alter
state, issue authority, or use a ready-bound manifest to create an ActionIntent.

**Threat/default-deny review:** Missing/unknown versions or task state, blocked or
terminal state, revision mismatch, state-changing replay, policy/safety/manifest/account
expiry, cross-scope identity, changed request reuse, oversubscription, malformed integer
units, tampered receipts, cancellation, and recovery-stale state deny with stable codes.
No lease, dispatch, worker assignment, grant, provider call, gateway request, or network
effect is introduced.

**Compatibility, privacy, migration, and rollback:** V1 remains running-only. Migration
0041 additively backfills immutable `task_state=running` for historical manifests and
reservations. Application rollback disables v2 production while retaining security
history; reversing the migration is unsupported. Only bounded identifiers, hashes,
integer amounts, timestamps, and state are stored—no secrets, evidence, prompts,
credentials, provider payloads, targets, or raw lease tokens.

**Limitations and residual risk:** Durable leases and worker fencing remain blocked on
this prerequisite’s merge. Checkpoints, retries, dispatch, Master Orchestrator runtime,
UI, provider/plugin execution, and effect-specific authorization remain deferred.
Non-independent review reduces governance assurance and is accepted only for this
local-development, non-executing slice.

## 2026-08-22 — Authenticated orchestration approval consumption v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy independent review or dual control.

**Scope and evidence:** Closed receipt schema, migration 0040, dedicated authenticated
API/service operation, exact storage predicate, atomic state/receipt/audit/outbox writes,
and synthetic positive, malformed, legacy-version, digest, signature, actor/session,
expiry, replay, concurrency, immutability, direct-transition, cancellation, and
recovery-stale tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-AUTH-005`, `INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`,
`INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`. The authenticated local principal
and process session cross into trusted core; only verified v2 request/decision records
can satisfy the exact readiness predicate. No model, agent, plugin, worker, gateway,
target, secret, or network boundary is trusted or crossed.

**Threat/default-deny review:** Missing authentication, v1/mixed versions, rejection,
invalid signatures or digests, caller identity, cross-scope/principal/session reuse,
expiry, cancellation, safety pause, policy or revision replacement, conflicting replay,
direct general transitions, direct storage writes without a receipt, and stale recovery
deny. Consumption changes coordination readiness only and creates no policy decision,
grant, dispatch, budget debit, network route, or external effect.

**Compatibility, privacy, migration, and rollback:** The schema, route, service method,
and receipt table are additive. Migration 0040 replaces the task transition trigger with
its prior rules plus one exact receipt-backed predicate. Rollback disables the route and
retains immutable receipts and state history; migration reversal is unsupported. Stored
data is bounded identity, provenance, hashes, revisions, and timestamps; credentials,
prompts, evidence, secrets, providers, and targets are absent.

**Limitations and residual risk:** One local desktop principal remains the identity
model. Leases, checkpoints, dispatch, UI, provider/plugin execution, and effect-specific
policy approval remain deferred. Non-independent review reduces governance assurance and
is accepted only for this local-development, non-executing slice.

## 2026-08-21 — Authenticated orchestration approval API v2

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, Desktop Maintainer, and Security Reviewer. The `GIT_WORKFLOW.md` exception
is used and does not satisfy independent review or dual control.

**Scope and evidence:** Additive closed request/decision v2 schemas, two narrowly typed
authenticated local-core routes, server-derived principal and per-process session
composition, v1/v2 replay
separation, synthetic authenticated/unauthenticated/forged-identity/confirmation/
changed-principal/stale-state tests, compatibility documentation, complete diff,
quality checks, and repository scans. No migration is required.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-AUTH-005`,
`INV-GRANT-003`, `INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`,
`INV-DATA-003`, and `INV-REL-001`; the existing bearer middleware authenticates before
body parsing, installs the local human principal, and the route passes only that
server-derived identity into the approval service. No caller identity, model, agent,
plugin, worker, tool, gateway, target, secret, or network boundary is trusted.

**Threat/default-deny review:** Missing or malformed credentials deny uniformly before
routing. Closed bodies reject actor, requester, role, authentication-context,
delegation, proxy, wildcard, and batch claims. Missing/false confirmation, changed
principal or session, v1/v2 mixing, malformed or unsupported data, stale policy/plan/task state,
expiry, cancellation, terminal state, changed replay, signature/content tampering, and
signer failure deny with stable codes. Approval remains non-authoritative and cannot
move a task out of `awaiting_human`.

**Compatibility, privacy, migration, and rollback:** V2 schemas and routes are
additive; v1 records remain readable and trusted-internal v1 production remains
compatible, while mixed-version use denies. Existing tables already store immutable
canonical documents, so no database migration is needed. Only the fixed local actor,
random per-process session UUID, and bounded approval metadata are added; credentials, prompts, evidence,
targets, secrets, and provider payloads are absent. Rollback removes the routes and v2
production while preserving immutable history.

**Limitations and residual risk:** The current launch credential maps to one local
desktop actor rather than multiple human accounts or OS-backed user identity; process
sessions are separately fenced.
Approval consumption, UI, leases, checkpoints, dispatch, provider execution, and
effect-specific policy approval remain deferred. Non-independent review reduces
governance assurance and is accepted only for this local-development, non-executing
slice.

## 2026-08-21 — Orchestration task approval v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy independent review or dual control.

**Scope and evidence:** Closed request/decision schemas, migration 0039, deterministic
request and signed-decision service, immutable persistence, audit/outbox linkage, and
synthetic positive, malformed, confirmation, replay, conflict, concurrency, expiry,
cancellation, signer, transition, and recovery-fencing tests.

**Invariants and trust boundaries:** `INV-AUTH-001` through `INV-AUTH-003`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and
`INV-REL-001`; trusted core creates the request, then its asserted human actor identifier
crosses into an immutable signed non-authoritative decision. Authentication remains a
documented prerequisite rather than a claim made by this slice. No provider, model,
plugin, worker, tool, gateway, target, secret, or network boundary is crossed.

**Threat/default-deny review:** Missing confirmation, malformed identity, unsupported
decision, stale policy/plan/task revisions, cross-scope substitution, changed replay,
expiry, cancellation, terminal state, signature/content tampering, and signer
unavailability deny with stable codes. Approval cannot alter task state, scope, policy,
capability, budget, privacy, or authority. Rejection can only use the pre-existing
`awaiting_human -> cancelled` transition.

**Compatibility, privacy, migration, and rollback:** Additive schemas, service, and
migration; no existing ActionIntent, approval, grant, or orchestration contract changes.
Only bounded metadata, identities, hashes, timestamps, decision reason, and signature
are stored. No prompts, evidence, targets, credentials, or secret references are stored.
Rollback disables the service and retains security history; migration 0039 is not
reversed.

**Limitations and residual risk:** Authenticated API/UI composition and a dedicated
approval-consuming readiness transition are deferred, as are leases, checkpoints,
dispatch, provider execution, and effect-specific policy approval. Non-independent
review reduces governance assurance and is accepted only for this local-development,
non-executing slice.

## 2026-08-21 — Durable orchestration task budget v1

**Review record:** Sole-maintainer security review — non-independent. The reviewer is
the repository owner, author, Product Owner, Principal Architect, Security Lead,
AI/Agent Lead, Core Maintainer, Contract Maintainer, Data Protection Lead, Execution
Safety Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used and does
not satisfy independent review or dual control.

**Scope and evidence:** Closed request/reservation schemas, migration 0038, durable
account activation, atomic reservation and recovery service, immutable identity,
hash-chained audit/outbox linkage, synthetic positive/default-deny/replay/concurrency/
expiry/cancellation/recovery/tampering tests, documentation, complete diff, quality
checks, and repository scans.

**Invariants and boundaries:** `INV-AUTH-001` through `INV-AUTH-003`, `INV-NET-005`,
`INV-AGENT-001` through `INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`,
`INV-REL-001`, and `INV-REL-002`; validated provider ceilings cross into a trusted
assessment account, then an untrusted request crosses deterministic current-state and
atomic accounting checks into a non-authoritative reservation. No provider, model,
secret broker, worker, tool, gateway, target, or network boundary is crossed.

**Threat/default-deny review:** Missing/unknown fields, floating-point or empty values,
overflow boundaries, authority-shaped input, stale account/policy/plan/task/manifest
versions, cross-scope or cross-agent substitution, manifest tampering, changed replay,
concurrent oversubscription, expiry, cancellation, terminal state, recovery ambiguity,
and persisted identity mutation deny with stable codes. Exact replay cannot bypass
fresh current-state checks. No material finding is accepted.

**Compatibility, privacy, migration, and rollback:** Additive contracts/service and
migration; existing AI and gateway ledgers and ActionIntent producers are unchanged.
Only identifiers, hashes, timestamps, states, and integer ceilings/amounts are stored;
no prompts, evidence, targets, credentials, secret references, or provider payloads.
Rollback disables the service and retains security history; migration 0038 is not
reversed.

**Limitations and residual risk:** Trusted account activation is not yet reached
through an authenticated Master Orchestrator. Provider usage reconciliation,
committed debit, per-action budget composition, leases, checkpoints, approvals,
dispatch, and execution remain deferred. Non-independent review reduces governance
assurance and is accepted only for this local-development non-executing slice.

## 2026-08-21 — Task capability manifest v1

**Review record:** Sole-maintainer security review — non-independent. The repository
owner is also author and security reviewer; the `GIT_WORKFLOW.md` exception is used and
does not satisfy an independent-review requirement.

**Scope and evidence:** Closed manifest and request-v2 schemas, migration 0037,
trusted-core issuance and conversion composition, immutable provenance, synthetic
positive/default-deny/replay/tampering/expiry/limit/cancellation/recovery tests,
contract and action-plan documentation, complete diff, quality checks, and repository
scans.

**Invariants and trust boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`; trusted core issues
a non-authoritative ceiling after current-state validation, then treats each agent
proposal as untrusted input and revalidates every binding before creating only a
pending ActionIntent. No provider, model, plugin, worker, tool, gateway, target, or
network boundary is crossed.

**Threat/default-deny review:** Wildcards, caller issuance, delegation, privilege
inheritance, unsupported operations, secret/credential/raw-evidence fields, malformed
or unknown data, stale policy/plan/task/manifest revisions, cross-scope or cross-agent
substitution, changed replay, expiry, limit expansion, cancellation, terminal state,
safety pause, and recovery reuse deny with stable codes. Exact replay is idempotent
only while current security bindings remain valid. No material finding is accepted.

**Compatibility, privacy, migration, and rollback:** Request v2 is additive; request
v1 is retained for stored-document compatibility but denied for new conversion.
ActionIntent v1 and other producers are unchanged. Migration 0037 preserves old rows
with nullable linkage and adds immutable manifest records. Only bounded metadata and
opaque digests are stored; no secrets or content. Rollback disables issuance and new
v2 conversion while retaining immutable history; the migration is not reversed.

**Limitations and residual risk:** Agent transport authentication, authenticated Master
Orchestrator authorship, generalized capability issuance, approvals, budget charging,
leases, dispatch, and execution remain deferred. Non-independent review reduces
governance assurance and is accepted only for this local-development non-executing
slice.

## 2026-08-21 — Agent request to pending ActionIntent v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer,
Execution Safety Lead, Data Protection Lead, and Security Reviewer. The
`GIT_WORKFLOW.md` exception is used. This review is not independent.

**Scope and evidence:** Closed request schema, migration 0036, deterministic conversion
service, immutable provenance/audit linkage, synthetic positive/default-deny/replay/
concurrency/tampering tests, migration checks, documentation, complete diff, quality
checks, and repository scans.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-DATA-003`, and `INV-REL-001`; untrusted agent
proposal to trusted deterministic validation, then immutable pending intent,
provenance, audit, and outbox persistence. No evaluation, approval, grant, provider,
plugin, worker, tool, gateway, target, or network boundary is crossed.

**Threat/default-deny review:** Unknown fields, raw-secret/command-shaped input,
delegation, unsupported agent/capability/method, action-digest or canonical-target
tampering, stale/expired input, cross-assessment/policy/plan/task substitution, stale
revisions, cancelled/terminal/non-validation tasks, paused safety, replay conflict,
concurrency, and database mutation deny. Exact replay is idempotent. No material
finding is accepted.

**Compatibility, privacy, migration, and rollback:** Additive schema/table/service;
ActionIntent v1 and prior producers are unchanged. Metadata and opaque digests only;
no content or secrets. Rollback disables conversion and retains immutable records;
migration 0036 is not reversed.

**Limitations and residual risk:** Agent/runtime identity is structurally bound but not
transport-authenticated. The input digest has no source artifact in this slice. Master
Orchestrator authorship, general capability manifests, approval, budgets, cancellation,
provider/model/runtime integration, and end-to-end evaluation remain deferred.
Non-independent review reduces governance assurance; the sole maintainer accepts that
risk only for this local-development non-executing slice.

## 2026-08-21 — Durable orchestration plan graph v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Plan-graph and transition schemas, migration 0035, deterministic
service, synthetic graph/transition/concurrency/recovery tests, migration tests,
contract and action-plan documentation, complete diff, quality checks, and repository
scans. Exact validation results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-003`, `INV-DATA-001`, `INV-REL-001`, and `INV-REL-002`; untrusted graph and
command documents to deterministic validation, validated coordination state to SQLite,
and interrupted state to fail-closed recovery. No provider, secret, evidence-content,
agent, worker, plugin, tool, gateway, target, or network boundary is crossed.

**Threat and abuse cases:** malformed/oversized graphs, duplicate or conflicting
identity, missing/cross-plan references, self/cyclic/duplicate edges, unsupported task
or dependency type, privilege inheritance, stale plan/task revision, cross-assessment
substitution, changed command replay, invalid or terminal transition, concurrent
mutation, database tampering/deletion, and restart attempts to resume interrupted work.

**Default-deny findings:** Closed contracts precede semantic checks. Exact assessment,
plan, task, revision, command identity, transition, and request time are bound. Graph
creation derives readiness rather than trusting caller state. Database constraints and
triggers retain non-authority, immutable identity/history, and monotonic revisions.
Recovery only fails interrupted tasks. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts and
migration; existing workflow and authorization records are unchanged. Only bounded
metadata and opaque references are stored. Raw secrets/evidence/model content are
absent. Application rollback disables the new service and retains immutable records;
the migration is not reversed.

**Limitations and residual risk:** Plan authorship and activation are not authenticated;
human approval, audit/outbox linkage, cancellation propagation, leases, checkpoints,
retries, budgets, retention, Master Orchestrator logic, agents, tool-to-`ActionIntent`
conversion, and execution are deferred. No task is dispatched. Non-independent review
reduces governance assurance; the sole maintainer accepts that risk only for this
local-development non-executing slice.

## 2026-08-20 — AI provider configuration contract v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, Core Maintainer, Contract Maintainer, and Security Reviewer.
The `GIT_WORKFLOW.md` sole-maintainer exception is used. This review is not independent
and does not satisfy any external independence or dual-control requirement.

**Scope reviewed:** The complete provider configuration schema, deterministic validator,
synthetic tests, compatibility documentation, Phase 2 dependency ordering, and the
unchanged Phase 1 authorization/network boundary.

**Invariants and trust boundaries:** `INV-AUTH-003`, `INV-AGENT-001`,
`INV-AGENT-004`, and `INV-DATA-001`; untrusted configuration/model producers to the
trusted core policy; core to a future secret broker; core to future local and remote
provider adapters. No provider, broker, adapter, model, evidence, or network boundary
is crossed by this slice.

**Threat and abuse cases examined:** provider/model substitution, provider-type
confusion, configuration expiry and future dating, remote use without dual opt-in,
raw credential fields, cross-provider secret references, secret or restricted raw
evidence routing, unknown properties, disabled execution mutation, zero/unbounded and
over-ceiling budgets, and configuration data attempting to expand the trusted
allowlist.

**Default-deny findings:** Schema validation precedes semantic validation. Exact
provider/model allowlists are supplied by trusted code. Missing, malformed, stale,
ambiguous, conflicting, unsupported, privacy-violating, or over-budget inputs deny with
stable codes. No configuration value can enable execution or create authorization.

**Compatibility, migration, privacy, secrets, and rollback:** The v1 contract is
additive and has no legacy consumers. No migration or persistence is introduced.
Remote routing is explicit and deny-by-default; secret and restricted raw evidence are
forbidden. Only opaque, provider-bound secret references are representable. Rollback
removes the additive files without data conversion or authority recovery.

**Evidence examined:** Targeted and full Python tests, JSON contract validation, Ruff,
mypy, complete branch diff, staged-path review, and scans for credentials, real targets,
databases, caches, generated output, and merge markers. Exact command results are
recorded in the pull request.

**Findings:** No material finding accepted. The local-runtime cost value is configured
but not reserved or charged; all budget enforcement beyond validation remains deferred.

**Limitations and residual risk:** Provider adapters, real secret storage/resolution,
context assembly, runtime budget accounting, prompt-injection defenses, structured
output, persistence/audit, UI, and provider availability are absent. The slice must not
be described as completing either provider-adapter or full allowlist/budget action-plan
items. Governance assurance is reduced because review is non-independent; the sole
maintainer accepts that governance risk only for this local-development contract slice.

## 2026-08-20 — Trusted AI provider registry v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete registry schema/compiler, configuration-policy
composition change, synthetic tests, contract documentation, action-plan note, complete
diff, contract validation, Python unit and pytest suites, Ruff, mypy, and repository
scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, `INV-AGENT-004`, and
`INV-DATA-001`; untrusted registry documents to trusted deterministic compilation, and
compiled policy to provider-configuration validation. No provider, secret broker,
evidence store, model, target, or network boundary is crossed.

**Threat and abuse cases:** malformed/missing registry data, provider/model
substitution, duplicate identity ambiguity, order-dependent disabled entries, stale or
future policy, configuration outliving policy, expired-policy reuse, empty/degraded
allowlists, forbidden data routing, invalid budgets, execution-enable mutation, and
source-document mutation after compilation.

**Default deny and findings:** Schema validation precedes semantic compilation.
Malformed, stale, ambiguous, privacy-unsafe, and empty-enabled registries deny with
stable codes. Compiled maps are immutable snapshots with registry revision and expiry.
Configuration cannot outlive or reuse expired registry policy. No material finding is
accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive registry v1;
configuration v1 remains compatible. Secret and restricted raw evidence routing denies,
and the registry stores no secret references or values. There is no persistence or
migration. Rollback removes the additive registry boundary without data conversion or
authority recovery.

**Limitations and residual risk:** Registry origin authentication, signatures,
rollback protection, durable activation/revocation, audit, UI, adapters, context
construction, secret brokerage, and runtime budget accounting are deferred. Execution
remains disabled. Non-independent review reduces governance assurance; the sole
maintainer accepts that risk only for this local-development non-executing slice.

## 2026-08-20 — Non-resolving AI secret reference v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete secret-reference schema/validator, provider
configuration and registry composition, synthetic tests, contract documentation,
action-plan note, complete diff, contract validation, Python unit and pytest suites,
Ruff, mypy, and repository scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, `INV-AGENT-004`, and
`INV-DATA-001`; untrusted descriptor to deterministic validation, configuration to
opaque reference binding, and future core to secret broker. No credential store,
provider, model, evidence, target, or network boundary is crossed.

**Threat and abuse cases:** raw-secret fields, malformed reference identity,
cross-provider confusion, configuration reuse/replay, purpose confusion, future/stale/
overlong lifetime, incomplete configuration coverage, revocation bypass, local-runtime
secret attachment, attempted resolution enablement, and invalid underlying registry or
configuration authority.

**Default deny and findings:** Schema validation rejects unknown/raw-value-shaped and
resolution-enabled documents. Exact configuration, provider, URI, purpose, lifecycle,
and time binding is required. Revoked, local, stale, mismatched, or reused descriptors
deny with stable codes. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive descriptor v1;
provider configuration/registry v1 stay compatible. No secret value or store locator is
represented, resolved, logged, or exposed. There is no persistence or migration.
Rollback removes the additive descriptor boundary without data conversion or authority
recovery.

**Limitations and residual risk:** Credential-store custody, broker authentication,
just-in-time and single-use resolution, rotation, durable revocation, audit, recovery,
redaction scans, UI, adapters, and runtime execution remain deferred. Non-independent
review reduces governance assurance; the sole maintainer accepts that risk only for
this local-development non-resolving slice.

## 2026-08-21 — Deterministic AI budget reservation v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Complete reservation-request and receipt schemas, deterministic
in-memory ledger, synthetic tests, contract documentation, action-plan note, complete
diff, contract validation, Python unit and pytest suites, Ruff, mypy, and repository
scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001`, and `INV-NET-005`;
untrusted reservation request to deterministic accounting, trusted configuration and
registry revision to a fenced ledger, and recovered receipts to fail-closed state. No
provider, secret broker, model, evidence, target, gateway, or network boundary is
crossed, and no execution authority is created.

**Threat and abuse cases:** malformed or empty amounts, integer boundary violations,
cumulative and concurrent oversubscription, duplicate and conflicting replay, stale
ledger versions, configuration/registry substitution, stale requests, overlong or
expired reservations, invalid lifecycle transitions, tampered recovery records,
duplicate recovered identity/version, and recovery of oversubscribed state.

**Default deny and findings:** Contract validation precedes semantic accounting.
Atomic compare-and-reserve, exact idempotency, monotonic version fencing, bounded
lifetime, immutable snapshots, and strict recovery validation deny unsafe state with
stable codes. Expired reservations cannot commit and are released during recovery. No
material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
provider configuration, registry, and secret-reference v1 remain compatible. Only
counts and opaque identifiers are accepted; no prompt, evidence, secret value, or
secret resolution is present. There is no persistence or migration. Rollback removes
the additive ledger boundary without data conversion or authority recovery.

**Limitations and residual risk:** Durable crash-atomic storage, audit linkage,
per-task and per-assessment aggregation, cancellation, pricing/version provenance,
provider usage reconciliation, and runtime deadline enforcement are deferred. Provider
execution remains disabled. Non-independent review reduces governance assurance; the
sole maintainer accepts that risk only for this local-development non-executing slice.

## 2026-08-21 — Assessment retrieval metadata and ACL v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Retrieval policy, request, and result schemas; immutable policy
compiler; metadata-only assessment catalog; envelope revalidation; ACL, version,
lifetime, replay, and deterministic ordering logic; synthetic positive, negative,
tampering, expiry, injection, and concurrency tests; contract/compatibility docs;
action-plan note; complete diff; contract validation; Python unit and pytest suites;
Ruff; mypy; and repository scans. Exact results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; trusted-core policy injection to immutable ACLs,
untrusted request to exact subject/purpose filtering, validated envelopes to bounded
metadata, and instruction-like content to inert annotations. No acquisition, content
return, index, model context, provider, secret broker, evidence store, plugin, target,
tool, gateway, agent, or network boundary is crossed, and no execution authority is
created.

**Threat and abuse cases:** malformed/future/stale/overlong policy, duplicate subject,
untrusted policy substitution, unknown or child subject, cross-purpose reuse, requested
origin/classification/limit expansion, secret/raw classification, cross-assessment
request or envelope, stale policy/catalog/request, invalid envelope provenance/digest/
metadata/lifetime, duplicate identity/provenance, result ambiguity, exact/conflicting/
concurrent replay, and prompt-injection attempts to mutate filters or authority.

**Default deny and findings:** Closed contracts precede semantic checks. Policy,
catalog, subject, purpose, query digest, filter subsets, result ceiling, and time are
exactly bound. Every envelope is revalidated before selection, any invalid member
denies the entire request, ordering is deterministic, and content is omitted. Request
identity consumption is locked. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
existing AI boundaries remain compatible. Secret and restricted-raw classifications
are unrepresentable, and results expose only bounded provenance metadata rather than
content. No secret resolution, content logging, persistence, or migration exists.
Rollback removes the additive boundary without conversion or authority recovery.

**Limitations and residual risk:** Policy injection is trusted but not authenticated;
ACL/catalog/request state and replay fencing are process-local. Durable policy
activation, indexing, acquisition, persistent ACLs, idempotent recovery, audit,
retention/deletion, content retrieval, query matching, embeddings, context construction,
provider routing, and agent integration are deferred. Provider execution remains
disabled. Non-independent review reduces governance assurance; the sole maintainer
accepts that risk only for this local-development non-executing slice.

## 2026-08-26 — Retry-budget consumption v2

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer,
Execution Safety Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used.
This review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Retry-budget consumption command/receipt v2, additive migration
0061, trusted-core accounting composition, immutable lineage and storage guards,
synthetic positive/default-deny/replay/concurrency/recovery tests, migration tests,
contract and compatibility documentation, action-plan update, complete diff, and local
validation recorded in the pull request.

**Security boundaries:** Only an exact current eligible decision v2 may consume one
remaining integer retry unit. Capacity is derived from the original immutable
reservation and prior v1 receipt; the refreshed v3 reservation cannot replenish it.
Account-version fencing and unique lineage prevent oversubscription and forks. Records
remain `authority: none` and `execution_enabled: false`. No attempt, schedule,
transition, lease, worker contact, provider/plugin call, network authority, or external
effect is created; the Phase 1 authorization chain is unchanged.

**Threats and default deny:** Denied, malformed, mixed-version, expired, tampered,
exhausted, overflow-prone, cross-scope, stale-policy, cancelled, safety-paused,
worker-revoked, recovery-stale, competing, changed-replay, and direct-storage inputs
deny. One-unit reservations terminate before v2 consumption rather than being refunded,
borrowed, or reinterpreted.

**Compatibility, privacy, migration, and rollback:** V1 behavior and immutable rows are
unchanged. Migration 0061 is additive and retains metadata-only accounting history.
Application rollback disables v2 issuance; consumed capacity remains non-refundable and
migration reversal is unsupported. Contracts exclude secrets, evidence, assessment
content, raw tokens, diagnostics, URLs, paths, commands, provider/plugin output, and
arbitrary blobs.

**Limitations and residual risk:** Attempt-three identity, scheduling, activation,
readiness prerequisites, leasing, checkpoints, failure/completion, dispatch, runtime
composition, provider/plugin execution, UI, Phase 2 demonstrations, and independent
review remain deferred. Non-independent review reduces governance assurance; the sole
maintainer accepts that risk only for this local-development non-executing slice.

## 2026-08-21 — Strict AI structured output v1

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Candidate-observation, repair-request, and parse-result schemas;
strict parser and one-repair session boundary; synthetic negative and concurrency tests;
contract and compatibility documentation; action-plan note; complete diff; contract
validation; Python unit and pytest suites; Ruff; mypy; and repository scans. Exact
results are recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; raw untrusted bytes to deterministic parsing,
initial failure to bounded repair metadata, and parsed candidate to a non-authoritative
result. No provider, model context, secret broker, evidence, target, gateway, agent, or
network boundary is crossed, and no execution authority is created.

**Threat and abuse cases:** invalid encoding, empty or oversized bytes, duplicate JSON
keys, trailing content, non-finite numbers, type coercion, non-object roots, missing or
unknown fields, unsupported versions/types/operations, excessive nesting or
collections, altered limits, digest/failure substitution, future/stale repair,
unexpected repair, replay, concurrent consumption, and repair exhaustion.

**Default deny and findings:** Byte limits precede decoding; strict UTF-8/JSON and
contract validation precede acceptance. Repair eligibility is narrow, short-lived,
digest-bound, fixed-limit, and atomically one-use. All results retain execution disabled
and accepted content remains candidate data. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contracts;
the existing provider, registry, secret-reference, and budget contracts remain
compatible. There are no dedicated prompt, evidence, assessment-data, credential,
secret-value, or reference fields, and the parser neither logs nor routes content.
Bounded descriptive strings remain untrusted and require later classification at every
consumer. There is no persistence or migration. Rollback removes the additive boundary
without data conversion or authority recovery.

**Limitations and residual risk:** Repair replay state is process-local; provider calls,
actual repair prompting, durable state/audit, broader typed outputs, untrusted-content
envelopes, prompt-injection evaluation, context routing, and agent consumers are
deferred. Provider execution remains disabled. Non-independent review reduces
governance assurance; the sole maintainer accepts that risk only for this local-
development non-executing slice.

## 2026-08-21 — Untrusted content envelope v1 and injection corpus

**Review record:** Sole-maintainer security review — non-independent.

**Roles held by reviewer:** repository owner, author, Product Owner, Principal
Architect, Security Lead, AI/Agent Lead, Core Maintainer, Contract Maintainer, Data
Protection Lead, and Security Reviewer. The `GIT_WORKFLOW.md` exception is used. This
review is not independent and cannot satisfy an external independence requirement.

**Scope and evidence:** Envelope schema; deterministic builder, validator, indicator
metadata, and process-local replay registry; eleven-family synthetic prompt-injection
corpus; positive, negative, boundary, tampering, replay, and concurrency tests; contract
and compatibility documentation; action-plan note; complete diff; contract validation;
Python unit and pytest suites; Ruff; mypy; and repository scans. Exact results are
recorded in the pull request.

**Invariants and boundaries:** `INV-AUTH-003`, `INV-AGENT-001` through
`INV-AGENT-004`, and `INV-DATA-001`; untrusted origin text to an inert assessment-
scoped envelope, provenance and digest metadata to deterministic validation, and
instruction-like text to non-authoritative annotations. No acquisition, provider,
model context, secret broker, evidence store, plugin, target, tool, gateway, agent, or
network boundary is crossed, and no execution authority is created.

**Threat and abuse cases:** unknown or forbidden origin/classification, secret or raw-
evidence classification, oversized UTF-8, cross-assessment substitution, origin/
provenance mismatch, content-digest and injection-metadata tampering, future/expired/
overlong lifetime, envelope identity conflict, provenance reuse, exact and concurrent
replay, authority-shaped unknown fields, and direct, indirect, encoded, obfuscated,
delimiter-breaking, role-confusion, authority-claim, secret-exfiltration, tool-call,
policy-mutation, and data-poisoning content.

**Default deny and findings:** Closed schema validation precedes semantic checks. Exact
scope, origin/provenance namespace, UTF-8 byte ceiling, digest, recomputed metadata, and
bounded lifetime are mandatory. Registry mutation is locked and rejects replay or
ambiguous identity/provenance. Detection never changes authority or serves as an
authorization control. No material finding is accepted.

**Compatibility, privacy, secrets, migration, and rollback:** Additive v1 contract;
existing AI boundaries remain compatible. Secret and restricted-raw classifications
are unrepresentable, and no credential/reference field, resolution, logging, or routing
exists. Arbitrary text can still be misclassified or contain sensitive material, so
future consumers must authenticate classification. There is no persistence or
migration. Rollback removes the additive boundary without conversion or authority
recovery.

**Limitations and residual risk:** Replay and provenance state are process-local;
source authentication, live acquisition, retrieval ACLs, classification assurance,
secret scanning, active-content stripping, context construction, provider routing,
canary traces, live model evaluation, and agent integration are deferred. Provider
execution remains disabled. Non-independent review reduces governance assurance; the
sole maintainer accepts that risk only for this local-development non-executing slice.
