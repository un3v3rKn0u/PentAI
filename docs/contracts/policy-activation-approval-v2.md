# Policy Activation Approval v2

## Scope

Policy Activation Approval v2 records one authenticated human `approved` or `rejected`
decision for the exact current Engagement Manifest v3 and immutable inactive Policy IR
v2 tuple. Trusted core derives every assessment, manifest, policy, version, and hash
binding from durable state and signs the closed document under the
`pentai-policy-activation-approval-v2` domain.

The caller supplies only the decision, an optional bounded reason and expiry, and the
policy identifier in the authenticated route. The actor comes from the server-side
local session. The approval is fixed to `authority: none` and
`execution_enabled: false`; it is chronology and review evidence and can be consumed
only by the version-exact Policy IR v2 activation transition.

## Default deny and lifecycle

Production revalidates the current source-backed Manifest v3, Policy IR v2 hash and
signature, latest manifest identity, engagement and policy validity, configured signer,
and global safety state in one transaction. Unsupported or mixed versions, superseded
manifests, stale provenance, altered signatures, expired state, inactive safety, and
cross-scope substitution deny with stable codes. An approval cannot outlive its policy.

Migration 0094 adds an insertion predicate to the existing immutable approval ledger.
It binds the v2 document to the relational manifest and policy rows and requires the
exact signer identity. Existing approval immutability and deletion denial remain in
force. Repeated decisions create separate immutable human-history records and do not
consume or supersede one another.

## Compatibility and rollback

Policy IR v1 continues to use Approval v1.2 without behavioral or signature changes.
Migration 0095 permits only an exact inactive-to-active Policy IR v2 transition backed
by a current approved v2 document, plus later fail-closed revocation. Trusted core
revalidates both signatures and all current durable lineage before activation. Startup
recovery never creates, consumes, activates, or resumes policy.

PolicyDecision v2 evaluation is now available as non-authorizing metadata. Local-model
approval consumption, grants, adapter execution, and external effects remain disabled.
Activation is coordination state and creates no execution authority.

Migration 0094 is additive. Older application versions ignore v2 approval documents.
Operational rollback should retain the validation and lifecycle triggers. Before an
older binary is used, any active Policy IR v2 must be revoked through the reviewed
service path. Removing v2 approval history requires a separately reviewed retention
decision rather than an automatic downgrade.
