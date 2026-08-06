# Authorized AI Security Testing: Intake and Operating Workflow

## Purpose

This document defines a platform-independent, reusable process for supplying an authorized AI security agent with the information needed for bug-bounty, vulnerability-disclosure, and penetration-testing engagements.

The workflow remains consistent across organizations. Only the engagement manifest, supporting sources, credentials, and known-issue catalog change.

## Core authorization model

Every proposed test must pass these gates:

```text
Valid program authorization
    → In-scope asset
    → Permitted technique
    → Operational limits satisfied
    → Known-issue and duplicate check
    → Minimal safe validation
    → Human-reviewed report
```

Core rules:

- **Default deny:** Missing, ambiguous, conflicting, expired, or unstated authorization means no testing.
- **Exact matching:** Scope is evaluated using canonical asset identifiers.
- **Least-impact validation:** Collect only enough evidence to establish the issue.
- **No inferred authority:** Related domains, subsidiaries, vendors, IP neighbors, redirects, and discovered infrastructure are not automatically in scope.
- **Time-bound authorization:** Testing stops when authorization expires, is revoked, or materially changes.
- **Human checkpoints:** Sensitive validation and report submission require human approval.
- **Traceability:** Every action records the manifest rule and version that authorized it.

## Reusable engagement manifest

Use a versioned YAML or equivalent JSON/database representation. Do not store raw passwords, tokens, private keys, cookies, or recovery codes in the manifest; store short-lived references to an approved secret manager.

```yaml
schema_version: "1.0"

engagement:
  id: ""
  organization: ""
  program_name: ""
  platform: ""
  program_url: ""
  program_type: "public_bug_bounty | private_bug_bounty | vdp | pentest"
  status: "draft | approved | active | paused | expired | revoked"
  effective_from: ""
  expires_at: ""
  approved_by: ""
  contacts:
    security: ""
    emergency: ""
    platform: ""
  source_hashes: []
  last_rules_check: ""

program_overview:
  objectives: []
  priority_areas: []
  business_context: ""
  timezone: "UTC"
  allowed_testing_windows: []
  blackout_periods: []

scope:
  assets:
    - asset_id: ""
      type: "domain | wildcard_domain | url | ip | cidr | api | mobile_app | repository | cloud_resource | hardware"
      value: ""
      status: "in_scope | out_of_scope"
      environment: "production | staging | test"
      ownership_verified: false
      allowed_paths: []
      excluded_paths: []
      allowed_ports: []
      excluded_components: []
      source_reference: ""
      notes: ""
  discovered_assets_default: "deny"
  related_domains_default: "deny"
  redirects_outside_scope: "stop"
  third_party_services: "deny_unless_explicit"
  shared_hosting_and_cdn: "deny_unless_explicit"
  scope_expansion_process: ""

techniques:
  permitted:
    - id: ""
      category: ""
      description: ""
      applicable_assets: []
      conditions: []
  prohibited:
    - "denial_of_service"
    - "social_engineering"
    - "physical_security"
    - "destructive_testing"
  conditional:
    - category: ""
      requires_prior_approval: true
      approval_reference: ""
  restrictions:
    command_execution: "prohibited | proof_only | permitted"
    file_uploads: "prohibited | benign_only | permitted"
    data_modification: "prohibited | own_test_data_only"
    automated_scanning: "prohibited | permitted_with_limits"
    credential_testing: "test_accounts_only"
    out_of_band_services: []

operational_limits:
  requests_per_second: 0
  per_host_requests_per_second: 0
  burst_limit: 0
  concurrent_connections: 0
  scanner_threads: 0
  required_headers: {}
  registered_source_ips: []
  user_agent: ""
  real_user_data: "avoid_and_stop"
  maximum_records_to_view: 0
  evidence_retention_days: 0
  approved_storage_locations: []
  stop_conditions:
    - "Service instability or performance degradation"
    - "Unexpected access to real-user data"
    - "Evidence that an asset belongs to a third party"
    - "Unexpected destructive capability or lateral access"
    - "Program suspension, expiration, or material rule change"
    - "Rate-limit or abuse-control warnings"
  incident_process:
    stop_immediately: true
    preserve_minimal_logs: true
    contact_within_minutes: 0

safe_harbor:
  available: false
  covered_activities: []
  conditions: []
  exclusions: []
  jurisdictions: []
  disclosure_terms: ""
  publication_allowed: false
  publication_approval_required: true
  source_reference: ""

architecture:
  summary: ""
  trust_boundaries: []
  internet_entry_points: []
  frontend: []
  backend: []
  api: []
  identity: []
  cloud: []
  mobile: []
  infrastructure: []
  data_classifications: []
  integrations:
    - name: ""
      owner: "organization | third_party | shared"
      testing_status: "allowed | prohibited | unknown"
  assumptions:
    - statement: ""
      verified: false
      source: ""

authentication:
  required: false
  approved_account_types: []
  test_accounts:
    - account_id: ""
      role: ""
      environment: ""
      credential_reference: ""
      permitted_actions: []
      prohibited_actions: []
  mfa_process: ""
  account_creation_allowed: false
  multiple_account_testing_allowed: false
  real_user_accounts: "prohibited"
  privilege_escalation_validation: "stop_after_minimal_proof"

rewards_and_severity:
  severity_standard: "program_specific | CVSS | custom"
  severity_definitions:
    critical: ""
    high: ""
    medium: ""
    low: ""
    informational: ""
  reward_table: []
  impact_requirements: []
  reward_exclusions: []
  chained_findings_policy: ""
  duplicate_policy: ""
  first_to_report_rule: ""

reporting:
  submission_channel: ""
  required_fields:
    - "Title"
    - "Affected asset"
    - "Vulnerability type"
    - "Reproduction steps"
    - "Observed and expected behavior"
    - "Security impact"
    - "Minimal evidence"
    - "Suggested remediation"
  evidence_rules: []
  redaction_rules: []
  video_allowed: false
  exploit_code_allowed: false
  disclosure_timeline: ""
  remediation_retest_policy: ""
  submission_requires_human_approval: true

known_issues:
  sources: []
  entries:
    - issue_id: ""
      title: ""
      status: "known | reported | duplicate | accepted_risk | excluded | fixed"
      vulnerability_class: ""
      affected_assets: []
      affected_versions: []
      fingerprints: []
      root_cause_family: ""
      first_seen: ""
      fixed_at: ""
      retest_allowed: false
      submission_allowed: false
      notes: ""

agent_controls:
  autonomy: "recommend_only | supervised_testing | bounded_execution"
  allowed_tools: []
  prohibited_tools: []
  network_allowlist: []
  network_denylist: []
  redirect_revalidation: true
  dns_rebinding_protection: true
  maximum_test_depth: 0
  maximum_runtime_minutes: 0
  human_approval_required_for:
    - "Authentication or authorization bypass validation"
    - "Access to sensitive information"
    - "Any server-side execution indication"
    - "Conditionally permitted techniques"
    - "Following a redirect to a different asset"
    - "Increasing request rate or validation impact"
    - "Preparing or submitting a report"

approvals:
  scope_reviewer: ""
  legal_and_rules_reviewer: ""
  technical_controls_reviewer: ""
  known_issue_reviewer: ""
  approved_at: ""
  status: "pending | approved | rejected"

provenance:
  created_at: ""
  updated_at: ""
  sources:
    - source_id: ""
      reference: ""
      retrieved_at: ""
      content_hash: ""
      authority: "contract | program_page | program_staff | platform_rule | internal_note"
  unresolved_questions: []
  normalization_warnings: []
```

## Intake and normalization procedure

### 1. Collect authoritative material

Collect the program brief, scope tables, rules, safe-harbor text, platform-wide rules, reward table, written clarifications, architecture information, test-account instructions, disclosure requirements, and known or excluded issues.

For each source, retain its location, retrieval time, authority level, effective date, version, and content hash.

### 2. Extract without inference

Map every relevant source statement to the manifest and preserve its source reference. Classify each rule as:

- Explicitly permitted
- Explicitly prohibited
- Conditional on prior approval
- Unknown or unstated

Never convert “not prohibited” into “permitted.” Record ambiguities as unresolved and deny the affected activity until clarified.

### 3. Canonicalize scope

- Lowercase domains and remove trailing dots.
- Normalize internationalized domain names consistently.
- Define whether a wildcard includes the apex domain; never assume it does.
- Normalize URLs by scheme, host, port, and path boundary.
- Parse IP addresses and CIDRs with strict network semantics.
- Identify mobile apps by package/bundle ID, signer, and approved source.
- Identify CDN, SaaS, cloud, tenant, and shared-hosting boundaries.
- Treat redirects, alternate ports, new IPs, sibling domains, and discovered services as new authorization decisions.

DNS resolution alone is not proof of ownership or authorization.

### 4. Resolve conflicts

Unless the contract says otherwise, use this precedence:

1. Signed authorization or engagement contract
2. Explicit written clarification from authorized program personnel
3. Current program rules and scope page
4. Platform-wide rules
5. Internal notes or analyst assumptions

If authoritative sources conflict, apply the more restrictive rule and pause affected testing until resolved.

### 5. Validate completeness

Do not activate the engagement until:

- Authorization is current and attributable.
- At least one exact in-scope asset exists.
- Out-of-scope and third-party boundaries are defined.
- Technique permissions and operational limits are known.
- Stop conditions and emergency contacts exist.
- Authentication restrictions are resolved.
- Evidence and data-handling rules are defined.
- Reporting and duplicate policies are captured.
- Known-issue sources have been checked.
- Material ambiguity is resolved or explicitly denied.
- A human has approved the normalized manifest.

Perform schema and semantic validation. Reject contradictions such as an asset being both allowed and denied, an expired authorization, conditional testing without approval, or scanning enabled without usable limits.

## Agent execution package

Supply the agent with a compact, signed package:

```text
Normalized engagement manifest
├── Machine-enforced network allowlist
├── Technique-policy matrix
├── Short-lived test-account references
├── Architecture and trust-boundary summary
├── Known-issue fingerprint index
├── Reporting template
└── Source and provenance bundle
```

At startup, the agent must identify the engagement ID, manifest version, authorization expiry, exact target, intended technique, applicable limits, required approval, and relevant stop conditions.

The execution layer should require a short-lived action authorization containing the asset, technique, limits, manifest version, and expiry. Unstructured source documents may provide context but cannot override normalized policy.

## Runtime scope guard

Before every network action, verify:

1. The engagement is active and unexpired.
2. The canonical destination exactly matches an in-scope asset.
3. No more-specific host, path, port, or component exclusion applies.
4. Ownership and third-party status permit testing.
5. The technique is explicitly permitted for this asset.
6. Conditional approvals are recorded.
7. Rate, concurrency, timing, and data limits are satisfied.
8. The selected account is authorized for the action.
9. Validation remains below the permitted impact level.
10. No known-issue or duplicate rule blocks further work.

Any failed or unknown check blocks the action. Repeat the guard after DNS resolution, redirects, authentication or role changes, and discovery of any new host, port, endpoint, tenant, or integration.

Enforce scope with a network-level allowlist. Prompt instructions alone are not an adequate security boundary.

## Safe validation ladder

Advance incrementally:

1. Passive observation
2. Benign metadata or configuration check
3. Non-destructive interaction using owned test data
4. Minimal proof of unauthorized behavior
5. Higher-impact validation only with explicit human approval

Stop once the reporting threshold is met. Do not establish persistence, pivot, enumerate real-user data, extract bulk records, access unrelated tenants, alter production data, or demonstrate destructive impact unless separately and explicitly authorized.

If unexpected sensitive data appears, stop, retain only minimal evidence, do not enumerate further, redact the evidence, notify the reviewer, and follow the program incident process.

## Known-vulnerability and duplicate check

Perform this check before active validation and again before submission.

Create a normalized candidate fingerprint using:

- Canonical asset and affected component
- Endpoint or feature family
- Vulnerability class
- Preconditions and required role
- Source-to-sink or trust-boundary path
- Root-cause hypothesis
- Security impact
- Affected version or environment
- Stable response, error, or behavioral indicators
- Relevant CWE, CVE, advisory, or internal identifiers

Do not use payload text alone as a fingerprint. Compare against:

1. The engagement known-issue catalog
2. Reports previously available to the tester
3. Program-provided excluded and accepted-risk issues
4. Published advisories and documented limitations
5. Fixed issues and affected-version ranges
6. Same-root-cause reports involving adjacent endpoints

Classify the result as:

- `no_match`
- `possible_duplicate`
- `probable_duplicate`
- `known_but_retest_allowed`
- `excluded`
- `fixed_version_retest`
- `needs_human_review`

Probable duplicates, exclusions, and uncertain matches do not proceed to higher-impact validation. A human determines whether a different root cause, asset, impact, or regression justifies continued work. Record sources searched, query terms, candidate matches, the decision, reviewer, and timestamp.

## Finding lifecycle

```text
Observed
  → Scope checked
  → Known-issue precheck
  → Minimally validated
  → Impact assessed
  → Duplicate recheck
  → Human reviewed
  → Submitted
  → Triaged
  → Remediation retest
  → Closed
```

Side states include `blocked_by_scope`, `authorization_unclear`, `stopped_for_safety`, `possible_duplicate`, `known_or_excluded`, `approval_required`, and `false_positive`.

## Submission checklist

Before submission, verify:

- The asset was in scope at the time of testing.
- The technique and validation depth were permitted.
- Reproduction uses minimal-impact steps.
- Evidence contains no unnecessary secrets or personal data.
- Severity follows the program’s definitions.
- Observed facts are distinguished from inference.
- Known-issue and duplicate checks are documented.
- Remediation addresses the root cause.
- Disclosure restrictions are respected.
- A human approved the report.

Include the manifest version and testing timestamp in the report.

## Change management and audit

Recheck authoritative sources before each testing session and on a defined schedule. When a source changes:

1. Save and hash the new version.
2. Produce a semantic difference for assets, techniques, limits, and terms.
3. Suspend affected actions immediately.
4. Revalidate and reapprove the manifest.
5. Issue a new version and invalidate older action authorizations.
6. Preserve prior versions for audit.

Maintain an append-only log of policy decisions, approvals, destinations, techniques, rate consumption, stop events, duplicate checks, evidence access, and report transitions. Keep secrets and sensitive payloads out of general logs.

## Separation of duties

Where practical, separate these functions:

- **Intake curator:** Collects sources and prepares the manifest.
- **Authorization reviewer:** Confirms scope and legal/program restrictions.
- **Security agent:** Performs only policy-approved testing.
- **Finding reviewer:** Reviews evidence, duplication, severity, and submission.

Smaller teams may combine roles, but scope activation, sensitive validation, and report submission should retain explicit human checkpoints.

This workflow is reusable because authorization, normalization, policy enforcement, validation, deduplication, and reporting remain fixed. Only the program-specific manifest and its supporting materials change.
