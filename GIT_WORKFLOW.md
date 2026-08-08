# PentAI Git and GitHub Workflow

This document is the authoritative Git and GitHub operating procedure for PentAI.
It applies to humans, automation, and AI agents. Rules marked **Required** are
mandatory. Items marked **Recommended** are defaults that may be changed through a
documented team decision.

## 1. Repository context

PentAI is a private, local-first security product organized as a monorepo:

- `apps/ui/`: React, TypeScript, Vite, and Vitest UI.
- `apps/desktop/`: Rust and Tauri desktop shell.
- `services/core/`: Python and FastAPI local service.
- `packages/policy/`: deterministic Python policy and canonicalization code.
- `schemas/v1/`: versioned security-critical JSON contracts.
- `migrations/`: SQLite migrations.
- `docs/`: product, security-invariant, and contract documentation.
- `.github/workflows/`: Python, UI, migration, and cross-platform desktop checks.

The security invariants and authorization contracts are release-critical. Changes to
policy semantics, authorization-critical schemas, migrations, network boundaries,
approvals, grants, evidence handling, or audit behavior require heightened review.

The repository version is currently `0.1.0` in Python, npm, and Tauri/Rust manifests.
Until the team approves another model, this guide assumes `<default-branch>` will be
`main`, matching the existing `quality.yml` workflow.

## 2. Non-negotiable safety rules

**Required**

1. Never commit or upload secrets, credentials, private keys, tokens, real assessment
   data, target data, evidence, captures, local databases, or unredacted reports.
2. Never use `git add .`, `git add -A`, or a GUI equivalent without reviewing every
   path and the staged diff.
3. Never force-push `<default-branch>`, a release branch, or a shared branch.
4. Never rewrite published history without explicit approval from affected
   collaborators. If approved, use `--force-with-lease`, never `--force`.
5. Never bypass required checks or branch protection to merge.
6. Never combine security-policy changes with unrelated UI, refactor, or formatting
   work.
7. Preserve lockfiles: `pnpm-lock.yaml` and `apps/desktop/Cargo.lock` are intentional,
   reviewable source artifacts.
8. Treat changes to `schemas/v1/`, `docs/security/security_invariants.md`,
   `packages/policy/`, `migrations/`, and GitHub workflows as security-sensitive.
9. Before any Git operation, read this file and inspect `git status --short --branch`.
10. Use non-destructive recovery first. Do not run `reset --hard`, `clean -fd`,
    destructive checkout/restore, history filters, or forced pushes without explicit
    approval and a recovery point.

## 3. Branch model and naming

PentAI uses short-lived branches and pull requests into `<default-branch>`.

| Branch | Purpose | Lifetime |
|---|---|---|
| `<default-branch>` | Protected, releasable integration branch | Permanent |
| `feature/<issue>-<slug>` | New user-visible capability | Short-lived |
| `fix/<issue>-<slug>` | Defect or security fix | Short-lived |
| `docs/<issue>-<slug>` | Documentation-only change | Short-lived |
| `refactor/<issue>-<slug>` | Behavior-preserving code restructuring | Short-lived |
| `test/<issue>-<slug>` | Test-only improvement | Short-lived |
| `chore/<issue>-<slug>` | Tooling, dependency, or maintenance work | Short-lived |
| `release/vX.Y.Z` | Final release preparation only | Temporary |
| `hotfix/<issue>-<slug>` | Urgent fix from the latest production tag | Exceptional |

**Required**

- Use lowercase ASCII, hyphens, and one `/` separator.
- Use the tracker identifier when one exists; otherwise omit `<issue>`.
- Keep the slug specific and under roughly 50 characters.
- Create branches from an up-to-date `<default-branch>`, except a hotfix, which starts
  from the affected release tag.
- One branch must represent one reviewable outcome.
- Delete remote branches after merge unless they support an active release.
- Do not create long-lived `develop`, personal, environment, or deployment branches
  without a recorded architecture/release decision.

Examples:

```text
feature/142-policy-expiry-validation
fix/187-reject-redirect-port-change
docs/contract-versioning
refactor/203-canonical-url-parser
release/v0.2.0
```

### When to use each branch

- **Feature:** behavior or capability is added. Include tests and relevant docs.
- **Fix:** observed behavior is corrected. Add a regression test first or explain in
  the PR why one is impractical.
- **Documentation:** only prose, diagrams, or examples change. If behavior, schema, or
  commands change, use the corresponding feature/fix branch.
- **Refactor:** externally observable behavior and contracts remain unchanged. Split
  behavior changes into a separate branch.
- **Release:** update versions, changelog, release notes, and final release metadata.
  Do not develop features on a release branch.
- **Hotfix:** only for a severe released defect that cannot wait for the normal flow.

## 4. Plan and scope before editing

**Required**

Before making a commit:

1. State the intended outcome in one sentence.
2. Identify the affected component(s), tests, documents, contracts, and migrations.
3. Read the relevant security invariant and contract documentation.
4. Decide the smallest independently valid commit sequence.
5. Identify compatibility, migration, rollback, privacy, and security impact.
6. Keep unrelated cleanup out of the branch or isolate it in a separate commit.

For authorization-critical or persistence changes, the plan must explicitly answer:

- Which invariant or contract is affected?
- Does the change default-deny on missing, malformed, stale, or ambiguous input?
- Is a schema version or migration required?
- Are old data and old producers/consumers compatible?
- What test proves the safety property and the negative path?

## 5. Commit construction and atomicity

**Required**

- A commit must have one coherent purpose and leave the repository in a testable state.
- Include implementation and its direct tests in the same commit.
- Include a migration with the model/code that requires it.
- Include schema compatibility documentation with a contract change.
- Do not mix mechanical formatting, dependency updates, generated output, and product
  behavior in one commit.
- Review with `git diff` before staging and `git diff --cached` before committing.
- Stage explicit paths or interactive hunks.
- Generated build products, caches, local environments, and databases are not commits.

**Recommended**

- Prefer commits that a reviewer can understand in minutes rather than commits sized
  by an arbitrary line count.
- Split a large change by dependency order: contract/migration, implementation, UI,
  then documentation—only when each commit is valid and reviewable.
- Avoid “checkpoint,” “WIP,” or “misc fixes” commits in a PR’s final history.

## 6. Commit messages

Use Conventional Commits:

```text
<type>(<scope>): <imperative summary>

<why and noteworthy behavior, if needed>

<trailers, if needed>
```

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`,
`perf`, and `revert`.

Preferred scopes: `ui`, `desktop`, `core`, `policy`, `contracts`, `migrations`,
`security`, `ci`, `docs`, or `deps`.

**Required**

- Use an imperative, lowercase summary with no final period.
- Keep the subject concise (target 72 characters or fewer).
- Explain why and safety/compatibility consequences in the body when not obvious.
- Use `BREAKING CHANGE:` only for an intentional incompatible API or contract change.
- Reference an issue in a trailer when applicable, for example `Refs: #142` or
  `Fixes: #187`.
- Never put secrets, target names, customer/program data, or exploit details in commit
  messages.

Repository-relevant examples:

```text
feat(policy): reject expired engagement manifests
fix(core): roll back failed SQLite migrations
test(contracts): cover encoded path boundary cases
docs(security): clarify action-grant replay invariant
ci(desktop): cache Rust dependencies for smoke checks
refactor(ui): isolate assessment status rendering
```

## 7. Required checks

### Before every commit

Run checks proportional to the touched area. All applicable checks are required:

```text
PYTHONPATH=packages/policy/src:services/core/src python3 -m unittest discover -s tests -p "test_*.py"
python3 scripts/validate_contracts.py
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
pnpm typecheck
pnpm test
pnpm build
cargo check --manifest-path apps/desktop/Cargo.toml
```

Use an available compatible Python environment. The project declares Python 3.12+
and CI currently uses Python 3.13.

Area mapping:

- Python/core/policy/migrations/contracts: unit tests, contract validation, Ruff,
  mypy, and pytest.
- UI: typecheck, Vitest, and production build.
- Desktop/Tauri: UI build plus Cargo check.
- Workflows/build configuration: validate YAML and exercise the closest local command;
  the PR must pass GitHub Actions.
- Documentation-only: verify links, commands, paths, and formatting; run code checks if
  documented behavior or generated references changed.

### Before every push

**Required**

1. Confirm `git status --short --branch` shows the expected branch.
2. Review commits not yet in the upstream branch.
3. Re-run checks affected since the last successful run.
4. Synchronize with the latest `<default-branch>`.
5. Inspect the complete branch diff and scan staged/tracked paths for sensitive or
   generated files.
6. Confirm no merge markers remain.

CI is not a substitute for local checks.

## 8. Safe day-to-day procedures

The examples assume remote `origin` and default branch `<default-branch>`.

### Start a branch

```text
git status --short --branch
git fetch --prune origin
git switch <default-branch>
git pull --ff-only origin <default-branch>
git switch -c feature/<issue>-<slug>
```

`git pull --ff-only` is required on `<default-branch>` so Git cannot create an
accidental local merge commit.

### Stage and commit

```text
git status --short
git diff
git add --patch
git diff --cached --check
git diff --cached
git commit
```

Stage explicit files with `git add -- <path>` when hunk staging is unsuitable. Quote
paths containing spaces. After committing, inspect `git show --stat --oneline HEAD`.

### Synchronize a private feature branch

Preferred for a private, unshared branch:

```text
git fetch origin
git rebase origin/<default-branch>
```

If the branch has already been shared or another person is building on it, do not
rewrite it. Merge instead:

```text
git fetch origin
git merge --no-ff origin/<default-branch>
```

**Required:** communicate before rebasing shared commits. If an approved rebase changes
an already-pushed private branch, push only with:

```text
git push --force-with-lease origin <branch>
```

### Push

First push:

```text
git push --set-upstream origin <branch>
```

Later pushes:

```text
git push
```

Never push directly to `<default-branch>` or a release branch. Do not use push options
that skip CI.

## 9. Pull requests

### Title and scope

Use the same format as a commit subject:

```text
feat(policy): reject expired engagement manifests
```

**Required**

- One PR, one outcome; split unrelated work.
- Open a draft early for high-risk or cross-component work.
- Keep the PR current with `<default-branch>`.
- List exact checks run and their results.
- Call out security, privacy, schema, migration, compatibility, rollback, and release
  effects.
- Never place secrets, live targets, real evidence, or sensitive logs in the PR.
- Resolve all required review conversations and pass all required checks before merge.

### Review expectations

- At least one approval is required for ordinary changes.
- At least two approvals are required for policy semantics, authorization contracts,
  security invariants, migrations that can lose/transform data, CI permission changes,
  signing/release configuration, or execution/network-boundary code.
- At least one security-focused reviewer must be independent of the author for
  security-critical changes.
- Authors may not approve their own PR.
- New commits after approval dismiss stale approvals for protected areas.

#### Sole-maintainer exception

PentAI is currently maintained by one person. While there is no other qualified human
available, the sole maintainer may perform the required security review even though
they are also the author, Product Owner, Security Lead, repository owner, or a
combination of those roles. This is a documented exception to the independence,
two-approver, and author-self-approval requirements above; it is not an independent
review and must never be described as one.

**Required when using this exception**

1. State in the pull request and approval record that the sole-maintainer exception
   was used, identify every role held by the reviewer, and explicitly disclose that
   the review was not independent.
2. Perform a separate security-review pass after implementation is complete. Review
   the complete diff, affected invariants and contracts, threat and abuse cases,
   authorization boundaries, negative/default-deny tests, compatibility, rollback,
   and all validation evidence.
3. Record the review date, scope, evidence examined, findings, limitations, deferred
   work, and any accepted residual risk. Unresolved material findings block approval.
4. Require all applicable automated checks to pass. The exception cannot waive,
   bypass, or relabel a missing, skipped, cancelled, or failed check.
5. Record approval as `Sole-maintainer security review — non-independent`, never as
   an independent approval. GitHub self-approval, if unavailable or prohibited, may
   be represented by a dated approval record committed to the repository and linked
   from the pull request.
6. Do not use the exception for signing/notarization key custody, production release
   authorization, destructive migration approval, disclosure decisions involving
   another party, or any external requirement that expressly mandates independent or
   dual control. Those items remain blocked until the required reviewer exists.
7. Re-evaluate this exception when another regular maintainer or qualified security
   reviewer becomes available. From that point, the normal independent-review and
   approval requirements apply to new security-critical changes.

Use of this exception reduces assurance but permits a formal project decision when
the alternative is an impossible approval condition. The sole maintainer explicitly
accepts that residual governance risk for the reviewed scope; technical or product
risks still require their own documented treatment.

### Merge strategy

**Required:** use squash merge for normal feature, fix, documentation, refactor, test,
and chore PRs. The final squash message must follow this guide.

**Recommended:** use a merge commit for an approved `release/vX.Y.Z` PR when preserving
the release boundary is useful. Disable rebase-merge in GitHub unless the team adopts
a deliberate linear-history policy. Delete the source branch after merge.

### Reusable pull-request template

```markdown
## Summary

<!-- What outcome does this PR deliver? -->

## Why

<!-- Problem, requirement, or invariant addressed. -->

## Scope

- Included:
- Explicitly excluded:

## Security and compatibility

- Invariants/contracts affected:
- Authorization or privacy impact:
- Schema/migration impact:
- Backward compatibility:
- Rollback plan:

## Validation

- [ ] Python unit/pytest checks (if applicable)
- [ ] Ruff and mypy (if applicable)
- [ ] Contract validation (if applicable)
- [ ] UI typecheck, tests, and build (if applicable)
- [ ] Cargo check / desktop smoke (if applicable)
- [ ] Manual verification:

## Review guidance

<!-- Risky files, ordering, screenshots with synthetic data only, or key decisions. -->

## Checklist

- [ ] The branch contains one coherent outcome.
- [ ] No secret, target, evidence, database, cache, dependency, or build output is included.
- [ ] Tests cover success, failure, and default-deny paths where applicable.
- [ ] Documentation and changelog are updated where needed.
- [ ] All review comments and required checks are resolved.
```

## 10. Merge conflicts

**Required**

1. Stop and understand both sides; do not choose “ours” or “theirs” wholesale.
2. Fetch the current remote state and create a temporary backup branch before a
   difficult rebase or merge.
3. Resolve source conflicts according to intended behavior, then remove all conflict
   markers.
4. Regenerate lockfiles only with the repository’s declared tool version. Do not
   hand-edit `pnpm-lock.yaml` or `Cargo.lock`.
5. Reconcile schema and migration conflicts semantically. Never renumber or silently
   replace an existing migration that may have been applied.
6. For security invariants/contracts, obtain the required reviewer’s decision when two
   changes disagree.
7. Run every check affected by either side and review the post-resolution diff.

Abort safely when uncertain:

```text
git rebase --abort
git merge --abort
git cherry-pick --abort
```

## 11. Versioning, changelog, tags, and releases

PentAI currently declares `0.1.0` in `pyproject.toml`, root and UI `package.json`
files, `apps/desktop/Cargo.toml`, and `apps/desktop/tauri.conf.json`.

**Required**

- Use Semantic Versioning: patch for compatible fixes, minor for compatible
  capabilities, major for incompatible public behavior or stable contract changes.
- Version authorization-critical contracts independently according to
  `docs/contracts/README.md`; a new required field, removed value, or semantic change
  requires a new major contract version.
- Keep all application version declarations synchronized in a release PR.
- Maintain `CHANGELOG.md` once the first release process begins, using an `Unreleased`
  section and user/security-relevant entries.
- Create annotated, signed tags where signing is available: `vX.Y.Z`.
- Tags must point to reviewed commits on `<default-branch>` and must never be moved or
  reused.
- GitHub Releases must be created from the tag, summarize changes and known risks, and
  include only CI-produced, verified artifacts.
- A security release must avoid disclosing operational exploit detail before users can
  update.

**Recommended**

- Adopt Keep a Changelog structure.
- Add automated manifest-version consistency and artifact checksum checks before the
  first distributable release.
- Record build provenance, SBOM, signatures, platform smoke results, and rollback
  instructions with each production release.

## 12. Files that must never be committed

**Required exclusions**

- Secrets and local configuration: `.env`, `.env.*` except reviewed examples,
  credentials, tokens, API keys, private keys, certificates with private material,
  signing/notarization files, and provider or platform profiles.
- Assessment data: real program terms, targets, cookies, credentials, traffic
  captures, scan results, evidence, screenshots, reports, or vulnerability details.
- Local databases and sidecars: `*.db`, `*.sqlite`, `*.sqlite3`, `*.db-shm`,
  `*.db-wal`, and equivalents.
- Dependencies/environments: `node_modules/`, `.venv*/`, and local toolchains.
- Build/generated outputs: `dist/`, `target/`, `apps/desktop/gen/schemas/`,
  `*.tsbuildinfo`, coverage reports, packaged installers, binaries, and source maps
  unless an approved release process explicitly requires a reviewed source artifact.
- Caches and test output: `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`,
  `.ruff_cache/`, `.coverage*`, `htmlcov/`, Playwright output, snapshots containing
  sensitive data, and temporary directories.
- Logs and editor/OS state: `*.log`, `.DS_Store`, IDE folders, swap files, and backups.

Only synthetic, clearly fictional, minimal test fixtures may be committed. Review them
as if they were production data.

### Repository-specific `.gitignore` recommendation

The existing `.gitignore` covers common dependencies, basic Python caches, `dist/`,
`target/`, `.env`, and `*.db`. Before initialization, extend it to cover:

```gitignore
# Secrets and local configuration
.env.*
!.env.example
!.env.*.example
*.pem
*.key
*.p12
*.pfx

# Python
.venv*/
.coverage
.coverage.*
htmlcov/
*.sqlite
*.sqlite3

# TypeScript/Vite
*.tsbuildinfo
*.map

# Rust/Tauri generated state
apps/desktop/gen/schemas/

# Logs, test output, and local tools
*.log
test-results/
.idea/
.vscode/
*.swp
*~
```

Do not ignore `pnpm-lock.yaml`, `apps/desktop/Cargo.lock`, migrations, schemas, or
synthetic contract fixtures. Before the first commit, verify ignore behavior with
`git check-ignore -v --no-index <path>` and inspect the complete candidate file list.

## 13. GitHub Actions and repository protection

The existing workflows provide:

- `Quality / Python and contracts`
- `Quality / UI`
- `Quality / SQLite migration`
- `Desktop smoke / Tauri check` on Ubuntu, macOS, and Windows for relevant PRs

**Required before publication**

- Change `pnpm install --frozen-lockfile=false` in `quality.yml` to
  `pnpm install --frozen-lockfile` so CI detects lockfile drift.
- Pin third-party Actions to full commit SHAs, especially non-GitHub actions; use a
  dependency updater to propose reviewed pin updates.
- Keep workflow permissions minimal and explicit. Never expose secrets to untrusted PR
  code or use `pull_request_target` to execute PR content.
- Add dependency review and secret scanning appropriate to a private repository and
  the selected GitHub plan.

Protect `<default-branch>` with:

- pull requests required; no direct pushes;
- one approval normally and two for protected/security-sensitive areas, except while
  the documented sole-maintainer exception in section 9 applies;
- CODEOWNERS review for policy, contracts, invariants, migrations, workflows, and
  release/signing configuration;
- required successful status checks using the stable job names above;
- conversation resolution and stale-approval dismissal;
- branch up-to-date requirement, unless GitHub merge queue is enabled;
- force pushes and deletions disabled;
- administrator bypass disabled or tightly restricted and audited;
- squash merge enabled and auto-delete head branches enabled.

**Recommended**

- Add `.github/CODEOWNERS`, `.github/pull_request_template.md`, Dependabot/Renovate,
  CodeQL for Python/TypeScript/Rust where supported, and a credential/secret scanner.
- Add concurrency cancellation for superseded PR workflow runs.
- Add path-sensitive checks only after verifying security-critical changes cannot skip
  a required job.
- Use GitHub environments with required reviewers for signing or release secrets.

## 14. Non-destructive recovery

Always inspect `git status`, `git diff`, and `git reflog` before recovery.

### Staged the wrong file

Keep the working copy:

```text
git restore --staged -- <path>
```

### Committed too early but did not push

Safest default: add a correcting commit. If the commit is strictly local and no one
depends on it, `git commit --amend` is allowed after reviewing the staged diff.

### Need to undo a pushed commit

Create a new inverse commit:

```text
git revert <commit>
```

Do not reset or force-push shared history.

### Work is on the wrong branch

Create a branch at the current commit, then restore the original branch by a
non-destructive, situation-specific method. If uncommitted work exists, create a patch
or named stash first and verify it:

```text
git diff > ../pentai-recovery.patch
git stash push -u -m "recovery: move work to correct branch"
```

Keep recovery files outside the repository and ensure they contain no secrets.

### Lost commit or branch

Use `git reflog` to locate the commit, then preserve it immediately:

```text
git branch recovery/<date>-<slug> <commit>
```

### Interrupted merge/rebase/cherry-pick

Abort using the matching command in section 10. Do not delete lock files or Git
metadata unless the process state has been independently verified.

### Sensitive data was committed

1. Stop pushing and sharing.
2. Revoke/rotate the credential or sensitive access immediately; deletion from Git is
   not sufficient.
3. Notify the repository/security owner.
4. Identify every affected ref, fork, artifact, cache, and log without printing the
   value.
5. Obtain explicit approval for history rewriting and coordinate a fresh clone for all
   collaborators.
6. Follow GitHub’s current sensitive-data removal process.

History rewriting is destructive and exceptional. Create a verified backup, document
the exact scope, and never improvise it on the only copy.

## 15. Concise operating checklists

### Every commit

- [ ] One intended outcome; explicit paths/hunks only.
- [ ] Security invariants, contracts, migrations, and docs considered.
- [ ] No secrets, real assessment data, generated output, caches, or local state.
- [ ] Applicable tests, lint, types, contracts, and builds pass.
- [ ] `git diff --cached --check` and `git diff --cached` reviewed.
- [ ] Conventional Commit message is accurate and contains no sensitive data.

### Every push

- [ ] Correct branch and upstream confirmed.
- [ ] Branch synchronized with `origin/<default-branch>`.
- [ ] Complete outgoing commits and diff reviewed.
- [ ] Applicable checks re-run after the last change or conflict resolution.
- [ ] Normal push used; `--force-with-lease` only for an approved private-branch rebase.

### Every pull request

- [ ] Title and description explain one coherent outcome.
- [ ] Security, privacy, compatibility, migration, rollback, and release impact stated.
- [ ] Tests and manual validation reported.
- [ ] Required independent reviewers assigned, or the sole-maintainer exception is
      explicitly recorded as non-independent with its review evidence and accepted
      governance risk.
- [ ] Required Actions pass; conflicts and conversations resolved.
- [ ] Squash message is clean; source branch will be deleted after merge.
