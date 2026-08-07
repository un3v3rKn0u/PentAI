# Release Process

PentAI is pre-release software. This process applies when the maintainers approve the
first public release and every release thereafter.

## Release model

- `main` is the protected, releasable integration branch.
- `release/vX.Y.Z` is a temporary stabilization branch created from an up-to-date
  `main`.
- Release branches accept only version, changelog, release-note, packaging, and
  release-blocking fix changes.
- Normal development continues through short-lived branches and does not enter an
  active release branch.
- Tags use the signed, annotated form `vX.Y.Z` and are created only from the approved
  release commit on `main`.

## Prepare

1. Confirm the intended version follows Semantic Versioning.
2. Confirm `main` is clean, synchronized, and passing every required check.
3. Create `release/vX.Y.Z` from `main`.
4. Update the version consistently in:
   - `pyproject.toml`
   - `package.json`
   - `apps/ui/package.json`
   - `apps/desktop/Cargo.toml`
   - `apps/desktop/tauri.conf.json`
5. Move the relevant `CHANGELOG.md` entries from **Unreleased** into a dated version
   section.
6. Confirm no credential, target, assessment data, database, evidence, cache, or build
   output is present.

## Validate

Run the complete local suite:

```text
PYTHONPATH=packages/policy/src:services/core/src python3 -m unittest discover -s tests -p "test_*.py"
python3 scripts/validate_contracts.py
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
pnpm audit
pnpm typecheck
pnpm test
pnpm build
cargo check --manifest-path apps/desktop/Cargo.toml
```

The release pull request must also pass Quality, Dependency review, CodeQL, and all
applicable cross-platform Desktop smoke jobs. Security-critical release changes require
the independent reviews defined in `GIT_WORKFLOW.md`.

## Approve and publish

1. Open a pull request from `release/vX.Y.Z` to `main`.
2. Resolve every review conversation and required check.
3. Merge using the repository-approved method. Do not bypass rules or force-push.
4. From the updated `main`, create a signed annotated tag:

   ```text
   git tag -s vX.Y.Z -m "PentAI vX.Y.Z"
   git push origin vX.Y.Z
   ```

5. Create a GitHub release from that tag using the matching changelog section.
6. Attach only reproducible artifacts produced by an approved release workflow.
   PentAI does not yet publish desktop binaries because artifact signing and
   platform-specific notarization are not configured.
7. Verify the release and tag are visible, then delete the temporary release branch.

## Rollback and incident handling

- Do not move or replace a published release tag.
- For an urgent released defect, branch `hotfix/<issue>-<slug>` from the affected tag,
  apply the smallest fix, and follow the same review and validation requirements.
- If an artifact or tag may be compromised, stop distribution, document the incident,
  rotate affected credentials, and publish a new patch version. Never silently replace
  an artifact under an existing version.

## Deferred release controls

Before publishing desktop binaries, the project must define and verify:

- macOS signing and notarization;
- Windows code signing;
- protected release environments and approvers;
- provenance/SBOM generation and artifact attestations;
- secure storage and rotation of signing credentials;
- reproducible build expectations and artifact retention.
