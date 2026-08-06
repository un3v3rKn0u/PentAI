# Changelog

All notable changes to PentAI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release is being prepared as `0.1.0`. Move these entries into a dated
`[0.1.0]` section only when the release commit and tag are approved.

### Added

- Phase 0 monorepo scaffold for the React/Vite UI, Tauri desktop shell, FastAPI core
  service, and deterministic Python policy package.
- Initial SQLite migration and migration verification.
- Versioned JSON contracts for engagement manifests, action intents, approvals,
  grants, policy decisions, policy IR, and canonical types.
- Canonicalization fixtures and automated policy, contract, migration, UI, and
  cross-platform desktop checks.
- Repository-specific Git workflow, AI-agent instructions, pull-request template,
  and automated dependency-update configuration.

### Security

- Documented the deterministic authorization boundary: AI may propose and interpret,
  while policy and isolated infrastructure decide and enforce.
- Established security invariants for authorization contracts, approvals, grants,
  evidence handling, audit behavior, and default-deny processing.
- Restricted GitHub Actions permissions and pinned action dependencies to reviewed
  commit SHAs.

[Unreleased]: https://github.com/un3v3rKn0u/PentAI/commits/main
