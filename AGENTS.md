# AI Agent Instructions

## Git and GitHub operations

Before performing any Git- or GitHub-related operation in this repository, every AI
agent must read and follow `GIT_WORKFLOW.md` in full.

This requirement includes read-only inspection as well as branch creation, staging,
committing, pulling, fetching, rebasing, merging, tagging, pushing, opening or editing
pull requests, changing remotes, modifying workflows, and publishing releases.

Agents must also:

- inspect the current repository and working-tree state before acting;
- preserve all user changes and avoid destructive Git operations;
- never expose, commit, or upload secrets or real assessment data;
- obtain explicit user approval before initializing Git, creating a GitHub repository,
  changing remotes, publishing, rewriting history, force-pushing, deleting branches or
  tags, or otherwise performing an external or destructive Git/GitHub action;
- report conflicts between a request and `GIT_WORKFLOW.md` instead of silently
  bypassing the guide; and
- use placeholders such as `<owner>`, `<repository>`, and `<default-branch>` when
  repository settings are unknown.

If `GIT_WORKFLOW.md` is missing or unreadable, stop all Git/GitHub write operations and
ask the user how to proceed.
