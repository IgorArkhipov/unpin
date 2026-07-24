# Reviewer Guide

This guide is for maintainers and collaborators reviewing Unpin changes. The review goal is not only "does it compile?", but "can this safely touch a user's local AI-agent setup?"

## Review Priorities

Review in this order:

1. User safety and privacy
2. Correctness of discovery, mutation, backup, and restore behavior
3. Protocol and CLI output compatibility
4. Test quality and fixture discipline
5. Maintainability and public documentation

## Scope Check

Before reviewing details, confirm the PR fits the current public project scope:

- Supports the modern provider stack: Claude Code, Codex CLI, Cursor current config paths, and Zed current config paths.
- Does not revive legacy app-version behavior or historical paths without an explicit maintainer decision.
- Does not read `.env*` files or real provider configuration in tests.
- Keeps generated, local, and private state out of committed artifacts.

## Safety Checklist

For any change that can write provider or Unpin state, verify:

- There is a no-write plan or preview path.
- Apply paths have explicit confirmation at user-facing boundaries where appropriate.
- Mutations are guarded by source fingerprints, drift checks, locks, or equivalent protection when stale state would be dangerous.
- Backups capture enough state to restore the pre-apply condition.
- Restore paths handle conflicts, invalid manifests, and partial failure safely.
- Tests use temporary directories and fixtures rather than live home-directory state.

## Provider Review Checklist

- Claude Code: check JSON shape preservation for settings and MCP approval maps.
- Codex CLI: check TOML section handling and unrelated section preservation.
- Cursor: check modern `$HOME/.cursor/mcp.json`, project `.cursor/mcp.json`, and workspace SQLite state handling; do not rely on legacy app-support `mcp.json`.
- Zed: check JSONC settings handling, global/project skill paths, instructions, and `context_servers`.

## MCP And CLI Checklist

- JSON output should remain stable and explicit.
- MCP tools should validate selectors, confirmation fields, fingerprints, and max item limits before planning or applying writes.
- JSON-RPC framing should not emit responses for notifications.
- Human output should be useful without becoming the source of truth for machine contracts.

## Test Expectations

A PR that changes behavior should usually include a focused regression test plus any broader integration coverage needed for confidence. Ask for tests when a change touches:

- Provider discovery rules
- Mutation planning or apply behavior
- Backup, audit, or restore semantics
- CLI or MCP output contracts
- TUI state transitions
- Fixture validation or capability matrices

Docs-only PRs should still be checked for command accuracy and safety of examples.

## Review Feedback Style

Prefer specific, actionable comments tied to user impact. Distinguish blockers from follow-ups:

- Block when the change can corrupt user state, leak private data, break documented contracts, or ship untested risky behavior.
- Request changes when the implementation is incomplete or the tests do not prove the intended behavior.
- Suggest follow-ups for broader refactors, polish, or adjacent improvements that should not block a focused PR.

When in doubt, ask for a smaller PR. Unpin benefits from tight, reviewable changes.
