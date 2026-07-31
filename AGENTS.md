# AGENTS.md

Guidance for AI coding agents working in this repository. Keep this file concise and project-specific; human-facing architecture and contribution details live in `docs/ONBOARDING.md`, `README.md`, `CONTRIBUTING.md`, and `REVIEWING.md`.

## Project Overview

Unpin is a Rust CLI/TUI for local AI-agent configuration discovery, snapshots, safe mutation, backup, restore, and MCP-backed workflows.

Supported provider scope:

- Claude Code
- Codex CLI
- Cursor current MCP/config locations
- Pi current skills and package-extension filters (fixture- and live-host-verified; native MCP unsupported)
- OpenCode current skills, MCP settings, and npm plugin references (fixture- and live-host-verified)
- Zed current skills, instructions, and `context_servers` settings

Zed plugins remain out of scope; Zed uses standard Agent Skills.

Do not reintroduce legacy app-version support or historical provider paths unless a maintainer explicitly asks for that work.

## Architecture

- `crates/unpin-core` owns headless behavior: discovery, models, mutation planning/apply, snapshots, backups, restore, fixture validation, and MCP-safe logic.
- `crates/unpin-cli` owns the binary surface: argument parsing, output rendering, terminal UI, and process-level command behavior.
- Keep core code independent of terminal UI crates and process-exit behavior.
- Keep CLI code thin; delegate product behavior to `unpin-core`.
- Public behavior should be fixture-backed and documented through tests, not inferred from private local machine state.

## Safety Rules

- Never read, create, or depend on `.env*` files.
- Do not read or mutate real home-directory provider state in tests or examples.
- Use committed fixtures and temporary directories for discovery and mutation tests.
- Any write path should preserve the safety model: dry-run planning, explicit confirmation where appropriate, locking/drift protection, backup evidence, audit evidence, and restore behavior.
- Treat repository-owned `.unpin.json` as untrusted. It must never select
  `projectRoot`, `appStateRoot`, or `cursorRoot`, or otherwise redirect
  discovery, provider mutation, approval, policy, backup, session, or audit
  state; those roots belong to user config or explicit CLI overrides.
- Do not log secrets, private paths beyond what tests intentionally create, or provider payloads that could contain sensitive user data.
- Ask before adding runtime dependencies.

## Workflow For Agents

1. Read the issue, PR, or user request and identify the smallest safe change.
2. Inspect existing code and tests before editing.
3. For behavior changes, prefer a failing regression test first.
4. Keep edits scoped to the affected provider, command, or module.
5. Update public docs or examples when user-facing behavior changes.
6. Run focused tests first, then the relevant verification gates.
7. Summarize what changed, what was tested, and any residual risk.

Do not perform broad refactors, formatting churn, dependency swaps, or public-contract changes as incidental cleanup.

## Coding Guidelines

- Use stable Rust and idiomatic Cargo workspace conventions.
- Prefer typed data models and structured parsers over ad hoc string manipulation.
- Preserve unrelated provider config sections when rewriting JSON, JSONC, TOML, or SQLite-backed state.
- Keep mutation logic explicit about source paths, state paths, fingerprints, backups, and restore targets.
- Keep MCP output stable and machine-readable; human output should not become the only contract.
- Prefer clear errors with enough context for users to recover safely.

## Testing Expectations

Use the standard checks from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run -p unpin-cli --locked -- --help
cargo audit --deny warnings
cargo deny check
cargo machete
```

Testing guidance:

- Discovery changes need fixture-backed tests.
- Mutation changes need dry-run/apply/backup/restore coverage when relevant.
- MCP changes need protocol/output contract tests.
- CLI output changes need integration tests.
- TUI changes should prefer state/event tests that do not require an interactive terminal.
- Docs-only changes should at least pass `git diff --check`.
- Distribution candidates and broad provider, mutation, backup/restore, TUI, or
  MCP changes should pass and finalize `python3
  scripts/run_local_provider_matrix.py`.
- Public release candidates should also pass
  `python3 scripts/validate_live_provider_hosts.py` with supported Pi and
  OpenCode executables on `PATH`.
- A maintainer-approved delivery-only release that changes no program logic may
  replace those two gates with focused release-build evidence: workflow lint,
  locked metadata, a version smoke, a verified GNU/Linux glibc ceiling, and a
  Debian 12 artifact smoke. Document the exception and post-tag verification
  in the release notes and PR.

## Provider-Specific Notes

- Claude Code: preserve settings and MCP approval-map shapes.
- Codex CLI: preserve unrelated TOML sections and ordering as much as practical.
- Cursor: support modern `$HOME/.cursor/mcp.json`, project `.cursor/mcp.json`, and workspace SQLite disabled-server state; do not rely on legacy app-support `mcp.json`.
- Pi: preserve package sources and non-extension resources when changing
  extension filters; native MCP remains unsupported.
- OpenCode: preserve JSON/JSONC comments and trailing commas; local auto-loaded
  plugin files remain read-only.
- Zed: preserve JSONC settings behavior, global/project skill paths, instructions, and `context_servers`.

## Pull Request Output

When preparing a handoff or PR summary, include:

- The user-facing change.
- The safety boundary touched, if any.
- Tests run and their results.
- Follow-up work that should not block the current change.

Keep summaries factual and compact. If a required check was not run, say so plainly.
