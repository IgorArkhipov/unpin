# Contributing To Unpin

Thanks for helping make Unpin safer and more useful. This project manages local AI-agent configuration, so contributions should be careful about user data, provider state, and reversible changes.

## Project Scope

Unpin is a Rust CLI/TUI for discovering, snapshotting, safely toggling, and restoring local AI-agent configuration. The current supported provider stack is:

- Claude Code
- Codex CLI
- Cursor current MCP/config locations
- Zed current skills, instructions, and `context_servers` settings

Please do not add compatibility for legacy app versions or historical config paths unless maintainers explicitly open an issue for that work.

## Before You Start

- Use stable Rust.
- Keep changes small and focused.
- Search existing tests before adding new behavior.
- Avoid reading or depending on real home-directory provider state.
- Never use `.env*` files as inputs, fixtures, examples, or test data.

For behavior changes, open or comment on an issue first when the intended behavior is not obvious from the current code and tests.

## Development Setup

Run the local CI-equivalent checks from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run -p unpin-cli --locked -- --help
cargo audit --no-yanked
cargo machete
```

CI also verifies the declared Rust 1.96 MSRV separately from the pinned Rust 1.97.1 development toolchain.

## Code Guidelines

- Keep `unpin-core` headless. It should own discovery, planning, mutation, snapshots, backups, restore, and MCP-safe logic.
- Keep `unpin-cli` thin. It should parse arguments, render output, run the TUI, and delegate behavior to `unpin-core`.
- Prefer structured parsers and typed data over ad hoc string manipulation.
- Preserve actionable error context.
- Do not add runtime dependencies unless the benefit is clear and the change is easy to justify in review.

## Testing Guidelines

- Provider discovery tests must use committed fixtures or temporary directories, not real user config.
- Mutation tests must write only to temporary sandboxes and should cover dry-run, apply, backup, audit, drift, rollback, and restore behavior when relevant.
- CLI and MCP behavior should be covered with integration tests when output shape or protocol behavior is part of the contract.
- Public docs examples that apply writes should use temporary fixture copies and temporary app-state roots.

## Pull Requests

Please include:

- What changed and why.
- How the change was tested.
- Any provider state or safety boundary touched.
- Any follow-up work that should not block the PR.

Reviewer time is precious. Prefer one coherent change over a grab bag of cleanup.

## Safety And Privacy

Unpin operates near private local configuration. Contributions should avoid logging secrets, reading unrelated user files, or making irreversible mutations. A write path should have a dry-run plan, explicit confirmation where appropriate, backup evidence, and a restore path unless maintainers agree the surface is read-only or non-restorable by design.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) in issues, pull requests, reviews, and other project spaces.

If you believe you found a security issue, please avoid opening a public proof-of-concept issue with sensitive details. Contact the maintainers privately once a security reporting channel is published.
