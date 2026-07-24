# Changelog

All notable changes to Unpin are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.2] - 2026-07-24

### Added

- Normalized discovery for Claude Code, Codex, Cursor, Pi, OpenCode, and Zed
  skills, MCP servers, selected plugins, hooks, agents, and settings.
- Plan-first CLI and TUI mutation workflows with exact reviewed fingerprints,
  authenticated backups, audit evidence, rollback, and restore.
- Immutable profiles with session, physical-worktree, repository, global, and
  native-default policy precedence plus global provider capability locks.
- Authenticated session leases, optional gateway routing, MCP human-action
  handoffs, and reviewed hook trust.
- Fixture-backed provider contracts and a 31-case CLI, real-PTY TUI, and
  persistent MCP validation matrix.
- Disposable-root live-host compatibility validation for Pi 0.81.1 and
  OpenCode 1.18.4 global/project configuration.

### Security

- Purpose-separated backup, approval, and session authority keys.
- Replay-resistant approval receipts, drift detection, conflict locking,
  authenticated backup manifest v3, bounded transports, and secret zeroization.
- SHA-pinned GitHub Actions and automated dependency policy checks.

### Known limitations

- Windows is not a supported beta platform.
- Strict live gateway attachment, native MCP-reference lifecycle, and native
  managed-hook activation remain explicitly unavailable where provider adapters
  cannot prove enforcement.

[Unreleased]: https://github.com/IgorArkhipov/unpin/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.2
