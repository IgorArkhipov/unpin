# Changelog

All notable changes to Unpin are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.5] - 2026-07-29

### Added

- Authenticated workspace-policy migration, orphan classification, reattach,
  discard, cleanup, and restore execution through the CLI.
- TUI and read-only MCP policy-maintenance status surfaces lifecycle and
  CLI-managed action state.

### Fixed

- Inventory-group best-effort apply now preserves blocked members and continues
  independent cohorts after another cohort cannot be prepared or applied.

### Security

- Persistent profile and capability-lock changes now create authenticated
  pre-change policy backups; protected profile results and recovery-required
  errors expose redacted restore handoffs when available.
- Workspace-policy maintenance binds reviewed plans, physical checkout
  evidence, current policy revisions, authenticated records, and restore
  backups before mutation.

## [0.1.0-beta.4] - 2026-07-27

### Added

- Personal and repository inventory groups that save explicit mixed-type item
  collections and operate on them through CLI, TUI, or externally approved MCP
  apply flows.
- File/stdin transport for large inventory-group approval challenges.

### Security

- Inventory-group recovery preserves authenticated operation evidence, fixture
  apply paths remain sandboxed, and malformed repository group documents cannot
  hide authenticated personal groups from combined list surfaces.

### Compatibility

- This pre-1.0 beta adds inventory-group apply state to the public
  `unpin-core` MCP context and transition-kind contracts. Beta consumers must
  recompile against this release; persisted group plans and definition history
  use their new schema versions rather than accepting earlier prototypes.

## [0.1.0-beta.3] - 2026-07-24

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

[Unreleased]: https://github.com/IgorArkhipov/unpin/compare/v0.1.0-beta.5...HEAD
[0.1.0-beta.5]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.3
