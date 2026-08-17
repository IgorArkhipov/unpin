# Changelog

All notable changes to Unpin are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.2] - 2026-08-17

### Fixed

- Made tag release workflow reruns recognize an already-published immutable
  release as a non-mutating success while preserving guarded draft refreshes.

## [1.4.1] - 2026-08-17

### Changed

- Reused one repository walk across supported project skill scopes instead of
  scanning the same tree independently for each provider.
- Reused desktop discovery projections for up to 60 seconds within one bridge
  process. **Reload** starts a replacement bridge and reads external provider
  changes immediately.
- Split the mutation, MCP, terminal UI, and desktop bridge implementations into
  focused modules, shared discovery-item ID prefixes, and extracted toggle
  dispatch without changing their public contracts.
- Updated the pinned GitHub Actions and compatible Rust dependencies.

### Fixed

- Invalidated the desktop discovery cache after group, restore, and Agent
  Plugin mutation attempts, including failed applies, so a later refresh does
  not reuse a projection from before the attempted change.

## [1.4.0] - 2026-08-14

### Fixed

- Replaced per-release macOS Keychain access with a create-once, Unpin-specific
  credential broker stored under the app-state root. Ordinary CLI updates leave
  its exact signed bytes unchanged, so an approved broker does not prompt again
  merely because the CLI was rebuilt.

### Security

- Removed the unrelated release-signing identity from active automation. macOS
  release jobs now require an Unpin-specific self-signed certificate and public
  fingerprint from the protected `release-signing` Environment, package a
  separately identified broker, and authenticate broker clients before any
  Keychain operation.
- The identity migration requires one verified manual or deliberately staged
  installation and one new broker authorization. Broker upgrades are explicit
  and require renewed authorization; ordinary application updates cannot
  replace the installed broker.

### Compatibility

- Upgrading from `1.3.0` or earlier requires a one-time manual installation of
  both `unpin` and `unpin-credential-broker` from the same verified `1.4.0`
  archive. The first credential operation installs and authorizes the new
  stable broker; the retired unrelated certificate is not carried forward.
- Later compatible updates preserve the installed broker byte-for-byte, so a
  rebuilt CLI or desktop application does not by itself trigger another
  Keychain authorization prompt. Deliberate broker upgrades or signing
  certificate rotation still require explicit replacement and reauthorization.

## [1.3.0] - 2026-08-13

### Added

- Added revision-pinned workflow modes that expose a narrow, task-appropriate
  set of tools, skills, hooks, and MCP capabilities for planning,
  implementation, review, and custom workflows.
- Added workflow and session controls across the CLI, terminal TUI, native
  desktop workbench, MCP runtime, and authenticated gateway connections.
- Added safe workflow transitions with explicit desired and observed state,
  cancellation, bounded recovery, immutable revision history, and canonical
  mode-routing evidence in the provider matrix.

### Security

- Workflow authority is scoped to the authenticated connection and pinned
  workflow revision; reconnects cannot silently inherit another connection's
  exposure or a later definition revision.
- Workflow definition changes and transitions retain Unpin's validation,
  drift, locking, approval, journaling, and recovery boundaries. Invalid or
  stale transitions fail closed.

### Compatibility

- Existing provider discovery, plugins, groups, CLI, TUI, desktop, and MCP
  workflows remain supported. The built-in workflow presets add routing
  without changing provider configuration formats.
- The macOS certificate and executable identifiers are unchanged, so the
  built-in updater accepts a verified update from `1.2.0`. This is an update
  trust check, not a guarantee that Keychain access will avoid another prompt.

## [1.2.0] - 2026-08-11

### Added

- Added discovery and control of portable Agent Plugin packages across the CLI,
  terminal TUI, native desktop workbench, and MCP planning surface.
- Added a sortable and filterable desktop Packages workbench with Light and
  Dark appearances, first-run guidance, and exact CLI handoffs.
- Added actionable Claude global/project and Codex global activation anchors;
  unsupported provider and layer combinations remain visible as diagnostics.

### Security

- Package rows are derived from existing provider inventory instead of a
  second package store, and incomplete or symlinked package caches fail closed.
- Package changes retain Unpin's provider reach, fingerprint, drift, locking,
  confirmation, backup, audit, restore, and recovery protections. MCP remains
  no-write and prepares human-action handoffs instead of applying changes.

### Compatibility

- Existing skills, MCP servers, plugins, groups, CLI, TUI, desktop, and MCP
  workflows remain supported. Agent Plugin activation is currently actionable
  for Claude and Codex anchors; other detected combinations are diagnostic.
- The macOS certificate and executable identifiers are unchanged, so the
  built-in updater accepts a verified update from `1.1.0`. Rebuilt executable
  bytes could still trigger another Keychain prompt.

## [1.1.0] - 2026-08-07

### Added

- Added `unpin update check` and confirmation-gated `unpin update apply` for verified stable CLI and macOS desktop releases.
- Added automatic desktop update checks at launch and an on-demand **Check for Updates…** application-menu flow with confirmed install and relaunch.
- Added `run_local_provider_matrix.py --capture-screenshots`, enabled by
  default on macOS, to capture the native provider-matrix dashboard with a
  documented manual fallback on other platforms.

### Security

- Update downloads are HTTPS-host restricted and bounded, archives are checksum-verified and traversal-safe, and candidates must report the expected version before atomic replacement.
- macOS updates require exact release identifiers and byte-for-byte equality with the installed designated requirements for the standalone CLI, desktop app, and bundled bridge. Certificate or identifier rotation is rejected as an update-trust violation; this check does not itself preserve Keychain authorization.

### Compatibility

- `v1.0.2` does not contain the updater, so moving to `v1.1.0` is a final manual
  installation. Both releases use the same certificate and identifiers, so the
  designated-requirement trust boundary is unchanged. Later compatible releases
  can use the built-in update flow, but rebuilt binaries may still prompt for
  Keychain access.

## [1.0.2] - 2026-08-06

### Changed

- Official macOS CLI and desktop archives began using a consistent self-signed
  certificate to stabilize each executable's designated requirement across
  releases. That certificate has since been retired because it was unrelated to
  Unpin, and a stable requirement alone did not prevent recurring Keychain
  prompts for rebuilt executables.
- The release workflow reads the P12 and password from the protected
  `release-signing` Environment after required approval, imports them into an
  ephemeral runner Keychain, rejects a missing or mismatched identity instead of
  falling back to ad-hoc signing, and removes the temporary Keychain and P12
  after packaging.

### Compatibility

- CLI, terminal TUI, MCP, and desktop behavior are unchanged from `1.0.1`.
- Updating from `1.0.1` or earlier changes the designated requirement once from
  the old ad-hoc signature, so macOS may prompt for Keychain access again on the
  first `1.0.2` launch. Later rebuilt executables may prompt again even when the
  certificate and identifiers are unchanged; certificate rotation also changes
  the updater's trust requirement.
- The personal certificate is not Developer ID signing or notarization and does
  not establish Gatekeeper trust. It uses timestamp mode `none`; secure
  timestamping is not claimed for this personal self-signed certificate. The
  documented checksum, attestation, and first-launch verification flow remains
  required.

### Verification

- This delivery-only release uses the maintainer-approved artifact-evidence
  exception: signing helper tests, all release-tooling tests, shell syntax,
  Python compilation, workflow lint, locked metadata, version smoke, protected
  release CI, GNU/Linux compatibility, and post-tag signature and fresh-download
  checks replace provider-matrix and live-host reruns. The post-tag checks still
  require the expected certificate fingerprint and exact app, bridge, and CLI
  code-signing identifiers for every macOS artifact.

## [1.0.1] - 2026-08-06

### Added

- Added persistent, collapsible first-run guidance and actionable workspace, loading, empty, filtered, blocked, and selection states across every native desktop work area.
- Added exact copy-only CLI and MCP handoffs for profiles, gateways, sessions, and hooks while keeping those workflows outside native desktop authority.
- Added a reproducible 52-image Light/Dark desktop guidance matrix with authoritative scenario metadata and mandatory visual review.

### Fixed

- Discover and Organize now keeps provider, layer, category, state, and access filters readable, supports prioritized multi-column sorting, and clears facet selections that disappear after inventory refresh.
- Recover and Audit now refreshes on activation without tying bridge reads to view lifetime, prevents stale recovery responses from overwriting post-mutation evidence, and keeps reviewed restore discard available under recovery blockers.
- Desktop release evidence now rejects blank or incomplete screenshot inventories, bounds Xcode subprocesses, validates Python and XCTest scenario metadata, and checks handoffs against the real built CLI in CI.

### Verification

- Implementation commit `bc64f0a` passed the full locked Rust workspace gates, macOS XCTest bridge and workbench suite, desktop handoff and release-script tests, a reviewed 52-image native Light/Dark matrix, a finalized 31/31 CLI, 31/31 TUI, 31/31 MCP provider matrix, and live Pi/OpenCode validation with provider state unchanged.

## [1.0.0] - 2026-08-05

### Changed

- Promoted the unified CLI, terminal TUI, MCP server, and native macOS
  workbench from release candidate to the stable `1.0.0` GitHub release.
- Stable desktop archives remain ad-hoc signed with Hardened Runtime under an
  explicit maintainer-approved unsigned-GA exception. They are not Developer ID
  signed or notarized, so checksum and attestation verification plus the
  documented Gatekeeper first-launch override remain required.

### Verification

- The finalized provider matrix at implementation baseline `6877cd2` passed
  31/31 CLI, 31/31 TUI, and 31/31 MCP cases, alongside the full locked Rust
  workspace gates, 35 native XCTest cases, both macOS architecture archive
  smokes, and live Pi/OpenCode validation without provider-state mutation.
- Subsequent release hardening and the stable promotion tree passed locked
  metadata, the `unpin 1.0.0` version smoke, workflow lint, the focused desktop
  release tests (9/9), and `git diff --check`. Protected-branch CI, clean
  merged-head Linux compatibility, and exact-version desktop artifact
  verification remain required before publication.

## [1.0.0-rc.1] - 2026-08-04

### Added

- A native macOS workbench organizes the primary human workflows around
  Discover and Organize, Govern and Automate, Change Safely, and Recover and
  Audit while retaining the terminal TUI for later-parity workflows.
- A versioned local stdio desktop bridge exposes redacted inventory, group,
  reviewed change, backup, audit, and restore state while keeping Rust as the
  only provider-mutation authority.
- The shared Xcode scheme now has an XCTest action covering bundled-child
  integrity, protocol and binary compatibility, isolated workspace loading,
  and work-oriented navigation.
- Release automation builds separate Apple Silicon and Intel desktop archives
  with deterministic packaging, ad-hoc Hardened Runtime signing, SBOMs,
  provenance attestations, checksums, and isolated bridge smoke verification.

### Compatibility

- CLI, terminal TUI, and MCP remain supported. Profiles, gateways, sessions,
  and hooks continue through their existing non-desktop surfaces until later
  workbench parity phases.
- Desktop updates are manual in this release candidate. Desktop archives are
  not Developer ID signed or notarized, so Gatekeeper can require an explicit
  first-launch override after checksum and provenance verification.

## [0.6.2] - 2026-08-03

### Fixed

- Bulk toggles now consolidate successful native item backups into one
  authenticated transaction bundle. The bundle stores one before-image for
  each physical resource, so shared configuration files are not repeatedly
  snapshotted and restore returns the complete batch to its pre-apply state.

### Compatibility

- Restore plans generated by v0.6.1 must be re-planned after upgrading to
  v0.6.2, which binds complete provider coverage in restore-plan schema 3.
  Existing authenticated backups remain restorable in v0.6.2; v0.6.1 cannot
  read the new bundled backup format.

## [0.6.1] - 2026-08-03

### Fixed

- Project-scope skill discovery now stays within the checkout selected for the
  run. It excludes inactive nested worktrees and conventional test and fixture
  subtrees, preventing repository fixtures from appearing as mutable items.

## [0.6.0] - 2026-08-03

### Changed

- Discovery is split into provider-focused modules while preserving the public
  discovery registry and fixture-backed provider behavior.
- Cursor-compatible repository skill roots share one multi-root scope
  traversal for each discovery run. The result is cached by root, traversal,
  and scope mode, so compatible roots reuse the discovery work without sharing
  results across different projects or traversal modes.

## [0.5.0] - 2026-08-02

### Added

- The public stdio MCP server now supports the stateless 2026-07-28 protocol
  edition, including `server/discover`, per-request protocol metadata,
  `resultType`, server identity metadata, and cache declarations for
  `tools/list`.

### Changed

- Unpin is promoted to the non-prerelease `0.5.0` release channel. Release
  tags with a prerelease suffix remain GitHub prereleases; final version tags
  create stable draft releases.

## [0.1.0-beta.15] - 2026-08-02

### Fixed

- Cursor project-scope discovery now recurses only below an actual enclosing
  Git root, preventing a non-repository launch directory such as `$HOME` from
  causing an inflated inventory and delayed TUI startup.
- Project-scope workers stop dequeuing new subtrees after a sibling error or
  cancellation, and terminal cleanup remains reliable when startup exits.

## [0.1.0-beta.14] - 2026-08-02

### Changed

- Project-scoped discovery now scans independent provider roots concurrently,
  while preserving deterministic results and diagnostics.
- The terminal UI renders a cancellable loading view immediately, then reports
  provider-by-provider discovery progress while discovery and credential
  resolution run off the terminal event loop.

## [0.1.0-beta.13] - 2026-08-01

### Added

- Added a reviewed backup-delete action to Restore Operations: `D` prepares a
  deletion bound to the manifest shown to the user, `Enter` confirms it, and
  `A` applies it with audit evidence.
- Added a macOS local credential broker. It keeps the purpose-separated keys
  in one idle-expiring process and serves concurrent Unpin CLI/MCP clients over
  a private same-user socket. Existing keys are bundled into one Keychain item
  after the first successful broker start, so later starts need one Keychain
  access.

### Changed

- Backup rows now identify the provider, scope, affected item, requested state,
  and creation time instead of leading with an opaque backup identifier.
- All TUI control lists keep their selected row in view. Navigation is now
  arrow-only, and the command footer uses consistent title case.

### Security

- Backup deletion rechecks the reviewed manifest digest under the mutation lock,
  rejects symlink/special-file backup trees, and records both request and
  completion audit events.
- The credential broker uses a `0700` directory and `0600` Unix socket; it is
  intentionally scoped to the owning macOS user rather than arbitrary network
  clients.

## [0.1.0-beta.12] - 2026-08-01

### Changed

- Reworked the terminal command footer into named, underlined mnemonics. The
  active view now shows every available contextual control without repeating a
  separate shortcut token; plain headless output marks the same keys in
  brackets.
- Let `p`/`l`/`c` narrow member candidates while creating or editing a named
  group, and prioritized compact header state ahead of wrapped command-footer
  detail so narrow and short terminals do not overlap or lose their summary.
- Replaced the action legend with input-specific guidance while search or a
  group name is being edited, so the footer never advertises keys consumed as text.
- Updated direct Rust dependencies: `http` 1.5.0, `jsonc-parser` 0.33.1, and
  `rmcp` 3.0.1.

### Fixed

- Kept the command legend and case-sensitive TUI key bindings aligned, including
  group reach, scope, rename, restore, approval, definition-save, and export.
- Reject fully non-interactive live approvals before opening macOS Keychain, so
  automated applies fail closed instead of waiting for a human prompt.

## [0.1.0-beta.11] - 2026-08-01

### Fixed

- Clarified named-group control plans in the terminal UI: `Groups` now uses the
  standard title case, long control content wraps and scrolls, and group
  identities are shown as `Agent | scope | type | name` without duplicated
  namespaces.

## [0.1.0-beta.10] - 2026-07-31

### Fixed

- Published the delivery-only release candidate with a signed tag. Program logic and provider behavior are unchanged from `0.1.0-beta.9`.

## [0.1.0-beta.9] - 2026-07-31

### Fixed

- Corrected the pinned Rust 1.96.1 setup action and removed unsupported
  toolchain inputs from CI so the MSRV jobs prove the intended compiler.
- Hardened release evidence and publication so workflow-generated checksums
  remain the trust root, evidence uploads are staged without clobbering, and
  publication requires fresh checksums plus the exact expected asset set.

## [0.1.0-beta.8] - 2026-07-31

### Fixed

- Corrected MCP annotations for human-handoff tools that persist internal
  Unpin transaction, payload, and coordination state: they now report
  `readOnlyHint: false` and `destructiveHint: false` while continuing to leave
  provider configuration unchanged.
- Added contract coverage that verifies the handoff state is created without
  changing the target provider bytes.

## [0.1.0-beta.7] - 2026-07-31

### Security

- Updated the transitive `event-listener` dependency from 5.4.1 to 5.4.2 to
  resolve RustSec advisory RUSTSEC-2026-0221.

## [0.1.0-beta.6] - 2026-07-31

### Fixed

- GNU/Linux archives are now built on Ubuntu 22.04, lowering the glibc
  baseline to 2.35 and restoring compatibility with Debian 12 (glibc 2.36).

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
- Restore plans disclose and bind every overwritten policy and maintenance
  record target, and protected changes with no observable failed residue can
  be safely retried; interrupted partial changes remain restorable.

### Compatibility

- This beta adds the read-only `unpin_get_policy_maintenance_status` MCP tool
  and policy-maintenance JSON contracts. Policy-maintenance plans use schema
  version 2, so plans from earlier beta.5 prerelease builds must be replanned;
  inventory-group definitions and approved-apply contracts remain compatible
  with beta.4.

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

[Unreleased]: https://github.com/IgorArkhipov/unpin/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/IgorArkhipov/unpin/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/IgorArkhipov/unpin/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/IgorArkhipov/unpin/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/IgorArkhipov/unpin/compare/v1.0.0-rc.1...v1.0.0
[1.0.0-rc.1]: https://github.com/IgorArkhipov/unpin/compare/v0.6.2...v1.0.0-rc.1
[0.6.2]: https://github.com/IgorArkhipov/unpin/compare/v0.6.1...v0.6.2

[0.6.1]: https://github.com/IgorArkhipov/unpin/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/IgorArkhipov/unpin/compare/v0.5.0...v0.6.0

[0.5.0]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.5.0
[0.1.0-beta.15]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.15
[0.1.0-beta.14]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.14
[0.1.0-beta.13]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.13
[0.1.0-beta.12]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.12

[0.1.0-beta.11]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.11
[0.1.0-beta.10]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.10
[0.1.0-beta.9]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.9
[0.1.0-beta.8]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.8
[0.1.0-beta.7]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.7
[0.1.0-beta.6]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.6
[0.1.0-beta.5]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/IgorArkhipov/unpin/releases/tag/v0.1.0-beta.3
