# Unpin

Unpin is a Rust CLI and terminal UI for discovering, inspecting, and safely
managing local AI-agent configuration across Claude Code, Codex, Cursor, Pi,
OpenCode, and Zed. The headless core owns provider discovery, normalized
inventory, profiles and layered policy, guarded transitions, authenticated
backups, restore, sessions, gateway policy, hook trust, and MCP-safe control
workflows. The CLI and Ratatui interface are thin surfaces over that core.

The original Rust bootstrap was informed by a TypeScript AgentScope
implementation from `ai-setup`. Unpin now has its own architecture and safety
contract: plan-first writes, exact reviewed fingerprints, purpose-separated
approval, authenticated backup and session keys, drift and conflict protection,
audit evidence, and explicit recovery outcomes.

## Current status

- Version: `0.1.0-beta.2` public-beta release candidate.
- Canonical repository: `https://github.com/IgorArkhipov/unpin`.
- License: MIT, copyright Igor Arkhipov.
- Distribution: GitHub release archives for Apple Silicon macOS, Intel macOS,
  and 64-bit GNU/Linux.
- Integrity: SHA-256 checksums, CycloneDX SBOMs, GitHub artifact attestations,
  and an immutable-release policy.
- Durable policy: global, repository/project, and physical worktree.
- Ephemeral policy: one authenticated session lease.
- Native provider behavior remains the default; gateway routing is optional.
- Nested-folder policy is intentionally out of scope.
- Pi 0.81.1 and OpenCode 1.18.4 global/project config compatibility is
  fixture-backed and live-host-verified in disposable roots.
- Native MCP-reference lifecycle and strict live provider attachment remain
  explicit gateway limitations rather than inferred support.

The pre-release baseline matrix run `2026-07-24-184505-local-matrix` passed 31
CLI, 31 real-PTY TUI, and 31 persistent MCP scenarios. It also passed 620 Rust
tests, inventoried 938 live items without persisting private names, and verified
that live provider state did not change. Release-specific evidence is rerun from
the exact tag commit and attached to the GitHub release rather than committed.

## Distribution readiness

The repository now contains package metadata, an MIT license, private GitHub
security reporting instructions, release notes, a changelog, target packaging,
SBOM generation, provenance attestation, checksums, and a draft-only release
workflow. crates.io, Homebrew, Linux ARM64, Windows, and platform code signing
remain deferred.

Publishing `v0.1.0-beta.2` is gated on required CI, a finalized provider matrix
from the exact clean release commit, approved evidence and checksums attached to
the draft, and enabled branch, private-security-reporting, and immutable-release
controls.

The [onboarding guide](docs/ONBOARDING.md) explains the architecture and first
safe run. The [local provider validation matrix](docs/local-provider-matrix.md)
documents the release evidence procedure, and the
[release guide](docs/RELEASING.md) documents publication.

Copied TypeScript-era context under `old/` and agent workflow material under
`memory-bank/`, `.prompts/`, and `.protocols/` are local-only and git-ignored so
public commits stay focused on the Rust product source.
