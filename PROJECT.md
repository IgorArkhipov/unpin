# Unpin

Unpin is a Rust-first successor to the TypeScript AgentScope implementation from `ai-setup`. It is a local CLI and terminal UI for discovering, inspecting, and safely managing AI-agent configuration across Claude Code, Codex, Cursor, and future compatible providers.

The product intent is parity with the existing TypeScript tool while rebuilding the implementation, documentation, and delivery process from scratch around Rust conventions. The headless core owns provider discovery, normalized inventory, dry-run mutation planning, guarded apply and restore, snapshots, and MCP-safe command adapters. The CLI and Ratatui terminal UI are thin surfaces over that core.

The repository keeps copied TypeScript-era context under the git-ignored `old/` directory. Agent workflow material such as `memory-bank/`, `.prompts/`, and `.protocols/` is also local-only and git-ignored so public commits stay focused on the Rust product source.
