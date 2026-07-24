## Summary

- TBD

## Test Plan

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] `cargo run -p unpin-cli --locked -- --help`
- [ ] `cargo audit --no-yanked`
- [ ] `cargo machete`
- [ ] Pi/OpenCode disposable-root host validation when release-impacting
- [ ] Full local provider matrix run and finalized when release-impacting

## Safety Checklist

- [ ] Tests and examples do not read real home-directory provider state.
- [ ] Tests and examples do not use `.env*` files.
- [ ] Write paths use dry-run planning, confirmation, backup, audit, and restore behavior where relevant.
- [ ] Provider changes stay within the current Claude Code, Codex CLI, Cursor,
      Pi, OpenCode, and Zed support scope.
- [ ] Public docs or examples were updated when behavior changed.

## Reviewer Notes

- TBD
