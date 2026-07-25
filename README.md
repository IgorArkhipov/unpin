# Unpin

Unpin is a Rust CLI/TUI for local AI-agent configuration discovery, safe mutation, snapshots, restore, and MCP-backed agent workflows.

Internal agent workflow context may exist locally under `memory-bank/`, `.prompts/`, `.protocols/`, and `old/`, but those folders are excluded from git and are not part of the public repository surface.

## Distribution status and quick start

Unpin `0.1.0-beta.3` is the first public beta. GitHub Releases provide
provenance-attested archives for Apple Silicon macOS, Intel macOS, and 64-bit
GNU/Linux, together with CycloneDX SBOM attestations, SHA-256 checksums, and
approved provider-matrix evidence. The binaries are not Apple-notarized or
platform-code-signed. crates.io and package-manager distribution are deferred.

Download the archive for your platform from
[GitHub Releases](https://github.com/IgorArkhipov/unpin/releases), verify it
against `SHA256SUMS`, then verify its GitHub build provenance:

```bash
gh attestation verify unpin-v0.1.0-beta.3-TARGET.tar.gz \
  --repo IgorArkhipov/unpin
```

Extract the archive, install the included binary on your user `PATH`, and start
with read-only inspection:

```bash
cd unpin-v0.1.0-beta.3-TARGET
mkdir -p "$HOME/.local/bin"
install -m 0755 unpin "$HOME/.local/bin/unpin"
export PATH="$HOME/.local/bin:$PATH"

unpin --help
unpin providers
unpin doctor
unpin list --json
```

Add `$HOME/.local/bin` to your shell's startup configuration if it is not
already on `PATH`.

To build from source, use Rust 1.96 or newer:

```bash
cargo build --release --locked
./target/release/unpin --help
```

Release users can continue with the five-minute setup below. To connect an
agent, use the [MCP setup guide](docs/MCP.md). Contributors should start with
the [onboarding guide](docs/ONBOARDING.md) for the architecture, scope
precedence, guided code tour, and fixture-backed first mutation.

## Five-minute local setup

Run Unpin from the Git repository whose agent configuration you want to
inspect:

```bash
cd /path/to/repository
PROJECT_ROOT="$(git rev-parse --show-toplevel)"

unpin --version
unpin doctor --project-root "$PROJECT_ROOT"
unpin list --project-root "$PROJECT_ROOT" --json
```

These commands are read-only. Before the first persistent toggle, restore, or
protected session, initialize Unpin's purpose-separated keychain keys once:

```bash
unpin auth backup init
unpin auth approval init
unpin auth session init
```

### Toggle one project skill or MCP server

First discover the exact item ID. Narrow the inventory by provider, kind, and
project layer:

```bash
unpin list \
  --project-root "$PROJECT_ROOT" \
  --provider claude \
  --kind skill \
  --layer project \
  --json
```

Plan the one-item toggle without writing anything:

```bash
unpin toggle \
  --project-root "$PROJECT_ROOT" \
  --provider claude \
  --kind skill \
  --layer project \
  --id EXACT_ITEM_ID \
  --json
```

Review the target state, effects, and fingerprint. Apply that exact selection
only by repeating it with the returned fingerprint:

```bash
unpin toggle \
  --project-root "$PROJECT_ROOT" \
  --provider claude \
  --kind skill \
  --layer project \
  --id EXACT_ITEM_ID \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN
```

`toggle` flips the item's current enabled state. To manage a configured MCP
server instead, use `--kind mcp` and the exact MCP item ID returned by `list`.
Change `--provider` for another supported agent. Unpin refuses unsupported or
read-only combinations rather than inventing provider state.

### Connect Unpin to an agent

Agents connect by launching Unpin's local stdio server:

```bash
unpin mcp --project-root "$PROJECT_ROOT"
```

The process stays attached to stdio while the host is connected; normally put
this command in the host's MCP configuration instead of running it by hand.

The [MCP setup guide](docs/MCP.md) has copy-ready configuration for Codex,
Claude Code, Cursor, OpenCode, and Zed; explains Pi's native-MCP limitation;
and includes a prompt you can give an agent to configure and verify the
connection automatically. The
[MCP capability-control prompt library](docs/MCP-PROMPTS.md) covers project
allowlists, profiles, capability locks, hooks, sessions, and restore. MCP can
inspect and prepare plans, but persistent writes always return a CLI/TUI
human-action handoff.

## Command Surface

- `unpin auth backup|approval|session|cursor-dashboard` manages purpose-separated OS-keychain state.
- `unpin providers` prints the provider capability matrix.
- `unpin doctor` validates discovery inputs, configured vault integrity, fixture capability-matrix drift, and provider fixture shape drift.
- `unpin snapshot` writes a discovery snapshot into Unpin app state.
- `unpin list` lists discovered provider items.
- `unpin toggle` plans a supported item toggle, then applies only the exact confirmed fingerprint.
- `unpin restore` plans a backup restore, then applies only the exact confirmed fingerprint.
- `unpin catalog`, `profile`, `gateway`, `session`, and `hook` manage normalized capabilities, reusable policy, optional routing, isolated leases, and reviewed hook trust.
- `unpin mcp` runs a newline-delimited stdio MCP control plane. Persistent apply requests return human-action handoffs instead of minting approval.
- `unpin tui` opens the terminal inventory UI. `unpin dashboard` is an alias for the same command.

## Provider Coverage

Unpin currently discovers Claude Code, Codex, Cursor, Pi, OpenCode, and Zed skills, configured MCPs, agents, hooks, provider settings, and selected plugin surfaces from fixture-backed or explicitly provided roots. Provider-owned Claude skills under `$HOME/.claude/skills` and repository-scoped `.claude/skills`, recursively nested Cursor skills under `$HOME/.cursor/skills` and repository-scoped `.cursor/skills`, Pi skills under `$HOME/.pi/agent/skills` and `.pi/skills`, OpenCode skills under `$HOME/.config/opencode/skills` and `.opencode/skills`, Cursor local plugin directories under `$HOME/.cursor/plugins/local`, and agent files are writable through guarded Unpin vault toggles with backup and restore evidence. Pi direct Markdown skills use a file vault; skill directories use a directory vault. Cursor-compatible skills, Codex shared `.agents/skills`, Pi shared `.agents/skills`, OpenCode shared `.agents/skills` and `.claude/skills`, plus Zed `.agents/skills`, use the same guarded cross-provider flow. Disabling one shared source records its original path and keeps every loading provider visible as disabled; re-enable through any provider view or backup restore returns it to that path. OpenCode MCPs use native `mcp.<id>.enabled` state in global or project JSON/JSONC while preserving comments and trailing commas. OpenCode npm plugin toggles remove and restore only config references through guarded Unpin vault state with authenticated backup evidence; Bun cache files remain installed. Pi intentionally has no native MCP core; MCP connectors belong to Pi extensions/packages. Pi package extension toggles set native `packages[].extensions` filters to `[]`, retain package references and every non-extension resource, then restore the exact original package entry through guarded Unpin vault state with authenticated backup evidence. Pi 0.81.1 and OpenCode 1.18.4 global/project config compatibility was live-validated in disposable, explicitly rooted environments for this beta. OpenCode auto-loaded local plugin files are read-only because current host docs expose no local-file disable setting. Existing Claude, Codex, Cursor, and Zed mutation contracts remain unchanged. Hooks, settings, instructions, permissions, and sandbox files remain non-writable inventory. IDE extensions unrelated to agent harnesses remain outside scope.

Unpin prefers provider-native enable state. Claude, Codex, and OpenCode plugin toggles edit supported settings references and leave installed bundles or caches untouched. Cursor local plugin directories are path-discovered and have no documented local disable reference; Unpin therefore relocates the intact bundle into authenticated Unpin vault state instead of deleting it, then restores it to its recorded origin on re-enable or backup restore.

Plugin scope support is explicit:

| Provider | Global/user plugins | Project/repository plugins |
| --- | --- | --- |
| Claude Code | Writable through `enabledPlugins` | Writable through project/local `enabledPlugins` |
| Codex | Writable through user `plugins.<id>.enabled` | Unsupported by current Codex plugin host contract |
| Cursor | Local bundles writable through intact vault/restore; marketplace installs read-only | Marketplace installs inventoried read-only |
| Pi | Package extension filters fixture- and live-host-verified | Package extension filters fixture- and live-host-verified |
| OpenCode | npm config toggles fixture- and live-host-verified; local files read-only | npm config toggles fixture- and live-host-verified; local files read-only |
| Zed | Out of scope; Zed uses standard Agent Skills | Out of scope; Zed uses standard Agent Skills |

Unpin does not invent repository plugin state for Codex or write Cursor marketplace caches/SQLite rows as if they were authoritative settings.

Skill discovery follows current provider layouts. Claude scans `.claude/skills`; Codex scans shared `.agents/skills` and administrator-managed `/etc/codex/skills`; Cursor recursively scans native and compatibility roots. Pi recursively scans native `.pi` and shared `.agents` roots and also inventories direct Markdown skills in native roots. OpenCode scans native `.opencode` plus shared `.agents` and `.claude` roots from selected directory to repository root. Zed uses global and selected-project `.agents/skills`. Reserved `@compat/...` and `@file/...` namespaces prevent native, shared, and direct-file item-id collisions. Vaulted skills remain filtered to currently resolved roots, so disabled items from another home or repository do not leak into inventory. Unreadable nested directories produce path-safe warnings while readable scopes remain available. Provider-owned skill links preserve link identity; skills under symlinked provider roots remain read-only.

Zed `context_servers` and OpenCode `mcp.<id>.enabled` mutation are JSONC-aware: comments, trailing commas, and surrounding formatting survive toggles and backup restore.

OpenCode is the supported harness in this provider family. OpenRouter is a model/API router with per-request plugins, not a standard local global/project agent-configuration host, so it has no Unpin provider adapter.

## Profiles and optional gateway

Native provider behavior remains default. Profiles are immutable allowlists resolved by replacement: session, workspace/worktree, repository, global, then native default. Provider-specific policy wins before generic policy at each scope. Global provider capability locks are applied after that selection: `hard-enabled` restores a capability omitted by a narrower profile, while `hard-disabled` removes it. Active sessions pin profile, lock, and exposure revisions, so another process, worktree, branch change, or later policy edit cannot mutate their capability set.

Inspect locks with `unpin profile locks --provider codex --json`. Change one with a plan-first `unpin profile lock --provider codex --capability <id> --state hard-enabled|hard-disabled|clear --json`, then re-run with the emitted fingerprint plus `--apply --confirm`. Lock status includes repository/worktree identity, the effective gateway source, conservative enforcement quality, and `next-session-only` activation; native mode is never reported as strict when the provider cannot prove it.

Gateway lifecycle separates installation, routing, and detachment:

- `gateway install` records dormant Unpin-owned lifecycle state.
- `gateway on` selects intended gateway policy for future sessions; it does not prove a live host attachment.
- `gateway off` restores ledger-owned adopted skill views, selects native policy, and closes admission; active matching leases block unless explicitly drained.
- `gateway detach` restores ledger-owned adopted skill views, selects native policy, and removes managed lifecycle state.

Managed native MCP configuration references are not yet part of gateway lifecycle effects. Status, dry-run, apply, MCP, and TUI output report this as `nativeMcpReferences=not-managed`; live provider attachment remains blocked, so Unpin never claims duplicate-free MCP routing before that effect exists.

Every persistent profile, capability-lock, gateway, session-end, adoption, trust, toggle, and restore action is plan-first. Apply requires `--confirm` plus exact `--plan-fingerprint` from current dry-run. MCP callers receive structured handoff and cannot issue human approval or expose keychain material.

Exact terminal retries revalidate live policy, provider, adopted-view, and restored-target state before returning cached success. Divergence reports `recovery-required`. Catalog adoption reports rolled-back and needs-repair outcomes explicitly and exits nonzero for both.

`profile propose --prompt ...` ranks profile metadata locally and returns a confirmation-required session proposal. It emits only the prompt digest, never prompt text, and does not mutate policy or start a session.

Fixture-backed `session launch` creates one private lease, Unix-socket gateway, and overlay per child harness. Lease protection binds every applicable global, repository, and workspace gateway-mode and policy target, current mutable native-item transitions, authenticated restorable backups, and adopted-view resources, including global views shared by another worktree. Gateway, restore, and native-toggle apply acquire the same transition conflict guard before mutation. All live launches require backup and session authentication so adopted and restorable resources cannot be silently omitted from the lease. Live profile-scoped launch currently fails closed until each provider adapter can prove strict native masking and gateway attachment. Native launches remain available after those authentication prerequisites. Repository identity groups shared blast radius; physical worktree identity isolates workspace policy; opaque session identity isolates exposure. Separate worktrees remain required when agents also need source-file edit isolation.

Hook inventory records individual handlers and honest provider coverage. Trust receipts bind handler invocation fingerprint, compiled profile digest, provider, workspace, and session. Gateway-routed MCP hook policy is fixture-contract verified. Native dispatcher/managed-bridge host activation still requires live-provider wiring and verification; Zed built-in hooks remain unsupported.

## Examples

Fixture-backed discovery:

```bash
cargo run -p unpin-cli -- list --fixture-root crates/unpin-core/tests/fixtures
cargo run -p unpin-cli -- doctor --fixture-root crates/unpin-core/tests/fixtures
cargo run -p unpin-cli -- tui --fixture-root crates/unpin-core/tests/fixtures --headless
cargo run -p unpin-cli -- dashboard --fixture-root crates/unpin-core/tests/fixtures --headless
```

When `--fixture-root` is supplied, `doctor` validates `capability-matrix.json` and required provider fixture shapes before returning OK, so stale provider contracts fail deterministically.

Explicit live-style roots:

```bash
cargo run -p unpin-cli -- list \
  --home-root "$HOME" \
  --project-root "$PWD" \
  --cursor-root "$HOME/Library/Application Support/Cursor/User"
```

## Configuration

Unpin resolves command roots in this order:

1. Defaults: current directory for the project root, `~/.config/unpin` for Unpin-owned state, `$HOME/.cursor/mcp.json` for Cursor global MCP config, `<project>/.cursor/mcp.json` for Cursor project MCP config, and the macOS Cursor user-data directory for Cursor app-support state.
2. User config: `~/.config/unpin/config.json`.
3. Project config: `<projectRoot>/.unpin.json`.
4. CLI flags such as `--project-root`, `--app-state-root`, and `--cursor-root`.

Config files are JSON and may contain:

```json
{
  "version": 1,
  "projectRoot": "~/work/my-project",
  "appStateRoot": "~/.config/unpin",
  "cursorRoot": "~/Library/Application Support/Cursor/User"
}
```

Path fields must be non-empty strings or `null`. Invalid types and blank paths fail configuration loading instead of falling back to another root.

`cursorRoot` points at Cursor app-support state such as profiles and workspace storage. Cursor MCP config discovery uses the resolved home root for `$HOME/.cursor/mcp.json` and the resolved project root for `<project>/.cursor/mcp.json`.

Live `doctor`, `list`, `snapshot`, `toggle`, `restore`, `mcp`, `tui`, and `dashboard` commands use the resolved app-state root when `--app-state-root` is omitted. Vault discovery reports malformed metadata, mismatched provider paths, and missing payloads as `invalid-vault-entry` warnings; `doctor` fails when any such warning exists.

## Backup Authentication

Live applies and protected session launches require a 32-byte backup authentication key stored in OS keychain. Initialize it once, then inspect its non-secret fingerprint:

```bash
cargo run -p unpin-cli -- auth backup init
cargo run -p unpin-cli -- auth backup status
```

Approval signing uses a separate key purpose:

```bash
cargo run -p unpin-cli -- auth approval init
cargo run -p unpin-cli -- auth approval status
```

Session leases, child launch controls, and transition conflict checks use a dedicated authentication key. Initialize it before live session, gateway, profile-policy, restore, TUI, or native apply workflows:

```bash
cargo run -p unpin-cli -- auth session init
cargo run -p unpin-cli -- auth session status
```

Session state uses HMAC-SHA256 over complete bootstrap and lease records. Launch controls bind signed payload to unique control path, preventing cross-session or cross-workspace replay. Key remains in OS keychain; session documents contain only non-secret key fingerprint and authentication tag.

Optional Cursor dashboard cookie storage reads secret bytes only from stdin, binds them to Cursor marketplace mutation purpose, and never prints them:

```bash
printf '%s' "$CURSOR_DASHBOARD_COOKIE" \
  | cargo run -p unpin-cli -- auth cursor-dashboard store
cargo run -p unpin-cli -- auth cursor-dashboard status
cargo run -p unpin-cli -- auth cursor-dashboard remove
```

Cookie presence does not make unsupported Cursor marketplace entries writable; each operation still reports current provider support and required human action.

New backup manifests use version 3 with purpose-separated HMAC-SHA256 authentication over manifest fields and deterministic payload-tree SHA-256 digests. Restore verifies both before acquiring mutation lock or writing provider state. Missing, mismatched, or tampered authentication blocks restore. Older authenticated manifests use version-specific verification. Legacy version 1 backups remain visible as `legacy-unauthenticated` but are not restorable unless a trusted caller explicitly authenticates current contents through the core migration API; Unpin never signs them automatically.

TUI header reports backup-auth readiness. MCP inventory summary exposes `writeSafety.backupAuthentication` and `writeSafety.writesEnabled`, allowing agents to preflight write availability without attempting mutation.

Fixture commands use deterministic fixture key and never access OS keychain. Keep `--fixture-root` on fixture-backed restore, TUI, and MCP checks so they verify fixture-created backups with same key.

Plan a no-write skill toggle:

```bash
cargo run -p unpin-cli -- toggle \
  --fixture-root crates/unpin-core/tests/fixtures \
  --provider claude \
  --kind skill \
  --layer project \
  --id claude:project:skill:example-claude-skill
```

Apply a Claude project configured MCP approval toggle against disposable fixtures:

```bash
tmp_fixture="$(mktemp -d)"
tmp_state="$(mktemp -d)"
cp -R crates/unpin-core/tests/fixtures/. "$tmp_fixture/"
cargo run -p unpin-cli -- toggle \
  --fixture-root "$tmp_fixture" \
  --app-state-root "$tmp_state" \
  --provider claude \
  --kind mcp \
  --layer project \
  --id claude:project:configured-mcp:github \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN
```

Apply a Zed configured MCP `context_servers` vault toggle against disposable fixtures:

```bash
tmp_fixture="$(mktemp -d)"
tmp_state="$(mktemp -d)"
cp -R crates/unpin-core/tests/fixtures/. "$tmp_fixture/"
cargo run -p unpin-cli -- toggle \
  --fixture-root "$tmp_fixture" \
  --app-state-root "$tmp_state" \
  --provider zed \
  --kind mcp \
  --layer global \
  --id zed:global:configured-mcp:github \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN
```

Apply an agent-file vault toggle against disposable fixtures:

```bash
tmp_fixture="$(mktemp -d)"
tmp_state="$(mktemp -d)"
cp -R crates/unpin-core/tests/fixtures/. "$tmp_fixture/"
cargo run -p unpin-cli -- toggle \
  --fixture-root "$tmp_fixture" \
  --app-state-root "$tmp_state" \
  --provider claude \
  --kind agent \
  --layer global \
  --id claude:global:agent:claude-global-reviewer \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN
```

## Terminal UI

The TUI lists the same discovered inventory as `list`, with provider/layer/category filters, `/` search, selected-item details, dry-run plan preview, discovery warnings, and recent backups. Writable items can be staged with space, confirmed with enter, and applied with `a`. After a successful staged apply, Unpin rediscovers live provider state, reloads backups, and writes a fresh latest/history snapshot.

TUI keeps last apply outcome visible. Blocked entries remain staged with confirmation reset; refresh failures skip stale snapshots, and snapshot write failures are reported after mutation succeeds.

Run the MCP stdio loop with one shell-provided request:

```bash
request='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
printf '%s\n' "$request" \
  | cargo run -p unpin-cli -- mcp --fixture-root crates/unpin-core/tests/fixtures
```

Use `--once` for a one-request smoke check that exits immediately.

MCP tool IDs, titles, descriptions, and server identity use Unpin branding.

Malformed or empty JSON lines return a JSON-RPC `-32700` parse error with `id: null`; the long-running stdio loop continues with later messages. Messages larger than 8 MiB remain fatal transport errors.

Plan a bulk MCP toggle:

```bash
request='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unpin_plan_toggle_items","arguments":{"selector":{"providers":["claude"],"kinds":["plugin"]},"targetEnabled":false}}}'
printf '%s\n' "$request" \
  | cargo run -p unpin-cli -- mcp --fixture-root crates/unpin-core/tests/fixtures --once
```

MCP apply tools require exact reviewed fingerprints and return structured human-action handoffs without writing provider state. Bulk requests also require `maxItems`. Configured MCP entries named `unpin` remain protected from disable attempts through their own control plane.

## Development

Contributor and reviewer guidance:

- [Project and distribution status](PROJECT.md)
- [Changelog](CHANGELOG.md)
- [Agent MCP setup](docs/MCP.md)
- [MCP capability-control prompts](docs/MCP-PROMPTS.md)
- [Onboarding guide](docs/ONBOARDING.md)
- [Local provider validation matrix](docs/local-provider-matrix.md)
- [Release procedure](docs/RELEASING.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Reviewer guide](REVIEWING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [AI agent guidance](AGENTS.md)

Local CI-equivalent gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo run -p unpin-cli --locked -- --help
cargo audit --no-yanked
cargo machete
```

CI also checks the declared Rust 1.96 MSRV separately from the pinned Rust 1.97.1 development toolchain.
