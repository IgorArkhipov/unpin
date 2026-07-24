# Local onboarding and provider matrix

This guide gets an engineer from a source checkout to a safe Unpin inventory,
CLI/TUI use, MCP host registration, and a reproducible local evidence bundle.

Unpin supports Claude Code, Codex, Cursor, Pi, OpenCode, and Zed. It inventories current
provider configuration, plans changes without writing by default, and applies
supported toggles with authenticated backup, audit, and restore evidence.

## Support matrix

| Provider | Skills | Plugins | MCP servers |
| --- | --- | --- | --- |
| Claude Code | Global and project | Global and project `enabledPlugins` | Global and project |
| Codex | Global and project | Global only; project plugins unsupported by current host contract | Global and project |
| Cursor | Global, shared, and project | Local global bundles writable; marketplace installs read-only | Global and project |
| Pi | Global, shared, and project | Global and project package extension filters; live host verification pending | Unsupported by Pi core; use package extensions |
| OpenCode | Global, shared, and project | Global and project npm config references; auto-loaded local files read-only; fixture-verified, live host pending | Global and project native enabled state; fixture-verified, live host pending |
| Zed | Global and project standard Agent Skills | Out of scope | Global and project `context_servers` |

Zed plugins are intentionally absent. Zed uses standard Agent Skills for reusable
agent instructions. IDE extensions are also outside scope because they extend an
editor, not an agent or model configuration.

Shared skill sources are one physical item. Disabling a shared `.agents/skills`
item affects every supported provider that loads that path. Restore returns it to
its recorded origin.

Codex shared `.agents/skills` entries use that cross-provider vault flow. Codex
administrator-managed skills remain in place and use path-specific
`[[skills.config]]` state, because those sources are not shared with other hosts.

## Build

From repository root:

```bash
cargo build -p unpin-cli
./target/debug/unpin --help
```

Examples below use `/absolute/path/to/unpin` for built binary. Replace it with
output of `realpath target/debug/unpin`.

## First safe inventory

Inspect capabilities and health before any mutation:

```bash
./target/debug/unpin providers
./target/debug/unpin doctor
./target/debug/unpin list --json
```

Limit inventory when investigating one cell:

```bash
./target/debug/unpin list \
  --provider cursor \
  --kind mcp \
  --layer global \
  --json
```

Use explicit roots when current directory or Cursor profile is ambiguous:

```bash
./target/debug/unpin list \
  --home-root "$HOME" \
  --project-root "$PWD" \
  --cursor-root "$HOME/Library/Application Support/Cursor/User" \
  --json
```

`list`, `doctor`, and a toggle without `--apply` are read-only. Cursor marketplace
plugins remain read-only inventory even when Cursor is authenticated. Unpin
does not rewrite Cursor-owned marketplace cache or SQLite state.

## Backup authentication

Live writes and protected session launches require backup authentication; writes also require a separate approval-signing key in OS keychain:

```bash
./target/debug/unpin auth backup init
./target/debug/unpin auth backup status
./target/debug/unpin auth approval init
./target/debug/unpin auth approval status
```

`status` prints readiness and a non-secret fingerprint. It never prints key
material. Fixture runs use a deterministic test key and never access OS keychain.

## CLI toggle and restore

Copy an exact item id from `list --json`. First render a dry-run plan:

```bash
./target/debug/unpin toggle \
  --provider codex \
  --kind mcp \
  --layer global \
  --id codex:global:configured-mcp:example \
  --json
```

Review target, operation, affected paths, and target state. Apply same selection:

```bash
./target/debug/unpin toggle \
  --provider codex \
  --kind mcp \
  --layer global \
  --id codex:global:configured-mcp:example \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN \
  --json
```

Save returned backup id. Restore is also plan-first:

```bash
./target/debug/unpin restore BACKUP_ID --json
./target/debug/unpin restore BACKUP_ID \
  --apply \
  --confirm \
  --plan-fingerprint PLAN_FINGERPRINT_FROM_DRY_RUN \
  --json
```

Restart or reload affected host after native configuration changes. Cursor local
plugin changes require window reload or restart; Codex native skill and plugin
changes require Codex restart. Pi package extension and OpenCode config changes
require their host to restart or reload.

## Terminal UI

```bash
./target/debug/unpin tui
```

Useful keys:

| Key | Action |
| --- | --- |
| `j` / `k` | Move selection |
| `p` | Cycle provider filter |
| `l` | Cycle layer filter |
| `c` | Cycle category filter |
| `/` | Search |
| `x` | Clear search |
| `space` | Stage writable item |
| `enter` | Confirm staged plan |
| `a` | Apply confirmed plan |
| `u` | Unstage |
| `q` | Quit |

Selected-item pane shows dry-run plan before staging. Header shows backup-auth
readiness, warnings, backup count, and latest action.

## Profiles, sessions, hooks, and optional gateway

Native mode remains default. Profile policy resolves session, workspace/worktree,
repository, global, then native default. Each explicit slot replaces broader
selection; it never merges implicitly. Global provider locks are applied after
selection and are pinned into each new session, so later lock changes do not
alter an active lease. Inspect and validate before applying:

```bash
./target/debug/unpin catalog list --json
./target/debug/unpin profile list --json
./target/debug/unpin profile validate --id review --json
./target/debug/unpin profile propose --prompt "peer review" --json
./target/debug/unpin profile locks --provider codex --json
./target/debug/unpin profile lock \
  --provider codex \
  --capability skill.example \
  --state hard-disabled \
  --json
./target/debug/unpin profile apply \
  --id review \
  --scope workspace \
  --mode gateway \
  --json
```

Use emitted fingerprint with `--apply --confirm --plan-fingerprint ...` for
persistent policy change. Capability lock status reports the global source,
repository/worktree identity, effective gateway source, active-session impact,
and conservative provider enforcement. Locks activate for new sessions; native
best-effort, read-only, and unsupported paths are never described as strict.
Gateway installation and routing are separate:

```bash
./target/debug/unpin gateway status --scope workspace --json
./target/debug/unpin gateway install --scope workspace --json
./target/debug/unpin gateway on --scope workspace --json
./target/debug/unpin gateway off --scope workspace --json
./target/debug/unpin gateway detach --scope workspace --json
```

Each command above is dry-run unless given reviewed apply flags. Active leases
block off/detach unless explicit force path drains them. Gateway status reports
configured intent separately from live host attachment; status does not infer a
running listener and reports runtime observation as unavailable. Native MCP
configuration references remain explicitly `not-managed`, and live provider
attachment stays blocked until those references and strict masking are safely
wired. Fixture-backed `session
launch` binds one child process to one private lease, Unix-socket gateway, and
immutable exposure revision. Lease resources include every applicable global,
repository, and workspace gateway-mode and policy target, current mutable
native-item transitions, authenticated restorable backups, and adopted views;
global adopted views fence conflicting transitions across worktrees. Gateway,
profile-policy, toggle, and restore apply acquire same lease conflict guard.
All live launches require initialized backup and session authentication. Live
profile-scoped launch fails closed until a
provider adapter proves strict native masking and gateway attachment; native
launch remains available. `session list` is restricted to current repository
and workspace and never reveals bootstrap authority.
Separate worktrees isolate workspace policy and code edits. Separate sessions in
same worktree isolate capability exposure only after provider attachment is
verified; they still share source files.

Exact terminal retries verify current policy, provider, adopted-view, and
restored-target state before returning cached success. Drift returns
`recovery-required`. Catalog adoption returns nonzero for `rolled-back` and
`recovery-required` terminal outcomes.

Inspect individual hooks and provider coverage with:

```bash
./target/debug/unpin hook list --json
./target/debug/unpin hook coverage --json
```

Executable/network hook trust is profile-digest and invocation-fingerprint
bound. Changed handlers require new review. Gateway MCP before/after policy is
fixture-contract verified. Native built-in-tool dispatcher and managed-bridge
activation remain pending live-provider wiring and verification; coverage output
reports that boundary explicitly.

Optional Cursor dashboard cookie storage uses stdin and separate keychain
purpose:

```bash
printf '%s' "$CURSOR_DASHBOARD_COOKIE" \
  | ./target/debug/unpin auth cursor-dashboard store
./target/debug/unpin auth cursor-dashboard status
```

Cookie presence never changes a read-only inventory item by itself. Unpin
still reports current marketplace mutation support per operation.

## Register Unpin MCP

Unpin runs a local stdio MCP server:

```bash
/absolute/path/to/unpin mcp
```

Omit `--project-root` when host launches MCP from active repository. Add an
absolute `--project-root` argument when registration must stay fixed to one repo.
Keep normal host tool approvals enabled. Unpin MCP verifies reviewed plans
but cannot mint human approval: persistent apply requests return structured
handoff for CLI/TUI completion. Host approval remains another safety boundary.

### Codex

User registration:

```bash
codex mcp add unpin -- /absolute/path/to/unpin mcp
codex mcp list
```

Repository registration in trusted `.codex/config.toml`:

```toml
[mcp_servers.unpin]
command = "/absolute/path/to/unpin"
args = ["mcp", "--project-root", "/absolute/path/to/repository"]
```

Restart Codex, then use `/mcp` to inspect server. See
[Codex MCP documentation](https://developers.openai.com/codex/mcp/).

### Claude Code

User registration:

```bash
claude mcp add --scope user unpin -- /absolute/path/to/unpin mcp
claude mcp list
```

Shared repository registration:

```bash
claude mcp add --scope project unpin -- \
  /absolute/path/to/unpin mcp \
  --project-root /absolute/path/to/repository
```

Open Claude Code and use `/mcp` to approve project registration and inspect
status. See [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

### Cursor

Use `$HOME/.cursor/mcp.json` for global registration or `.cursor/mcp.json` for
repository registration:

```json
{
  "mcpServers": {
    "unpin": {
      "command": "/absolute/path/to/unpin",
      "args": [
        "mcp",
        "--project-root",
        "/absolute/path/to/repository"
      ]
    }
  }
}
```

Reload Cursor and inspect Settings > Tools & MCP. See
[Cursor MCP documentation](https://cursor.com/docs/mcp).

### Zed

Add global registration to `$HOME/.config/zed/settings.json`, or repository
registration to `.zed/settings.json`:

```jsonc
{
  "context_servers": {
    "unpin": {
      "command": "/absolute/path/to/unpin",
      "args": [
        "mcp",
        "--project-root",
        "/absolute/path/to/repository"
      ]
    }
  }
}
```

Open Settings > AI > MCP Servers. Active server has green status indicator. See
[Zed MCP documentation](https://zed.dev/docs/ai/mcp).

## MCP safety check

Before requesting an MCP human-action handoff, call inventory summary and verify:

- backup authentication and approval signing are ready before CLI/TUI completion;
- `writesEnabled` is `false` and `humanApproval` is `cli-or-tui-required`;
- selected item is `read-write`;
- plan matches intended provider, kind, layer, and target state.

Apply and restore tools reject stale or incomplete review data and never write
provider state directly. Bulk handoff also requires reviewed plan fingerprint and
maximum item count. MCP entries named `unpin` or `agentscope` cannot disable
themselves through MCP control plane.

Typical MCP sequence:

1. `initialize`, then `notifications/initialized`.
2. `tools/list` and verify Unpin tools are discoverable.
3. `agentscope_get_inventory_summary` and `agentscope_list_items`.
4. `agentscope_plan_toggle_item` with exact provider/kind/layer/id selection.
5. `agentscope_apply_toggle_item` only after reviewing exact fingerprint; follow
   returned human-action handoff in CLI/TUI.
6. `agentscope_list_backups`, then plan restore and follow same signed handoff
   when rollback is needed.

## Reproduce local provider matrix

Runner reads installed provider state, hashes every discovered live source/state
path before and after dry-run planning, mutates only isolated copies of committed
fixtures, and restores every copy byte-for-byte:

```bash
python3 scripts/run_local_provider_matrix.py
```

Runner prints private evidence directory outside checkout, such as
`/tmp/2026-07-17-174208-local-matrix`. It covers:

- installed host versions and aggregate library counts;
- one no-write live plan for every installed writable matrix cell;
- 31 CLI enable/disable/restore cycles;
- 31 interactive TUI cycles through search, stage, confirmation, two applies,
  and backup using a real terminal PTY, followed by CLI restore verification;
- same 31 plan/review/handoff cycles through persistent MCP sessions, including
  initialize, initialized notification, tool discovery, rejected unreviewed
  writes, and exact-fingerprint CLI completion of each human-action handoff;
- cross-provider fan-out assertions for every skill source visible to multiple
  hosts, proving disable hides all views and enable restores all original views;
- authenticated manifest v3 backup and audit-event checks;
- headless TUI, provider doctor, formatter, Clippy, workspace tests, build, CLI
  help, diff, and Python syntax checks.

Open generated `dashboard.html`. Capture these sections into `screenshots/`:

| Section | Filename |
| --- | --- |
| Overview | `overview.png` |
| Installed library | `live-library.png` |
| Coverage matrix | `coverage-matrix.png` |
| Headless TUI | `tui-library.png` |
| Claude transitions | `claude-states.png` |
| Codex transitions | `codex-states.png` |
| Cursor transitions | `cursor-states.png` |
| Pi transitions | `pi-states.png` |
| OpenCode transitions | `opencode-states.png` |
| Zed transitions | `zed-states.png` |
| MCP control plane | `mcp-states.png` |

Inspect every PNG before publishing. Set `screenshot-review.json` to `approved`,
record reviewer and timezone-qualified UTC review time, add each PNG's
`sha256:<digest>` under `checksums`, and change all four assertions to `true`
only after confirming expected section, readable state labels, and absence of
private item names or local home paths. Record checksums after capture and before
review approval. Finalization rejects pending review, missing/invalid or modified
PNG files, screenshots newer than review time, and mismatched screenshot lists.

Finalize after screenshots exist:

```bash
python3 scripts/run_local_provider_matrix.py \
  --artifact-root /tmp/YOUR-RUN-local-matrix \
  --finalize
```

Finalization checks screenshot set, rejects publishable text containing local home
path, verifies tested binary SHA-256 plus Git/workspace-state binding, and writes
`evidence-manifest.json` with SHA-256 checksums. Custom binaries and partial runs
made with either skip flag cannot be finalized or announced as publishable
evidence.

## Share evidence

Safe files to share are listed in `evidence-manifest.json`:

- `report.md`
- `dashboard.html`
- `announcement.md`
- `screenshot-review.json`
- `screenshots/*.png`
- `evidence-manifest.json`

Full live inventory is aggregated in memory and never persisted. Saved live plans
contain only provider/kind/layer, operation types, and path classes. Keep case
directories, backup payloads, and audit logs local. Evidence root and contents use
owner-only permissions under `/tmp`, outside Git tracking; attach manifest-listed
files explicitly instead of committing machine-local output.
