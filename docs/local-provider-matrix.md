# Local provider validation matrix

This guide takes an engineer from a source checkout to a safe Unpin inventory,
CLI/TUI validation, MCP host validation, and a reproducible local evidence
bundle. Start with the [onboarding guide](ONBOARDING.md) for architecture,
terminology, and the first fixture-backed workflow. For day-to-day agent
registration, use the dedicated [MCP setup guide](MCP.md).

Unpin supports Claude Code, Codex, Cursor, Pi, OpenCode, and Zed. It inventories current
provider configuration, plans changes without writing by default, and applies
supported toggles with authenticated backup, audit, and restore evidence.

## Support matrix

| Provider | Skills | Plugins | MCP servers |
| --- | --- | --- | --- |
| Claude Code | Global and project | Global and project `enabledPlugins` | Global and project |
| Codex | Global and project | Global only; project plugins unsupported by current host contract | Global and project |
| Cursor | Global, shared, and project | Local global bundles writable; marketplace installs read-only | Global and project |
| Pi | Global, shared, and project | Global and project package extension filters; fixture- and live-host-verified | Unsupported by Pi core; use package extensions |
| OpenCode | Global, shared, and project | Global and project npm config references; auto-loaded local files read-only; fixture- and live-host-verified | Global and project native enabled state; fixture- and live-host-verified |
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

For the first beta, disposable-root validation used Pi 0.81.1 and OpenCode
1.18.4. Each host loaded its native global/project configuration, then Unpin
discovered the host-produced or host-accepted package, plugin, and MCP entries
without warnings and produced no-write plans for every writable cell.

With both host executables on `PATH`, reproduce that isolated check after
building Unpin:

```bash
cargo build -p unpin-cli --locked
python3 scripts/validate_live_provider_hosts.py
```

The script supplies an empty temporary home and project, disables Pi telemetry
and network startup, runs OpenCode in pure config-debug mode, and prints only
versions and aggregate assertions. It never applies a mutation.

## Build

From repository root:

```bash
cargo build -p unpin-cli --locked
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

Live writes and protected session launches require backup authentication.
Reviewed writes use a separate approval-signing key, while leases use a
dedicated session key. Initialize all three purpose-separated keys in the OS
keychain:

```bash
./target/debug/unpin auth backup init
./target/debug/unpin auth backup status
./target/debug/unpin auth approval init
./target/debug/unpin auth approval status
./target/debug/unpin auth session init
./target/debug/unpin auth session status
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

## MCP host validation

User-facing registration instructions, current host configuration examples,
the MCP safety boundary, troubleshooting, and a copy-ready automatic setup
prompt live in the [MCP setup guide](MCP.md).

For provider-matrix validation, register the exact build under test with at
least one supported host and verify:

1. The host launches the absolute Unpin binary path with a pinned absolute
   `--project-root`.
2. MCP initialization and `tools/list` complete successfully.
3. `agentscope_get_inventory_summary` reports the expected repository,
   `writesEnabled=false`, and `humanApproval=cli-or-tui-required`.
4. `agentscope_list_items` can filter project skills and configured MCP
   servers without changing provider files.
5. A one-item plan identifies the intended provider, kind, layer, target state,
   and exact plan fingerprint.
6. An apply request returns a structured CLI/TUI human-action handoff rather
   than mutating provider state.

Current host registration is documented for Codex, Claude Code, Cursor,
OpenCode, and Zed. Pi core has no native MCP client configuration surface.
Keep normal host tool approvals enabled, and retain the self-protection check:
configured MCP entries named `unpin` or `agentscope` cannot disable themselves
through Unpin's MCP control plane.

## Reproduce local provider matrix

Runner reads installed provider state, hashes every discovered live source/state
path before and after dry-run planning, mutates only isolated copies of committed
fixtures, and restores every copy byte-for-byte:

```bash
python3 scripts/run_local_provider_matrix.py
```

Runner prints a private evidence directory outside the checkout. The
pre-release baseline run `2026-07-24-184505-local-matrix` was archived under the
repository's ignored `tmp/2026-07-24-184505-local-matrix` directory. It was
bound to clean workspace commit
`8f267d626b479ae2798a1712ef79537cb2352e31` and recorded:

- 31/31 CLI, 31/31 real-PTY TUI, and 31/31 persistent MCP scenarios;
- 620 passing Rust tests and all eight local quality gates passing;
- 938 live inventory items aggregated without persisting private item names;
- Claude Code 2.1.219, Codex CLI 0.144.6, Cursor 3.12.30, and Zed Preview
  1.13.0 detected locally;
- Pi and OpenCode fixture coverage passing while live host verification remains
  pending because those executables were not installed;
- unchanged live provider state;
- 11 visually approved screenshots and a 21-file checksum manifest.

Release-specific runs repeat the full procedure from the exact clean tag commit
with Pi and OpenCode available on `PATH`. Their manifest-approved evidence is
attached to the GitHub release rather than committed to source control.

Each full run covers:

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
directories, backup payloads, and audit logs local. The runner creates the
evidence root with owner-only permissions under the system temporary directory.
If a finalized run is archived under the repository's ignored `tmp/` directory,
preserve those permissions and attach only manifest-listed files instead of
committing machine-local output.
