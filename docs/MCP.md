# Connect Unpin to an agent with MCP

Unpin can run as a local
[Model Context Protocol](https://modelcontextprotocol.io/) server over stdio.
This lets an agent inspect Unpin's normalized inventory, review capability
state, and prepare exact toggle or restore plans without driving the terminal
UI directly.

## Protocol compatibility

Unpin supports both the stateless MCP `2026-07-28` edition and the legacy
initialization-based editions through `2024-11-05`. Modern clients should call
`server/discover`, then include `io.modelcontextprotocol/protocolVersion` set
to `2026-07-28` and an object-valued
`io.modelcontextprotocol/clientCapabilities` in every request's `params._meta`.
Responses include `resultType: "complete"` and server identity in `_meta`.

`tools/list` is deliberately declared `cacheScope: "private"` with `ttlMs: 0`:
the host may retain no freshness window for a tool list whose safety boundary
depends on the current Unpin process and provider scope. Existing hosts may
continue to use `initialize` and `notifications/initialized`; no session ID or
additional mutation permission is introduced by the newer protocol edition.

## Safety boundary

### Routed workflow sessions

A confirmed workflow session receives one immutable maximum envelope and one
active mode. `tools/list`, `unpin_search_skills`, `unpin_load_skill`, projected
upstream calls, and gateway hooks all resolve against the same observed exposure
revision. Out-of-mode schemas and skill bodies are absent rather than merely
denied after entering model context.

The fixed session control allowlist is:

- `unpin_workflow_status`
- `unpin_workflow_modes`
- `unpin_workflow_enter_mode`
- `unpin_workflow_cancel_transition`

These controls can inspect state or request/cancel an in-envelope transition.
They cannot edit workflow definitions, approve launch, expand the confirmed
envelope, end a session, change gateway lifecycle, or dispatch arbitrary Unpin
commands. Agent Plugin packages may contribute normalized skills, projected MCP
tools, and hooks to referenced profiles, but a workflow transition never toggles
the installed package or provider-native registration.

On a host with negotiated list-change support, entering a mode stages the new
revision and closes new-call admission. Notification changes status only. The
same authenticated primary connection must perform a matching `tools/list`
before Unpin promotes that revision and reopens admission; auxiliary, stale,
disconnected, or other-session connections cannot observe it. Calls admitted
under the previous pinned revision may finish.

Fallbacks are explicit:

- `refresh-unconfirmed`: notification sent without a matching re-list; cancel
  restores the last observed exposure.
- `reload-required`: reconnect is required; cancel restores the last observed
  exposure.
- `next-session-only`: nothing is staged into the current connection and its
  observed exposure remains callable; start a new confirmed session or cancel
  the proposal.

The confirmed maximum envelope is the privilege boundary. An out-of-envelope
request returns a local-human approval handoff and cannot be approved through
the session MCP server. Native host capabilities outside Unpin's gateway remain
`native-unmanaged` and are not hidden, toggled, or claimed as strict isolation.

An MCP-connected agent can:

- inspect providers, skills, configured MCP servers, plugins, derived Agent Plugin packages, and backups;
- list and inspect personal or repository inventory groups;
- inspect authenticated workspace-policy binding and orphan classification;
- check whether write prerequisites are ready;
- prepare one-item, bounded bulk, inventory-group, or Agent Plugin package plans;
- return the exact plan fingerprint and affected resources for review.

An MCP-connected agent cannot approve its own persistent write, create or edit
an inventory-group definition, or mint approval. Item, bulk, restore, profile,
policy, gateway, session, and hook apply tools return a structured human-action
handoff. Complete that handoff through the Unpin CLI or terminal TUI after
reviewing the exact plan.

The macOS desktop workbench has its own local-human review path for its bundled
local bridge. That approval never mints, receives, or consumes an MCP challenge
or approval artifact, so it does not complete an agent-originated MCP handoff
or widen this server's mutation authority.

This boundary distinguishes provider writes from internal handoff-state writes.
`unpin_apply_toggle_item`, `unpin_apply_toggle_items`, and
`unpin_plan_profile_provider` are non-destructive but not read-only: they
persist transaction/payload metadata and coordination lock files under the
configured Unpin app-state root so the CLI or TUI can continue the exact
operation. They do not mutate provider configuration.

Inventory groups have one narrow opt-in exception. A persistent server started
with `--enable-approved-group-apply` may apply an exact group operation only
after the CLI or terminal TUI independently verifies its challenge and issues a
short-lived, one-time approval artifact. Default MCP and `mcp --once` never
expose that apply tool. Keep the host agent's normal MCP tool approvals enabled
as an additional boundary.

MCP tool IDs use the `unpin_` prefix. Their titles, descriptions, and server
identity use Unpin branding.

### Agent Plugin package tools

MCP exposes three path-free package tools:

- `unpin_list_agent_plugins` returns derived logical packages within the server connection's provider scope, including `inventoryComplete` so an unreadable installed cache is distinguishable from no packages;
- `unpin_inspect_agent_plugin` returns one package's safe metadata, provider coverage, aggregate state, component dispositions, blockers, and fingerprints;
- `unpin_plan_agent_plugin_toggle` derives a fresh exact-member plan and returns a signed, expiring `human-action-required` handoff for CLI, TUI, or desktop review.

Agent Plugins remain a derived projection over existing provider inventory. MCP cannot install, update, import, delete, or directly apply a package, and it cannot supply internal exact identities or selection-context fingerprints. The plan tool derives those values server-side from fresh discovery and binds explicit provider reach. A provider-scoped MCP connection can select only its pinned provider; use an all-provider connection and `providerReach: "all"` only for deliberate cross-provider review.

Planning may persist sealed handoff metadata under Unpin app state, but it does not modify provider files or create backup payloads. Diagnostics-only packages remain inspectable and reject planning before a durable operation is created. The returned continuation data identifies the CLI and desktop review action. The CLI can adopt the sealed handoff by preserving its operation ID, plan fingerprint, workspace binding, reach, and expiry. Desktop instead starts a fresh local `agentPlugins.plan` review for its current bridge connection before its own approval and apply sequence; it must not represent this as adoption of the MCP operation.

### Workspace-policy maintenance status

`unpin_get_policy_maintenance_status` is read-only. It reports whether the
current or explicitly keyed workspace policy has an authenticated maintenance
record, classifies its physical checkout binding, and returns the exact CLI
handoff for migration, reattachment, discard, or cleanup. It never exposes a
policy-maintenance mutation tool.

Use `candidateCurrent=true` only when intentionally comparing a recorded
workspace target with the MCP process's current checkout. Supply
`repositoryKey` and `workspaceKey` together when inspecting a recorded target.
If backup authentication is unavailable, initialize it with
`unpin auth backup init`, restart the MCP session, and retry.

### Inventory-group MCP modes

Default persistent MCP and one-request `mcp --once` expose these read-only
group tools:

- `unpin_list_inventory_groups`
- `unpin_get_inventory_group`
- `unpin_plan_inventory_group`

The plan is a non-authorizable `preview`: it contains no challenge and creates
no authorizing operation. The one-request mode rejects
`--enable-approved-group-apply`.

For a deliberately privileged persistent connection, start:

```bash
unpin mcp \
  --provider all \
  --project-root "$PROJECT_ROOT" \
  --enable-approved-group-apply
```

Use the narrowest provider scope that contains every member of the intended
group; `all` is needed only for a cross-provider group. This mode adds only
`unpin_apply_inventory_group`. Its initialization capability reports:

```text
mutation=human-handoff-only
conditionalGroupApply=approved-group-apply-v1
conditionalProviderWritesEnabled=true
challengeStoreWrites=false
sessionLeaseWrites=true
approvalArtifactRequired=true
canMintApproval=false
requiresPersistentSession=true
```

The MCP process creates a private authenticated session lease, but it cannot
write the challenge store or approval store on the human's behalf. The CLI or
terminal TUI must approve the exact operation, plan fingerprint, challenge,
session, workspace, definition revision, and resources. Approval is single-use
and expires; any definition, inventory, provider-state, or resource drift
requires a fresh MCP plan and fresh approval.

## Prerequisites

Install Unpin, then resolve stable absolute paths:

```bash
cd /path/to/repository
UNPIN_BIN="$(command -v unpin)"
PROJECT_ROOT="$(git rev-parse --show-toplevel)"

"$UNPIN_BIN" --version
"$UNPIN_BIN" doctor --project-root "$PROJECT_ROOT"
```

Stop if `command -v unpin` returns no path or `doctor` reports an invalid
configuration. Use the absolute executable path in host configuration so the
agent does not depend on a different shell `PATH`.

For read-only MCP use, no Unpin keychain initialization is required. Before
completing persistent handoffs through the CLI or TUI, initialize the
purpose-separated keys once. Approved inventory-group apply also requires all
three keys before the persistent MCP process starts:

```bash
unpin auth backup init
unpin auth approval init
unpin auth session init
```

## Choose a scope

- Set `--provider` to the agent host that owns the connection: `claude`,
  `codex`, `cursor`, `opencode`, or `zed`. The named provider becomes a hard
  boundary for every tool call. Omitted provider fields inherit that boundary,
  and conflicting scalar or list selectors are rejected.
- Use `--provider all` only for a deliberate cross-provider administrative
  connection. `all` is the compatibility default when the flag is omitted.
- Omit `--project-root` when the host always starts Unpin from the active
  repository and the MCP should follow that working directory.
- Add `--project-root /absolute/path/to/repository` to pin one registration to
  one repository.
- Prefer the host's private, current-project scope while evaluating Unpin,
  when that scope is available.
- Before committing a shared registration, replace machine-specific executable
  and repository paths with a team-agreed wrapper or environment convention.

The examples below pin the server to one repository.

## Codex

For a user-level server that follows the active Codex working directory:

```bash
codex mcp add unpin -- "$UNPIN_BIN" mcp --provider codex
codex mcp list
```

For a trusted repository, add a project-scoped `.codex/config.toml` entry:

```toml
[mcp_servers.unpin]
command = "/absolute/path/to/unpin"
args = ["mcp", "--provider", "codex", "--project-root", "/absolute/path/to/repository"]
cwd = "/absolute/path/to/repository"
```

Restart Codex, then use `/mcp` to inspect the connection. The Codex CLI, IDE
extension, and ChatGPT desktop Codex surface share the same Codex MCP
configuration. See the
[official Codex MCP documentation](https://developers.openai.com/codex/mcp/).

## Claude Code

Run this from the repository to create a private registration for the current
project:

```bash
claude mcp add \
  --transport stdio \
  --scope local \
  unpin -- \
  "$UNPIN_BIN" mcp --provider claude --project-root "$PROJECT_ROOT"

claude mcp list
```

Use `--scope project` instead of `--scope local` only when the resulting
`.mcp.json` should be shared with the team. Review machine-specific paths before
committing it. Open Claude Code and use `/mcp` to approve and inspect the
server. See the
[official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## Cursor

Add a project registration to `.cursor/mcp.json`. Use
`$HOME/.cursor/mcp.json` instead when the server should be available to every
Cursor project:

```json
{
  "mcpServers": {
    "unpin": {
      "command": "/absolute/path/to/unpin",
      "args": [
        "mcp",
        "--provider",
        "cursor",
        "--project-root",
        "/absolute/path/to/repository"
      ]
    }
  }
}
```

Reload Cursor and inspect **Settings → Tools & MCP**. Cursor Agent CLI users can
also run `cursor-agent mcp list`. See the
[official Cursor MCP documentation](https://cursor.com/docs/mcp).

## OpenCode

Add a local server to the repository's `opencode.json` or `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "unpin": {
      "type": "local",
      "command": [
        "/absolute/path/to/unpin",
        "mcp",
        "--provider",
        "opencode",
        "--project-root",
        "/absolute/path/to/repository"
      ],
      "enabled": true
    }
  }
}
```

Restart OpenCode, then run:

```bash
opencode mcp list
```

OpenCode exposes the server's tools with the server name as a prefix. See the
[official OpenCode MCP documentation](https://opencode.ai/docs/mcp-servers).

## Zed

Add a project registration to `.zed/settings.json`. For a global registration,
open **Settings → AI → MCP Servers**, choose **Add Local Server**, and put the
same entry in the user settings file Zed opens:

```jsonc
{
  "context_servers": {
    "unpin": {
      "command": "/absolute/path/to/unpin",
      "args": [
        "mcp",
        "--provider",
        "zed",
        "--project-root",
        "/absolute/path/to/repository"
      ]
    }
  }
}
```

Review and trust the worktree before allowing a project MCP server to run. In
**Settings → AI → MCP Servers**, an active server has a green status indicator.
See the
[official Zed MCP documentation](https://zed.dev/docs/ai/mcp).

## Pi

Pi core does not provide a native MCP client configuration surface. Unpin can
still inventory Pi skills and package-extension filters. If a Pi package adds
an MCP client, configure Unpin through that package's documented interface;
there is no generic Pi registration snippet that Unpin can safely recommend.

## Verify from the agent

After restarting or reloading the host, use this read-only request:

> Use the Unpin MCP server to list project-scoped skills and configured MCP
> servers for this repository. Report provider, layer, item ID, enabled state,
> and mutability. Do not plan or apply changes.

If the agent cannot see Unpin:

1. Run the host's MCP list/status command or UI.
2. Confirm the configured command is an absolute executable path.
3. Run that exact command manually with `--help`.
4. Confirm `--project-root` points at the intended Git repository.
5. Restart or reload the host after changing its configuration.

Configured MCP entries named `unpin` are protected from disabling themselves
through the same MCP control plane.

## Typical MCP workflow

1. Modern hosts call `server/discover`; legacy hosts initialize the server;
   both then discover its tools.
2. Call `unpin_get_inventory_summary` and confirm the expected project,
   `providerScope`, backup-authentication state, and `humanApproval` boundary.
3. Call `unpin_list_items` with provider, kind, and layer filters.
4. Call `unpin_plan_toggle_item` for one exact item ID.
5. Review the target state, affected resources, and plan fingerprint.
6. Request the apply tool only to obtain a human-action handoff.
7. Complete the handoff in the CLI or TUI.
8. Rediscover inventory and retain the returned backup ID for recovery.

Bulk plans require an explicit maximum item count. Prefer one-item plans while
learning the workflow.

## Reach-aware plans and handoffs (schema v2)

Reach is the mutation authority for a reviewed operation. It is not a list or
discovery filter, and it is not the MCP connection boundary. The server's
`--provider` scope remains a hard boundary: a plan may narrow that boundary,
but a reach request can never widen it. A visibility filter therefore never
grants write authority by itself.

Every item, bulk, group, and named-profile operation follows the same
plan-first sequence:

1. Discover the current inventory and control status. Resolve exact provider,
   layer, kind, item or capability IDs, mutability, and revisions.
2. Choose the operation reach explicitly: `All providers`, or `Selected
   provider` with the provider that owns the mutation. For an exact item, the
   item provider may establish `exact-individual-target` provenance. Other
   selected-provider plans must report why authority was established, such as
   `explicit-input`, `tui-control`, or `pinned-mcp-boundary`.
3. Call the family-specific plan tool. Do not infer reach from a list filter,
   a connected provider, or the providers that happen to appear in a result.
4. Review the complete plan before requesting an apply handoff. The review
   must include `providerReach`, selected-provider provenance (when present),
   every `providerCoverage` entry, included and excluded providers, exclusion
   reasons, target state, activation/lifecycle, blocked items, and the exact
   plan fingerprint. Group and profile plans must also show their member or
   provider target classifications.
5. Preserve the exact `operationId` and `planFingerprint` together. Applying
   with either value changed, omitted, or copied from another plan is invalid.

Bulk selectors must contain a non-provider criterion (for example an explicit
ID, kind, category, layer, or enabled-state filter). A selector that resolves
the whole provider inventory requires an explicit whole-inventory
acknowledgement (`acknowledgeWholeInventory=true`); an empty result is only
valid when the plan also carries an intentional empty-selection
acknowledgement. This prevents a provider filter or a broad connection from
silently becoming a whole-inventory write.

### MCP-to-CLI/TUI handoff

MCP plan and apply tools are review and transport surfaces; they do not mint
human approval. After the plan is reviewed, request the structured handoff and
complete it through the CLI or TUI with the same operation ID, fingerprint,
reach, provider authority, and resolved roots. For bulk CLI handoff, use the
exact operation and fingerprint returned by the MCP plan; do not reconstruct a
new selector from a changed visible filter. Named profile operations use the
provider-operation controller, while generic profile policy and capability
lock contracts retain their existing policy semantics.

Approval and transfer records are short-lived and audience-bound. Their
expiry, session, workspace/repository context, root binding, and selected
provider authority are part of the reviewed scope. A transfer may be consumed
once; a duplicate request can return the authenticated terminal result but
must never replay provider writes. Restarting the host or CLI does not extend
expiry or authorize a different operation.

### Tamper, drift, and restart behavior

The CLI/TUI and MCP implementation reject a handoff when any of these change:

- operation ID, plan fingerprint, reach, provenance, provider coverage, or
  acknowledgement;
- connection/session/workspace context, trusted roots, authority tag, or
  approval/transfer audience and expiry;
- provider state, inventory identities, source fingerprints, group revision,
  profile/catalog revision, or any other pre-state fingerprint reviewed by the
  plan.

On rejection, stop and request fresh discovery and a fresh plan. Never retry a
stale handoff merely because the visible item still has the same name. After a
restart, poll operation status by the exact operation ID until the durable
record is terminal, then rediscover the affected providers. A terminal result
is safe to read again; it is not permission to run a second write.

Lifecycle is explicit and must remain distinct in machine-readable output:

| Lifecycle | Meaning | CLI exit |
| --- | --- | ---: |
| `applied` / `no-op` | All reviewed targets completed or already matched. | `0` |
| `partial` | Some targets completed and others did not; preserve backups and evidence. | `2` |
| `blocked` / `no-targets-in-provider-reach` | No provider write was authorized or no target was in the selected reach. | `3` |
| `recovery-required` | A write or rollback needs manual repair or authenticated restore. | `4` |

Do not collapse `partial`, `blocked`, no-targets, and
`recovery-required` into a generic failure. For partial or recovery-required
results, stop automatic retries, retain operation and backup IDs, and follow
the reported repair/restore path before starting a new plan.

Reach-aware projections use schema-v2 (schema version 2) and add reach,
provenance, coverage, acknowledgement, lifecycle, and durable handoff fields
only to the operation families that support them. This is deliberately scoped:
unrelated schema-v1 inventory, list, discovery, restore, policy, gateway,
session, and hook contracts remain valid and must not be made to require
schema-v2 fields.
Clients should ignore additive v2 fields when consuming an older family and
must not rename or reinterpret existing v1 fields.

For copy-ready requests covering one-item changes, bounded project allowlists,
inventory groups, reusable profiles, session-specific profiles, capability
locks, hook trust, and restore, use the
[MCP capability-control prompt library](MCP-PROMPTS.md).

## Inventory-group workflow

Groups are explicit collections of full provider inventory identities. They
operate on provider-native enabled state. Profiles instead contain normalized
capability IDs and select policy or exposure for future sessions. Creating a
group does not create a profile, and selecting a profile does not toggle a
group.

Create, edit, rename, delete, inspect history, or restore a definition through
`unpin group` or the TUI. MCP exposes no definition-write tool. Personal and
repository scopes may contain the same name, so use a qualified reference such
as `personal:brainstorming` or `repository:brainstorming` when a collision is
possible.

Group inspection reports:

- `On`, `Off`, or `Mixed` aggregate state;
- every explicit member and provider covered by the definition;
- unresolved identities, individually blocked members, and context mismatch;
- connected resource cohorts and shared-source fan-out;
- current definition revision.

In default MCP mode, list or get the group, then call
`unpin_plan_inventory_group` with its qualified name, an explicit
`targetEnabled`, and a bounded `maxMembers`. The result is read-only preview
evidence and cannot be approved. An unqualified name collision returns
`status: ambiguous` with a stable error code and safe personal/repository
qualified candidates.

In approved persistent mode:

1. Call the same plan tool. An actionable result contains the exact operation
   ID, fingerprint, and opaque challenge.
2. Review every member outcome, connected cohort, affected resource, provider,
   activation requirement, and blocked item.
3. From a separate controlling terminal, run:

   ```bash
   unpin group approve \
     --project-root "$PROJECT_ROOT" \
     OPAQUE_CHALLENGE \
     --json
   ```

   For large challenges, avoid process argument limits by writing the opaque
   value to a file and passing `--challenge-file PATH`. Use
   `--challenge-file -` to read it from stdin.

4. Type the displayed approval phrase only after matching the complete plan.
   The CLI returns an opaque `approvalArtifact`; it does not expose signing
   material. In the TUI, the issued handoff remains visible without applying
   provider state; press `X` to export the exact operation, fingerprint,
   challenge, artifact, and expiry as private atomic JSON under the Unpin state
   root.
5. Supply the exact operation ID, plan fingerprint, original challenge, and
   approval artifact to `unpin_apply_inventory_group`. The first accepted call
   consumes write authority. Repeating that exact fully bound call returns only
   the current authenticated operation result and never replays provider
   writes, which makes a lost MCP response recoverable.
6. Inspect `unpin group operation-show OPERATION_ID --json`, rediscover the
   group, and retain every backup ID.

Operation inspection includes authenticated `cohortBackupIndexes`. Each
`coverage` entry maps one original-state rollback backup to the exact
`resourceIds` and group `memberIdentities` it covers; intermediate child
backups are not presented as cohort rollback points. `evidenceAvailable` is
false whenever a referenced authenticated backup manifest can no longer be
verified; in that case the public operation lifecycle is overlaid as
`recovery-required` even though the immutable terminal record is retained.

Never use a stale challenge or artifact for a new operation, changed plan, or
different session. A blocked plan writes nothing.
Failure before provider writes is terminal and requires a fresh plan. If an
operation records partial provider or rollback evidence, stop automatic
retries, preserve its operation and backup records, repair or restore as
reported, and then start from fresh discovery.

## Prompt an agent to configure Unpin

Once `unpin` is installed, paste the following prompt into Codex, Claude Code,
Cursor, OpenCode, Zed, or another local agent that can edit its MCP
configuration:

```text
Set up the installed Unpin CLI as a local stdio MCP server for this Git
repository.

Requirements:
1. Work from the repository root. Resolve it with
   `git rev-parse --show-toplevel`.
2. Locate Unpin with `command -v unpin`, use its absolute path, and verify
   `unpin --version` and `unpin doctor --project-root <repo>`. Stop and report
   the problem if either check fails.
3. Detect which agent host you are running in. If the host or desired scope is
   ambiguous, ask me before editing configuration.
4. Prefer a private registration scoped to this repository. Ask before adding
   a machine-wide registration or committing a team-shared configuration.
5. Preserve all unrelated configuration. Show the exact file and proposed diff
   before writing it. Back up the file before changing it.
6. Configure a server named `unpin` with the absolute command path and these
   arguments: `mcp`, `--provider`, the detected host provider ID,
   `--project-root`, and the absolute repository root. Use `claude`, `codex`,
   `cursor`, `opencode`, or `zed`; never choose `all` unless I explicitly ask
   for a cross-provider administrative connection.
7. Do not initialize keychain credentials, toggle capabilities, apply plans, or
   modify provider configuration during setup.
8. Reload or restart the host as required, verify that the Unpin MCP tools are
   visible, confirm inventory reports the detected `providerScope`, then use
   them only to list project skills and configured MCP servers. Do not plan or
   apply a change.
9. Report what changed, how the connection was verified, and how to remove the
   registration.

Remember that default Unpin MCP may inspect and plan, but persistent writes
require a human-action handoff completed through the Unpin CLI or TUI. Do not
enable approved group apply during initial setup.
```

### Policy-maintenance status

`policy_maintenance_status` leaves `candidateCurrent` disabled by default, so
an MCP query reports the authenticated target without implicitly comparing it
to the current checkout. Set `candidateCurrent: true` when that comparison is
intended. The interactive TUI always performs this comparison for its active
workspace; the CLI exposes the same choice as `--candidate-current`.
