# Connect Unpin to an agent with MCP

Unpin can run as a local
[Model Context Protocol](https://modelcontextprotocol.io/) server over stdio.
This lets an agent inspect Unpin's normalized inventory, review capability
state, and prepare exact toggle or restore plans without driving the terminal
UI directly.

## Safety boundary

An MCP-connected agent can:

- inspect providers, skills, configured MCP servers, plugins, and backups;
- check whether write prerequisites are ready;
- prepare one-item or bounded bulk plans;
- return the exact plan fingerprint and affected resources for review.

An MCP-connected agent cannot approve its own persistent write. Apply and
restore tools return a structured human-action handoff. Complete that handoff
through the Unpin CLI or TUI after reviewing the exact plan. Keep the host
agent's normal MCP tool approvals enabled as an additional boundary.

MCP tool IDs currently retain the compatibility prefix `agentscope_`. Their
titles, descriptions, and server identity use Unpin branding.

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
purpose-separated keys once:

```bash
unpin auth backup init
unpin auth approval init
unpin auth session init
```

## Choose a scope

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
codex mcp add unpin -- "$UNPIN_BIN" mcp
codex mcp list
```

For a trusted repository, add a project-scoped `.codex/config.toml` entry:

```toml
[mcp_servers.unpin]
command = "/absolute/path/to/unpin"
args = ["mcp", "--project-root", "/absolute/path/to/repository"]
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
  "$UNPIN_BIN" mcp --project-root "$PROJECT_ROOT"

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

Configured MCP entries named `unpin` or `agentscope` are protected from
disabling themselves through the same MCP control plane.

## Typical MCP workflow

1. The host initializes the server and discovers its tools.
2. Call `agentscope_get_inventory_summary` and confirm the expected project,
   backup-authentication state, and `humanApproval` boundary.
3. Call `agentscope_list_items` with provider, kind, and layer filters.
4. Call `agentscope_plan_toggle_item` for one exact item ID.
5. Review the target state, affected resources, and plan fingerprint.
6. Request the apply tool only to obtain a human-action handoff.
7. Complete the handoff in the CLI or TUI.
8. Rediscover inventory and retain the returned backup ID for recovery.

Bulk plans require an explicit maximum item count. Prefer one-item plans while
learning the workflow.

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
   arguments: `mcp`, `--project-root`, and the absolute repository root.
7. Do not initialize keychain credentials, toggle capabilities, apply plans, or
   modify provider configuration during setup.
8. Reload or restart the host as required, verify that the Unpin MCP tools are
   visible, then use them only to list project skills and configured MCP
   servers. Do not plan or apply a change.
9. Report what changed, how the connection was verified, and how to remove the
   registration.

Remember that Unpin MCP may inspect and plan, but persistent writes require a
human-action handoff completed through the Unpin CLI or TUI.
```
