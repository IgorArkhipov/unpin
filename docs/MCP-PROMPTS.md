# Control agent capabilities through Unpin MCP

These prompts help an MCP-connected agent inspect and control which skills,
configured MCP servers, plugins, agents, and hooks are available. Start with
the [MCP setup guide](MCP.md) if the host is not connected to Unpin yet.

## Understand the control model

Unpin exposes several related controls. Choose the one that matches the desired
outcome:

| Desired outcome | Unpin control | Scope and activation |
| --- | --- | --- |
| Change provider-native enabled state | Single or bounded bulk item toggle | Global or project item; live, reload, or restart as reported by the plan |
| Select a reusable capability allowlist | Profile policy | Global, repository, or workspace; future sessions |
| Override every profile for one provider capability | Capability lock | Global `hard-enabled`, `hard-disabled`, or `clear`; future sessions |
| Use a task-specific setup temporarily | Profile proposal and session launch handoff | One immutable session lease |
| Permit an executable or network hook | Profile membership plus hook trust | Bound to the exact profile digest and handler fingerprint |
| Recover provider state | Authenticated backup restore | Exact reviewed backup and restore plan |

Profile scopes use this precedence:

1. Session
2. Workspace, meaning one physical Git checkout or worktree
3. Repository, shared by every worktree of that repository
4. Global
5. Native provider default

An explicit narrower profile replaces the broader profile; profiles do not
merge implicitly. Global capability locks are applied after profile selection.
Active sessions pin profile, lock, and exposure revisions, so later changes do
not silently alter a running session.

## Guardrails for every prompt

Include these instructions whenever an agent is allowed to prepare changes:

```text
Use only the Unpin MCP server for inventory, planning, and handoff generation.
Do not edit provider configuration directly.

Begin with Unpin inventory and control status. Resolve exact provider, kind,
layer or policy scope, item or capability IDs, enabled state, mutability, and
current revisions before proposing a change.

Never treat `confirm`, host tool approval, or an MCP apply-tool call as
authorization to write provider state. Unpin MCP apply tools only validate the
reviewed fingerprint and return a CLI/TUI human-action handoff.

Show me the complete plan, actionable and blocked items, affected paths or
resources, cross-provider fan-out, activation timing, warnings, and exact plan
fingerprint. Stop for my review before requesting an apply handoff. Never claim
the change was applied until the CLI or TUI completion and subsequent
rediscovery prove it.
```

## Audit the current project setup

Use this before changing anything:

```text
Using only Unpin MCP, audit the effective agent capability setup for this
repository.

1. Call inventory summary and control status.
2. List project skills, configured MCP servers, plugins, agents, and hooks for
   every discovered provider.
3. Report each exact item ID, normalized capability ID when available, provider,
   layer, enabled state, mutability, and whether its physical source is shared
   across providers.
4. Report the effective profile and gateway source at global, repository, and
   workspace scope, plus all provider capability locks.
5. Report hook coverage and trust state separately. Do not describe hooks as
   generic writable toggles.
6. Identify drift, read-only items, unsupported provider combinations, and
   changes that would require reload, restart, or a new session.

Do not plan, request, or apply any change.
```

## Enable or disable one exact item

Replace the placeholders before sending:

```text
Using only Unpin MCP, prepare a change for exactly one item:

- provider: PROVIDER
- kind: skill | mcp | plugin | agent
- layer: global | project
- item name or exact ID: ITEM
- desired state: enabled | disabled

List matching items first. If there is not exactly one match, stop and ask me
to choose. Confirm that the item is writable and show any shared-source
cross-provider impact.

Call the one-item plan tool with the exact provider, kind, layer, item ID, and
explicit targetEnabled value. Show the complete plan and fingerprint, then stop
for review. After I approve the plan, request only the structured CLI/TUI
human-action handoff. Rediscover the item after I complete that handoff.
```

Do not ask an agent to "toggle" without an explicit desired state. The current
state may change between discovery and planning; `targetEnabled` makes intent
unambiguous.

## Converge writable project items to an explicit allowlist

This prompt controls provider-native state. It does not create a reusable
profile:

```text
Using only Unpin MCP, prepare a bounded project-native capability convergence
for PROVIDER.

Desired enabled project item IDs:
- skills: SKILL_IDS
- configured MCP servers: MCP_IDS
- plugins: PLUGIN_IDS
- agents: AGENT_IDS

1. List all project items for only those four kinds and report enabled state,
   mutability, source sharing, and exact IDs.
2. Verify every requested ID exists. Stop if an ID is ambiguous, read-only, or
   belongs to another layer or provider.
3. Compute the exact IDs that must become enabled and the exact IDs that must
   become disabled. Do not use an unbounded provider-wide selector.
4. Prepare separate bounded plans for enable and disable operations using only
   those explicit ID lists. Treat an empty selection as an error unless no
   change is genuinely required.
5. Show matched, actionable, blocked, and already-correct items. Set maxItems
   for each eventual handoff to exactly the reviewed actionable count.
6. Stop for review before requesting either handoff. Never bypass blocked or
   read-only items.
7. After I complete the CLI/TUI handoffs, rediscover all four kinds and compare
   them with this allowlist. Retain the returned backup IDs.
```

Provider boundaries still apply:

- Codex project plugins are unsupported by the current host contract.
- Cursor marketplace plugins are read-only; writable local bundles use guarded
  vault and restore behavior.
- OpenCode npm plugin references are writable, but auto-loaded local plugin
  files are read-only.
- Zed plugins are out of scope because Zed uses standard Agent Skills.
- Pi package-extension filters are supported, but Pi core has no native MCP
  client configuration surface.

## Create or select a reusable project profile

A profile is an immutable allowlist of normalized capability IDs, not provider
inventory item IDs. Project-local profile definitions can be stored as
`.unpin/profiles/PROFILE_ID.json`.

```text
Using only Unpin MCP for Unpin operations, help me establish a reusable
capability profile named PROFILE_ID for this repository.

Desired capabilities:
- DESCRIBE_REQUIRED_SKILLS_MCPS_PLUGINS_AGENTS_AND_HOOKS

1. List the normalized Unpin catalog and resolve the exact capability ID for
   every requested capability. Show provider contribution fan-out and reject
   ambiguous names.
2. Inspect existing profile and policy state. If PROFILE_ID already exists,
   show and validate it before proposing changes.
3. Build a version 1 profile definition containing only the reviewed capability
   IDs. Profiles use replacement semantics, so explicitly report capabilities
   that the new definition would omit.
4. Validate the definition inline with sourceScope `workspace`. Validation must
   report `materialized=false`; do not claim that validation saved anything.
5. Show the proposed `.unpin/profiles/PROFILE_ID.json` file and wait for my
   approval before creating or editing it. This profile definition is ordinary
   project content, so use the host's file-editing capability only for this
   approved file; never edit provider configuration directly. Preserve
   unrelated project files.
6. After the file is approved and written, validate the stored profile by ID.
7. Ask me to choose policy scope:
   - `repository` for every worktree of this Git repository;
   - `workspace` for only this physical checkout;
   - `global` for every repository on this machine.
8. Ask me to choose `native` or `gateway` mode. Report conservative enforcement
   quality and any unsupported native masking or gateway attachment instead of
   promising strict enforcement.
9. Plan the profile policy selection, show its exact fingerprint and
   next-session activation, then stop for review. After approval, request only
   the CLI/TUI human-action handoff.
10. After I complete the handoff, rediscover control status. Do not claim that
    an already running session changed.
```

A minimal profile definition has this shape:

```json
{
  "version": 1,
  "id": "review",
  "displayName": "Review",
  "description": "Capabilities used for review work",
  "members": [
    "skill.review",
    "mcp.review"
  ]
}
```

Use catalog capability IDs returned on the target machine; do not copy the
illustrative IDs above unless they actually exist.

## Choose a profile for one task or session

This prompt does not change persistent policy:

```text
Using only Unpin MCP, recommend an existing profile for this task:

TASK_DESCRIPTION

Provider: PROVIDER

1. Inspect control status and available stored profiles.
2. Use the session-profile proposal tool with my task description and provider.
3. Show the ranked result, profile metadata, and prompt digest. Do not expose or
   store my original prompt beyond the current interaction.
4. Ask me to choose the profile; do not select it automatically.
5. Validate the selected stored profile and report its exact profile,
   definition, catalog, policy, lock, and exposure revisions.
6. Explain whether the provider can enforce the requested exposure. If strict
   masking or gateway attachment is unavailable, stop and report that boundary.
7. Only after I confirm the exact profile and revisions, prepare the
   argv-safe session-launch handoff. Do not accept or invent a child command,
   spawn a process, or claim that a session was launched.
```

## Add or clear a global capability lock

Locks override every selected profile for one provider:

```text
Using only Unpin MCP, prepare a global capability lock change:

- provider: PROVIDER
- capability: CAPABILITY_NAME_OR_ID
- desired lock: hard-enabled | hard-disabled | clear

List the normalized catalog and current locks first. Resolve exactly one
capability ID and show every provider contribution. Explain how this lock would
change global, repository, workspace, and session profile results.

Plan the lock change and report enforcement quality, affected future sessions,
current active-session impact, and exact fingerprint. Stop for review. After I
approve, request only the CLI/TUI human-action handoff, then verify the restored
lock revision through control status.
```

Use locks sparingly. They are machine-wide provider constraints, not
repository-local preferences.

## Review and trust hooks

Hooks are not generic enabled/disabled provider items. Executable and network
hooks require both membership in the selected profile and trust bound to the
exact compiled profile digest and handler invocation fingerprint.

```text
Using only Unpin MCP, inspect hooks for PROVIDER under profile PROFILE_ID.

1. Validate the stored profile and obtain its exact compiled profile digest.
2. List hook coverage and granular hook metadata for that provider and digest.
3. Report native event, normalized event family, matcher, route owner, source
   layer, ownership, failure policy, timeout, profile membership, and current
   trust state. Do not expose executable bodies, secrets, or trust receipts.
4. Separate unsupported built-in host hooks from gateway-routed MCP hooks.
5. Do not call the generic item-toggle tools for hooks.
6. If I ask to trust one handler, require one exact handler ID and confirm that
   it belongs to the compiled profile.
7. Plan hook trust and show the handler fingerprint, invocation fingerprint,
   profile digest, affected session if supplied, and exact plan fingerprint.
   Stop for review.
8. After I approve, request only the CLI human-action handoff. Rediscover the
   stored trust decision afterward and report whether a reload, restart, or new
   session is required.
```

Changing the handler or profile digest invalidates the previous trust decision
and requires review again.

## Restore the previous provider state

```text
Using only Unpin MCP, help me recover the most recent relevant Unpin mutation
for PROVIDER and this repository.

List recent backups and identify candidates by provider, operation, affected
resources, creation time, and restorable authentication status. Do not choose a
backup solely because it is newest.

Ask me to select one backup ID. Validate its restore plan, payload and manifest
authentication, current target state, conflicts, and exact fingerprint. Show
the full plan and stop for review. After I approve, request only the CLI/TUI
human-action handoff. After I complete it, rediscover inventory and report the
restored state.
```

## What completion looks like

An agent has completed an Unpin-assisted change only when it reports:

1. The exact reviewed intent and scope.
2. The plan fingerprint and activation timing.
3. The CLI/TUI handoff returned by MCP.
4. Human completion of that handoff.
5. Post-change inventory or control status proving the result.
6. Backup or recovery evidence when provider state changed.

Anything before step 4 is a reviewed plan, not an applied change.
