use super::super::*;

pub(crate) fn discover_cursor(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        project_scope_cache,
        shared_skill_views,
        items,
        warnings,
    } = state;
    let global_skill_root = roots.cursor_config.join("skills");
    let live_skill_ids = discover_recursive_skill_dirs(
        &global_skill_root,
        ProviderId::Cursor,
        DiscoveryLayer::Global,
        CURSOR_GLOBAL_SKILL_ID_PREFIX,
        DiscoveryMutability::ReadWrite,
        items,
        warnings,
    )?;
    prepopulate_cursor_repository_scopes(roots, project_scope_cache)?;
    let project_skills = discover_project_skill_dirs(
        &roots.cursor_project,
        Path::new(".cursor/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Project,
            id_prefix: "cursor:project:skill:",
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Repository,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    let mut cursor_global_live_ids = live_skill_ids;
    let mut cursor_global_roots = vec![global_skill_root];
    let mut cursor_project_live_ids = project_skills.live_ids;
    let mut cursor_project_roots = project_skills.skill_roots;
    for (global_root, project_root, relative_skill_root, id_namespace) in [
        (
            roots.shared_global.join(".agents/skills"),
            roots.shared_project.as_path(),
            ".agents/skills",
            CURSOR_COMPAT_AGENTS_SKILL_NAMESPACE,
        ),
        (
            roots.claude_global.join("skills"),
            roots.claude_project.as_path(),
            ".claude/skills",
            CURSOR_COMPAT_CLAUDE_SKILL_NAMESPACE,
        ),
        (
            roots.codex_global.join("skills"),
            roots.codex_project.as_path(),
            ".codex/skills",
            CURSOR_COMPAT_CODEX_SKILL_NAMESPACE,
        ),
    ] {
        let global_id_prefix = format!("{CURSOR_GLOBAL_SKILL_ID_PREFIX}{id_namespace}");
        let global_live_ids = discover_recursive_skill_dirs(
            &global_root,
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            &global_id_prefix,
            DiscoveryMutability::ReadWrite,
            items,
            warnings,
        )?;
        shared_skill_views.push(SkillView::new(
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            global_root.clone(),
            global_id_prefix,
            SkillRootTraversal::Recursive,
        ));
        cursor_global_live_ids.extend(global_live_ids);
        cursor_global_roots.push(global_root);

        let project_id_prefix = format!("{CURSOR_PROJECT_SKILL_ID_PREFIX}{id_namespace}");
        let project_skills = discover_project_skill_dirs(
            project_root,
            Path::new(relative_skill_root),
            SkillDiscoverySpec {
                provider: ProviderId::Cursor,
                layer: DiscoveryLayer::Project,
                id_prefix: &project_id_prefix,
                mutability: DiscoveryMutability::ReadWrite,
                traversal: ProjectSkillTraversal::Repository,
                skill_root_traversal: SkillRootTraversal::Recursive,
            },
            roots.scan_project_scopes,
            project_scope_cache,
            warnings,
            items,
        )?;
        shared_skill_views.extend(project_skills.skill_views.iter().cloned());
        cursor_project_live_ids.extend(project_skills.live_ids);
        for skill_root in project_skills.skill_roots {
            if !cursor_project_roots.contains(&skill_root) {
                cursor_project_roots.push(skill_root);
            }
        }
    }
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Global,
            live_ids: &cursor_global_live_ids,
            allowed_skill_roots: &cursor_global_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Project,
            live_ids: &cursor_project_live_ids,
            allowed_skill_roots: &cursor_project_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    let global_agent_root = roots.cursor_global.join("agents");
    let live_agent_ids = discover_agent_files(
        &global_agent_root,
        ProviderId::Cursor,
        DiscoveryLayer::Global,
        "cursor:global:agent:",
        &[AgentFileKind::Markdown],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Cursor,
        DiscoveryLayer::Global,
        &live_agent_ids,
        std::slice::from_ref(&global_agent_root),
        items,
        warnings,
    )?;
    let project_agent_root = roots.cursor_project.join(".cursor").join("agents");
    let live_agent_ids = discover_agent_files(
        &project_agent_root,
        ProviderId::Cursor,
        DiscoveryLayer::Project,
        "cursor:project:agent:",
        &[AgentFileKind::Markdown],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Cursor,
        DiscoveryLayer::Project,
        &live_agent_ids,
        std::slice::from_ref(&project_agent_root),
        items,
        warnings,
    )?;

    let mut live_cursor_global_mcp_ids = BTreeSet::new();
    let workspace_state =
        load_cursor_workspace_state(&roots.cursor_global, &roots.cursor_project, warnings);
    let cursor_global_mcp_path = roots.cursor_config.join("mcp.json");
    discover_cursor_mcp_file(
        &cursor_global_mcp_path,
        DiscoveryLayer::Global,
        Some(&workspace_state),
        &mut live_cursor_global_mcp_ids,
        items,
        warnings,
    )?;
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Global,
            payload_kind: "json-payload",
            live_ids: &live_cursor_global_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&cursor_global_mcp_path),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    let mut live_cursor_project_mcp_ids = BTreeSet::new();
    let cursor_project_mcp_path = roots.cursor_project.join(".cursor").join("mcp.json");
    discover_cursor_mcp_file(
        &cursor_project_mcp_path,
        DiscoveryLayer::Project,
        None,
        &mut live_cursor_project_mcp_ids,
        items,
        warnings,
    )?;
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Project,
            payload_kind: "json-payload",
            live_ids: &live_cursor_project_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&cursor_project_mcp_path),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    discover_json_hooks_file(
        &roots.cursor_global.join("hooks.json"),
        JsonHooksSpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Global,
            hook_id_prefix: "cursor:global:hook:hooks-json:",
            setting_id: "cursor:global:setting:hooks-json",
            setting_display_name: "hooks.json",
            allow_top_level_events: false,
        },
        items,
        warnings,
    )?;
    discover_setting_files(
        ProviderId::Cursor,
        DiscoveryLayer::Global,
        &[
            (
                roots.cursor_global.join("permissions.json"),
                "cursor:global:setting:permissions-json",
                "permissions.json",
            ),
            (
                roots.cursor_global.join("sandbox.json"),
                "cursor:global:setting:sandbox-json",
                "sandbox.json",
            ),
            (
                roots.cursor_global.join("cli-config.json"),
                "cursor:global:setting:cli-config-json",
                "cli-config.json",
            ),
        ],
        items,
    );
    discover_json_hooks_file(
        &roots.cursor_project.join(".cursor").join("hooks.json"),
        JsonHooksSpec {
            provider: ProviderId::Cursor,
            layer: DiscoveryLayer::Project,
            hook_id_prefix: "cursor:project:hook:hooks-json:",
            setting_id: "cursor:project:setting:hooks-json",
            setting_display_name: ".cursor/hooks.json",
            allow_top_level_events: false,
        },
        items,
        warnings,
    )?;
    discover_setting_files(
        ProviderId::Cursor,
        DiscoveryLayer::Project,
        &[
            (
                roots
                    .cursor_project
                    .join(".cursor")
                    .join("permissions.json"),
                "cursor:project:setting:permissions-json",
                ".cursor/permissions.json",
            ),
            (
                roots.cursor_project.join(".cursor").join("sandbox.json"),
                "cursor:project:setting:sandbox-json",
                ".cursor/sandbox.json",
            ),
            (
                roots.cursor_project.join(".cursor").join("cli.json"),
                "cursor:project:setting:cli-json",
                ".cursor/cli.json",
            ),
        ],
        items,
    );
    let local_plugins_root = roots.cursor_config.join("plugins").join("local");
    let live_plugin_ids = discover_cursor_plugin_manifests(&local_plugins_root, items, warnings)?;
    discover_vaulted_cursor_plugin_items(
        roots.app_state_root.as_deref(),
        &live_plugin_ids,
        &local_plugins_root,
        items,
        warnings,
    )?;
    discover_cursor_marketplace_plugins(
        &roots.cursor_global,
        &roots.cursor_project,
        items,
        warnings,
    );
    Ok(())
}

fn discover_cursor_mcp_file(
    path: &Path,
    layer: DiscoveryLayer,
    workspace_state: Option<&CursorWorkspaceState>,
    live_ids: &mut BTreeSet<String>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(document) =
        read_json_if_exists::<McpDocument>(path, ProviderId::Cursor, Some(layer), warnings)?
    else {
        return Ok(());
    };

    for (server_id, value) in &document.mcp_servers {
        if !value.is_object() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Cursor,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!(
                    "{} mcpServers.{server_id} must be a JSON object",
                    path.display()
                ),
            });
            continue;
        }

        let id = format!("cursor:{}:configured-mcp:{server_id}", layer.as_str());
        if live_ids.contains(&id) {
            continue;
        }

        let workspace_disabled = workspace_state.is_some_and(|workspace_state| {
            cursor_workspace_server_is_disabled(workspace_state, server_id)
        });
        let state_path = match (workspace_state, workspace_disabled) {
            (Some(CursorWorkspaceState::Ok { database_path, .. }), true) => database_path,
            _ => path,
        };
        live_ids.insert(id.clone());
        let mut item = configured_mcp_item(
            ProviderId::Cursor,
            layer,
            id,
            server_id,
            !cursor_mcp_server_is_disabled(value) && !workspace_disabled,
            path,
            state_path,
        );
        item.source_fingerprint = Some(json_value_source_fingerprint(value));
        items.push(item);
    }

    Ok(())
}
