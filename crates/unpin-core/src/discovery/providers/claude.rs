use super::super::*;

pub(crate) fn discover_claude(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        project_scope_cache,
        shared_skill_views,
        items,
        warnings,
    } = state;
    let global_skill_root = roots.claude_global.join("skills");
    let live_skill_ids = discover_direct_child_skill_dirs(
        &global_skill_root,
        ProviderId::Claude,
        DiscoveryLayer::Global,
        "claude:global:skill:",
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    shared_skill_views.push(SkillView::new(
        ProviderId::Claude,
        DiscoveryLayer::Global,
        global_skill_root.clone(),
        "claude:global:skill:",
        SkillRootTraversal::Direct,
    ));
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Claude,
            layer: DiscoveryLayer::Global,
            live_ids: &live_skill_ids,
            allowed_skill_roots: std::slice::from_ref(&global_skill_root),
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;
    let project_skills = discover_project_skill_dirs(
        &roots.claude_project,
        Path::new(".claude/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Claude,
            layer: DiscoveryLayer::Project,
            id_prefix: "claude:project:skill:",
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::AncestorsAndDescendants,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    shared_skill_views.extend(project_skills.skill_views.iter().cloned());
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Claude,
            layer: DiscoveryLayer::Project,
            live_ids: &project_skills.live_ids,
            allowed_skill_roots: &project_skills.skill_roots,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;
    let global_agent_root = roots.claude_global.join("agents");
    let live_agent_ids = discover_agent_files(
        &global_agent_root,
        ProviderId::Claude,
        DiscoveryLayer::Global,
        "claude:global:agent:",
        &[AgentFileKind::Markdown],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Claude,
        DiscoveryLayer::Global,
        &live_agent_ids,
        std::slice::from_ref(&global_agent_root),
        items,
        warnings,
    )?;
    let project_agent_root = roots.claude_project.join(".claude").join("agents");
    let live_agent_ids = discover_agent_files(
        &project_agent_root,
        ProviderId::Claude,
        DiscoveryLayer::Project,
        "claude:project:agent:",
        &[AgentFileKind::Markdown],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Claude,
        DiscoveryLayer::Project,
        &live_agent_ids,
        std::slice::from_ref(&project_agent_root),
        items,
        warnings,
    )?;

    let mut live_claude_global_mcp_ids = BTreeSet::new();
    if let Some(document) = read_json_if_exists::<McpDocument>(
        &roots.claude_user_state,
        ProviderId::Claude,
        Some(DiscoveryLayer::Global),
        warnings,
    )? {
        for (server_id, value) in &document.mcp_servers {
            if !value.is_object() {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::Claude,
                    layer: Some(DiscoveryLayer::Global),
                    code: "json-shape-error".to_string(),
                    message: format!(
                        "{} mcpServers.{server_id} must be a JSON object",
                        roots.claude_user_state.display()
                    ),
                });
                continue;
            }
            let id = format!("claude:global:configured-mcp:{server_id}");
            live_claude_global_mcp_ids.insert(id.clone());
            let mut item = configured_mcp_item(
                ProviderId::Claude,
                DiscoveryLayer::Global,
                id,
                server_id,
                true,
                &roots.claude_user_state,
                &roots.claude_user_state,
            );
            item.source_fingerprint = Some(json_value_source_fingerprint(value));
            items.push(item);
        }
    }
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Claude,
            layer: DiscoveryLayer::Global,
            payload_kind: "json-payload",
            live_ids: &live_claude_global_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&roots.claude_user_state),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;
    discover_claude_local_configured_mcps(roots, items, warnings)?;

    let mcp_path = roots.claude_project.join(".mcp.json");
    let settings_path = roots
        .claude_project
        .join(".claude")
        .join("settings.local.json");
    let project_settings = read_json_if_exists::<ClaudeSettings>(
        &settings_path,
        ProviderId::Claude,
        Some(DiscoveryLayer::Project),
        warnings,
    )?;

    if let Some(document) = read_json_if_exists::<McpDocument>(
        &mcp_path,
        ProviderId::Claude,
        Some(DiscoveryLayer::Project),
        warnings,
    )? {
        for (server_id, value) in &document.mcp_servers {
            let mut item = configured_mcp_item(
                ProviderId::Claude,
                DiscoveryLayer::Project,
                format!("claude:project:configured-mcp:{server_id}"),
                server_id,
                project_settings
                    .as_ref()
                    .is_none_or(|settings| claude_configured_mcp_enabled(settings, server_id)),
                &mcp_path,
                &settings_path,
            );
            item.source_fingerprint = Some(json_value_source_fingerprint(value));
            items.push(item);
        }
    }

    if let Some(settings) = project_settings
        && let Some(enabled) = settings.enable_all_project_mcp_servers
    {
        items.push(configured_mcp_item(
            ProviderId::Claude,
            DiscoveryLayer::Project,
            "claude:project:configured-mcp:all-project-mcp-servers".to_string(),
            "all-project-mcp-servers",
            enabled,
            &mcp_path,
            &settings_path,
        ));
    }

    for source in [
        read_settings_source::<ClaudeSettings>(
            roots.claude_global.join("settings.json"),
            ProviderId::Claude,
            DiscoveryLayer::Global,
            "settings",
            "settings.json",
            warnings,
        )?,
        read_settings_source::<ClaudeSettings>(
            roots.claude_global.join("settings.local.json"),
            ProviderId::Claude,
            DiscoveryLayer::Global,
            "settings-local",
            "settings.local.json",
            warnings,
        )?,
        read_settings_source::<ClaudeSettings>(
            roots.claude_project.join(".claude").join("settings.json"),
            ProviderId::Claude,
            DiscoveryLayer::Project,
            "settings",
            ".claude/settings.json",
            warnings,
        )?,
        read_settings_source::<ClaudeSettings>(
            roots
                .claude_project
                .join(".claude")
                .join("settings.local.json"),
            ProviderId::Claude,
            DiscoveryLayer::Project,
            "settings-local",
            ".claude/settings.local.json",
            warnings,
        )?,
    ]
    .into_iter()
    .flatten()
    {
        items.push(provider_setting_item(
            ProviderId::Claude,
            source.layer,
            format!(
                "claude:{}:setting:{}",
                source.layer.as_str(),
                source.source_label
            ),
            source.display_name,
            &source.path,
        ));
        items.extend(claude_plugin_config_items(&source));
        items.extend(claude_hook_items(&source, warnings));
    }

    Ok(())
}

fn claude_configured_mcp_enabled(settings: &ClaudeSettings, server_id: &str) -> bool {
    if settings.disabled_mcpjson_servers.contains_key(server_id) {
        return false;
    }

    if settings.enabled_mcpjson_servers.contains_key(server_id) {
        return true;
    }

    true
}

fn discover_claude_local_configured_mcps(
    roots: &DiscoveryRoots,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    let requested_project_key = path_string(&roots.claude_project);
    let mut project_key_candidates = vec![requested_project_key.clone()];
    if let Ok(canonical_project) = fs::canonicalize(&roots.claude_project) {
        push_unique_path_string(&mut project_key_candidates, &canonical_project);
    }
    let repository_root = find_repository_root(&roots.claude_project);
    push_unique_path_string(&mut project_key_candidates, &repository_root);
    if let Ok(canonical_repository_root) = fs::canonicalize(&repository_root) {
        push_unique_path_string(&mut project_key_candidates, &canonical_repository_root);
    }
    let mut selected_project_key = requested_project_key.clone();
    let document = read_json_if_exists::<serde_json::Value>(
        &roots.claude_user_state,
        ProviderId::Claude,
        Some(DiscoveryLayer::Project),
        warnings,
    )?;

    if let Some(document) = document
        && let Some(projects_value) = document.get("projects")
    {
        if let Some(projects) = projects_value.as_object() {
            let selected = project_key_candidates
                .iter()
                .find_map(|key| projects.get_key_value(key));

            if let Some((project_key, project_value)) = selected {
                selected_project_key = project_key.clone();
                if let Some(project) = project_value.as_object() {
                    if let Some(servers_value) = project.get("mcpServers") {
                        if let Some(servers) = servers_value.as_object() {
                            let scope_token = claude_local_scope_token(project_key);
                            for (server_id, value) in servers {
                                if !value.is_object() {
                                    warnings.push(DiscoveryWarning {
                                        provider: ProviderId::Claude,
                                        layer: Some(DiscoveryLayer::Project),
                                        code: "json-shape-error".to_string(),
                                        message: format!(
                                            "{} selected project mcpServers.{server_id} must be a JSON object",
                                            roots.claude_user_state.display()
                                        ),
                                    });
                                    continue;
                                }
                                let id = format!(
                                    "{CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX}{scope_token}:{server_id}"
                                );
                                live_ids.insert(id.clone());
                                let mut item = configured_mcp_item(
                                    ProviderId::Claude,
                                    DiscoveryLayer::Project,
                                    id,
                                    server_id,
                                    true,
                                    &roots.claude_user_state,
                                    &roots.claude_user_state,
                                );
                                item.source_fingerprint =
                                    Some(json_value_source_fingerprint(value));
                                items.push(item);
                            }
                        } else {
                            warnings.push(DiscoveryWarning {
                                provider: ProviderId::Claude,
                                layer: Some(DiscoveryLayer::Project),
                                code: "json-shape-error".to_string(),
                                message: format!(
                                    "{} selected project mcpServers must be a JSON object",
                                    roots.claude_user_state.display()
                                ),
                            });
                        }
                    }
                } else {
                    warnings.push(DiscoveryWarning {
                        provider: ProviderId::Claude,
                        layer: Some(DiscoveryLayer::Project),
                        code: "json-shape-error".to_string(),
                        message: format!(
                            "{} selected projects entry must be a JSON object",
                            roots.claude_user_state.display()
                        ),
                    });
                }
            }
        } else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Claude,
                layer: Some(DiscoveryLayer::Project),
                code: "json-shape-error".to_string(),
                message: format!(
                    "{} projects must be a JSON object",
                    roots.claude_user_state.display()
                ),
            });
        }
    }

    let scope_token = claude_local_scope_token(&selected_project_key);
    let allowed_item_id_prefix = format!("{CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX}{scope_token}:");
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Claude,
            layer: DiscoveryLayer::Project,
            payload_kind: "json-payload",
            live_ids: &live_ids,
            allowed_state_paths: std::slice::from_ref(&roots.claude_user_state),
            allowed_item_id_prefix: Some(&allowed_item_id_prefix),
        },
        items,
        warnings,
    )
}

pub(crate) fn claude_local_scope_token(project_key: &str) -> String {
    source_fingerprint(project_key)
        .strip_prefix("sha256:")
        .expect("source fingerprints use sha256")
        .to_string()
}

fn push_unique_path_string(paths: &mut Vec<String>, path: &Path) {
    let path = path_string(path);
    if !paths.contains(&path) {
        paths.push(path);
    }
}
