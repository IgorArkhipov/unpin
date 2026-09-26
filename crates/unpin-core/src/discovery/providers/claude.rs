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
        agent_plugin_metadata,
        agent_plugin_item_keys,
    } = state;
    let settings_sources = [
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
    .collect::<Vec<_>>();
    let disable_all_hooks = settings_sources
        .iter()
        .rev()
        .find_map(|source| source.document.disable_all_hooks)
        .unwrap_or(false);

    let global_skill_root = roots.claude_global.join("skills");
    let live_skill_ids = discover_direct_child_skill_dirs(
        &global_skill_root,
        ProviderId::Claude,
        DiscoveryLayer::Global,
        "claude:global:skill:",
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    let global_plugin_roots = discover_claude_skill_directory_plugins(
        &global_skill_root,
        "claude:global:skill:",
        DiscoveryLayer::Global,
        disable_all_hooks,
        items,
        warnings,
    )?;
    apply_claude_skill_overrides(
        items,
        DiscoveryLayer::Global,
        &settings_sources,
        &global_plugin_roots,
    );
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
    let mut project_plugin_roots = BTreeSet::new();
    for view in &project_skills.skill_views {
        project_plugin_roots.extend(discover_claude_skill_directory_plugins(
            &view.root,
            &view.id_prefix,
            DiscoveryLayer::Project,
            disable_all_hooks,
            items,
            warnings,
        )?);
    }
    apply_claude_skill_overrides(
        items,
        DiscoveryLayer::Project,
        &settings_sources,
        &project_plugin_roots,
    );
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
    let project_settings = settings_sources
        .iter()
        .rev()
        .find(|source| {
            source.layer == DiscoveryLayer::Project && source.source_label == "settings-local"
        })
        .map(|source| &source.document);

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

    for source in &settings_sources {
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
        items.extend(claude_plugin_config_items(source));
        items.extend(claude_hook_items(source, disable_all_hooks, warnings));
    }

    let activations = crate::agent_plugins::activation_candidates(ProviderId::Claude, items);
    crate::agent_plugins::discover_cached_agent_plugins(
        ProviderId::Claude,
        &roots.claude_global.join("plugins").join("cache"),
        &activations,
        agent_plugin_metadata,
        agent_plugin_item_keys,
        warnings,
    )?;

    Ok(())
}

fn apply_claude_skill_overrides(
    items: &mut [DiscoveryItem],
    layer: DiscoveryLayer,
    settings_sources: &[SettingsSource<ClaudeSettings>],
    plugin_roots: &BTreeSet<PathBuf>,
) {
    let mut overrides = BTreeMap::new();
    for source in settings_sources
        .iter()
        .filter(|source| source.layer <= layer)
    {
        overrides.extend(
            source
                .document
                .skill_overrides
                .iter()
                .map(|(name, state)| (name.as_str(), state.as_str())),
        );
    }

    for item in items.iter_mut().filter(|item| {
        item.provider == ProviderId::Claude
            && item.layer == layer
            && item.category == DiscoveryCategory::Skill
            && !plugin_roots.contains(Path::new(&item.state_path))
    }) {
        let Some(state) = overrides.get(item.display_name.as_str()) else {
            continue;
        };
        match *state {
            "on" => item.enabled = true,
            "off" => {
                item.enabled = false;
                item.mutability = DiscoveryMutability::ReadOnly;
            }
            "name-only" | "user-invocable-only" => {
                item.enabled = true;
                item.mutability = DiscoveryMutability::ReadOnly;
            }
            _ => {}
        }
    }
}

fn discover_claude_skill_directory_plugins(
    skill_root: &Path,
    skill_id_prefix: &str,
    layer: DiscoveryLayer,
    disable_all_hooks: bool,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<PathBuf>, DiscoveryError> {
    let mut plugin_roots = BTreeSet::new();
    if !skill_root.exists() {
        return Ok(plugin_roots);
    }

    let mut entries = Vec::new();
    let mut skipped_entries = 0;
    for entry in fs::read_dir(skill_root)? {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) if recoverable_project_scope_scan_error(&error) => skipped_entries += 1,
            Err(error) => return Err(error.into()),
        }
    }
    entries.sort_by_key(|entry| entry.file_name());
    let base_skill_prefix = format!("claude:{}:skill:", layer.as_str());
    let scope_suffix = skill_id_prefix
        .strip_prefix(&base_skill_prefix)
        .unwrap_or_default();
    let plugin_id_prefix = format!(
        "claude:{}:plugin-manifest:skills-dir:{}",
        layer.as_str(),
        scope_suffix
    );

    for entry in entries {
        let skill_dir = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if recoverable_project_scope_scan_error(&error) => {
                skipped_entries += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let is_skill_dir = if file_type.is_dir() {
            true
        } else if file_type.is_symlink() {
            fs::metadata(&skill_dir)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(false)
        } else {
            false
        };
        if !is_skill_dir || !skill_dir.join("SKILL.md").is_file() {
            continue;
        }

        let plugin_dir = skill_dir.join(".claude-plugin");
        let plugin_dir_metadata = match fs::symlink_metadata(&plugin_dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                push_claude_plugin_warning(
                    warnings,
                    layer,
                    &plugin_dir,
                    format!("plugin directory could not be read: {error}"),
                );
                continue;
            }
        };
        if plugin_dir_metadata.file_type().is_symlink() || !plugin_dir_metadata.is_dir() {
            push_claude_plugin_warning(
                warnings,
                layer,
                &plugin_dir,
                "plugin directory must be a regular directory",
            );
            continue;
        }

        let manifest_path = plugin_dir.join("plugin.json");
        let manifest_metadata = match fs::symlink_metadata(&manifest_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                push_claude_plugin_warning(
                    warnings,
                    layer,
                    &manifest_path,
                    format!("plugin manifest could not be read: {error}"),
                );
                continue;
            }
        };
        if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
            push_claude_plugin_warning(
                warnings,
                layer,
                &manifest_path,
                "plugin.json must be a regular file",
            );
            continue;
        }

        let raw = match fs::read_to_string(&manifest_path) {
            Ok(raw) => raw,
            Err(error) => {
                push_claude_plugin_warning(
                    warnings,
                    layer,
                    &manifest_path,
                    format!("plugin manifest could not be read: {error}"),
                );
                continue;
            }
        };
        let value = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => value,
            Err(_) => {
                push_claude_plugin_warning(
                    warnings,
                    layer,
                    &manifest_path,
                    "plugin manifest is not valid JSON",
                );
                continue;
            }
        };
        let Some(name) = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.trim().is_empty())
        else {
            push_claude_plugin_warning(
                warnings,
                layer,
                &manifest_path,
                "plugin manifest must contain a non-empty name",
            );
            continue;
        };

        let relative_id = skill_dir.strip_prefix(skill_root)?;
        let plugin_id = format!("{}{}", plugin_id_prefix, skill_id_path(relative_id));
        items.push(DiscoveryItem {
            provider: ProviderId::Claude,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginManifest,
            layer,
            id: plugin_id.clone(),
            display_name: format!("{name}@skills-dir"),
            enabled: true,
            mutability: DiscoveryMutability::ReadOnly,
            source_path: path_string(&manifest_path),
            state_path: path_string(&skill_dir),
            source_fingerprint: Some(source_fingerprint(&raw)),
            hook: None,
        });
        plugin_roots.insert(skill_dir.clone());
        for item in items.iter_mut().filter(|item| {
            item.provider == ProviderId::Claude
                && item.layer == layer
                && item.category == DiscoveryCategory::Skill
                && item.state_path == path_string(&skill_dir)
        }) {
            // A skill-directory plugin is an auto-loaded unit. Mutating its
            // child skill would vault the directory and make the plugin row
            // disappear on the next discovery pass.
            item.mutability = DiscoveryMutability::ReadOnly;
        }
        let mut hook_target = ClaudePluginHookTarget {
            layer,
            disable_all_hooks,
            items: &mut *items,
            warnings: &mut *warnings,
        };
        discover_claude_plugin_hooks(
            &skill_dir,
            &manifest_path,
            &plugin_id,
            &value,
            &mut hook_target,
        );
    }

    if skipped_entries > 0 {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Claude,
            layer: Some(layer),
            code: "scope-scan-incomplete".to_string(),
            message: format!(
                "Claude {} plugin skill scan skipped {skipped_entries} unreadable or vanished entries",
                layer.as_str()
            ),
        });
    }
    Ok(plugin_roots)
}

struct ClaudePluginHookTarget<'a> {
    layer: DiscoveryLayer,
    disable_all_hooks: bool,
    items: &'a mut Vec<DiscoveryItem>,
    warnings: &'a mut Vec<DiscoveryWarning>,
}

fn discover_claude_plugin_hooks(
    plugin_root: &Path,
    manifest_path: &Path,
    plugin_id: &str,
    manifest: &serde_json::Value,
    target: &mut ClaudePluginHookTarget<'_>,
) {
    let default_hook_suffix = if manifest.get("hooks").is_some() {
        "default:"
    } else {
        ""
    };
    match claude_plugin_relative_path(plugin_root, "./hooks/hooks.json") {
        Ok(default_hooks_path) => append_claude_plugin_hook_file(
            &default_hooks_path,
            &format!("{plugin_id}:hook:{default_hook_suffix}"),
            target.layer,
            target.disable_all_hooks,
            false,
            target.items,
            target.warnings,
        ),
        Err(reason) => push_claude_plugin_warning(
            target.warnings,
            target.layer,
            &plugin_root.join("hooks/hooks.json"),
            reason,
        ),
    }

    let Some(declared_hooks) = manifest.get("hooks") else {
        return;
    };

    match declared_hooks {
        serde_json::Value::Array(entries) => {
            for (index, entry) in entries.iter().enumerate() {
                append_claude_plugin_hook_component(
                    plugin_root,
                    manifest_path,
                    &format!("{plugin_id}:hook:manifest:{index}:"),
                    entry,
                    target,
                );
            }
        }
        serde_json::Value::Object(_) => append_claude_plugin_hook_component(
            plugin_root,
            manifest_path,
            &format!("{plugin_id}:hook:"),
            declared_hooks,
            target,
        ),
        entry => append_claude_plugin_hook_component(
            plugin_root,
            manifest_path,
            &format!("{plugin_id}:hook:manifest:"),
            entry,
            target,
        ),
    }
}

fn append_claude_plugin_hook_component(
    plugin_root: &Path,
    manifest_path: &Path,
    hook_id_prefix: &str,
    component: &serde_json::Value,
    target: &mut ClaudePluginHookTarget<'_>,
) {
    match component {
        serde_json::Value::Object(_) => {
            let hook_document = serde_json::json!({ "hooks": component });
            append_claude_plugin_hook_document(
                &hook_document,
                manifest_path,
                hook_id_prefix,
                target.layer,
                target.disable_all_hooks,
                target.items,
                target.warnings,
            );
        }
        serde_json::Value::String(path) => {
            let path = match claude_plugin_relative_path(plugin_root, path) {
                Ok(path) => path,
                Err(reason) => {
                    push_claude_plugin_warning(
                        target.warnings,
                        target.layer,
                        manifest_path,
                        reason,
                    );
                    return;
                }
            };
            append_claude_plugin_hook_file(
                &path,
                hook_id_prefix,
                target.layer,
                target.disable_all_hooks,
                true,
                target.items,
                target.warnings,
            );
        }
        _ => push_claude_plugin_warning(
            target.warnings,
            target.layer,
            manifest_path,
            "plugin hooks must be an object, relative JSON path, or array of those",
        ),
    }
}

fn append_claude_plugin_hook_file(
    path: &Path,
    hook_id_prefix: &str,
    layer: DiscoveryLayer,
    disable_all_hooks: bool,
    warn_if_missing: bool,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !warn_if_missing => return,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            push_claude_plugin_warning(warnings, layer, path, "bundled hooks file was not found");
            return;
        }
        Err(_) => {
            push_claude_plugin_warning(
                warnings,
                layer,
                path,
                "bundled hooks file could not be inspected",
            );
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        push_claude_plugin_warning(
            warnings,
            layer,
            path,
            "bundled hooks path must be a regular file",
        );
        return;
    }
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => {
            push_claude_plugin_warning(
                warnings,
                layer,
                path,
                "bundled hooks file could not be read",
            );
            return;
        }
    };
    let document = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(document) => document,
        Err(_) => {
            push_claude_plugin_warning(
                warnings,
                layer,
                path,
                "bundled hooks file is not valid JSON",
            );
            return;
        }
    };
    append_claude_plugin_hook_document(
        &document,
        path,
        hook_id_prefix,
        layer,
        disable_all_hooks,
        items,
        warnings,
    );
}

fn append_claude_plugin_hook_document(
    document: &serde_json::Value,
    source_path: &Path,
    hook_id_prefix: &str,
    layer: DiscoveryLayer,
    disable_all_hooks: bool,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) {
    let mut hook_items = parsed_hook_items(
        ProviderId::Claude,
        layer,
        hook_id_prefix,
        document,
        false,
        source_path,
        warnings,
    );
    if disable_all_hooks {
        for item in &mut hook_items {
            item.enabled = false;
        }
    }
    items.extend(hook_items);
}

fn claude_plugin_relative_path(
    plugin_root: &Path,
    raw_path: &str,
) -> Result<PathBuf, &'static str> {
    let path = Path::new(raw_path);
    if path.is_absolute() {
        return Err("plugin hooks path must stay inside the plugin directory");
    }
    if !raw_path.starts_with("./") {
        return Err("plugin hooks path must start with ./");
    }

    let mut resolved = plugin_root.to_path_buf();
    let mut has_component = false;
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(component) => {
                has_component = true;
                resolved.push(component);
                if fs::symlink_metadata(&resolved)
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    return Err("plugin hooks path cannot traverse a symlink");
                }
            }
            _ => return Err("plugin hooks path must stay inside the plugin directory"),
        }
    }
    if !has_component {
        return Err("plugin hooks path must name a JSON file");
    }
    Ok(resolved)
}

fn push_claude_plugin_warning(
    warnings: &mut Vec<DiscoveryWarning>,
    layer: DiscoveryLayer,
    path: &Path,
    reason: impl AsRef<str>,
) {
    warnings.push(DiscoveryWarning {
        provider: ProviderId::Claude,
        layer: Some(layer),
        code: "agent-plugin-invalid".to_string(),
        message: format!(
            "{}: {}",
            path.file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("plugin file"),
            reason.as_ref()
        ),
    });
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
