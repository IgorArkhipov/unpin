use super::super::*;

pub(crate) fn discover_opencode(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        project_scope_cache,
        shared_skill_views,
        items,
        warnings,
    } = state;
    let native_global_root = roots.opencode_global.join("skills");
    let agents_global_root = roots.shared_global.join(".agents").join("skills");
    let claude_global_root = roots.claude_global.join("skills");
    let mut global_live_ids = discover_direct_child_skill_dirs(
        &native_global_root,
        ProviderId::OpenCode,
        DiscoveryLayer::Global,
        OPENCODE_GLOBAL_SKILL_ID_PREFIX,
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    for (root, namespace) in [
        (&agents_global_root, OPENCODE_COMPAT_AGENTS_SKILL_NAMESPACE),
        (&claude_global_root, OPENCODE_COMPAT_CLAUDE_SKILL_NAMESPACE),
    ] {
        let id_prefix = format!("{OPENCODE_GLOBAL_SKILL_ID_PREFIX}{namespace}");
        global_live_ids.extend(discover_direct_child_skill_dirs(
            root,
            ProviderId::OpenCode,
            DiscoveryLayer::Global,
            &id_prefix,
            DiscoveryMutability::ReadWrite,
            items,
        )?);
        shared_skill_views.push(SkillView::new(
            ProviderId::OpenCode,
            DiscoveryLayer::Global,
            root.clone(),
            id_prefix,
            SkillRootTraversal::Direct,
        ));
    }
    let global_skill_roots = [native_global_root, agents_global_root, claude_global_root];
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::OpenCode,
            layer: DiscoveryLayer::Global,
            live_ids: &global_live_ids,
            allowed_skill_roots: &global_skill_roots,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;

    let mut project_live_ids = BTreeSet::new();
    let mut project_skill_roots = Vec::new();
    for (project_root, relative_root, namespace) in [
        (
            roots.opencode_project.as_path(),
            Path::new(".opencode/skills"),
            None,
        ),
        (
            roots.shared_project.as_path(),
            Path::new(".agents/skills"),
            Some(OPENCODE_COMPAT_AGENTS_SKILL_NAMESPACE),
        ),
        (
            roots.claude_project.as_path(),
            Path::new(".claude/skills"),
            Some(OPENCODE_COMPAT_CLAUDE_SKILL_NAMESPACE),
        ),
    ] {
        let id_prefix = namespace.map_or_else(
            || OPENCODE_PROJECT_SKILL_ID_PREFIX.to_string(),
            |namespace| format!("{OPENCODE_PROJECT_SKILL_ID_PREFIX}{namespace}"),
        );
        let discovered = discover_project_skill_dirs(
            project_root,
            relative_root,
            SkillDiscoverySpec {
                provider: ProviderId::OpenCode,
                layer: DiscoveryLayer::Project,
                id_prefix: &id_prefix,
                mutability: DiscoveryMutability::ReadWrite,
                traversal: ProjectSkillTraversal::Ancestors,
                skill_root_traversal: SkillRootTraversal::Direct,
            },
            roots.scan_project_scopes,
            project_scope_cache,
            warnings,
            items,
        )?;
        if namespace.is_some() {
            shared_skill_views.extend(discovered.skill_views.iter().cloned());
        }
        project_live_ids.extend(discovered.live_ids);
        project_skill_roots.extend(discovered.skill_roots);
    }
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::OpenCode,
            layer: DiscoveryLayer::Project,
            live_ids: &project_live_ids,
            allowed_skill_roots: &project_skill_roots,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;

    let global_config_path = preferred_opencode_config_path(&roots.opencode_global);
    let global_plugin_ids =
        discover_opencode_config(&global_config_path, DiscoveryLayer::Global, items, warnings)?;
    discover_vaulted_opencode_plugin_config_items(
        roots.app_state_root.as_deref(),
        DiscoveryLayer::Global,
        &global_plugin_ids,
        std::slice::from_ref(&global_config_path),
        items,
        warnings,
    )?;
    let project_config_path =
        opencode_project_config_path(&roots.opencode_project, roots.scan_project_scopes);
    let project_plugin_ids = discover_opencode_config(
        &project_config_path,
        DiscoveryLayer::Project,
        items,
        warnings,
    )?;
    discover_vaulted_opencode_plugin_config_items(
        roots.app_state_root.as_deref(),
        DiscoveryLayer::Project,
        &project_plugin_ids,
        std::slice::from_ref(&project_config_path),
        items,
        warnings,
    )?;

    discover_opencode_local_plugins(
        &roots.opencode_global.join("plugins"),
        DiscoveryLayer::Global,
        items,
    )?;
    discover_opencode_local_plugins(
        &roots.opencode_project.join(".opencode").join("plugins"),
        DiscoveryLayer::Project,
        items,
    )?;

    Ok(())
}

fn preferred_opencode_config_path(root: &Path) -> PathBuf {
    let jsonc = root.join("opencode.jsonc");
    if jsonc.is_file() {
        jsonc
    } else {
        root.join("opencode.json")
    }
}

fn opencode_project_config_path(project_root: &Path, scan_project_scopes: bool) -> PathBuf {
    if !scan_project_scopes {
        return preferred_opencode_config_path(project_root);
    }

    let repository_root = find_repository_root(project_root);
    project_root
        .ancestors()
        .take_while(|ancestor| ancestor.starts_with(&repository_root))
        .map(preferred_opencode_config_path)
        .find(|path| path.is_file())
        .unwrap_or_else(|| project_root.join("opencode.json"))
}

fn discover_opencode_config(
    path: &Path,
    layer: DiscoveryLayer,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let Some(document) =
        read_jsonc_if_exists::<OpenCodeConfig>(path, ProviderId::OpenCode, Some(layer), warnings)?
    else {
        return Ok(BTreeSet::new());
    };

    let display_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("opencode.json");
    items.push(provider_setting_item(
        ProviderId::OpenCode,
        layer,
        format!("opencode:{}:setting:{display_name}", layer.as_str()),
        display_name,
        path,
    ));

    let mcp_id_prefix = match layer {
        DiscoveryLayer::Global => OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX,
        DiscoveryLayer::Project => OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX,
    };
    for (server_id, value) in document.mcp {
        let Some(server) = value.as_object() else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!("{} mcp.{server_id} must be a JSON object", path.display()),
            });
            continue;
        };
        if server
            .get("enabled")
            .is_some_and(|value| !value.is_boolean())
        {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!(
                    "{} mcp.{server_id}.enabled must be a boolean",
                    path.display()
                ),
            });
            continue;
        }
        let mut item = configured_mcp_item(
            ProviderId::OpenCode,
            layer,
            format!("{mcp_id_prefix}{server_id}"),
            &server_id,
            server
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true),
            path,
            path,
        );
        item.source_fingerprint = Some(json_value_source_fingerprint(&value));
        items.push(item);
    }

    let plugin_id_prefix = format!("opencode:{}:plugin-config:npm:", layer.as_str());
    let mut validated_plugin_ids = BTreeSet::new();
    let plugin_mutability = if document.plugin.iter().all(|plugin| {
        plugin
            .as_str()
            .filter(|plugin_id| !plugin_id.is_empty())
            .is_some_and(|plugin_id| validated_plugin_ids.insert(plugin_id.to_string()))
    }) {
        DiscoveryMutability::ReadWrite
    } else {
        DiscoveryMutability::ReadOnly
    };
    let mut plugin_ids = BTreeSet::new();
    for plugin in document.plugin {
        let Some(plugin_id) = plugin.as_str() else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!("{} plugin entries must be strings", path.display()),
            });
            continue;
        };
        if plugin_id.is_empty() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!(
                    "{} plugin entries must be non-empty strings",
                    path.display()
                ),
            });
            continue;
        }
        let item_id = format!("{plugin_id_prefix}{plugin_id}");
        if !plugin_ids.insert(item_id.clone()) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "duplicate-id".to_string(),
                message: format!(
                    "{} plugin contains duplicate reference {plugin_id}",
                    path.display()
                ),
            });
            continue;
        }
        let mut item =
            plugin_config_item(ProviderId::OpenCode, layer, item_id, plugin_id, true, path);
        item.mutability = plugin_mutability;
        item.source_fingerprint = Some(json_value_source_fingerprint(&plugin));
        items.push(item);
    }

    Ok(plugin_ids)
}

fn discover_opencode_local_plugins(
    root: &Path,
    layer: DiscoveryLayer,
    items: &mut Vec<DiscoveryItem>,
) -> Result<(), DiscoveryError> {
    if !root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if !path.is_file() || !matches!(path.extension().and_then(OsStr::to_str), Some("js" | "ts"))
        {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        items.push(DiscoveryItem {
            provider: ProviderId::OpenCode,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginManifest,
            layer,
            id: format!(
                "opencode:{}:plugin-manifest:local:{file_name}",
                layer.as_str()
            ),
            display_name: file_name.to_string(),
            enabled: true,
            mutability: DiscoveryMutability::ReadOnly,
            source_path: path_string(&path),
            state_path: path_string(&path),
            source_fingerprint: fs::read_to_string(&path)
                .ok()
                .map(|raw| source_fingerprint(&raw)),
            hook: None,
        });
    }
    Ok(())
}
