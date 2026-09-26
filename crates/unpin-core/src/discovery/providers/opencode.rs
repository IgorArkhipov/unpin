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
        ..
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

    let global_config_paths = opencode_global_config_paths(&roots.opencode_global);
    let global_config = discover_opencode_configs(
        &global_config_paths,
        DiscoveryLayer::Global,
        roots,
        items,
        warnings,
    )?;
    discover_vaulted_opencode_plugin_config_items(
        roots.app_state_root.as_deref(),
        DiscoveryLayer::Global,
        &global_config.plugin_ids,
        &global_config_paths,
        items,
        warnings,
    )?;
    let project_config_paths =
        opencode_project_config_paths(&roots.opencode_project, roots.scan_project_scopes);
    let project_config = discover_opencode_configs(
        &project_config_paths,
        DiscoveryLayer::Project,
        roots,
        items,
        warnings,
    )?;
    discover_vaulted_opencode_plugin_config_items(
        roots.app_state_root.as_deref(),
        DiscoveryLayer::Project,
        &project_config.plugin_ids,
        &project_config_paths,
        items,
        warnings,
    )?;

    let project_has_configured_skill_paths = project_config.configured_skill_paths.is_some();
    let effective_skill_paths = project_config
        .configured_skill_paths
        .or(global_config.configured_skill_paths);
    if let Some((paths, config_path)) = effective_skill_paths {
        let layer = if project_has_configured_skill_paths {
            DiscoveryLayer::Project
        } else {
            DiscoveryLayer::Global
        };
        discover_opencode_configured_skill_paths(
            &paths,
            layer,
            roots,
            &config_path,
            items,
            warnings,
        )?;
    }

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

fn opencode_config_paths(root: &Path) -> [PathBuf; 2] {
    [root.join("opencode.json"), root.join("opencode.jsonc")]
}

fn opencode_global_config_paths(root: &Path) -> Vec<PathBuf> {
    opencode_config_paths(root).into_iter().collect()
}

fn opencode_project_config_paths(project_root: &Path, scan_project_scopes: bool) -> Vec<PathBuf> {
    let scopes = if scan_project_scopes {
        let repository_root = find_repository_root(project_root);
        let mut scopes = project_root
            .ancestors()
            .take_while(|ancestor| ancestor.starts_with(&repository_root))
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        scopes.reverse();
        scopes
    } else {
        vec![project_root.to_path_buf()]
    };

    let mut paths = Vec::new();
    for scope in &scopes {
        paths.extend(opencode_config_paths(scope));
    }
    for scope in scopes {
        paths.extend(opencode_config_paths(&scope.join(".opencode")));
    }
    paths
}

#[derive(Debug)]
struct OpenCodeConfigDiscovery {
    plugin_ids: BTreeSet<String>,
    configured_skill_paths: Option<(Vec<String>, PathBuf)>,
}

#[derive(Debug, Clone, Copy)]
struct ParsedOpenCodePluginEntry<'a> {
    source: &'a str,
}

fn parse_opencode_plugin_entry(
    value: &serde_json::Value,
) -> Result<ParsedOpenCodePluginEntry<'_>, &'static str> {
    if let Some(source) = value.as_str() {
        return (!source.is_empty())
            .then_some(ParsedOpenCodePluginEntry { source })
            .ok_or("plugin entries must be non-empty strings");
    }

    let Some(entry) = value.as_array() else {
        return Err("plugin entries must be strings or [source, options] pairs");
    };
    if entry.len() != 2 {
        return Err("plugin option entries must contain [source, options]");
    }
    let Some(source) = entry[0].as_str().filter(|source| !source.is_empty()) else {
        return Err("plugin option entries must start with a non-empty string source");
    };
    if !entry[1].is_object() {
        return Err("plugin option entries must end with an options object");
    }
    Ok(ParsedOpenCodePluginEntry { source })
}

fn parse_opencode_skill_paths(
    value: &serde_json::Value,
    config_name: &str,
    layer: DiscoveryLayer,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Option<Vec<String>> {
    let Some(object) = value.as_object() else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::OpenCode,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{config_name} skills must be an object"),
        });
        return Some(Vec::new());
    };

    let Some(entries) = object.get("paths") else {
        if object.get("urls").is_some() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "unsupported-source".to_string(),
                message: format!("{config_name} skills.urls is not fetched during local discovery"),
            });
        }
        return None;
    };
    let Some(entries) = entries.as_array() else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::OpenCode,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{config_name} skills.paths must be an array"),
        });
        return Some(Vec::new());
    };

    let mut paths = Vec::new();
    for entry in entries {
        if let Some(path) = entry.as_str().filter(|path| !path.is_empty()) {
            paths.push(path.to_string());
        } else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!("{config_name} skills.paths entries must be non-empty strings"),
            });
        }
    }
    Some(paths)
}

fn opencode_config_name(path: &Path) -> &str {
    path.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("opencode.json")
}

fn discover_opencode_configs(
    paths: &[PathBuf],
    layer: DiscoveryLayer,
    _roots: &DiscoveryRoots,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<OpenCodeConfigDiscovery, DiscoveryError> {
    let mut documents = Vec::new();
    for path in paths {
        let document = match read_jsonc_if_exists::<OpenCodeConfig>(
            path,
            ProviderId::OpenCode,
            Some(layer),
            warnings,
        ) {
            Ok(document) => document,
            Err(_) => {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::OpenCode,
                    layer: Some(layer),
                    code: "read-error".to_string(),
                    message: format!("{} could not be read", opencode_config_name(path)),
                });
                continue;
            }
        };
        let Some(document) = document else {
            continue;
        };

        let display_name = opencode_config_name(path);
        let base_id = format!("opencode:{}:setting:{display_name}", layer.as_str());
        let setting_id = if items.iter().any(|item| item.id == base_id) {
            format!(
                "{base_id}:scope/{}",
                source_fingerprint(&path.to_string_lossy())
            )
        } else {
            base_id
        };
        items.push(provider_setting_item(
            ProviderId::OpenCode,
            layer,
            setting_id,
            display_name,
            path,
        ));
        documents.push((path.clone(), document));
    }

    let mcp_id_prefix = match layer {
        DiscoveryLayer::Global => OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX,
        DiscoveryLayer::Project => OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX,
    };
    let mut effective_mcp = BTreeMap::new();
    let mut effective_plugins = BTreeMap::new();
    let mut unsafe_plugin_paths = BTreeSet::new();
    let mut unsafe_plugin_ids = BTreeSet::new();
    let mut configured_skill_paths = None;
    for (path, document) in documents {
        let OpenCodeConfig {
            mcp,
            plugin,
            skills,
        } = document;
        for (server_id, value) in mcp {
            effective_mcp.insert(server_id, (value, path.clone()));
        }
        let mut document_plugin_ids = BTreeSet::new();
        for plugin in plugin {
            let parsed = match parse_opencode_plugin_entry(&plugin) {
                Ok(parsed) => parsed,
                Err(reason) => {
                    unsafe_plugin_paths.insert(path.clone());
                    warnings.push(DiscoveryWarning {
                        provider: ProviderId::OpenCode,
                        layer: Some(layer),
                        code: "invalid-shape".to_string(),
                        message: format!("{} {reason}", opencode_config_name(&path)),
                    });
                    continue;
                }
            };
            if !document_plugin_ids.insert(parsed.source.to_string()) {
                unsafe_plugin_paths.insert(path.clone());
                unsafe_plugin_ids.insert(parsed.source.to_string());
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::OpenCode,
                    layer: Some(layer),
                    code: "duplicate-id".to_string(),
                    message: format!(
                        "{} plugin contains a duplicate reference",
                        opencode_config_name(&path)
                    ),
                });
            }
            if effective_plugins.contains_key(parsed.source) {
                // A duplicate across files has a winning declaration, but the
                // current mutator cannot safely edit that declaration without
                // understanding all config layers.
                unsafe_plugin_ids.insert(parsed.source.to_string());
            }
            effective_plugins.insert(parsed.source.to_string(), (plugin, path.clone()));
        }
        if let Some(skills) = skills
            && let Some(paths) =
                parse_opencode_skill_paths(&skills, opencode_config_name(&path), layer, warnings)
        {
            configured_skill_paths = Some((paths, path));
        }
    }

    for (server_id, (value, path)) in effective_mcp {
        let Some(server) = value.as_object() else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!(
                    "{} mcp.{server_id} must be a JSON object",
                    opencode_config_name(&path)
                ),
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
                    opencode_config_name(&path)
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
            &path,
            &path,
        );
        item.source_fingerprint = Some(json_value_source_fingerprint(&value));
        items.push(item);
    }

    let plugin_id_prefix = format!("opencode:{}:plugin-config:npm:", layer.as_str());
    let mut plugin_ids = BTreeSet::new();
    for (plugin_id, (plugin, path)) in effective_plugins {
        let item_id = format!("{plugin_id_prefix}{plugin_id}");
        if !plugin_ids.insert(item_id.clone()) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "duplicate-id".to_string(),
                message: format!(
                    "{} plugin contains a duplicate reference",
                    opencode_config_name(&path)
                ),
            });
            continue;
        }
        let mut item = plugin_config_item(
            ProviderId::OpenCode,
            layer,
            item_id,
            &plugin_id,
            true,
            &path,
        );
        if unsafe_plugin_paths.contains(&path) || unsafe_plugin_ids.contains(&plugin_id) {
            item.mutability = DiscoveryMutability::ReadOnly;
        }
        item.source_fingerprint = Some(json_value_source_fingerprint(&plugin));
        items.push(item);
    }

    Ok(OpenCodeConfigDiscovery {
        plugin_ids,
        configured_skill_paths,
    })
}

fn resolve_opencode_skill_path(raw: &str, roots: &DiscoveryRoots) -> Option<PathBuf> {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return None;
    }
    if raw == "~" {
        return Some(roots.shared_global.clone());
    }
    if let Some(relative) = raw.strip_prefix("~/") {
        return Some(roots.shared_global.join(relative));
    }
    let path = Path::new(raw);
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        roots.opencode_project.join(path)
    })
}

fn discover_opencode_configured_skill_paths(
    configured_paths: &[String],
    layer: DiscoveryLayer,
    roots: &DiscoveryRoots,
    config_path: &Path,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let mut seen_roots = BTreeSet::new();
    for (index, raw_path) in configured_paths.iter().enumerate() {
        let Some(root) = resolve_opencode_skill_path(raw_path, roots) else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "unsupported-source".to_string(),
                message: format!(
                    "{} skills.paths[{index}] is a remote URL and was not fetched",
                    opencode_config_name(config_path)
                ),
            });
            continue;
        };
        if !seen_roots.insert(root.clone()) {
            continue;
        }
        if !root.is_dir() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "path-not-found".to_string(),
                message: format!(
                    "{} skills.paths[{index}] is not a directory",
                    opencode_config_name(config_path)
                ),
            });
            continue;
        }
        if layer == DiscoveryLayer::Project && !path_within_scope(&root, &roots.opencode_project) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::OpenCode,
                layer: Some(layer),
                code: "scope-outside-project".to_string(),
                message: format!(
                    "{} skills.paths[{index}] is outside the selected project",
                    opencode_config_name(config_path)
                ),
            });
            continue;
        }
        let id_prefix = format!(
            "opencode:{}:skill:@config/{}/",
            layer.as_str(),
            source_fingerprint(&root.to_string_lossy())
        );
        discover_configured_skill_dirs(
            &root,
            SkillItemDiscoverySpec {
                provider: ProviderId::OpenCode,
                layer,
                id_prefix: &id_prefix,
                mutability: DiscoveryMutability::ReadOnly,
                max_fingerprint_bytes: None,
                scan_scope: (layer == DiscoveryLayer::Project)
                    .then_some(roots.opencode_project.as_path()),
            },
            true,
            items,
            warnings,
        )?;
    }
    Ok(())
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
