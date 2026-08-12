use super::super::*;

pub(crate) fn discover_codex(
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
    let config_path = roots.codex_global.join("config.toml");
    let skill_config_states = if let Some(raw) = read_optional_string(&config_path)? {
        match parse_codex_skill_config_states(&raw) {
            Ok(states) => states,
            Err(error) => {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::Codex,
                    layer: Some(DiscoveryLayer::Global),
                    code: "toml-parse-error".to_string(),
                    message: format!("Codex skills.config could not be read: {error}"),
                });
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };
    let skill_item_start = items.len();
    let shared_global_skill_root = roots.shared_global.join(".agents").join("skills");
    let global_live_skill_ids = discover_direct_child_skill_dirs(
        &shared_global_skill_root,
        ProviderId::Codex,
        DiscoveryLayer::Global,
        "codex:global:skill:",
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    shared_skill_views.push(SkillView::new(
        ProviderId::Codex,
        DiscoveryLayer::Global,
        shared_global_skill_root.clone(),
        "codex:global:skill:",
        SkillRootTraversal::Direct,
    ));
    discover_direct_child_skill_dirs(
        &roots.codex_admin.join("skills"),
        ProviderId::Codex,
        DiscoveryLayer::Global,
        "codex:global:skill:admin/",
        DiscoveryMutability::ReadOnly,
        items,
    )?;
    let project_skills = discover_project_skill_dirs(
        &roots.shared_project,
        Path::new(".agents/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Project,
            id_prefix: "codex:project:skill:",
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Ancestors,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    shared_skill_views.extend(project_skills.skill_views.iter().cloned());
    apply_codex_skill_config_states(
        &mut items[skill_item_start..],
        &config_path,
        &skill_config_states,
    );
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Global,
            live_ids: &global_live_skill_ids,
            allowed_skill_roots: std::slice::from_ref(&shared_global_skill_root),
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Project,
            live_ids: &project_skills.live_ids,
            allowed_skill_roots: &project_skills.skill_roots,
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;
    let global_agent_root = roots.codex_global.join("agents");
    let live_agent_ids = discover_agent_files(
        &global_agent_root,
        ProviderId::Codex,
        DiscoveryLayer::Global,
        "codex:global:agent:",
        &[AgentFileKind::Markdown, AgentFileKind::Toml],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Codex,
        DiscoveryLayer::Global,
        &live_agent_ids,
        std::slice::from_ref(&global_agent_root),
        items,
        warnings,
    )?;
    let project_agent_root = roots.codex_project.join(".codex").join("agents");
    let live_agent_ids = discover_agent_files(
        &project_agent_root,
        ProviderId::Codex,
        DiscoveryLayer::Project,
        "codex:project:agent:",
        &[AgentFileKind::Markdown, AgentFileKind::Toml],
        items,
    )?;
    discover_vaulted_agent_items(
        roots.app_state_root.as_deref(),
        ProviderId::Codex,
        DiscoveryLayer::Project,
        &live_agent_ids,
        std::slice::from_ref(&project_agent_root),
        items,
        warnings,
    )?;

    let live_codex_global_mcp_ids = discover_codex_config_file(
        &config_path,
        CodexConfigSpec {
            layer: DiscoveryLayer::Global,
            id_scope: "",
            setting_id: "codex:global:setting:config-toml",
            setting_display_name: "config.toml",
        },
        items,
        warnings,
    )?;
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Global,
            payload_kind: "text-payload",
            live_ids: &live_codex_global_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&config_path),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    discover_json_hooks_file(
        &roots.codex_global.join("hooks.json"),
        JsonHooksSpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Global,
            hook_id_prefix: "codex:global:hook:hooks-json:",
            setting_id: "codex:global:setting:hooks-json",
            setting_display_name: "hooks.json",
            allow_top_level_events: true,
        },
        items,
        warnings,
    )?;

    let repository_root = if roots.scan_project_scopes {
        find_repository_root(&roots.codex_project)
    } else {
        roots.codex_project.clone()
    };
    let mut project_scopes = Vec::new();
    add_project_ancestors(&roots.codex_project, &repository_root, &mut project_scopes);
    project_scopes.reverse();

    let mut live_codex_project_mcp_ids = BTreeSet::new();
    let mut codex_project_config_paths = Vec::new();
    for scope_root in project_scopes {
        let relative_scope = scope_root.strip_prefix(&repository_root)?;
        let id_scope = if relative_scope.as_os_str().is_empty() {
            String::new()
        } else {
            format!("@scope/{}/", skill_id_path(relative_scope))
        };
        let setting_id = format!("codex:project:setting:{id_scope}config-toml");
        let setting_display_name = if relative_scope.as_os_str().is_empty() {
            ".codex/config.toml".to_string()
        } else {
            format!("{}/.codex/config.toml", relative_scope.to_string_lossy())
        };
        let scope_config_path = scope_root.join(".codex").join("config.toml");
        codex_project_config_paths.push(scope_config_path.clone());
        live_codex_project_mcp_ids.extend(discover_codex_config_file(
            &scope_config_path,
            CodexConfigSpec {
                layer: DiscoveryLayer::Project,
                id_scope: &id_scope,
                setting_id: &setting_id,
                setting_display_name: &setting_display_name,
            },
            items,
            warnings,
        )?);
    }
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Project,
            payload_kind: "text-payload",
            live_ids: &live_codex_project_mcp_ids,
            allowed_state_paths: &codex_project_config_paths,
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    discover_json_hooks_file(
        &roots.codex_project.join(".codex").join("hooks.json"),
        JsonHooksSpec {
            provider: ProviderId::Codex,
            layer: DiscoveryLayer::Project,
            hook_id_prefix: "codex:project:hook:hooks-json:",
            setting_id: "codex:project:setting:hooks-json",
            setting_display_name: ".codex/hooks.json",
            allow_top_level_events: true,
        },
        items,
        warnings,
    )?;

    let activations = crate::agent_plugins::activation_candidates(ProviderId::Codex, items);
    crate::agent_plugins::discover_cached_agent_plugins(
        ProviderId::Codex,
        &roots.codex_global.join("plugins").join("cache"),
        &activations,
        agent_plugin_metadata,
        agent_plugin_item_keys,
        warnings,
    )?;

    Ok(())
}

fn apply_codex_skill_config_states(
    items: &mut [DiscoveryItem],
    config_path: &Path,
    states: &BTreeMap<String, bool>,
) {
    let state_path = path_string(config_path);
    for item in items {
        if item.provider != ProviderId::Codex || item.category != DiscoveryCategory::Skill {
            continue;
        }

        item.enabled = states.get(&item.source_path).copied().unwrap_or(true);
        item.mutability = DiscoveryMutability::ReadWrite;
        item.state_path.clone_from(&state_path);
    }
}

pub(crate) fn codex_skill_config_enabled(raw: &str, skill_path: &Path) -> Result<bool, String> {
    Ok(parse_codex_skill_config_states(raw)?
        .get(&path_string(skill_path))
        .copied()
        .unwrap_or(true))
}

pub(crate) fn codex_skill_config_path(section: &str) -> Result<Option<String>, String> {
    toml_assignment_value(section, "path")
        .map(parse_toml_string)
        .transpose()
}

fn parse_codex_skill_config_states(raw: &str) -> Result<BTreeMap<String, bool>, String> {
    let mut states = BTreeMap::new();
    for section in codex_array_table_sections(raw, "skills.config") {
        let path = codex_skill_config_path(section)?
            .ok_or_else(|| "skills.config entry is missing path".to_string())?;
        let enabled = match toml_assignment_value(section, "enabled") {
            Some(raw_enabled) => parse_toml_bool(raw_enabled)?,
            None => true,
        };
        if states.insert(path, enabled).is_some() {
            return Err("duplicate skills.config path".to_string());
        }
    }
    Ok(states)
}

fn codex_array_table_sections<'a>(raw: &'a str, target: &str) -> Vec<&'a str> {
    find_array_table_sections(raw, target)
        .into_iter()
        .map(|section| section.content)
        .collect()
}

pub(crate) fn toml_assignment_value<'a>(section: &'a str, key: &str) -> Option<&'a str> {
    crate::toml_syntax::top_level_assignment(section, key).map(|assignment| assignment.value)
}

pub(crate) fn parse_toml_bool(raw: &str) -> Result<bool, String> {
    match raw.split('#').next().unwrap_or_default().trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("enabled must be true or false".to_string()),
    }
}

pub(crate) fn parse_toml_string(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if let Some(literal) = raw.strip_prefix('\'') {
        let end = literal
            .find('\'')
            .ok_or_else(|| "unterminated TOML literal string".to_string())?;
        ensure_toml_value_tail(&literal[end + 1..])?;
        return Ok(literal[..end].to_string());
    }

    if !raw.starts_with('"') {
        return Err("path must be a quoted TOML string".to_string());
    }
    let mut escaped = false;
    let mut end = None;
    for (index, character) in raw.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                end = Some(index + character.len_utf8());
                break;
            }
            _ => {}
        }
    }
    let end = end.ok_or_else(|| "unterminated TOML basic string".to_string())?;
    ensure_toml_value_tail(&raw[end..])?;
    serde_json::from_str(&raw[..end]).map_err(|error| format!("invalid TOML path string: {error}"))
}

fn ensure_toml_value_tail(tail: &str) -> Result<(), String> {
    let tail = tail.trim();
    if tail.is_empty() || tail.starts_with('#') {
        Ok(())
    } else {
        Err("unexpected content after TOML value".to_string())
    }
}

#[derive(Debug, Clone, Copy)]
struct CodexConfigSpec<'a> {
    layer: DiscoveryLayer,
    id_scope: &'a str,
    setting_id: &'a str,
    setting_display_name: &'a str,
}

fn discover_codex_config_file(
    config_path: &Path,
    spec: CodexConfigSpec<'_>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_mcp_ids = BTreeSet::new();
    let Some(raw) = read_optional_string(config_path)? else {
        return Ok(live_mcp_ids);
    };
    items.push(provider_setting_item(
        ProviderId::Codex,
        spec.layer,
        spec.setting_id.to_string(),
        spec.setting_display_name,
        config_path,
    ));
    let malformed_table_headers = malformed_table_header_lines(&raw);
    if !malformed_table_headers.is_empty() {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Codex,
            layer: Some(spec.layer),
            code: "invalid-toml-table-header".to_string(),
            message: format!(
                "{} contains malformed TOML table headers on lines: {}",
                config_path.display(),
                malformed_table_headers
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
        return Ok(live_mcp_ids);
    }
    let duplicate_tables = duplicate_standard_table_names(&raw);
    if !duplicate_tables.is_empty() {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Codex,
            layer: Some(spec.layer),
            code: "duplicate-toml-table".to_string(),
            message: format!(
                "{} contains duplicate TOML table declarations: {}",
                config_path.display(),
                duplicate_tables.join(", ")
            ),
        });
        return Ok(live_mcp_ids);
    }
    let duplicate_enabled_keys = duplicate_top_level_key_tables(&raw, "enabled");
    if !duplicate_enabled_keys.is_empty() {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Codex,
            layer: Some(spec.layer),
            code: "duplicate-toml-key".to_string(),
            message: format!(
                "{} contains duplicate enabled keys in TOML tables: {}",
                config_path.display(),
                duplicate_enabled_keys.join(", ")
            ),
        });
        return Ok(live_mcp_ids);
    }
    items.extend(codex_inline_hook_items(
        config_path,
        &raw,
        spec.layer,
        spec.id_scope,
        warnings,
    ));

    for server_id in parse_codex_section_ids(&raw, "mcp_servers") {
        let id = format!(
            "codex:{}:configured-mcp:{}{server_id}",
            spec.layer.as_str(),
            spec.id_scope
        );
        live_mcp_ids.insert(id.clone());
        let section = find_table_section(&raw, "mcp_servers", &server_id);
        let enabled = section
            .map(|section| codex_section_enabled(section.content))
            .unwrap_or(true);
        let mut item = configured_mcp_item(
            ProviderId::Codex,
            spec.layer,
            id,
            &server_id,
            enabled,
            config_path,
            config_path,
        );
        item.source_fingerprint = table_subtree_content(&raw, "mcp_servers", &server_id)
            .map(|content| source_fingerprint(&content));
        items.push(item);
    }

    if spec.layer == DiscoveryLayer::Global {
        for plugin_id in parse_codex_section_ids(&raw, "plugins") {
            let section = find_table_section(&raw, "plugins", &plugin_id);
            let enabled = section
                .map(|section| codex_section_enabled(section.content))
                .unwrap_or(true);
            let mut item = plugin_config_item(
                ProviderId::Codex,
                spec.layer,
                format!("codex:global:plugin-config:config:{plugin_id}"),
                &plugin_id,
                enabled,
                config_path,
            );
            item.source_fingerprint = table_subtree_content(&raw, "plugins", &plugin_id)
                .map(|content| source_fingerprint(&content));
            items.push(item);
        }
    }

    Ok(live_mcp_ids)
}

fn codex_section_enabled(section: &str) -> bool {
    toml_assignment_value(section, "enabled")
        .and_then(|value| parse_toml_bool(value).ok())
        .unwrap_or(true)
}
