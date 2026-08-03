use super::super::*;

pub(crate) fn discover_zed(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        shared_skill_views,
        items,
        warnings,
        ..
    } = state;
    let global_skill_root = roots.shared_global.join(".agents").join("skills");
    let global_live_skill_ids = discover_direct_child_skill_dirs(
        &global_skill_root,
        ProviderId::Zed,
        DiscoveryLayer::Global,
        "zed:global:skill:",
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    shared_skill_views.push(SkillView::new(
        ProviderId::Zed,
        DiscoveryLayer::Global,
        global_skill_root.clone(),
        "zed:global:skill:",
        SkillRootTraversal::Direct,
    ));
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Zed,
            layer: DiscoveryLayer::Global,
            live_ids: &global_live_skill_ids,
            allowed_skill_roots: std::slice::from_ref(&global_skill_root),
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;

    let project_skill_root = roots.shared_project.join(".agents").join("skills");
    let project_live_skill_ids = discover_direct_child_skill_dirs(
        &project_skill_root,
        ProviderId::Zed,
        DiscoveryLayer::Project,
        "zed:project:skill:",
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    shared_skill_views.push(SkillView::new(
        ProviderId::Zed,
        DiscoveryLayer::Project,
        project_skill_root.clone(),
        "zed:project:skill:",
        SkillRootTraversal::Direct,
    ));
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Zed,
            layer: DiscoveryLayer::Project,
            live_ids: &project_live_skill_ids,
            allowed_skill_roots: std::slice::from_ref(&project_skill_root),
            skill_root_traversal: SkillRootTraversal::Direct,
        },
        items,
        warnings,
    )?;

    discover_setting_files(
        ProviderId::Zed,
        DiscoveryLayer::Global,
        &[(
            roots.zed_global.join("AGENTS.md"),
            "zed:global:setting:agents-md",
            "AGENTS.md",
        )],
        items,
    );
    discover_setting_files(
        ProviderId::Zed,
        DiscoveryLayer::Project,
        &[(
            roots.zed_project.join("AGENTS.md"),
            "zed:project:setting:agents-md",
            "AGENTS.md",
        )],
        items,
    );

    let global_settings_path = roots.zed_global.join("settings.json");
    let live_zed_global_mcp_ids = discover_zed_settings(
        &global_settings_path,
        DiscoveryLayer::Global,
        "zed:global:setting:settings-json",
        "settings.json",
        items,
        warnings,
    )?;
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Zed,
            layer: DiscoveryLayer::Global,
            payload_kind: "json-payload",
            live_ids: &live_zed_global_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&global_settings_path),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    let project_settings_path = roots.zed_project.join(".zed").join("settings.json");
    let live_zed_project_mcp_ids = discover_zed_settings(
        &project_settings_path,
        DiscoveryLayer::Project,
        "zed:project:setting:settings-json",
        ".zed/settings.json",
        items,
        warnings,
    )?;
    discover_vaulted_configured_mcp_items(
        roots.app_state_root.as_deref(),
        ConfiguredMcpVaultSpec {
            provider: ProviderId::Zed,
            layer: DiscoveryLayer::Project,
            payload_kind: "json-payload",
            live_ids: &live_zed_project_mcp_ids,
            allowed_state_paths: std::slice::from_ref(&project_settings_path),
            allowed_item_id_prefix: None,
        },
        items,
        warnings,
    )?;

    Ok(())
}

fn discover_zed_settings(
    path: &Path,
    layer: DiscoveryLayer,
    setting_id: &'static str,
    setting_display_name: &'static str,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    let Some(document) =
        read_jsonc_if_exists::<ZedSettings>(path, ProviderId::Zed, Some(layer), warnings)?
    else {
        return Ok(live_ids);
    };

    items.push(provider_setting_item(
        ProviderId::Zed,
        layer,
        setting_id.to_string(),
        setting_display_name,
        path,
    ));

    for (server_id, value) in &document.context_servers {
        if !value.is_object() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Zed,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!(
                    "{} context_servers.{server_id} must be a JSON object",
                    path.display()
                ),
            });
            continue;
        }

        let id = format!("zed:{}:configured-mcp:{server_id}", layer.as_str());
        live_ids.insert(id.clone());
        let mut item = configured_mcp_item(ProviderId::Zed, layer, id, server_id, true, path, path);
        item.source_fingerprint = Some(json_value_source_fingerprint(value));
        items.push(item);
    }

    Ok(live_ids)
}
