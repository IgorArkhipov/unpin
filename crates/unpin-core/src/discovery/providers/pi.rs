use super::super::*;

pub(crate) fn discover_pi(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        project_scope_cache,
        shared_skill_views,
        items,
        warnings,
    } = state;
    let native_global_root = roots.pi_global.join("skills");
    let shared_global_root = roots.shared_global.join(".agents").join("skills");
    let mut global_live_ids = discover_recursive_skill_dirs(
        &native_global_root,
        ProviderId::Pi,
        DiscoveryLayer::Global,
        PI_GLOBAL_SKILL_ID_PREFIX,
        DiscoveryMutability::ReadWrite,
        items,
        warnings,
    )?;
    let global_file_skill_ids = discover_direct_skill_markdown_files(
        &native_global_root,
        ProviderId::Pi,
        DiscoveryLayer::Global,
        &format!("{PI_GLOBAL_SKILL_ID_PREFIX}@file/"),
        DiscoveryMutability::ReadWrite,
        items,
    )?;
    global_live_ids.extend(global_file_skill_ids);
    let shared_global_id_prefix =
        format!("{PI_GLOBAL_SKILL_ID_PREFIX}{PI_COMPAT_AGENTS_SKILL_NAMESPACE}");
    global_live_ids.extend(discover_recursive_skill_dirs(
        &shared_global_root,
        ProviderId::Pi,
        DiscoveryLayer::Global,
        &shared_global_id_prefix,
        DiscoveryMutability::ReadWrite,
        items,
        warnings,
    )?);
    shared_skill_views.push(SkillView::new(
        ProviderId::Pi,
        DiscoveryLayer::Global,
        shared_global_root.clone(),
        shared_global_id_prefix,
        SkillRootTraversal::Recursive,
    ));
    let global_skill_roots = [native_global_root, shared_global_root];
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Global,
            live_ids: &global_live_ids,
            allowed_skill_roots: &global_skill_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_file_items(
        roots.app_state_root.as_deref(),
        ProviderId::Pi,
        DiscoveryLayer::Global,
        &global_live_ids,
        std::slice::from_ref(&global_skill_roots[0]),
        items,
        warnings,
    )?;

    let native_project_skills = discover_project_skill_dirs(
        &roots.pi_project,
        Path::new(".pi/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            id_prefix: PI_PROJECT_SKILL_ID_PREFIX,
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Selected,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    let shared_project_id_prefix =
        format!("{PI_PROJECT_SKILL_ID_PREFIX}{PI_COMPAT_AGENTS_SKILL_NAMESPACE}");
    let shared_project_skills = discover_project_skill_dirs(
        &roots.shared_project,
        Path::new(".agents/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            id_prefix: &shared_project_id_prefix,
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Ancestors,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    shared_skill_views.extend(shared_project_skills.skill_views.iter().cloned());
    let mut project_live_ids = native_project_skills.live_ids;
    project_live_ids.extend(shared_project_skills.live_ids);
    let mut project_skill_roots = native_project_skills.skill_roots;
    project_skill_roots.extend(shared_project_skills.skill_roots);
    let native_project_skill_root = roots.pi_project.join(".pi").join("skills");
    project_live_ids.extend(discover_direct_skill_markdown_files(
        &native_project_skill_root,
        ProviderId::Pi,
        DiscoveryLayer::Project,
        &format!("{PI_PROJECT_SKILL_ID_PREFIX}@file/"),
        DiscoveryMutability::ReadWrite,
        items,
    )?);
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            live_ids: &project_live_ids,
            allowed_skill_roots: &project_skill_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_file_items(
        roots.app_state_root.as_deref(),
        ProviderId::Pi,
        DiscoveryLayer::Project,
        &project_live_ids,
        std::slice::from_ref(&native_project_skill_root),
        items,
        warnings,
    )?;

    discover_pi_settings(
        &roots.pi_global.join("settings.json"),
        DiscoveryLayer::Global,
        "settings.json",
        roots.app_state_root.as_deref(),
        items,
        warnings,
    )?;
    discover_pi_settings(
        &roots.pi_project.join(".pi").join("settings.json"),
        DiscoveryLayer::Project,
        ".pi/settings.json",
        roots.app_state_root.as_deref(),
        items,
        warnings,
    )?;

    Ok(())
}

fn discover_pi_settings(
    path: &Path,
    layer: DiscoveryLayer,
    display_name: &str,
    app_state_root: Option<&Path>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    if !path.exists() {
        return Ok(());
    }
    items.push(provider_setting_item(
        ProviderId::Pi,
        layer,
        format!("pi:{}:setting:settings-json", layer.as_str()),
        display_name,
        path,
    ));

    let Some(document) =
        read_json_if_exists::<serde_json::Value>(path, ProviderId::Pi, Some(layer), warnings)?
    else {
        return Ok(());
    };
    let Some(document) = document.as_object() else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Pi,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{} must contain a JSON object", path.display()),
        });
        return Ok(());
    };
    let Some(packages) = document
        .get("packages")
        .and_then(serde_json::Value::as_array)
    else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Pi,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{} packages must be an array", path.display()),
        });
        return Ok(());
    };

    let package_item_start = items.len();
    let mut validated_sources = BTreeSet::new();
    let mutability = if packages.iter().all(|package| {
        pi_package_extension_state(package)
            .ok()
            .is_some_and(|(source, _)| validated_sources.insert(source.to_string()))
    }) {
        DiscoveryMutability::ReadWrite
    } else {
        DiscoveryMutability::ReadOnly
    };
    let id_prefix = match layer {
        DiscoveryLayer::Global => PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX,
    };
    let mut item_ids = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        let (source, enabled) = match pi_package_extension_state(package) {
            Ok(state) => state,
            Err(reason) => {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::Pi,
                    layer: Some(layer),
                    code: "invalid-shape".to_string(),
                    message: format!("{} packages[{index}] {reason}", path.display()),
                });
                continue;
            }
        };
        let item_id = format!("{id_prefix}{source}");
        if !item_ids.insert(item_id.clone()) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "duplicate-id".to_string(),
                message: format!(
                    "{} packages contains duplicate source {source}",
                    path.display()
                ),
            });
            continue;
        }
        let mut item = plugin_config_item(ProviderId::Pi, layer, item_id, source, enabled, path);
        item.mutability = mutability;
        item.source_fingerprint = Some(json_value_source_fingerprint(package));
        items.push(item);
    }
    validate_pi_package_vaults(
        app_state_root,
        path,
        layer,
        &mut items[package_item_start..],
        warnings,
    )?;
    Ok(())
}

fn validate_pi_package_vaults(
    app_state_root: Option<&Path>,
    settings_path: &Path,
    layer: DiscoveryLayer,
    package_items: &mut [DiscoveryItem],
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let provider = ProviderId::Pi;
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("plugin");
    match fs::symlink_metadata(&vault_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &vault_root,
                "Pi plugin vault root must be a regular directory",
            );
            for item in package_items {
                item.mutability = DiscoveryMutability::ReadOnly;
            }
            return Ok(());
        }
        Ok(_) => {}
    }
    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = match layer {
        DiscoveryLayer::Global => PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX,
    };

    for entry in entries {
        let warning_count = warnings.len();
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "plugin",
            "json-payload",
            expected_id_prefix,
            warnings,
        ) else {
            if warnings.len() > warning_count {
                for item in package_items.iter_mut() {
                    item.mutability = DiscoveryMutability::ReadOnly;
                }
            }
            continue;
        };
        let package_source = vault_entry
            .item_id
            .strip_prefix(expected_id_prefix)
            .expect("stored Pi vault id prefix validated");
        let Some(item) = package_items
            .iter_mut()
            .find(|item| item.id == vault_entry.item_id)
        else {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_path,
                "vaulted package is missing from the live Pi settings packages array",
            );
            continue;
        };
        let expected_payload = entry.path().join("payload.json");
        let invalid_reason = if Path::new(&vault_entry.original_path) != settings_path {
            Some("originalPath does not match the discovered Pi settings path")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_payload,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !fs::symlink_metadata(&vault_entry.vaulted_path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            Some("vaultedPath is not a regular file")
        } else if item.enabled {
            Some("vault exists but the live Pi package extensions are enabled")
        } else {
            let payload_matches = fs::read_to_string(&vault_entry.vaulted_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<StoredPiPackageVaultPayload>(&raw).ok())
                .is_some_and(|payload| {
                    let original_matches =
                        serde_json::from_str::<serde_json::Value>(&payload.original_raw)
                            .is_ok_and(|original_raw| original_raw == payload.original_entry);
                    let disabled_matches = pi_disabled_package_entry(&payload.original_entry)
                        .ok()
                        .flatten()
                        .is_some_and(|disabled| {
                            payload.disabled_entry_fingerprint
                                == json_value_source_fingerprint(&disabled)
                        });
                    payload.package_source == package_source
                        && original_matches
                        && disabled_matches
                        && item.source_fingerprint.as_deref()
                            == Some(payload.disabled_entry_fingerprint.as_str())
                        && vault_entry.display_name == package_source
                });
            if payload_matches {
                None
            } else {
                Some("vault payload does not match the Pi package identity or disabled state")
            }
        };
        if let Some(reason) = invalid_reason {
            item.mutability = DiscoveryMutability::ReadOnly;
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
        }
    }
    Ok(())
}
