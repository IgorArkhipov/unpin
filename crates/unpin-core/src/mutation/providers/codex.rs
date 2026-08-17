use super::super::*;

pub(crate) fn plan_codex_skill_toggle(item: DiscoveryItem) -> ToggleResult {
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = match fs::read_to_string(&item.source_path) {
            Ok(raw) => source_fingerprint(&raw),
            Err(error) => {
                return blocked(
                    item,
                    format!("Codex skill source could not be read: {error}"),
                );
            }
        };
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item.clone(),
                format!(
                    "Codex skill source drifted for {}: discovered {discovered_fingerprint}, current {current_fingerprint}",
                    item.id
                ),
            );
        }
    }

    let config_path = PathBuf::from(&item.state_path);
    let raw = match read_optional_string(&config_path) {
        Ok(Some(raw)) => raw,
        Ok(None) => String::new(),
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {error}"));
        }
    };
    let current_enabled = match codex_skill_config_enabled(&raw, Path::new(&item.source_path)) {
        Ok(enabled) => enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Codex skill state drifted: discovered {discovered_enabled}, current {current_enabled}"
            ),
        );
    }

    let target_enabled = !item.enabled;
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in Codex skills.config. Restart Codex to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![MutationTarget {
            target_type: "statePath".to_string(),
            path: item.state_path.clone(),
        }],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_codex_skill_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_codex_skill_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let config_path = PathBuf::from(&item.state_path);
    let (config_existed, raw) = match read_optional_string(&config_path) {
        Ok(Some(raw)) => (true, raw),
        Ok(None) => (false, String::new()),
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {error}"));
        }
    };
    let rewritten = match set_codex_skill_config_enabled(
        &raw,
        Path::new(&item.source_path),
        plan.target_enabled,
    ) {
        Ok(rewritten) => rewritten,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(&backup_root)?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        let payload = if config_existed {
            fs::create_dir_all(
                backup_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&config_path, &backup_payload)?;
            Some(BackupPayload {
                storage: "path".to_string(),
                path: "entries/entry-1/payload".to_string(),
            })
        } else {
            None
        };
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: config_existed,
                path_kind: config_existed.then(|| "file".to_string()),
                payload,
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_provider_config(&config_path, rewritten)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();

    drop(lock);
    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}
pub(crate) fn plan_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Codex configured MCP item id"),
    };

    if item.state_path.ends_with("entry.json") {
        return plan_disabled_codex_configured_mcp_toggle(app_state_root, item, &server_id);
    }

    plan_codex_toml_table_toggle(
        item,
        "mcp_servers",
        &server_id,
        "configured MCP",
        "its Codex mcp_servers section",
        false,
    )
}

pub(crate) fn plan_codex_plugin_toggle(item: DiscoveryItem) -> ToggleResult {
    let plugin_id = match codex_plugin_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid Codex plugin item id"),
    };

    plan_codex_toml_table_toggle(
        item,
        "plugins",
        &plugin_id,
        "plugin",
        "its Codex plugins section",
        true,
    )
}

pub(crate) fn plan_codex_toml_table_toggle(
    item: DiscoveryItem,
    table_prefix: &str,
    table_id: &str,
    item_description: &str,
    summary_location: &str,
    restart_required: bool,
) -> ToggleResult {
    let config_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        return blocked(item, reason);
    }

    let section = match find_toml_table_section(&raw, table_prefix, table_id) {
        Some(section) => section,
        None => {
            return blocked(
                item,
                format!("Codex {item_description} section not found: [{table_prefix}.{table_id}]"),
            );
        }
    };
    let current_enabled = match toml_table_bool(section.content, "enabled") {
        Ok(enabled) => enabled.unwrap_or(true),
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Codex {item_description} state drifted for {table_id}: discovered {}, current {current_enabled}",
                discovered_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let Some(current_content) = toml_table_subtree_content(&raw, table_prefix, table_id) else {
            return blocked(
                item,
                format!("Codex {item_description} table subtree is ambiguous for {table_id}"),
            );
        };
        let current_fingerprint = source_fingerprint(&current_content);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "Codex {item_description} source drifted for {table_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;

    let restart_guidance = if restart_required {
        " Restart Codex to load the change."
    } else {
        ""
    };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in {summary_location}.{restart_guidance}",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![MutationTarget {
            target_type: "statePath".to_string(),
            path: item.state_path.clone(),
        }],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn plan_disabled_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let vault_entry = match load_codex_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let config_path = PathBuf::from(&vault_entry.original_path);
    let raw = match fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        return blocked(item, reason);
    }
    if find_toml_table_section(&raw, "mcp_servers", server_id).is_some() {
        return blocked(
            item,
            format!(
                "live-section-conflict: {server_id} is already present in {}",
                config_path.display()
            ),
        );
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload_raw = match fs::read_to_string(&vault_payload) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(
                item,
                format!(
                    "vault payload could not be read: {}: {error}",
                    vault_payload.display()
                ),
            );
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&payload_raw) {
        return blocked(item, format!("vault payload is ambiguous: {reason}"));
    }
    if find_toml_table_section(&payload_raw, "mcp_servers", server_id).is_none() {
        return blocked(
            item,
            format!("vault payload does not contain [mcp_servers.{server_id}]"),
        );
    }

    let vault_root = vault_root_path(&app_state_root, &item);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: true,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(vault_entry.original_path.clone()),
            to_path: Some(vault_entry.vaulted_path.clone()),
            summary: format!(
                "Enable {} by restoring its vaulted Codex mcp_servers section.",
                item.id
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: vault_entry.original_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_entry.vaulted_path,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if item.state_path.ends_with("entry.json") {
        return apply_disabled_codex_configured_mcp_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Codex configured MCP item id"),
    };

    apply_codex_toml_table_toggle(
        app_state_root,
        item,
        CodexTomlToggleSpec {
            table_prefix: "mcp_servers",
            table_id: &server_id,
            item_description: "configured MCP",
            summary_location: "its Codex mcp_servers section",
            restart_required: false,
        },
        backup_authentication_key,
    )
}

pub(crate) fn apply_codex_plugin_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let plugin_id = match codex_plugin_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid Codex plugin item id"),
    };

    apply_codex_toml_table_toggle(
        app_state_root,
        item,
        CodexTomlToggleSpec {
            table_prefix: "plugins",
            table_id: &plugin_id,
            item_description: "plugin",
            summary_location: "its Codex plugins section",
            restart_required: true,
        },
        backup_authentication_key,
    )
}

pub(crate) struct CodexTomlToggleSpec<'a> {
    table_prefix: &'a str,
    table_id: &'a str,
    item_description: &'a str,
    summary_location: &'a str,
    restart_required: bool,
}

pub(crate) fn apply_codex_toml_table_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    spec: CodexTomlToggleSpec<'_>,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_codex_toml_table_toggle(
        item.clone(),
        spec.table_prefix,
        spec.table_id,
        spec.item_description,
        spec.summary_location,
        spec.restart_required,
    );
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    let rewritten = match set_toml_table_bool(
        &raw,
        spec.table_prefix,
        spec.table_id,
        "enabled",
        plan.target_enabled,
    ) {
        Ok(rewritten) => rewritten,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Codex config file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rewritten)?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

pub(crate) fn apply_disabled_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Codex configured MCP item id");
        }
    };
    let plan = plan_codex_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_codex_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        drop(lock);
        return blocked(item, reason);
    }
    if find_toml_table_section(&raw, "mcp_servers", &server_id).is_some() {
        drop(lock);
        return blocked(
            item,
            format!(
                "live-section-conflict: {server_id} is already present in {}",
                source_path.display()
            ),
        );
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload_raw = match fs::read_to_string(&vault_payload) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "vault payload could not be read: {}: {error}",
                    vault_payload.display()
                ),
            );
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&payload_raw) {
        drop(lock);
        return blocked(item, format!("vault payload is ambiguous: {reason}"));
    }
    let section = match find_toml_table_section(&payload_raw, "mcp_servers", &server_id) {
        Some(section) => section,
        None => {
            drop(lock);
            return blocked(
                item,
                format!("vault payload does not contain [mcp_servers.{server_id}]"),
            );
        }
    };
    let rewritten = append_toml_table_section(&raw, section.content);

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !source_path.is_file() {
        let reason = format!("Codex config file not found: {}", source_path.display());
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-1/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rewritten)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}
