use super::super::*;

pub(crate) fn plan_opencode_configured_mcp_toggle(item: DiscoveryItem) -> ToggleResult {
    let server_id = match opencode_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid OpenCode configured MCP item id"),
    };
    let config_path = PathBuf::from(&item.state_path);
    let raw = match read_jsonc_raw(&config_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    let server_value = match opencode_mcp_server_value(&raw, &server_id) {
        Ok(value) => value,
        Err(reason) => return blocked(item, reason),
    };
    let current_enabled = server_value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "OpenCode configured MCP state drifted for {server_id}: discovered {discovered_enabled}, current {current_enabled}"
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&server_value);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "OpenCode configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;
    if let Err(reason) = set_opencode_mcp_enabled_jsonc(&raw, &server_id, target_enabled) {
        return blocked(item, reason);
    }
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in OpenCode mcp config. Restart OpenCode to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: Some(vec!["mcp".to_string(), server_id, "enabled".to_string()]),
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

pub(crate) fn apply_opencode_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_configured_mcp_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let server_id = match opencode_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode configured MCP item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match set_opencode_mcp_enabled_jsonc(&raw, &server_id, plan.target_enabled) {
        Ok(rendered) => rendered,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

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
        write_provider_config(&source_path, rendered)?;
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
pub(crate) fn plan_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid OpenCode npm plugin item id"),
    };

    if !item.enabled {
        let vault_entry = match load_opencode_plugin_config_vault_entry(&app_state_root, &item) {
            Ok(vault_entry) => vault_entry,
            Err(reason) => return blocked(item, reason),
        };
        let source_path = PathBuf::from(&vault_entry.original_path);
        let source_raw = match read_jsonc_raw(&source_path) {
            Ok(raw) => raw,
            Err(reason) => return blocked(item, reason),
        };
        let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
        let payload = match read_opencode_plugin_vault_payload(&vault_payload, &plugin_id) {
            Ok(payload) => payload,
            Err(reason) => return blocked(item, reason),
        };
        if let Err(reason) = prepare_opencode_plugin_restore(
            &source_raw,
            &plugin_id,
            &payload,
            vault_entry.jsonc_format.as_ref(),
        ) {
            return blocked(item, reason);
        }

        let vault_root = vault_root_path(&app_state_root, &item);
        return ToggleResult {
            status: ToggleStatus::DryRun,
            selection: item.clone(),
            target_enabled: true,
            operations: vec![MutationOperation {
                operation_type: "replaceFile".to_string(),
                from_path: Some(vault_entry.original_path.clone()),
                to_path: Some(vault_entry.vaulted_path.clone()),
                summary: format!(
                    "Enable {} by restoring its OpenCode plugin config reference. Restart OpenCode to load the change.",
                    item.id
                ),
                path: Some(vault_entry.original_path.clone()),
                json_path: Some(vec!["plugin".to_string()]),
                value: Some(Value::String(plugin_id)),
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
        };
    }

    let source_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    let original_order =
        match opencode_plugin_order_with_vaults(&app_state_root, &item, &source_raw) {
            Ok(original_order) => original_order,
            Err(reason) => return blocked(item, reason),
        };
    if let Err(reason) = prepare_opencode_plugin_removal(
        &source_raw,
        &plugin_id,
        item.source_fingerprint.as_deref(),
        original_order,
    ) {
        return blocked(item, reason);
    }
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: false,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: Some(path_string(vault_payload.clone())),
            summary: format!(
                "Disable {} by removing its OpenCode plugin config reference while retaining installed cache files. Restart OpenCode to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: Some(vec!["plugin".to_string()]),
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: path_string(vault_payload),
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

pub(crate) fn apply_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_opencode_plugin_config_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_plugin_config_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode npm plugin item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let original_order =
        match opencode_plugin_order_with_vaults(&app_state_root, &item, &source_raw) {
            Ok(original_order) => original_order,
            Err(reason) => {
                drop(lock);
                return blocked(item, reason);
            }
        };
    let removal = match prepare_opencode_plugin_removal(
        &source_raw,
        &plugin_id,
        item.source_fingerprint.as_deref(),
        original_order,
    ) {
        Ok(removal) => removal,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }
    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
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
            target_enabled: false,
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

        fs::create_dir_all(&vault_root)?;
        write_json_file(&vault_payload, &removal.payload)?;
        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: vault_kind_segment(&item).to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "json-payload".to_string(),
            jsonc_format: removal.jsonc_format,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;
        write_provider_config(&source_path, &removal.rendered)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
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

pub(crate) fn apply_disabled_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_plugin_config_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode npm plugin item id");
        }
    };
    let vault_entry = match load_opencode_plugin_config_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload = match read_opencode_plugin_vault_payload(&vault_payload, &plugin_id) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match prepare_opencode_plugin_restore(
        &source_raw,
        &plugin_id,
        &payload,
        vault_entry.jsonc_format.as_ref(),
    ) {
        Ok(rendered) => rendered,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

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

        write_provider_config(&source_path, rendered)?;
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
