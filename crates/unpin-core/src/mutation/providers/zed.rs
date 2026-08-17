use super::super::*;

pub(crate) fn plan_zed_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Zed configured MCP item id"),
    };

    if !item.enabled {
        return plan_disabled_zed_configured_mcp_vault_toggle(app_state_root, item, &server_id);
    }

    let settings_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&settings_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    if let Err(reason) = prepare_zed_context_server_removal(
        &source_raw,
        &server_id,
        item.source_fingerprint.as_deref(),
    ) {
        return blocked(item, reason);
    }

    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = zed_configured_mcp_vault_payload_path(&app_state_root, &item);
    let vault_payload_string = path_string(vault_payload);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: false,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: Some(vault_payload_string.clone()),
            summary: format!(
                "Disable {} by removing its Zed context_servers entry and vaulting it.",
                item.id
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_payload_string,
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

pub(crate) fn plan_disabled_zed_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let vault_entry = match load_zed_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let settings_path = PathBuf::from(&vault_entry.original_path);
    let source_raw = match read_jsonc_raw(&settings_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let vault_payload_raw = match read_jsonc_raw(&vault_payload) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    if let Err(reason) = prepare_zed_context_server_restore(
        &settings_path,
        &source_raw,
        server_id,
        &vault_payload,
        &vault_payload_raw,
        vault_entry.jsonc_format.as_ref(),
    ) {
        return blocked(item, reason);
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
                "Enable {} by restoring its vaulted Zed context_servers entry.",
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

pub(crate) fn apply_zed_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_zed_configured_mcp_vault_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_zed_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Zed configured MCP item id");
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
    let removal = match prepare_zed_context_server_removal(
        &source_raw,
        &server_id,
        item.source_fingerprint.as_deref(),
    ) {
        Ok(removal) => removal,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = removal.rendered;
    let vaulted_server_raw = removal.value_raw;
    let jsonc_format = removal.format;

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = zed_configured_mcp_vault_payload_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!("Zed settings file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

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
        fs::write(
            &vault_payload,
            format!("{}\n", vaulted_server_raw.trim_end()),
        )?;

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
            jsonc_format,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        write_provider_config(&source_path, &rendered)?;

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

pub(crate) fn apply_disabled_zed_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Zed configured MCP item id");
        }
    };
    let plan = plan_zed_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_zed_configured_mcp_vault_entry(&app_state_root, &item) {
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
    let vaulted_server_raw = match read_jsonc_raw(&vault_payload) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match prepare_zed_context_server_restore(
        &source_path,
        &source_raw,
        &server_id,
        &vault_payload,
        &vaulted_server_raw,
        vault_entry.jsonc_format.as_ref(),
    ) {
        Ok(rendered) => rendered,
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
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !source_path.is_file() {
        let reason = format!("Zed settings file not found: {}", source_path.display());
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

        write_provider_config(&source_path, &rendered)?;
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
