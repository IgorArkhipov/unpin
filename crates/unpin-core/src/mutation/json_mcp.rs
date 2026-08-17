use super::*;

pub(crate) fn plan_json_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };

    if !item.enabled && item.state_path.ends_with("entry.json") {
        return plan_disabled_json_configured_mcp_vault_toggle(app_state_root, item, &server_id);
    }

    if !item.enabled && is_cursor_workspace_state_path(&item) {
        return plan_cursor_workspace_configured_mcp_toggle(item, &server_id);
    }

    let config_path = PathBuf::from(&item.state_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };

    let server_value = match configured_json_mcp_server_value(&document, &item, &server_id) {
        Ok(server_value) => server_value,
        Err(reason) => return blocked(item, reason),
    };
    let current_enabled = if item.provider == ProviderId::Cursor {
        cursor_mcp_server_enabled_from_value(&server_value)
    } else {
        true
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "{provider_name} configured MCP state drifted for {server_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&server_value);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "{provider_name} configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    if !item.enabled {
        if item.provider != ProviderId::Cursor {
            return blocked(item, "disabled JSON MCP item is missing its vault entry");
        }
        if let Err(reason) = cursor_mcp_server_disabled_flag(&document, &server_id) {
            return blocked(item, reason);
        }

        return ToggleResult {
            status: ToggleStatus::DryRun,
            selection: item.clone(),
            target_enabled: true,
            operations: vec![MutationOperation {
                operation_type: "replaceFile".to_string(),
                from_path: Some(item.state_path.clone()),
                to_path: None,
                summary: format!(
                    "Enable {} by removing its Cursor mcpServers disabled flag.",
                    item.id
                ),
                path: None,
                json_path: None,
                value: None,
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
        };
    }

    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = json_configured_mcp_vault_payload_path(&app_state_root, &item);
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
                "Disable {} by removing its {provider_name} mcpServers entry and vaulting it.",
                item.id,
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

pub(crate) fn plan_disabled_json_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let provider_name = json_mcp_provider_name(item.provider);
    let vault_entry = match load_json_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let config_path = PathBuf::from(&vault_entry.original_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };
    match configured_json_mcp_server_present(&document, &item, server_id) {
        Ok(true) => {
            return blocked(
                item,
                format!(
                    "live-entry-conflict: {server_id} is already present in {}",
                    config_path.display()
                ),
            );
        }
        Ok(false) => {}
        Err(reason) => return blocked(item, reason),
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload = match read_json_value(&vault_payload) {
        Ok(payload) => payload,
        Err(reason) => return blocked(item, reason),
    };
    if !payload.is_object() {
        let reason = format!(
            "invalid-vault-payload: {} must contain a JSON object for {}",
            vault_payload.display(),
            item.id
        );
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
                "Enable {} by restoring its vaulted {provider_name} mcpServers entry.",
                item.id,
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

pub(crate) fn plan_cursor_workspace_configured_mcp_toggle(
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let config_path = PathBuf::from(&item.source_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };

    let server_value = match configured_json_mcp_server_value(&document, &item, server_id) {
        Ok(server_value) => server_value,
        Err(reason) => return blocked(item, reason),
    };
    let workspace_path = PathBuf::from(&item.state_path);
    let disabled_server_ids = match read_cursor_workspace_disabled_server_ids(&workspace_path) {
        Ok(disabled_server_ids) => disabled_server_ids,
        Err(reason) => return blocked(item, reason),
    };
    let workspace_server_id = cursor_workspace_server_id(server_id);
    let has_workspace_disabled = disabled_server_ids
        .iter()
        .any(|server_id| server_id == &workspace_server_id);
    let has_json_disabled = server_value.get("disabled").and_then(Value::as_bool) == Some(true);

    if !has_workspace_disabled && !has_json_disabled {
        return blocked(
            item,
            format!(
                "unsupported-live-disabled-entry: {server_id} is not disabled in a writable Cursor state source"
            ),
        );
    }

    let next_disabled_server_ids = disabled_server_ids
        .into_iter()
        .filter(|server_id| server_id != &workspace_server_id)
        .collect::<Vec<_>>();
    let mut operations = Vec::new();
    let mut affected_targets = Vec::new();

    if has_json_disabled {
        operations.push(MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.source_path.clone()),
            to_path: None,
            summary: format!(
                "Enable {} by removing its Cursor mcpServers disabled flag.",
                item.id
            ),
            path: Some(item.source_path.clone()),
            json_path: None,
            value: None,
        });
        affected_targets.push(MutationTarget {
            target_type: "statePath".to_string(),
            path: item.source_path.clone(),
        });
    }

    if has_workspace_disabled {
        operations.push(MutationOperation {
            operation_type: "replaceSqliteItemTableValue".to_string(),
            from_path: None,
            to_path: None,
            summary: format!(
                "Enable {} by removing it from Cursor workspace disabled MCP state.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Array(
                next_disabled_server_ids
                    .iter()
                    .map(|server_id| Value::String(server_id.clone()))
                    .collect(),
            )),
        });
        affected_targets.push(MutationTarget {
            target_type: "sqlite-item".to_string(),
            path: item.state_path.clone(),
        });
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled: true,
        operations,
        affected_targets,
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_json_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        if item.state_path.ends_with("entry.json") {
            return apply_disabled_json_configured_mcp_vault_toggle(
                app_state_root,
                item,
                backup_authentication_key,
            );
        }
        if is_cursor_workspace_state_path(&item) {
            return apply_cursor_workspace_configured_mcp_toggle(
                app_state_root,
                item,
                backup_authentication_key,
            );
        }
        if item.provider != ProviderId::Cursor {
            return blocked(item, "disabled JSON MCP item is missing its vault entry");
        }
        return apply_cursor_configured_mcp_disabled_flag_enable(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let server_value = match remove_configured_json_mcp_server(&mut document, &item, &server_id) {
        Ok(server_value) => server_value,
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
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = json_configured_mcp_vault_payload_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!(
            "{provider_name} MCP config file not found: {}",
            item.state_path
        );
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
        write_json_file(&vault_payload, &server_value)?;

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
            jsonc_format: None,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

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

pub(crate) fn apply_cursor_workspace_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match cursor_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Cursor configured MCP item id");
        }
    };
    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.source_path);
    let workspace_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let has_json_disabled = cursor_mcp_server_disabled_flag(&document, &server_id).is_ok();
    if has_json_disabled
        && let Err(reason) = remove_cursor_mcp_server_disabled_flag(&mut document, &server_id)
    {
        drop(lock);
        return blocked(item, reason);
    }

    let mut workspace_connection = match open_cursor_workspace_database(
        &workspace_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "begin write transaction for",
    ) {
        Ok(connection) => connection,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let workspace_transaction = match workspace_connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
    {
        Ok(transaction) => transaction,
        Err(error) => {
            let reason =
                cursor_workspace_database_error(&workspace_path, "reserve write access to", &error);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let workspace_raw = match read_cursor_workspace_disabled_server_ids_raw_from_connection(
        &workspace_transaction,
        &workspace_path,
    ) {
        Ok(Some(workspace_raw)) => workspace_raw,
        Ok(None) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(
                item,
                format!(
                    "Cursor workspace state is missing {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} in {}",
                    workspace_path.display()
                ),
            );
        }
        Err(reason) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let disabled_server_ids =
        match parse_cursor_workspace_disabled_server_ids(&workspace_path, &workspace_raw) {
            Ok(disabled_server_ids) => disabled_server_ids,
            Err(reason) => {
                drop(workspace_transaction);
                drop(lock);
                return blocked(item, reason);
            }
        };
    let workspace_server_id = cursor_workspace_server_id(&server_id);
    if !disabled_server_ids
        .iter()
        .any(|server_id| server_id == &workspace_server_id)
    {
        drop(workspace_transaction);
        drop(lock);
        return blocked(
            item,
            format!(
                "Cursor workspace state drifted for {server_id}: {workspace_server_id} is no longer disabled"
            ),
        );
    }
    let next_disabled_server_ids = disabled_server_ids
        .into_iter()
        .filter(|server_id| server_id != &workspace_server_id)
        .collect::<Vec<_>>();
    let next_workspace_raw = match serde_json::to_vec(&next_disabled_server_ids) {
        Ok(raw) => raw,
        Err(error) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, error.to_string());
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);

    if has_json_disabled && !source_path.is_file() {
        let reason = format!("Cursor mcp.json file not found: {}", source_path.display());
        drop(workspace_transaction);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(workspace_transaction);
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;

        let mut entries = Vec::new();
        let mut next_entry_id = 1usize;

        if has_json_disabled {
            let entry_id = format!("entry-{next_entry_id}");
            next_entry_id += 1;
            let backup_payload = backup_root.join("entries").join(&entry_id).join("payload");
            fs::create_dir_all(
                backup_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&source_path, &backup_payload)?;
            entries.push(BackupEntry {
                entry_id: entry_id.clone(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.source_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: entry_payload_path(&entry_id),
                }),
            });
        }

        let entry_id = format!("entry-{next_entry_id}");
        let backup_payload = backup_root.join("entries").join(&entry_id).join("payload");
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::write(&backup_payload, &workspace_raw)?;
        entries.push(BackupEntry {
            entry_id: entry_id.clone(),
            target: MutationTarget {
                target_type: "sqlite-item".to_string(),
                path: item.state_path.clone(),
            },
            existed: true,
            path_kind: None,
            payload: Some(BackupPayload {
                storage: "path".to_string(),
                path: entry_payload_path(&entry_id),
            }),
        });

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries,
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if has_json_disabled {
            let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
            write_provider_config(&source_path, format!("{rendered}\n"))?;
        }
        write_cursor_workspace_disabled_server_ids_raw_on_connection(
            &workspace_transaction,
            &workspace_path,
            &next_workspace_raw,
        )
        .map_err(io::Error::other)?;
        workspace_transaction.commit().map_err(|error| {
            io::Error::other(cursor_workspace_database_error(
                &workspace_path,
                "commit write transaction for",
                &error,
            ))
        })?;

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

pub(crate) fn apply_disabled_json_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };
    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_json_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    match configured_json_mcp_server_present(&document, &item, &server_id) {
        Ok(true) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "live-entry-conflict: {server_id} is already present in {}",
                    source_path.display()
                ),
            );
        }
        Ok(false) => {}
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let mut payload = match read_json_value(&vault_payload) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if item.provider == ProviderId::Cursor {
        if let Err(reason) = prepare_cursor_mcp_payload(&mut payload, &server_id) {
            drop(lock);
            return blocked(item, reason);
        }
    } else if !payload.is_object() {
        drop(lock);
        return blocked(
            item,
            format!("mcpServers.{server_id} vaulted payload is not an object"),
        );
    }
    if let Err(reason) =
        insert_configured_json_mcp_server(&mut document, &item, &server_id, payload)
    {
        drop(lock);
        return blocked(item, reason);
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

    if !source_path.is_file() {
        let reason = format!(
            "{provider_name} MCP config file not found: {}",
            source_path.display()
        );
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

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;
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

pub(crate) fn apply_cursor_configured_mcp_disabled_flag_enable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let server_id = match cursor_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Cursor configured MCP item id");
        }
    };

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = remove_cursor_mcp_server_disabled_flag(&mut document, &server_id) {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Cursor mcp.json file not found: {}", item.state_path);
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
            target_enabled: true,
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

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

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
