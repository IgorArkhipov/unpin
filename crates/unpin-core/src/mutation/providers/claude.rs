use super::super::*;

pub(crate) fn plan_claude_plugin_config_toggle(item: DiscoveryItem) -> ToggleResult {
    let plugin_id = match claude_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id,
        None => return blocked(item, "invalid Claude plugin config item id"),
    };
    let target_enabled = !item.enabled;
    let state_path = item.state_path.clone();
    let current_enabled = match read_claude_enabled_plugin(Path::new(&state_path), &plugin_id) {
        Ok(current_enabled) => current_enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude plugin state drifted for enabledPlugins.{plugin_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceJsonValue".to_string(),
            from_path: Some(state_path.clone()),
            to_path: None,
            summary: format!("Set enabledPlugins.{plugin_id} to {target_enabled}."),
            path: Some(state_path.clone()),
            json_path: Some(vec!["enabledPlugins".to_string(), plugin_id.clone()]),
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("enabledPlugins.{plugin_id}"),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_claude_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plugin_id = match claude_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id,
        None => {
            drop(lock);
            return blocked(item, "invalid Claude plugin config item id");
        }
    };
    let plan = plan_claude_plugin_config_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = set_claude_enabled_plugin(&mut document, &plugin_id, plan.target_enabled) {
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
        let reason = format!("Claude settings file not found: {}", item.state_path);
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

pub(crate) fn plan_claude_all_project_mcp_servers_toggle(item: DiscoveryItem) -> ToggleResult {
    let target_enabled = !item.enabled;
    let state_path = item.state_path.clone();
    let current_enabled = match read_claude_all_project_mcp_servers(Path::new(&state_path)) {
        Ok(current_enabled) => current_enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude all-project MCP state drifted: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceJsonValue".to_string(),
            from_path: Some(state_path.clone()),
            to_path: None,
            summary: format!("Set enableAllProjectMcpServers to {target_enabled}."),
            path: Some(state_path.clone()),
            json_path: Some(vec!["enableAllProjectMcpServers".to_string()]),
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: "enableAllProjectMcpServers".to_string(),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_claude_all_project_mcp_servers_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_claude_all_project_mcp_servers_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = set_claude_all_project_mcp_servers(&mut document, plan.target_enabled) {
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
        let reason = format!("Claude settings file not found: {}", item.state_path);
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

pub(crate) fn plan_claude_configured_mcp_toggle(item: DiscoveryItem) -> ToggleResult {
    let server_id = match claude_project_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Claude configured MCP item id"),
    };
    let settings_path = item.state_path.clone();
    let mcp_path = item.source_path.clone();
    let mcp_document = match read_json_value(Path::new(&mcp_path)) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };
    let payload = match claude_mcp_server_value(&mcp_document, &server_id) {
        Ok(payload) => payload,
        Err(reason) => return blocked(item, reason),
    };

    let current_enabled =
        match read_claude_configured_mcp_enabled(Path::new(&settings_path), &server_id) {
            Ok(current_enabled) => current_enabled,
            Err(reason) => return blocked(item, reason),
        };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude configured MCP state drifted for {server_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&payload);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "Claude configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;
    let action = if target_enabled { "Enable" } else { "Disable" };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(settings_path.clone()),
            to_path: None,
            summary: format!(
                "{action} Claude configured MCP {server_id} by rewriting project approval maps."
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: settings_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("enabledMcpjsonServers.{server_id}"),
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("disabledMcpjsonServers.{server_id}"),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_claude_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match claude_project_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Claude configured MCP item id");
        }
    };
    let plan = plan_claude_configured_mcp_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let mcp_document = match read_json_value(Path::new(&item.source_path)) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let payload = match claude_mcp_server_value(&mcp_document, &server_id) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) =
        set_claude_configured_mcp_approval(&mut document, &server_id, payload, plan.target_enabled)
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

    if !source_path.is_file() {
        let reason = format!("Claude settings file not found: {}", item.state_path);
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
