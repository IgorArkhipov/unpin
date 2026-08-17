use super::super::*;

pub(crate) fn plan_pi_package_extension_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => return blocked(item, "invalid Pi package extension item id"),
    };
    let settings_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&settings_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    settings_path.display()
                ),
            );
        }
    };

    let vault = if item.enabled {
        if let Err(reason) =
            prepare_pi_package_disable(&raw, &package_source, item.source_fingerprint.as_deref())
        {
            return blocked(item, reason);
        }
        None
    } else {
        let vault = match load_optional_pi_package_vault(&app_state_root, &item, &package_source) {
            Ok(vault) => vault,
            Err(reason) => return blocked(item, reason),
        };
        if let Err(reason) = prepare_pi_package_enable(
            &raw,
            &package_source,
            item.source_fingerprint.as_deref(),
            vault.as_ref().map(|(_, payload)| payload),
        ) {
            return blocked(item, reason);
        }
        vault
    };

    let target_enabled = !item.enabled;
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    let mut affected_targets = vec![MutationTarget {
        target_type: "statePath".to_string(),
        path: item.state_path.clone(),
    }];
    if item.enabled || vault.is_some() {
        affected_targets.extend([
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: path_string(vault_payload.clone()),
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ]);
    }
    let action = if target_enabled { "Enable" } else { "Disable" };
    let summary = if target_enabled && vault.is_some() {
        format!(
            "{action} {} by restoring its Pi package extension filter while keeping the package installed. Restart Pi to load the change.",
            item.id
        )
    } else if target_enabled {
        format!(
            "{action} {} by removing its empty Pi package extension filter so all package extensions load while keeping the package installed. Restart Pi to load the change.",
            item.id
        )
    } else {
        format!(
            "{action} {} by setting packages[].extensions to an empty array while keeping the package reference and other resources. Restart Pi to load the change.",
            item.id
        )
    };
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: (item.enabled || vault.is_some()).then(|| path_string(vault_payload)),
            summary,
            path: Some(item.state_path.clone()),
            json_path: Some(vec![
                "packages".to_string(),
                package_source,
                "extensions".to_string(),
            ]),
            value: (!target_enabled).then(|| Value::Array(Vec::new())),
        }],
        affected_targets,
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_pi_package_extension_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if item.enabled {
        apply_pi_package_extension_disable(app_state_root, item, backup_authentication_key)
    } else {
        apply_pi_package_extension_enable(app_state_root, item, backup_authentication_key)
    }
}

pub(crate) fn apply_pi_package_extension_disable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_pi_package_extension_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Pi package extension item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    source_path.display()
                ),
            );
        }
    };
    let rewrite =
        match prepare_pi_package_disable(&raw, &package_source, item.source_fingerprint.as_deref())
        {
            Ok(rewrite) => rewrite,
            Err(reason) => {
                drop(lock);
                return blocked(item, reason);
            }
        };
    let payload = rewrite
        .payload
        .expect("Pi disable rewrite includes vault payload");
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("Pi settings file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries/entry-1/payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }
    match fs::symlink_metadata(&vault_root) {
        Ok(_) => {
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            drop(lock);
            return blocked(item, error.to_string());
        }
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
        write_json_file(&vault_payload, &payload)?;
        write_json_file(
            &vault_root.join("entry.json"),
            &VaultEntry {
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
            },
        )?;
        write_provider_config(&source_path, rewrite.rendered)?;
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

pub(crate) fn apply_pi_package_extension_enable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_pi_package_extension_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Pi package extension item id");
        }
    };
    let vault = match load_optional_pi_package_vault(&app_state_root, &item, &package_source) {
        Ok(vault) => vault,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    source_path.display()
                ),
            );
        }
    };
    let rewrite = match prepare_pi_package_enable(
        &raw,
        &package_source,
        item.source_fingerprint.as_deref(),
        vault.as_ref().map(|(_, payload)| payload),
    ) {
        Ok(rewrite) => rewrite,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("Pi settings file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries/entry-1/payload");
    let backup_vault_payload = backup_root.join("entries/entry-2/payload");
    let backup_vault_entry = backup_root.join("entries/entry-3/payload");
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

        let mut entries = vec![BackupEntry {
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
        }];
        if let Some((vault_entry, _)) = &vault {
            fs::create_dir_all(
                backup_vault_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&vault_entry.vaulted_path, &backup_vault_payload)?;
            fs::create_dir_all(
                backup_vault_entry
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&vault_entry_path, &backup_vault_entry)?;
            entries.extend([
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
            ]);
        }
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

        write_provider_config(&source_path, rewrite.rendered)?;
        if vault.is_some() {
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
