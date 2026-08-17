use super::*;

pub(crate) fn plan_path_file_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let noun = path_file_item_noun(&item);
    let title = path_file_item_title(&item);
    let target_enabled = !item.enabled;

    let (from_path, to_path, state_path, vault_path_string, summary) = if item.enabled {
        if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
            let current_fingerprint = match fs::read_to_string(&item.source_path) {
                Ok(raw) => source_fingerprint(&raw),
                Err(error) => {
                    let reason = format!(
                        "{noun} source could not be read: {}: {error}",
                        item.source_path
                    );
                    return blocked(item, reason);
                }
            };
            if current_fingerprint != discovered_fingerprint {
                let reason = format!(
                    "{title} source drifted for {}: discovered {discovered_fingerprint}, current {current_fingerprint}",
                    item.id
                );
                return blocked(item, reason);
            }
        }

        let state_path = item.state_path.clone();
        let vault_path_string = path_string(vault_path(&app_state_root, &item));
        let summary = format!(
            "Disable {} by moving its {noun} file into the Unpin vault.",
            item.id
        );
        (
            state_path.clone(),
            vault_path_string.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    } else {
        let vault_entry = match load_path_file_vault_entry(&app_state_root, &item) {
            Ok(vault_entry) => vault_entry,
            Err(reason) => return blocked(item, reason),
        };
        let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
        if !vault_payload.is_file() {
            return blocked(
                item,
                format!("vaulted {noun} file not found: {}", vault_payload.display()),
            );
        }
        let restore_target = PathBuf::from(&vault_entry.original_path);
        if restore_target.exists() {
            return blocked(
                item,
                format!(
                    "restore target already exists: {}",
                    restore_target.display()
                ),
            );
        }
        let state_path = vault_entry.original_path.clone();
        let vault_path_string = vault_entry.vaulted_path.clone();
        let summary = format!(
            "Enable {} by moving its {noun} file out of the Unpin vault.",
            item.id
        );
        (
            vault_path_string.clone(),
            state_path.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "renamePath".to_string(),
            from_path: Some(from_path),
            to_path: Some(to_path),
            summary,
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_path_string,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root_path(&app_state_root, &item).join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

pub(crate) fn apply_path_file_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_path_file_toggle(app_state_root, item, backup_authentication_key);
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_path_file_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let source_path = PathBuf::from(&item.state_path);
    let vault_payload = vault_path(&app_state_root, &item);
    let vault_root = vault_root_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!(
            "source {} file not found: {}",
            path_file_item_noun(&item),
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
        rename_mutation_path(&source_path, &vault_payload)?;

        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: item.kind.as_str().to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "path".to_string(),
            jsonc_format: None,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

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

pub(crate) fn apply_disabled_path_file_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let vault_entry = match load_path_file_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_path_file_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        return plan;
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let restore_target = PathBuf::from(&vault_entry.original_path);
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !vault_payload.is_file() {
        let noun = path_file_item_noun(&item);
        return blocked(
            item,
            format!(
                "vaulted {} file not found: {}",
                noun,
                vault_payload.display()
            ),
        );
    }

    if restore_target.exists() {
        return blocked(
            item,
            format!(
                "restore target already exists: {}",
                restore_target.display()
            ),
        );
    }

    if backup_root.exists() {
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
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
                    existed: false,
                    path_kind: None,
                    payload: None,
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

        if let Some(parent) = restore_target.parent() {
            fs::create_dir_all(parent)?;
        }
        rename_mutation_path(&vault_payload, &restore_target)?;
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
