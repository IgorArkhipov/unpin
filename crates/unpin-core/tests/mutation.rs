use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process,
};

use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unpin_core::{
    control_operation::{DurableControlError, ReachAwareRootBinding},
    discovery::{DiscoveryItem, DiscoveryMutability, DiscoveryRoots, ProviderId, discover_all},
    mutation::{
        BackupAuthenticationKey, BackupAuthenticationStatus, NativeToggleControlError,
        NativeToggleController, RestoreBackupInput, RestoreControlError, RestoreController,
        RestoreStatus, TogglePlanRequest, ToggleResult, ToggleStatus, authenticate_legacy_backup,
        load_backup_summaries_authenticated, plan_toggle as core_plan_toggle, restore_backup,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, ProviderReach, ProviderReachError,
        ProviderReachInput, ProviderReachRequest, SelectedProviderProvenance,
    },
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
    state::atomic_json::OwnerGeneration,
    transitions::{
        EffectAuthority, EffectCheckpointStatus, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionJournalStore, TransitionKind, TransitionLifecycle,
        TransitionPlan,
    },
};

mod support;

use support::{control_authorization, control_context};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn backup_authentication_key() -> BackupAuthenticationKey {
    BackupAuthenticationKey::new([0x42; 32])
}

fn session_authority_key() -> SessionAuthorityKey {
    SessionAuthorityKey::new([0x53; 32])
}

#[test]
fn apply_audit_failure_preserves_recovery_evidence_after_directory_move() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("Claude skill");
    let source_path = PathBuf::from(&item.state_path);
    fs::create_dir_all(app_state.path().join("audit/log.jsonl"))
        .expect("audit log path that rejects append");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::RecoveryRequired);
    let backup_id = result
        .backup_id
        .as_deref()
        .expect("failed apply must expose its backup id");
    assert!(
        result
            .writes
            .as_deref()
            .is_some_and(|writes| writes.contains("may already have been performed"))
    );
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("recovery-required"))
    );
    assert!(app_state.path().join("backups").join(backup_id).is_dir());
    assert!(
        !source_path.exists(),
        "the test must reach the post-mutation audit failure"
    );
}

#[test]
fn reach_aware_native_wrapper_rejects_context_drift_before_writes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state root");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill");
    let context = control_context("reach-aware-repository", "reach-aware-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let authorization = control_authorization(
        &app_state_root,
        &plan
            .approval_expectation(&context)
            .expect("approval expectation"),
        "reach-aware-context-drift",
        2_000_000_000,
    );
    let provider_root = fixture_copy.path().join("codex").join("global");
    let roots = ReachAwareRootBinding::from_provider_paths(
        &app_state_root,
        vec![(
            ProviderId::Codex,
            provider_root,
            "fixture-codex".to_string(),
        )],
        "fixture",
    )
    .expect("trusted roots");
    let result = controller.apply_with_reach_aware(
        &plan,
        authorization,
        &control_context("drifted-repository", "reach-aware-workspace"),
        backup_authentication_key(),
        roots,
        "unpin-test-audience",
        100,
        200,
    );
    assert!(matches!(
        result,
        Err(NativeToggleControlError::ContextMismatch)
    ));
    assert!(!app_state_root.join("transactions").exists());
    assert!(!app_state_root.join("backups").exists());
}

fn sha256_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(value) {
        write!(&mut encoded, "{byte:02x}").expect("write digest");
    }
    encoded
}

#[derive(Clone)]
struct TogglePlanInput {
    app_state_root: PathBuf,
    item: DiscoveryItem,
    apply: bool,
    backup_authentication_key: Option<BackupAuthenticationKey>,
}

fn core_toggle_plan(input: &TogglePlanInput) -> ToggleResult {
    core_plan_toggle(TogglePlanRequest {
        app_state_root: input.app_state_root.clone(),
        item: input.item.clone(),
    })
}

fn plan_toggle(mut input: TogglePlanInput) -> ToggleResult {
    if let Ok(app_state_root) = fs::canonicalize(&input.app_state_root) {
        input.app_state_root = app_state_root;
    }
    if !input.apply {
        return core_toggle_plan(&input);
    }

    fs::create_dir_all(&input.app_state_root).expect("create test app state root");
    let app_state_root = fs::canonicalize(&input.app_state_root).expect("canonical app state root");
    let mut preview_input = input.clone();
    preview_input.app_state_root = app_state_root.clone();
    preview_input.apply = false;
    preview_input.backup_authentication_key = None;
    let mut preview = core_toggle_plan(&preview_input);
    if preview.status != ToggleStatus::DryRun {
        return preview;
    }
    let Some(backup_key) = input.backup_authentication_key else {
        preview.status = ToggleStatus::Blocked;
        preview.reason = Some("backup authentication key is required before apply".to_string());
        return preview;
    };

    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = match controller.plan(input.item, &context) {
        Ok(plan) => plan,
        Err(NativeToggleControlError::Blocked(reason)) => {
            preview.status = ToggleStatus::Blocked;
            preview.reason = Some(reason);
            return preview;
        }
        Err(error) => {
            preview.status = ToggleStatus::Blocked;
            preview.reason = Some(error.to_string());
            return preview;
        }
    };
    let marker = plan.transition.operation_id.as_str();
    let authorization = control_authorization(
        &app_state_root,
        &plan
            .approval_expectation(&context)
            .expect("toggle approval expectation"),
        marker,
        2_000_000_000,
    );
    match controller.apply(&plan, authorization, &context, backup_key) {
        Ok(result) => result,
        Err(NativeToggleControlError::Blocked(reason)) => {
            preview.status = ToggleStatus::Blocked;
            preview.reason = Some(reason);
            preview
        }
        Err(error) => {
            preview.status = ToggleStatus::Blocked;
            preview.reason = Some(error.to_string());
            preview
        }
    }
}

fn authenticate_backup(app_state_root: &Path, backup_id: &str) {
    authenticate_legacy_backup(app_state_root, backup_id, &backup_authentication_key())
        .expect("authenticate legacy backup");
}

fn apply_example_skill_backup(
    fixture_root: &Path,
    app_state_root: &Path,
) -> (unpin_core::discovery::DiscoveryItem, String) {
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixture_root)).expect("fixture discovery");
    let item = discovery
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state_root.to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(result.status, ToggleStatus::Applied, "{result:?}");
    (
        item,
        result.backup_id.expect("applied toggle has backup id"),
    )
}

fn copy_dir_all(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("copy file");
        }
    }
}

fn backup_count(app_state_root: &Path) -> usize {
    fs::read_dir(app_state_root.join("backups"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn audit_log(app_state_root: &Path) -> Option<String> {
    fs::read_to_string(app_state_root.join("audit").join("log.jsonl")).ok()
}

fn hold_mutation_lock(app_state_root: &Path, contents: &str) -> fs::File {
    let lock_dir = app_state_root.join("locks");
    let lock_path = lock_dir.join("mutation.lock");
    fs::create_dir_all(&lock_dir).expect("locks dir");
    fs::write(&lock_path, contents).expect("lock file");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .expect("open lock file");
    lock_file.try_lock().expect("hold mutation lock");
    lock_file
}

fn write_file_restore_manifest(backup_root: &Path, backup_id: &str, target_path: &Path) {
    write_file_restore_manifest_with_target_enabled(backup_root, backup_id, target_path, true);
}

fn write_file_restore_manifest_with_target_enabled(
    backup_root: &Path,
    backup_id: &str,
    target_path: &Path,
    target_enabled: bool,
) {
    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": backup_id,
                "createdAt": "2026-07-13T12:00:00Z",
                "selection": {
                    "provider": "claude",
                    "kind": "mcp",
                    "category": "configured-mcp",
                    "layer": "global",
                    "id": "claude:global:configured-mcp:example",
                    "displayName": "example",
                    "enabled": false,
                    "mutability": "read-write",
                    "sourcePath": target_path.to_string_lossy(),
                    "statePath": target_path.to_string_lossy()
                },
                "targetEnabled": target_enabled,
                "affectedTargets": [
                    { "targetType": "statePath", "path": target_path.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": target_path.to_string_lossy() },
                        "existed": true,
                        "pathKind": "file",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");
}

fn settings_plugin_enabled(path: &Path, plugin_id: &str) -> bool {
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("settings json"))
            .expect("settings value");
    value["enabledPlugins"][plugin_id]
        .as_bool()
        .unwrap_or_else(|| panic!("enabledPlugins.{plugin_id} should be boolean"))
}

fn cursor_mcp_server(path: &Path, server_id: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("cursor mcp json"))
            .expect("cursor mcp value");
    value["mcpServers"].as_object()?.get(server_id).cloned()
}

fn zed_context_server(path: &Path, server_id: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = jsonc_parser::parse_to_serde_value(
        &fs::read_to_string(path).expect("zed settings JSONC"),
        &Default::default(),
    )
    .expect("zed settings value");
    value["context_servers"]
        .as_object()?
        .get(server_id)
        .cloned()
}

fn write_cursor_workspace_disabled_servers(
    cursor_root: &Path,
    project_root: &Path,
    disabled_server_ids: &[&str],
) -> PathBuf {
    let workspace_root = cursor_root
        .join("workspaceStorage")
        .join("sandbox-workspace");
    let database_path = workspace_root.join("state.vscdb");
    fs::create_dir_all(&workspace_root).expect("create cursor workspace storage");
    fs::write(
        workspace_root.join("workspace.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "folder": project_file_url(project_root)
        }))
        .expect("workspace json"),
    )
    .expect("write workspace json");

    let connection = Connection::open(&database_path).expect("open cursor workspace database");
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )
        .expect("create ItemTable");
    let raw_value = serde_json::to_string(disabled_server_ids).expect("disabled servers serialize");
    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("cursor/disabledMcpServers", raw_value.as_bytes()),
        )
        .expect("write disabled MCP state");

    database_path
}

fn read_cursor_workspace_disabled_servers(database_path: &Path) -> Vec<String> {
    let connection = Connection::open(database_path).expect("open cursor workspace database");
    let raw_value: Vec<u8> = connection
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1",
            ["cursor/disabledMcpServers"],
            |row| row.get(0),
        )
        .expect("disabled MCP state row");
    serde_json::from_slice(&raw_value).expect("disabled MCP state json")
}

fn project_file_url(project_root: &Path) -> String {
    format!("file://{}", project_root.display())
}

#[test]
fn blocks_apply_when_backup_authentication_key_is_missing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill")
        .clone();
    let state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(
        result.reason.as_deref(),
        Some("backup authentication key is required before apply")
    );
    assert!(state_path.exists());
    assert_eq!(backup_count(app_state.path()), 0);
    assert!(audit_log(app_state.path()).is_none());
}

#[test]
fn blocks_restore_when_backup_authentication_key_is_missing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), app_state.path());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: None,
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("backup authentication key is required for restore")
    );
    assert!(!Path::new(&item.state_path).exists());
    assert_eq!(
        audit_log(app_state.path())
            .expect("apply audit")
            .lines()
            .count(),
        1
    );
}

#[test]
fn exact_restore_retry_returns_cached_result_without_another_restore_or_backup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), &root);
    let key = backup_authentication_key();
    let controller = RestoreController::with_session_authority_key(&root, session_authority_key());
    let context = control_context("test-repository", "test-workspace");
    let plan = controller
        .plan(&backup_id, &context, Some(&key))
        .expect("restore control plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("restore approval expectation");
    let authorization =
        control_authorization(&root, &expectation, "restore-exact-retry", 2_000_000_000);
    let backups_before_restore = backup_count(&root);

    let restored = controller
        .apply(&plan, authorization, &context, Some(key.clone()))
        .expect("restore apply");
    assert_eq!(restored.status, RestoreStatus::Restored);
    let audit_lines_after_restore = audit_log(&root)
        .expect("toggle and restore audit")
        .lines()
        .count();

    let retry_authorization =
        control_authorization(&root, &expectation, "restore-exact-retry", 2_000_000_000);
    let retried = controller
        .apply(&plan, retry_authorization, &context, Some(key.clone()))
        .expect("exact restore retry");

    assert_eq!(retried, restored);
    assert_eq!(backup_count(&root), backups_before_restore);
    assert_eq!(
        audit_log(&root).expect("audit after retry").lines().count(),
        audit_lines_after_restore
    );

    let restored_path = Path::new(&item.state_path);
    let metadata = fs::symlink_metadata(restored_path).expect("restored target metadata");
    if metadata.is_dir() {
        fs::write(restored_path.join("unexpected-file"), b"external change")
            .expect("tamper restored directory");
    } else {
        fs::write(restored_path, b"external change").expect("tamper restored file");
    }
    let divergent_retry_authorization =
        control_authorization(&root, &expectation, "restore-exact-retry", 2_000_000_000);
    let error = controller
        .apply(&plan, divergent_retry_authorization, &context, Some(key))
        .expect_err("cached restore must verify live target state");
    assert!(matches!(
        error,
        RestoreControlError::Durable(DurableControlError::RecoveryRequired(_))
    ));
}

#[test]
fn restore_plan_fingerprint_is_bound_to_repository_and_workspace() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (_, backup_id) = apply_example_skill_backup(fixture_copy.path(), &root);
    let key = backup_authentication_key();
    let controller = RestoreController::new(&root);
    let first_context = control_context("repository-a", "workspace-a");
    let second_context = control_context("repository-a", "workspace-b");

    let first = controller
        .plan(&backup_id, &first_context, Some(&key))
        .expect("first restore plan");
    let second = controller
        .plan(&backup_id, &second_context, Some(&key))
        .expect("second restore plan");

    assert_ne!(first.plan_fingerprint, second.plan_fingerprint);
    assert!(matches!(
        first.approval_expectation(&second_context),
        Err(RestoreControlError::ContextMismatch)
    ));
}

#[test]
fn interrupted_restore_after_target_write_resumes_as_committed() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), &root);
    let key = backup_authentication_key();
    let controller = RestoreController::with_session_authority_key(&root, session_authority_key());
    let context = control_context("test-repository", "test-workspace");
    let plan = controller
        .plan(&backup_id, &context, Some(&key))
        .expect("restore control plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("restore approval expectation");
    let authorization = control_authorization(
        &root,
        &expectation,
        "restore-interrupted-after-write",
        2_000_000_000,
    );
    let effects = plan
        .affected_resources
        .iter()
        .enumerate()
        .map(|(index, resource)| TransitionEffect {
            effect_id: format!("restore-effect-{index}"),
            kind: TransitionEffectKind::RestoreView,
            resource_id: resource.resource_id.clone(),
            target_type: "restore-target".to_string(),
            summary: "Restore authenticated backup target".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: plan.activation,
            expected_pre_fingerprint: Some(resource.pre_state_fingerprint.clone()),
            expected_post_fingerprint: Some(sha256_hex(
                format!("{}:{}", plan.backup_id, resource.resource_id).as_bytes(),
            )),
            provider_views: vec![plan.provider],
        })
        .collect();
    let transition = TransitionPlan::new(
        expectation.operation_id.clone(),
        TransitionKind::RestoreNative,
        TransitionContext {
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: None,
            profile_digest: None,
        },
        effects,
    )
    .expect("restore transition plan");
    let journal_store = TransitionJournalStore::new(&root);
    let journal_owner = format!(
        "control-{}",
        &sha256_hex(transition.operation_id.as_bytes())[..32]
    );
    let mut journal = journal_store
        .create_or_attach(&transition, OwnerGeneration::new(journal_owner, 1).unwrap())
        .expect("create restore journal");
    journal.journal.authorization_decision_digest =
        Some(authorization.decision_digest().to_string());
    journal
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .unwrap();
    journal_store.save(&mut journal).unwrap();
    journal
        .journal
        .record(TransitionLifecycle::Applying, "control-applying", None)
        .unwrap();
    journal_store.save(&mut journal).unwrap();

    let restored_before_commit = restore_backup(RestoreBackupInput {
        app_state_root: root.clone(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(key.clone()),
    });
    assert_eq!(restored_before_commit.status, RestoreStatus::Restored);
    assert!(Path::new(&item.state_path).exists());

    let resumed = controller
        .apply(&plan, authorization, &context, Some(key))
        .expect("resume restore journal after target write");
    assert_eq!(resumed.status, RestoreStatus::Restored);
    let committed = journal_store
        .list()
        .unwrap()
        .into_iter()
        .find(|journal| journal.operation_id == expectation.operation_id)
        .unwrap();
    assert_eq!(committed.lifecycle, TransitionLifecycle::Committed);
}

#[test]
fn restore_lock_contention_prevents_journal_and_target_changes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), &root);
    let key = backup_authentication_key();
    let controller = RestoreController::with_session_authority_key(&root, session_authority_key());
    let context = control_context("test-repository", "test-workspace");
    let plan = controller.plan(&backup_id, &context, Some(&key)).unwrap();
    let expectation = plan.approval_expectation(&context).unwrap();
    let authorization = control_authorization(
        &root,
        &expectation,
        "restore-lock-contention",
        2_000_000_000,
    );
    let lock_dir = root.join("locks");
    fs::create_dir_all(&lock_dir).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_dir.join("mutation.lock"))
        .unwrap();
    lock.try_lock().unwrap();

    let error = controller
        .apply(&plan, authorization, &context, Some(key))
        .expect_err("held mutation lock must block restore");

    assert!(matches!(error, RestoreControlError::MutationLock(_)));
    assert!(!Path::new(&item.state_path).exists());
    assert!(
        TransitionJournalStore::new(&root)
            .list()
            .unwrap()
            .into_iter()
            .all(|journal| journal.operation_id != expectation.operation_id)
    );
}

#[test]
fn reviewed_restore_apply_honors_active_session_conflict_guard() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), &root);
    let key = backup_authentication_key();
    let context = control_context("test-repository", "test-workspace");
    let controller = RestoreController::with_session_authority_key(&root, session_authority_key());
    let plan = controller
        .plan(&backup_id, &context, Some(&key))
        .expect("restore control plan");
    let protected_resource = plan.affected_resources[0].resource_id.clone();
    let sessions = SessionManager::with_authority_key(&root, session_authority_key());
    let request = BootstrapRequest {
        provider: plan.provider,
        repository_key: "repository-key".to_string(),
        workspace_key: "workspace-key".to_string(),
        workspace_revision: None,
        exposure: PinnedExposure {
            revision: "e".repeat(64),
            profile: PinnedProfile::None,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: process::id(),
            start_marker: "restore-conflict-process".to_string(),
        },
        connection_scope_id: "restore-conflict-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([protected_resource.clone()]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "restore-conflict-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = sessions
        .prepare_bootstrap(request, 1_000)
        .expect("prepare session");
    let session = sessions
        .claim_bootstrap(&authority, &claim, 1_001)
        .expect("claim session");
    let expectation = plan
        .approval_expectation(&context)
        .expect("restore approval expectation");
    let authorization =
        control_authorization(&root, &expectation, "restore-conflict", 2_000_000_000);

    let error = controller
        .apply(&plan, authorization, &context, Some(key))
        .expect_err("active session must block restore");

    assert!(error.to_string().contains(&protected_resource));
    assert!(!Path::new(&item.state_path).exists());
    sessions
        .close_owned(
            &session.handle,
            &session.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close session");
}

#[test]
fn authenticated_backup_detects_payload_tampering_and_wrong_key() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), app_state.path());
    let key = backup_authentication_key();

    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].restorable);
    assert_eq!(
        summaries[0].authentication,
        BackupAuthenticationStatus::Verified
    );
    let without_key = load_backup_summaries_authenticated(app_state.path(), None);
    assert_eq!(
        without_key[0].authentication,
        BackupAuthenticationStatus::KeyUnavailable
    );
    assert!(!without_key[0].restorable);
    let wrong_key = BackupAuthenticationKey::new([0x24; 32]);
    let with_wrong_key = load_backup_summaries_authenticated(app_state.path(), Some(&wrong_key));
    assert_eq!(
        with_wrong_key[0].authentication,
        BackupAuthenticationStatus::Failed
    );

    let backup_root = app_state.path().join("backups").join(&backup_id);
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(backup_root.join("manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["version"], 3);
    assert_eq!(
        manifest["authenticity"]["algorithm"],
        "hmac-sha256-unpin-backup-v1"
    );
    assert_eq!(
        manifest["authenticity"]["keyId"],
        backup_authentication_key().key_id()
    );
    assert_eq!(
        manifest["authenticity"]["tag"]
            .as_str()
            .expect("authentication tag")
            .len(),
        64
    );

    fs::write(
        backup_root.join("entries/entry-1/payload/SKILL.md"),
        "# tampered\n",
    )
    .expect("tamper backup payload");
    let tampered = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        tampered[0].authentication,
        BackupAuthenticationStatus::Failed
    );
    assert!(!tampered[0].restorable);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(key),
    });
    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payload authentication failed"))
    );
    assert!(!Path::new(&item.state_path).exists());
    assert_eq!(
        audit_log(app_state.path())
            .expect("apply audit")
            .lines()
            .count(),
        1
    );
}

#[test]
fn authenticated_backup_detects_manifest_tampering_before_restore() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let (item, backup_id) = apply_example_skill_backup(fixture_copy.path(), app_state.path());
    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest"))
            .expect("manifest JSON");
    manifest["targetEnabled"] = serde_json::json!(true);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("tamper manifest");

    let key = backup_authentication_key();
    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        summaries[0].authentication,
        BackupAuthenticationStatus::Failed
    );
    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(key),
    });
    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("backup manifest authentication failed")
    );
    assert!(!Path::new(&item.state_path).exists());
}

#[test]
fn legacy_backup_is_inventory_only_until_explicitly_authenticated() {
    let app_state = TempDir::new().expect("temp app state");
    let backup_id = "backup-legacy";
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state.path().join("backups").join(backup_id);
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "legacy\n").expect("backup payload");
    write_file_restore_manifest(&backup_root, backup_id, &target_path);
    let key = backup_authentication_key();

    let legacy = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        legacy[0].authentication,
        BackupAuthenticationStatus::LegacyUnauthenticated
    );
    assert!(!legacy[0].restorable);
    let blocked = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.to_string(),
        backup_authentication_key: Some(key.clone()),
    });
    assert_eq!(blocked.status, RestoreStatus::Failed);
    assert_eq!(
        blocked.reason.as_deref(),
        Some("legacy backup is unauthenticated; restore is blocked")
    );

    authenticate_legacy_backup(app_state.path(), backup_id, &key)
        .expect("authenticate trusted legacy backup");
    let authenticated = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        authenticated[0].authentication,
        BackupAuthenticationStatus::Verified
    );
    assert!(authenticated[0].restorable);
    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.to_string(),
        backup_authentication_key: Some(key),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(target_path).expect("restored target"),
        "legacy\n"
    );
}

#[test]
fn restore_rejects_entries_outside_the_reviewed_target_allowlist() {
    let app_state = TempDir::new().expect("temp app state");
    let backup_id = "backup-hidden-target";
    let reviewed_target = app_state.path().join("live/settings.json");
    let hidden_target = app_state.path().join("live/hidden.json");
    let backup_root = app_state.path().join("backups").join(backup_id);
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "reviewed\n").expect("backup payload");
    write_file_restore_manifest(&backup_root, backup_id, &reviewed_target);

    let manifest_path = backup_root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest json");
    manifest["entries"]
        .as_array_mut()
        .expect("manifest entries")
        .push(serde_json::json!({
            "entryId": "entry-hidden",
            "target": {
                "targetType": "path",
                "path": hidden_target.to_string_lossy()
            },
            "existed": false
        }));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("encode manifest"),
    )
    .expect("write hidden target manifest");

    let key = backup_authentication_key();
    assert_eq!(
        authenticate_legacy_backup(app_state.path(), backup_id, &key),
        Err(
            "backup entry entry-hidden target is not declared in the restore allowlist".to_string()
        )
    );
    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        summaries[0].authentication,
        BackupAuthenticationStatus::Failed
    );
    assert!(!summaries[0].restorable);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.to_string(),
        backup_authentication_key: Some(key),
    });
    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("backup entry entry-hidden target is not declared in the restore allowlist")
    );
    assert!(!reviewed_target.exists());
    assert!(!hidden_target.exists());
}

#[test]
fn version_two_backup_manifests_are_not_accepted() {
    let app_state = TempDir::new().expect("temp app state");
    let backup_id = "backup-version-two";
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state.path().join("backups").join(backup_id);
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "legacy\n").expect("backup payload");
    write_file_restore_manifest(&backup_root, backup_id, &target_path);

    let manifest_path = backup_root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest json");
    manifest["version"] = serde_json::json!(2);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("encode manifest"),
    )
    .expect("write version two manifest");

    let key = backup_authentication_key();
    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    assert_eq!(
        summaries[0].authentication,
        BackupAuthenticationStatus::Failed
    );
    assert!(!summaries[0].restorable);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.to_string(),
        backup_authentication_key: Some(key),
    });
    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("unsupported backup manifest version: 2")
    );
    assert!(!target_path.exists());
}

#[test]
fn plans_skill_disable_as_vault_rename_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "renamePath");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault path")
            .contains("/vault/claude/project/skill/")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn signed_toggle_apply_honors_active_session_conflict_guard() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill")
        .clone();
    let context = control_context("test-repository", "test-workspace");
    let protected_resource = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    )
    .plan(item.clone(), &context)
    .expect("native toggle plan")
    .transition
    .effects[0]
        .resource_id
        .clone();
    let sessions = SessionManager::with_authority_key(&app_state_root, session_authority_key());
    let request = BootstrapRequest {
        provider: ProviderId::Claude,
        repository_key: "repository-key".to_string(),
        workspace_key: "workspace-key".to_string(),
        workspace_revision: None,
        exposure: PinnedExposure {
            revision: "e".repeat(64),
            profile: PinnedProfile::None,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: process::id(),
            start_marker: "mutation-test-process".to_string(),
        },
        connection_scope_id: "mutation-test-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([protected_resource.clone()]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "mutation-test-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = sessions
        .prepare_bootstrap(request, 1_000)
        .expect("prepare session");
    let session = sessions
        .claim_bootstrap(&authority, &claim, 1_001)
        .expect("claim session");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state_root.clone(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(result.status, ToggleStatus::Blocked, "{result:?}");
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains(&format!("active-lease-{protected_resource}"))
    );
    assert!(!result.reason.as_deref().unwrap().contains("gateway mode"));
    assert!(Path::new(&item.state_path).exists());
    assert_eq!(backup_count(&app_state_root), 0);
    assert!(
        TransitionJournalStore::new(&app_state_root)
            .list()
            .expect("toggle journals")
            .is_empty()
    );
    sessions
        .close_owned(
            &session.handle,
            &session.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close session");
}

#[test]
fn exact_native_toggle_retry_verifies_authenticated_live_post_state() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let key = backup_authentication_key();
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-exact-retry",
        2_000_000_000,
    );
    let first_decision_digest = authorization.decision_digest().to_string();
    let applied = controller
        .apply(&plan, authorization, &context, key.clone())
        .expect("native toggle apply");
    assert_eq!(applied.provider_reach, Some(plan.provider_reach));
    assert_eq!(applied.coverage.as_ref(), Some(&plan.coverage));
    let backup_id = applied.backup_id.clone().expect("native toggle backup");
    let committed = TransitionJournalStore::new(&app_state_root)
        .list()
        .expect("native toggle journals")
        .into_iter()
        .find(|journal| journal.operation_id == plan.transition.operation_id)
        .expect("committed native toggle journal");
    assert_eq!(
        committed.authorization_decision_history,
        vec![first_decision_digest]
    );

    let exact_retry_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-exact-retry",
        2_000_000_000,
    );
    let exact_retry = controller
        .apply(&plan, exact_retry_authorization, &context, key.clone())
        .expect("verified exact native toggle retry");
    assert_eq!(exact_retry.status, ToggleStatus::Applied);
    assert_eq!(exact_retry.provider_reach, Some(plan.provider_reach));
    assert_eq!(exact_retry.coverage.as_ref(), Some(&plan.coverage));
    assert_eq!(exact_retry.backup_id.as_deref(), Some(backup_id.as_str()));

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state_root.clone(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(key.clone()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    let divergent_retry_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-exact-retry",
        2_000_000_000,
    );
    let recovery = controller
        .apply(&plan, divergent_retry_authorization, &context, key)
        .expect("cached native toggle must surface live post-state recovery evidence");
    assert_eq!(recovery.status, ToggleStatus::RecoveryRequired);
    assert_eq!(recovery.backup_id.as_deref(), Some(backup_id.as_str()));
    assert!(
        recovery
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("post-state diverged"))
    );
}

#[test]
fn interrupted_native_toggle_accepts_refreshed_approval_before_writes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let first_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-interrupted-first",
        2_000_000_000,
    );
    let first_digest = first_authorization.decision_digest().to_string();
    let store = TransitionJournalStore::new(&app_state_root);
    let mut interrupted = store
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("interrupted native toggle journal");
    interrupted.journal.authorization_decision_digest = Some(first_digest.clone());
    interrupted
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .expect("approval checkpoint");
    interrupted
        .journal
        .record(
            TransitionLifecycle::Locked,
            "legacy-mutation-lock-delegated",
            None,
        )
        .expect("lock checkpoint");
    interrupted
        .journal
        .record(
            TransitionLifecycle::Applying,
            "legacy-apply-started",
            Some("native-toggle-effect"),
        )
        .expect("apply checkpoint");
    store
        .save(&mut interrupted)
        .expect("save interrupted journal");

    let refreshed_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-interrupted-refreshed",
        2_000_000_000,
    );
    let refreshed_digest = refreshed_authorization.decision_digest().to_string();
    let result = controller
        .apply(
            &plan,
            refreshed_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect("safe pre-write interruption must accept refreshed approval");

    assert_eq!(result.status, ToggleStatus::Applied);
    let committed = store
        .list()
        .expect("native toggle journals")
        .into_iter()
        .find(|journal| journal.operation_id == plan.transition.operation_id)
        .expect("committed native toggle journal");
    assert_eq!(
        committed.authorization_decision_history,
        vec![first_digest, refreshed_digest.clone()]
    );
    assert_eq!(
        committed.authorization_decision_digest.as_deref(),
        Some(refreshed_digest.as_str())
    );
    assert!(
        committed
            .audit
            .iter()
            .any(|event| event.code == "approval-refreshed")
    );
}

#[test]
fn interrupted_native_toggle_with_provider_drift_requires_recovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-interrupted-drift",
        2_000_000_000,
    );
    let store = TransitionJournalStore::new(&app_state_root);
    let mut interrupted = store
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("interrupted native toggle journal");
    interrupted.journal.authorization_decision_digest =
        Some(authorization.decision_digest().to_string());
    interrupted
        .journal
        .authorization_decision_history
        .push(authorization.decision_digest().to_string());
    interrupted
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .expect("approval checkpoint");
    interrupted
        .journal
        .record(
            TransitionLifecycle::Locked,
            "legacy-mutation-lock-delegated",
            None,
        )
        .expect("lock checkpoint");
    interrupted
        .journal
        .record(
            TransitionLifecycle::Applying,
            "legacy-apply-started",
            Some("native-toggle-effect"),
        )
        .expect("apply checkpoint");
    store
        .save(&mut interrupted)
        .expect("save interrupted journal");

    fs::write(
        PathBuf::from(&plan.preview.selection.state_path).join("SKILL.md"),
        "# drifted during interrupted apply\n",
    )
    .expect("drift provider state");

    let recovery = controller
        .apply(&plan, authorization, &context, backup_authentication_key())
        .expect("interrupted provider drift must surface recovery evidence");

    assert_eq!(recovery.status, ToggleStatus::RecoveryRequired);
    let repaired = store
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("needs-repair native toggle journal");
    assert_eq!(repaired.journal.lifecycle, TransitionLifecycle::NeedsRepair);
    assert_eq!(
        repaired.journal.terminal_code.as_deref(),
        Some("legacy-resume-state-diverged")
    );
}

#[test]
fn native_toggle_omitted_reach_uses_exact_target_provenance() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| {
            item.provider == ProviderId::Codex && item.mutability == DiscoveryMutability::ReadWrite
        })
        .expect("Codex writable item");
    let controller = NativeToggleController::new(app_state.path());
    let plan = controller
        .plan(item, &control_context("test-repository", "test-workspace"))
        .expect("exact target plan");

    assert_eq!(
        plan.provider_reach,
        ProviderReach::selected(
            ProviderId::Codex,
            SelectedProviderProvenance::ExactIndividualTarget,
        )
    );
    assert_eq!(plan.preview.provider_reach, Some(plan.provider_reach));
    assert_eq!(plan.coverage.entries.len(), 1);
    assert!(plan.coverage.entries[0].included);
}

#[test]
fn native_toggle_rejects_selected_provider_conflict_before_native_planning() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("Zed configured MCP item");
    let request = ProviderReachRequest::new(
        ConnectionBoundary::All,
        ProviderReachInput::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
        DerivedTargetKind::Individual,
    );
    let error = NativeToggleController::new(app_state.path())
        .plan_with_reach_request(
            item,
            &control_context("test-repository", "test-workspace"),
            request,
        )
        .expect_err("selected Codex must reject exact Zed target");
    assert!(matches!(
        error,
        NativeToggleControlError::ProviderReach(ProviderReachError::ExactTargetConflict {
            selected: ProviderId::Codex,
            target: ProviderId::Zed,
        })
    ));
    assert!(
        !app_state.path().join("journals").exists(),
        "authority conflict must happen before native transition state"
    );
}

#[test]
fn native_toggle_blocks_shared_source_outside_selected_provider_reach() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:example-claude-global-skill")
        .cloned()
        .expect("Claude shared skill");

    let error = NativeToggleController::new(app_state.path())
        .plan_with_reach_in_inventory(
            item,
            &discovery.items,
            &control_context("test-repository", "test-workspace"),
            ConnectionBoundary::All,
            ProviderReachInput::selected(
                ProviderId::Claude,
                SelectedProviderProvenance::ExplicitInput,
            ),
            vec![unpin_core::provider_reach::SelectedProviderAuthority::new(
                ProviderId::Claude,
                SelectedProviderProvenance::ExplicitInput,
            )],
        )
        .expect_err("shared source must block before native planning");

    assert!(matches!(
        error,
        NativeToggleControlError::Blocked(reason)
            if reason == "shared-source-crosses-provider-reach"
    ));
    assert!(
        !app_state.path().join("journals").exists(),
        "shared-source guard must run before transition state"
    );
}

#[test]
fn native_toggle_review_fingerprint_ignores_journal_generation() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::new(&app_state_root);
    let first = controller
        .plan(item.clone(), &context)
        .expect("first toggle plan");
    let journals = TransitionJournalStore::new(&app_state_root);
    let mut terminal = journals
        .create_or_attach(
            &first.transition,
            OwnerGeneration::new("toggle-generation-test", 1).unwrap(),
        )
        .unwrap();
    terminal
        .journal
        .record(TransitionLifecycle::RolledBack, "test-rolled-back", None)
        .unwrap();
    journals.save(&mut terminal).unwrap();

    let second = controller.plan(item, &context).expect("second toggle plan");

    assert_eq!(second.plan_fingerprint, first.plan_fingerprint);
    assert_eq!(
        first
            .approval_expectation(&context)
            .unwrap()
            .effect_graph_digest,
        first.plan_fingerprint
    );
    assert_eq!(
        second
            .approval_expectation(&context)
            .unwrap()
            .effect_graph_digest,
        second.plan_fingerprint
    );
    assert_ne!(
        second.transition.operation_id,
        first.transition.operation_id
    );
}

#[test]
fn native_toggle_journal_generation_is_scoped_to_workspace() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let first_context = control_context("test-repository", "worktree-a");
    let second_context = control_context("test-repository", "worktree-b");
    let controller = NativeToggleController::new(&app_state_root);
    let first = controller
        .plan(item.clone(), &first_context)
        .expect("first worktree plan");
    let second = controller
        .plan(item.clone(), &second_context)
        .expect("second worktree plan");

    assert_ne!(
        first.transition.operation_id,
        second.transition.operation_id
    );
    assert_ne!(first.plan_fingerprint, second.plan_fingerprint);

    let journals = TransitionJournalStore::new(&app_state_root);
    let mut terminal = journals
        .create_or_attach(
            &first.transition,
            OwnerGeneration::new("toggle-worktree-generation-test", 1).unwrap(),
        )
        .unwrap();
    terminal
        .journal
        .record(TransitionLifecycle::RolledBack, "test-rolled-back", None)
        .unwrap();
    journals.save(&mut terminal).unwrap();

    let next_first = controller
        .plan(item.clone(), &first_context)
        .expect("next first worktree plan");
    let next_second = controller
        .plan(item, &second_context)
        .expect("next second worktree plan");

    assert_ne!(
        next_first.transition.operation_id,
        first.transition.operation_id
    );
    assert_eq!(
        next_second.transition.operation_id,
        second.transition.operation_id
    );
    assert_eq!(next_first.plan_fingerprint, first.plan_fingerprint);
    assert_eq!(next_second.plan_fingerprint, second.plan_fingerprint);
}

#[test]
fn overlapping_native_toggle_journal_requires_recovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let blocker = TransitionPlan::new(
        "blocking-native-toggle",
        plan.transition.kind,
        plan.transition.context.clone(),
        plan.transition.effects.clone(),
    )
    .expect("blocking transition");
    let store = TransitionJournalStore::new(&app_state_root);
    let mut blocker_handle = store
        .create_or_attach(
            &blocker,
            OwnerGeneration::new("blocking-native-toggle", 1).expect("blocker owner"),
        )
        .expect("blocking journal");
    blocker_handle
        .journal
        .record(TransitionLifecycle::Applying, "apply-interrupted", None)
        .expect("mark blocking journal applying");
    store
        .save(&mut blocker_handle)
        .expect("save blocking journal");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-overlap",
        2_000_000_000,
    );

    let error = controller
        .apply(&plan, authorization, &context, backup_authentication_key())
        .expect_err("overlapping journal must require recovery");

    assert!(matches!(
        error,
        NativeToggleControlError::RecoveryRequired(ref reason)
            if reason.contains("blocking-native-toggle")
    ));
    assert_eq!(backup_count(&app_state_root), 0);
}

#[test]
fn native_toggle_backup_without_checkpoint_requires_recovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let handle = TransitionJournalStore::new(&app_state_root)
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("interrupted native toggle journal");
    fs::create_dir_all(
        app_state_root
            .join("backups")
            .join(&handle.journal.backup_id),
    )
    .expect("interrupted backup root");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-interrupted-backup",
        2_000_000_000,
    );

    let recovery = controller
        .apply(&plan, authorization, &context, backup_authentication_key())
        .expect("interrupted backup must surface recovery evidence");

    assert_eq!(recovery.status, ToggleStatus::RecoveryRequired);
    assert_eq!(
        recovery.backup_id.as_deref(),
        Some(handle.journal.backup_id.as_str())
    );
    assert!(
        recovery
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("backup exists without a committed checkpoint"))
    );
    let journal = TransitionJournalStore::new(&app_state_root)
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("needs-repair journal");
    assert_eq!(journal.journal.lifecycle, TransitionLifecycle::NeedsRepair);
}

#[test]
fn native_toggle_provider_write_without_checkpoint_requires_recovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-interrupted-provider-write",
        2_000_000_000,
    );
    let store = TransitionJournalStore::new(&app_state_root);
    let mut handle = store
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("interrupted native toggle journal");
    handle.journal.authorization_decision_digest =
        Some(authorization.decision_digest().to_string());
    handle
        .journal
        .authorization_decision_history
        .push(authorization.decision_digest().to_string());
    handle
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .expect("approval checkpoint");
    handle
        .journal
        .record(
            TransitionLifecycle::Locked,
            "legacy-mutation-lock-delegated",
            None,
        )
        .expect("lock checkpoint");
    handle
        .journal
        .record(
            TransitionLifecycle::Applying,
            "legacy-apply-started",
            Some("native-toggle-effect"),
        )
        .expect("apply checkpoint");
    store.save(&mut handle).expect("save interrupted journal");

    let backup_root = app_state_root
        .join("backups")
        .join(&handle.journal.backup_id);
    fs::create_dir_all(&backup_root).expect("interrupted backup root");
    let operation = plan.preview.operations.first().expect("rename operation");
    let source_path = PathBuf::from(operation.from_path.as_deref().expect("rename source path"));
    let destination_path = PathBuf::from(
        operation
            .to_path
            .as_deref()
            .expect("rename destination path"),
    );
    fs::create_dir_all(destination_path.parent().expect("destination parent"))
        .expect("create vault parent");
    fs::rename(&source_path, &destination_path).expect("simulate completed provider write");

    let recovery = controller
        .apply(&plan, authorization, &context, backup_authentication_key())
        .expect("post-write interruption must surface recovery evidence");

    assert_eq!(recovery.status, ToggleStatus::RecoveryRequired);
    assert_eq!(
        recovery.backup_id.as_deref(),
        Some(handle.journal.backup_id.as_str())
    );
    assert!(
        recovery
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("recovery-required: "))
    );
    assert!(
        recovery
            .writes
            .as_deref()
            .is_some_and(|writes| writes.contains("may already have been performed"))
    );
    let journal = store
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("needs-repair journal");
    assert_eq!(journal.journal.lifecycle, TransitionLifecycle::NeedsRepair);
    assert_eq!(
        journal.journal.terminal_code.as_deref(),
        Some("legacy-recovery-required")
    );
}

#[test]
fn fresh_native_toggle_preview_drift_does_not_create_journal() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-fresh-preview-drift",
        2_000_000_000,
    );
    fs::write(
        PathBuf::from(&plan.preview.selection.state_path).join("SKILL.md"),
        "# drifted skill\n",
    )
    .expect("drift skill after review");

    let error = controller
        .apply(&plan, authorization, &context, backup_authentication_key())
        .expect_err("fresh preview drift must block the toggle");

    assert!(matches!(error, NativeToggleControlError::Blocked(_)));
    assert!(
        TransitionJournalStore::new(&app_state_root)
            .list()
            .expect("native toggle journals")
            .is_empty(),
        "a rejected fresh preview must not leave a journal"
    );
}

#[test]
fn pre_lock_native_toggle_contention_with_later_drift_stays_blocked() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let first_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-pre-backup-failure",
        2_000_000_000,
    );
    let live_pid = process::id();
    let held_lock = hold_mutation_lock(
        &app_state_root,
        &format!(r#"{{"pid":{live_pid},"acquiredAt":"2026-06-20T12:00:00Z"}}"#),
    );

    let first_error = controller
        .apply(
            &plan,
            first_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect_err("held mutation lock must block before backup");
    assert!(matches!(
        first_error,
        NativeToggleControlError::Blocked(ref reason)
            if reason.contains("mutation lock is already held")
    ));
    assert_eq!(backup_count(&app_state_root), 0);
    let store = TransitionJournalStore::new(&app_state_root);
    assert!(
        store
            .list()
            .expect("native toggle journals after contention")
            .is_empty(),
        "pre-lock contention must not create or update a transition journal"
    );
    drop(held_lock);

    fs::write(
        PathBuf::from(&plan.preview.selection.state_path).join("SKILL.md"),
        "# drifted after pre-backup failure\n",
    )
    .expect("drift skill after interrupted apply");
    let retry_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-pre-backup-drift-retry",
        2_000_000_000,
    );

    let retry_error = controller
        .apply(
            &plan,
            retry_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect_err("drift after pre-lock contention must remain an ordinary blocked retry");
    assert!(matches!(retry_error, NativeToggleControlError::Blocked(_)));
    assert!(
        store
            .list()
            .expect("native toggle journals after drift")
            .is_empty(),
        "drift after pre-lock contention must not leave recovery state"
    );
    assert_eq!(backup_count(&app_state_root), 0);
}

#[test]
fn pre_lock_native_toggle_contention_accepts_new_approval_on_retry() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let first_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-pre-backup-retry-first",
        2_000_000_000,
    );
    let live_pid = process::id();
    let held_lock = hold_mutation_lock(
        &app_state_root,
        &format!(r#"{{"pid":{live_pid},"acquiredAt":"2026-06-20T12:00:00Z"}}"#),
    );

    let first_error = controller
        .apply(
            &plan,
            first_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect_err("held mutation lock must block before backup");
    assert!(matches!(
        first_error,
        NativeToggleControlError::Blocked(ref reason)
            if reason.contains("mutation lock is already held")
    ));
    assert_eq!(backup_count(&app_state_root), 0);
    drop(held_lock);

    let retry_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-pre-backup-retry-refreshed",
        2_000_000_000,
    );
    let retry_digest = retry_authorization.decision_digest().to_string();
    let applied = controller
        .apply(
            &plan,
            retry_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect("a new approval must apply after pre-lock contention clears");

    assert_eq!(applied.status, ToggleStatus::Applied);
    let committed = TransitionJournalStore::new(&app_state_root)
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("committed native toggle journal");
    assert_eq!(
        committed.journal.authorization_decision_history,
        vec![retry_digest.clone()]
    );
    assert_eq!(
        committed.journal.authorization_decision_digest.as_deref(),
        Some(retry_digest.as_str())
    );
    assert_eq!(committed.journal.lifecycle, TransitionLifecycle::Committed);
    assert!(
        committed
            .journal
            .audit
            .iter()
            .all(|event| event.code != "approval-refreshed")
    );
}

#[test]
fn recovering_native_toggle_with_checkpointed_effect_rejects_refreshed_approval() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let first_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-recovering-checkpointed-first",
        2_000_000_000,
    );
    let first_digest = first_authorization.decision_digest().to_string();
    let store = TransitionJournalStore::new(&app_state_root);
    let mut recovering = store
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("recovering native toggle journal");
    recovering.journal.authorization_decision_digest = Some(first_digest.clone());
    recovering
        .journal
        .authorization_decision_history
        .push(first_digest.clone());
    recovering
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .expect("approval checkpoint");
    recovering
        .journal
        .record(
            TransitionLifecycle::Locked,
            "legacy-mutation-lock-delegated",
            None,
        )
        .expect("lock checkpoint");
    recovering.journal.effects[0].status = EffectCheckpointStatus::BackedUp;
    recovering
        .journal
        .record(
            TransitionLifecycle::Recovering,
            "legacy-apply-blocked",
            Some("native-toggle-effect"),
        )
        .expect("recovery checkpoint");
    store
        .save(&mut recovering)
        .expect("save recovering journal");
    let refreshed_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-recovering-checkpointed-refreshed",
        2_000_000_000,
    );

    let error = controller
        .apply(
            &plan,
            refreshed_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect_err("checkpointed recovery must reject refreshed approval");

    assert!(matches!(
        error,
        NativeToggleControlError::Blocked(ref reason)
            if reason == "native toggle is bound to another approval decision"
    ));
    let unchanged = store
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("unchanged recovering journal");
    assert_eq!(
        unchanged.journal.authorization_decision_digest.as_deref(),
        Some(first_digest.as_str())
    );
    assert_eq!(
        unchanged.journal.authorization_decision_history,
        vec![first_digest]
    );
    assert_eq!(unchanged.journal.lifecycle, TransitionLifecycle::Recovering);
}

#[test]
fn recovering_native_toggle_bounds_approval_refresh_history() {
    const MAX_REFRESH_HISTORY: usize = 32;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let store = TransitionJournalStore::new(&app_state_root);
    let mut recovering = store
        .create_or_attach(
            &plan.transition,
            OwnerGeneration::new("native-toggle-control", 1).expect("journal owner"),
        )
        .expect("recovering native toggle journal");
    recovering.journal.authorization_decision_history = (0..MAX_REFRESH_HISTORY)
        .map(|index| format!("bounded-approval-{index}"))
        .collect();
    recovering.journal.authorization_decision_digest = recovering
        .journal
        .authorization_decision_history
        .last()
        .cloned();
    recovering
        .journal
        .record(TransitionLifecycle::Approved, "approval-recorded", None)
        .expect("approval checkpoint");
    recovering
        .journal
        .record(
            TransitionLifecycle::Locked,
            "legacy-mutation-lock-delegated",
            None,
        )
        .expect("lock checkpoint");
    recovering
        .journal
        .record(
            TransitionLifecycle::Recovering,
            "legacy-apply-blocked",
            Some("native-toggle-effect"),
        )
        .expect("recovery checkpoint");
    store
        .save(&mut recovering)
        .expect("save bounded recovery journal");
    let overflow_authorization = control_authorization(
        &app_state_root,
        &expectation,
        "native-toggle-refresh-limit-overflow",
        2_000_000_000,
    );
    let recovery = controller
        .apply(
            &plan,
            overflow_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect("approval history overflow must surface recovery evidence");

    assert_eq!(recovery.status, ToggleStatus::RecoveryRequired);
    let bounded = store
        .load(
            &plan.transition,
            OwnerGeneration::new("verify-native-toggle", 1).expect("verify owner"),
        )
        .expect("bounded native toggle journal");
    assert_eq!(
        bounded.journal.authorization_decision_history.len(),
        MAX_REFRESH_HISTORY
    );
    assert_eq!(bounded.journal.lifecycle, TransitionLifecycle::NeedsRepair);
    assert_eq!(
        bounded.journal.terminal_code.as_deref(),
        Some("approval-refresh-limit")
    );
}

#[test]
fn contended_native_toggle_retries_do_not_create_journals() {
    const CONTENDED_RETRIES: usize = 64;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let context = control_context("test-repository", "test-workspace");
    let controller = NativeToggleController::with_session_authority_key(
        &app_state_root,
        session_authority_key(),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("native toggle expectation");
    let live_pid = process::id();
    let held_lock = hold_mutation_lock(
        &app_state_root,
        &format!(r#"{{"pid":{live_pid},"acquiredAt":"2026-06-20T12:00:00Z"}}"#),
    );

    let authorization_marker = "native-toggle-exact-retry-limit";
    let first_authorization = control_authorization(
        &app_state_root,
        &expectation,
        authorization_marker,
        2_000_000_000,
    );
    let first_error = controller
        .apply(
            &plan,
            first_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect_err("pre-lock contention must block without starting an apply");
    assert!(matches!(first_error, NativeToggleControlError::Blocked(_)));
    let store = TransitionJournalStore::new(&app_state_root);
    assert!(
        store
            .list()
            .expect("native toggle journals after initial contention")
            .is_empty(),
        "contention must be rejected before journal creation"
    );

    for _ in 1..CONTENDED_RETRIES {
        let authorization = control_authorization(
            &app_state_root,
            &expectation,
            authorization_marker,
            2_000_000_000,
        );
        let error = controller
            .apply(&plan, authorization, &context, backup_authentication_key())
            .expect_err("exact retry must remain safely blocked before lock acquisition");
        assert!(matches!(error, NativeToggleControlError::Blocked(_)));
    }

    assert!(
        store
            .list()
            .expect("native toggle journals after repeated contention")
            .is_empty(),
        "repeated contention must not grow approval or audit evidence"
    );

    drop(held_lock);
    let final_authorization = control_authorization(
        &app_state_root,
        &expectation,
        authorization_marker,
        2_000_000_000,
    );
    let applied = controller
        .apply(
            &plan,
            final_authorization,
            &context,
            backup_authentication_key(),
        )
        .expect("contention must not permanently block the approved toggle");
    assert_eq!(applied.status, ToggleStatus::Applied);
}

#[test]
fn plans_claude_plugin_config_disable_as_json_value_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:tool:settings:safe-shell")
        .expect("claude plugin config");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceJsonValue");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(
        result.operations[0]
            .summary
            .contains("enabledPlugins.safe-shell")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn plans_agent_disable_as_file_vault_rename_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "renamePath");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault path")
            .contains("/vault/claude/global/agent/")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn plans_cursor_configured_mcp_disable_as_json_file_rewrite_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceFile");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault path")
            .contains("/vault/cursor/global/configured-mcp/")
    );
    assert!(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault path")
            .ends_with("/payload.json")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn plans_zed_configured_mcp_disable_as_json_file_rewrite_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("zed mcp");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceFile");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault path")
            .contains("/vault/zed/global/configured-mcp/")
    );
    assert!(
        result.operations[0]
            .summary
            .contains("Zed context_servers entry")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn plans_cursor_configured_mcp_disabled_flag_enable_as_json_file_rewrite_dry_run() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");
    fs::write(
        &mcp_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "modern-global": {
                    "command": "npx",
                    "disabled": true
                }
            }
        }))
        .expect("mcp json"),
    )
    .expect("write cursor mcp");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    assert!(!item.enabled);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceFile");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert_eq!(result.operations[0].to_path, None);
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn plans_codex_plugin_disable_as_native_file_rewrite() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("codex plugin config");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceFile");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert!(result.operations[0].summary.contains("Restart Codex"));
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[cfg(unix)]
#[test]
fn blocks_provider_config_symlink_replacement_before_toggle() {
    use std::os::unix::fs::symlink;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let external_path = fixture_copy.path().join("external-config.toml");
    let original = fs::read(&config_path).expect("original config");
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("codex plugin config")
        .clone();

    fs::write(&external_path, &original).expect("external config");
    fs::remove_file(&config_path).expect("remove provider config");
    symlink(&external_path, &config_path).expect("replace provider config with symlink");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("provider config path is a symlink"))
    );
    assert_eq!(
        fs::read(&external_path).expect("external config remains"),
        original
    );
}

#[test]
fn blocks_non_regular_provider_config_before_toggle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("codex plugin config")
        .clone();

    fs::remove_file(&config_path).expect("remove provider config");
    fs::create_dir(&config_path).expect("replace provider config with directory");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("provider config path is not a regular file"))
    );
}

#[cfg(unix)]
#[test]
fn blocks_provider_config_with_symlinked_parent_before_toggle() {
    use std::os::unix::fs::symlink;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_parent = fixture_copy.path().join("codex/global");
    let external_parent = fixture_copy.path().join("external-codex-global");
    let config_path = config_parent.join("config.toml");
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("codex plugin config")
        .clone();
    let original = fs::read(&config_path).expect("original config");

    fs::rename(&config_parent, &external_parent).expect("move provider config parent");
    symlink(&external_parent, &config_parent).expect("replace provider config parent with symlink");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("mutation target parent contains a symlink"))
    );
    assert_eq!(
        fs::read(external_parent.join("config.toml")).expect("external config remains"),
        original
    );
}

#[test]
fn applies_and_restores_codex_connector_plugin_without_moving_bundle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let original = fs::read_to_string(&config_path).expect("original config");
    let plugin_root = fixture_copy
        .path()
        .join("codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0");
    let plugin_manifest = plugin_root.join(".codex-plugin/plugin.json");
    let plugin_connector = plugin_root.join(".mcp.json");
    let original_manifest = fs::read(&plugin_manifest).expect("original plugin manifest");
    let original_connector = fs::read(&plugin_connector).expect("original plugin connector");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| {
            item.id == "codex:global:plugin-config:config:connector-kit@example-marketplace"
        })
        .expect("Codex connector plugin");
    assert!(item.enabled);

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    let backup_id = applied.backup_id.expect("backup id");
    let disabled = fs::read_to_string(&config_path).expect("disabled config");
    assert!(
        disabled.contains("[plugins.\"connector-kit@example-marketplace\"]\nenabled = false\n")
    );
    assert!(disabled.contains("[plugins.\"disabled-helper\"] # disabled plugin\nenabled = false"));
    assert!(disabled.contains("[mcp_servers.github]"));
    assert!(disabled.contains("[hooks.PreToolUse]"));
    assert_eq!(
        fs::read(&plugin_manifest).expect("plugin manifest after disable"),
        original_manifest
    );
    assert_eq!(
        fs::read(&plugin_connector).expect("plugin connector after disable"),
        original_connector
    );
    assert!(!app_state.path().join("vault").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| {
            item.id == "codex:global:plugin-config:config:connector-kit@example-marketplace"
        })
        .expect("disabled Codex connector plugin");
    assert!(!disabled_item.enabled);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored config"),
        original
    );
    assert_eq!(
        fs::read(&plugin_manifest).expect("plugin manifest after restore"),
        original_manifest
    );
    assert_eq!(
        fs::read(&plugin_connector).expect("plugin connector after restore"),
        original_connector
    );
}

#[test]
fn blocks_codex_plugin_toggle_when_section_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin")
        .clone();
    let raw = fs::read_to_string(&config_path).expect("config");
    fs::write(
        &config_path,
        raw.replace(
            "[plugins.safe-shell]\nenabled = true",
            "[plugins.safe-shell]\nenabled = true\ninstall_policy = \"available\"",
        ),
    )
    .expect("drift plugin section");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("source drifted")
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn blocks_codex_plugin_toggle_when_nested_subtable_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let raw = fs::read_to_string(&config_path).expect("config");
    let raw = raw.replace(
        "[plugins.safe-shell]\nenabled = true",
        concat!(
            "[plugins.safe-shell]\n",
            "enabled = true\n",
            "[plugins.safe-shell.environment]\n",
            "MODE = \"reviewed\"",
        ),
    );
    fs::write(&config_path, &raw).expect("config with plugin subtable");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin")
        .clone();
    let drifted = raw.replace("MODE = \"reviewed\"", "MODE = \"changed\"");
    fs::write(&config_path, &drifted).expect("drift plugin subtable");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("source drifted")
    );
    assert_eq!(
        fs::read_to_string(config_path).expect("unchanged config"),
        drifted
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn blocks_codex_toggle_when_any_standard_table_is_duplicated() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin")
        .clone();
    let raw = fs::read_to_string(&config_path).expect("config");
    fs::write(
        &config_path,
        format!("{raw}\n[mcp_servers.github]\nenabled = false\n"),
    )
    .expect("duplicate unrelated table");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("duplicate TOML table declarations")
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn blocks_codex_toggle_when_enabled_key_is_duplicated() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin")
        .clone();
    let raw = fs::read_to_string(&config_path).expect("config");
    let raw = raw.replace(
        "[plugins.safe-shell]\nenabled = true",
        "[plugins.safe-shell]\nenabled = true\n\"enabled\" = false",
    );
    fs::write(&config_path, &raw).expect("duplicate normalized enabled key");

    let rediscovery = discover_all(&roots).expect("rediscovery");
    assert!(rediscovery.warnings.iter().any(|warning| {
        warning.code == "duplicate-toml-key" && warning.message.contains("plugins.safe-shell")
    }));
    assert!(
        !rediscovery
            .items
            .iter()
            .any(|candidate| candidate.id == item.id)
    );

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("duplicate enabled keys")
    );
    assert_eq!(
        fs::read_to_string(config_path).expect("unchanged config"),
        raw
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn blocks_codex_toggle_when_table_header_is_malformed() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin")
        .clone();
    let mut raw = fs::read_to_string(&config_path).expect("config");
    raw.push_str("\n[mcp_servers.incomplete\ncommand = \"unsafe\"\n");
    fs::write(&config_path, &raw).expect("malformed TOML table header");

    let rediscovery = discover_all(&roots).expect("rediscovery");
    assert!(rediscovery.warnings.iter().any(|warning| {
        warning.code == "invalid-toml-table-header"
            && warning.message.contains("malformed TOML table headers")
    }));
    assert!(
        !rediscovery
            .items
            .iter()
            .any(|candidate| candidate.id == item.id)
    );

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("malformed TOML table headers")
    );
    assert_eq!(
        fs::read_to_string(config_path).expect("unchanged config"),
        raw
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn plans_codex_configured_mcp_disable_as_file_rewrite_dry_run() {
    let app_state = TempDir::new().expect("temp app state");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::DryRun);
    assert_eq!(result.selection.id, item.id);
    assert!(!result.target_enabled);
    assert_eq!(result.operations.len(), 1);
    assert_eq!(result.operations[0].operation_type, "replaceFile");
    assert_eq!(
        result.operations[0].from_path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
}

#[test]
fn applies_codex_configured_mcp_native_enabled_toggle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");
    let original = fs::read_to_string(&config_path).expect("original config");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");
    assert!(item.enabled);

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled.status, ToggleStatus::Applied);
    assert!(!disabled.target_enabled);
    let disabled_config = fs::read_to_string(&config_path).expect("disabled config");
    assert!(disabled_config.contains("[mcp_servers.github]"));
    assert!(disabled_config.contains("[mcp_servers.github]\nenabled = false\n"));
    assert!(disabled_config.contains("[plugins.safe-shell]"));
    assert!(!app_state.path().join("vault").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("disabled codex mcp");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.state_path, config_path.to_string_lossy());

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert!(enabled.target_enabled);
    let enabled_config = fs::read_to_string(&config_path).expect("enabled config");
    assert!(enabled_config.contains("[mcp_servers.github]\nenabled = true\n"));
    assert!(enabled_config.contains("[plugins.safe-shell]"));
    assert_ne!(enabled_config, original);
}

#[test]
fn discovers_and_toggles_codex_quoted_dotted_table_ids() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    fs::write(
        &config_path,
        concat!(
            "[mcp_servers.\"docs.example\"]\n",
            "command = \"docs\"\n\n",
            "[plugins.'connector.example']\n",
            "enabled = true\n",
        ),
    )
    .expect("write quoted Codex config");

    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:docs.example")
        .expect("quoted dotted Codex MCP");
    assert!(
        discovery
            .items
            .iter()
            .any(|item| { item.id == "codex:global:plugin-config:config:connector.example" })
    );

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    let rewritten = fs::read_to_string(config_path).expect("rewritten Codex config");
    assert!(
        rewritten.contains("[mcp_servers.\"docs.example\"]\nenabled = false\ncommand = \"docs\"")
    );
    assert!(rewritten.contains("[plugins.'connector.example']\nenabled = true"));
}

#[test]
fn discovers_and_toggles_codex_quoted_enabled_key() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    fs::write(
        &config_path,
        concat!(
            "[plugins.safe-shell]\n",
            "\"enabled\" = false # preserve this comment\n",
        ),
    )
    .expect("write quoted-key Codex config");

    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:safe-shell")
        .expect("Codex plugin with quoted enabled key");
    assert!(!item.enabled);

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    let rewritten = fs::read_to_string(config_path).expect("rewritten Codex config");
    assert!(rewritten.contains("\"enabled\" = true # preserve this comment"));
    assert!(!rewritten.contains("\nenabled = "));
}

#[test]
fn applies_and_restores_project_codex_configured_mcp_native_toggle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("project")
        .join(".codex")
        .join("config.toml");
    let original = fs::read_to_string(&config_path).expect("original project config");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:project:configured-mcp:project-docs")
        .expect("project codex mcp");
    assert!(!item.enabled);

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(applied.target_enabled);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    let enabled = fs::read_to_string(&config_path).expect("enabled project config");
    assert!(enabled.contains("[mcp_servers.project-docs]"));
    assert!(enabled.contains("enabled = true"));
    assert!(enabled.contains("[hooks.ProjectStart]"));

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored project config"),
        original
    );
}

#[test]
fn applies_codex_skill_native_config_toggle_without_moving_admin_source() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let skill_path = fixture_copy
        .path()
        .join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config = fs::read_to_string(&config_path).expect("Codex config fixture");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]] # existing override\npath = {:?}\nenabled = true # default\n",
            skill_path.to_string_lossy()
        ),
    )
    .expect("write existing Codex skill config");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill");
    assert!(item.enabled);
    assert_eq!(item.state_path, config_path.to_string_lossy());

    let disable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(disable_plan.status, ToggleStatus::DryRun);
    assert!(!disable_plan.target_enabled);
    assert_eq!(disable_plan.operations[0].operation_type, "replaceFile");
    assert!(disable_plan.operations[0].summary.contains("Restart Codex"));
    assert_eq!(disable_plan.affected_targets.len(), 1);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(
        skill_path.is_file(),
        "admin skill source must remain in place"
    );
    let disabled_config = fs::read_to_string(&config_path).expect("disabled Codex config");
    assert!(disabled_config.contains("[[skills.config]]"));
    assert!(disabled_config.contains("[[skills.config]] # existing override"));
    assert!(disabled_config.contains(&format!("path = {:?}", skill_path.to_string_lossy())));
    assert!(disabled_config.contains("enabled = false"));
    assert!(disabled_config.contains("[plugins.safe-shell]\nenabled = true"));
    assert!(disabled_config.contains("[mcp_servers.github]"));
    assert!(disabled_config.contains("[hooks.PreToolUse]\ncommand = \"echo\""));
    assert!(!app_state.path().join("vault").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("disabled Codex skill");
    assert!(!disabled_item.enabled);
    assert!(skill_path.is_file());

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(
        enabled_apply.status,
        ToggleStatus::Applied,
        "{enabled_apply:?}"
    );
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply.backup_id.expect("enable backup id");
    let enabled_config = fs::read_to_string(&config_path).expect("enabled Codex config");
    assert!(enabled_config.contains("enabled = true"));
    assert!(skill_path.is_file());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    let restored_config = fs::read_to_string(&config_path).expect("restored Codex config");
    assert!(restored_config.contains("enabled = false"));
    assert!(skill_path.is_file());
}

#[test]
fn applies_codex_shared_skill_toggle_without_moving_shared_source() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let skill_path = fixture_copy
        .path()
        .join("shared/global/.agents/skills/example-shared-global-skill/SKILL.md");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:example-shared-global-skill")
        .expect("Codex shared skill");
    assert!(item.enabled);
    assert_eq!(item.state_path, config_path.to_string_lossy());

    let disable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(disable_plan.status, ToggleStatus::DryRun);
    assert_eq!(disable_plan.operations[0].operation_type, "replaceFile");
    assert!(
        disable_plan
            .operations
            .iter()
            .all(|operation| operation.operation_type != "renamePath")
    );

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(skill_path.is_file(), "shared skill source remains in place");
    assert!(!app_state.path().join("vault").exists());
    let disabled_config = fs::read_to_string(&config_path).expect("disabled Codex config");
    assert!(disabled_config.contains(&format!("path = {:?}", skill_path.to_string_lossy())));
    assert!(disabled_config.contains("enabled = false"));
    assert!(disabled_config.contains("[plugins.safe-shell]\nenabled = true"));
    assert!(disabled_config.contains("[mcp_servers.github]"));
    assert!(disabled_config.contains("[hooks.PreToolUse]\ncommand = \"echo\""));

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:example-shared-global-skill")
        .expect("disabled Codex shared skill");
    assert!(!disabled_item.enabled);
    for item_id in [
        "cursor:global:skill:@compat/agents/example-shared-global-skill",
        "pi:global:skill:@compat/agents/example-shared-global-skill",
        "opencode:global:skill:@compat/agents/example-shared-global-skill",
        "zed:global:skill:example-shared-global-skill",
    ] {
        assert!(
            disabled_discovery
                .items
                .iter()
                .find(|item| item.id == item_id)
                .is_some_and(|item| item.enabled),
            "{item_id} remains enabled"
        );
    }

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    assert!(skill_path.is_file());
    assert!(
        fs::read_to_string(&config_path)
            .expect("enabled Codex config")
            .contains("enabled = true")
    );
}

#[test]
fn blocks_codex_skill_toggle_when_native_config_has_duplicate_paths() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let skill_path = fixture_copy
        .path()
        .join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config = fs::read_to_string(&config_path).expect("Codex config fixture");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = true\n\n[[skills.config]]\npath = {:?}\nenabled = false\n",
            skill_path.to_string_lossy(),
            skill_path.to_string_lossy(),
        ),
    )
    .expect("write duplicate Codex skill config");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill");
    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("duplicate skills.config path"))
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("unchanged Codex config"),
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = true\n\n[[skills.config]]\npath = {:?}\nenabled = false\n",
            skill_path.to_string_lossy(),
            skill_path.to_string_lossy(),
        )
    );
}

#[test]
fn creates_and_restores_missing_codex_config_for_skill_toggle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    fs::remove_file(&config_path).expect("remove Codex config fixture");

    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill");
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.state_path, config_path.to_string_lossy());

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    let backup_id = applied.backup_id.expect("backup id");
    let config = fs::read_to_string(&config_path).expect("created Codex config");
    assert!(config.contains("[[skills.config]]"));
    assert!(config.contains("enabled = false"));
    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["existed"], false);
    assert!(manifest["entries"][0]["payload"].is_null());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert!(!config_path.exists());
}

#[test]
fn blocks_codex_skill_toggle_when_source_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill")
        .clone();
    fs::write(&item.source_path, "# drifted skill\n").expect("drift Codex skill source");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with(
                "Codex skill source drifted for codex:global:skill:admin/example-codex-admin-skill:"
            )
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn blocks_codex_skill_toggle_when_native_state_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill")
        .clone();
    let config_path = PathBuf::from(&item.state_path);
    let config = fs::read_to_string(&config_path).expect("Codex config");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = false\n",
            item.source_path
        ),
    )
    .expect("drift Codex skill state");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(
        result.reason.as_deref(),
        Some("Codex skill state drifted: discovered true, current false")
    );
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn applies_skill_disable_with_backup_vault_entry_and_audit() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);
    assert!(original_state_path.join("SKILL.md").exists());

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Applied, "{result:?}");
    assert!(!result.target_enabled);
    let backup_id = result.backup_id.as_deref().expect("backup id");

    let transaction_files = fs::read_dir(app_state.path().join("transactions"))
        .expect("transition journals")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        })
        .collect::<Vec<_>>();
    assert_eq!(transaction_files.len(), 1);
    let transaction: serde_json::Value =
        serde_json::from_slice(&fs::read(&transaction_files[0]).expect("transition journal JSON"))
            .expect("decode transition journal");
    assert_eq!(transaction["value"]["operationKind"], "native-toggle");
    assert_eq!(transaction["value"]["lifecycle"], "committed");
    assert_eq!(transaction["value"]["backupId"], backup_id);
    assert_eq!(
        transaction["value"]["effects"]
            .as_array()
            .expect("one-effect transaction")
            .len(),
        1
    );
    assert_eq!(backup_count(app_state.path()), 1);

    assert!(!original_state_path.exists());
    let vault_payload = PathBuf::from(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(vault_payload.join("SKILL.md").exists());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["backupId"], backup_id);
    assert_eq!(manifest["selection"]["id"], item.id);
    assert_eq!(manifest["targetEnabled"], false);
    assert_eq!(manifest["entries"][0]["pathKind"], "directory");

    let backup_payload = app_state
        .path()
        .join("backups")
        .join(backup_id)
        .join("entries")
        .join("entry-1")
        .join("payload");
    assert!(backup_payload.join("SKILL.md").exists());

    let entry_path = vault_payload
        .parent()
        .expect("vault root")
        .join("entry.json");
    let entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(entry_path).expect("vault entry"))
            .expect("vault entry json");
    assert_eq!(entry["itemId"], item.id);
    assert_eq!(entry["originalPath"], item.state_path);
    assert_eq!(
        entry["vaultedPath"],
        vault_payload.to_string_lossy().as_ref()
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"event\":\"apply\""));
    assert!(audit.contains(backup_id));
}

#[test]
fn blocks_skill_disable_when_source_file_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    assert!(item.enabled);

    let skill_file = PathBuf::from(&item.source_path);
    let skill_dir = PathBuf::from(&item.state_path);
    let drifted = "# Example Claude Skill\n\nUpdated after discovery.\n";
    fs::write(&skill_file, drifted).expect("write drifted skill file");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with("Skill source drifted for claude:project:skill:example-claude-skill:")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert!(skill_dir.is_dir());
    assert_eq!(
        fs::read_to_string(&skill_file).expect("current skill file"),
        drifted
    );
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn records_failed_apply_audit_when_skill_vault_conflict_blocks_guarded_setup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);
    let vault_root = app_state
        .path()
        .join("vault")
        .join("claude")
        .join("project")
        .join("skill")
        .join("claude%3Aproject%3Askill%3Aexample-claude-skill");
    fs::create_dir_all(&vault_root).expect("pre-existing vault root");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
    assert!(
        original_state_path.join("SKILL.md").exists(),
        "failed setup must not move the provider skill"
    );
    assert!(
        !app_state.path().join("backups").exists(),
        "failed setup must not create backup manifests"
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    let entries = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit entry json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["event"], "failed-apply");
    assert_eq!(entry["selection"]["id"], item.id);
    assert_eq!(entry["targetEnabled"], false);
    assert_eq!(entry["rollbackSucceeded"], true);
    assert!(entry["rollbackFailure"].is_null());
    assert_eq!(entry["backupDeleted"], false);
    assert!(
        entry["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
}

#[test]
fn records_failed_apply_audit_when_agent_vault_conflict_blocks_guarded_setup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);
    let original_agent = fs::read_to_string(&original_state_path).expect("original agent file");
    let vault_root = app_state
        .path()
        .join("vault")
        .join("claude")
        .join("global")
        .join("agent")
        .join("claude%3Aglobal%3Aagent%3Aclaude-global-reviewer");
    fs::create_dir_all(&vault_root).expect("pre-existing vault root");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
    assert_eq!(
        fs::read_to_string(&original_state_path).expect("current agent file"),
        original_agent,
        "failed setup must not move the provider agent"
    );
    assert!(
        !app_state.path().join("backups").exists(),
        "failed setup must not create backup manifests"
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    let entries = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit entry json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["event"], "failed-apply");
    assert_eq!(entry["selection"]["id"], item.id);
    assert_eq!(entry["targetEnabled"], false);
    assert_eq!(entry["rollbackSucceeded"], true);
    assert!(entry["rollbackFailure"].is_null());
    assert_eq!(entry["backupDeleted"], false);
    assert!(
        entry["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
}

#[test]
fn applies_cursor_skill_disable_rediscovers_disabled_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_skill_root = fixture_copy.path().join("cursor/home/skills");
    let direct_skill = cursor_skill_root.join("example-cursor-skill");
    let nested_skill = cursor_skill_root.join("workflows/example-cursor-skill");
    fs::create_dir_all(nested_skill.parent().expect("nested skill has parent"))
        .expect("create nested skill parent");
    fs::rename(&direct_skill, &nested_skill).expect("nest cursor skill");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:workflows/example-cursor-skill")
        .expect("cursor skill");
    let original_state_path = PathBuf::from(&item.state_path);
    let original_skill = original_state_path.join("SKILL.md");
    let original = fs::read_to_string(&original_skill).expect("original cursor skill");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(!original_state_path.exists());
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(vault_payload.join("SKILL.md").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:workflows/example-cursor-skill")
        .expect("disabled cursor skill");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(disabled_item.source_path, original_skill.to_string_lossy());
    assert!(
        disabled_item.state_path.ends_with("entry.json"),
        "disabled state path should point at vault entry, got {}",
        disabled_item.state_path
    );

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(
        enabled_apply.status,
        ToggleStatus::Applied,
        "{enabled_apply:?}"
    );
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert_eq!(
        fs::read_to_string(&original_skill).expect("re-enabled cursor skill"),
        original
    );
    assert!(!vault_payload.parent().expect("vault root").exists());
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&enable_backup_id)
            .join("manifest.json")
            .exists()
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn shared_skills_move_to_vault_and_restore_origin() {
    for (id, source_suffix) in [
        (
            "claude:global:skill:example-claude-global-skill",
            "claude/global/skills/example-claude-global-skill",
        ),
        (
            "claude:project:skill:example-claude-skill",
            "claude/project/.claude/skills/example-claude-skill",
        ),
        (
            "cursor:global:skill:@compat/agents/example-shared-global-skill",
            "shared/global/.agents/skills/example-shared-global-skill",
        ),
        (
            "cursor:project:skill:@compat/agents/example-shared-project-skill",
            "shared/project/.agents/skills/example-shared-project-skill",
        ),
        (
            "cursor:global:skill:@compat/claude/example-claude-global-skill",
            "claude/global/skills/example-claude-global-skill",
        ),
        (
            "cursor:project:skill:@compat/claude/example-claude-skill",
            "claude/project/.claude/skills/example-claude-skill",
        ),
        (
            "cursor:global:skill:@compat/codex/example-codex-compat-global-skill",
            "codex/global/skills/example-codex-compat-global-skill",
        ),
        (
            "cursor:project:skill:@compat/codex/example-codex-compat-project-skill",
            "codex/project/.codex/skills/example-codex-compat-project-skill",
        ),
        (
            "zed:global:skill:example-shared-global-skill",
            "shared/global/.agents/skills/example-shared-global-skill",
        ),
        (
            "zed:project:skill:example-shared-project-skill",
            "shared/project/.agents/skills/example-shared-project-skill",
        ),
    ] {
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        let app_state = TempDir::new().expect("temp app state");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let roots =
            DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
        let original_state_path = fixture_copy.path().join(source_suffix);
        let original_skill_path = original_state_path.join("SKILL.md");
        if !original_skill_path.exists() {
            fs::create_dir_all(&original_state_path).expect("create compatibility skill root");
            fs::write(&original_skill_path, format!("# {id}\n")).expect("seed compatibility skill");
        }
        let original = fs::read_to_string(&original_skill_path).expect("original shared skill");

        let discovery = discover_all(&roots).expect("shared skill discovery");
        let mut loading_item_ids = discovery
            .items
            .iter()
            .filter(|item| item.source_path == original_skill_path.to_string_lossy())
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        loading_item_ids.sort();
        let item = discovery
            .items
            .into_iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}"));
        assert_eq!(item.mutability, DiscoveryMutability::ReadWrite, "{id}");

        let dry_run = plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item: item.clone(),
            apply: false,
            backup_authentication_key: None,
        });
        assert_eq!(dry_run.status, ToggleStatus::DryRun, "{id}");
        assert!(
            dry_run.operations[0]
                .summary
                .contains("every provider loading this source path"),
            "shared impact must be explicit for {id}: {}",
            dry_run.operations[0].summary
        );

        let disabled_apply = plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item,
            apply: true,
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(disabled_apply.status, ToggleStatus::Applied, "{id}");
        assert!(!original_state_path.exists(), "{id} source should move");
        let first_vault_payload = PathBuf::from(
            disabled_apply.operations[0]
                .to_path
                .as_deref()
                .expect("vault payload"),
        );
        assert!(first_vault_payload.join("SKILL.md").is_file(), "{id}");

        let disabled_discovery = discover_all(&roots).expect("disabled shared skill discovery");
        assert!(
            disabled_discovery.warnings.is_empty(),
            "valid shared vault entry produced warnings for {id}: {:#?}",
            disabled_discovery.warnings
        );
        assert!(
            !disabled_discovery.items.iter().any(|item| {
                item.enabled && item.source_path == original_skill_path.to_string_lossy()
            }),
            "disabling {id} must disable every provider view of its source"
        );
        let mut disabled_views = disabled_discovery
            .items
            .into_iter()
            .filter(|item| item.source_path == original_skill_path.to_string_lossy())
            .collect::<Vec<_>>();
        disabled_views.sort_by(|left, right| left.id.cmp(&right.id));
        assert_eq!(
            disabled_views
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>(),
            loading_item_ids,
            "disabling {id} must retain every provider view as disabled"
        );
        assert!(
            disabled_views.iter().all(|item| !item.enabled),
            "every provider view must report disabled for {id}"
        );
        let disabled_item = disabled_views
            .iter()
            .find(|item| item.id != id)
            .unwrap_or_else(|| {
                disabled_views
                    .iter()
                    .find(|item| item.id == id)
                    .unwrap_or_else(|| panic!("missing disabled {id}"))
            })
            .clone();
        assert!(!disabled_item.enabled, "{id}");
        assert_eq!(
            disabled_item.source_path,
            original_skill_path.to_string_lossy(),
            "{id} origin"
        );

        let enabled_apply = plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item: disabled_item,
            apply: true,
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(
            enabled_apply.status,
            ToggleStatus::Applied,
            "{id}: {enabled_apply:#?}"
        );
        assert_eq!(
            fs::read_to_string(&original_skill_path).expect("re-enabled shared skill"),
            original,
            "{id} content"
        );

        let restored_discovery = discover_all(&roots).expect("restored shared skill discovery");
        let mut restored_loading_item_ids = restored_discovery
            .items
            .iter()
            .filter(|item| item.source_path == original_skill_path.to_string_lossy())
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        restored_loading_item_ids.sort();
        assert_eq!(
            restored_loading_item_ids, loading_item_ids,
            "enabling {id} must restore every provider view of its source"
        );
        let live_item = restored_discovery
            .items
            .into_iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing restored {id}"));
        let disabled_again = plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item: live_item,
            apply: true,
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(disabled_again.status, ToggleStatus::Applied, "{id}");
        let disable_backup_id = disabled_again.backup_id.expect("disable backup id");
        let second_vault_payload = PathBuf::from(
            disabled_again.operations[0]
                .to_path
                .as_deref()
                .expect("vault payload"),
        );

        let restored = restore_backup(RestoreBackupInput {
            app_state_root: app_state.path().to_path_buf(),
            backup_id: disable_backup_id,
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(
            restored.status,
            RestoreStatus::Restored,
            "{id}: {:?}",
            restored.reason
        );
        assert_eq!(
            fs::read_to_string(&original_skill_path).expect("backup-restored shared skill"),
            original,
            "{id} restored content"
        );
        assert!(
            !second_vault_payload.parent().expect("vault root").exists(),
            "{id} restored vault entry should be removed"
        );
    }
}

#[cfg(unix)]
#[test]
fn preserves_relative_skill_directory_symlink_through_toggle_and_backup_restore() {
    let home_root = TempDir::new().expect("temp home root");
    let project_root = TempDir::new().expect("temp project root");
    let cursor_root = TempDir::new().expect("temp cursor root");
    let app_state = TempDir::new().expect("temp app state");
    let skill_target = home_root.path().join(".agents/skills/shared-skill");
    fs::create_dir_all(&skill_target).expect("create shared skill");
    fs::write(skill_target.join("SKILL.md"), "# Shared Skill\n").expect("write shared skill");

    let claude_skills = home_root.path().join(".claude/skills");
    fs::create_dir_all(&claude_skills).expect("create Claude skills root");
    let original_state_path = claude_skills.join("linked-skill");
    let relative_target = PathBuf::from("../../.agents/skills/shared-skill");
    std::os::unix::fs::symlink(&relative_target, &original_state_path).expect("link Claude skill");

    let roots =
        DiscoveryRoots::from_locations(home_root.path(), project_root.path(), cursor_root.path())
            .with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("linked skill discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:skill:linked-skill")
        .expect("linked Claude skill");
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disable_backup_id = disabled.backup_id.expect("disable backup id");
    let vault_payload = PathBuf::from(
        disabled.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(fs::symlink_metadata(&original_state_path).is_err());
    assert!(
        fs::symlink_metadata(&vault_payload)
            .expect("vaulted link metadata")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(&vault_payload).expect("vaulted link target"),
        relative_target
    );
    let disable_manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            app_state
                .path()
                .join("backups")
                .join(&disable_backup_id)
                .join("manifest.json"),
        )
        .expect("disable manifest"),
    )
    .expect("disable manifest JSON");
    assert_eq!(
        disable_manifest["entries"][0]["pathKind"],
        "directory-symlink"
    );

    let disabled_item = discover_all(&roots)
        .expect("disabled linked skill discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:skill:linked-skill")
        .expect("disabled linked Claude skill");
    assert!(!disabled_item.enabled);

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    let enable_backup_id = enabled.backup_id.expect("enable backup id");
    assert_eq!(
        fs::read_link(&original_state_path).expect("restored provider link"),
        relative_target
    );
    assert_eq!(
        fs::read_to_string(original_state_path.join("SKILL.md")).expect("restored skill"),
        "# Shared Skill\n"
    );

    let restore_enable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_enable.status, RestoreStatus::Restored);
    assert!(fs::symlink_metadata(&original_state_path).is_err());
    assert!(
        discover_all(&roots)
            .expect("restored disabled discovery")
            .items
            .iter()
            .any(|item| item.id == "claude:global:skill:linked-skill" && !item.enabled)
    );

    let restore_disable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: disable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_disable.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_link(&original_state_path).expect("backup-restored provider link"),
        relative_target
    );
}

#[cfg(unix)]
#[test]
fn preserves_relative_skill_file_symlink_through_toggle_and_backup_restore() {
    let home_root = TempDir::new().expect("temp home root");
    let project_root = TempDir::new().expect("temp project root");
    let cursor_root = TempDir::new().expect("temp cursor root");
    let app_state = TempDir::new().expect("temp app state");
    let skill_target = home_root.path().join(".agents/skills/shared-file-skill");
    fs::create_dir_all(&skill_target).expect("create shared skill");
    fs::write(skill_target.join("SKILL.md"), "# Shared File Skill\n").expect("write shared skill");

    let original_state_path = home_root.path().join(".claude/skills/file-linked-skill");
    fs::create_dir_all(&original_state_path).expect("create Claude skill directory");
    let relative_target = PathBuf::from("../../../.agents/skills/shared-file-skill/SKILL.md");
    std::os::unix::fs::symlink(&relative_target, original_state_path.join("SKILL.md"))
        .expect("link Claude skill file");

    let roots =
        DiscoveryRoots::from_locations(home_root.path(), project_root.path(), cursor_root.path())
            .with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("linked skill discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:skill:file-linked-skill")
        .expect("file-linked Claude skill");
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disable_backup_id = disabled.backup_id.expect("disable backup id");
    let vault_payload = PathBuf::from(
        disabled.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(fs::symlink_metadata(&original_state_path).is_err());
    assert!(vault_payload.is_dir());
    assert_eq!(
        fs::read_link(vault_payload.join("SKILL.md")).expect("vaulted skill file link"),
        relative_target
    );
    let disable_manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            app_state
                .path()
                .join("backups")
                .join(&disable_backup_id)
                .join("manifest.json"),
        )
        .expect("disable manifest"),
    )
    .expect("disable manifest JSON");
    assert_eq!(
        disable_manifest["entries"][0]["pathKind"],
        "directory-with-symlinks"
    );

    let disabled_discovery = discover_all(&roots).expect("disabled linked skill discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:file-linked-skill")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "disabled file-linked Claude skill; warnings: {:?}",
                disabled_discovery.warnings
            )
        });
    assert!(!disabled_item.enabled);

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    let enable_backup_id = enabled.backup_id.expect("enable backup id");
    assert_eq!(
        fs::read_link(original_state_path.join("SKILL.md")).expect("restored skill file link"),
        relative_target
    );
    assert_eq!(
        fs::read_to_string(original_state_path.join("SKILL.md")).expect("restored skill"),
        "# Shared File Skill\n"
    );

    let restore_enable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_enable.status, RestoreStatus::Restored);
    assert!(fs::symlink_metadata(&original_state_path).is_err());
    assert_eq!(
        fs::read_link(vault_payload.join("SKILL.md")).expect("backup-restored vaulted file link"),
        relative_target
    );

    let restore_disable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: disable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_disable.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_link(original_state_path.join("SKILL.md"))
            .expect("backup-restored provider file link"),
        relative_target
    );
}

#[test]
fn applies_pi_markdown_skill_disable_rediscovers_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "pi:global:skill:@file/example-pi-file-skill")
        .expect("Pi Markdown skill")
        .clone();
    let original_path = PathBuf::from(&item.state_path);
    let original = fs::read_to_string(&original_path).expect("original Pi skill");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(!original_path.exists());
    assert!(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file())
    );

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "pi:global:skill:@file/example-pi-file-skill")
        .expect("disabled Pi Markdown skill");
    assert!(!disabled_item.enabled);
    assert!(disabled_item.state_path.ends_with("entry.json"));

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    assert_eq!(
        fs::read_to_string(&original_path).expect("restored Pi skill"),
        original
    );
}

#[test]
fn applies_cursor_local_plugin_disable_rediscovers_disabled_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("Cursor local plugin");
    let original_state_path = PathBuf::from(&item.state_path);
    let original_manifest = original_state_path
        .join(".cursor-plugin")
        .join("plugin.json");
    let original = fs::read_to_string(&original_manifest).expect("original plugin manifest");
    let original_connector_path = original_state_path.join("mcp.json");
    let original_connector = fs::read(&original_connector_path).expect("original plugin connector");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(!original_state_path.exists());
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(
        vault_payload
            .join(".cursor-plugin")
            .join("plugin.json")
            .exists()
    );
    assert_eq!(
        fs::read(vault_payload.join("mcp.json")).expect("vaulted plugin connector"),
        original_connector
    );

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("disabled Cursor local plugin");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(
        disabled_item.source_path,
        original_manifest.to_string_lossy()
    );
    assert!(disabled_item.state_path.ends_with("entry.json"));

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    assert_eq!(
        fs::read_to_string(&original_manifest).expect("re-enabled plugin manifest"),
        original
    );
    assert_eq!(
        fs::read(&original_connector_path).expect("re-enabled plugin connector"),
        original_connector
    );
    assert!(!vault_payload.parent().expect("vault root").exists());
    let enable_backup_id = enabled_apply.backup_id.expect("enable backup id");

    let restore_enable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_enable.status, RestoreStatus::Restored);
    assert!(!original_state_path.exists());
    assert_eq!(
        fs::read(vault_payload.join("mcp.json")).expect("restore-vaulted plugin connector"),
        original_connector
    );

    let restore_disable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: disabled_apply.backup_id.expect("disable backup id"),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restore_disable.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read(&original_connector_path).expect("backup-restored plugin connector"),
        original_connector
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn blocks_cursor_local_plugin_disable_when_manifest_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("Cursor local plugin");
    let plugin_dir = PathBuf::from(&item.state_path);
    fs::write(
        &item.source_path,
        r#"{"name":"example-plugin","displayName":"Drifted Plugin"}"#,
    )
    .expect("drift plugin manifest");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with(
                "Cursor local plugin source drifted for cursor:global:plugin-manifest:local:example-plugin:"
            )
    );
    assert!(plugin_dir.is_dir());
    assert_eq!(backup_count(app_state.path()), 0);
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn blocks_cursor_local_plugin_reenable_when_vault_paths_are_tampered() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("Cursor local plugin");
    let original_plugin_path = PathBuf::from(&item.state_path);
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("disabled Cursor local plugin");
    let entry_path = PathBuf::from(&disabled_item.state_path);
    let mut entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&entry_path).expect("vault entry"))
            .expect("vault entry JSON");
    entry["originalPath"] = serde_json::Value::String(
        original_plugin_path
            .parent()
            .expect("local plugins root")
            .join("other-plugin")
            .to_string_lossy()
            .into_owned(),
    );
    fs::write(
        &entry_path,
        serde_json::to_string_pretty(&entry).expect("tampered entry JSON"),
    )
    .expect("tamper vault entry");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault entry does not match disabled plugin")
    );
    assert!(!original_plugin_path.exists());
    assert!(
        entry_path
            .parent()
            .expect("vault root")
            .join("payload")
            .is_dir()
    );
    assert_eq!(backup_count(app_state.path()), 1);
}

#[cfg(unix)]
#[test]
fn blocks_cursor_local_plugin_reenable_through_symlinked_vault_entry() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let external_root = TempDir::new().expect("external vault root");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("Cursor local plugin");
    let original_plugin_path = PathBuf::from(&item.state_path);
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("disabled Cursor local plugin");
    let entry_root = PathBuf::from(&disabled_item.state_path)
        .parent()
        .expect("vault entry root")
        .to_path_buf();
    let external_entry_root = external_root.path().join("plugin-entry");
    fs::rename(&entry_root, &external_entry_root).expect("move vault entry outside state root");
    std::os::unix::fs::symlink(&external_entry_root, &entry_root)
        .expect("replace vault entry with symlink");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault path contains a symlink")
    );
    assert!(!original_plugin_path.exists());
    assert!(external_entry_root.join("payload").is_dir());
    assert_eq!(backup_count(app_state.path()), 1);
}

#[cfg(unix)]
#[test]
fn blocks_cursor_local_plugin_disable_when_directory_becomes_symlink_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let external_root = TempDir::new().expect("external plugin root");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("Cursor local plugin")
        .clone();
    let plugin_dir = PathBuf::from(&item.state_path);
    let external_plugin = external_root.path().join("example-plugin");
    fs::rename(&plugin_dir, &external_plugin).expect("move plugin outside local root");
    std::os::unix::fs::symlink(&external_plugin, &plugin_dir)
        .expect("replace plugin directory with symlink");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("contains a symlink or special file")
    );
    assert!(
        fs::symlink_metadata(&plugin_dir)
            .expect("plugin path metadata")
            .file_type()
            .is_symlink()
    );
    assert!(
        external_plugin
            .join(".cursor-plugin")
            .join("plugin.json")
            .exists()
    );
    assert_eq!(backup_count(app_state.path()), 0);
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn restoring_skill_reenable_backup_returns_item_to_disabled_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("cursor skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("disabled cursor skill");

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert!(original_state_path.exists());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert!(!original_state_path.exists());
    let rediscovered = discover_all(&roots).expect("restored disabled discovery");
    let restored_item = rediscovered
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("restored disabled cursor skill");
    assert!(!restored_item.enabled);
    assert!(restored_item.state_path.ends_with("entry.json"));
}

#[test]
fn blocks_skill_reenable_plan_when_vault_payload_missing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("cursor skill");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("disabled cursor skill")
        .clone();
    let backups_before = backup_count(app_state.path());
    let audit_before = audit_log(app_state.path());
    fs::remove_dir_all(&vault_payload).expect("remove vaulted skill payload");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.operations.len(), 0);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vaulted skill directory not found"))
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(backup_count(app_state.path()), backups_before);
    assert_eq!(audit_log(app_state.path()), audit_before);
}

#[test]
fn blocks_skill_reenable_plan_when_restore_target_exists() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("cursor skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:example-cursor-skill")
        .expect("disabled cursor skill")
        .clone();
    let backups_before = backup_count(app_state.path());
    let audit_before = audit_log(app_state.path());
    fs::create_dir_all(&original_state_path).expect("recreate original skill directory");
    fs::write(
        original_state_path.join("SKILL.md"),
        "# Recreated\n\nCreated after discovery.\n",
    )
    .expect("write recreated skill");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.operations.len(), 0);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target already exists"))
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(backup_count(app_state.path()), backups_before);
    assert_eq!(audit_log(app_state.path()), audit_before);
}

#[test]
fn applies_agent_disable_with_backup_vault_entry_disabled_discovery_and_restore() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);
    let original = fs::read_to_string(&original_state_path).expect("original agent file");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Applied);
    assert!(!result.target_enabled);
    let backup_id = result.backup_id.as_deref().expect("backup id").to_string();
    assert!(!original_state_path.exists());

    let vault_payload = PathBuf::from(
        result.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(vault_payload.is_file());
    assert_eq!(
        fs::read_to_string(&vault_payload).expect("vault payload"),
        original
    );

    let vault_root = vault_payload.parent().expect("vault root");
    let entry: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vault_root.join("entry.json")).expect("vault entry"),
    )
    .expect("vault entry json");
    assert_eq!(entry["kind"], "agent");
    assert_eq!(entry["payloadKind"], "path");
    assert_eq!(entry["itemId"], item.id);

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .is_file()
    );

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled agent");
    assert!(!disabled.enabled);
    assert_eq!(
        disabled.state_path,
        vault_root.join("entry.json").to_string_lossy()
    );
    assert_eq!(disabled.source_path, original_state_path.to_string_lossy());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&original_state_path).expect("restored agent file"),
        original
    );
    assert!(!vault_root.exists());
}

#[test]
fn restore_blocks_when_agent_file_target_was_recreated() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    let backup_id = disabled_apply
        .backup_id
        .as_deref()
        .expect("backup id")
        .to_string();
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    let vault_root = vault_payload.parent().expect("vault root").to_path_buf();
    let recreated = "# Recreated\n\nCreated after disable.\n";
    fs::write(&original_state_path, recreated).expect("recreate agent file");
    let audit_before = audit_log(app_state.path());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target already exists"))
    );
    assert_eq!(
        fs::read_to_string(&original_state_path).expect("recreated agent file"),
        recreated
    );
    assert!(vault_payload.is_file());
    assert!(vault_root.join("entry.json").exists());
    assert!(app_state.path().join("backups").join(&backup_id).exists());
    assert_eq!(audit_log(app_state.path()), audit_before);
    assert!(
        !app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("rollback")
            .exists(),
        "blocked restore should not leave rollback scratch state"
    );
}

#[test]
fn blocks_agent_disable_when_source_file_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    assert!(item.enabled);

    let agent_file = PathBuf::from(&item.state_path);
    let drifted = "# Reviewer\n\nUpdated after discovery.\n";
    fs::write(&agent_file, drifted).expect("write drifted agent file");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with("Agent source drifted for claude:global:agent:claude-global-reviewer:")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(
        fs::read_to_string(&agent_file).expect("current agent file"),
        drifted
    );
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn applies_agent_disable_rediscovers_disabled_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);
    let original = fs::read_to_string(&original_state_path).expect("original agent file");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(!original_state_path.exists());
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    let vault_root = vault_payload.parent().expect("vault root").to_path_buf();
    assert!(vault_payload.is_file());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled agent");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(
        disabled_item.source_path,
        original_state_path.to_string_lossy()
    );
    assert_eq!(
        disabled_item.state_path,
        vault_root.join("entry.json").to_string_lossy()
    );

    let enable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(enable_plan.status, ToggleStatus::DryRun);
    assert!(enable_plan.target_enabled);
    assert_eq!(enable_plan.operations.len(), 1);
    assert_eq!(enable_plan.operations[0].operation_type, "renamePath");
    assert_eq!(
        enable_plan.operations[0].from_path.as_deref(),
        Some(vault_payload.to_string_lossy().as_ref())
    );
    assert_eq!(
        enable_plan.operations[0].to_path.as_deref(),
        Some(original_state_path.to_string_lossy().as_ref())
    );
    assert_eq!(
        enable_plan.writes.as_deref(),
        Some("no writes were performed")
    );

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert_eq!(
        fs::read_to_string(&original_state_path).expect("re-enabled agent file"),
        original
    );
    assert!(!vault_root.exists());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&enable_backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["targetEnabled"], true);
    assert_eq!(manifest["entries"][0]["existed"], false);
    assert_eq!(manifest["entries"][0]["payload"], serde_json::Value::Null);
    assert_eq!(manifest["entries"][1]["pathKind"], "file");
    assert_eq!(manifest["entries"][2]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&enable_backup_id)
            .join("entries")
            .join("entry-2")
            .join("payload")
            .is_file()
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn restoring_agent_reenable_backup_returns_item_to_disabled_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled claude agent");

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert!(original_state_path.exists());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert!(!original_state_path.exists());
    let rediscovered = discover_all(&roots).expect("restored disabled discovery");
    let restored_item = rediscovered
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("restored disabled claude agent");
    assert!(!restored_item.enabled);
    assert!(restored_item.state_path.ends_with("entry.json"));
}

#[test]
fn blocks_agent_reenable_plan_when_vault_payload_missing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    let vault_payload = PathBuf::from(
        disabled_apply.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled agent")
        .clone();
    let backups_before = backup_count(app_state.path());
    let audit_before = audit_log(app_state.path());
    fs::remove_file(&vault_payload).expect("remove vaulted agent payload");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.operations.len(), 0);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vaulted agent file not found"))
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(backup_count(app_state.path()), backups_before);
    assert_eq!(audit_log(app_state.path()), audit_before);
}

#[test]
fn blocks_agent_reenable_when_vault_metadata_drifts_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled agent");
    let entry_path = PathBuf::from(&disabled_item.state_path);
    let mut entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&entry_path).expect("vault entry"))
            .expect("vault entry JSON");
    entry["originalPath"] = serde_json::Value::String(
        PathBuf::from(&disabled_item.source_path)
            .with_file_name("other-agent.md")
            .to_string_lossy()
            .into_owned(),
    );
    fs::write(
        &entry_path,
        serde_json::to_string_pretty(&entry).expect("tampered entry JSON"),
    )
    .expect("tamper vault entry");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault entry does not match disabled agent")
    );
}

#[test]
fn blocks_agent_reenable_plan_when_restore_target_exists() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("claude agent");
    let original_state_path = PathBuf::from(&item.state_path);

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:agent:claude-global-reviewer")
        .expect("disabled agent")
        .clone();
    let backups_before = backup_count(app_state.path());
    let audit_before = audit_log(app_state.path());
    fs::write(&original_state_path, "# Recreated\n").expect("recreate original agent file");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.operations.len(), 0);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target already exists"))
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(backup_count(app_state.path()), backups_before);
    assert_eq!(audit_log(app_state.path()), audit_before);
}

#[test]
fn applies_and_restores_claude_connector_plugin_without_moving_bundle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("settings.json");
    let original = fs::read_to_string(&settings_path).expect("original settings");
    let plugin_root = fixture_copy
        .path()
        .join("claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0");
    let plugin_manifest = plugin_root.join(".claude-plugin/plugin.json");
    let plugin_connector = plugin_root.join(".mcp.json");
    let original_manifest = fs::read(&plugin_manifest).expect("original plugin manifest");
    let original_connector = fs::read(&plugin_connector).expect("original plugin connector");
    assert!(settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:tool:settings:connector-kit@example-marketplace")
        .expect("Claude connector plugin config");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    assert_eq!(applied.operations[0].operation_type, "replaceJsonValue");
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    assert!(!settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));
    assert_eq!(
        fs::read(&plugin_manifest).expect("plugin manifest after disable"),
        original_manifest
    );
    assert_eq!(
        fs::read(&plugin_connector).expect("plugin connector after disable"),
        original_connector
    );

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["selection"]["id"], item.id);
    assert_eq!(manifest["targetEnabled"], false);
    assert_eq!(manifest["entries"][0]["pathKind"], "file");

    let after_discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery after apply");
    let disabled = after_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:global:tool:settings:connector-kit@example-marketplace")
        .expect("disabled Claude connector plugin config");
    assert!(!disabled.enabled);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored settings"),
        original
    );
    assert_eq!(
        fs::read(&plugin_manifest).expect("plugin manifest after restore"),
        original_manifest
    );
    assert_eq!(
        fs::read(&plugin_connector).expect("plugin connector after restore"),
        original_connector
    );
}

#[test]
fn applies_and_restores_project_claude_plugin_config_enable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".claude")
        .join("settings.local.json");
    let original = fs::read_to_string(&settings_path).expect("original settings");
    assert!(!settings_plugin_enabled(&settings_path, "local-shell"));

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:tool:settings-local:local-shell")
        .expect("project Claude plugin config");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(applied.target_enabled);
    assert!(settings_plugin_enabled(&settings_path, "local-shell"));

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: applied.backup_id.as_deref().expect("backup id").to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored settings"),
        original
    );
}

#[test]
fn applies_claude_global_configured_mcp_disable_rediscovers_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let original: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:configured-mcp:global-docs")
        .expect("Claude global MCP");

    let plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(plan.status, ToggleStatus::DryRun);
    assert!(!plan.target_enabled);
    assert_eq!(plan.operations[0].operation_type, "replaceFile");

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    assert!(!disabled.target_enabled);
    let disabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("disabled Claude user state"))
            .expect("disabled Claude user state JSON");
    assert!(disabled_state["mcpServers"].get("global-docs").is_none());
    assert_eq!(disabled_state["unrelatedState"], original["unrelatedState"]);

    let vault_root = app_state
        .path()
        .join("vault")
        .join("claude")
        .join("global")
        .join("configured-mcp")
        .join("claude%3Aglobal%3Aconfigured-mcp%3Aglobal-docs");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(vault_root.join("payload.json")).expect("vault payload")
        )
        .expect("vault payload JSON")["command"],
        "npx"
    );

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:configured-mcp:global-docs")
        .expect("disabled Claude global MCP");
    assert!(!disabled_item.enabled);
    assert!(disabled_item.state_path.ends_with("entry.json"));

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert!(enabled.target_enabled);
    let enabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("enabled Claude user state"))
            .expect("enabled Claude user state JSON");
    assert_eq!(
        enabled_state["mcpServers"]["global-docs"],
        original["mcpServers"]["global-docs"]
    );
    assert_eq!(enabled_state["unrelatedState"], original["unrelatedState"]);
    assert!(!vault_root.exists());
}

#[test]
fn blocks_claude_global_configured_mcp_disable_when_source_payload_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "claude:global:configured-mcp:global-docs")
        .expect("Claude global MCP");

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    document["mcpServers"]["global-docs"]["command"] = "drifted-command".into();
    fs::write(
        &state_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("drifted Claude user state")
        ),
    )
    .expect("write drifted Claude user state");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(result.reason.as_deref().is_some_and(|reason| {
        reason.starts_with("Claude configured MCP source drifted for global-docs:")
    }));
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn applies_claude_local_configured_mcp_toggle_without_cross_project_leakage() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let original: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    let mut roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    roots.claude_project = PathBuf::from("/fixture/project");
    let roots = roots.with_app_state_root(app_state.path());

    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.display_name == "local-search")
        .expect("Claude local MCP");
    let item_id = item.id.clone();

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    assert!(!disabled.target_enabled);
    let disabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("disabled Claude user state"))
            .expect("disabled Claude user state JSON");
    assert!(
        disabled_state["projects"]["/fixture/project"]["mcpServers"]
            .get("local-search")
            .is_none()
    );
    assert_eq!(
        disabled_state["projects"]["/fixture/project"]["unrelatedProjectState"],
        original["projects"]["/fixture/project"]["unrelatedProjectState"]
    );
    assert_eq!(
        disabled_state["projects"]["/fixture/other-project"],
        original["projects"]["/fixture/other-project"]
    );
    assert_eq!(disabled_state["mcpServers"], original["mcpServers"]);

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("disabled Claude local MCP");
    assert!(!disabled_item.enabled);
    assert!(disabled_item.state_path.ends_with("entry.json"));

    let mut malformed_state = disabled_state.clone();
    malformed_state["projects"]["/fixture/project"]["mcpServers"] =
        serde_json::Value::Array(Vec::new());
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&malformed_state).expect("malformed state serializes"),
    )
    .expect("write malformed local state");
    let malformed_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(malformed_plan.status, ToggleStatus::Blocked);
    assert_eq!(
        malformed_plan.reason.as_deref(),
        Some("Claude local project mcpServers is missing or not an object")
    );
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&disabled_state).expect("disabled state serializes"),
    )
    .expect("restore disabled local state");

    let mut other_roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    other_roots.claude_project = PathBuf::from("/fixture/other-project");
    let other_roots = other_roots.with_app_state_root(app_state.path());
    assert!(
        !discover_all(&other_roots)
            .expect("other project discovery")
            .items
            .iter()
            .any(|item| item.id == item_id)
    );

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert!(enabled.target_enabled);
    let enabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("enabled Claude user state"))
            .expect("enabled Claude user state JSON");
    assert_eq!(
        enabled_state["projects"]["/fixture/project"]["mcpServers"]["local-search"],
        original["projects"]["/fixture/project"]["mcpServers"]["local-search"]
    );
}

#[test]
fn blocks_claude_local_configured_mcp_disable_when_source_payload_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let mut roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    roots.claude_project = PathBuf::from("/fixture/project");
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.display_name == "local-search")
        .expect("Claude local MCP");

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    document["projects"]["/fixture/project"]["mcpServers"]["local-search"]["command"] =
        "drifted-local-command".into();
    fs::write(
        &state_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("drifted Claude user state")
        ),
    )
    .expect("write drifted Claude user state");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(result.reason.as_deref().is_some_and(|reason| {
        reason.starts_with("Claude configured MCP source drifted for local-search:")
    }));
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn applies_and_restores_claude_project_configured_mcp_disable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".claude")
        .join("settings.local.json");
    let mcp_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".mcp.json");
    let original_settings = fs::read_to_string(&settings_path).expect("original settings");
    let original_mcp = fs::read_to_string(&mcp_path).expect("original mcp json");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:configured-mcp:github")
        .expect("claude project mcp");
    assert!(item.enabled);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.source_path, mcp_path.to_string_lossy());
    assert_eq!(item.state_path, settings_path.to_string_lossy());

    let plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(plan.status, ToggleStatus::DryRun);
    assert!(!plan.target_enabled);
    assert_eq!(plan.operations.len(), 1);
    assert_eq!(plan.operations[0].operation_type, "replaceFile");
    assert_eq!(
        plan.operations[0].from_path.as_deref(),
        Some(settings_path.to_string_lossy().as_ref())
    );
    assert_eq!(plan.writes.as_deref(), Some("no writes were performed"));

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();

    let rewritten: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("rewritten settings"))
            .expect("settings json");
    assert!(rewritten["enabledMcpjsonServers"]["github"].is_null());
    assert_eq!(
        rewritten["disabledMcpjsonServers"]["github"]["command"],
        "npx"
    );
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("unchanged mcp json"),
        original_mcp
    );

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:configured-mcp:github")
        .expect("disabled claude project mcp");
    assert!(!disabled.enabled);
    assert_eq!(disabled.mutability, DiscoveryMutability::ReadWrite);

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .is_file()
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored settings"),
        original_settings
    );
}

#[test]
fn blocks_claude_project_configured_mcp_disable_when_source_payload_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".claude")
        .join("settings.local.json");
    let mcp_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".mcp.json");
    let original_settings = fs::read_to_string(&settings_path).expect("original settings");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:configured-mcp:github")
        .expect("claude project mcp");
    assert!(item.enabled);

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&mcp_path).expect("mcp json")).expect("mcp value");
    document["mcpServers"]["github"]["command"] = serde_json::Value::String("node".to_string());
    fs::write(
        &mcp_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("drifted mcp json")
        ),
    )
    .expect("write drifted mcp json");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with("Claude configured MCP source drifted for github:")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(
        fs::read_to_string(&settings_path).expect("current settings"),
        original_settings
    );
    assert_eq!(
        cursor_mcp_server(&mcp_path, "github").expect("github mcp")["command"],
        "node"
    );
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn applies_and_restores_claude_all_project_mcp_flag_enable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".claude")
        .join("settings.local.json");
    let original_settings = fs::read_to_string(&settings_path).expect("original settings");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:configured-mcp:all-project-mcp-servers")
        .expect("claude all project mcp flag");
    assert!(!item.enabled);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.state_path, settings_path.to_string_lossy());

    let plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(plan.status, ToggleStatus::DryRun);
    assert!(plan.target_enabled);
    assert_eq!(plan.operations.len(), 1);
    assert_eq!(plan.operations[0].operation_type, "replaceJsonValue");
    assert_eq!(
        plan.operations[0].json_path.as_deref(),
        Some(&["enableAllProjectMcpServers".to_string()][..])
    );
    assert_eq!(
        plan.operations[0].value,
        Some(serde_json::Value::Bool(true))
    );
    assert_eq!(plan.writes.as_deref(), Some("no writes were performed"));

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(applied.target_enabled);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();

    let rewritten: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("rewritten settings"))
            .expect("settings json");
    assert_eq!(rewritten["enableAllProjectMcpServers"], true);
    assert!(rewritten["enabledMcpjsonServers"]["github"].is_object());
    assert!(rewritten["disabledMcpjsonServers"]["legacy-local"].is_object());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .is_file()
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored settings"),
        original_settings
    );
}

#[test]
fn codex_toggle_ignores_enabled_assignments_inside_multiline_strings() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let original = fs::read_to_string(&config_path).expect("fixture config");
    let multiline_values = concat!(
        "description = \"\"\"\n",
        "enabled = true\n",
        "\"\"\"\n",
        "literal_description = '''\n",
        "enabled = true\n",
        "'''\n",
    );
    let configured = original.replacen(
        "[mcp_servers.github]\n",
        &format!("[mcp_servers.github]\n{multiline_values}"),
        1,
    );
    fs::write(&config_path, configured).expect("write multiline TOML fixture");

    let roots = DiscoveryRoots::fixture_root(fixture_copy.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("Codex MCP")
        .clone();
    assert!(item.enabled, "text inside multiline values is not state");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(applied.status, ToggleStatus::Applied);

    let rewritten = fs::read_to_string(config_path).expect("rewritten config");
    assert!(
        rewritten.contains(&format!(
            "[mcp_servers.github]\nenabled = false\n{multiline_values}"
        )),
        "the real state must be inserted without rewriting multiline values:\n{rewritten}"
    );
}

#[test]
fn applies_and_restores_codex_configured_mcp_native_disable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");
    let fixture_config = fs::read_to_string(&config_path).expect("fixture config");
    fs::write(
        &config_path,
        format!("{fixture_config}\n[[profiles]]\nname = \"default\"\n"),
    )
    .expect("append array table fixture");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");
    let original = fs::read_to_string(&config_path).expect("original config");
    assert!(original.contains("[mcp_servers.github]"));
    assert!(original.contains("[plugins.safe-shell]"));
    assert!(original.contains("[[profiles]]"));

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    let rewritten = fs::read_to_string(&config_path).expect("rewritten config");
    assert!(rewritten.contains("[mcp_servers.github]\nenabled = false\n"));
    assert!(rewritten.contains("[plugins.safe-shell]"));
    assert!(rewritten.contains("[[profiles]]"));
    assert!(!app_state.path().join("vault").exists());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .exists()
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored config"),
        original
    );
}

#[test]
fn native_codex_configured_mcp_toggle_ignores_legacy_vault_directory() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");
    let vault_root = app_state
        .path()
        .join("vault")
        .join("codex")
        .join("global")
        .join("configured-mcp")
        .join("codex%3Aglobal%3Aconfigured-mcp%3Agithub");
    fs::create_dir_all(&vault_root).expect("pre-existing vault root");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Applied);
    assert!(
        fs::read_to_string(&config_path)
            .expect("current config")
            .contains("[mcp_servers.github]\nenabled = false\n")
    );
    assert!(
        vault_root.exists(),
        "native toggle must not mutate legacy vault"
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    let entries = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit entry json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["event"], "apply");
    assert_eq!(entry["selection"]["id"], item.id);
    assert_eq!(entry["targetEnabled"], false);
}

#[test]
fn legacy_codex_vault_reenable_preserves_live_trailing_bytes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");
    let live_raw = "[plugins.safe-shell]\nenabled = true\r\n \t\r\n";
    fs::write(&config_path, live_raw).expect("write live Codex config");

    let vault_root = app_state_root
        .join("vault/codex/global/configured-mcp")
        .join("codex%3Aglobal%3Aconfigured-mcp%3Agithub");
    let vault_payload = vault_root.join("payload");
    fs::create_dir_all(&vault_root).expect("create legacy vault");
    let section = "[mcp_servers.github]\r\ncommand = \"npx\"\r\n";
    fs::write(&vault_payload, section).expect("write legacy vault payload");
    fs::write(
        vault_root.join("entry.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "provider": "codex",
            "kind": "configured-mcp",
            "layer": "global",
            "itemId": "codex:global:configured-mcp:github",
            "displayName": "github",
            "originalPath": config_path,
            "vaultedPath": vault_payload,
            "payloadKind": "text-payload"
        }))
        .expect("legacy vault entry"),
    )
    .expect("write legacy vault entry");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(&app_state_root);
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("legacy vaulted Codex MCP");
    assert!(!item.enabled);
    assert_eq!(item.display_name, "github");
    assert_eq!(item.source_path, config_path.to_string_lossy());
    assert_eq!(
        item.state_path,
        vault_root.join("entry.json").to_string_lossy()
    );

    let applied = plan_toggle(TogglePlanInput {
        app_state_root,
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(
        applied.status,
        ToggleStatus::Applied,
        "{:?}",
        applied.reason
    );
    let rewritten = fs::read_to_string(config_path).expect("reenabled Codex config");
    assert!(
        rewritten.ends_with("\r\n \t\r\n"),
        "existing trailing bytes must remain at the end:\n{rewritten:?}"
    );
    assert!(
        rewritten.contains(section),
        "vaulted section bytes must be restored exactly:\n{rewritten:?}"
    );
    assert!(
        rewritten.find(section).expect("restored section") < rewritten.len() - "\r\n \t\r\n".len(),
        "the restored section must be inserted before the original trailing suffix"
    );
}

#[test]
fn blocks_codex_configured_mcp_disable_when_source_section_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");
    assert!(item.enabled);

    let original = fs::read_to_string(&config_path).expect("original codex config");
    let drifted = original.replace(r#"command = "npx""#, r#"command = "node""#);
    assert_ne!(drifted, original);
    fs::write(&config_path, &drifted).expect("write drifted codex config");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with("Codex configured MCP source drifted for github:")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    let current = fs::read_to_string(&config_path).expect("current codex config");
    assert!(current.contains("[mcp_servers.github]"));
    assert!(current.contains(r#"command = "node""#));
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn applies_codex_configured_mcp_disable_rediscovers_and_reenables_native_state() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");
    let fixture_config = fs::read_to_string(&config_path).expect("fixture config");
    fs::write(
        &config_path,
        format!("{fixture_config}\n[[profiles]]\nname = \"default\"\n"),
    )
    .expect("append array table fixture");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("codex mcp");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    let disabled_config = fs::read_to_string(&config_path).expect("disabled config");
    assert!(disabled_config.contains("[mcp_servers.github]\nenabled = false\n"));
    assert!(disabled_config.contains("[plugins.safe-shell]"));
    assert!(disabled_config.contains("[[profiles]]"));
    assert!(!app_state.path().join("vault").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("disabled codex mcp");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(disabled_item.source_path, config_path.to_string_lossy());
    assert_eq!(disabled_item.state_path, config_path.to_string_lossy());

    let enable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(enable_plan.status, ToggleStatus::DryRun);
    assert!(enable_plan.target_enabled);
    assert_eq!(enable_plan.operations.len(), 1);
    assert_eq!(enable_plan.operations[0].operation_type, "replaceFile");
    assert_eq!(
        enable_plan.writes.as_deref(),
        Some("no writes were performed")
    );

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    let enabled_config = fs::read_to_string(&config_path).expect("enabled config");
    assert!(enabled_config.contains("[mcp_servers.github]\nenabled = true\n"));
    assert!(enabled_config.contains("[plugins.safe-shell]"));
    assert!(enabled_config.contains("[[profiles]]"));
    assert!(!app_state.path().join("vault").exists());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&enable_backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["selection"]["id"], disabled_item.id);
    assert_eq!(manifest["targetEnabled"], true);
    let config_path_string = config_path.to_string_lossy().to_string();
    assert_eq!(
        manifest["entries"][0]["target"]["path"].as_str(),
        Some(config_path_string.as_str())
    );
    assert_eq!(manifest["entries"][0]["pathKind"], "file");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    let restored_config = fs::read_to_string(&config_path).expect("restored disabled config");
    assert!(restored_config.contains("[mcp_servers.github]\nenabled = false\n"));
    assert!(restored_config.contains("[plugins.safe-shell]"));
    assert!(restored_config.contains("[[profiles]]"));
    assert!(!app_state.path().join("vault").exists());
    let rediscovered = discover_all(&roots).expect("restored disabled discovery");
    let restored_item = rediscovered
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("restored disabled codex mcp");
    assert!(!restored_item.enabled);
    assert_eq!(restored_item.state_path, config_path.to_string_lossy());

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn applies_and_restores_cursor_configured_mcp_disable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");
    let original = fs::read_to_string(&mcp_path).expect("original cursor mcp json");
    assert_eq!(
        cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp")["command"],
        "npx"
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    assert_eq!(applied.operations[0].operation_type, "replaceFile");
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_none());

    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("configured-mcp")
        .join("cursor%3Aglobal%3Aconfigured-mcp%3Amodern-global");
    let vault_payload = vault_root.join("payload.json");
    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vault_payload).expect("vault payload"))
            .expect("vault payload json");
    assert_eq!(payload["command"], "npx");

    let entry: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vault_root.join("entry.json")).expect("vault entry"),
    )
    .expect("vault entry json");
    assert_eq!(entry["kind"], "configured-mcp");
    assert_eq!(entry["payloadKind"], "json-payload");
    assert_eq!(entry["itemId"], item.id);

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .exists()
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("restored cursor mcp json"),
        original
    );
    assert!(!vault_root.exists());
}

#[test]
fn applies_and_restores_zed_configured_mcp_disable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed")
        .join("global")
        .join(".config")
        .join("zed")
        .join("settings.json");
    let original = fs::read_to_string(&settings_path).expect("original zed settings json");
    assert_eq!(
        zed_context_server(&settings_path, "github").expect("github context server")["command"],
        "npx"
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("zed mcp");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    assert_eq!(applied.operations[0].operation_type, "replaceFile");
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    assert!(zed_context_server(&settings_path, "github").is_none());
    let rewritten: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("rewritten settings"))
            .expect("rewritten settings json");
    assert_eq!(rewritten["theme"], "Ayu Dark");

    let vault_root = app_state
        .path()
        .join("vault")
        .join("zed")
        .join("global")
        .join("configured-mcp")
        .join("zed%3Aglobal%3Aconfigured-mcp%3Agithub");
    let vault_payload = vault_root.join("payload.json");
    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vault_payload).expect("vault payload"))
            .expect("vault payload json");
    assert_eq!(payload["command"], "npx");

    let entry: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vault_root.join("entry.json")).expect("vault entry"),
    )
    .expect("vault entry json");
    assert_eq!(entry["provider"], "zed");
    assert_eq!(entry["kind"], "configured-mcp");
    assert_eq!(entry["payloadKind"], "json-payload");
    assert_eq!(entry["itemId"], item.id);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored zed settings"),
        original
    );
    assert!(!vault_root.exists());
}

#[test]
fn applies_and_restores_zed_configured_mcp_disable_from_jsonc_settings() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed")
        .join("global")
        .join(".config")
        .join("zed")
        .join("settings.json");
    fs::write(
        &settings_path,
        r#"// Zed settings may contain comments.
{
  "theme": "Ayu Dark",
  "context_servers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
    },
  },
}
"#,
    )
    .expect("write zed JSONC settings");
    let original = fs::read_to_string(&settings_path).expect("original zed settings");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("zed mcp from JSONC");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(zed_context_server(&settings_path, "github").is_none());
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored zed settings"),
        original
    );
}

#[test]
fn opencode_jsonc_mcp_toggle_preserves_comments_and_formatting() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("opencode")
        .join("global")
        .join("opencode.jsonc");
    let original = r#"{
  // OpenCode fixture comment
  "mcp": {
    "example-global": {
      "type": "local",
      "command": ["example-opencode-mcp"],
      "enabled": true, // preserve this comment
    },
  },
  "plugin": ["example-opencode-connector"],
}
"#;
    fs::write(&config_path, original).expect("write OpenCode JSONC fixture");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:configured-mcp:example-global")
        .expect("OpenCode MCP");

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_raw = fs::read_to_string(&config_path).expect("disabled OpenCode config");
    assert!(disabled_raw.contains("// OpenCode fixture comment"));
    assert!(disabled_raw.contains("false, // preserve this comment"));

    let disabled_item = discover_all(&roots)
        .expect("disabled OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:configured-mcp:example-global")
        .expect("disabled OpenCode MCP");
    assert!(!disabled_item.enabled);
    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert_eq!(
        fs::read_to_string(&config_path).expect("re-enabled OpenCode config"),
        original
    );
}

#[test]
fn opencode_npm_plugin_toggle_vaults_config_reference_and_restores_jsonc() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("opencode")
        .join("global")
        .join("opencode.jsonc");
    let original = r#"{
  // Keep unrelated OpenCode settings.
  "mcp": {},
  "plugin": [
    // Keep connector placement and comment.
    "example-opencode-connector",
    "keep-opencode-plugin",
  ],
}
"#;
    fs::write(&config_path, original).expect("write OpenCode JSONC fixture");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:example-opencode-connector")
        .expect("OpenCode npm plugin");
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_raw = fs::read_to_string(&config_path).expect("disabled OpenCode config");
    assert!(disabled_raw.contains("// Keep unrelated OpenCode settings."));
    assert!(disabled_raw.contains("// Keep connector placement and comment."));
    assert!(!disabled_raw.contains("\"example-opencode-connector\""));
    assert!(disabled_raw.contains("\"keep-opencode-plugin\""));

    let disabled_item = discover_all(&roots)
        .expect("disabled OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:example-opencode-connector")
        .expect("disabled OpenCode npm plugin");
    assert!(!disabled_item.enabled);
    assert!(disabled_item.state_path.ends_with("entry.json"));

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert_eq!(
        fs::read_to_string(&config_path).expect("re-enabled OpenCode config"),
        original
    );
}

#[test]
fn opencode_project_plugin_toggle_restores_strict_json_and_backup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("opencode")
        .join("project")
        .join("opencode.json");
    let original = r#"{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {},
  "plugin": [
    "keep-opencode-plugin",
    "example-opencode-project-connector"
  ]
}
"#;
    fs::write(&config_path, original).expect("write OpenCode JSON fixture");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("OpenCode discovery")
        .items
        .into_iter()
        .find(|item| {
            item.id == "opencode:project:plugin-config:npm:example-opencode-project-connector"
        })
        .expect("OpenCode project npm plugin");

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_raw = fs::read_to_string(&config_path).expect("disabled OpenCode config");
    serde_json::from_str::<serde_json::Value>(&disabled_raw).expect("strict JSON remains valid");
    assert!(!disabled_raw.contains("example-opencode-project-connector"));
    assert!(disabled_raw.contains("keep-opencode-plugin"));

    let backup_id = disabled.backup_id.expect("disable backup id");
    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored OpenCode config"),
        original
    );

    let item = discover_all(&roots)
        .expect("restored OpenCode discovery")
        .items
        .into_iter()
        .find(|item| {
            item.id == "opencode:project:plugin-config:npm:example-opencode-project-connector"
        })
        .expect("restored OpenCode project npm plugin");
    assert!(item.enabled);

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled OpenCode discovery")
        .items
        .into_iter()
        .find(|item| {
            item.id == "opencode:project:plugin-config:npm:example-opencode-project-connector"
        })
        .expect("disabled OpenCode project npm plugin");
    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert_eq!(
        fs::read_to_string(&config_path).expect("re-enabled OpenCode config"),
        original
    );
}

#[test]
fn opencode_strict_json_plugins_restore_original_order_after_multiple_disables() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("opencode/project/opencode.json");
    let original = r#"{
  "mcp": {},
  "plugin": [
    "plugin-a",
    "plugin-b",
    "plugin-c"
  ]
}
"#;
    fs::write(&config_path, original).expect("write OpenCode JSON fixture");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let toggle = |plugin_id: &str, enabled: bool| {
        let item_id = format!("opencode:project:plugin-config:npm:{plugin_id}");
        let item = discover_all(&roots)
            .expect("OpenCode discovery")
            .items
            .into_iter()
            .find(|item| item.id == item_id)
            .unwrap_or_else(|| panic!("missing OpenCode plugin {plugin_id}"));
        assert_eq!(item.enabled, enabled);
        let result = plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item,
            apply: true,
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(result.status, ToggleStatus::Applied);
    };

    toggle("plugin-b", true);
    toggle("plugin-a", true);
    let disabled_raw = fs::read_to_string(&config_path).expect("disabled OpenCode config");
    let disabled_document: serde_json::Value =
        serde_json::from_str(&disabled_raw).expect("strict JSON remains valid");
    assert_eq!(disabled_document["plugin"], serde_json::json!(["plugin-c"]));

    toggle("plugin-b", false);
    toggle("plugin-a", false);
    assert_eq!(
        fs::read_to_string(&config_path).expect("re-enabled OpenCode config"),
        original
    );
}

#[test]
fn blocks_opencode_plugin_reenable_when_vault_payload_is_tampered() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:example-opencode-connector")
        .expect("OpenCode npm plugin");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);

    let disabled_item = discover_all(&roots)
        .expect("disabled OpenCode discovery")
        .items
        .into_iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:example-opencode-connector")
        .expect("disabled OpenCode npm plugin");
    let payload_path = Path::new(&disabled_item.state_path)
        .parent()
        .expect("vault root")
        .join("payload.json");
    fs::write(&payload_path, "\"tampered-plugin\"\n").expect("tamper vault payload");

    let blocked = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(blocked.status, ToggleStatus::Blocked);
    assert!(
        blocked
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault payload is invalid")
    );
}

#[test]
fn pi_string_package_extension_toggle_preserves_reference_backup_and_round_trip() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    let original = fs::read_to_string(&settings_path).expect("original Pi settings");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item_id = "pi:global:plugin-config:package-extensions:npm:example-pi-connector";

    let disable_once = || {
        let item = discover_all(&roots)
            .expect("Pi discovery")
            .items
            .into_iter()
            .find(|item| item.id == item_id)
            .expect("Pi package extensions");
        assert!(item.enabled);
        plan_toggle(TogglePlanInput {
            app_state_root: app_state.path().to_path_buf(),
            item,
            apply: true,
            backup_authentication_key: Some(backup_authentication_key()),
        })
    };

    let disabled = disable_once();
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("disabled Pi settings"))
            .expect("valid disabled Pi JSON");
    assert_eq!(
        disabled_document["packages"][0],
        serde_json::json!({
            "source": "npm:example-pi-connector",
            "extensions": []
        })
    );

    let disabled_item = discover_all(&roots)
        .expect("disabled Pi discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("disabled Pi package extensions");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.state_path, disabled_item.source_path);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: disabled.backup_id.expect("disable backup id"),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("backup-restored Pi settings"),
        original
    );

    let disabled = disable_once();
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled Pi discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("disabled Pi package extensions");
    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(
        enabled.status,
        ToggleStatus::Applied,
        "{}",
        enabled.reason.as_deref().unwrap_or("missing reason")
    );
    assert_eq!(
        fs::read_to_string(&settings_path).expect("re-enabled Pi settings"),
        original
    );
    let restored_enable = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enabled.backup_id.expect("enable backup id"),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored_enable.status, RestoreStatus::Restored);
    let disabled_item = discover_all(&roots)
        .expect("enable-backup-restored Pi discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("enable-backup-restored Pi package extensions");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
}

#[test]
fn pi_filtered_package_extension_toggle_restores_exact_object_entry() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy.path().join("pi/project/.pi/settings.json");
    let original = fs::read_to_string(&settings_path).expect("original Pi project settings");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item_id = "pi:project:plugin-config:package-extensions:npm:example-pi-project-connector";
    let item = discover_all(&roots)
        .expect("Pi project discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("Pi project package extensions");

    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_document: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&settings_path).expect("disabled Pi project settings"),
    )
    .expect("valid disabled Pi project JSON");
    assert_eq!(
        disabled_document["packages"][0]["extensions"],
        serde_json::json!([])
    );
    assert_eq!(
        disabled_document["packages"][0]["skills"],
        serde_json::json!([])
    );

    let disabled_item = discover_all(&roots)
        .expect("disabled Pi project discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("disabled Pi project package extensions");
    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(
        enabled.status,
        ToggleStatus::Applied,
        "{}",
        enabled.reason.as_deref().unwrap_or("missing reason")
    );
    assert_eq!(
        fs::read_to_string(&settings_path).expect("re-enabled Pi project settings"),
        original
    );
}

#[test]
fn pi_manual_disabled_package_enables_without_unpin_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    let disabled = r#"{
  "packages": [
    {
      "source": "npm:example-pi-connector",
      "extensions": [],
      "skills": ["review"]
    }
  ]
}
"#;
    fs::write(&settings_path, disabled).expect("write manually disabled Pi package");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("manual disabled Pi discovery")
        .items
        .into_iter()
        .find(|item| {
            item.id == "pi:global:plugin-config:package-extensions:npm:example-pi-connector"
        })
        .expect("manual disabled Pi package extensions");
    assert!(!item.enabled);

    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled.status, ToggleStatus::Applied);
    assert!(
        enabled.operations[0]
            .summary
            .contains("removing its empty Pi package extension filter")
    );
    let enabled_document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).expect("enabled Pi settings"))
            .expect("valid enabled Pi JSON");
    assert!(enabled_document["packages"][0].get("extensions").is_none());
    assert_eq!(
        enabled_document["packages"][0]["skills"],
        serde_json::json!(["review"])
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enabled.backup_id.expect("enable backup id"),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored manual Pi settings"),
        disabled
    );
}

#[test]
fn blocks_pi_package_reenable_when_vault_payload_is_tampered() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item_id = "pi:global:plugin-config:package-extensions:npm:example-pi-connector";
    let item = discover_all(&roots)
        .expect("Pi discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("Pi package extensions");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_item = discover_all(&roots)
        .expect("disabled Pi discovery")
        .items
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("disabled Pi package extensions");
    let payload_path = PathBuf::from(
        disabled.operations[0]
            .to_path
            .as_deref()
            .expect("Pi vault payload path"),
    );
    fs::write(&payload_path, "{}\n").expect("tamper Pi vault payload");

    let rediscovered = discover_all(&roots).expect("tampered Pi discovery");
    let read_only = rediscovered
        .items
        .iter()
        .find(|item| item.id == item_id)
        .expect("tampered Pi package remains inventoried");
    assert_eq!(read_only.mutability, DiscoveryMutability::ReadOnly);
    assert!(rediscovered.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "invalid-vault-entry"
    }));

    let blocked = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(blocked.status, ToggleStatus::Blocked);
    assert!(
        blocked
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault payload is invalid")
    );
}

#[test]
fn blocks_pi_package_disable_after_selected_entry_drift() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("Pi discovery")
        .items
        .into_iter()
        .find(|item| {
            item.id == "pi:global:plugin-config:package-extensions:npm:example-pi-connector"
        })
        .expect("Pi package extensions");
    fs::write(
        &settings_path,
        r#"{
  "packages": [
    { "source": "npm:example-pi-connector", "skills": ["new-skill"] }
  ]
}
"#,
    )
    .expect("drift Pi package entry");

    let blocked = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(blocked.status, ToggleStatus::Blocked);
    assert!(
        blocked
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("source drifted")
    );
}

#[test]
fn zed_jsonc_disable_and_reenable_preserves_formatting_and_server_comments() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed/global/.config/zed/settings.json");
    let original = r#"// Keep top-level guidance.
{
  "theme": "Ayu Dark", // Keep inline theme note.
  "context_servers": {
    // Keep unrelated server note.
    "docs": {
      "command": "python3",
      "args": ["-m", "docs"],
    },
    // Keep GitHub server note across disable/re-enable.
    "github": {
      // Keep command note inside vaulted server value.
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
    }
  },
}
"#;
    fs::write(&settings_path, original).expect("write Zed JSONC settings");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("Zed GitHub MCP");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled.status, ToggleStatus::Applied);
    let disabled_raw = fs::read_to_string(&settings_path).expect("disabled Zed settings");
    assert!(disabled_raw.contains("// Keep top-level guidance."));
    assert!(disabled_raw.contains("// Keep inline theme note."));
    assert!(disabled_raw.contains("// Keep unrelated server note."));
    assert!(disabled_raw.contains("// Keep GitHub server note across disable/re-enable."));
    assert!(!disabled_raw.contains("\"github\""));
    assert!(disabled_raw.contains("\"args\": [\"-m\", \"docs\"],"));
    assert!(serde_json::from_str::<serde_json::Value>(&disabled_raw).is_err());
    assert!(zed_context_server(&settings_path, "github").is_none());

    let vault_payload = app_state.path().join(
        "vault/zed/global/configured-mcp/zed%3Aglobal%3Aconfigured-mcp%3Agithub/payload.json",
    );
    let vaulted_raw = fs::read_to_string(&vault_payload).expect("vaulted Zed server JSONC");
    assert!(vaulted_raw.contains("// Keep command note inside vaulted server value."));
    let vault_entry = vault_payload
        .parent()
        .expect("vault payload parent")
        .join("entry.json");
    let vault_entry_raw = fs::read_to_string(&vault_entry).expect("Zed vault entry");
    assert!(!vault_entry_raw.contains("@modelcontextprotocol/server-github"));

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("disabled Zed GitHub MCP");
    assert!(!disabled_item.enabled);
    let enabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled.status, ToggleStatus::Applied);
    let reenable_backup_id = enabled.backup_id.expect("re-enable backup id");
    assert_eq!(
        fs::read_to_string(&settings_path).expect("re-enabled Zed settings"),
        original
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: reenable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored disabled Zed settings"),
        disabled_raw
    );
    assert_eq!(
        fs::read_to_string(&vault_entry).expect("restored Zed vault entry"),
        vault_entry_raw
    );

    let restored_disabled_item = discover_all(&roots)
        .expect("restored disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("restored disabled Zed GitHub MCP");
    assert!(!restored_disabled_item.enabled);
    let enabled_again = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: restored_disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_again.status, ToggleStatus::Applied);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("re-enabled restored Zed settings"),
        original
    );
}

#[test]
fn blocks_zed_jsonc_reenable_plan_when_disable_marker_drifted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed/global/.config/zed/settings.json");
    fs::write(
        &settings_path,
        r#"// Zed JSONC
{
  "context_servers": {
    "github": {
      "command": "npx",
    },
  },
}
"#,
    )
    .expect("write Zed JSONC settings");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("Zed GitHub MCP");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);

    let entry_path = app_state
        .path()
        .join("vault/zed/global/configured-mcp/zed%3Aglobal%3Aconfigured-mcp%3Agithub/entry.json");
    let entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&entry_path).expect("vault entry"))
            .expect("vault entry JSON");
    let marker = entry["jsoncFormat"]["marker"]
        .as_str()
        .expect("JSONC marker");
    let disabled_raw = fs::read_to_string(&settings_path).expect("disabled Zed settings");

    let conflict_raw =
        disabled_raw.replacen(marker, &format!("\"github\": false,\n    {marker}"), 1);
    assert_ne!(conflict_raw, disabled_raw);
    fs::write(&settings_path, &conflict_raw).expect("add malformed live Zed entry");
    let conflict_item = discover_all(&roots)
        .expect("conflict discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("disabled Zed GitHub MCP with conflict");
    let conflict_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: conflict_item,
        apply: false,
        backup_authentication_key: None,
    });
    assert_eq!(conflict_plan.status, ToggleStatus::Blocked);
    assert!(
        conflict_plan
            .reason
            .as_deref()
            .expect("conflict reason")
            .contains("live-entry-conflict")
    );
    fs::write(&settings_path, &disabled_raw).expect("remove malformed live Zed entry");

    let drifted_raw = disabled_raw.replace(marker, "/* edited marker */");
    assert_ne!(drifted_raw, disabled_raw);
    fs::write(&settings_path, &drifted_raw).expect("drift JSONC marker");

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .expect("disabled Zed GitHub MCP");
    let plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(plan.status, ToggleStatus::Blocked);
    assert!(
        plan.reason
            .as_deref()
            .expect("blocked reason")
            .contains("disable marker is missing")
    );
    assert_eq!(backup_count(app_state.path()), 1);
    assert_eq!(
        fs::read_to_string(&settings_path).expect("current Zed settings"),
        drifted_raw
    );
}

#[test]
fn applies_zed_configured_mcp_disable_rediscovers_disabled_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed")
        .join("project")
        .join(".zed")
        .join("settings.json");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "zed:project:configured-mcp:local-docs")
        .expect("zed project mcp");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(zed_context_server(&settings_path, "local-docs").is_none());
    assert!(
        serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&settings_path).expect("disabled strict Zed settings")
        )
        .is_ok()
    );

    let vault_root = app_state
        .path()
        .join("vault")
        .join("zed")
        .join("project")
        .join("configured-mcp")
        .join("zed%3Aproject%3Aconfigured-mcp%3Alocal-docs");
    assert!(vault_root.join("entry.json").exists());
    assert!(vault_root.join("payload.json").exists());

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "zed:project:configured-mcp:local-docs")
        .expect("disabled zed mcp");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(disabled_item.source_path, settings_path.to_string_lossy());
    assert!(
        disabled_item.state_path.ends_with("entry.json"),
        "disabled state path should point at vault entry, got {}",
        disabled_item.state_path
    );

    let enable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(enable_plan.status, ToggleStatus::DryRun);
    assert!(enable_plan.target_enabled);
    assert_eq!(enable_plan.operations.len(), 1);
    assert_eq!(enable_plan.operations[0].operation_type, "replaceFile");
    assert!(
        enable_plan.operations[0]
            .summary
            .contains("vaulted Zed context_servers entry")
    );

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert_eq!(
        zed_context_server(&settings_path, "local-docs").expect("restored zed context server")["command"],
        "python3"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&settings_path).expect("re-enabled strict Zed settings")
        )
        .is_ok()
    );
    assert!(!vault_root.exists());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert!(zed_context_server(&settings_path, "local-docs").is_none());
    assert!(vault_root.join("entry.json").exists());
    assert!(vault_root.join("payload.json").exists());
    let rediscovered = discover_all(&roots).expect("restored disabled discovery");
    let restored_item = rediscovered
        .items
        .iter()
        .find(|item| item.id == "zed:project:configured-mcp:local-docs")
        .expect("restored disabled zed mcp");
    assert!(!restored_item.enabled);
    assert!(restored_item.state_path.ends_with("entry.json"));

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"provider\":\"zed\""));
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn records_failed_apply_audit_when_cursor_configured_mcp_vault_conflict_blocks_guarded_setup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    let original = fs::read_to_string(&mcp_path).expect("original cursor mcp json");
    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("configured-mcp")
        .join("cursor%3Aglobal%3Aconfigured-mcp%3Amodern-global");
    fs::create_dir_all(&vault_root).expect("pre-existing vault root");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("current cursor mcp json"),
        original,
        "failed setup must not rewrite the Cursor mcp.json"
    );
    assert!(
        !app_state.path().join("backups").exists(),
        "failed setup must not create backup manifests"
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    let entries = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit entry json"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["event"], "failed-apply");
    assert_eq!(entry["selection"]["id"], item.id);
    assert_eq!(entry["targetEnabled"], false);
    assert_eq!(entry["rollbackSucceeded"], true);
    assert!(entry["rollbackFailure"].is_null());
    assert_eq!(entry["backupDeleted"], false);
    assert!(
        entry["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("vault entry already exists"))
    );
}

#[test]
fn blocks_cursor_configured_mcp_disable_when_live_disabled_state_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    assert!(item.enabled);

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&mcp_path).expect("cursor mcp json"))
            .expect("cursor mcp value");
    document["mcpServers"]["modern-global"]["disabled"] = serde_json::Value::Bool(true);
    fs::write(
        &mcp_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("drifted cursor mcp json")
        ),
    )
    .expect("write drifted cursor mcp json");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert_eq!(
        result.reason.as_deref(),
        Some(
            "Cursor configured MCP state drifted for modern-global: discovered true, current false"
        )
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(
        cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp")["disabled"],
        true
    );
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn blocks_cursor_configured_mcp_disable_when_source_payload_drifted_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    assert!(item.enabled);

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&mcp_path).expect("cursor mcp json"))
            .expect("cursor mcp value");
    document["mcpServers"]["modern-global"]["command"] =
        serde_json::Value::String("node".to_string());
    fs::write(
        &mcp_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&document).expect("drifted cursor mcp json")
        ),
    )
    .expect("write drifted cursor mcp json");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.backup_id, None);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .starts_with("Cursor configured MCP source drifted for modern-global:")
    );
    assert_eq!(result.writes.as_deref(), Some("no writes were performed"));
    assert_eq!(
        cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp")["command"],
        "node"
    );
    assert!(!app_state.path().join("backups").exists());
    assert!(!app_state.path().join("vault").exists());
    assert!(!app_state.path().join("audit").exists());
}

#[test]
fn applies_cursor_configured_mcp_disable_rediscovers_disabled_and_reenables_from_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(!disabled_apply.target_enabled);
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_none());

    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("configured-mcp")
        .join("cursor%3Aglobal%3Aconfigured-mcp%3Amodern-global");
    assert!(vault_root.join("entry.json").exists());
    let vault_payload = vault_root.join("payload.json");
    let mut payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vault_payload).expect("vault payload"))
            .expect("vault payload json");
    payload["disabled"] = serde_json::Value::Bool(true);
    fs::write(
        &vault_payload,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&payload).expect("payload json")
        ),
    )
    .expect("write disabled payload");

    let disabled_discovery = discover_all(&roots).expect("disabled discovery");
    let disabled_item = disabled_discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("disabled cursor mcp");
    assert!(!disabled_item.enabled);
    assert_eq!(disabled_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(disabled_item.source_path, mcp_path.to_string_lossy());
    assert!(
        disabled_item.state_path.ends_with("entry.json"),
        "disabled state path should point at vault entry, got {}",
        disabled_item.state_path
    );

    let enable_plan = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(enable_plan.status, ToggleStatus::DryRun);
    assert!(enable_plan.target_enabled);
    assert_eq!(enable_plan.operations.len(), 1);
    assert_eq!(enable_plan.operations[0].operation_type, "replaceFile");
    assert_eq!(
        enable_plan.writes.as_deref(),
        Some("no writes were performed")
    );

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    assert!(enabled_apply.target_enabled);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    let server = cursor_mcp_server(&mcp_path, "modern-global").expect("restored cursor mcp");
    assert_eq!(server["command"], "npx");
    assert!(server.get("disabled").is_none());
    assert!(!vault_root.exists());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&enable_backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["selection"]["id"], disabled_item.id);
    assert_eq!(manifest["targetEnabled"], true);
    let mcp_path_string = mcp_path.to_string_lossy().to_string();
    assert_eq!(
        manifest["entries"][0]["target"]["path"].as_str(),
        Some(mcp_path_string.as_str())
    );
    assert_eq!(manifest["entries"][0]["pathKind"], "file");

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"targetEnabled\":false"));
    assert!(audit.contains("\"targetEnabled\":true"));
}

#[test]
fn restoring_cursor_configured_mcp_reenable_backup_returns_item_to_disabled_vault() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    let disabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled_apply.status, ToggleStatus::Applied);
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_none());
    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("disabled cursor mcp");

    let enabled_apply = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(enabled_apply.status, ToggleStatus::Applied);
    let enable_backup_id = enabled_apply
        .backup_id
        .as_deref()
        .expect("enable backup id")
        .to_string();
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_some());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: enable_backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_none());
    let rediscovered = discover_all(&roots).expect("restored disabled discovery");
    let restored_item = rediscovered
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("restored disabled cursor mcp");
    assert!(!restored_item.enabled);
    assert!(restored_item.state_path.ends_with("entry.json"));
}

#[test]
fn blocks_cursor_configured_mcp_reenable_when_vault_metadata_drifts_after_discovery() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let item = discover_all(&roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    let disabled = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(disabled.status, ToggleStatus::Applied);

    let disabled_item = discover_all(&roots)
        .expect("disabled discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("disabled cursor mcp");
    let entry_path = PathBuf::from(&disabled_item.state_path);
    let replacement_path = PathBuf::from(&disabled_item.source_path).with_file_name("other.json");
    fs::write(&replacement_path, "{\"mcpServers\":{}}\n").expect("replacement MCP config");
    let mut entry: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&entry_path).expect("vault entry"))
            .expect("vault entry JSON");
    entry["originalPath"] =
        serde_json::Value::String(replacement_path.to_string_lossy().into_owned());
    fs::write(
        &entry_path,
        serde_json::to_string_pretty(&entry).expect("tampered entry JSON"),
    )
    .expect("tamper vault entry");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: disabled_item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .expect("blocked reason")
            .contains("vault entry does not match disabled Cursor configured MCP")
    );
}

#[test]
fn applies_and_restores_project_cursor_configured_mcp_disable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("project")
        .join(".cursor")
        .join("mcp.json");
    let original = fs::read_to_string(&mcp_path).expect("original project cursor mcp json");
    assert_eq!(
        cursor_mcp_server(&mcp_path, "project-docs").expect("project docs mcp")["command"],
        "node"
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:project:configured-mcp:project-docs")
        .expect("project cursor mcp");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(!applied.target_enabled);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    assert!(cursor_mcp_server(&mcp_path, "project-docs").is_none());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("restored project cursor mcp json"),
        original
    );
}

#[test]
fn applies_and_restores_cursor_configured_mcp_workspace_disabled_state_enable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global", "user-other"],
    );
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");
    assert_eq!(
        cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp")["command"],
        "npx"
    );

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    assert!(!item.enabled);
    assert_eq!(item.source_path, mcp_path.to_string_lossy());
    assert_eq!(item.state_path, database_path.to_string_lossy());

    let dry_run = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(dry_run.status, ToggleStatus::DryRun);
    assert!(dry_run.target_enabled);
    assert_eq!(dry_run.operations.len(), 1);
    assert_eq!(
        dry_run.operations[0].operation_type,
        "replaceSqliteItemTableValue"
    );
    assert_eq!(
        dry_run.operations[0].path.as_deref(),
        Some(item.state_path.as_str())
    );
    assert_eq!(
        dry_run.operations[0].value,
        Some(serde_json::json!(["user-other"]))
    );

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(applied.target_enabled);
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    assert_eq!(
        read_cursor_workspace_disabled_servers(&database_path),
        vec!["user-other".to_string()]
    );
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_some());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["selection"]["id"], item.id);
    assert_eq!(manifest["targetEnabled"], true);
    assert_eq!(
        manifest["entries"][0]["target"]["targetType"],
        "sqlite-item"
    );
    assert_eq!(
        manifest["entries"][0]["target"]["path"].as_str(),
        Some(database_path.to_string_lossy().as_ref())
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        read_cursor_workspace_disabled_servers(&database_path),
        vec!["user-modern-global".to_string(), "user-other".to_string()]
    );
}

#[test]
fn cursor_workspace_audit_failure_reports_committed_database_write_and_backup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global", "user-other"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");
    fs::create_dir_all(app_state.path().join("audit/log.jsonl"))
        .expect("audit log path that rejects append");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::RecoveryRequired);
    let backup_id = result
        .backup_id
        .as_deref()
        .expect("failed audit must retain the Cursor backup id");
    assert!(app_state.path().join("backups").join(backup_id).is_dir());
    assert!(
        result
            .writes
            .as_deref()
            .is_some_and(|writes| writes.contains("may already have been performed"))
    );
    assert_eq!(
        read_cursor_workspace_disabled_servers(&database_path),
        vec!["user-other".to_string()],
        "the test must reach the post-commit audit failure"
    );
}

#[test]
fn cursor_workspace_toggle_plan_does_not_create_missing_database() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");
    assert_eq!(item.state_path, database_path.to_string_lossy());
    fs::remove_file(&database_path).expect("remove workspace database");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(!database_path.exists());

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("workspace database not found"))
    );
    assert!(!database_path.exists());
}

#[cfg(unix)]
#[test]
fn cursor_workspace_toggle_rejects_symlinked_database() {
    use std::os::unix::fs::symlink;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");
    let external_database = fixture_copy.path().join("external-state.vscdb");
    fs::rename(&database_path, &external_database).expect("move workspace database");
    symlink(&external_database, &database_path).expect("symlink workspace database");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("database path is a symlink"))
    );
    assert_eq!(
        read_cursor_workspace_disabled_servers(&external_database),
        vec!["user-modern-global".to_string()]
    );
}

#[cfg(unix)]
#[test]
fn cursor_workspace_toggle_rejects_symlinked_database_parent() {
    use std::os::unix::fs::symlink;

    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");
    let database_parent = database_path.parent().expect("database parent");
    let external_parent = fixture_copy.path().join("external-workspace-state");
    fs::rename(database_parent, &external_parent).expect("move workspace database parent");
    symlink(&external_parent, database_parent).expect("symlink workspace database parent");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: false,
        backup_authentication_key: None,
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("mutation target parent contains a symlink"))
    );
    assert_eq!(
        read_cursor_workspace_disabled_servers(&external_parent.join("state.vscdb")),
        vec!["user-modern-global".to_string()]
    );
}

#[test]
fn cursor_workspace_toggle_reports_host_busy_without_writes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");

    let blocker = Connection::open(&database_path).expect("open blocker connection");
    blocker
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("lock Cursor workspace database");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    blocker
        .execute_batch("ROLLBACK")
        .expect("unlock Cursor workspace database");

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cursor-host-busy"))
    );
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("close Cursor"))
    );
    assert!(!app_state.path().join("backups").exists());
}

#[test]
fn cursor_workspace_toggle_reserves_write_before_creating_backup() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        &["user-modern-global", "user-other"],
    );
    let item = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor workspace MCP");

    let blocker = Connection::open(&database_path).expect("open blocker connection");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("reserve Cursor workspace database write access");

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item,
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    blocker
        .execute_batch("ROLLBACK")
        .expect("unlock Cursor workspace database");

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert!(
        result
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cursor-host-busy"))
    );
    assert!(
        !app_state.path().join("backups").exists(),
        "write reservation failure must happen before backup artifacts are created"
    );
    assert_eq!(
        read_cursor_workspace_disabled_servers(&database_path),
        vec!["user-modern-global".to_string(), "user-other".to_string()]
    );
}

#[test]
fn applies_and_restores_cursor_configured_mcp_disabled_flag_enable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");
    let original = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "modern-global": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "disabled": true
                }
            }
        }))
        .expect("mcp json")
    );
    fs::write(&mcp_path, &original).expect("write cursor mcp");
    assert_eq!(
        cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp")["disabled"],
        true
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");
    assert!(!item.enabled);

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(applied.status, ToggleStatus::Applied);
    assert!(applied.target_enabled);
    assert_eq!(applied.operations[0].operation_type, "replaceFile");
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    let server = cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp");
    assert_eq!(server["command"], "npx");
    assert_eq!(server["args"][0], "-y");
    assert!(server.get("disabled").is_none());

    let manifest_path = app_state
        .path()
        .join("backups")
        .join(&backup_id)
        .join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(manifest_path).expect("backup manifest"))
            .expect("manifest json");
    assert_eq!(manifest["selection"]["id"], item.id);
    assert_eq!(manifest["targetEnabled"], true);
    assert_eq!(manifest["entries"][0]["pathKind"], "file");
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("entries")
            .join("entry-1")
            .join("payload")
            .exists()
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("restored cursor mcp json"),
        original
    );
}

#[test]
fn blocks_skill_apply_when_mutation_lock_is_held() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let live_pid = process::id();
    let _held_lock = hold_mutation_lock(
        app_state.path(),
        &format!(r#"{{"pid":{live_pid},"acquiredAt":"2026-06-20T12:00:00Z"}}"#),
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    let expected_reason =
        format!("lock-contention: mutation lock is already held by pid {live_pid}");
    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(result.reason.as_deref(), Some(expected_reason.as_str()));
    assert!(original_state_path.join("SKILL.md").exists());
}

#[test]
fn reuses_unlocked_mutation_lock_with_stale_pid_metadata() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::create_dir_all(app_state.path().join("locks")).expect("locks dir");
    fs::write(
        app_state.path().join("locks").join("mutation.lock"),
        r#"{"pid":999999,"acquiredAt":"2026-06-20T12:00:00Z"}"#,
    )
    .expect("lock file");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Applied);
    assert!(!original_state_path.exists());
    assert!(
        result
            .backup_id
            .as_deref()
            .is_some_and(|id| id.starts_with("backup-"))
    );
    assert!(app_state.path().join("locks/mutation.lock").is_file());
}

#[test]
fn blocks_on_fresh_malformed_mutation_lock() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let _held_lock = hold_mutation_lock(app_state.path(), "{ invalid json");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(
        result.reason.as_deref(),
        Some("lock-contention: mutation lock is already held")
    );
    assert!(original_state_path.exists());
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn reuses_unlocked_malformed_mutation_lock() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::create_dir_all(app_state.path().join("locks")).expect("locks dir");
    fs::write(
        app_state.path().join("locks").join("mutation.lock"),
        "{ invalid json",
    )
    .expect("lock file");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Applied);
    assert!(!original_state_path.exists());
    assert!(
        result
            .backup_id
            .as_deref()
            .is_some_and(|id| id.starts_with("backup-"))
    );
    assert!(app_state.path().join("locks/mutation.lock").is_file());
}

#[cfg(unix)]
#[test]
fn blocks_symlinked_mutation_lock_without_touching_target() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let external = TempDir::new().expect("external temp dir");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let lock_dir = app_state.path().join("locks");
    let external_target = external.path().join("keep.txt");
    fs::create_dir_all(&lock_dir).expect("locks dir");
    fs::write(&external_target, "keep me").expect("external target");
    std::os::unix::fs::symlink(&external_target, lock_dir.join("mutation.lock"))
        .expect("symlink lock path");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let result = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(result.status, ToggleStatus::Blocked);
    assert_eq!(
        result.reason.as_deref(),
        Some("mutation lock path is not a regular file")
    );
    assert!(original_state_path.exists());
    assert_eq!(fs::read_to_string(external_target).unwrap(), "keep me");
    assert_eq!(backup_count(app_state.path()), 0);
}

#[test]
fn restores_skill_backup_and_removes_vault_entry() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");
    let original_state_path = PathBuf::from(&item.state_path);

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    let vault_payload = PathBuf::from(
        applied.operations[0]
            .to_path
            .as_deref()
            .expect("vault payload"),
    );
    assert!(vault_payload.join("SKILL.md").exists());
    assert!(!original_state_path.exists());

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: backup_id.clone(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Restored);
    assert_eq!(restored.backup_id, backup_id);
    assert!(original_state_path.join("SKILL.md").exists());
    assert!(!vault_payload.parent().expect("vault root").exists());
    assert!(
        app_state
            .path()
            .join("backups")
            .join(&backup_id)
            .join("manifest.json")
            .exists()
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"event\":\"apply\""));
    assert!(audit.contains("\"event\":\"restore\""));
}

#[test]
fn restore_rejects_manifest_with_mismatched_backup_id() {
    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let target_path = live_root.join("config.toml");
    let requested_backup_root = app_state.path().join("backups").join("backup-requested");
    let other_backup_root = app_state.path().join("backups").join("backup-other");
    fs::create_dir_all(&live_root).expect("live root");
    fs::create_dir_all(app_state.path().join("audit")).expect("audit root");
    fs::create_dir_all(requested_backup_root.join("entries").join("entry-1"))
        .expect("requested backup payload dir");
    fs::create_dir_all(other_backup_root.join("entries").join("entry-1"))
        .expect("other backup payload dir");
    fs::write(&target_path, "live current\n").expect("live target");
    fs::write(
        requested_backup_root
            .join("entries")
            .join("entry-1")
            .join("payload"),
        "requested payload\n",
    )
    .expect("requested backup payload");
    fs::write(
        other_backup_root
            .join("entries")
            .join("entry-1")
            .join("payload"),
        "other payload\n",
    )
    .expect("other backup payload");
    fs::write(
        requested_backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-other",
                "createdAt": "2026-06-20T12:00:00Z",
                "selection": {
                    "provider": "codex",
                    "kind": "mcp",
                    "category": "configured-mcp",
                    "layer": "global",
                    "id": "codex:global:configured-mcp:github",
                    "displayName": "github",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": target_path.to_string_lossy(),
                    "statePath": target_path.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "path", "path": target_path.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": target_path.to_string_lossy() },
                        "existed": true,
                        "pathKind": "file",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-requested".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("backup manifest id mismatch: expected backup-requested, found backup-other")
    );
    assert_eq!(
        fs::read_to_string(&target_path).expect("live target"),
        "live current\n"
    );
    assert!(
        !app_state.path().join("audit").join("log.jsonl").exists(),
        "mismatched manifest should not append restore audit"
    );
    assert!(
        !requested_backup_root.join("rollback").exists(),
        "requested backup should not get rollback scratch state"
    );
    assert!(
        !other_backup_root.join("rollback").exists(),
        "mismatched backup should not get rollback scratch state"
    );
}

#[test]
fn restore_rejects_empty_backup_manifest_before_transaction() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/config.toml");
    let backup_root = app_state.path().join("backups/backup-empty");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "backup\n").expect("backup payload");
    write_file_restore_manifest(&backup_root, "backup-empty", &target_path);
    let manifest_path = backup_root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("backup manifest"))
            .expect("manifest JSON");
    manifest["entries"] = serde_json::json!([]);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("empty manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-empty".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("backup manifest has no entries")
    );
    assert!(!target_path.exists());
    assert!(!app_state.path().join("audit").exists());
    assert!(!backup_root.join("rollback").exists());
}

#[test]
fn restore_rejects_future_backup_manifest_version_before_transaction() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/config.toml");
    let backup_root = app_state.path().join("backups/backup-future");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "backup\n").expect("backup payload");
    write_file_restore_manifest(&backup_root, "backup-future", &target_path);
    let manifest_path = backup_root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("backup manifest"))
            .expect("manifest JSON");
    manifest["version"] = serde_json::json!(4);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("future manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-future".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("unsupported backup manifest version: 4")
    );
    assert!(!target_path.exists());
    assert!(!app_state.path().join("audit").exists());
    assert!(!backup_root.join("rollback").exists());
}

#[test]
fn restore_rejects_backup_payload_owned_by_another_entry() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/config.toml");
    let backup_root = app_state.path().join("backups/backup-payload-alias");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::create_dir_all(backup_root.join("entries/entry-2")).expect("aliased backup entry");
    fs::write(backup_root.join("entries/entry-1/payload"), "owned\n").expect("owned payload");
    fs::write(backup_root.join("entries/entry-2/payload"), "aliased\n").expect("aliased payload");
    write_file_restore_manifest(&backup_root, "backup-payload-alias", &target_path);
    let manifest_path = backup_root.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("backup manifest"))
            .expect("manifest JSON");
    manifest["entries"][0]["payload"]["path"] = serde_json::json!("entries/entry-2/payload");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("aliased manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-payload-alias".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some(
            "backup entry entry-1 payload path must be entries/entry-1/payload, got entries/entry-2/payload"
        )
    );
    assert!(!target_path.exists());
    assert!(!app_state.path().join("audit").exists());
    assert!(!backup_root.join("rollback").exists());
}

#[test]
fn backup_summaries_and_restore_reject_missing_or_wrong_kind_payloads() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/config.toml");
    let valid_root = app_state.path().join("backups/backup-valid-payload");
    let missing_root = app_state.path().join("backups/backup-missing-payload");
    let wrong_kind_root = app_state.path().join("backups/backup-wrong-kind-payload");

    for (backup_root, backup_id) in [
        (&valid_root, "backup-valid-payload"),
        (&missing_root, "backup-missing-payload"),
        (&wrong_kind_root, "backup-wrong-kind-payload"),
    ] {
        fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
        write_file_restore_manifest(backup_root, backup_id, &target_path);
    }
    fs::write(valid_root.join("entries/entry-1/payload"), "valid\n").expect("valid payload");
    fs::create_dir_all(wrong_kind_root.join("entries/entry-1/payload"))
        .expect("wrong-kind payload");
    authenticate_backup(app_state.path(), "backup-valid-payload");

    let key = backup_authentication_key();
    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));
    let restorable = |backup_id: &str| {
        summaries
            .iter()
            .find(|summary| summary.backup_id == backup_id)
            .unwrap_or_else(|| panic!("missing backup summary: {backup_id}"))
            .restorable
    };
    assert!(restorable("backup-valid-payload"));
    assert!(!restorable("backup-missing-payload"));
    assert!(!restorable("backup-wrong-kind-payload"));

    for backup_id in ["backup-missing-payload", "backup-wrong-kind-payload"] {
        let restored = restore_backup(RestoreBackupInput {
            app_state_root: app_state.path().to_path_buf(),
            backup_id: backup_id.to_string(),
            backup_authentication_key: Some(backup_authentication_key()),
        });
        assert_eq!(restored.status, RestoreStatus::Failed);
    }
    assert!(!target_path.exists());
    assert!(!app_state.path().join("audit").exists());
    assert!(!missing_root.join("rollback").exists());
    assert!(!wrong_kind_root.join("rollback").exists());
}

#[test]
fn restore_rejects_payload_path_outside_backup_root() {
    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let target_path = live_root.join("config.toml");
    let backup_root = app_state.path().join("backups").join("backup-traversal");
    let outside_payload = app_state.path().join("outside-payload");
    fs::create_dir_all(&live_root).expect("live root");
    fs::create_dir_all(app_state.path().join("audit")).expect("audit root");
    fs::create_dir_all(backup_root.join("entries").join("entry-1")).expect("backup payload dir");
    fs::write(&target_path, "live current\n").expect("live target");
    fs::write(&outside_payload, "outside payload\n").expect("outside payload");
    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-traversal",
                "createdAt": "2026-06-20T12:00:00Z",
                "selection": {
                    "provider": "codex",
                    "kind": "mcp",
                    "category": "configured-mcp",
                    "layer": "global",
                    "id": "codex:global:configured-mcp:github",
                    "displayName": "github",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": target_path.to_string_lossy(),
                    "statePath": target_path.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "path", "path": target_path.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": target_path.to_string_lossy() },
                        "existed": true,
                        "pathKind": "file",
                        "payload": { "storage": "path", "path": "../../outside-payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-traversal".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        restored.reason.as_deref(),
        Some("invalid backup payload path: ../../outside-payload")
    );
    assert_eq!(
        fs::read_to_string(&target_path).expect("live target"),
        "live current\n"
    );
    assert!(
        !app_state.path().join("audit").join("log.jsonl").exists(),
        "invalid payload path should not append restore audit"
    );
    assert!(
        !backup_root.join("rollback").exists(),
        "invalid payload path should not leave rollback scratch state"
    );
}

#[test]
fn load_backup_summaries_marks_invalid_backup_ids_unrestorable() {
    let app_state = TempDir::new().expect("temp app state");

    for (backup_dir, backup_id, created_at) in [
        ("backup-valid", "backup-valid", "2026-06-20T12:02:00Z"),
        ("bad id", "bad id", "2026-06-20T12:01:00Z"),
        ("bad_id", "bad_id", "2026-06-20T12:00:00Z"),
    ] {
        let backup_root = app_state.path().join("backups").join(backup_dir);
        fs::create_dir_all(backup_root.join("entries").join("entry-1"))
            .expect("backup payload dir");
        fs::write(
            backup_root.join("entries").join("entry-1").join("payload"),
            "backup\n",
        )
        .expect("backup payload");
        fs::write(
            backup_root.join("manifest.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": 1,
                    "backupId": backup_id,
                    "createdAt": created_at,
                    "selection": {
                        "provider": "codex",
                        "kind": "mcp",
                        "category": "configured-mcp",
                        "layer": "global",
                        "id": "codex:global:configured-mcp:github",
                        "displayName": "github",
                        "enabled": true,
                        "mutability": "read-write",
                        "sourcePath": "/tmp/unpin-config.toml",
                        "statePath": "/tmp/unpin-config.toml"
                    },
                    "targetEnabled": false,
                    "affectedTargets": [
                        {
                            "targetType": "path",
                            "path": "/tmp/unpin-config.toml"
                        }
                    ],
                    "entries": [
                        {
                            "entryId": "entry-1",
                            "target": {
                                "targetType": "path",
                                "path": "/tmp/unpin-config.toml"
                            },
                            "existed": true,
                            "pathKind": "file",
                            "payload": {
                                "storage": "path",
                                "path": "entries/entry-1/payload"
                            }
                        }
                    ]
                }))
                .expect("manifest json")
            ),
        )
        .expect("manifest");
    }

    authenticate_backup(app_state.path(), "backup-valid");
    let key = backup_authentication_key();
    let summaries = load_backup_summaries_authenticated(app_state.path(), Some(&key));

    assert_eq!(summaries.len(), 3);
    assert_eq!(summaries[0].backup_id, "backup-valid");
    assert!(summaries[0].restorable);
    assert_eq!(
        summaries[0].authentication,
        BackupAuthenticationStatus::Verified
    );
    assert_eq!(summaries[1].backup_id, "bad id");
    assert!(!summaries[1].restorable);
    assert_eq!(
        summaries[1].authentication,
        BackupAuthenticationStatus::Failed
    );
    assert_eq!(summaries[2].backup_id, "bad_id");
    assert!(!summaries[2].restorable);
}

#[test]
fn failed_restore_rolls_back_already_restored_path_targets() {
    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let backup_root = app_state.path().join("backups").join("backup-rollback");
    let file_target = live_root.join("settings.json");
    let directory_target = live_root.join("existing-skill");
    fs::create_dir_all(&directory_target).expect("live directory target");
    fs::create_dir_all(backup_root.join("entries").join("entry-1").join("payload"))
        .expect("directory backup payload");
    fs::create_dir_all(backup_root.join("entries").join("entry-2")).expect("file backup dir");
    fs::write(&file_target, "live file\n").expect("live file");
    fs::write(
        backup_root
            .join("entries")
            .join("entry-1")
            .join("payload")
            .join("SKILL.md"),
        "# Restored skill\n",
    )
    .expect("directory backup file");
    fs::write(
        backup_root.join("entries").join("entry-2").join("payload"),
        "backup file\n",
    )
    .expect("file backup payload");
    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-rollback",
                "createdAt": "2026-06-20T12:00:00Z",
                "selection": {
                    "provider": "claude",
                    "kind": "skill",
                    "category": "skill",
                    "layer": "project",
                    "id": "claude:project:skill:rollback-fixture",
                    "displayName": "rollback-fixture",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": directory_target.to_string_lossy(),
                    "statePath": directory_target.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "statePath", "path": directory_target.to_string_lossy() },
                    { "targetType": "vaultPath", "path": file_target.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": directory_target.to_string_lossy() },
                        "existed": true,
                        "pathKind": "directory",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    },
                    {
                        "entryId": "entry-2",
                        "target": { "targetType": "path", "path": file_target.to_string_lossy() },
                        "existed": true,
                        "pathKind": "file",
                        "payload": { "storage": "path", "path": "entries/entry-2/payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");
    authenticate_backup(app_state.path(), "backup-rollback");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-rollback".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target already exists"))
    );
    assert_eq!(
        fs::read_to_string(&file_target).expect("rolled back file"),
        "live file\n"
    );
    assert!(directory_target.exists());
    assert!(
        !app_state.path().join("audit").join("log.jsonl").exists(),
        "failed restore should not append success audit"
    );
    assert!(
        !backup_root.join("rollback").exists(),
        "temporary rollback snapshots should be cleaned up after failed restore"
    );
}

#[test]
fn failed_restore_rolls_back_already_restored_sqlite_targets() {
    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-sqlite-rollback");
    let directory_target = live_root.join("existing-skill");
    let cursor_root = live_root.join("cursor");
    let project_root = live_root.join("project");
    let database_path =
        write_cursor_workspace_disabled_servers(&cursor_root, &project_root, &["user-current"]);
    fs::create_dir_all(&directory_target).expect("live directory target");
    fs::create_dir_all(backup_root.join("entries").join("entry-1").join("payload"))
        .expect("directory backup payload");
    fs::create_dir_all(backup_root.join("entries").join("entry-2")).expect("sqlite backup dir");
    fs::write(
        backup_root
            .join("entries")
            .join("entry-1")
            .join("payload")
            .join("SKILL.md"),
        "# Restored skill\n",
    )
    .expect("directory backup file");
    fs::write(
        backup_root.join("entries").join("entry-2").join("payload"),
        serde_json::to_vec(&vec!["user-backup"]).expect("sqlite backup payload"),
    )
    .expect("sqlite backup payload");

    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-sqlite-rollback",
                "createdAt": "2026-06-20T12:00:00Z",
                "selection": {
                    "provider": "cursor",
                    "kind": "mcp",
                    "category": "configured-mcp",
                    "layer": "global",
                    "id": "cursor:global:configured-mcp:modern-global",
                    "displayName": "modern-global",
                    "enabled": false,
                    "mutability": "read-write",
                    "sourcePath": directory_target.to_string_lossy(),
                    "statePath": database_path.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "statePath", "path": directory_target.to_string_lossy() },
                    { "targetType": "workspaceState", "path": database_path.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": directory_target.to_string_lossy() },
                        "existed": true,
                        "pathKind": "directory",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    },
                    {
                        "entryId": "entry-2",
                        "target": { "targetType": "sqlite-item", "path": database_path.to_string_lossy() },
                        "existed": true,
                        "pathKind": null,
                        "payload": { "storage": "path", "path": "entries/entry-2/payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");
    authenticate_backup(app_state.path(), "backup-sqlite-rollback");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-sqlite-rollback".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target already exists"))
    );
    assert_eq!(
        read_cursor_workspace_disabled_servers(&database_path),
        vec!["user-current".to_string()]
    );
    assert!(directory_target.exists());
    assert!(
        !app_state.path().join("audit").join("log.jsonl").exists(),
        "failed restore should not append success audit"
    );
    assert!(
        !backup_root.join("rollback").exists(),
        "temporary rollback snapshots should be cleaned up after failed restore"
    );
}

#[cfg(unix)]
#[test]
fn failed_restore_rolls_back_removed_directory_symlink_from_manifest_entries() {
    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-symlink-rollback");
    let link_target = live_root.join("target-skill");
    let provider_link = live_root.join("provider-skill");
    let conflicting_target = live_root.join("existing-skill");
    fs::create_dir_all(&link_target).expect("link target");
    fs::write(link_target.join("SKILL.md"), "# Linked\n").expect("linked skill");
    fs::create_dir_all(&conflicting_target).expect("conflicting directory");
    std::os::unix::fs::symlink("target-skill", &provider_link).expect("provider skill link");
    fs::create_dir_all(backup_root.join("entries/entry-1/payload"))
        .expect("directory backup payload");
    fs::write(
        backup_root.join("entries/entry-1/payload/SKILL.md"),
        "# Backup\n",
    )
    .expect("directory backup file");
    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-symlink-rollback",
                "createdAt": "2026-07-13T12:00:00Z",
                "selection": {
                    "provider": "claude",
                    "kind": "skill",
                    "category": "skill",
                    "layer": "global",
                    "id": "claude:global:skill:provider-skill",
                    "displayName": "provider-skill",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": provider_link.join("SKILL.md").to_string_lossy(),
                    "statePath": provider_link.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "statePath", "path": provider_link.to_string_lossy() },
                    { "targetType": "vaultPath", "path": conflicting_target.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": conflicting_target.to_string_lossy() },
                        "existed": true,
                        "pathKind": "directory",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    },
                    {
                        "entryId": "entry-2",
                        "target": { "targetType": "path", "path": provider_link.to_string_lossy() },
                        "existed": false,
                        "pathKind": null,
                        "payload": null
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");
    authenticate_backup(app_state.path(), "backup-symlink-rollback");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-symlink-rollback".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        fs::read_link(&provider_link).expect("rolled-back provider link"),
        PathBuf::from("target-skill")
    );
    assert_eq!(
        fs::read_to_string(provider_link.join("SKILL.md")).expect("linked skill after rollback"),
        "# Linked\n"
    );
    assert!(!backup_root.join("rollback").exists());
}

#[cfg(unix)]
#[test]
fn restore_rejects_file_target_replaced_by_symlink() {
    let app_state = TempDir::new().expect("temp app state");
    let external_root = TempDir::new().expect("external root");
    let live_root = app_state.path().join("live");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-file-symlink-target");
    let external_file = external_root.path().join("settings.json");
    let target_path = live_root.join("settings.json");
    fs::create_dir_all(&live_root).expect("live root");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::create_dir_all(app_state.path().join("audit")).expect("audit root");
    fs::write(&external_file, "external live\n").expect("external file");
    std::os::unix::fs::symlink(&external_file, &target_path).expect("replace target with link");
    fs::write(
        backup_root.join("entries/entry-1/payload"),
        "backup payload\n",
    )
    .expect("backup payload");
    write_file_restore_manifest(&backup_root, "backup-file-symlink-target", &target_path);
    authenticate_backup(app_state.path(), "backup-file-symlink-target");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-file-symlink-target".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore target is a symlink"))
    );
    assert_eq!(
        fs::read_to_string(&external_file).expect("external file unchanged"),
        "external live\n"
    );
    assert_eq!(
        fs::read_link(&target_path).expect("target remains symlink"),
        external_file
    );
}

#[cfg(unix)]
#[test]
fn restore_rejects_file_target_with_symlinked_parent() {
    use std::os::unix::fs::symlink;

    let app_state = TempDir::new().expect("temp app state");
    let live_root = app_state.path().join("live");
    let external_parent = app_state.path().join("external-live");
    let linked_parent = live_root.join("linked");
    let target_path = linked_parent.join("settings.json");
    let external_file = external_parent.join("settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-file-parent-symlink");
    fs::create_dir_all(&live_root).expect("live root");
    fs::create_dir_all(&external_parent).expect("external parent");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(&external_file, "external live\n").expect("external file");
    fs::write(
        backup_root.join("entries/entry-1/payload"),
        "backup payload\n",
    )
    .expect("backup payload");
    symlink(&external_parent, &linked_parent).expect("symlinked restore target parent");
    write_file_restore_manifest(&backup_root, "backup-file-parent-symlink", &target_path);
    authenticate_backup(app_state.path(), "backup-file-parent-symlink");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-file-parent-symlink".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("mutation target parent contains a symlink"))
    );
    assert_eq!(
        fs::read_to_string(&external_file).expect("external file unchanged"),
        "external live\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_rejects_symlinked_file_backup_payload() {
    let app_state = TempDir::new().expect("temp app state");
    let external_root = TempDir::new().expect("external root");
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-symlink-payload");
    let external_payload = external_root.path().join("payload.json");
    fs::create_dir_all(target_path.parent().expect("target parent")).expect("target parent");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::write(&target_path, "live config\n").expect("live config");
    fs::write(&external_payload, "external payload\n").expect("external payload");
    std::os::unix::fs::symlink(
        &external_payload,
        backup_root.join("entries/entry-1/payload"),
    )
    .expect("symlink backup payload");
    write_file_restore_manifest(&backup_root, "backup-symlink-payload", &target_path);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-symlink-payload".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("backup payload must be a regular file"))
    );
    assert_eq!(
        fs::read_to_string(&target_path).expect("live config unchanged"),
        "live config\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_rejects_symlinked_backup_payload_parent() {
    let app_state = TempDir::new().expect("temp app state");
    let external_root = TempDir::new().expect("external root");
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-symlink-payload-parent");
    let external_entries = external_root.path().join("entries");
    fs::create_dir_all(target_path.parent().expect("target parent")).expect("target parent");
    fs::create_dir_all(external_entries.join("entry-1")).expect("external backup entry");
    fs::create_dir_all(&backup_root).expect("backup root");
    fs::write(&target_path, "live config\n").expect("live config");
    fs::write(
        external_entries.join("entry-1/payload"),
        "external payload\n",
    )
    .expect("external payload");
    std::os::unix::fs::symlink(&external_entries, backup_root.join("entries"))
        .expect("symlink entries parent");
    write_file_restore_manifest(&backup_root, "backup-symlink-payload-parent", &target_path);

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-symlink-payload-parent".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("backup payload path contains a symlink"))
    );
    assert_eq!(
        fs::read_to_string(&target_path).expect("live config unchanged"),
        "live config\n"
    );
}

#[test]
fn restore_preserves_preexisting_rollback_snapshots() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-retained-rollback");
    let rollback_marker = backup_root.join("rollback/recovery-marker");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::create_dir_all(rollback_marker.parent().expect("rollback parent")).expect("rollback root");
    fs::write(backup_root.join("entries/entry-1/payload"), "backup\n").expect("backup payload");
    fs::write(&rollback_marker, "retain me\n").expect("rollback marker");
    write_file_restore_manifest(&backup_root, "backup-retained-rollback", &target_path);
    authenticate_backup(app_state.path(), "backup-retained-rollback");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-retained-rollback".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("restore rollback snapshots already exist"))
    );
    assert_eq!(
        fs::read_to_string(&rollback_marker).expect("retained rollback marker"),
        "retain me\n"
    );
    assert!(!target_path.exists());
}

#[test]
fn restore_rolls_back_provider_file_when_audit_append_fails() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-audit-failure");
    let audit_log_path = app_state.path().join("audit/log.jsonl");
    fs::create_dir_all(target_path.parent().expect("target parent")).expect("target parent");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::create_dir_all(&audit_log_path).expect("invalid audit log directory");
    fs::write(audit_log_path.join("marker"), "retain audit state\n").expect("audit marker");
    fs::write(&target_path, "live config\n").expect("live config");
    fs::write(
        backup_root.join("entries/entry-1/payload"),
        "backup config\n",
    )
    .expect("backup payload");
    write_file_restore_manifest(&backup_root, "backup-audit-failure", &target_path);
    authenticate_backup(app_state.path(), "backup-audit-failure");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-audit-failure".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert_eq!(
        fs::read_to_string(&target_path).expect("provider state rolled back"),
        "live config\n"
    );
    assert_eq!(
        fs::read_to_string(audit_log_path.join("marker")).expect("audit state rolled back"),
        "retain audit state\n"
    );
    assert!(!backup_root.join("rollback").exists());
}

#[test]
fn restore_rolls_back_provider_file_when_vault_cleanup_fails() {
    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/settings.json");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-vault-cleanup-failure");
    let vault_root = app_state
        .path()
        .join("vault/claude/global/configured-mcp")
        .join("claude%3Aglobal%3Aconfigured-mcp%3Aexample");
    fs::create_dir_all(target_path.parent().expect("target parent")).expect("target parent");
    fs::create_dir_all(backup_root.join("entries/entry-1")).expect("backup entry");
    fs::create_dir_all(vault_root.parent().expect("vault parent")).expect("vault parent");
    fs::write(&vault_root, "invalid vault root\n").expect("invalid vault root file");
    fs::write(
        backup_root.join("entries/entry-1/payload"),
        "backup config\n",
    )
    .expect("backup payload");
    write_file_restore_manifest_with_target_enabled(
        &backup_root,
        "backup-vault-cleanup-failure",
        &target_path,
        false,
    );
    authenticate_backup(app_state.path(), "backup-vault-cleanup-failure");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-vault-cleanup-failure".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(!target_path.exists(), "provider restore must roll back");
    assert_eq!(
        fs::read_to_string(&vault_root).expect("vault state rolled back"),
        "invalid vault root\n"
    );
    assert!(!backup_root.join("rollback").exists());
}

#[cfg(unix)]
#[test]
fn restore_rejects_directory_payload_with_special_file_before_writes() {
    use std::os::unix::net::UnixListener;

    let app_state = TempDir::new().expect("temp app state");
    let target_path = app_state.path().join("live/restored-skill");
    let backup_root = app_state
        .path()
        .join("backups")
        .join("backup-partial-directory");
    let payload_path = backup_root.join("entries/entry-1/payload");
    let socket_root = TempDir::new_in("/tmp").expect("short socket root");
    let socket_path = socket_root.path().join("payload.socket");
    fs::create_dir_all(&payload_path).expect("directory payload");
    fs::write(payload_path.join("SKILL.md"), "# Partial\n").expect("payload file");
    let _socket = UnixListener::bind(&socket_path).expect("special payload file");
    fs::rename(&socket_path, payload_path.join("unsupported.socket"))
        .expect("move special payload file");
    fs::write(
        backup_root.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "backupId": "backup-partial-directory",
                "createdAt": "2026-07-13T12:00:00Z",
                "selection": {
                    "provider": "claude",
                    "kind": "skill",
                    "category": "skill",
                    "layer": "global",
                    "id": "claude:global:skill:partial",
                    "displayName": "partial",
                    "enabled": false,
                    "mutability": "read-write",
                    "sourcePath": target_path.join("SKILL.md").to_string_lossy(),
                    "statePath": target_path.to_string_lossy()
                },
                "targetEnabled": true,
                "affectedTargets": [
                    { "targetType": "statePath", "path": target_path.to_string_lossy() }
                ],
                "entries": [
                    {
                        "entryId": "entry-1",
                        "target": { "targetType": "path", "path": target_path.to_string_lossy() },
                        "existed": true,
                        "pathKind": "directory-with-symlinks",
                        "payload": { "storage": "path", "path": "entries/entry-1/payload" }
                    }
                ]
            }))
            .expect("manifest json")
        ),
    )
    .expect("manifest");

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-partial-directory".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    assert!(
        restored
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("special file"))
    );
    assert!(
        !target_path.exists(),
        "invalid payload must not create restore target"
    );
    assert!(!backup_root.join("rollback").exists());
    assert!(!app_state.path().join("audit/log.jsonl").exists());
}

#[test]
fn restore_reports_invalid_and_missing_backup_ids() {
    let app_state = TempDir::new().expect("temp app state");

    let invalid = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "bad id".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(invalid.status, RestoreStatus::Failed);
    assert_eq!(invalid.reason.as_deref(), Some("invalid backup id: bad id"));

    let missing = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id: "backup-missing".to_string(),
        backup_authentication_key: Some(backup_authentication_key()),
    });
    assert_eq!(missing.status, RestoreStatus::Failed);
    assert_eq!(
        missing.reason.as_deref(),
        Some("backup manifest not found for backup-missing")
    );
}

#[test]
fn restore_blocks_when_mutation_lock_is_held() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("fixture discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");

    let applied = plan_toggle(TogglePlanInput {
        app_state_root: app_state.path().to_path_buf(),
        item: item.clone(),
        apply: true,
        backup_authentication_key: Some(backup_authentication_key()),
    });
    let backup_id = applied.backup_id.as_deref().expect("backup id").to_string();
    let live_pid = process::id();
    let _held_lock = hold_mutation_lock(
        app_state.path(),
        &format!(r#"{{"pid":{live_pid},"acquiredAt":"2026-06-20T12:00:00Z"}}"#),
    );

    let restored = restore_backup(RestoreBackupInput {
        app_state_root: app_state.path().to_path_buf(),
        backup_id,
        backup_authentication_key: Some(backup_authentication_key()),
    });

    assert_eq!(restored.status, RestoreStatus::Failed);
    let expected_reason =
        format!("lock-contention: mutation lock is already held by pid {live_pid}");
    assert_eq!(restored.reason.as_deref(), Some(expected_reason.as_str()));
}
