use std::path::{Path, PathBuf};

use tempfile::TempDir;
use unpin_core::config::{
    LoadConfigOptions, UnpinConfigOverrides, default_cursor_root, expand_home_path,
    get_activation_root, get_catalog_index_path, get_catalog_object_path, get_gateway_mode_path,
    get_gateway_modes_dir, get_global_policy_path, get_global_profile_definition_path,
    get_hook_trust_path, get_latest_snapshot_path, get_profile_revision_path,
    get_project_snapshot_key, get_project_snapshots_dir, get_repository_policy_path,
    get_session_lease_path, get_session_leases_dir, get_session_overlay_root,
    get_session_registry_lock_path, get_session_transition_admission_lock_path,
    get_snapshot_history_dir, get_transition_journal_path, get_workspace_policy_path,
    get_workspace_policy_state_path, get_workspace_profiles_dir, load_config,
    normalize_absolute_path,
};

fn write_text(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().expect("fixture file has parent"))
        .expect("create parent");
    std::fs::write(path, content).expect("write fixture file");
}

fn load_with(
    cwd: impl Into<PathBuf>,
    home_dir: impl Into<PathBuf>,
    overrides: UnpinConfigOverrides,
) -> unpin_core::config::ConfigResult<unpin_core::config::UnpinConfig> {
    load_config(LoadConfigOptions {
        cwd: cwd.into(),
        home_dir: home_dir.into(),
        overrides,
    })
}

#[test]
fn path_helpers_match_unpin_resolution_rules() {
    let temp = TempDir::new().expect("temp paths");
    let cwd = temp.path().join("workspace").join("project");
    let home_dir = temp.path().join("home");

    assert_eq!(
        expand_home_path("~/Library/Application Support", &home_dir),
        home_dir.join("Library").join("Application Support")
    );
    assert_eq!(expand_home_path("~", &home_dir), home_dir);
    assert_eq!(
        normalize_absolute_path("../other-project", &cwd, &home_dir),
        temp.path().join("workspace").join("other-project")
    );
    let expected_cursor_root = if cfg!(target_os = "macos") {
        home_dir.join("Library/Application Support/Cursor/User")
    } else if cfg!(target_os = "windows") {
        home_dir.join("AppData/Roaming/Cursor/User")
    } else {
        home_dir.join(".config/Cursor/User")
    };
    assert_eq!(
        default_cursor_root(&home_dir).expect("supported Cursor host"),
        expected_cursor_root
    );
    assert_eq!(
        get_snapshot_history_dir(Path::new("/state"), Path::new("/workspace/project")),
        get_project_snapshots_dir(Path::new("/state"), Path::new("/workspace/project"))
            .join("history")
    );
    assert_eq!(
        get_latest_snapshot_path(Path::new("/state"), Path::new("/workspace/project")),
        get_project_snapshots_dir(Path::new("/state"), Path::new("/workspace/project"))
            .join("latest.json")
    );
    assert_ne!(
        get_project_snapshot_key(Path::new("/workspace/project")),
        get_project_snapshot_key(Path::new("/workspace/other-project"))
    );
    assert_eq!(
        get_catalog_index_path("/state"),
        PathBuf::from("/state/catalog/index.json")
    );
    assert_eq!(
        get_catalog_object_path("/state", "abc"),
        PathBuf::from("/state/catalog/objects/abc.json")
    );
    assert_eq!(
        get_global_profile_definition_path("/state", "review/team"),
        PathBuf::from("/state/profiles/review%2Fteam.json")
    );
    assert_eq!(
        get_profile_revision_path("/state", "digest"),
        PathBuf::from("/state/profiles/revisions/digest.json")
    );
    assert_eq!(
        get_global_policy_path("/state"),
        PathBuf::from("/state/policy/global.json")
    );
    assert_eq!(
        get_repository_policy_path("/state", "repo/key"),
        PathBuf::from("/state/policy/repositories/repo%2Fkey.json")
    );
    assert_eq!(
        get_activation_root("/state", ".."),
        PathBuf::from("/state/activations/%2E.")
    );
    assert_eq!(
        get_transition_journal_path("/state", ".hidden-operation"),
        PathBuf::from("/state/transactions/%2Ehidden-operation.json")
    );
    assert_eq!(
        get_session_leases_dir("/state"),
        PathBuf::from("/state/runtime/sessions")
    );
    assert_eq!(
        get_session_lease_path("/state", "../session"),
        PathBuf::from("/state/runtime/sessions/%2E.%2Fsession.json")
    );
    assert_eq!(
        get_session_registry_lock_path("/state"),
        PathBuf::from("/state/runtime/session-registry")
    );
    assert_eq!(
        get_session_transition_admission_lock_path("/state", "digest"),
        PathBuf::from("/state/runtime/session-transition-admission/digest")
    );
    assert_eq!(
        get_gateway_mode_path("/state", ".global"),
        PathBuf::from("/state/runtime/modes/%2Eglobal.json")
    );
    assert_eq!(
        get_gateway_modes_dir("/state"),
        PathBuf::from("/state/runtime/modes")
    );
    assert_eq!(
        get_session_overlay_root("/state", "session/a"),
        PathBuf::from("/state/runtime/overlays/session%2Fa")
    );
    assert_eq!(
        get_workspace_profiles_dir("/workspace"),
        PathBuf::from("/workspace/.unpin/profiles")
    );
    assert_eq!(
        get_workspace_policy_path("/workspace"),
        PathBuf::from("/workspace/.unpin/policy.json")
    );
    assert_eq!(
        get_workspace_policy_state_path("/state", "repo/key", "workspace/key"),
        PathBuf::from("/state/policy/workspaces/repo%2Fkey/workspace%2Fkey.json")
    );
    assert_eq!(
        get_hook_trust_path("/state", "hook/trust"),
        PathBuf::from("/state/trust/hooks/hook%2Ftrust.json")
    );
}

#[test]
fn load_config_uses_unpin_defaults_when_no_config_files_exist() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("project");
    let home_dir = temp.path().join("home");

    let config =
        load_with(&cwd, &home_dir, UnpinConfigOverrides::default()).expect("config defaults");

    assert_eq!(config.version, 1);
    assert_eq!(config.project_root, cwd);
    assert_eq!(
        config.app_state_root,
        home_dir.join(".config").join("unpin")
    );
    assert_eq!(
        config.cursor_root,
        default_cursor_root(&home_dir).expect("supported Cursor host")
    );
    assert_eq!(
        config.config_paths.user_config_path,
        home_dir.join(".config").join("unpin").join("config.json")
    );
    assert_eq!(
        config.config_paths.project_config_path,
        config.project_root.join(".unpin.json")
    );
}

#[test]
fn load_config_merges_user_project_and_cli_precedence() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("workspace").join("project");
    let home_dir = temp.path().join("home");
    let user_project = temp.path().join("workspace").join("user-project");
    let cli_state = temp.path().join("cli-state");

    write_text(
        &home_dir.join(".config").join("unpin").join("config.json"),
        &serde_json::json!({
            "projectRoot": user_project,
            "appStateRoot": "~/user-state",
            "cursorRoot": "~/CursorUser"
        })
        .to_string(),
    );
    write_text(
        &user_project.join(".unpin.json"),
        &serde_json::json!({
            "version": 1
        })
        .to_string(),
    );

    let config = load_with(
        &cwd,
        &home_dir,
        UnpinConfigOverrides {
            app_state_root: Some(cli_state.clone()),
            ..UnpinConfigOverrides::default()
        },
    )
    .expect("merged config");

    assert_eq!(config.project_root, user_project);
    assert_eq!(config.app_state_root, cli_state);
    assert_eq!(config.cursor_root, home_dir.join("CursorUser"));
}

#[test]
fn load_config_uses_cli_project_root_for_project_config_lookup() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("workspace").join("project");
    let home_dir = temp.path().join("home");
    let user_project = temp.path().join("workspace").join("user-project");
    let cli_project = temp.path().join("workspace").join("cli-project");
    let cli_cursor = temp.path().join("cli-cursor");

    write_text(
        &home_dir.join(".config").join("unpin").join("config.json"),
        &serde_json::json!({
            "projectRoot": user_project,
            "appStateRoot": "/tmp/user-state",
            "cursorRoot": "/tmp/user-cursor"
        })
        .to_string(),
    );
    write_text(
        &cli_project.join(".unpin.json"),
        &serde_json::json!({
            "version": 1
        })
        .to_string(),
    );

    let config = load_with(
        &cwd,
        &home_dir,
        UnpinConfigOverrides {
            project_root: Some(cli_project.clone()),
            cursor_root: Some(cli_cursor.clone()),
            ..UnpinConfigOverrides::default()
        },
    )
    .expect("merged config");

    assert_eq!(config.project_root, cli_project);
    assert_eq!(config.app_state_root, PathBuf::from("/tmp/user-state"));
    assert_eq!(config.cursor_root, cli_cursor);
    assert_eq!(
        config.config_paths.project_config_path,
        config.project_root.join(".unpin.json")
    );
}

#[test]
fn load_config_rejects_project_owned_root_overrides() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("project");
    let home_dir = temp.path().join("home");

    for field in ["projectRoot", "appStateRoot", "cursorRoot"] {
        write_text(
            &cwd.join(".unpin.json"),
            &serde_json::json!({
                (field): "./repository-controlled-root"
            })
            .to_string(),
        );

        let error = load_with(&cwd, &home_dir, UnpinConfigOverrides::default())
            .expect_err("project config must not control command roots");
        assert!(
            error
                .to_string()
                .contains(&format!("{field} is not allowed in project config")),
            "unexpected error for {field}: {error}"
        );
    }
    assert!(!cwd.join("repository-controlled-root").exists());
}

#[test]
fn load_config_requires_supported_schema_versions_and_ignores_unknown_keys() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("project");
    let home_dir = temp.path().join("home");
    let config_path = home_dir.join(".config").join("unpin").join("config.json");

    for unsupported_version in [0, 2] {
        write_text(
            &config_path,
            &serde_json::json!({
                "version": unsupported_version
            })
            .to_string(),
        );
        let error = load_with(&cwd, &home_dir, UnpinConfigOverrides::default())
            .expect_err("unsupported version should fail");
        assert!(
            error.to_string().contains(&format!(
                "Unsupported unpin config schema version: {unsupported_version}"
            )),
            "unexpected error: {error}"
        );
    }

    write_text(
        &config_path,
        &serde_json::json!({
            "version": 1,
            "projectRoot": "/workspace/from-user",
            "unknownFutureKey": {
                "keep": "ignored"
            }
        })
        .to_string(),
    );
    let config =
        load_with(&cwd, &home_dir, UnpinConfigOverrides::default()).expect("unknown keys ignored");
    assert_eq!(config.version, 1);
    assert_eq!(config.project_root, PathBuf::from("/workspace/from-user"));
}

#[test]
fn load_config_rejects_invalid_path_fields_instead_of_falling_back() {
    let temp = TempDir::new().expect("temp config");
    let cwd = temp.path().join("project");
    let home_dir = temp.path().join("home");
    let config_path = home_dir.join(".config").join("unpin").join("config.json");

    for (field, value, expected) in [
        (
            "projectRoot",
            serde_json::json!(42),
            "projectRoot must be a string or null",
        ),
        (
            "appStateRoot",
            serde_json::json!("  "),
            "appStateRoot must not be empty",
        ),
        (
            "cursorRoot",
            serde_json::json!([]),
            "cursorRoot must be a string or null",
        ),
    ] {
        write_text(
            &config_path,
            &serde_json::json!({
                (field): value
            })
            .to_string(),
        );

        let error = load_with(&cwd, &home_dir, UnpinConfigOverrides::default())
            .expect_err("invalid path field should fail");
        assert!(
            error.to_string().contains(expected),
            "unexpected error for {field}: {error}"
        );
    }
}
