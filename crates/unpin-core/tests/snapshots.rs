use std::{
    fs,
    path::{Path, PathBuf},
};

use tempfile::TempDir;
use unpin_core::{
    config::get_latest_snapshot_path,
    control::build_control_status,
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput, DiscoveryRoots, DiscoveryWarning, ProviderId, discover_all,
    },
    hooks::HookTrustState,
    sessions::SessionAuthorityKey,
    snapshots::{
        DiscoverySnapshot, SnapshotWriteOptions, list_snapshot_history,
        load_latest_discovery_snapshot, write_control_snapshot, write_discovery_snapshot,
    },
};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn discovered_fixture_inventory() -> unpin_core::discovery::DiscoveryOutput {
    discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("fixture discovery")
}

fn mutate_snapshot_file(snapshot_path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(snapshot_path).expect("snapshot json"))
            .expect("snapshot value");
    mutate(&mut value);
    fs::write(
        snapshot_path,
        serde_json::to_string_pretty(&value).expect("snapshot json"),
    )
    .expect("write mutated snapshot");
}

fn item(
    provider: ProviderId,
    kind: DiscoveryKind,
    category: DiscoveryCategory,
    layer: DiscoveryLayer,
    id: &str,
    enabled: bool,
) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind,
        category,
        layer,
        id: id.to_string(),
        display_name: id.to_string(),
        enabled,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: format!("/fixtures/{id}"),
        state_path: format!("/state/{id}"),
        source_fingerprint: None,
        hook: None,
    }
}

fn warning(
    provider: ProviderId,
    layer: Option<DiscoveryLayer>,
    code: &str,
    message: &str,
) -> DiscoveryWarning {
    DiscoveryWarning {
        provider,
        layer,
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn deterministic_order_discovery() -> DiscoveryOutput {
    DiscoveryOutput {
        items: vec![
            item(
                ProviderId::Cursor,
                DiscoveryKind::Setting,
                DiscoveryCategory::ProviderSetting,
                DiscoveryLayer::Project,
                "cursor-setting",
                true,
            ),
            item(
                ProviderId::Claude,
                DiscoveryKind::Plugin,
                DiscoveryCategory::Tool,
                DiscoveryLayer::Global,
                "claude-tool",
                false,
            ),
            item(
                ProviderId::Codex,
                DiscoveryKind::Agent,
                DiscoveryCategory::Agent,
                DiscoveryLayer::Project,
                "codex-agent",
                true,
            ),
            item(
                ProviderId::Claude,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Project,
                "claude-project-skill",
                true,
            ),
            item(
                ProviderId::Claude,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Global,
                "claude-skill",
                true,
            ),
        ],
        warnings: vec![
            warning(
                ProviderId::Cursor,
                Some(DiscoveryLayer::Project),
                "z-cursor",
                "cursor warning",
            ),
            warning(
                ProviderId::Claude,
                Some(DiscoveryLayer::Project),
                "a-project",
                "claude project warning",
            ),
            warning(ProviderId::Claude, None, "c-no-layer", "claude warning"),
            warning(
                ProviderId::Codex,
                Some(DiscoveryLayer::Global),
                "a-codex",
                "codex warning",
            ),
            warning(
                ProviderId::Claude,
                Some(DiscoveryLayer::Global),
                "b-global",
                "claude global warning",
            ),
        ],
    }
}

fn assert_deterministic_snapshot_order(snapshot: &DiscoverySnapshot) {
    let item_ids = snapshot
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        item_ids,
        [
            "claude-skill",
            "claude-tool",
            "claude-project-skill",
            "codex-agent",
            "cursor-setting",
        ]
    );

    let warning_order = snapshot
        .warnings
        .iter()
        .map(|warning| {
            (
                warning.provider.as_str(),
                warning.layer.map(DiscoveryLayer::as_str),
                warning.code.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        warning_order,
        [
            ("claude", Some("global"), "b-global"),
            ("claude", None, "c-no-layer"),
            ("claude", Some("project"), "a-project"),
            ("codex", Some("global"), "a-codex"),
            ("cursor", Some("project"), "z-cursor"),
        ]
    );
}

#[test]
fn writes_latest_and_history_snapshot() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = discovered_fixture_inventory();

    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovery.clone(),
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-fixed".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");

    assert_eq!(written.snapshot.id, "snap-fixed");
    assert_eq!(written.snapshot.version, 1);
    assert!(written.snapshot.control.is_none());
    assert_eq!(written.snapshot.project_root, "/tmp/unpin/project");
    assert_eq!(written.snapshot.items, discovery.items);
    assert!(written.latest_path.ends_with("latest.json"));
    assert!(written.history_path.ends_with("history/snap-fixed.json"));
    assert!(written.latest_path.exists());
    assert!(written.history_path.exists());
    assert_eq!(
        written.snapshot.inventory.providers.len(),
        ProviderId::ALL.len()
    );
    assert!(
        written
            .snapshot
            .inventory
            .providers
            .iter()
            .any(|provider| provider.provider == ProviderId::Zed)
    );
}

#[test]
fn version_two_snapshot_round_trip_adds_redacted_control_metadata_without_runtime_state() {
    let temp = TempDir::new().expect("temp snapshot v2 root");
    let root = fs::canonicalize(temp.path()).expect("canonical snapshot v2 root");
    let app_state = root.join("state");
    let project_root = root.join("project");
    fs::create_dir(&project_root).expect("project root");
    let git = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&project_root)
        .output()
        .expect("git init");
    assert!(git.status.success());
    let mut discovery = discovered_fixture_inventory();
    let hook = discovery
        .items
        .iter_mut()
        .find_map(|item| item.hook.as_mut())
        .expect("fixture hook");
    hook.trust = HookTrustState::Reviewed {
        invocation_fingerprint: hook.invocation_fingerprint.clone(),
        profile_digest: "a".repeat(64),
    };
    let control = build_control_status(
        &discovery,
        &app_state,
        &project_root,
        &SessionAuthorityKey::new([0x53; 32]),
    )
    .expect("control status")
    .persistent_metadata();

    let written = write_control_snapshot(
        SnapshotWriteOptions {
            app_state_root: app_state.clone(),
            project_root: project_root.clone(),
            discovery,
            captured_at: Some("2026-06-20T12:00:00Z".to_string()),
            id: Some("snap-v2".to_string()),
            max_history: 20,
        },
        control,
    )
    .expect("snapshot v2 write");
    assert_eq!(written.snapshot.version, 2);
    assert!(written.snapshot.control.is_some());
    let rendered = fs::read_to_string(&written.latest_path).expect("snapshot v2 JSON");
    assert!(!rendered.contains("sessions"));
    assert!(!rendered.contains("gateways"));
    assert!(!rendered.contains("secretDigest"));
    assert!(!rendered.contains("trustReceipt"));
    assert!(!rendered.contains("\"trust\""));

    let loaded = load_latest_discovery_snapshot(&app_state, &project_root)
        .expect("snapshot v2 load")
        .expect("snapshot v2 present");
    assert_eq!(loaded, written.snapshot);
}

#[test]
fn written_snapshot_uses_public_config_path_helpers() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project with spaces");
    let discovery = discovered_fixture_inventory();

    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery,
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-config-path".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");

    let public_latest_path = get_latest_snapshot_path(app_state.path(), project_root);
    assert_eq!(written.latest_path, public_latest_path);
    assert!(public_latest_path.exists());
}

#[test]
fn writes_snapshot_items_and_warnings_in_deterministic_order() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");

    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: deterministic_order_discovery(),
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-order".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");

    assert_deterministic_snapshot_order(&written.snapshot);
}

#[test]
fn loaded_snapshots_return_deterministic_item_and_warning_order() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");

    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: deterministic_order_discovery(),
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-order-load".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");

    for path in [&written.latest_path, &written.history_path] {
        mutate_snapshot_file(path, |value| {
            value["items"]
                .as_array_mut()
                .expect("snapshot items array")
                .reverse();
            value["warnings"]
                .as_array_mut()
                .expect("snapshot warnings array")
                .reverse();
        });
    }

    let latest = load_latest_discovery_snapshot(app_state.path(), project_root)
        .expect("latest load")
        .expect("latest snapshot");
    assert_deterministic_snapshot_order(&latest);

    let history = list_snapshot_history(app_state.path(), project_root).expect("history list");
    assert_eq!(history.len(), 1);
    assert_deterministic_snapshot_order(&history[0]);
}

#[test]
fn snapshot_inventory_summarizes_kind_category_and_layer_buckets() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = DiscoveryOutput {
        items: vec![
            item(
                ProviderId::Claude,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Project,
                "claude-skill",
                true,
            ),
            item(
                ProviderId::Claude,
                DiscoveryKind::Plugin,
                DiscoveryCategory::Tool,
                DiscoveryLayer::Global,
                "claude-tool-disabled",
                false,
            ),
            item(
                ProviderId::Codex,
                DiscoveryKind::Hook,
                DiscoveryCategory::Hook,
                DiscoveryLayer::Global,
                "codex-hook",
                true,
            ),
        ],
        warnings: vec![DiscoveryWarning {
            provider: ProviderId::Claude,
            layer: Some(DiscoveryLayer::Global),
            code: "json-parse-error".to_string(),
            message: "bad settings".to_string(),
        }],
    };

    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery,
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-buckets".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");
    let inventory = serde_json::to_value(&written.snapshot.inventory).expect("inventory json");
    let claude = &inventory["providers"][0];

    assert_eq!(claude["provider"], "claude");
    assert_eq!(claude["totalAvailable"], 2);
    assert_eq!(claude["totalActive"], 1);
    assert_eq!(claude["warningCount"], 1);
    assert_eq!(
        claude["kinds"]["skill"],
        serde_json::json!({"available": 1, "active": 1})
    );
    assert_eq!(
        claude["kinds"]["plugin"],
        serde_json::json!({"available": 1, "active": 0})
    );
    assert_eq!(
        claude["categories"]["tool"],
        serde_json::json!({"available": 1, "active": 0})
    );
    assert_eq!(
        claude["categories"]["configured-mcp"],
        serde_json::json!({"available": 0, "active": 0})
    );
    assert_eq!(
        claude["layers"]["global"],
        serde_json::json!({"available": 1, "active": 0})
    );
    assert_eq!(
        claude["layers"]["project"],
        serde_json::json!({"available": 1, "active": 1})
    );
}

#[test]
fn latest_snapshot_loader_returns_none_when_latest_is_absent() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");

    let latest = load_latest_discovery_snapshot(app_state.path(), project_root)
        .expect("missing latest should not error");

    assert!(latest.is_none());
}

#[test]
fn latest_snapshot_loader_returns_validated_latest_snapshot() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = discovered_fixture_inventory();
    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery,
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-latest".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");

    let latest = load_latest_discovery_snapshot(app_state.path(), project_root)
        .expect("latest load")
        .expect("latest snapshot");

    assert_eq!(latest, written.snapshot);
}

#[test]
fn latest_snapshot_loader_rejects_malformed_latest_snapshot() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovered_fixture_inventory(),
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-latest".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");
    fs::write(&written.latest_path, "{not-valid-json}").expect("write malformed latest");

    let error = load_latest_discovery_snapshot(app_state.path(), project_root)
        .expect_err("malformed latest should fail");

    assert!(
        error.to_string().contains("latest.json"),
        "error should identify latest snapshot path; got: {error}"
    );
}

#[test]
fn latest_snapshot_loader_rejects_semantically_invalid_latest_snapshot() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let written = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovered_fixture_inventory(),
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-latest".to_string()),
        max_history: 20,
    })
    .expect("snapshot write");
    mutate_snapshot_file(&written.latest_path, |value| {
        value["inventory"]["providers"] = serde_json::json!([]);
    });

    let error = load_latest_discovery_snapshot(app_state.path(), project_root)
        .expect_err("invalid latest should fail");

    assert!(
        error.to_string().contains("latest.json"),
        "error should identify latest snapshot path; got: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("snapshot inventory does not match items and warnings"),
        "error should identify invalid inventory; got: {error}"
    );
}

#[test]
fn keeps_newest_bounded_history_entries() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = discovered_fixture_inventory();

    for (id, captured_at) in [
        ("snap-old", "2026-06-20T10:00:00Z"),
        ("snap-mid", "2026-06-20T11:00:00Z"),
        ("snap-new", "2026-06-20T12:00:00Z"),
    ] {
        write_discovery_snapshot(SnapshotWriteOptions {
            app_state_root: app_state.path().to_path_buf(),
            project_root: project_root.to_path_buf(),
            discovery: discovery.clone(),
            captured_at: Some(captured_at.to_string()),
            id: Some(id.to_string()),
            max_history: 2,
        })
        .expect("snapshot write");
    }

    let history = list_snapshot_history(app_state.path(), project_root).expect("history list");
    let ids = history
        .into_iter()
        .map(|snapshot| snapshot.id)
        .collect::<Vec<_>>();

    assert_eq!(ids, ["snap-new", "snap-mid"]);
}

#[test]
fn fails_before_writing_when_existing_history_is_malformed() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = discovered_fixture_inventory();

    let initial = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovery.clone(),
        captured_at: Some("2026-06-20T10:00:00Z".to_string()),
        id: Some("snap-initial".to_string()),
        max_history: 20,
    })
    .expect("initial snapshot write");
    let history_dir = initial
        .history_path
        .parent()
        .expect("history path has parent");
    let broken_history_path = history_dir.join("broken.json");
    fs::write(&broken_history_path, "{not-valid-json}").expect("write broken history");

    let result = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery,
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-next".to_string()),
        max_history: 20,
    });

    let error = result.expect_err("malformed history should fail snapshot write");
    assert!(
        error.to_string().contains("broken.json"),
        "error should identify malformed history path; got: {error}"
    );
    assert!(
        !history_dir.join("snap-next.json").exists(),
        "new history entry should not be written after malformed history is detected"
    );
    assert!(
        broken_history_path.exists(),
        "malformed history should be preserved for manual inspection"
    );

    let latest = fs::read_to_string(&initial.latest_path).expect("latest snapshot json");
    assert!(latest.contains("snap-initial"));
    assert!(!latest.contains("snap-next"));
}

#[test]
fn rejects_malformed_history_during_history_listing() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let initial = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovered_fixture_inventory(),
        captured_at: Some("2026-06-20T10:00:00Z".to_string()),
        id: Some("snap-initial".to_string()),
        max_history: 20,
    })
    .expect("initial snapshot write");
    let history_dir = initial
        .history_path
        .parent()
        .expect("history path has parent");
    fs::write(history_dir.join("broken.json"), "{not-valid-json}").expect("write broken history");

    let error = list_snapshot_history(app_state.path(), project_root)
        .expect_err("malformed history should fail history listing");

    assert!(
        error.to_string().contains("broken.json"),
        "error should identify malformed history path; got: {error}"
    );
}

#[test]
fn rejects_semantically_invalid_history_during_history_listing() {
    type SnapshotMutation = fn(&mut serde_json::Value);
    let cases: [(&str, SnapshotMutation, &str); 5] = [
        (
            "version.json",
            |value| value["version"] = serde_json::json!(3),
            "unsupported snapshot schema version: 3",
        ),
        (
            "id.json",
            |value| value["id"] = serde_json::json!(""),
            "snapshot id must be a non-empty string",
        ),
        (
            "captured-at.json",
            |value| value["capturedAt"] = serde_json::json!("not-a-date"),
            "snapshot capturedAt must be a valid RFC3339 timestamp",
        ),
        (
            "project-root.json",
            |value| value["projectRoot"] = serde_json::json!(""),
            "snapshot projectRoot must be a non-empty string",
        ),
        (
            "inventory.json",
            |value| value["inventory"]["providers"] = serde_json::json!([]),
            "snapshot inventory does not match items and warnings",
        ),
    ];

    for (file_name, mutate, expected_error) in cases {
        let app_state = TempDir::new().expect("temp app state");
        let project_root = Path::new("/tmp/unpin/project");
        let written = write_discovery_snapshot(SnapshotWriteOptions {
            app_state_root: app_state.path().to_path_buf(),
            project_root: project_root.to_path_buf(),
            discovery: discovered_fixture_inventory(),
            captured_at: Some("2026-06-20T10:00:00Z".to_string()),
            id: Some("snap-initial".to_string()),
            max_history: 20,
        })
        .expect("initial snapshot write");
        let history_path = written
            .history_path
            .parent()
            .expect("history path has parent")
            .join(file_name);
        fs::rename(&written.history_path, &history_path).expect("rename history file");
        mutate_snapshot_file(&history_path, mutate);

        let error = list_snapshot_history(app_state.path(), project_root)
            .expect_err("semantically invalid history should fail history listing");

        assert!(
            error.to_string().contains(file_name),
            "error should identify invalid history path; got: {error}"
        );
        assert!(
            error.to_string().contains(expected_error),
            "error should include semantic validation detail {expected_error:?}; got: {error}"
        );
    }
}

#[test]
fn fails_before_writing_when_existing_history_inventory_is_invalid() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = Path::new("/tmp/unpin/project");
    let discovery = discovered_fixture_inventory();

    let initial = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery: discovery.clone(),
        captured_at: Some("2026-06-20T10:00:00Z".to_string()),
        id: Some("snap-initial".to_string()),
        max_history: 20,
    })
    .expect("initial snapshot write");
    mutate_snapshot_file(&initial.history_path, |value| {
        value["inventory"]["providers"] = serde_json::json!([]);
    });

    let result = write_discovery_snapshot(SnapshotWriteOptions {
        app_state_root: app_state.path().to_path_buf(),
        project_root: project_root.to_path_buf(),
        discovery,
        captured_at: Some("2026-06-20T12:00:00Z".to_string()),
        id: Some("snap-next".to_string()),
        max_history: 20,
    });

    let error = result.expect_err("invalid history inventory should fail snapshot write");
    assert!(
        error
            .to_string()
            .contains("snapshot inventory does not match items and warnings"),
        "error should identify invalid inventory; got: {error}"
    );
    assert!(
        !initial
            .history_path
            .parent()
            .expect("history path has parent")
            .join("snap-next.json")
            .exists(),
        "new history entry should not be written after semantic validation fails"
    );

    let latest = fs::read_to_string(&initial.latest_path).expect("latest snapshot json");
    assert!(latest.contains("snap-initial"));
    assert!(!latest.contains("snap-next"));
}
