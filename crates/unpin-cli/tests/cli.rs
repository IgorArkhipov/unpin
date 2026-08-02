use assert_cmd::Command;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output},
};
#[cfg(unix)]
use std::{
    process::Stdio,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        ControlApprovalContext, authorize_control,
    },
    catalog::Catalog,
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryRoots, ProviderId, discover_all,
    },
    fixture::{FixtureCredentialPurpose, fixture_credential_key},
    groups::{
        GroupAccessContext, GroupController, GroupDefinitionV1, GroupMemberIdentity, GroupPlanMode,
        GroupPlanner, GroupRef, GroupResolver, GroupScope, GroupTargetState, PersonalGroupStore,
        RepositoryGroupStore,
    },
    mutation::{
        BackupAuthenticationKey, NativeToggleController, ToggleStatus, authenticate_legacy_backup,
    },
    profiles::{
        PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope, ProfileStore,
        compile_profile,
    },
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, LeaseLifecycle,
        PinnedExposure, PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
    state::atomic_json::OwnerGeneration,
    state::workspace::resolve_workspace_identity,
};
#[cfg(unix)]
use unpin_core::{
    profiles::{PolicyStore, PolicyTarget},
    sessions::{GatewayModeManager, GatewayModeTarget},
};

fn session_authority_key(app_state_root: &Path) -> SessionAuthorityKey {
    SessionAuthorityKey::new(
        fixture_credential_key(app_state_root, FixtureCredentialPurpose::SessionAuthority)
            .expect("fixture session authority key"),
    )
}

fn backup_authentication_key(app_state_root: &Path) -> BackupAuthenticationKey {
    BackupAuthenticationKey::new(
        fixture_credential_key(
            app_state_root,
            FixtureCredentialPurpose::BackupAuthentication,
        )
        .expect("fixture backup authentication key"),
    )
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate has workspace crates parent")
        .join("unpin-core")
        .join("tests")
        .join("fixtures")
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

fn write_text(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("fixture file has parent")).expect("create parent");
    fs::write(path, content).expect("write fixture file");
}

fn run_group_command(
    fixture_root: &Path,
    project_root: &Path,
    app_state_root: &Path,
    args: &[&str],
) -> Output {
    Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("group")
        .args(args)
        .arg("--fixture-root")
        .arg(fixture_root)
        .arg("--project-root")
        .arg(project_root)
        .arg("--home-root")
        .arg(fixture_root)
        .arg("--app-state-root")
        .arg(app_state_root)
        .arg("--json")
        .output()
        .expect("group command output")
}

fn assert_success_json(output: Output, label: &str) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{label} should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{label} should return JSON: {error}"))
}

fn run_git(cwd: &Path, args: &[&str]) {
    let output = StdCommand::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn detached_unpin_command() -> StdCommand {
    use std::os::unix::process::CommandExt;

    unsafe extern "C" {
        fn setsid() -> std::os::raw::c_int;
    }

    let mut command = StdCommand::new(env!("CARGO_BIN_EXE_unpin"));
    // SAFETY: `setsid` is async-signal-safe and called without captured state
    // between fork and exec. A new session guarantees `/dev/tty` cannot open.
    unsafe {
        command.pre_exec(|| {
            // SAFETY: POSIX `setsid` has no pointer arguments and only mutates
            // calling process session membership.
            if setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command
}

#[cfg(unix)]
fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

fn run_reviewed_restore(
    backup_id: &str,
    final_json: bool,
    configure: impl Fn(&mut Command),
) -> Output {
    let mut planned = Command::cargo_bin("unpin").expect("unpin binary");
    planned.arg("restore").arg(backup_id);
    configure(&mut planned);
    planned.arg("--json");
    let planned = planned.output().expect("restore plan output");
    assert!(
        planned.status.success(),
        "restore planning should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_json: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("restore plan is json");
    let fingerprint = planned_json["plan"]["planFingerprint"]
        .as_str()
        .expect("restore plan fingerprint");

    let mut applied = Command::cargo_bin("unpin").expect("unpin binary");
    applied.arg("restore").arg(backup_id);
    configure(&mut applied);
    applied
        .args(["--apply", "--confirm", "--plan-fingerprint"])
        .arg(fingerprint);
    if final_json {
        applied.arg("--json");
    }
    let applied = applied.output().expect("restore apply output");
    assert!(
        applied.status.success(),
        "restore apply should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    applied
}

fn run_reviewed_toggle(final_json: bool, configure: impl Fn(&mut Command)) -> Output {
    let mut planned = Command::cargo_bin("unpin").expect("unpin binary");
    planned.arg("toggle");
    configure(&mut planned);
    planned.arg("--json");
    let planned = planned.output().expect("toggle plan output");
    assert!(
        planned.status.success(),
        "toggle planning should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_json: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("toggle plan is json");
    let fingerprint = planned_json["planFingerprint"]
        .as_str()
        .expect("toggle plan fingerprint");

    let mut applied = Command::cargo_bin("unpin").expect("unpin binary");
    applied.arg("toggle");
    configure(&mut applied);
    applied
        .args(["--apply", "--confirm", "--plan-fingerprint"])
        .arg(fingerprint);
    if final_json {
        applied.arg("--json");
    }
    let applied = applied.output().expect("toggle apply output");
    assert!(
        applied.status.success(),
        "toggle apply should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    applied
}

fn apply_native_toggle_for_test(
    app_state_root: &Path,
    item: DiscoveryItem,
) -> unpin_core::mutation::ToggleResult {
    let context =
        ControlApprovalContext::new("test-repository", "test-workspace").expect("context");
    let controller = NativeToggleController::with_session_authority_key(
        app_state_root,
        session_authority_key(app_state_root),
    );
    let plan = controller.plan(item, &context).expect("native toggle plan");
    let expectation = plan
        .approval_expectation(&context)
        .expect("approval expectation");
    let key = ApprovalKey::new([0x71; 32]);
    let issuer = ApprovalIssuer::new(
        key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer");
    let now_unix = 2_000_000_000;
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: "receipt-cli-native-toggle".to_string(),
            nonce: "nonce-cli-native-toggle".to_string(),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 60,
        })
        .expect("approval receipt");
    let authorization = authorize_control(
        app_state_root,
        &receipt,
        &ApprovalVerifier::new(key),
        &expectation,
        now_unix,
        OwnerGeneration::new("cli-native-toggle-test", 1).expect("owner"),
    )
    .expect("control authorization");
    controller
        .apply(
            &plan,
            authorization,
            &context,
            backup_authentication_key(app_state_root),
        )
        .expect("native toggle apply")
}

fn write_backup_manifest(
    app_state_root: &Path,
    backup_id: &str,
    created_at: &str,
    entry_count: usize,
) {
    let entries = (0..entry_count)
        .map(|index| {
            let entry_id = format!("entry-{index}");
            serde_json::json!({
                "entryId": entry_id,
                "target": {
                    "targetType": "path",
                    "path": "/tmp/unpin-live-target"
                },
                "existed": true,
                "pathKind": "file",
                "payload": {
                    "storage": "path",
                    "path": format!("entries/{entry_id}/payload")
                }
            })
        })
        .collect::<Vec<_>>();
    write_text(
        &app_state_root
            .join("backups")
            .join(backup_id)
            .join("manifest.json"),
        &serde_json::json!({
            "version": 1,
            "backupId": backup_id,
            "createdAt": created_at,
            "selection": {
                "provider": "claude",
                "kind": "skill",
                "category": "skill",
                "layer": "project",
                "id": "claude:project:skill:example",
                "displayName": "example",
                "enabled": true,
                "mutability": "read-write",
                "sourcePath": "/tmp/unpin-source",
                "statePath": "/tmp/unpin-state"
            },
            "targetEnabled": false,
            "affectedTargets": [
                {
                    "targetType": "path",
                    "path": "/tmp/unpin-live-target"
                }
            ],
            "entries": entries
        })
        .to_string(),
    );
    for index in 0..entry_count {
        write_text(
            &app_state_root
                .join("backups")
                .join(backup_id)
                .join("entries")
                .join(format!("entry-{index}"))
                .join("payload"),
            "backup\n",
        );
    }
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
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("zed settings json"))
            .expect("zed settings value");
    value["context_servers"]
        .as_object()?
        .get(server_id)
        .cloned()
}

fn line_request(request: serde_json::Value) -> String {
    format!("{request}\n")
}

fn response_bodies(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(output.to_vec())
        .expect("MCP output is utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("MCP line is JSON"))
        .collect()
}

#[test]
fn help_lists_planned_command_surface() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("--help")
        .output()
        .expect("help output");

    assert!(output.status.success(), "help should exit successfully");
    let stdout = String::from_utf8(output.stdout).expect("help stdout is utf8");

    for expected in [
        "auth",
        "providers",
        "doctor",
        "snapshot",
        "list",
        "toggle",
        "restore",
        "session",
        "catalog",
        "profile",
        "gateway",
        "hook",
        "mcp",
        "tui",
    ] {
        assert!(
            stdout.contains(expected),
            "help output should include {expected:?}; got:\n{stdout}"
        );
    }
}

#[test]
fn hook_trust_is_profile_bound_and_visible_as_stored_decision() {
    let temp = TempDir::new().expect("temporary hook trust root");
    let root = fs::canonicalize(temp.path()).expect("canonical hook trust root");
    let project = root.join("project");
    let state = root.join("state");
    let fixtures = fixtures_root();
    fs::create_dir(&project).expect("project directory");
    run_git(&project, &["init", "-q"]);

    let discovery = discover_all(&DiscoveryRoots::fixture_root(&fixtures)).expect("discovery");
    let catalog = Catalog::from_discovery(&discovery).expect("catalog");
    let hook_item = discovery
        .items
        .iter()
        .find(|item| item.provider == ProviderId::Codex && item.kind == DiscoveryKind::Hook)
        .expect("discovered Codex hook");
    let hook_id = hook_item.id.clone();
    let hook_capability_id = catalog
        .find_provider_view(ProviderId::Codex, &hook_id)
        .expect("Codex hook capability")
        .id
        .clone();
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "hook-review".to_string(),
        display_name: "Hook review".to_string(),
        description: None,
        members: vec![hook_capability_id],
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    let compiled = compile_profile(&definition, &catalog, ProfileSourceScope::Global)
        .expect("compile profile");
    ProfileStore::new(&state)
        .materialize_revision(&compiled, OwnerGeneration::new("cli-hook-test", 1).unwrap())
        .expect("materialize profile");

    let common = [
        "hook",
        "trust",
        "--provider",
        "codex",
        "--id",
        hook_id.as_str(),
        "--profile-digest",
        compiled.digest.as_str(),
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];
    let planned = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["activation"], "next-session-only");
    let cli_fingerprint = planned["planFingerprint"].as_str().unwrap();
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "hook-trust-plan",
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_hook_trust",
            "arguments": {
                "provider": "codex",
                "id": hook_id,
                "profileDigest": compiled.digest
            }
        }
    }));
    let mcp_planned = Command::cargo_bin("unpin")
        .unwrap()
        .args(["mcp", "--fixture-root"])
        .arg(&fixtures)
        .args(["--project-root"])
        .arg(&project)
        .args(["--app-state-root"])
        .arg(&state)
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP hook trust plan");
    assert!(
        mcp_planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&mcp_planned.stdout),
        String::from_utf8_lossy(&mcp_planned.stderr)
    );
    let bodies = response_bodies(&mcp_planned.stdout);
    let fingerprint = bodies[0]["result"]["structuredContent"]["planFingerprint"]
        .as_str()
        .expect("MCP hook trust fingerprint");
    assert_eq!(fingerprint, cli_fingerprint);

    let applied = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["status"], "trusted");
    assert_eq!(applied["activation"], "next-session-only");

    let listed = Command::cargo_bin("unpin")
        .unwrap()
        .args([
            "hook",
            "list",
            "--profile-digest",
            compiled.digest.as_str(),
            "--fixture-root",
            fixtures.to_str().unwrap(),
            "--project-root",
            project.to_str().unwrap(),
            "--app-state-root",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(
        listed["hooks"].as_array().unwrap().iter().any(|entry| {
            entry["item"]["id"] == hook_id && entry["storedTrustDecision"] == true
        })
    );
}

#[test]
fn catalog_adoption_requires_reviewed_plan_and_preserves_canonical_copy() {
    let temp = TempDir::new().expect("temporary catalog adoption root");
    let root = fs::canonicalize(temp.path()).expect("canonical catalog adoption root");
    let fixture_copy = root.join("fixtures");
    let project = root.join("project");
    let state = root.join("state");
    copy_dir_all(&fixtures_root(), &fixture_copy);
    fs::create_dir(&project).expect("project directory");
    run_git(&project, &["init", "-q"]);

    let discovery = discover_all(&DiscoveryRoots::fixture_root(&fixture_copy)).expect("discovery");
    let item = discovery
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Codex
                && item.kind == DiscoveryKind::Skill
                && item.is_catalog_adoption_candidate()
                && item.source_path.contains("/codex/")
        })
        .expect("adoptable Codex skill");
    let source = PathBuf::from(&item.source_path);
    let provider_root = source.parent().expect("provider skill root").to_path_buf();
    let common = [
        "catalog",
        "adopt",
        "--provider",
        "codex",
        "--id",
        item.id.as_str(),
        "--provider-root",
        provider_root.to_str().unwrap(),
        "--fixture-root",
        fixture_copy.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];

    let planned = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["humanApprovalRequired"], true);
    let fingerprint = planned["planFingerprint"].as_str().unwrap();

    let applied = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["status"], "completed");
    assert_eq!(applied["result"]["status"], "committed");
    assert!(
        !source.exists(),
        "native view should be withdrawn after backup"
    );

    let canonical = fs::read_dir(state.join("catalog/adopted"))
        .expect("adopted catalog root")
        .next()
        .expect("catalog capability directory")
        .expect("catalog capability entry")
        .path();
    assert!(
        canonical
            .read_dir()
            .expect("fingerprint directory")
            .next()
            .is_some(),
        "canonical copy should remain available"
    );
}

#[test]
fn session_end_uses_reviewed_plan_and_fences_future_admission() {
    let temp = TempDir::new().expect("temporary session end root");
    let root = fs::canonicalize(temp.path()).expect("canonical session end root");
    let project = root.join("project");
    let state = root.join("state");
    let fixtures = fixtures_root();
    fs::create_dir(&project).expect("project directory");
    run_git(&project, &["init", "-q"]);
    let identity = resolve_workspace_identity(&project).expect("workspace identity");
    let manager = SessionManager::with_authority_key(&state, session_authority_key(&state));
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64;
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: identity.repository_key,
        workspace_key: identity.workspace_key,
        workspace_revision: None,
        exposure: PinnedExposure {
            revision: "e".repeat(64),
            profile: PinnedProfile::Native,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: std::process::id(),
            start_marker: "cli-session-end-test".to_string(),
        },
        connection_scope_id: "cli-session-end-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["provider-config".to_string()]),
        lease_expires_at_unix: now_unix + 3_600,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "cli-session-end-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = manager
        .prepare_bootstrap(request, now_unix)
        .expect("prepare session");
    let session = manager
        .claim_bootstrap(&authority, &claim, now_unix + 1)
        .expect("claim session");
    let common = [
        "session",
        "end",
        "--id",
        session.lease.lease.session_id.as_str(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--json",
    ];
    let planned = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(planned["status"], "planned");
    let fingerprint = planned["plan"]["planFingerprint"].as_str().unwrap();

    let applied = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["result"]["status"], "revocation-requested");
    let leases = manager
        .list()
        .expect("revoking session remains for owner cleanup");
    assert_eq!(leases[0].lease.lifecycle, LeaseLifecycle::Revoking);
    assert!(!leases[0].lease.admission_open);
}

#[test]
fn gateway_install_on_and_status_share_reviewed_scope_plan() {
    let temp = TempDir::new().expect("temporary gateway root");
    let root = fs::canonicalize(temp.path()).expect("canonical gateway root");
    let project = root.join("project");
    let state = root.join("state");
    let fixtures = fixtures_root();
    fs::create_dir(&project).expect("project directory");
    run_git(&project, &["init", "-q"]);
    let common = [
        "--scope",
        "workspace",
        "--provider",
        "codex",
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--json",
    ];

    for action in ["install", "on"] {
        let planned = Command::cargo_bin("unpin")
            .unwrap()
            .args(["gateway", action])
            .args(common)
            .output()
            .unwrap();
        assert!(
            planned.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&planned.stdout),
            String::from_utf8_lossy(&planned.stderr)
        );
        let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
        assert_eq!(planned["status"], "planned");
        assert_eq!(planned["nativeMcpReferences"], "not-managed");
        let fingerprint = planned["planFingerprint"].as_str().unwrap();
        let applied = Command::cargo_bin("unpin")
            .unwrap()
            .args(["gateway", action])
            .args(common)
            .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
            .output()
            .unwrap();
        assert!(
            applied.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&applied.stdout),
            String::from_utf8_lossy(&applied.stderr)
        );
        let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
        assert_eq!(applied["nativeMcpReferences"], "not-managed");
    }

    let status = Command::cargo_bin("unpin")
        .unwrap()
        .args(["gateway", "status"])
        .args(common)
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["mode"]["installation"], "installed");
    assert_eq!(status["mode"]["routing"], "active");
    assert_eq!(status["policy"]["providers"]["codex"]["gateway"], "gateway");
    assert_eq!(status["providerCoverage"][0]["provider"], "codex");
    assert_eq!(status["runtime"]["routingIntentActive"], true);
    assert_eq!(
        status["runtime"]["configuredRoutingIsLive"],
        serde_json::Value::Null
    );
    assert_eq!(status["runtime"]["runtimeObservation"], "not-performed");
    assert_eq!(status["runtime"]["nativeMcpReferences"], "not-managed");
}

#[test]
#[cfg(unix)]
fn detached_live_profile_apply_fails_before_mutation() {
    let temp = TempDir::new().expect("temporary noninteractive approval root");
    let root = fs::canonicalize(temp.path()).expect("canonical approval root");
    let home = root.join("home");
    let project = root.join("project");
    let cursor = root.join("cursor");
    let state = root.join("state");
    for directory in [&home, &project, &cursor] {
        fs::create_dir_all(directory).expect("test root");
    }
    run_git(&project, &["init", "-q"]);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "noninteractive-review".to_string(),
        display_name: "Noninteractive review".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    ProfileStore::new(&state)
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("cli-noninteractive-test", 1).unwrap(),
        )
        .expect("save global profile");

    let common = [
        "profile",
        "apply",
        "--id",
        definition.id.as_str(),
        "--scope",
        "workspace",
        "--mode",
        "native",
        "--home-root",
        home.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--cursor-root",
        cursor.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];
    let planned = StdCommand::new(env!("CARGO_BIN_EXE_unpin"))
        .args(common)
        .output()
        .expect("profile plan output");
    assert!(
        planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_json: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("profile plan JSON");
    let fingerprint = planned_json["plan"]["planFingerprint"]
        .as_str()
        .expect("plan fingerprint");
    let identity = resolve_workspace_identity(&project).expect("workspace identity");
    let target =
        PolicyTarget::workspace(&identity.repository_key, &identity.workspace_key).unwrap();
    assert!(
        PolicyStore::new(&state)
            .load(&target)
            .expect("policy state before apply")
            .is_none()
    );

    let applied = detached_unpin_command()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .expect("detached profile apply output");
    assert!(!applied.status.success(), "detached apply must fail closed");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(
        output.contains("interactive human approval requires a controlling terminal"),
        "unexpected output: {output}"
    );
    assert!(
        PolicyStore::new(&state)
            .load(&target)
            .expect("policy state after apply")
            .is_none(),
        "failed approval must not mutate profile policy"
    );
}

#[test]
fn fixture_credentials_cannot_authorize_non_temporary_profile_scope() {
    let temp = TempDir::new().expect("temporary fixture authority state");
    let state = fs::canonicalize(temp.path()).expect("canonical state root");
    let project = std::env::current_dir().expect("repository project root");
    let fixtures = fixtures_root();
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "fixture-authority-boundary".to_string(),
        display_name: "Fixture authority boundary".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    ProfileStore::new(&state)
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("cli-fixture-boundary-test", 1).unwrap(),
        )
        .expect("save global profile");

    let common = [
        "profile",
        "apply",
        "--id",
        definition.id.as_str(),
        "--scope",
        "workspace",
        "--mode",
        "native",
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];
    let planned = StdCommand::new(env!("CARGO_BIN_EXE_unpin"))
        .args(common)
        .output()
        .expect("fixture profile plan output");
    assert!(
        planned.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_json: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("profile plan JSON");
    let fingerprint = planned_json["plan"]["planFingerprint"]
        .as_str()
        .expect("plan fingerprint");

    let applied = StdCommand::new(env!("CARGO_BIN_EXE_unpin"))
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .expect("fixture profile apply output");
    assert!(!applied.status.success(), "fixture escape must fail closed");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(
        output.contains("fixture apply is confined to private temporary paths"),
        "unexpected output: {output}"
    );
}

#[test]
fn profile_list_and_apply_use_reviewed_next_session_policy_plan() {
    let temp = TempDir::new().expect("temporary profile root");
    let root = fs::canonicalize(temp.path()).expect("canonical profile root");
    let project = root.join("project");
    let state = root.join("state");
    let fixtures = fixtures_root();
    fs::create_dir(&project).expect("project directory");
    run_git(&project, &["init", "-q"]);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "empty-review".to_string(),
        display_name: "Empty review".to_string(),
        description: Some("Profile surface test".to_string()),
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    ProfileStore::new(&state)
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("cli-profile-test", 1).unwrap(),
        )
        .expect("save global profile");

    let list = Command::cargo_bin("unpin")
        .unwrap()
        .args([
            "profile",
            "list",
            "--fixture-root",
            fixtures.to_str().unwrap(),
            "--project-root",
            project.to_str().unwrap(),
            "--app-state-root",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed["profiles"][0]["definition"]["id"], "empty-review");
    assert_eq!(listed["profiles"][0]["scope"], "global");

    let proposal = Command::cargo_bin("unpin")
        .unwrap()
        .args([
            "profile",
            "propose",
            "--prompt",
            "Please use empty review for this patch",
            "--provider",
            "codex",
            "--fixture-root",
            fixtures.to_str().unwrap(),
            "--project-root",
            project.to_str().unwrap(),
            "--app-state-root",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        proposal.status.success(),
        "{}",
        String::from_utf8_lossy(&proposal.stderr)
    );
    let proposal_text = String::from_utf8(proposal.stdout).unwrap();
    assert!(!proposal_text.contains("Please use empty review"));
    let proposal: serde_json::Value = serde_json::from_str(&proposal_text).unwrap();
    assert_eq!(proposal["status"], "proposed");
    assert_eq!(
        proposal["proposal"]["recommended"]["profileId"],
        "empty-review"
    );
    assert_eq!(proposal["proposal"]["confirmationRequired"], true);
    assert_eq!(proposal["proposal"]["mutatesState"], false);
    assert!(!state.join("policies").exists());

    let common = [
        "profile",
        "apply",
        "--id",
        "empty-review",
        "--provider",
        "codex",
        "--scope",
        "workspace",
        "--mode",
        "gateway",
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];
    let dry_run = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let planned: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["plan"]["activation"], "next-session-only");
    let fingerprint = planned["plan"]["planFingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let applied = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", &fingerprint])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["result"]["activation"], "next-session-only");
    assert_eq!(
        applied["result"]["policy"]["providers"]["codex"]["gateway"],
        "gateway"
    );
}

#[test]
fn capability_lock_cli_uses_global_provider_plan_and_reports_pinned_revision() {
    let temp = TempDir::new().expect("temporary capability lock root");
    let root = fs::canonicalize(temp.path()).expect("canonical capability lock root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private capability lock root");
    }
    let project = root.join("project");
    let state = root.join("state");
    let fixtures = fixtures_root();
    fs::create_dir(&project).expect("project directory");
    fs::create_dir(&state).expect("state directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("private capability lock state");
    }
    run_git(&project, &["init", "-q"]);

    let common = [
        "profile",
        "lock",
        "--provider",
        "codex",
        "--capability",
        "skill.review",
        "--state",
        "hard-disabled",
        "--fixture-root",
        fixtures.to_str().unwrap(),
        "--project-root",
        project.to_str().unwrap(),
        "--app-state-root",
        state.to_str().unwrap(),
        "--json",
    ];
    let dry_run = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .output()
        .unwrap();
    assert!(
        dry_run.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&dry_run.stdout),
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let planned: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["plan"]["target"]["scope"], "global");
    assert_eq!(planned["plan"]["provider"], "codex");
    assert_eq!(planned["plan"]["activation"], "next-session-only");
    let fingerprint = planned["plan"]["planFingerprint"].as_str().unwrap();

    let applied = Command::cargo_bin("unpin")
        .unwrap()
        .args(common)
        .args(["--apply", "--confirm", "--plan-fingerprint", fingerprint])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );

    let status = Command::cargo_bin("unpin")
        .unwrap()
        .args([
            "profile",
            "locks",
            "--provider",
            "codex",
            "--fixture-root",
            fixtures.to_str().unwrap(),
            "--project-root",
            project.to_str().unwrap(),
            "--app-state-root",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["locks"][0]["provider"], "codex");
    assert_eq!(
        status["locks"][0]["entries"]["skill.review"],
        "hard-disabled"
    );
    assert_eq!(status["locks"][0]["activation"], "next-session-only");
    assert_eq!(status["locks"][0]["source"], "global");
    assert_eq!(status["locks"][0]["digest"].as_str().unwrap().len(), 64);
}

#[cfg(unix)]
#[test]
fn session_launch_uses_private_nonsecret_overlay_and_cleans_runtime_state() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let temp = TempDir::new().expect("temporary session launch root");
    let temp_path = fs::canonicalize(temp.path()).expect("canonical session root");
    let home = temp_path.join("home");
    let project = temp_path.join("project");
    let app_state = temp_path.join("state");
    let host = temp_path.join("fake-host.sh");
    let host_output = temp_path.join("host-output.txt");
    let gateway_output = temp_path.join("gateway-output.jsonl");
    let bridge_socket = temp_path.join("bridge.sock");
    let _bridge = UnixListener::bind(&bridge_socket).expect("bridge control socket");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&project).expect("project root");
    fs::write(
        &host,
        r#"#!/bin/sh
set -eu
output="$1"
gateway_output="$2"
{
  printf 'session=%s\n' "$UNPIN_SESSION_ID"
  printf 'gateway=%s\n' "$UNPIN_GATEWAY_MODE"
  printf 'overlay=%s\n' "$UNPIN_CONFIG_OVERLAY"
  printf 'repository=%s\n' "$UNPIN_REPOSITORY_KEY"
  printf 'workspace=%s\n' "$UNPIN_WORKSPACE_KEY"
  printf 'provider=%s\n' "$UNPIN_PROVIDER"
  printf 'bridge=%s\n' "$UNPIN_BRIDGE_SOCKET"
  printf 'gateway_socket=%s\n' "$UNPIN_GATEWAY_SOCKET"
  printf 'args=%s\n' "$*"
} > "$output"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"unpin-fixture","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | "$UNPIN_GATEWAY_PROXY_EXECUTABLE" gateway-session-proxy --socket "$UNPIN_GATEWAY_SOCKET" \
  > "$gateway_output"
"#,
    )
    .expect("fake host script");
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700)).expect("executable fake host");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "launch", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .args([
            "--provider",
            "codex",
            "--exposure-revision",
            &"e".repeat(64),
            "--bridge-socket",
        ])
        .arg(&bridge_socket)
        .args(["--json", "--"])
        .arg(&host)
        .arg(&host_output)
        .arg(&gateway_output)
        .output()
        .expect("session launch output");
    assert!(
        output.status.success(),
        "session launch failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("session launch JSON");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["isolation"], "connection-scoped");
    assert_eq!(
        result["degradation"],
        serde_json::json!(["fixture-harness-overlay"])
    );
    assert_eq!(result["cleanupComplete"], true);
    assert_eq!(result["cleanupFailures"], serde_json::json!([]));

    let host_state = fs::read_to_string(&host_output).expect("fake host output");
    assert!(host_state.contains("gateway=session"));
    assert!(host_state.contains("provider=codex"));
    assert!(host_state.contains(&format!("bridge={}", bridge_socket.display())));
    assert!(host_state.contains("gateway_socket=/tmp/unpin-gw-"));
    assert!(host_state.contains(&format!(
        "args={} {}",
        host_output.display(),
        gateway_output.display()
    )));
    let gateway_state = fs::read_to_string(&gateway_output).expect("gateway MCP output");
    assert!(gateway_state.contains("unpin_search_skills"));
    assert!(gateway_state.contains("unpin_load_skill"));
    assert!(gateway_state.contains("unpin_get_session_status"));
    let gateway_socket = host_state
        .lines()
        .find_map(|line| line.strip_prefix("gateway_socket="))
        .expect("gateway socket path");
    assert!(!Path::new(gateway_socket).exists());
    assert!(!Path::new(gateway_socket).parent().unwrap().exists());
    let overlay = host_state
        .lines()
        .find_map(|line| line.strip_prefix("overlay="))
        .expect("overlay path");
    assert!(!Path::new(overlay).exists());
    assert!(!host_state.contains("bootstrap"));

    let list = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "list", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .arg("--json")
        .output()
        .expect("session list output");
    assert!(list.status.success());
    let list: serde_json::Value = serde_json::from_slice(&list.stdout).expect("session list JSON");
    assert_eq!(list["sessions"], serde_json::json!([]));
}

#[test]
fn session_launch_rejects_partial_profile_binding_before_starting_child() {
    let temp = TempDir::new().expect("temporary session validation root");
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&project).expect("project root");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "launch", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .args([
            "--provider",
            "codex",
            "--exposure-revision",
            &"e".repeat(64),
            "--profile-id",
            "review",
            "--json",
            "--",
            "/usr/bin/false",
        ])
        .output()
        .expect("invalid session launch output");
    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("session error JSON");
    assert_eq!(result["status"], "failed");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("must be supplied together")
    );
}

#[cfg(unix)]
#[test]
fn session_launch_rejects_non_socket_bridge_control_before_starting_child() {
    let temp = TempDir::new().expect("temporary bridge validation root");
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    let app_state = temp.path().join("state");
    let invalid_socket = temp.path().join("not-a-socket");
    let sentinel = temp.path().join("host-ran");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&project).expect("project root");
    fs::write(&invalid_socket, "regular file").expect("invalid socket fixture");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "launch", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .args([
            "--provider",
            "codex",
            "--exposure-revision",
            &"e".repeat(64),
            "--bridge-socket",
        ])
        .arg(&invalid_socket)
        .args(["--json", "--", "/usr/bin/touch"])
        .arg(&sentinel)
        .output()
        .expect("invalid bridge session output");

    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("bridge error JSON");
    assert_eq!(result["status"], "failed");
    assert!(result["reason"].as_str().unwrap().contains("unavailable"));
    assert!(!sentinel.exists());
}

#[cfg(unix)]
#[test]
fn session_launch_respects_mode_admission_fence_and_removes_pending_state() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary fenced session root");
    let temp_path = fs::canonicalize(temp.path()).expect("canonical fenced session root");
    let home = temp_path.join("home");
    let project = temp_path.join("project");
    let app_state = temp_path.join("state");
    let host = temp_path.join("must-not-run.sh");
    let sentinel = temp_path.join("host-ran");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&project).expect("project root");
    fs::write(
        &host,
        format!("#!/bin/sh\nprintf ran > '{}'\n", sentinel.display()),
    )
    .expect("fenced host script");
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700)).expect("fenced host executable");
    let identity = resolve_workspace_identity(&project).expect("workspace identity");
    let sessions =
        SessionManager::with_authority_key(&app_state, session_authority_key(&app_state));
    GatewayModeManager::new(&app_state, sessions.clone())
        .install(
            GatewayModeTarget::repository_provider(identity.repository_key, ProviderId::Codex)
                .expect("repository mode target"),
            "test-mode-control",
            1_000,
        )
        .expect("install gateway in off mode");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "launch", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .args([
            "--provider",
            "codex",
            "--exposure-revision",
            &"e".repeat(64),
            "--json",
            "--",
        ])
        .arg(&host)
        .output()
        .expect("fenced session launch");
    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fenced session JSON");
    assert!(
        result["reason"]
            .as_str()
            .expect("fence reason")
            .contains("not admitting new sessions")
    );
    assert!(!sentinel.exists());
    assert!(
        sessions
            .list()
            .expect("no established fenced lease")
            .is_empty()
    );
    let overlay_root = app_state.join("runtime/overlays");
    if overlay_root.exists() {
        assert_eq!(fs::read_dir(overlay_root).expect("overlay root").count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn failed_child_exec_still_cleans_session_lease_and_overlay() {
    let temp = TempDir::new().expect("temporary failed child root");
    let temp_path = fs::canonicalize(temp.path()).expect("canonical failed child root");
    let home = temp_path.join("home");
    let project = temp_path.join("project");
    let app_state = temp_path.join("state");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&project).expect("project root");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "launch", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&project)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .args([
            "--provider",
            "codex",
            "--exposure-revision",
            &"e".repeat(64),
            "--json",
            "--",
            "/definitely/missing/unpin-host",
        ])
        .output()
        .expect("failed child session launch");
    assert!(!output.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("failed child JSON");
    assert_eq!(result["status"], "child-failed");
    assert_eq!(result["cleanupComplete"], true);
    assert_eq!(result["cleanupFailures"], serde_json::json!([]));
    assert!(
        SessionManager::with_authority_key(&app_state, session_authority_key(&app_state))
            .list()
            .expect("post-failure sessions")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn concurrent_session_launches_keep_git_worktrees_and_exposures_disjoint() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary concurrent session root");
    let temp_path = fs::canonicalize(temp.path()).expect("canonical concurrent session root");
    let home = temp_path.join("home");
    let app_state = temp_path.join("state");
    let repository = temp_path.join("repository");
    let worktree = temp_path.join("worktree");
    let host = temp_path.join("blocking-host.sh");
    let release = temp_path.join("release-hosts");
    fs::create_dir_all(&home).expect("home root");
    fs::create_dir_all(&repository).expect("repository root");
    run_git(&repository, &["init", "--initial-branch=main"]);
    run_git(&repository, &["config", "user.name", "Unpin Test"]);
    run_git(
        &repository,
        &["config", "user.email", "unpin@example.invalid"],
    );
    fs::write(repository.join("README.md"), "initial\n").expect("repository file");
    run_git(&repository, &["add", "README.md"]);
    run_git(&repository, &["commit", "-m", "initial"]);
    run_git(
        &repository,
        &[
            "worktree",
            "add",
            "--detach",
            worktree.to_str().expect("worktree path"),
            "HEAD",
        ],
    );
    fs::write(
        &host,
        r#"#!/bin/sh
set -eu
output="$1"
release="$2"
{
  printf 'session=%s\n' "$UNPIN_SESSION_ID"
  printf 'repository=%s\n' "$UNPIN_REPOSITORY_KEY"
  printf 'workspace=%s\n' "$UNPIN_WORKSPACE_KEY"
} > "$output"
while [ ! -f "$release" ]; do sleep 0.02; done
"#,
    )
    .expect("blocking host script");
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700))
        .expect("executable blocking host");

    let binary = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .get_program()
        .to_os_string();
    let profile_store = ProfileStore::new(&app_state);
    let profiles = (0..2)
        .map(|index| {
            let profile = compile_profile(
                &ProfileDefinition {
                    version: PROFILE_DEFINITION_VERSION,
                    id: format!("worktree-profile-{index}"),
                    display_name: format!("Worktree Profile {index}"),
                    description: None,
                    members: Vec::new(),
                    provider_members: Default::default(),
                    supported_providers: Default::default(),
                },
                &Catalog::default(),
                ProfileSourceScope::Workspace,
            )
            .expect("compile worktree profile");
            profile_store
                .materialize_revision(
                    &profile,
                    OwnerGeneration::new(
                        format!("parallel-profile-{index}"),
                        u64::try_from(index + 1).expect("profile generation"),
                    )
                    .expect("profile owner"),
                )
                .expect("materialize worktree profile");
            profile
        })
        .collect::<Vec<_>>();
    let mut children = Vec::new();
    for (index, project, revision) in [
        (0, repository.as_path(), "a".repeat(64)),
        (1, worktree.as_path(), "b".repeat(64)),
    ] {
        let host_output = temp_path.join(format!("host-{index}.txt"));
        let profile = &profiles[index];
        let child = StdCommand::new(&binary)
            .current_dir(project)
            .args(["session", "launch", "--home-root"])
            .arg(&home)
            .arg("--project-root")
            .arg(project)
            .arg("--app-state-root")
            .arg(&app_state)
            .arg("--fixture-root")
            .arg(fixtures_root())
            .args([
                "--provider",
                "codex",
                "--exposure-revision",
                &revision,
                "--profile-id",
                &profile.profile_id,
                "--profile-digest",
                &profile.digest,
                "--definition-digest",
                &profile.origin.definition_digest,
                "--json",
                "--",
            ])
            .arg(&host)
            .arg(&host_output)
            .arg(&release)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn concurrent session");
        children.push((child, host_output));
    }
    for (_, host_output) in &children {
        assert!(
            wait_for_path(host_output, Duration::from_secs(10)),
            "host did not start"
        );
    }

    let mut scoped_sessions = Vec::new();
    for (project, expected_revision, expected_profile) in [
        (repository.as_path(), "a".repeat(64), &profiles[0]),
        (worktree.as_path(), "b".repeat(64), &profiles[1]),
    ] {
        let list = Command::cargo_bin("unpin")
            .expect("unpin binary")
            .args(["session", "list", "--home-root"])
            .arg(&home)
            .arg("--project-root")
            .arg(project)
            .arg("--app-state-root")
            .arg(&app_state)
            .arg("--fixture-root")
            .arg(fixtures_root())
            .arg("--json")
            .output()
            .expect("worktree-scoped session list");
        assert!(list.status.success());
        let list: serde_json::Value =
            serde_json::from_slice(&list.stdout).expect("worktree-scoped session JSON");
        let sessions = list["sessions"].as_array().expect("session summaries");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["desiredExposureRevision"], expected_revision);
        assert_eq!(sessions[0]["profileDigest"], expected_profile.digest);
        scoped_sessions.push(sessions[0].clone());
    }
    assert_eq!(
        scoped_sessions[0]["repositoryKey"],
        scoped_sessions[1]["repositoryKey"]
    );
    assert_ne!(
        scoped_sessions[0]["workspaceKey"],
        scoped_sessions[1]["workspaceKey"]
    );
    let leases = SessionManager::with_authority_key(&app_state, session_authority_key(&app_state))
        .list()
        .expect("authenticated concurrent leases");
    assert_eq!(leases.len(), 2);
    for lease in leases {
        assert!(
            lease
                .lease
                .protected_resources
                .iter()
                .any(|resource| resource.starts_with("gateway-mode-"))
        );
        assert!(
            lease
                .lease
                .protected_resources
                .iter()
                .any(|resource| resource.starts_with("profile-policy-"))
        );
        assert!(
            lease
                .lease
                .protected_resources
                .iter()
                .any(|resource| resource.starts_with("native-resource-"))
        );
    }

    fs::write(&release, b"release").expect("release concurrent hosts");
    for (child, _) in &mut children {
        assert!(child.wait().expect("concurrent session exit").success());
    }
    let empty = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["session", "list", "--home-root"])
        .arg(&home)
        .arg("--project-root")
        .arg(&repository)
        .arg("--app-state-root")
        .arg(&app_state)
        .arg("--fixture-root")
        .arg(fixtures_root())
        .arg("--json")
        .output()
        .expect("post-session list");
    let empty: serde_json::Value =
        serde_json::from_slice(&empty.stdout).expect("post-session JSON");
    assert_eq!(empty["sessions"], serde_json::json!([]));
}

#[test]
fn backup_auth_help_lists_init_and_status_without_accessing_keychain() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["auth", "backup", "--help"])
        .output()
        .expect("backup auth help output");

    assert!(output.status.success(), "backup auth help should succeed");
    let stdout = String::from_utf8(output.stdout).expect("help stdout is utf8");
    assert!(stdout.contains("init"));
    assert!(stdout.contains("status"));
}

#[test]
fn cursor_dashboard_auth_help_exposes_store_status_and_remove_without_secret_argument() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["auth", "cursor-dashboard", "--help"])
        .output()
        .expect("Cursor dashboard auth help output");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help stdout is utf8");
    for command in ["store", "status", "remove"] {
        assert!(stdout.contains(command));
    }
    assert!(!stdout.contains("--cookie"));
    assert!(!stdout.contains("--token"));
}

#[test]
fn missing_command_returns_command_selection_error() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .output()
        .expect("missing command output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    assert_eq!(stdout.trim(), "");
    assert_eq!(stderr.trim(), "No command specified.");
}

#[test]
fn unknown_command_returns_command_selection_error() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("unknown-command")
        .output()
        .expect("unknown command output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    assert_eq!(stdout.trim(), "");
    assert_eq!(stderr.trim(), "Unknown command: unknown-command");
}

#[test]
fn providers_renders_capability_matrix() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("providers")
        .output()
        .expect("providers output");

    assert!(
        output.status.success(),
        "providers should exit successfully"
    );
    let stdout = String::from_utf8(output.stdout).expect("providers stdout is utf8");

    for expected in [
        "Supported providers",
        "Claude Code (claude)",
        "Skills:          verified",
        "Configured MCPs: verified",
        "Tools:           unsupported",
        "Hooks:           needs-verification",
        "Provider settings: read-only",
        "Plugin configs:  verified",
        "Plugin manifests: unsupported",
        "Plugin global scope: verified",
        "Plugin project scope: verified",
        "Extensions:      unsupported",
        "note:            Verified Claude toggles cover regular and provider-owned linked global and repository-scoped .claude/skills",
        "Codex (codex)",
        "Plugin configs:  verified",
        "Plugin project scope: unsupported",
        "note:            Verified Codex shared global and project `.agents/skills` toggles use Unpin-owned vault state",
        "Cursor (cursor)",
        "Plugin project scope: read-only",
        "Zed (zed)",
        "Hooks:           gateway-only",
        "Plugin configs:  out-of-scope",
        "Plugin manifests: out-of-scope",
        "Plugin global scope: out-of-scope",
        "Plugin project scope: out-of-scope",
        "note:            Verified Zed global and project Agent Skills from .agents/skills use Unpin-owned vault state",
    ] {
        assert!(
            stdout.contains(expected),
            "providers output should include {expected:?}; got:\n{stdout}"
        );
    }
    assert!(!stdout.contains("Provider Capability Matrix"));
}

#[test]
fn list_renders_human_inventory_from_fixture_root() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .output()
        .expect("list output");

    assert!(output.status.success(), "list should exit successfully");
    let stdout = String::from_utf8(output.stdout).expect("list stdout is utf8");

    for expected in [
        "Discovered items:",
        "claude project skill example-claude-skill",
        "claude global agent claude-global-reviewer",
        "claude global plugin-config safe-shell",
        "codex global configured-mcp github",
        "codex global plugin-config safe-shell",
        "cursor global configured-mcp modern-global",
        "cursor global plugin-manifest Example Cursor Plugin",
        "zed global configured-mcp github",
        "zed project skill example-shared-project-skill",
    ] {
        assert!(
            stdout.contains(expected),
            "list output should include {expected:?}; got:\n{stdout}"
        );
    }
}

#[test]
fn list_with_fixture_root_does_not_read_user_unpin_config() {
    let home = TempDir::new().expect("temp home");
    write_text(
        &home
            .path()
            .join(".config")
            .join("unpin")
            .join("config.json"),
        "{invalid json",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--home-root"])
        .arg(home.path())
        .output()
        .expect("list output");

    assert!(
        output.status.success(),
        "fixture-root list should ignore malformed user config; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("list stdout is utf8");
    assert!(stdout.contains("Discovered items:"));
}

#[test]
fn list_renders_json_inventory_from_fixture_root() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .arg("--json")
        .output()
        .expect("list json output");

    assert!(
        output.status.success(),
        "list --json should exit successfully"
    );
    let stdout = String::from_utf8(output.stdout).expect("list json stdout is utf8");

    assert!(stdout.contains("\"items\""));
    assert!(stdout.contains("\"warnings\""));
    assert!(stdout.contains("claude:project:skill:example-claude-skill"));
    assert!(stdout.contains("claude:global:agent:claude-global-reviewer"));
    assert!(stdout.contains("codex:global:hook:config-toml:PreToolUse"));
    assert!(stdout.contains("cursor:global:plugin-manifest:local:example-plugin"));
    assert!(stdout.contains("cursor:global:configured-mcp:modern-global"));
    assert!(stdout.contains("zed:global:configured-mcp:github"));
    assert!(stdout.contains("zed:project:configured-mcp:local-docs"));
}

#[test]
fn list_filters_inventory_by_provider_and_layer() {
    let provider_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--provider", "claude"])
        .output()
        .expect("list provider output");

    assert!(
        provider_output.status.success(),
        "provider filter should succeed"
    );
    let provider_stdout =
        String::from_utf8(provider_output.stdout).expect("provider stdout is utf8");
    assert!(provider_stdout.contains("claude project skill"));
    assert!(!provider_stdout.contains("codex global"));
    assert!(!provider_stdout.contains("cursor global"));
    assert!(!provider_stdout.contains("zed global"));

    let zed_provider_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--provider", "zed"])
        .output()
        .expect("list zed provider output");

    assert!(
        zed_provider_output.status.success(),
        "zed provider filter should succeed"
    );
    let zed_provider_stdout =
        String::from_utf8(zed_provider_output.stdout).expect("zed provider stdout is utf8");
    assert!(zed_provider_stdout.contains("zed global configured-mcp github"));
    assert!(zed_provider_stdout.contains("zed project skill example-shared-project-skill"));
    assert!(!zed_provider_stdout.contains("claude project"));

    let layer_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--layer", "global"])
        .output()
        .expect("list layer output");

    assert!(layer_output.status.success(), "layer filter should succeed");
    let layer_stdout = String::from_utf8(layer_output.stdout).expect("layer stdout is utf8");
    assert!(layer_stdout.contains("codex global"));
    assert!(layer_stdout.contains("cursor global"));
    assert!(layer_stdout.contains("zed global"));
    assert!(!layer_stdout.contains("claude project"));
}

#[test]
fn list_renders_provider_warnings_from_malformed_json() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_text(
        &fixture_copy
            .path()
            .join("cursor")
            .join("global")
            .join("hooks.json"),
        "{ invalid json",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .output()
        .expect("list output");

    assert!(
        output.status.success(),
        "list warnings are advisory and should not fail the command"
    );
    let stdout = String::from_utf8(output.stdout).expect("list stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("list stderr is utf8");
    assert!(stdout.contains("Discovered items:"));
    assert!(stdout.contains("codex global skill example-shared-global-skill"));
    assert!(!stdout.contains("Warnings:"));
    assert!(stderr.contains("Warnings:"));
    assert!(stderr.contains("- cursor global json-parse-error:"));
    assert!(stderr.contains("hooks.json"));

    let json_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .arg("--json")
        .output()
        .expect("list JSON output");
    assert!(
        json_output.status.success(),
        "JSON list warnings are advisory and should not fail the command"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("list JSON stdout");
    assert_eq!(json["warnings"][0]["provider"], "cursor");
    assert_eq!(json["warnings"][0]["code"], "json-parse-error");

    let kind_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--kind", "skill", "--json"])
        .output()
        .expect("kind-filtered list JSON output");
    assert!(kind_output.status.success());
    let kind_json: serde_json::Value =
        serde_json::from_slice(&kind_output.stdout).expect("kind-filtered list JSON stdout");
    assert_eq!(kind_json["warnings"][0]["provider"], "cursor");
    assert_eq!(kind_json["warnings"][0]["code"], "json-parse-error");
    assert!(
        kind_json["items"]
            .as_array()
            .expect("kind-filtered items")
            .iter()
            .all(|item| item["kind"] == "skill")
    );
}

#[test]
fn doctor_fails_when_provider_warnings_are_detected() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_text(
        &fixture_copy
            .path()
            .join("cursor")
            .join("global")
            .join("hooks.json"),
        "{ invalid json",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["doctor", "--fixture-root"])
        .arg(fixture_copy.path())
        .output()
        .expect("doctor output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("unpin doctor: provider issues detected"));
    assert!(stdout.contains("- cursor global json-parse-error:"));
    assert!(stdout.contains("hooks.json"));
}

#[test]
fn doctor_fails_when_capability_matrix_is_stale() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let matrix_path = fixture_copy.path().join("capability-matrix.json");
    let mut matrix: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&matrix_path).expect("matrix json"))
            .expect("matrix value");
    matrix["providers"]["claude"]
        .as_object_mut()
        .expect("claude capabilities")
        .remove("agents");
    fs::write(
        &matrix_path,
        serde_json::to_string_pretty(&matrix).expect("matrix json"),
    )
    .expect("write matrix");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["doctor", "--fixture-root"])
        .arg(fixture_copy.path())
        .output()
        .expect("doctor output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("unpin doctor: capability matrix validation failed"));
    assert!(stdout.contains("capability-matrix.json is missing claude.agents"));
}

#[test]
fn doctor_fails_when_required_fixture_file_is_missing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::remove_file(
        fixture_copy
            .path()
            .join("claude")
            .join("global")
            .join("settings.json"),
    )
    .expect("remove fixture");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["doctor", "--fixture-root"])
        .arg(fixture_copy.path())
        .output()
        .expect("doctor output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("unpin doctor: fixture validation failed"));
    assert!(stdout.contains("claude/global/settings.json"));
    assert!(stdout.contains("fixture file is missing"));
}

#[test]
fn doctor_fails_when_fixture_shape_is_invalid() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::write(
        fixture_copy
            .path()
            .join("cursor")
            .join("home")
            .join("mcp.json"),
        r#"{"mcpServers":[]}"#,
    )
    .expect("write invalid cursor mcp");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["doctor", "--fixture-root"])
        .arg(fixture_copy.path())
        .output()
        .expect("doctor output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("unpin doctor: fixture validation failed"));
    assert!(stdout.contains("cursor/home/mcp.json"));
    assert!(stdout.contains("mcpServers must be an object"));
}

#[test]
fn doctor_fails_when_configured_vault_entry_is_malformed() {
    let temp = TempDir::new().expect("temp configured roots");
    let home_root = temp.path().join("home");
    let project_root = temp.path().join("project");
    let cursor_root = temp.path().join("cursor");
    let app_state_root = temp.path().join("state");
    fs::create_dir_all(&app_state_root).expect("create app state root");
    let app_state_root = fs::canonicalize(app_state_root).expect("canonical app state root");
    write_text(
        &home_root.join(".config").join("unpin").join("config.json"),
        &serde_json::json!({
            "projectRoot": project_root,
            "cursorRoot": cursor_root,
            "appStateRoot": app_state_root
        })
        .to_string(),
    );
    let entry_path = app_state_root
        .join("vault")
        .join("claude")
        .join("project")
        .join("skill")
        .join("broken")
        .join("entry.json");
    write_text(&entry_path, "{ invalid json");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("doctor")
        .args(["--home-root"])
        .arg(&home_root)
        .output()
        .expect("doctor configured vault output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("unpin doctor: provider issues detected"));
    assert!(stdout.contains("invalid-vault-entry"));
    assert!(stdout.contains(entry_path.to_string_lossy().as_ref()));
}

#[test]
fn list_discovers_explicit_live_style_roots_without_fixture_root() {
    let home_root = TempDir::new().expect("temp home root");
    let project_root = TempDir::new().expect("temp project root");
    let cursor_root = TempDir::new().expect("temp cursor root");

    write_text(
        &project_root
            .path()
            .join(".claude")
            .join("skills")
            .join("live-claude")
            .join("SKILL.md"),
        "# Live Claude Skill\n",
    );
    write_text(
        &home_root.path().join(".claude.json"),
        r#"{"mcpServers":{"live-claude-global":{"command":"claude-mcp"}}}"#,
    );
    write_text(
        &home_root.path().join(".codex").join("config.toml"),
        "[mcp_servers.github]\ncommand = \"gh\"\n",
    );
    write_text(
        &home_root
            .path()
            .join(".cursor")
            .join("skills")
            .join("live-cursor")
            .join("SKILL.md"),
        "# Live Cursor Skill\n",
    );
    write_text(
        &home_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"modern-cursor":{"command":"cursor-mcp"}}}"#,
    );
    write_text(
        &project_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"project-cursor":{"command":"project-cursor-mcp"}}}"#,
    );
    write_text(
        &home_root
            .path()
            .join(".agents")
            .join("skills")
            .join("live-zed")
            .join("SKILL.md"),
        "# Live Zed Skill\n",
    );
    write_text(
        &home_root
            .path()
            .join(".config")
            .join("zed")
            .join("settings.json"),
        r#"{"context_servers":{"zed-live":{"command":"zed-mcp"}}}"#,
    );
    write_text(
        &project_root
            .path()
            .join(".agents")
            .join("skills")
            .join("live-zed-project")
            .join("SKILL.md"),
        "# Live Project Zed Skill\n",
    );
    write_text(
        &project_root.path().join(".zed").join("settings.json"),
        r#"{"context_servers":{"project-zed":{"command":"project-zed-mcp"}}}"#,
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("list")
        .args(["--home-root"])
        .arg(home_root.path())
        .args(["--claude-root"])
        .arg(home_root.path())
        .args(["--codex-root"])
        .arg(home_root.path().join(".codex"))
        .args(["--project-root"])
        .arg(project_root.path())
        .args(["--cursor-root"])
        .arg(cursor_root.path())
        .args(["--pi-root"])
        .arg(home_root.path().join(".pi").join("agent"))
        .args(["--opencode-root"])
        .arg(home_root.path().join(".config").join("opencode"))
        .args(["--zed-root"])
        .arg(home_root.path().join(".config").join("zed"))
        .output()
        .expect("list live roots output");

    assert!(output.status.success(), "live-root list should succeed");
    let stdout = String::from_utf8(output.stdout).expect("list stdout is utf8");
    assert!(stdout.contains("claude project skill live-claude"));
    assert!(stdout.contains("claude global configured-mcp live-claude-global"));
    assert!(stdout.contains("codex global configured-mcp github"));
    assert!(stdout.contains("cursor global skill live-cursor"));
    assert!(stdout.contains("cursor global configured-mcp modern-cursor"));
    assert!(stdout.contains("cursor project configured-mcp project-cursor"));
    assert!(stdout.contains("zed global skill live-zed"));
    assert!(stdout.contains("zed global configured-mcp zed-live"));
    assert!(stdout.contains("zed project skill live-zed-project"));
    assert!(stdout.contains("zed project configured-mcp project-zed"));
}

#[test]
fn list_uses_configured_app_state_to_discover_vaulted_items() {
    let temp = TempDir::new().expect("temp configured roots");
    let temp_root = fs::canonicalize(temp.path()).expect("canonical temp root");
    let home_root = temp_root.join("home");
    let project_root = temp_root.join("project");
    let cursor_root = temp_root.join("cursor");
    let app_state_root = temp_root.join("state");
    write_text(
        &home_root.join(".config").join("unpin").join("config.json"),
        &serde_json::json!({
            "projectRoot": project_root,
            "cursorRoot": cursor_root,
            "appStateRoot": app_state_root
        })
        .to_string(),
    );
    let skill_path = project_root
        .join(".claude")
        .join("skills")
        .join("configured-vault")
        .join("SKILL.md");
    write_text(&skill_path, "# Configured Vault Skill\n");

    let disabled = apply_native_toggle_for_test(
        &app_state_root,
        DiscoveryItem {
            provider: ProviderId::Claude,
            kind: DiscoveryKind::Skill,
            category: DiscoveryCategory::Skill,
            layer: DiscoveryLayer::Project,
            id: "claude:project:skill:configured-vault".to_string(),
            display_name: "configured-vault".to_string(),
            enabled: true,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: skill_path.to_string_lossy().into_owned(),
            state_path: skill_path
                .parent()
                .expect("skill directory")
                .to_string_lossy()
                .into_owned(),
            source_fingerprint: None,
            hook: None,
        },
    );
    assert_eq!(disabled.status, ToggleStatus::Applied);
    assert!(!skill_path.exists());

    let listed = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("list")
        .args(["--home-root"])
        .arg(&home_root)
        .args(["--provider", "claude", "--kind", "skill", "--json"])
        .output()
        .expect("list configured vault");
    assert!(
        listed.status.success(),
        "list should use configured app state; stderr=\n{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list stdout is JSON");
    let item = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "claude:project:skill:configured-vault")
        .expect("configured vaulted skill");
    assert_eq!(item["enabled"], false);
}

#[test]
fn list_rejects_invalid_layer_filter() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--layer", "workspace"])
        .output()
        .expect("list invalid layer output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("list stdout is utf8");
    assert!(stdout.contains("invalid layer: expected global, project, or all"));
}

#[test]
fn list_rejects_invalid_layer_filter_as_json_error() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--layer", "workspace", "--json"])
        .output()
        .expect("list invalid layer json output");

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("list stdout is json");
    assert_eq!(value["status"], "failed");
    assert_eq!(
        value["reason"],
        "invalid layer: expected global, project, or all"
    );
    assert_eq!(value.as_object().expect("object").len(), 2);
    let stderr = String::from_utf8(output.stderr).expect("list stderr is utf8");
    assert_eq!(stderr.trim(), "");
}

#[test]
fn doctor_validates_fixture_discovery() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["doctor", "--fixture-root"])
        .arg(fixtures_root())
        .output()
        .expect("doctor output");

    assert!(output.status.success(), "doctor should succeed");
    let stdout = String::from_utf8(output.stdout).expect("doctor stdout is utf8");
    assert!(stdout.contains("OK"));
    assert!(stdout.contains("fixtures root:"));
    assert!(stdout.contains("capability matrix:"));
    assert!(stdout.contains("items discovered:"));
}

#[test]
fn tui_headless_renders_inventory_view() {
    let app_state = TempDir::new().expect("temp app state");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["tui", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--headless")
        .output()
        .expect("tui headless output");

    assert!(output.status.success(), "tui --headless should succeed");
    let stdout = String::from_utf8(output.stdout).expect("tui stdout is utf8");
    assert!(stdout.contains("Unpin"));
    assert!(stdout.contains("Items: "));
    assert!(stdout.contains("Providers: claude="));
    for provider in ["codex", "cursor", "pi", "opencode", "zed"] {
        assert!(
            stdout.contains(&format!(" {provider}=")),
            "missing {provider}"
        );
    }
    assert!(stdout.contains("Showing: "));
    assert!(stdout.contains("Warnings: 0"));
    assert!(stdout.contains("Backups: 0"));
    assert!(stdout.contains("Filters: provider=all layer=all category=all"));
    assert!(stdout.contains("Selected: 1/"));
    assert!(stdout.contains("claude:global:skill:example-claude-global-skill"));
    assert!(stdout.contains("provider: claude"));
    assert!(stdout.contains("layer: global"));
    assert!(stdout.contains("category: skill"));
    assert!(stdout.contains("kind: skill"));
    assert!(stdout.contains("mutability: read-write"));
    assert!(stdout.contains("Plan preview:"));
    assert!(stdout.contains("plan status: dry-run"));
    assert!(stdout.contains("target enabled: false"));
    assert!(stdout.contains("operation: renamePath"));
    assert!(stdout.contains("writes: no writes were performed"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("[Q]uit"));
    assert!(stdout.contains("filter: [p]rovider/[l]ayer/[c]ategory"));
    assert!(stdout.contains("Commands (Groups):"));
    assert!(stdout.contains("Groups: [P] reach"));
}

#[test]
fn dashboard_alias_renders_inventory_view() {
    let app_state = TempDir::new().expect("temp app state");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["dashboard", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--headless")
        .output()
        .expect("dashboard headless output");

    assert!(
        output.status.success(),
        "dashboard --headless should succeed"
    );
    let stdout = String::from_utf8(output.stdout).expect("dashboard stdout is utf8");
    assert!(stdout.contains("Unpin"));
    assert!(stdout.contains("Items: "));
    assert!(stdout.contains("Filters: provider=all layer=all category=all"));
}

#[test]
fn tui_headless_renders_backup_summaries() {
    let app_state = TempDir::new().expect("temp app state");
    write_backup_manifest(app_state.path(), "backup-new", "2026-06-20T12:00:00Z", 1);
    authenticate_legacy_backup(
        app_state.path(),
        "backup-new",
        &backup_authentication_key(app_state.path()),
    )
    .expect("authenticate backup");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["tui", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--headless")
        .output()
        .expect("tui headless output");

    assert!(output.status.success(), "tui --headless should succeed");
    let stdout = String::from_utf8(output.stdout).expect("tui stdout is utf8");
    assert!(stdout.contains("Backups: 1"));
    assert!(stdout.contains("Backup details:"));
    assert!(stdout.contains(
        "- claude project example → disabled created: 2026-06-20T12:00:00Z entries: 1 restorable: true"
    ));
    assert!(stdout.contains("id: backup-new"));
}

#[test]
fn tui_headless_renders_provider_warnings() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_text(
        &fixture_copy
            .path()
            .join("cursor")
            .join("global")
            .join("hooks.json"),
        "{ invalid json",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["tui", "--fixture-root"])
        .arg(fixture_copy.path())
        .arg("--headless")
        .output()
        .expect("tui headless output");

    assert!(
        output.status.success(),
        "tui --headless should succeed with warnings"
    );
    let stdout = String::from_utf8(output.stdout).expect("tui stdout is utf8");
    assert!(stdout.contains("Warnings: 1"));
    assert!(stdout.contains("Warning details:"));
    assert!(stdout.contains("- cursor global json-parse-error:"));
    assert!(stdout.contains("hooks.json"));
}

#[test]
fn snapshot_writes_human_summary_and_files() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = TempDir::new().expect("temp project root");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["snapshot", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--project-root"])
        .arg(project_root.path())
        .output()
        .expect("snapshot output");

    assert!(output.status.success(), "snapshot should exit successfully");
    let stdout = String::from_utf8(output.stdout).expect("snapshot stdout is utf8");

    assert!(stdout.contains("Snapshot saved:"));
    assert!(stdout.contains("Latest path:"));
    assert!(stdout.contains("History path:"));
    assert!(stdout.contains(
        "Inventory semantics: available=discovered in the current scope, active=currently enabled within that scope."
    ));
    assert!(app_state.path().join("snapshots").exists());
}

#[test]
fn snapshot_renders_json_summary() {
    let app_state = TempDir::new().expect("temp app state");
    let project_root = TempDir::new().expect("temp project root");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["snapshot", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--project-root"])
        .arg(project_root.path())
        .arg("--json")
        .output()
        .expect("snapshot json output");

    assert!(
        output.status.success(),
        "snapshot --json should exit successfully"
    );
    let stdout = String::from_utf8(output.stdout).expect("snapshot json stdout is utf8");

    assert!(stdout.contains("\"snapshot\""));
    assert!(stdout.contains("\"latestPath\""));
    assert!(stdout.contains("\"historyPath\""));
    assert!(stdout.contains("\"inventory\""));
}

#[test]
fn snapshot_uses_unpin_config_app_state_and_project_root_when_app_state_arg_omitted() {
    let temp = TempDir::new().expect("temp config roots");
    let home_root = temp.path().join("home");
    let project_root = temp.path().join("configured-project");
    let app_state = temp.path().join("configured-state");
    fs::create_dir_all(&app_state).expect("create configured app state");
    write_text(
        &home_root.join(".config").join("unpin").join("config.json"),
        &serde_json::json!({
            "projectRoot": project_root,
            "appStateRoot": app_state
        })
        .to_string(),
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["snapshot", "--fixture-root"])
        .arg(fixtures_root())
        .arg("--json")
        .env("HOME", &home_root)
        .output()
        .expect("snapshot config output");

    assert!(
        output.status.success(),
        "snapshot should use configured app-state root; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("snapshot stdout is json");
    assert_eq!(
        value["snapshot"]["projectRoot"],
        project_root.to_string_lossy().as_ref()
    );
    let latest_path = value["latestPath"].as_str().expect("latest path");
    assert!(Path::new(latest_path).starts_with(&app_state));
    assert!(Path::new(latest_path).exists());
}

#[test]
fn snapshot_discovers_explicit_live_style_roots_without_fixture_root() {
    let home_root = TempDir::new().expect("temp home root");
    let project_root = TempDir::new().expect("temp project root");
    let cursor_root = TempDir::new().expect("temp cursor root");
    let app_state = TempDir::new().expect("temp app state");

    write_text(
        &project_root
            .path()
            .join(".claude")
            .join("skills")
            .join("live-claude")
            .join("SKILL.md"),
        "# Live Claude Skill\n",
    );
    write_text(
        &home_root.path().join(".codex").join("config.toml"),
        "[mcp_servers.github]\ncommand = \"gh\"\n",
    );
    write_text(
        &home_root
            .path()
            .join(".cursor")
            .join("skills")
            .join("live-cursor")
            .join("SKILL.md"),
        "# Live Cursor Skill\n",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("snapshot")
        .args(["--home-root"])
        .arg(home_root.path())
        .args(["--codex-root"])
        .arg(home_root.path().join(".codex"))
        .args(["--project-root"])
        .arg(project_root.path())
        .args(["--cursor-root"])
        .arg(cursor_root.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--json")
        .output()
        .expect("snapshot live roots output");

    assert!(output.status.success(), "live-root snapshot should succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("snapshot stdout is json");
    assert_eq!(
        value["snapshot"]["projectRoot"],
        project_root.path().to_string_lossy().as_ref()
    );
    let items = value["snapshot"]["items"]
        .as_array()
        .expect("snapshot items");
    for expected in [
        "claude:project:skill:live-claude",
        "codex:global:configured-mcp:github",
        "cursor:global:skill:live-cursor",
    ] {
        assert!(
            items.iter().any(|item| item["id"] == expected),
            "snapshot should include {expected}; got {items:#?}"
        );
    }
    let latest_path = value["latestPath"].as_str().expect("latest path");
    assert!(Path::new(latest_path).starts_with(app_state.path()));
    assert!(Path::new(latest_path).exists());
}

#[test]
fn snapshot_returns_failure_when_discovery_warnings_are_detected() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    let project_root = TempDir::new().expect("temp project root");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_text(
        &fixture_copy
            .path()
            .join("claude")
            .join("global")
            .join("settings.json"),
        "{ invalid json",
    );

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["snapshot", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--project-root"])
        .arg(project_root.path())
        .output()
        .expect("snapshot warning output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("snapshot stdout is utf8");
    assert!(stdout.contains("Snapshot saved:"));
    assert!(stdout.contains(
        "Inventory semantics: available=discovered in the current scope, active=currently enabled within that scope."
    ));
    assert!(stdout.contains("Warnings:"));
    assert!(stdout.contains("- claude global json-parse-error:"));
    assert!(stdout.contains("settings.json"));
    assert!(!stdout.contains("Warnings: 1"));
    assert!(app_state.path().join("snapshots").exists());
}

#[test]
fn toggle_plans_skill_disable_human_dry_run() {
    let app_state = TempDir::new().expect("temp app state");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["toggle", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args([
            "--provider",
            "pi",
            "--kind",
            "skill",
            "--layer",
            "project",
            "--id",
            "pi:project:skill:example-pi-project-skill",
        ])
        .output()
        .expect("toggle output");

    assert!(output.status.success(), "toggle should exit successfully");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");

    assert!(stdout.contains("status: dry-run"));
    assert!(stdout.contains("targetEnabled: false"));
    assert!(stdout.contains("pi:project:skill:example-pi-project-skill"));
    assert!(stdout.contains("rename path"));
    assert!(stdout.contains("/vault/pi/project/skill/"));
    assert!(stdout.contains("affectedTargets:"));
    assert!(stdout.contains("no writes were performed"));
    assert!(!stdout.contains("target enabled:"));
    assert!(!stdout.contains("affected targets:"));
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn toggle_blocks_shared_skill_outside_selected_provider_reach() {
    let app_state = TempDir::new().expect("temp app state");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["toggle", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args([
            "--provider",
            "claude",
            "--kind",
            "skill",
            "--layer",
            "project",
            "--id",
            "claude:project:skill:example-claude-skill",
            "--json",
        ])
        .output()
        .expect("toggle output");

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("toggle stdout is json");
    assert_eq!(value["status"], "blocked");
    assert_eq!(
        value["reason"],
        "native toggle blocked: shared-source-crosses-provider-reach"
    );
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn group_cli_crud_history_restore_and_action_bound_previews() {
    fn member_keys(value: &serde_json::Value) -> BTreeSet<String> {
        value
            .as_array()
            .expect("group members")
            .iter()
            .map(|member| {
                let member = member.get("identity").unwrap_or(member);
                format!(
                    "{}:{}:{}:{}:{}",
                    member["provider"].as_str().expect("member provider"),
                    member["layer"].as_str().expect("member layer"),
                    member["kind"].as_str().expect("member kind"),
                    member["category"].as_str().expect("member category"),
                    member["id"].as_str().expect("member id"),
                )
            })
            .collect()
    }

    let temp = TempDir::new().expect("temporary group CLI root");
    let root = fs::canonicalize(temp.path()).expect("canonical group CLI root");
    let fixture_root = root.join("fixtures");
    let project_root = root.join("workspace");
    let app_state_root = root.join("state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(project_root.join(".git")).expect("workspace");
    fs::create_dir_all(&app_state_root).expect("app state");

    let first_skill = fixture_root.join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let second_skill = fixture_root.join("codex/admin/skills/example-group-second/SKILL.md");
    write_text(
        &second_skill,
        "---\nname: example-group-second\ndescription: Group CLI fixture skill.\n---\n",
    );
    let config_path = fixture_root.join("codex/global/config.toml");
    let config = fs::read_to_string(&config_path).expect("Codex fixture config");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = true\n\n[[skills.config]]\npath = {:?}\nenabled = true\n",
            first_skill.to_string_lossy(),
            second_skill.to_string_lossy(),
        ),
    )
    .expect("configure group fixture skills");

    let first_member =
        "codex:global:skill:skill:codex:global:skill:admin/example-codex-admin-skill";
    let second_member = "codex:global:skill:skill:codex:global:skill:admin/example-group-second";
    let expected_members = BTreeSet::from([first_member.to_string(), second_member.to_string()]);

    let create_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "create",
                "--scope",
                "personal",
                "--name",
                "brainstorming",
                "--member",
                first_member,
            ],
        ),
        "group create preview",
    );
    assert_eq!(create_preview["status"], "planned");
    let create_fingerprint = create_preview["planFingerprint"]
        .as_str()
        .expect("create plan fingerprint")
        .to_string();
    let created = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "create",
                "--scope",
                "personal",
                "--name",
                "brainstorming",
                "--member",
                first_member,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                &create_fingerprint,
            ],
        ),
        "group create apply",
    );
    assert_eq!(created["status"], "created");
    let created_revision = created["result"]["revision"]
        .as_str()
        .expect("created revision")
        .to_string();

    let edit_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "edit",
                "personal:brainstorming",
                "--member",
                first_member,
                "--member",
                second_member,
                "--expected-revision",
                &created_revision,
            ],
        ),
        "group edit preview",
    );
    let edit_fingerprint = edit_preview["planFingerprint"]
        .as_str()
        .expect("edit plan fingerprint")
        .to_string();
    assert_ne!(create_fingerprint, edit_fingerprint);
    let edited = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "edit",
                "personal:brainstorming",
                "--member",
                first_member,
                "--member",
                second_member,
                "--expected-revision",
                &created_revision,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                &edit_fingerprint,
            ],
        ),
        "group edit apply",
    );
    assert_eq!(
        member_keys(&edited["result"]["definition"]["members"]),
        expected_members
    );
    let edited_revision = edited["result"]["revision"]
        .as_str()
        .expect("edited revision")
        .to_string();

    let rename_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "rename",
                "personal:brainstorming",
                "--new-name",
                "planning",
                "--expected-revision",
                &edited_revision,
            ],
        ),
        "group rename preview",
    );
    let rename_fingerprint = rename_preview["planFingerprint"]
        .as_str()
        .expect("rename plan fingerprint")
        .to_string();
    let renamed = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "rename",
                "personal:brainstorming",
                "--new-name",
                "planning",
                "--expected-revision",
                &edited_revision,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                &rename_fingerprint,
            ],
        ),
        "group rename apply",
    );
    let renamed_revision = renamed["result"]["revision"]
        .as_str()
        .expect("renamed revision")
        .to_string();
    assert_eq!(renamed["result"]["qualifiedName"], "personal:planning");

    let delete_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "delete",
                "personal:planning",
                "--expected-revision",
                &renamed_revision,
            ],
        ),
        "group delete preview",
    );
    let delete_fingerprint = delete_preview["planFingerprint"]
        .as_str()
        .expect("delete plan fingerprint")
        .to_string();
    let deleted = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "delete",
                "personal:planning",
                "--expected-revision",
                &renamed_revision,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                &delete_fingerprint,
            ],
        ),
        "group delete apply",
    );
    let delete_history_id = deleted["result"]["historyId"]
        .as_str()
        .expect("delete history ID")
        .to_string();

    let history = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &["history", "--scope", "personal"],
        ),
        "group history",
    );
    let delete_history = history["result"]
        .as_array()
        .expect("history records")
        .iter()
        .find(|record| record["historyId"] == delete_history_id)
        .expect("delete history");
    assert_eq!(delete_history["change"], "delete");
    assert_eq!(
        member_keys(&delete_history["definitionBefore"]["members"]),
        expected_members
    );

    let restore_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "restore-definition",
                "--scope",
                "personal",
                &delete_history_id,
            ],
        ),
        "group restore preview",
    );
    let restore_fingerprint = restore_preview["planFingerprint"]
        .as_str()
        .expect("restore plan fingerprint")
        .to_string();
    let restored = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "restore-definition",
                "--scope",
                "personal",
                &delete_history_id,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                &restore_fingerprint,
            ],
        ),
        "group restore apply",
    );
    assert_eq!(restored["status"], "restored");
    assert_eq!(restored["result"]["qualifiedName"], "personal:planning");
    assert_eq!(
        member_keys(&restored["result"]["definition"]["members"]),
        expected_members
    );

    let shown = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &["show", "personal:planning"],
        ),
        "group show restored",
    );
    assert_eq!(member_keys(&shown["result"]["members"]), expected_members);

    let repository_create_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "create",
                "--scope",
                "repository",
                "--name",
                "implementation",
                "--member",
                first_member,
            ],
        ),
        "repository group create preview",
    );
    let repository_create = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "create",
                "--scope",
                "repository",
                "--name",
                "implementation",
                "--member",
                first_member,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                repository_create_preview["planFingerprint"]
                    .as_str()
                    .expect("repository create fingerprint"),
            ],
        ),
        "repository group create apply",
    );
    let repository_created_revision = repository_create["result"]["revision"]
        .as_str()
        .expect("repository created revision");
    let repository_edit_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "edit",
                "repository:implementation",
                "--member",
                first_member,
                "--member",
                second_member,
                "--expected-revision",
                repository_created_revision,
            ],
        ),
        "repository group edit preview",
    );
    let repository_edit = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "edit",
                "repository:implementation",
                "--member",
                first_member,
                "--member",
                second_member,
                "--expected-revision",
                repository_created_revision,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                repository_edit_preview["planFingerprint"]
                    .as_str()
                    .expect("repository edit fingerprint"),
            ],
        ),
        "repository group edit apply",
    );
    assert_eq!(
        member_keys(&repository_edit["result"]["definition"]["members"]),
        expected_members
    );
    let repository_edited_revision = repository_edit["result"]["revision"]
        .as_str()
        .expect("repository edited revision");
    let repository_delete_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "delete",
                "repository:implementation",
                "--expected-revision",
                repository_edited_revision,
            ],
        ),
        "repository group delete preview",
    );
    let repository_delete = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "delete",
                "repository:implementation",
                "--expected-revision",
                repository_edited_revision,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                repository_delete_preview["planFingerprint"]
                    .as_str()
                    .expect("repository delete fingerprint"),
            ],
        ),
        "repository group delete apply",
    );
    let repository_history_id = repository_delete["result"]["historyId"]
        .as_str()
        .expect("repository delete history ID");
    let repository_history = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &["history", "--scope", "repository"],
        ),
        "repository group history",
    );
    let repository_delete_history = repository_history["result"]
        .as_array()
        .expect("repository history records")
        .iter()
        .find(|record| record["historyId"] == repository_history_id)
        .expect("repository delete history");
    assert_eq!(
        member_keys(&repository_delete_history["definitionBefore"]["members"]),
        expected_members
    );
    let repository_restore_preview = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "restore-definition",
                "--scope",
                "repository",
                repository_history_id,
            ],
        ),
        "repository group restore preview",
    );
    let repository_restored = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &[
                "restore-definition",
                "--scope",
                "repository",
                repository_history_id,
                "--apply",
                "--confirm",
                "--plan-fingerprint",
                repository_restore_preview["planFingerprint"]
                    .as_str()
                    .expect("repository restore fingerprint"),
            ],
        ),
        "repository group restore apply",
    );
    assert_eq!(
        member_keys(&repository_restored["result"]["definition"]["members"]),
        expected_members
    );
}

#[test]
fn group_operation_show_handles_missing_context_and_redacts_internal_evidence() {
    let temp = TempDir::new().expect("temporary group operation CLI root");
    let root = fs::canonicalize(temp.path()).expect("canonical group operation CLI root");
    let fixture_root = root.join("fixtures");
    let project_root = root.join("workspace");
    let other_project_root = root.join("other-workspace");
    let app_state_root = root.join("state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(project_root.join(".git")).expect("workspace");
    fs::create_dir_all(other_project_root.join(".git")).expect("other workspace");
    fs::create_dir_all(&app_state_root).expect("app state");

    let skill_path = fixture_root.join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config_path = fixture_root.join("codex/global/config.toml");
    let config = fs::read_to_string(&config_path).expect("Codex fixture config");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = true\n",
            skill_path.to_string_lossy(),
        ),
    )
    .expect("configure group fixture skill");

    let roots = DiscoveryRoots::fixture_root(&fixture_root).with_app_state_root(&app_state_root);
    let access =
        GroupAccessContext::from_runtime(&app_state_root, &project_root, &roots, None, None)
            .expect("group access");
    let member = discover_all(&roots)
        .expect("group discovery")
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("group member identity")
        .expect("group fixture skill");
    let personal = PersonalGroupStore::new(access.clone());
    personal
        .create(
            &GroupDefinitionV1::new("operation-inspection", vec![member])
                .expect("group definition"),
            OwnerGeneration::new("group-operation-cli-test", 1).expect("group owner"),
        )
        .expect("create group");
    let planner = GroupPlanner::new(GroupResolver::new(
        access.clone(),
        personal,
        RepositoryGroupStore::new(access.clone()),
    ));
    let controller = GroupController::new(
        planner,
        backup_authentication_key(&app_state_root),
        session_authority_key(&app_state_root),
    );
    let plan = controller
        .plan(
            &GroupRef::qualified(GroupScope::Personal, "operation-inspection")
                .expect("group reference"),
            GroupTargetState::Disable,
            10,
            GroupPlanMode::TuiDirect,
        )
        .expect("group plan");
    let approval_context =
        ControlApprovalContext::new(access.repository_key(), access.workspace_key())
            .expect("approval context");
    let expectation = plan
        .approval_expectation(&approval_context)
        .expect("approval expectation");
    let approval_key = ApprovalKey::new([0x71; 32]);
    let now_unix = 2_000_000_000;
    let receipt = ApprovalIssuer::new(
        approval_key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer")
    .issue(ApprovalReceiptClaims {
        version: 1,
        receipt_id: "receipt-group-operation-cli".to_string(),
        nonce: "nonce-group-operation-cli".to_string(),
        issuer: String::new(),
        audience: String::new(),
        operation_id: expectation.operation_id.clone(),
        operation_kind: expectation.operation_kind.clone(),
        effect_graph_digest: expectation.effect_graph_digest.clone(),
        repository_key: expectation.repository_key.clone(),
        workspace_key: expectation.workspace_key.clone(),
        session_id: expectation.session_id.clone(),
        profile_digest: expectation.profile_digest.clone(),
        resources: expectation.resources.clone(),
        issued_at_unix: now_unix,
        expires_at_unix: now_unix + 60,
    })
    .expect("approval receipt");
    let authorization = authorize_control(
        &app_state_root,
        &receipt,
        &ApprovalVerifier::new(approval_key),
        &expectation,
        now_unix,
        OwnerGeneration::new("group-operation-cli-approval", 1).expect("approval owner"),
    )
    .expect("group authorization");
    let applied = controller.apply(&plan, authorization).expect("group apply");

    let shown = assert_success_json(
        run_group_command(
            &fixture_root,
            &project_root,
            &app_state_root,
            &["operation-show", &applied.operation_id],
        ),
        "group operation show",
    );
    assert_eq!(shown["status"], "operation");
    assert_eq!(
        shown["result"]["operation"]["operationId"],
        applied.operation_id
    );
    let rendered = shown.to_string();
    for private_field in [
        "authorizationDecisionDigest",
        "sealedPlan",
        "authenticationKeyId",
        "authenticationTag",
        "repositoryKey",
        "workspaceKey",
    ] {
        assert!(
            !rendered.contains(private_field),
            "operation inspection exposed {private_field}"
        );
    }
    assert!(
        !rendered.contains(root.to_string_lossy().as_ref()),
        "operation inspection exposed a private path"
    );

    let missing = run_group_command(
        &fixture_root,
        &project_root,
        &app_state_root,
        &["operation-show", "missing-operation"],
    );
    assert!(!missing.status.success());
    let missing: serde_json::Value =
        serde_json::from_slice(&missing.stdout).expect("missing operation JSON");
    assert_eq!(missing["status"], "failed");
    assert_eq!(missing["reason"], "group operation was not found");

    let mismatched = run_group_command(
        &fixture_root,
        &other_project_root,
        &app_state_root,
        &["operation-show", &applied.operation_id],
    );
    assert!(!mismatched.status.success());
    let mismatched: serde_json::Value =
        serde_json::from_slice(&mismatched.stdout).expect("context mismatch JSON");
    assert_eq!(mismatched["status"], "blocked");
    assert_eq!(
        mismatched["reason"],
        "group operation belongs to a different workspace context"
    );
    assert!(
        !mismatched
            .to_string()
            .contains(root.to_string_lossy().as_ref()),
        "context mismatch exposed a private path"
    );
}

#[test]
fn toggle_applies_and_reenables_claude_global_configured_mcp() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let selector = [
        "--provider",
        "claude",
        "--kind",
        "mcp",
        "--layer",
        "global",
        "--id",
        "claude:global:configured-mcp:global-docs",
    ];

    let disabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args(selector);
    });
    assert!(
        disabled.status.success(),
        "disable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&disabled.stdout),
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    assert!(disabled_state["mcpServers"].get("global-docs").is_none());

    let listed = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--provider", "claude", "--kind", "mcp", "--json"])
        .output()
        .expect("list disabled Claude global MCP");
    assert!(listed.status.success(), "disabled list should succeed");
    let listed: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list stdout is JSON");
    let disabled_item = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "claude:global:configured-mcp:global-docs")
        .unwrap_or_else(|| panic!("disabled Claude global MCP: {listed:#}"));
    assert_eq!(disabled_item["enabled"], false);

    let enabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args(selector);
    });
    assert!(
        enabled.status.success(),
        "enable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );
    let enabled_state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    assert_eq!(enabled_state["mcpServers"]["global-docs"]["command"], "npx");
}

#[test]
fn toggle_applies_and_reenables_claude_local_configured_mcp() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let state_path = fixture_copy.path().join("claude").join(".claude.json");
    let project_key = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .to_string_lossy()
        .to_string();
    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    document["projects"][project_key.as_str()] = serde_json::json!({
        "mcpServers": {
            "cli-local": { "command": "cli-local-mcp" }
        },
        "unrelated": true
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&document).expect("Claude user state serializes"),
    )
    .expect("write Claude local MCP fixture");

    let listed = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args([
            "--provider",
            "claude",
            "--kind",
            "mcp",
            "--layer",
            "project",
            "--json",
        ])
        .output()
        .expect("list Claude local MCP");
    assert!(listed.status.success(), "local MCP list should succeed");
    let listed: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list stdout is JSON");
    let item_id = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["displayName"] == "cli-local")
        .and_then(|item| item["id"].as_str())
        .expect("Claude local MCP id")
        .to_string();

    let toggle = |expected: &str| {
        let output = run_reviewed_toggle(false, |command| {
            command
                .args(["--fixture-root"])
                .arg(fixture_copy.path())
                .args(["--app-state-root"])
                .arg(app_state.path())
                .args([
                    "--provider",
                    "claude",
                    "--kind",
                    "mcp",
                    "--layer",
                    "project",
                    "--id",
                ])
                .arg(&item_id);
        });
        assert!(
            output.status.success(),
            "{expected} should succeed; stdout=\n{}\nstderr=\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    toggle("disable");
    let disabled: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("disabled user state"))
            .expect("disabled user state JSON");
    assert!(
        disabled["projects"][project_key.as_str()]["mcpServers"]
            .get("cli-local")
            .is_none()
    );
    assert_eq!(
        disabled["projects"][project_key.as_str()]["unrelated"],
        true
    );

    toggle("enable");
    let enabled: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(state_path).expect("enabled user state"))
            .expect("enabled user state JSON");
    assert_eq!(
        enabled["projects"][project_key]["mcpServers"]["cli-local"]["command"],
        "cli-local-mcp"
    );
}

#[test]
fn toggle_plans_skill_disable_json_dry_run() {
    let app_state = TempDir::new().expect("temp app state");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["toggle", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args([
            "--provider",
            "pi",
            "--kind",
            "skill",
            "--layer",
            "project",
            "--id",
            "pi:project:skill:example-pi-project-skill",
            "--json",
        ])
        .output()
        .expect("toggle json output");

    assert!(
        output.status.success(),
        "toggle --json should exit successfully"
    );

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("toggle stdout is json");
    assert_eq!(value["statusVersion"], 2);
    assert_eq!(value["status"], "dry-run");
    assert_eq!(value["targetEnabled"], false);
    assert_eq!(value["providerReach"]["selected"]["provider"], "pi");
    assert_eq!(
        value["providerReach"]["selected"]["provenance"],
        "explicit-input"
    );
    assert_eq!(
        value["providerCoverage"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        value["selection"]["id"],
        "pi:project:skill:example-pi-project-skill"
    );
    assert_eq!(value["operations"][0]["type"], "renamePath");
    assert!(
        value["operations"][0]["summary"]
            .as_str()
            .expect("operation summary")
            .contains("rename path")
    );
    assert!(value["operations"][0].get("operationType").is_none());
    assert!(value["operations"][0].get("toPath").is_none());
    assert!(value["affectedTargets"][0].as_str().is_some());
    assert_eq!(value["writes"], "no writes were performed");
    assert!(value.get("backupId").is_none());
    assert!(value.get("reason").is_none());
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn bulk_handoff_apply_and_status_preserve_reviewed_reach() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let fixture_root = fs::canonicalize(fixture_copy.path()).expect("canonical fixture copy root");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state root");
    let item_id = "codex:global:skill:admin/example-codex-admin-skill";

    let omitted_reach = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["bulk", "plan", "--fixture-root"])
        .arg(&fixture_root)
        .args(["--app-state-root"])
        .arg(&app_state_root)
        .args([
            "--provider",
            "codex",
            "--id",
            item_id,
            "--disable",
            "--json",
        ])
        .output()
        .expect("bulk plan without reach");
    assert_eq!(omitted_reach.status.code(), Some(3));
    let omitted: serde_json::Value =
        serde_json::from_slice(&omitted_reach.stdout).expect("omitted reach JSON");
    assert_eq!(omitted["status"], "blocked");
    assert!(
        omitted["reason"]
            .as_str()
            .expect("omitted reach reason")
            .contains("selected provider")
    );

    let handoff = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["bulk", "handoff", "--fixture-root"])
        .arg(&fixture_root)
        .args(["--app-state-root"])
        .arg(&app_state_root)
        .args([
            "--provider",
            "codex",
            "--selected-provider",
            "codex",
            "--reach",
            "selected",
            "--id",
            item_id,
            "--disable",
            "--json",
        ])
        .output()
        .expect("bulk handoff");
    assert!(
        handoff.status.success(),
        "bulk handoff should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&handoff.stdout),
        String::from_utf8_lossy(&handoff.stderr)
    );
    let handoff: serde_json::Value =
        serde_json::from_slice(&handoff.stdout).expect("bulk handoff JSON");
    assert_eq!(handoff["statusVersion"], 2);
    assert_eq!(handoff["providerReach"]["selected"]["provider"], "codex");
    assert_eq!(
        handoff["providerReach"]["selected"]["provenance"],
        "explicit-input"
    );
    let operation_id = handoff["operationId"].as_str().expect("bulk operation id");
    let fingerprint = handoff["planFingerprint"]
        .as_str()
        .expect("bulk plan fingerprint");
    assert_eq!(handoff["handoff"]["operationId"], operation_id);
    assert_eq!(handoff["handoff"]["planFingerprint"], fingerprint);

    let applied = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["bulk", "apply", "--fixture-root"])
        .arg(&fixture_root)
        .args(["--app-state-root"])
        .arg(&app_state_root)
        .args(["--operation-id", operation_id])
        .args(["--plan-fingerprint", fingerprint, "--confirm", "--json"])
        .output()
        .expect("bulk apply");
    assert!(
        applied.status.success(),
        "bulk apply should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let applied: serde_json::Value =
        serde_json::from_slice(&applied.stdout).expect("bulk apply JSON");
    assert_eq!(applied["statusVersion"], 2);
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["operationId"], operation_id);
    assert_eq!(applied["planFingerprint"], fingerprint);

    let status = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["bulk", "status", "--fixture-root"])
        .arg(&fixture_root)
        .args(["--app-state-root"])
        .arg(&app_state_root)
        .args(["--operation-id", operation_id, "--json"])
        .output()
        .expect("bulk status");
    assert!(status.status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("bulk status JSON");
    assert_eq!(status["statusVersion"], 2);
    assert_eq!(status["status"], "applied");
    assert_eq!(status["operationId"], operation_id);
    assert_eq!(status["result"]["lifecycle"], "applied");
}

#[test]
fn toggle_reports_missing_selector_as_command_error() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["toggle", "--fixture-root"])
        .arg(fixtures_root())
        .args([
            "--provider",
            "claude",
            "--kind",
            "skill",
            "--layer",
            "project",
        ])
        .output()
        .expect("toggle missing selector output");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("toggle stderr is utf8");
    assert_eq!(stdout.trim(), "missing required selector: --id");
    assert_eq!(stderr.trim(), "");
}

#[test]
fn toggle_reports_unknown_selection_as_json_blocked_error() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["toggle", "--fixture-root"])
        .arg(fixtures_root())
        .args([
            "--provider",
            "claude",
            "--kind",
            "skill",
            "--layer",
            "project",
            "--id",
            "missing",
            "--json",
        ])
        .output()
        .expect("toggle unknown selection output");

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("toggle stdout is json");
    assert_eq!(value["status"], "blocked");
    assert_eq!(value["reason"], "unknown selection for missing");
    assert_eq!(value.as_object().expect("object").len(), 2);
    let stderr = String::from_utf8(output.stderr).expect("toggle stderr is utf8");
    assert_eq!(stderr.trim(), "");
}

#[test]
fn toggle_apply_moves_skill_and_reports_backup_id() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_skill = fixture_copy
        .path()
        .join("pi")
        .join("project")
        .join(".pi")
        .join("skills")
        .join("example-pi-project-skill")
        .join("SKILL.md");
    assert!(original_skill.exists());

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "pi",
                "--kind",
                "skill",
                "--layer",
                "project",
                "--id",
                "pi:project:skill:example-pi-project-skill",
            ]);
    });

    assert!(output.status.success(), "toggle apply should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("rename path"));
    assert!(!original_skill.exists());

    let backup_roots = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("backup entries");
    assert_eq!(backup_roots.len(), 1);
    assert!(backup_roots[0].path().join("manifest.json").exists());
    assert!(
        backup_roots[0]
            .path()
            .join("entries")
            .join("entry-1")
            .join("payload")
            .join("SKILL.md")
            .exists()
    );

    let vault_entries = fs::read_dir(
        app_state
            .path()
            .join("vault")
            .join("pi")
            .join("project")
            .join("skill"),
    )
    .expect("vault skill dir")
    .collect::<Result<Vec<_>, _>>()
    .expect("vault entries");
    assert_eq!(vault_entries.len(), 1);
    assert!(
        vault_entries[0]
            .path()
            .join("payload")
            .join("SKILL.md")
            .exists()
    );
    assert!(vault_entries[0].path().join("entry.json").exists());

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"event\":\"apply\""));
}

#[test]
fn toggle_apply_reenables_vaulted_cursor_skill() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_skill = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("skills")
        .join("example-cursor-skill")
        .join("SKILL.md");
    let original = fs::read_to_string(&original_skill).expect("original cursor skill");

    let disabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "cursor",
                "--kind",
                "skill",
                "--layer",
                "global",
                "--id",
                "cursor:global:skill:example-cursor-skill",
            ]);
    });
    assert!(
        disabled.status.success(),
        "disable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&disabled.stdout),
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(!original_skill.exists());

    let listed = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--provider", "cursor", "--kind", "skill", "--json"])
        .output()
        .expect("list disabled cursor skill");
    assert!(listed.status.success(), "list should succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list stdout is json");
    let disabled_item = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "cursor:global:skill:example-cursor-skill")
        .unwrap_or_else(|| panic!("disabled cursor skill: {value:#}"));
    assert_eq!(disabled_item["enabled"], false);

    let enabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "cursor",
                "--kind",
                "skill",
                "--layer",
                "global",
                "--id",
                "cursor:global:skill:example-cursor-skill",
            ]);
    });
    assert!(
        enabled.status.success(),
        "enable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );
    let stdout = String::from_utf8(enabled.stdout).expect("enable stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("targetEnabled: true"));
    assert_eq!(
        fs::read_to_string(&original_skill).expect("re-enabled cursor skill"),
        original
    );

    let vault_skill_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("skill");
    assert!(
        !vault_skill_root.exists()
            || fs::read_dir(vault_skill_root)
                .expect("vault skill root")
                .next()
                .is_none()
    );
}

#[test]
fn toggle_apply_reenables_vaulted_cursor_local_plugin() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let manifest = fixture_copy
        .path()
        .join("cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json");
    let original = fs::read_to_string(&manifest).expect("original plugin manifest");
    let connector = fixture_copy
        .path()
        .join("cursor/home/plugins/local/example-plugin/mcp.json");
    let original_connector = fs::read(&connector).expect("original plugin connector");
    let toggle_args = [
        "--provider",
        "cursor",
        "--kind",
        "plugin",
        "--layer",
        "global",
        "--id",
        "cursor:global:plugin-manifest:local:example-plugin",
    ];

    let disabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args(toggle_args);
    });
    assert!(
        disabled.status.success(),
        "disable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&disabled.stdout),
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(!manifest.exists());
    assert!(
        String::from_utf8_lossy(&disabled.stdout).contains("Restart Cursor or reload its window")
    );

    let listed = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--provider", "cursor", "--kind", "plugin", "--json"])
        .output()
        .expect("list disabled Cursor local plugin");
    assert!(listed.status.success(), "list should succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list stdout is JSON");
    let disabled_item = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "cursor:global:plugin-manifest:local:example-plugin")
        .expect("disabled Cursor local plugin");
    assert_eq!(disabled_item["enabled"], false);

    let enabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args(toggle_args);
    });
    assert!(
        enabled.status.success(),
        "enable should succeed; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert_eq!(
        fs::read_to_string(&manifest).expect("re-enabled plugin manifest"),
        original
    );
    assert_eq!(
        fs::read(&connector).expect("re-enabled plugin connector"),
        original_connector
    );
}

#[test]
fn toggle_apply_vaults_agent_and_restore_recovers_file() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_agent = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("agents")
        .join("reviewer.md");
    let original = fs::read_to_string(&original_agent).expect("original agent");

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "claude",
                "--kind",
                "agent",
                "--layer",
                "global",
                "--id",
                "claude:global:agent:claude-global-reviewer",
            ]);
    });

    assert!(output.status.success(), "agent toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("rename path"));
    assert!(!original_agent.exists());

    let list = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--provider", "claude", "--kind", "agent", "--json"])
        .output()
        .expect("list disabled agent output");
    assert!(list.status.success(), "list disabled agent should succeed");
    let list_stdout = String::from_utf8(list.stdout).expect("list stdout is utf8");
    assert!(
        list_stdout.contains("\"id\": \"claude:global:agent:claude-global-reviewer\""),
        "{list_stdout}"
    );
    assert!(list_stdout.contains("\"enabled\": false"));

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(restore.status.success(), "agent restore should succeed");
    assert_eq!(
        fs::read_to_string(&original_agent).expect("restored agent"),
        original
    );
}

#[test]
fn toggle_apply_changes_claude_connector_plugin_and_preserves_bundle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("settings.json");
    let original = fs::read_to_string(&settings_path).expect("original settings");
    let connector = fixture_copy
        .path()
        .join("claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json");
    let original_connector = fs::read(&connector).expect("original plugin connector");
    assert!(settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "claude",
                "--kind",
                "plugin",
                "--layer",
                "global",
                "--id",
                "claude:global:tool:settings:connector-kit@example-marketplace",
            ]);
    });

    assert!(output.status.success(), "claude tool toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("replace JSON value"));
    assert!(!settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));
    assert_eq!(
        fs::read(&connector).expect("plugin connector after disable"),
        original_connector
    );

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(
        restore.status.success(),
        "claude tool restore should succeed"
    );
    assert_eq!(
        fs::read_to_string(&settings_path).expect("restored settings"),
        original
    );
    assert_eq!(
        fs::read(&connector).expect("plugin connector after restore"),
        original_connector
    );
}

#[test]
fn toggle_apply_changes_codex_configured_mcp_native_state_and_restore_recovers_config() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy
        .path()
        .join("codex")
        .join("global")
        .join("config.toml");
    let original = fs::read_to_string(&config_path).expect("original config");
    assert!(original.contains("[mcp_servers.github]"));
    assert!(original.contains("[plugins.safe-shell]"));

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "codex",
                "--kind",
                "mcp",
                "--layer",
                "global",
                "--id",
                "codex:global:configured-mcp:github",
            ]);
    });

    assert!(output.status.success(), "codex mcp toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("replace file"));

    let rewritten = fs::read_to_string(&config_path).expect("rewritten config");
    assert!(rewritten.contains("[mcp_servers.github]\nenabled = false\n"));
    assert!(rewritten.contains("[plugins.safe-shell]"));
    assert!(!app_state.path().join("vault").exists());

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(restore.status.success(), "codex mcp restore should succeed");
    let restore_stdout = String::from_utf8(restore.stdout).expect("restore stdout is utf8");
    assert!(restore_stdout.contains("status: restored"));
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored config"),
        original
    );
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn toggle_apply_changes_codex_admin_skill_native_state_and_restore_recovers_config() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let skill_path = fixture_copy
        .path()
        .join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let original = fs::read_to_string(&config_path).expect("original config");

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "codex",
                "--kind",
                "skill",
                "--layer",
                "global",
                "--id",
                "codex:global:skill:admin/example-codex-admin-skill",
            ]);
    });

    assert!(output.status.success(), "Codex skill toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("Restart Codex"));
    let rewritten = fs::read_to_string(&config_path).expect("rewritten config");
    assert!(rewritten.contains("[[skills.config]]"));
    assert!(rewritten.contains("enabled = false"));
    assert!(skill_path.is_file());
    assert!(!app_state.path().join("vault").exists());

    let list = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--provider", "codex", "--json"])
        .output()
        .expect("Codex list output");
    assert!(list.status.success(), "Codex list should succeed");
    let inventory: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("list stdout is json");
    let item = inventory["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("disabled Codex skill");
    assert_eq!(item["enabled"], false);
    assert_eq!(item["mutability"], "read-write");

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();
    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(
        restore.status.success(),
        "Codex skill restore should succeed"
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored config"),
        original
    );
    assert!(skill_path.is_file());
}

#[test]
fn toggle_apply_changes_codex_connector_plugin_and_preserves_bundle() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let original = fs::read_to_string(&config_path).expect("original config");
    let connector = fixture_copy
        .path()
        .join("codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json");
    let original_connector = fs::read(&connector).expect("original plugin connector");

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "codex",
                "--kind",
                "plugin",
                "--layer",
                "global",
                "--id",
                "codex:global:plugin-config:config:connector-kit@example-marketplace",
            ]);
    });

    assert!(
        output.status.success(),
        "Codex plugin toggle should succeed"
    );
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("Restart Codex"));
    let rewritten = fs::read_to_string(&config_path).expect("rewritten config");
    assert!(
        rewritten.contains("[plugins.\"connector-kit@example-marketplace\"]\nenabled = false\n")
    );
    assert_eq!(
        fs::read(&connector).expect("plugin connector after disable"),
        original_connector
    );

    let list = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["list", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--provider", "codex", "--json"])
        .output()
        .expect("Codex list output");
    assert!(list.status.success(), "Codex list should succeed");
    let inventory: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("list stdout is json");
    let item = inventory["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| {
            item["id"] == "codex:global:plugin-config:config:connector-kit@example-marketplace"
        })
        .expect("disabled Codex plugin");
    assert_eq!(item["enabled"], false);
    assert_eq!(item["mutability"], "read-write");

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();
    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });
    assert!(
        restore.status.success(),
        "Codex plugin restore should succeed"
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("restored config"),
        original
    );
    assert_eq!(
        fs::read(&connector).expect("plugin connector after restore"),
        original_connector
    );
}

#[test]
fn toggle_apply_removes_cursor_configured_mcp_and_restore_recovers_mcp_json() {
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

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "cursor",
                "--kind",
                "mcp",
                "--layer",
                "global",
                "--id",
                "cursor:global:configured-mcp:modern-global",
            ]);
    });

    assert!(output.status.success(), "cursor mcp toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("replace file"));
    assert!(cursor_mcp_server(&mcp_path, "modern-global").is_none());

    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("configured-mcp")
        .join("cursor%3Aglobal%3Aconfigured-mcp%3Amodern-global");
    let payload: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vault_root.join("payload.json")).expect("payload"),
    )
    .expect("payload json");
    assert_eq!(payload["command"], "npx");

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(
        restore.status.success(),
        "cursor mcp restore should succeed"
    );
    let restore_stdout = String::from_utf8(restore.stdout).expect("restore stdout is utf8");
    assert!(restore_stdout.contains("status: restored"));
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("restored cursor mcp json"),
        original
    );
    assert!(!vault_root.exists());
}

#[test]
fn toggle_apply_removes_zed_configured_mcp_and_restore_recovers_settings() {
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
    assert!(zed_context_server(&settings_path, "github").is_some());

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "zed",
                "--kind",
                "mcp",
                "--layer",
                "global",
                "--id",
                "zed:global:configured-mcp:github",
            ]);
    });

    assert!(output.status.success(), "zed mcp toggle should succeed");
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("replace file"));
    assert!(zed_context_server(&settings_path, "github").is_none());

    let vault_root = app_state
        .path()
        .join("vault")
        .join("zed")
        .join("global")
        .join("configured-mcp")
        .join("zed%3Aglobal%3Aconfigured-mcp%3Agithub");
    let payload: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vault_root.join("payload.json")).expect("payload"),
    )
    .expect("payload json");
    assert_eq!(payload["command"], "npx");

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(restore.status.success(), "zed mcp restore should succeed");
    let restore_stdout = String::from_utf8(restore.stdout).expect("restore stdout is utf8");
    assert!(restore_stdout.contains("status: restored"));
    assert!(zed_context_server(&settings_path, "github").is_some());
    assert!(!vault_root.exists());
}

#[test]
fn toggle_apply_enables_cursor_configured_mcp_disabled_flag_and_restore_recovers_mcp_json() {
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

    let output = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "cursor",
                "--kind",
                "mcp",
                "--layer",
                "global",
                "--id",
                "cursor:global:configured-mcp:modern-global",
            ]);
    });

    assert!(
        output.status.success(),
        "cursor disabled mcp toggle should succeed"
    );
    let stdout = String::from_utf8(output.stdout).expect("toggle stdout is utf8");
    assert!(stdout.contains("status: applied"));
    assert!(stdout.contains("backupId: backup-"));
    assert!(stdout.contains("replace file"));
    let server = cursor_mcp_server(&mcp_path, "modern-global").expect("modern-global mcp");
    assert_eq!(server["command"], "npx");
    assert!(server.get("disabled").is_none());

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(
        restore.status.success(),
        "cursor disabled mcp restore should succeed"
    );
    assert_eq!(
        fs::read_to_string(&mcp_path).expect("restored cursor mcp json"),
        original
    );
}

#[test]
fn restore_restores_skill_backup_created_by_toggle_apply() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_skill = fixture_copy
        .path()
        .join("pi")
        .join("project")
        .join(".pi")
        .join("skills")
        .join("example-pi-project-skill")
        .join("SKILL.md");

    let apply = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "pi",
                "--kind",
                "skill",
                "--layer",
                "project",
                "--id",
                "pi:project:skill:example-pi-project-skill",
            ]);
    });
    assert!(apply.status.success(), "toggle apply should succeed");
    assert!(!original_skill.exists());

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(restore.status.success(), "restore should succeed");
    let stdout = String::from_utf8(restore.stdout).expect("restore stdout is utf8");
    assert!(stdout.contains("status: restored"));
    assert!(stdout.contains(&format!("backupId: {backup_id}")));
    assert!(original_skill.exists());

    let vault_skill_root = app_state
        .path()
        .join("vault")
        .join("pi")
        .join("project")
        .join("skill");
    assert!(
        !vault_skill_root.exists()
            || fs::read_dir(vault_skill_root)
                .expect("vault skill root")
                .next()
                .is_none()
    );

    let audit =
        fs::read_to_string(app_state.path().join("audit").join("log.jsonl")).expect("audit log");
    assert!(audit.contains("\"event\":\"apply\""));
    assert!(audit.contains("\"event\":\"restore\""));
}

#[test]
fn restore_renders_json_with_string_targets() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_skill = fixture_copy
        .path()
        .join("pi")
        .join("project")
        .join(".pi")
        .join("skills")
        .join("example-pi-project-skill")
        .join("SKILL.md");

    let apply = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "pi",
                "--kind",
                "skill",
                "--layer",
                "project",
                "--id",
                "pi:project:skill:example-pi-project-skill",
            ]);
    });
    assert!(apply.status.success(), "toggle apply should succeed");

    let backup_root = fs::read_dir(app_state.path().join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, true, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path());
    });

    assert!(restore.status.success(), "restore should succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&restore.stdout).expect("restore stdout is json");
    assert_eq!(value["status"], "restored");
    assert_eq!(value["backupId"], backup_id);
    assert!(value["affectedTargets"][0].as_str().is_some());
    assert!(
        value["affectedTargets"]
            .as_array()
            .expect("affected targets")
            .iter()
            .any(|target| target.as_str().expect("target string").contains(
                original_skill
                    .parent()
                    .expect("skill dir")
                    .to_string_lossy()
                    .as_ref()
            ))
    );
    assert!(value.get("reason").is_none());
    assert!(original_skill.exists());
}

#[test]
fn restore_uses_user_config_app_state_when_app_state_arg_is_omitted() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let temp = TempDir::new().expect("temp config roots");
    let home_root = temp.path().join("home");
    let project_root = temp.path().join("configured-project");
    let app_state = temp.path().join("configured-state");
    fs::create_dir_all(&project_root).expect("create configured project");
    fs::create_dir_all(&app_state).expect("create configured app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_text(
        &home_root.join(".config/unpin/config.json"),
        &serde_json::json!({
            "appStateRoot": app_state
        })
        .to_string(),
    );
    let original_skill = fixture_copy
        .path()
        .join("pi")
        .join("project")
        .join(".pi")
        .join("skills")
        .join("example-pi-project-skill")
        .join("SKILL.md");

    let apply = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(&app_state)
            .args([
                "--provider",
                "pi",
                "--kind",
                "skill",
                "--layer",
                "project",
                "--id",
                "pi:project:skill:example-pi-project-skill",
            ]);
    });
    assert!(apply.status.success(), "toggle apply should succeed");
    assert!(!original_skill.exists());

    let backup_root = fs::read_dir(app_state.join("backups"))
        .expect("backups dir")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .path();
    let backup_id = backup_root
        .file_name()
        .expect("backup id")
        .to_string_lossy()
        .into_owned();

    let restore = run_reviewed_restore(&backup_id, false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--project-root"])
            .arg(&project_root)
            .env("HOME", &home_root);
    });

    assert!(
        restore.status.success(),
        "restore should use user config app-state root; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&restore.stdout),
        String::from_utf8_lossy(&restore.stderr)
    );
    let stdout = String::from_utf8(restore.stdout).expect("restore stdout is utf8");
    assert!(stdout.contains("status: restored"));
    assert!(original_skill.exists());
}

#[test]
fn mcp_restore_plan_fingerprint_is_accepted_by_cli_apply() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_skill = fixture_copy
        .path()
        .join("pi/project/.pi/skills/example-pi-project-skill/SKILL.md");
    let disabled = run_reviewed_toggle(false, |command| {
        command
            .args(["--fixture-root"])
            .arg(fixture_copy.path())
            .args(["--app-state-root"])
            .arg(app_state.path())
            .args([
                "--provider",
                "pi",
                "--kind",
                "skill",
                "--layer",
                "project",
                "--id",
                "pi:project:skill:example-pi-project-skill",
            ]);
    });
    assert!(disabled.status.success(), "toggle should create backup");
    assert!(!original_skill.exists());
    let backup_id = fs::read_dir(app_state.path().join("backups"))
        .expect("backups directory")
        .next()
        .expect("one backup")
        .expect("backup entry")
        .file_name()
        .to_string_lossy()
        .into_owned();
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "restore-plan",
        "method": "tools/call",
        "params": {
            "name": "unpin_restore_backup",
            "arguments": {"backupId": backup_id}
        }
    }));
    let planned = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP restore plan");
    assert!(
        planned.status.success(),
        "MCP restore plan should succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&planned.stdout),
        String::from_utf8_lossy(&planned.stderr)
    );
    let bodies = response_bodies(&planned.stdout);
    let fingerprint = bodies[0]["result"]["structuredContent"]["planFingerprint"]
        .as_str()
        .expect("MCP restore fingerprint");

    let restored = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("restore")
        .arg(&backup_id)
        .args(["--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args(["--apply", "--confirm", "--plan-fingerprint"])
        .arg(fingerprint)
        .arg("--json")
        .output()
        .expect("CLI restore apply");

    assert!(
        restored.status.success(),
        "CLI restore should accept MCP fingerprint; stdout={} stderr={}",
        String::from_utf8_lossy(&restored.stdout),
        String::from_utf8_lossy(&restored.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&restored.stdout).expect("CLI restore JSON");
    assert_eq!(result["status"], "restored");
    assert!(original_skill.exists());
}

#[test]
fn restore_reports_missing_backup_id() {
    let app_state = TempDir::new().expect("temp app state");

    let human_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("restore")
        .args(["--app-state-root"])
        .arg(app_state.path())
        .output()
        .expect("restore output");

    assert_eq!(human_output.status.code(), Some(1));
    let stdout = String::from_utf8(human_output.stdout).expect("restore stdout is utf8");
    let stderr = String::from_utf8(human_output.stderr).expect("restore stderr is utf8");
    assert_eq!(stdout.trim(), "missing backup id");
    assert_eq!(stderr.trim(), "");

    let json_output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("restore")
        .arg("--json")
        .args(["--app-state-root"])
        .arg(app_state.path())
        .output()
        .expect("restore json output");

    assert_eq!(json_output.status.code(), Some(1));
    let value: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("restore stdout is json");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["reason"], "missing backup id");
    assert_eq!(value.as_object().expect("object").len(), 2);
    let stderr = String::from_utf8(json_output.stderr).expect("restore stderr is utf8");
    assert_eq!(stderr.trim(), "");
}

#[test]
fn mcp_once_rejects_approved_group_apply_mode() {
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--once", "--enable-approved-group-apply"])
        .output()
        .expect("mcp startup output");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("MCP stderr is utf8");
    assert!(stderr.contains(
        "--once cannot be combined with --enable-approved-group-apply; approved apply requires a persistent MCP session"
    ));
}

#[test]
fn mcp_approved_group_apply_rejects_an_unsafe_fixture_state_root_before_leasing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project_root = fixture_copy.path().join("codex").join("project");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--project-root"])
        .arg(project_root)
        .args(["--app-state-root", "/", "--enable-approved-group-apply"])
        .output()
        .expect("mcp startup output");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("MCP stderr is utf8");
    assert!(
        stderr.contains("approved group apply session blocked")
            && stderr.contains("fixture apply is confined"),
        "{stderr}"
    );
}

#[test]
fn group_approve_accepts_challenge_file_transport_and_bounds_input() {
    let temp = TempDir::new().expect("temp challenge");
    let challenge_path = temp.path().join("challenge.txt");
    fs::write(
        &challenge_path,
        vec![b'a'; unpin_core::groups::MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES + 1],
    )
    .expect("oversized challenge");
    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["group", "approve", "--challenge-file"])
        .arg(&challenge_path)
        .output()
        .expect("group approve output");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("group approve stdout")
            .trim(),
        "inventory group challenge input is too large"
    );
}

#[test]
fn mcp_once_lists_stable_tool_surface() {
    let app_state = TempDir::new().expect("temp app state");
    let request = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}\n";

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("mcp output");

    assert!(output.status.success(), "mcp --once should succeed");
    assert!(output.stdout.ends_with(b"\n"));
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];
    let names = body["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        [
            "unpin_get_inventory_summary",
            "unpin_list_items",
            "unpin_list_inventory_groups",
            "unpin_get_inventory_group",
            "unpin_plan_inventory_group",
            "unpin_plan_toggle_item",
            "unpin_apply_toggle_item",
            "unpin_plan_toggle_items",
            "unpin_apply_toggle_items",
            "unpin_list_backups",
            "unpin_restore_backup",
            "unpin_run_doctor",
            "unpin_get_control_status",
            "unpin_get_policy_maintenance_status",
            "unpin_list_catalog",
            "unpin_list_hooks",
            "unpin_plan_catalog_adoption",
            "unpin_apply_catalog_adoption",
            "unpin_plan_hook_trust",
            "unpin_apply_hook_trust",
            "unpin_propose_session_profile",
            "unpin_validate_profile",
            "unpin_plan_profile_policy",
            "unpin_apply_profile_policy",
            "unpin_plan_profile_provider",
            "unpin_apply_profile_provider",
            "unpin_get_capability_locks",
            "unpin_plan_capability_lock",
            "unpin_apply_capability_lock",
            "unpin_plan_gateway_mode",
            "unpin_apply_gateway_mode",
            "unpin_get_gateway_status",
            "unpin_plan_session_end",
            "unpin_apply_session_end",
            "unpin_plan_session_launch",
        ]
    );
}

#[test]
fn mcp_once_accepts_a_provider_scope() {
    let app_state = TempDir::new().expect("temp app state");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "summary",
        "method": "tools/call",
        "params": {
            "name": "unpin_get_inventory_summary",
            "arguments": {}
        }
    }));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--provider", "zed", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("mcp output");

    assert!(
        output.status.success(),
        "mcp --provider zed should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let content = &bodies[0]["result"]["structuredContent"];
    assert_eq!(content["providerScope"], "zed");
    assert_eq!(
        content["inventory"]["providers"]
            .as_array()
            .expect("providers")
            .len(),
        1
    );
    assert_eq!(content["inventory"]["providers"][0]["provider"], "zed");
}

#[test]
fn mcp_processes_stdio_messages_until_eof_without_once() {
    let app_state = TempDir::new().expect("temp app state");
    let mut input = String::new();
    input.push_str(&line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize"
    })));
    input.push_str(&line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "tools",
        "method": "tools/list"
    })));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .write_stdin(input)
        .output()
        .expect("mcp output");

    assert!(
        output.status.success(),
        "mcp should process stdin until EOF"
    );
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["id"], "init");
    assert_eq!(bodies[0]["result"]["serverInfo"]["name"], "unpin");
    assert_eq!(bodies[1]["id"], "tools");
    assert_eq!(
        bodies[1]["result"]["tools"][0]["name"],
        "unpin_get_inventory_summary"
    );
    assert!(
        output.stderr.is_empty(),
        "mcp loop should not write diagnostics on success"
    );
}

#[test]
fn mcp_recovers_after_malformed_stdio_message() {
    let app_state = TempDir::new().expect("temp app state");
    let mut input = "{ invalid json\n".to_string();
    input.push_str(&line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "tools",
        "method": "tools/list"
    })));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .write_stdin(input)
        .output()
        .expect("mcp output");

    assert!(
        output.status.success(),
        "mcp should recover after malformed input; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["id"], serde_json::Value::Null);
    assert_eq!(bodies[0]["error"]["code"], -32700);
    assert_eq!(bodies[0]["error"]["message"], "parse error");
    assert_eq!(bodies[1]["id"], "tools");
    assert!(output.stderr.is_empty());
}

#[test]
fn mcp_once_plans_single_skill_toggle() {
    let app_state = TempDir::new().expect("temp app state");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_toggle_item",
            "arguments": {
                "provider": "pi",
                "kind": "skill",
                "layer": "project",
                "id": "pi:project:skill:example-pi-project-skill",
                "targetEnabled": false
            }
        }
    }));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("mcp output");

    assert!(output.status.success(), "mcp --once should succeed");
    assert!(output.stdout.ends_with(b"\n"));
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];

    assert_eq!(body["result"]["structuredContent"]["status"], "planned");
    assert_eq!(
        body["result"]["structuredContent"]["selection"]["id"],
        "pi:project:skill:example-pi-project-skill"
    );
    assert!(body["result"]["structuredContent"].get("writes").is_none());
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn mcp_toggle_plan_fingerprint_is_accepted_by_cli_apply() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let skill = fixture_copy
        .path()
        .join("pi/project/.pi/skills/example-pi-project-skill/SKILL.md");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": "toggle-plan",
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_toggle_item",
            "arguments": {
                "provider": "pi",
                "kind": "skill",
                "layer": "project",
                "id": "pi:project:skill:example-pi-project-skill",
                "targetEnabled": false
            }
        }
    }));
    let planned = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP toggle plan");
    assert!(
        planned.status.success(),
        "MCP plan should succeed; stderr={}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let bodies = response_bodies(&planned.stdout);
    let fingerprint = bodies[0]["result"]["structuredContent"]["planFingerprint"]
        .as_str()
        .expect("MCP plan fingerprint");

    let applied = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .arg("toggle")
        .args(["--fixture-root"])
        .arg(fixture_copy.path())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .args([
            "--provider",
            "pi",
            "--kind",
            "skill",
            "--layer",
            "project",
            "--id",
            "pi:project:skill:example-pi-project-skill",
            "--apply",
            "--confirm",
            "--plan-fingerprint",
        ])
        .arg(fingerprint)
        .arg("--json")
        .output()
        .expect("CLI toggle apply");

    assert!(
        applied.status.success(),
        "CLI apply should accept MCP fingerprint; stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&applied.stdout).expect("CLI apply JSON");
    assert_eq!(result["status"], "applied");
    assert!(!skill.exists());
}

#[test]
fn mcp_once_plans_codex_admin_skill_toggle_through_native_config() {
    let app_state = TempDir::new().expect("temp app state");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_toggle_item",
            "arguments": {
                "provider": "codex",
                "kind": "skill",
                "layer": "global",
                "id": "codex:global:skill:admin/example-codex-admin-skill",
                "targetEnabled": false
            }
        }
    }));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP output");

    assert!(output.status.success(), "MCP --once should succeed");
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let result = &bodies[0]["result"]["structuredContent"];
    assert_eq!(result["status"], "planned");
    assert_eq!(
        result["selection"]["id"],
        "codex:global:skill:admin/example-codex-admin-skill"
    );
    assert_eq!(result["operations"][0]["type"], "replaceFile");
    assert_eq!(result["warnings"][0]["code"], "restart-required");
    assert!(
        result["warnings"][0]["message"]
            .as_str()
            .expect("warning message")
            .contains("Restart Codex")
    );
    assert_eq!(
        result["affectedTargets"][0]["path"],
        fixtures_root()
            .join("codex/global/config.toml")
            .to_string_lossy()
            .as_ref()
    );
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn mcp_once_plans_codex_plugin_toggle_through_native_config() {
    let app_state = TempDir::new().expect("temp app state");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_toggle_item",
            "arguments": {
                "provider": "codex",
                "kind": "plugin",
                "layer": "global",
                "id": "codex:global:plugin-config:config:safe-shell",
                "targetEnabled": false
            }
        }
    }));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP output");

    assert!(output.status.success(), "MCP --once should succeed");
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let result = &bodies[0]["result"]["structuredContent"];
    assert_eq!(result["status"], "planned");
    assert_eq!(
        result["selection"]["id"],
        "codex:global:plugin-config:config:safe-shell"
    );
    assert_eq!(result["operations"][0]["type"], "replaceFile");
    assert_eq!(result["warnings"][0]["code"], "restart-required");
    assert!(
        result["warnings"][0]["message"]
            .as_str()
            .expect("warning message")
            .contains("Restart Codex")
    );
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn mcp_once_plans_cursor_local_plugin_toggle_through_guarded_vault() {
    let app_state = TempDir::new().expect("temp app state");
    let request = line_request(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "unpin_plan_toggle_item",
            "arguments": {
                "provider": "cursor",
                "kind": "plugin",
                "layer": "global",
                "id": "cursor:global:plugin-manifest:local:example-plugin",
                "targetEnabled": false
            }
        }
    }));

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["mcp", "--fixture-root"])
        .arg(fixtures_root())
        .args(["--app-state-root"])
        .arg(app_state.path())
        .arg("--once")
        .write_stdin(request)
        .output()
        .expect("MCP output");

    assert!(output.status.success(), "MCP --once should succeed");
    let bodies = response_bodies(&output.stdout);
    assert_eq!(bodies.len(), 1);
    let result = &bodies[0]["result"]["structuredContent"];
    assert_eq!(result["status"], "planned");
    assert_eq!(
        result["selection"]["id"],
        "cursor:global:plugin-manifest:local:example-plugin"
    );
    assert_eq!(result["operations"][0]["type"], "renamePath");
    assert_eq!(result["warnings"][0]["code"], "restart-required");
    assert!(
        result["warnings"][0]["message"]
            .as_str()
            .expect("warning message")
            .contains("Restart Cursor")
    );
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn profile_policy_cli_plans_applies_and_reports_authenticated_migration() {
    let temp = TempDir::new().expect("tempdir");
    let fixture_root = fs::canonicalize(temp.path()).expect("canonical fixture root");
    let project_root = fixture_root.join("project");
    let app_state_root = fixture_root.join("state");
    fs::create_dir_all(project_root.join(".unpin")).expect("workspace policy directory");
    let git = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(&project_root)
        .output()
        .expect("git init");
    assert!(git.status.success());
    fs::write(
        project_root.join(".unpin").join("policy.json"),
        serde_json::to_vec_pretty(&unpin_core::profiles::ScopePolicy::default())
            .expect("serialize workspace policy"),
    )
    .expect("write workspace policy");
    let configure = |command: &mut assert_cmd::Command| {
        command
            .arg("--fixture-root")
            .arg(&fixture_root)
            .arg("--project-root")
            .arg(&project_root)
            .arg("--app-state-root")
            .arg(&app_state_root)
            .arg("--json");
    };
    let configure_text = |command: &mut assert_cmd::Command| {
        command
            .arg("--fixture-root")
            .arg(&fixture_root)
            .arg("--project-root")
            .arg(&project_root)
            .arg("--app-state-root")
            .arg(&app_state_root);
    };

    let mut planned = Command::cargo_bin("unpin").expect("unpin binary");
    planned.args(["profile", "policy", "migrate"]);
    configure(&mut planned);
    let planned = planned.output().expect("migration plan output");
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let planned_text =
        String::from_utf8(planned.stdout.clone()).expect("migration plan output is utf8");
    assert!(!planned_text.contains(&project_root.to_string_lossy().to_string()));
    let planned: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("migration plan JSON");
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["plan"]["action"]["action"], "migrate");
    assert!(planned["plan"]["action"]["policy"].is_object());
    assert!(planned["plan"].get("sourcePath").is_none());
    assert!(planned["plan"].get("workspace").is_none());

    let mut text_planned = Command::cargo_bin("unpin").expect("unpin binary");
    text_planned.args(["profile", "policy", "migrate"]);
    configure_text(&mut text_planned);
    let text_planned = text_planned.output().expect("text migration plan output");
    assert!(
        text_planned.status.success(),
        "{}",
        String::from_utf8_lossy(&text_planned.stderr)
    );
    let text_planned = String::from_utf8(text_planned.stdout).expect("text migration plan is utf8");
    assert!(text_planned.contains("\"action\":\"migrate\""));
    assert!(text_planned.contains("operation="));
    assert!(!text_planned.contains(&project_root.to_string_lossy().to_string()));

    let fingerprint = planned["plan"]["planFingerprint"]
        .as_str()
        .expect("plan fingerprint");

    let mut applied = Command::cargo_bin("unpin").expect("unpin binary");
    applied.args(["profile", "policy", "migrate"]);
    configure(&mut applied);
    applied
        .args(["--apply", "--confirm", "--plan-fingerprint"])
        .arg(fingerprint);
    let applied = applied.output().expect("migration apply output");
    assert!(
        applied.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr),
    );
    let applied: serde_json::Value =
        serde_json::from_slice(&applied.stdout).expect("migration apply JSON");
    assert_eq!(applied["status"], "applied");
    assert!(applied["outcome"]["backupId"].as_str().is_some());

    let mut status = Command::cargo_bin("unpin").expect("unpin binary");
    status.args(["profile", "policy", "status", "--candidate-current"]);
    configure(&mut status);
    let status = status.output().expect("policy status output");
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("policy status JSON");
    assert_eq!(status["status"], "managed");
    assert_eq!(status["maintenance"]["classification"], "attached");
    assert_eq!(status["maintenance"]["lifecycle"]["state"], "active");
}

#[cfg(unix)]
#[test]
fn profile_policy_cli_does_not_offer_migration_for_existing_unmanaged_policy() {
    let temp = TempDir::new().expect("tempdir");
    let fixture_root = fs::canonicalize(temp.path()).expect("canonical fixture root");
    let project_root = fixture_root.join("project");
    let app_state_root = fixture_root.join("state");
    fs::create_dir_all(project_root.join(".unpin")).expect("workspace policy directory");
    let git = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(&project_root)
        .output()
        .expect("git init");
    assert!(git.status.success());
    fs::write(
        project_root.join(".unpin").join("policy.json"),
        serde_json::to_vec_pretty(&unpin_core::profiles::ScopePolicy::default())
            .expect("serialize workspace policy"),
    )
    .expect("write workspace policy");
    let identity = resolve_workspace_identity(&project_root).expect("workspace identity");
    let target = PolicyTarget::workspace(identity.repository_key, identity.workspace_key)
        .expect("workspace target");
    PolicyStore::new(&app_state_root)
        .save(
            &target,
            &unpin_core::profiles::ScopePolicy::default(),
            None,
            OwnerGeneration::new("cli-unmanaged-policy", 1).expect("owner"),
        )
        .expect("seed unmanaged destination policy");

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args(["profile", "policy", "status"])
        .arg("--fixture-root")
        .arg(&fixture_root)
        .arg("--project-root")
        .arg(&project_root)
        .arg("--app-state-root")
        .arg(&app_state_root)
        .arg("--json")
        .output()
        .expect("policy status output");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let status: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("policy status JSON");
    assert_eq!(status["status"], "unmanaged");
    assert_eq!(status["unmanagedState"], "existing-policy");
    assert_eq!(status["humanAction"]["code"], "inspect-existing-policy");
    assert!(!status.to_string().contains("review-migration"));
}
