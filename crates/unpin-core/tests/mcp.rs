use std::{
    collections::BTreeSet,
    fs,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        ControlApprovalContext,
    },
    catalog::Catalog,
    config::get_hook_trust_path,
    discovery::{DiscoveryKind, DiscoveryLayer, DiscoveryRoots, ProviderId, discover_all},
    groups::{
        GroupAccessContext, GroupApprovalArtifactStore, GroupDefinitionV1, GroupMemberIdentity,
        GroupPlanDisposition, McpGroupSessionBinding, McpGroupSessionLeaseStore,
        PersonalGroupStore, RepositoryGroupStore, current_unix_seconds,
    },
    hooks::{HookTrustRecord, HookTrustStore},
    mcp::{
        McpApprovedGroupApplyContext, McpAuthenticationReadiness, McpContext,
        McpCredentialReadiness, McpDiscoveryCache, McpProviderScope,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME, UNPIN_MCP_TOOL_NAMES, handle_mcp_request,
        handle_stdio_request_once, handle_stdio_requests,
    },
    mutation::{BackupAuthenticationKey, BulkToggleController, authenticate_legacy_backup},
    profiles::{
        CapabilityLockSnapshot, PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope,
        ProfileStore, compile_profile,
    },
    sessions::SessionAuthorityKey,
    state::{
        atomic_json::{AtomicJsonStore, OwnerGeneration},
        workspace::resolve_workspace_identity,
    },
};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

struct TestMcpContext {
    context: McpContext,
    _app_state: TempDir,
}

impl Deref for TestMcpContext {
    type Target = McpContext;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl DerefMut for TestMcpContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.context
    }
}

fn context() -> TestMcpContext {
    let app_state = TempDir::new().expect("temporary MCP app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical MCP app state");
    let context = context_with_roots(&fixtures_root(), &app_state_root);
    TestMcpContext {
        context,
        _app_state: app_state,
    }
}

fn context_with_roots(fixture_root: &Path, app_state_root: &Path) -> McpContext {
    let backup_authentication_key = BackupAuthenticationKey::new([0x42; 32]);
    McpContext {
        discovery_roots: DiscoveryRoots::fixture_root(fixture_root),
        fixture_root: Some(fixture_root.to_path_buf()),
        package_root: Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf(),
        app_state_root: app_state_root.to_path_buf(),
        project_root: fixture_root.join("cursor").join("project"),
        authentication: authentication_readiness(Some(backup_authentication_key.key_id())),
        backup_authentication_key: Some(backup_authentication_key),
        session_authority_key: Some(SessionAuthorityKey::new([0x53; 32])),
        provider_scope: McpProviderScope::All,
        discovery_cache: McpDiscoveryCache::default(),
        approved_group_apply: None,
    }
}

fn context_for_provider(provider: ProviderId) -> TestMcpContext {
    let mut context = context();
    context.provider_scope = McpProviderScope::Provider(provider);
    context
}

fn authentication_readiness(backup_key_id: Option<String>) -> McpAuthenticationReadiness {
    McpAuthenticationReadiness {
        backup_authentication: backup_key_id
            .map_or_else(McpCredentialReadiness::missing, |key_id| {
                McpCredentialReadiness::ready(Some(key_id))
            }),
        approval_signing: McpCredentialReadiness::ready(Some("approval-test-key".to_string())),
        cursor_dashboard: McpCredentialReadiness::missing(),
    }
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

fn write_claude_project_mcp_servers(fixture_root: &Path, servers: serde_json::Value) {
    let mcp_path = fixture_root
        .join("claude")
        .join("project")
        .join(".mcp.json");
    fs::write(
        mcp_path,
        serde_json::to_string_pretty(&json!({ "mcpServers": servers }))
            .expect("mcp json serializes"),
    )
    .expect("write claude project mcp");
}

fn write_claude_local_mcp_servers(fixture_root: &Path, servers: serde_json::Value) {
    let state_path = fixture_root.join("claude").join(".claude.json");
    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("Claude user state"))
            .expect("Claude user state JSON");
    let project_key = fixture_root
        .join("claude")
        .join("project")
        .to_string_lossy()
        .to_string();
    document["projects"][project_key.as_str()] = json!({ "mcpServers": servers });
    fs::write(
        state_path,
        serde_json::to_string_pretty(&document).expect("Claude user state serializes"),
    )
    .expect("write Claude local MCP state");
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
        serde_json::to_string_pretty(&json!({
            "folder": format!("file://{}", project_root.display())
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

fn write_backup_manifest(app_state_root: &Path, backup_dir: &str, manifest: serde_json::Value) {
    let manifest_path = app_state_root
        .join("backups")
        .join(backup_dir)
        .join("manifest.json");
    fs::create_dir_all(manifest_path.parent().expect("manifest has parent"))
        .expect("create manifest parent");
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest serializes"),
    )
    .expect("write manifest");
}

fn backup_manifest(
    backup_id: &str,
    created_at: &str,
    payload_path: Option<&str>,
) -> serde_json::Value {
    let entries = payload_path
        .map(|path| {
            json!([{
                "entryId": "entry-1",
                "target": {
                    "targetType": "path",
                    "path": "/tmp/unpin-live-target"
                },
                "existed": true,
                "pathKind": "file",
                "payload": {
                    "storage": "path",
                    "path": path
                }
            }])
        })
        .unwrap_or_else(|| json!([]));

    json!({
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
}

fn settings_plugin_enabled(path: &Path, plugin_id: &str) -> bool {
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("settings json"))
            .expect("settings value");
    value["enabledPlugins"][plugin_id]
        .as_bool()
        .unwrap_or_else(|| panic!("enabledPlugins.{plugin_id} should be boolean"))
}

fn call_tool(context: &McpContext, name: &str, arguments: serde_json::Value) -> serde_json::Value {
    let response = handle_mcp_request(
        context,
        &json!({
            "jsonrpc": "2.0",
            "id": name,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }),
    );

    response
        .pointer("/result/structuredContent")
        .cloned()
        .unwrap_or_else(|| panic!("tool {name} did not return structured content: {response:#}"))
}

fn call_tool_error(context: &McpContext, name: &str, arguments: serde_json::Value) -> String {
    let response = handle_mcp_request(
        context,
        &json!({
            "jsonrpc": "2.0",
            "id": name,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }),
    );

    response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("tool {name} did not return an error: {response:#}"))
        .to_string()
}

fn tool_descriptor(context: &McpContext, name: &str) -> serde_json::Value {
    let response = handle_mcp_request(
        context,
        &json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list"
        }),
    );

    response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap_or_else(|| panic!("tool descriptor should exist for {name}"))
        .clone()
}

fn required_input_fields(tool: &serde_json::Value) -> Vec<String> {
    tool["inputSchema"]["required"]
        .as_array()
        .expect("required field array")
        .iter()
        .map(|field| field.as_str().expect("required field name").to_string())
        .collect()
}

fn line_request(request: serde_json::Value) -> Vec<u8> {
    format!("{request}\n").into_bytes()
}

fn response_bodies(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(output.to_vec())
        .expect("MCP output is utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("MCP line is JSON"))
        .collect()
}

#[test]
fn initialize_negotiates_current_and_legacy_protocol_versions() {
    for requested in ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] {
        let response = handle_mcp_request(
            &context(),
            &json!({
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": requested,
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1" }
                }
            }),
        );

        assert_eq!(response["result"]["protocolVersion"], requested);
    }
}

#[test]
fn initialize_falls_back_to_latest_supported_protocol_version() {
    let response = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2099-01-01",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1" }
            }
        }),
    );

    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        response["result"]["capabilities"]["experimental"]["unpinControl"]["version"],
        2
    );
    assert_eq!(
        response["result"]["capabilities"]["experimental"]["unpinControl"]["mutation"],
        "human-handoff-only"
    );
}

#[test]
fn validates_inline_profile_without_materializing_state() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let catalog = Catalog::from_discovery(
        &discover_all(&context.discovery_roots).expect("fixture discovery"),
    )
    .expect("catalog");
    let capability_id = catalog
        .records
        .values()
        .next()
        .expect("catalog capability")
        .id
        .clone();
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "mcp-validate".to_string(),
        display_name: "MCP validate".to_string(),
        description: None,
        members: vec![capability_id.clone()],
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };

    let validated = call_tool(
        &context,
        "unpin_validate_profile",
        json!({
            "definition": definition,
            "sourceScope": "session"
        }),
    );

    assert_eq!(validated["status"], "valid");
    assert_eq!(validated["sourceScope"], "session");
    assert_eq!(validated["materialized"], false);
    assert!(!app_state.path().join("profiles").exists());
}

#[test]
fn gateway_status_reads_requested_scope_without_planning() {
    let app_state = TempDir::new().expect("temp app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let context = context_with_roots(&fixtures_root(), &app_state_root);
    let status = call_tool(
        &context,
        "unpin_get_gateway_status",
        json!({"scope": "global", "provider": "codex"}),
    );

    assert_eq!(status["status"], "ok");
    assert_eq!(status["target"]["provider"], "codex");
    assert!(status["target"]["repositoryKey"].is_null());
    assert!(status["mode"].is_null());
    assert!(status["policy"].is_null());
}

#[test]
fn handles_multiple_stdio_messages_until_eof() {
    let mut input = Vec::new();
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize"
    })));
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "id": "tools",
        "method": "tools/list"
    })));
    let mut output = Vec::new();

    handle_stdio_requests(&context(), input.as_slice(), &mut output).expect("stdio loop");

    let bodies = response_bodies(&output);
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["id"], "init");
    assert_eq!(bodies[0]["result"]["serverInfo"]["name"], "unpin");
    assert_eq!(bodies[0]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(bodies[1]["id"], "tools");
    assert_eq!(
        bodies[1]["result"]["tools"][0]["name"],
        "unpin_get_inventory_summary"
    );
}

#[test]
fn handles_malformed_once_request_as_json_rpc_parse_error() {
    let output = handle_stdio_request_once(&context(), b"{ invalid json\n".as_slice())
        .expect("malformed request should produce a response");

    let bodies = response_bodies(&output);
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["id"], serde_json::Value::Null);
    assert_eq!(bodies[0]["error"]["code"], -32700);
    assert_eq!(bodies[0]["error"]["message"], "parse error");
}

#[test]
fn stdio_loop_returns_parse_errors_and_continues() {
    let mut input = b"{ invalid json\n\n".to_vec();
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "id": "tools",
        "method": "tools/list"
    })));
    let mut output = Vec::new();

    handle_stdio_requests(&context(), input.as_slice(), &mut output)
        .expect("stdio loop should recover from parse errors");

    let bodies = response_bodies(&output);
    assert_eq!(bodies.len(), 3);
    for body in &bodies[..2] {
        assert_eq!(body["id"], serde_json::Value::Null);
        assert_eq!(body["error"]["code"], -32700);
        assert_eq!(body["error"]["message"], "parse error");
    }
    assert_eq!(bodies[2]["id"], "tools");
    assert_eq!(
        bodies[2]["result"]["tools"][0]["name"],
        "unpin_get_inventory_summary"
    );
}

#[test]
fn stdio_loop_skips_all_idless_message_responses() {
    let mut input = Vec::new();
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize"
    })));
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })));
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "method": "tools/list"
    })));
    input.extend(line_request(json!({
        "jsonrpc": "2.0",
        "id": "tools",
        "method": "tools/list"
    })));
    let mut output = Vec::new();

    handle_stdio_requests(&context(), input.as_slice(), &mut output).expect("stdio loop");

    let bodies = response_bodies(&output);
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["id"], "init");
    assert_eq!(bodies[1]["id"], "tools");
}

#[test]
fn plans_bulk_toggle_items_with_fingerprint_and_separate_no_op_items() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "providers": ["claude"],
                "kinds": ["plugin"]
            },
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "claude"
            },
            "acknowledgeWholeInventory": true
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert!(
        planned["planFingerprint"]
            .as_str()
            .expect("plan fingerprint")
            .starts_with("sha256:")
    );
    assert_eq!(planned["applyMode"], "fingerprint-required");
    assert!(planned.get("writes").is_none());
    let matched = planned["matched"].as_array().expect("matched items");
    let actionable = planned["actionable"].as_array().expect("actionable");
    let blocked = planned["blocked"].as_array().expect("blocked");
    assert!(matched.len() >= 4);
    assert_eq!(planned["matchedCount"].as_u64(), Some(matched.len() as u64));
    assert_eq!(
        planned["actionableCount"].as_u64(),
        Some(actionable.len() as u64)
    );
    assert_eq!(planned["blockedCount"].as_u64(), Some(blocked.len() as u64));
    assert_eq!(
        planned["matchedItems"]
            .as_array()
            .expect("matchedItems")
            .len(),
        matched.len()
    );
    assert_eq!(
        planned["actionableItems"]
            .as_array()
            .expect("actionableItems")
            .len(),
        actionable.len()
    );
    assert_eq!(
        planned["blockedItems"]
            .as_array()
            .expect("blockedItems")
            .len(),
        blocked.len()
    );
    assert_eq!(
        planned["perItemPlans"]
            .as_array()
            .expect("perItemPlans")
            .len(),
        planned["includedCount"].as_u64().expect("included count") as usize
    );
    assert_eq!(planned["warnings"], json!([]));
    assert!(
        planned["matchedItems"]
            .as_array()
            .expect("matchedItems")
            .iter()
            .all(|entry| entry.get("displayName").is_none() && entry.get("sourcePath").is_none())
    );
    assert!(
        planned["actionableItems"]
            .as_array()
            .expect("actionableItems")
            .iter()
            .any(|entry| entry["provider"] == "claude"
                && entry["kind"] == "plugin"
                && entry["layer"] == "global"
                && entry["id"] == "claude:global:tool:settings:safe-shell")
    );
    assert!(
        planned["perItemPlans"]
            .as_array()
            .expect("perItemPlans")
            .iter()
            .any(|entry| entry["status"] == "planned"
                && entry["selection"]["id"] == "claude:global:tool:settings:safe-shell")
    );
    assert!(
        planned["perItemPlans"]
            .as_array()
            .expect("perItemPlans")
            .iter()
            .any(
                |entry| entry["selection"]["id"] == "claude:global:tool:settings:safe-shell"
                    && entry["operations"][0]["op"] == "replaceJsonValue"
                    && entry["operations"][0]["pointer"] == "/enabledPlugins/safe-shell"
            )
    );
    assert!(
        planned["noOpItems"]
            .as_array()
            .expect("noOpItems")
            .iter()
            .any(|entry| entry["id"] == "claude:project:tool:settings-local:local-shell")
    );
    assert!(
        planned["blockedItems"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

#[test]
fn rejects_malformed_bulk_selector_fields() {
    let response = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "providers": "claude"
            },
            "targetEnabled": false
        }),
    );

    assert_eq!(response["status"], "blocked");
    assert_eq!(
        response["reason"],
        "selector.providers must be an array of strings"
    );
}

#[test]
fn bulk_preflight_rejects_missing_reach_and_provider_only_selectors() {
    let missing_reach = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "ids": ["claude:global:tool:settings:safe-shell"]
            },
            "targetEnabled": false
        }),
    );
    assert_eq!(missing_reach["status"], "blocked");
    assert_eq!(missing_reach["reasonCode"], "bulk-plan-invalid");
    assert!(
        missing_reach["message"]
            .as_str()
            .is_some_and(|message| message.contains("selected provider"))
    );

    let provider_only = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "providers": ["claude"]
            },
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "claude"
            },
            "allowEmptySelection": true
        }),
    );
    assert_eq!(provider_only["status"], "blocked");
    assert_eq!(
        provider_only["reasonCode"],
        "selector-requires-non-provider-criterion"
    );

    let malformed_reach = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "ids": ["claude:global:tool:settings:safe-shell"]
            },
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "claude",
                "unexpected": true
            }
        }),
    );
    assert_eq!(malformed_reach["status"], "blocked");
    assert_eq!(
        malformed_reach["reason"],
        "providerReach has unsupported fields"
    );
    let spoofed_provenance = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "ids": ["claude:global:tool:settings:safe-shell"]
            },
            "targetEnabled": false,
            "maxItems": 1,
            "providerReach": {
                "mode": "selected",
                "provider": "claude",
                "provenance": "pinned-mcp-boundary"
            }
        }),
    );
    assert_eq!(spoofed_provenance["status"], "blocked");
    assert_eq!(
        spoofed_provenance["reason"],
        "providerReach has unsupported fields"
    );
}

#[test]
fn bulk_whole_inventory_acknowledgement_precedes_reach_filtering() {
    let response = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "kinds": ["skill"]
            },
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "claude"
            }
        }),
    );

    assert_eq!(response["status"], "blocked");
    assert_eq!(
        response["reasonCode"],
        "whole-inventory-acknowledgement-required"
    );
    assert_eq!(response["acknowledgementRequired"], true);
    assert!(
        response["resolvedCounts"]
            .as_array()
            .is_some_and(|counts| counts.iter().any(|count| count["provider"] != "claude")),
        "counts come from the complete matched set before selected-provider filtering"
    );
}

#[test]
fn cursor_workspace_mcp_plan_preserves_sqlite_target_type() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_cursor_workspace_disabled_servers(
        &fixture_copy.path().join("cursor").join("global"),
        &fixture_copy.path().join("cursor").join("project"),
        &["user-modern-global"],
    );

    let planned = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_plan_toggle_item",
        json!({
            "provider": "cursor",
            "kind": "mcp",
            "layer": "global",
            "id": "cursor:global:configured-mcp:modern-global",
            "targetEnabled": true
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert_eq!(
        planned["operations"][0]["op"],
        "replaceSqliteItemTableValue"
    );
    assert_eq!(planned["affectedTargets"][0]["type"], "sqlite-item");
    assert_eq!(planned["affectedTargets"][0]["targetType"], "sqlite-item");
}

#[test]
fn mcp_without_backup_key_allows_plans_and_hands_off_apply_without_writing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mut context = context_with_roots(fixture_copy.path(), app_state.path());
    context.backup_authentication_key = None;
    context.authentication.backup_authentication = McpCredentialReadiness::missing();
    let arguments = json!({
        "provider": "pi",
        "kind": "skill",
        "layer": "project",
        "id": "pi:project:skill:example-pi-project-skill",
        "targetEnabled": false
    });

    let summary = call_tool(&context, "unpin_get_inventory_summary", json!({}));
    assert_eq!(summary["writeSafety"]["backupAuthentication"], "missing");
    assert_eq!(
        summary["writeSafety"]["backupAuthenticationDetails"],
        json!({"status": "missing"})
    );
    assert_eq!(summary["writeSafety"]["writesEnabled"], false);
    assert_eq!(
        summary["writeSafety"]["humanApproval"],
        "cli-or-tui-required"
    );

    let planned = call_tool(&context, "unpin_plan_toggle_item", arguments.clone());
    assert_eq!(planned["status"], "planned");

    let mut apply_arguments = arguments.as_object().expect("arguments object").clone();
    apply_arguments.insert("requireConfirmation".to_string(), json!(true));
    apply_arguments.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(apply_arguments),
    );
    assert_eq!(applied["status"], "human-action-required");
    assert!(!app_state.path().join("backups").exists());
}

#[test]
fn inventory_group_mcp_is_read_only_by_default_and_applies_only_external_one_time_approval() {
    let temp = TempDir::new().expect("temporary group MCP root");
    let root = fs::canonicalize(temp.path()).expect("canonical group MCP root");
    let fixture_root = root.join("fixtures");
    let app_state_root = root.join("state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(&app_state_root).expect("app state");

    let config_path = fixture_root.join("codex/global/config.toml");
    let skill_path = fixture_root.join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config_source = fs::read_to_string(&config_path).expect("Codex fixture");
    fs::write(
        &config_path,
        format!(
            "{config_source}\n[[skills.config]]\npath = {:?}\nenabled = true\n",
            skill_path.to_string_lossy()
        ),
    )
    .expect("Codex skill override");

    let mut context = context_with_roots(&fixture_root, &app_state_root);
    context.project_root = fixture_root.join("codex/project");
    let access = GroupAccessContext::from_runtime(
        &context.app_state_root,
        &context.project_root,
        &context.discovery_roots,
        None,
        None,
    )
    .expect("group access");
    let discovered = discover_all(&context.discovery_roots).expect("discovery");
    let item = discovered
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("group fixture skill");
    let member = GroupMemberIdentity::try_from(item).expect("member identity");
    let missing_member = GroupMemberIdentity::new(
        item.provider,
        item.kind,
        item.category,
        item.layer,
        "codex:global:skill:admin/missing-group-mcp-skill",
    )
    .expect("missing member identity");
    let personal = PersonalGroupStore::new(access.clone());
    personal
        .create(
            &GroupDefinitionV1::new("brainstorming", vec![member]).expect("group definition"),
            OwnerGeneration::new("group-mcp-test", 1).expect("owner"),
        )
        .expect("create group");
    personal
        .create(
            &GroupDefinitionV1::new("missing-members", vec![missing_member])
                .expect("missing-member group definition"),
            OwnerGeneration::new("group-mcp-test", 2).expect("next owner generation"),
        )
        .expect("create missing-member group");

    let default_tools = handle_mcp_request(
        &context,
        &json!({"jsonrpc": "2.0", "id": "tools", "method": "tools/list"}),
    );
    let default_names = default_tools["result"]["tools"]
        .as_array()
        .expect("default tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<BTreeSet<_>>();
    assert!(default_names.contains("unpin_list_inventory_groups"));
    assert!(default_names.contains("unpin_get_inventory_group"));
    assert!(default_names.contains("unpin_plan_inventory_group"));
    assert!(!default_names.contains(UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME));

    let default_initialize = handle_mcp_request(
        &context,
        &json!({"jsonrpc": "2.0", "id": "init", "method": "initialize"}),
    );
    let default_control =
        &default_initialize["result"]["capabilities"]["experimental"]["unpinControl"];
    assert_eq!(default_control["mutation"], "human-handoff-only");
    assert!(
        default_control
            .get("conditionalProviderWritesEnabled")
            .is_none()
    );
    assert!(default_control.get("sessionLeaseWrites").is_none());

    let preview = call_tool(
        &context,
        "unpin_plan_inventory_group",
        json!({
            "group": "personal:brainstorming",
            "targetEnabled": false,
            "maxMembers": 10,
            "providerReach": "all",
        }),
    );
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["plan"]["disposition"], "preview");
    assert_eq!(
        preview["plan"]["mode"],
        serde_json::to_value(unpin_core::groups::GroupPlanMode::PreviewOnly)
            .expect("preview mode JSON")
    );
    assert!(preview.get("challenge").is_none());
    assert!(preview.get("operationId").is_none());
    assert!(preview["plan"].get("operationId").is_none());
    assert!(
        call_tool_error(
            &context,
            UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
            json!({
                "operationId": "preview",
                "planFingerprint": "preview",
                "challenge": "preview",
                "approvalArtifact": "preview",
            }),
        )
        .contains("unknown tool")
    );

    let now_unix = current_unix_seconds().expect("current time");
    let session_key = context
        .session_authority_key
        .clone()
        .expect("session authority key");
    let session = McpGroupSessionLeaseStore::new(&context.app_state_root)
        .create(
            McpGroupSessionBinding {
                provider: None,
                repository_key: access.repository_key().to_string(),
                workspace_key: access.workspace_key().to_string(),
            },
            &session_key,
            now_unix,
        )
        .expect("approved group MCP lease");
    let approval_key = ApprovalKey::new([0x71; 32]);
    context.approved_group_apply = Some(McpApprovedGroupApplyContext {
        session: session.clone(),
        approval_key: approval_key.clone(),
    });

    let enabled_initialize = handle_mcp_request(
        &context,
        &json!({"jsonrpc": "2.0", "id": "init", "method": "initialize"}),
    );
    let enabled_control =
        &enabled_initialize["result"]["capabilities"]["experimental"]["unpinControl"];
    assert_eq!(enabled_control["mutation"], "human-handoff-only");
    assert_eq!(
        enabled_control["conditionalGroupApply"],
        "approved-group-apply-v1"
    );
    assert_eq!(enabled_control["unattendedWritesEnabled"], false);
    assert_eq!(enabled_control["conditionalProviderWritesEnabled"], true);
    assert_eq!(enabled_control["challengeStoreWrites"], false);
    assert_eq!(enabled_control["sessionLeaseWrites"], true);
    assert_eq!(enabled_control["approvalArtifactRequired"], true);
    assert_eq!(enabled_control["canMintApproval"], false);
    assert_eq!(enabled_control["requiresPersistentSession"], true);
    let apply_descriptor = tool_descriptor(&context, UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME);
    assert_eq!(apply_descriptor["annotations"]["readOnlyHint"], false);
    assert_eq!(
        required_input_fields(&apply_descriptor),
        vec![
            "operationId",
            "planFingerprint",
            "challenge",
            "approvalArtifact",
        ]
    );

    for (tool, arguments, expected_error) in [
        (
            "unpin_list_inventory_groups",
            json!({"unexpected": true}),
            "field: unexpected",
        ),
        (
            "unpin_get_inventory_group",
            json!({}),
            "missing required field: group",
        ),
        (
            "unpin_get_inventory_group",
            json!({"group": 1}),
            "missing required field: group",
        ),
        (
            "unpin_get_inventory_group",
            json!({"group": "personal:brainstorming", "unexpected": true}),
            "field: unexpected",
        ),
        (
            "unpin_plan_inventory_group",
            json!({"targetEnabled": false, "maxMembers": 10}),
            "missing required field: group",
        ),
        (
            "unpin_plan_inventory_group",
            json!({
                "group": "personal:brainstorming",
                "targetEnabled": "false",
                "maxMembers": 10,
            }),
            "missing required field: targetEnabled",
        ),
        (
            "unpin_plan_inventory_group",
            json!({
                "group": "personal:brainstorming",
                "targetEnabled": false,
                "maxMembers": "10",
            }),
            "maxMembers must be a positive integer",
        ),
        (
            "unpin_plan_inventory_group",
            json!({
                "group": "personal:brainstorming",
                "targetEnabled": false,
                "maxMembers": 10,
                "unexpected": true,
            }),
            "field: unexpected",
        ),
        (
            UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
            json!({}),
            "missing required field: operationId",
        ),
        (
            UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
            json!({
                "operationId": "operation",
                "planFingerprint": "fingerprint",
                "challenge": "challenge",
                "approvalArtifact": "artifact",
                "unexpected": true,
            }),
            "field: unexpected",
        ),
    ] {
        let error = call_tool_error(&context, tool, arguments);
        assert!(
            error.contains(expected_error),
            "{tool} returned {error:?}, expected {expected_error:?}"
        );
    }

    for (qualified_name, target_enabled, expected_status) in [
        ("personal:brainstorming", true, "no-op"),
        ("personal:missing-members", false, "blocked"),
    ] {
        let result = call_tool(
            &context,
            "unpin_plan_inventory_group",
            json!({
                "group": qualified_name,
                "targetEnabled": target_enabled,
                "maxMembers": 10,
                "providerReach": "all",
            }),
        );
        assert_eq!(result["status"], expected_status);
        assert_eq!(result["approval"], "not-required");
        assert_eq!(result["plan"]["disposition"], expected_status);
        assert!(result.get("challenge").is_none());
        assert!(result.get("operationId").is_none());
        assert!(result["plan"].get("operationId").is_none());
        assert!(result["humanAction"].is_null());
    }

    let actionable = call_tool(
        &context,
        "unpin_plan_inventory_group",
        json!({
            "group": "personal:brainstorming",
            "targetEnabled": false,
            "maxMembers": 10,
            "providerReach": "all",
        }),
    );
    assert_eq!(actionable["status"], "actionable");
    assert_eq!(actionable["approval"], "required");
    assert_eq!(actionable["humanAction"]["code"], "approve-for-mcp-apply");
    let plan: unpin_core::groups::GroupTogglePlan =
        serde_json::from_value(actionable["plan"].clone()).expect("actionable group plan");
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    let operation_id = actionable["operationId"].as_str().expect("operation ID");
    let fingerprint = actionable["planFingerprint"]
        .as_str()
        .expect("plan fingerprint");
    let challenge = actionable["challenge"]
        .as_str()
        .expect("approval challenge");
    let approval_context =
        ControlApprovalContext::new(access.repository_key(), access.workspace_key())
            .expect("approval context");
    let expectation = plan
        .approval_expectation(&approval_context)
        .expect("group expectation");
    let approval_receipt = |suffix: &str| {
        ApprovalIssuer::new(
            approval_key.clone(),
            expectation.issuer.clone(),
            expectation.audience.clone(),
        )
        .expect("group approval issuer")
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("receipt-group-mcp-{suffix}"),
            nonce: format!("nonce-group-mcp-{suffix}"),
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
        .expect("group approval receipt")
    };
    let drift_artifact = GroupApprovalArtifactStore::new(&context.app_state_root)
        .issue(
            session.clone(),
            &plan,
            challenge,
            approval_receipt("drift"),
            &session_key,
            now_unix,
        )
        .expect("drift approval artifact");

    let approved_config = fs::read_to_string(&config_path).expect("approved Codex config");
    let enabled_binding = format!("path = {:?}\nenabled = true", skill_path.to_string_lossy());
    let disabled_binding = format!("path = {:?}\nenabled = false", skill_path.to_string_lossy());
    let drifted_config = approved_config.replacen(&enabled_binding, &disabled_binding, 1);
    assert_ne!(drifted_config, approved_config);
    fs::write(&config_path, &drifted_config).expect("introduce approved-plan drift");
    let drifted = call_tool(
        &context,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
        json!({
            "operationId": operation_id,
            "planFingerprint": fingerprint,
            "challenge": challenge,
            "approvalArtifact": drift_artifact.artifact_id,
        }),
    );
    assert_eq!(drifted["status"], "blocked");
    assert!(
        drifted["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no longer matches current state")),
        "{drifted}"
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("drifted Codex config"),
        drifted_config
    );
    assert!(
        !context
            .app_state_root
            .join("groups/operations")
            .join(format!("{operation_id}.json"))
            .exists()
    );
    assert!(!context.app_state_root.join("backups").exists());
    fs::write(&config_path, approved_config).expect("restore approved Codex config");

    let actionable = call_tool(
        &context,
        "unpin_plan_inventory_group",
        json!({
            "group": "personal:brainstorming",
            "targetEnabled": false,
            "maxMembers": 10,
            "providerReach": "all",
        }),
    );
    let plan: unpin_core::groups::GroupTogglePlan =
        serde_json::from_value(actionable["plan"].clone()).expect("fresh actionable group plan");
    let operation_id = actionable["operationId"]
        .as_str()
        .expect("fresh operation ID");
    let fingerprint = actionable["planFingerprint"]
        .as_str()
        .expect("fresh plan fingerprint");
    let challenge = actionable["challenge"]
        .as_str()
        .expect("fresh approval challenge");
    let expectation = plan
        .approval_expectation(&approval_context)
        .expect("fresh group expectation");
    let artifact = GroupApprovalArtifactStore::new(&context.app_state_root)
        .issue(
            session.clone(),
            &plan,
            challenge,
            ApprovalIssuer::new(
                approval_key.clone(),
                expectation.issuer.clone(),
                expectation.audience.clone(),
            )
            .expect("fresh group approval issuer")
            .issue(ApprovalReceiptClaims {
                version: 1,
                receipt_id: "receipt-group-mcp-apply".to_string(),
                nonce: "nonce-group-mcp-apply".to_string(),
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
            .expect("fresh group approval receipt"),
            &session_key,
            now_unix,
        )
        .expect("approval artifact");

    let applied = call_tool(
        &context,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
        json!({
            "operationId": operation_id,
            "planFingerprint": fingerprint,
            "challenge": challenge,
            "approvalArtifact": artifact.artifact_id,
        }),
    );
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["operation"]["lifecycle"], "applied");
    assert_eq!(applied["operation"]["details"]["groupStatus"], "completed");
    assert_eq!(applied["operation"]["operationId"], operation_id);
    assert!(
        fs::read_to_string(&config_path)
            .expect("updated Codex config")
            .contains("enabled = false")
    );
    for internal_field in [
        "authorizationDecisionDigest",
        "sealedPlan",
        "authenticationKeyId",
        "authenticationTag",
    ] {
        assert!(
            applied["operation"].get(internal_field).is_none(),
            "public operation evidence exposed {internal_field}"
        );
    }
    let replayed = call_tool(
        &context,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
        json!({
            "operationId": operation_id,
            "planFingerprint": fingerprint,
            "challenge": challenge,
            "approvalArtifact": artifact.artifact_id,
        }),
    );
    assert_eq!(
        replayed, applied,
        "an exactly bound consumed artifact must return cached status"
    );

    let retry_artifact = GroupApprovalArtifactStore::new(&context.app_state_root)
        .issue(
            session,
            &plan,
            challenge,
            ApprovalIssuer::new(
                approval_key,
                expectation.issuer.clone(),
                expectation.audience.clone(),
            )
            .expect("retry group approval issuer")
            .issue(ApprovalReceiptClaims {
                version: 1,
                receipt_id: "receipt-group-mcp-retry".to_string(),
                nonce: "nonce-group-mcp-retry".to_string(),
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
            .expect("retry group approval receipt"),
            &session_key,
            now_unix,
        )
        .expect("retry approval artifact");
    for cohort in &plan.cohorts {
        fs::remove_file(
            context
                .app_state_root
                .join("groups")
                .join("operations")
                .join(operation_id)
                .join("cohorts")
                .join(format!("{}.json", cohort.cohort_id)),
        )
        .expect("remove cohort evidence to exercise recovery");
    }
    let backup_id = applied["operation"]["details"]["result"]["backupIds"][0]
        .as_str()
        .expect("applied backup ID");
    fs::remove_file(
        context
            .app_state_root
            .join("backups")
            .join(backup_id)
            .join("manifest.json"),
    )
    .expect("remove backup manifest to exercise structured apply failure");
    let failed_retry = call_tool(
        &context,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
        json!({
            "operationId": operation_id,
            "planFingerprint": fingerprint,
            "challenge": challenge,
            "approvalArtifact": retry_artifact.artifact_id,
        }),
    );
    assert_eq!(failed_retry["status"], "recovery-required");
    assert_eq!(failed_retry["operation"]["lifecycle"], "recovery-required");
    assert_eq!(
        failed_retry["operation"]["details"]["groupStatus"],
        "recovery-required"
    );
    assert!(
        failed_retry["operation"]["details"]["result"]["members"]
            .as_array()
            .expect("recovery members")
            .iter()
            .any(|member| {
                member["status"] == "failed" && member["failureMode"] == "recovery-required"
            })
    );
    assert!(
        !failed_retry
            .to_string()
            .contains(root.to_string_lossy().as_ref()),
        "structured group apply error exposed a private path"
    );

    let replay = call_tool(
        &context,
        UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME,
        json!({
            "operationId": operation_id,
            "planFingerprint": fingerprint,
            "challenge": challenge,
            "approvalArtifact": artifact.artifact_id,
        }),
    );
    assert_eq!(replay["status"], "recovery-required");
    assert_eq!(replay["operation"]["lifecycle"], "recovery-required");
}

#[test]
fn inventory_group_mcp_storage_errors_do_not_expose_private_paths() {
    let temp = TempDir::new().expect("temporary group MCP error root");
    let root = fs::canonicalize(temp.path()).expect("canonical group MCP error root");
    let fixture_root = root.join("fixtures");
    let app_state_root = root.join("private-state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(app_state_root.join("groups")).expect("group state directory");
    fs::write(app_state_root.join("groups/groups.json"), b"{not-json")
        .expect("malformed personal group state");
    let context = context_with_roots(&fixture_root, &app_state_root);

    let error = call_tool_error(&context, "unpin_list_inventory_groups", json!({}));

    assert_eq!(error, "inventory group storage is unavailable");
    assert!(
        !error.contains(root.to_string_lossy().as_ref()),
        "JSON-RPC group error exposed a private path"
    );
}

#[test]
fn inventory_group_mcp_ambiguity_returns_structured_qualified_candidates() {
    let temp = TempDir::new().expect("temporary group ambiguity root");
    let root = fs::canonicalize(temp.path()).expect("canonical group ambiguity root");
    let fixture_root = root.join("fixtures");
    let app_state_root = root.join("state");
    let project_root = root.join("project");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(&app_state_root).expect("app state");
    fs::create_dir_all(project_root.join(".git")).expect("project repository");
    let mut context = context_with_roots(&fixture_root, &app_state_root);
    context.project_root = project_root;
    let access = GroupAccessContext::from_runtime(
        &context.app_state_root,
        &context.project_root,
        &context.discovery_roots,
        None,
        None,
    )
    .expect("group access");
    let member = discover_all(&context.discovery_roots)
        .expect("fixture discovery")
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("member identity")
        .expect("fixture member");
    let definition = GroupDefinitionV1::new("collision", vec![member]).expect("group definition");
    let backup_key = context
        .backup_authentication_key
        .clone()
        .expect("backup authentication");
    PersonalGroupStore::new(access.clone())
        .with_history_authentication_key(backup_key.clone())
        .create(
            &definition,
            OwnerGeneration::new("mcp-ambiguity-personal", 1).expect("personal owner"),
        )
        .expect("personal group");
    RepositoryGroupStore::new(access)
        .with_history_authentication_key(backup_key)
        .create(
            &definition,
            OwnerGeneration::new("mcp-ambiguity-repository", 1).expect("repository owner"),
        )
        .expect("repository group");

    for response in [
        call_tool(
            &context,
            "unpin_get_inventory_group",
            json!({"group": "collision"}),
        ),
        call_tool(
            &context,
            "unpin_plan_inventory_group",
            json!({
                "group": "collision",
                "targetEnabled": false,
                "maxMembers": 10,
                "providerReach": "all",
            }),
        ),
    ] {
        assert_eq!(response["status"], "ambiguous");
        assert_eq!(response["error"]["code"], "group-reference-ambiguous");
        assert_eq!(
            response["error"]["candidates"],
            json!(["personal:collision", "repository:collision"])
        );
    }
}

#[test]
fn provider_scoped_mcp_redacts_mixed_provider_groups_and_plans_subset() {
    let temp = TempDir::new().expect("temporary provider-scoped group root");
    let root = fs::canonicalize(temp.path()).expect("canonical provider-scoped group root");
    let fixture_root = root.join("fixtures");
    let app_state_root = root.join("state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(&app_state_root).expect("app state");

    let mut context = context_with_roots(&fixture_root, &app_state_root);
    context.project_root = fixture_root.join("codex/project");
    let access = GroupAccessContext::from_runtime(
        &context.app_state_root,
        &context.project_root,
        &context.discovery_roots,
        None,
        None,
    )
    .expect("unscoped group access");
    let discovered = discover_all(&context.discovery_roots).expect("discovery");
    let member_for = |provider| {
        discovered
            .items
            .iter()
            .filter(|item| item.provider == provider && item.layer == DiscoveryLayer::Global)
            .find_map(|item| GroupMemberIdentity::try_from(item).ok())
            .unwrap_or_else(|| panic!("{provider:?} group member"))
    };
    PersonalGroupStore::new(access)
        .create(
            &GroupDefinitionV1::new(
                "mixed-providers",
                vec![
                    member_for(ProviderId::Codex),
                    member_for(ProviderId::Claude),
                ],
            )
            .expect("mixed-provider group"),
            OwnerGeneration::new("group-mcp-provider-test", 1).expect("owner"),
        )
        .expect("create mixed-provider group");

    context.provider_scope = McpProviderScope::Provider(ProviderId::Codex);
    context.discovery_cache.invalidate();
    let listed = call_tool(&context, "unpin_list_inventory_groups", json!({}));
    assert_eq!(listed["status"], "ok");
    let group = listed["groups"]
        .as_array()
        .expect("group list")
        .iter()
        .find(|group| group["qualifiedName"] == "personal:mixed-providers")
        .expect("mixed-provider group");
    assert_eq!(group["contextCompatible"], true);
    assert_eq!(
        group["members"].as_array().expect("scoped members").len(),
        1
    );
    assert_eq!(group["members"][0]["identity"]["provider"], json!("codex"));
    assert_eq!(
        group["counts"]
            .as_object()
            .expect("scoped counts")
            .values()
            .map(|count| count.as_u64().expect("count"))
            .sum::<u64>(),
        1,
        "aggregate state must not include excluded-provider members"
    );
    assert_eq!(group["providerCoverage"], json!(["codex"]));

    let shown = call_tool(
        &context,
        "unpin_get_inventory_group",
        json!({"group": "personal:mixed-providers"}),
    );
    assert_eq!(shown["status"], "ok");
    assert_eq!(
        shown["group"]["members"]
            .as_array()
            .expect("scoped members")
            .len(),
        1
    );
    assert_eq!(
        shown["group"]["counts"]
            .as_object()
            .expect("scoped counts")
            .values()
            .map(|count| count.as_u64().expect("count"))
            .sum::<u64>(),
        1,
        "detail state must not include excluded-provider members"
    );
    assert_eq!(shown["group"]["providerCoverage"], json!(["codex"]));
    let plan = call_tool(
        &context,
        "unpin_plan_inventory_group",
        json!({
            "group": "personal:mixed-providers",
            "targetEnabled": false,
            "maxMembers": 10,
            "providerReach": {
                "mode": "selected",
                "provider": "codex"
            }
        }),
    );
    assert_ne!(plan["status"], "blocked");
    assert_eq!(
        plan["plan"]["providerReach"]["selected"]["provider"],
        "codex"
    );
    assert_eq!(
        plan["plan"]["members"]
            .as_array()
            .expect("scoped plan members")
            .len(),
        1
    );
    let encoded = serde_json::to_string(&plan).expect("scoped plan JSON");
    assert!(
        !encoded.contains("claude:"),
        "excluded identity leaked: {encoded}"
    );
    assert!(!app_state_root.join("backups").exists());
}

#[test]
fn inventory_reports_redacted_authentication_readiness_without_enabling_mcp_writes() {
    let context = context();
    let summary = call_tool(&context, "unpin_get_inventory_summary", json!({}));

    assert_eq!(summary["writeSafety"]["backupAuthentication"], "ready");
    assert_eq!(
        summary["writeSafety"]["backupAuthenticationDetails"]["keyId"],
        context
            .backup_authentication_key
            .as_ref()
            .expect("backup key")
            .key_id()
    );
    assert_eq!(
        summary["writeSafety"]["approvalSigning"],
        json!({"status": "ready", "keyId": "approval-test-key"})
    );
    assert_eq!(
        summary["writeSafety"]["cursorDashboard"],
        json!({"status": "missing"})
    );
    assert_eq!(summary["writeSafety"]["writesEnabled"], false);
    assert_eq!(
        summary["writeSafety"]["humanApproval"],
        "cli-or-tui-required"
    );
}

#[test]
fn bulk_apply_requires_fingerprint_and_max_items_but_not_boolean_confirmation() {
    let selector = json!({
        "selector": {
            "providers": ["claude"],
            "kinds": ["plugin"],
            "ids": ["claude:global:tool:settings:safe-shell"]
        },
        "targetEnabled": false,
        "providerReach": {
            "mode": "selected",
            "provider": "claude"
        }
    });

    let unconfirmed = call_tool(&context(), "unpin_apply_toggle_items", selector.clone());
    assert_eq!(unconfirmed["status"], "blocked");
    assert_eq!(
        unconfirmed["reason"],
        "missing required field: planFingerprint"
    );

    let mut no_fingerprint = selector.as_object().expect("selector object").clone();
    no_fingerprint.insert("requireConfirmation".to_string(), json!(true));
    let no_fingerprint = call_tool(
        &context(),
        "unpin_apply_toggle_items",
        serde_json::Value::Object(no_fingerprint),
    );
    assert_eq!(no_fingerprint["status"], "blocked");
    assert_eq!(
        no_fingerprint["reason"],
        "missing required field: planFingerprint"
    );

    let mut no_max = selector.as_object().expect("selector object").clone();
    no_max.insert("requireConfirmation".to_string(), json!(true));
    no_max.insert("planFingerprint".to_string(), json!("sha256:not-reviewed"));
    let no_max = call_tool(
        &context(),
        "unpin_apply_toggle_items",
        serde_json::Value::Object(no_max),
    );
    assert_eq!(no_max["status"], "blocked");
    assert_eq!(no_max["reason"], "missing required field: maxItems");

    let planned = call_tool(&context(), "unpin_plan_toggle_items", selector.clone());
    let mut too_many = selector.as_object().expect("selector object").clone();
    too_many.insert("requireConfirmation".to_string(), json!(true));
    too_many.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    too_many.insert("maxItems".to_string(), json!(0));
    let too_many = call_tool(
        &context(),
        "unpin_apply_toggle_items",
        serde_json::Value::Object(too_many),
    );
    assert_eq!(too_many["status"], "blocked");
    assert_eq!(too_many["reason"], "max-items-exceeded");
    assert_eq!(too_many["maxItems"], 0);
    assert_eq!(too_many["actionableCount"], 1);
    assert_eq!(too_many["planFingerprint"], planned["planFingerprint"]);
    assert!(too_many.get("writes").is_none());
}

#[test]
fn bulk_plan_blocks_empty_selection_unless_explicitly_allowed() {
    let blocked = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "ids": ["missing-item"]
            },
            "targetEnabled": false,
            "providerReach": "all"
        }),
    );

    assert_eq!(blocked["status"], "blocked");
    assert_eq!(blocked["reason"], "empty-selection");

    let allowed = call_tool(
        &context(),
        "unpin_plan_toggle_items",
        json!({
            "selector": {
                "ids": ["missing-item"]
            },
            "targetEnabled": false,
            "providerReach": "all",
            "allowEmptySelection": true
        }),
    );

    assert_eq!(allowed["status"], "no-op");
    assert_eq!(
        allowed["matched"].as_array().expect("matched items").len(),
        0
    );
    assert!(
        allowed["planFingerprint"]
            .as_str()
            .expect("plan fingerprint")
            .starts_with("sha256:")
    );
    assert!(allowed.get("writes").is_none());

    let allowed_apply = call_tool(
        &context(),
        "unpin_apply_toggle_items",
        json!({
            "selector": {
                "ids": ["missing-item"]
            },
            "targetEnabled": false,
            "providerReach": "all",
            "allowEmptySelection": true,
            "requireConfirmation": true,
            "planFingerprint": allowed["planFingerprint"],
            "maxItems": 0
        }),
    );

    assert_eq!(allowed_apply["status"], "no-op");
    assert_eq!(allowed_apply["actionableCount"], 0);
    assert_eq!(allowed_apply["planFingerprint"], allowed["planFingerprint"]);
    assert!(allowed_apply.get("writes").is_none());
}

#[test]
fn bulk_apply_blocks_fingerprint_mismatch_without_writes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("settings.json");
    assert!(settings_plugin_enabled(&settings_path, "safe-shell"));

    let result = call_tool(
        &context,
        "unpin_apply_toggle_items",
        json!({
            "selector": {
                "providers": ["claude"],
                "kinds": ["plugin"],
                "ids": ["claude:global:tool:settings:safe-shell"]
            },
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "claude"
            },
            "requireConfirmation": true,
            "planFingerprint": "sha256:mismatch",
            "maxItems": 1
        }),
    );

    assert_eq!(result["status"], "blocked");
    assert_eq!(result["reasonCode"], "plan-fingerprint-mismatch");
    assert!(
        result["message"]
            .as_str()
            .expect("mismatch message")
            .contains("Re-run")
    );
    assert!(
        result["currentPlanFingerprint"]
            .as_str()
            .expect("current fingerprint")
            .starts_with("sha256:")
    );
    assert_eq!(result["planFingerprint"], "sha256:mismatch");
    assert!(result.get("providedPlanFingerprint").is_none());
    assert!(result.get("writes").is_none());
    assert!(settings_plugin_enabled(&settings_path, "safe-shell"));
    assert!(
        !app_state.path().join("backups").exists(),
        "mismatched fingerprint should not create backups"
    );
}

#[test]
fn bulk_apply_with_matching_fingerprint_returns_handoff_without_writes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let settings_path = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("settings.json");
    assert!(settings_plugin_enabled(&settings_path, "safe-shell"));

    let request = json!({
        "selector": {
            "providers": ["claude"],
            "kinds": ["plugin"],
            "ids": ["claude:global:tool:settings:safe-shell"]
        },
        "targetEnabled": false,
        "providerReach": {
            "mode": "selected",
            "provider": "claude"
        }
    });
    let planned = call_tool(&context, "unpin_plan_toggle_items", request.clone());
    let operation_id = planned["operationId"]
        .as_str()
        .expect("operation id")
        .to_string();
    let fingerprint = planned["planFingerprint"]
        .as_str()
        .expect("plan fingerprint")
        .to_string();

    let mut apply_request = request.as_object().expect("request object").clone();
    apply_request.insert("requireConfirmation".to_string(), json!(true));
    apply_request.insert("planFingerprint".to_string(), json!(fingerprint.clone()));
    apply_request.insert("maxItems".to_string(), json!(1));
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_items",
        serde_json::Value::Object(apply_request),
    );

    assert_eq!(applied["status"], "human-action-required");
    assert_eq!(applied["schemaVersion"], 2);
    assert_eq!(applied["operationId"], operation_id);
    assert_eq!(applied["planFingerprint"], fingerprint);
    assert_eq!(applied["handoff"]["operationId"], operation_id);
    assert_eq!(applied["handoff"]["planFingerprint"], fingerprint);
    assert_eq!(applied["operationV2"]["schemaVersion"], 2);
    assert_eq!(applied["operationV2"]["family"], "bulk-toggle");
    assert_eq!(applied["operationV2"]["operationId"], operation_id);
    assert_eq!(applied["operationV2"]["planFingerprint"], fingerprint);
    assert!(applied["operationV2"].get("roots").is_some());
    assert!(applied["operationV2"].get("principal").is_some());
    assert!(applied["operationV2"].get("payloadReference").is_some());
    assert!(applied["operationV2"].get("authenticationTag").is_some());
    assert!(applied.get("legacyBulkHandoff").is_none());
    let loaded = BulkToggleController::new(&context.app_state_root)
        .load_handoff(&operation_id)
        .expect("MCP handoff is loadable by the CLI controller");
    assert_eq!(loaded.operation_id, operation_id);
    assert_eq!(loaded.plan_fingerprint, fingerprint);

    let status = call_tool(
        &context,
        "unpin_get_control_status",
        json!({"operationId": operation_id}),
    );
    let operations = status["control"]["operations"]
        .as_array()
        .expect("filtered operations");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["operationId"], operation_id);
    assert_eq!(operations[0]["reachAware"]["schemaVersion"], 2);

    let mut pinned = context.clone();
    pinned.provider_scope = McpProviderScope::Provider(ProviderId::Claude);
    let pinned_status = call_tool(
        &pinned,
        "unpin_get_control_status",
        json!({"operationId": operation_id}),
    );
    let pinned_operations = pinned_status["control"]["operations"]
        .as_array()
        .expect("pinned operations");
    assert_eq!(pinned_operations.len(), 1);
    assert!(
        pinned_operations[0]["reachAware"]["providerCoverage"]["entries"]
            .as_array()
            .expect("pinned provider coverage")
            .iter()
            .all(|entry| entry["provider"] == "claude")
    );
    assert!(settings_plugin_enabled(&settings_path, "safe-shell"));
    assert!(!app_state.path().join("backups").exists());
}

#[test]
fn lists_stable_mcp_tool_names() {
    let response = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );

    let names = response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();

    assert_eq!(names, UNPIN_MCP_TOOL_NAMES);
}

#[test]
fn descriptors_use_unpin_branding_for_every_tool() {
    let response = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );

    for tool in response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
    {
        let name = tool["name"].as_str().expect("tool name");
        assert!(name.starts_with("unpin_"), "tool id lacks Unpin brand");
        assert!(
            tool["title"]
                .as_str()
                .expect("tool title")
                .contains("Unpin"),
            "tool title should identify Unpin"
        );
    }
}

#[test]
fn session_launch_descriptor_is_read_only_and_rejects_child_commands_by_schema() {
    let descriptor = tool_descriptor(&context(), "unpin_plan_session_launch");

    assert_eq!(descriptor["annotations"]["readOnlyHint"], true);
    assert_eq!(
        descriptor["inputSchema"]["required"],
        json!(["provider", "exposureRevision", "profile"])
    );
    assert_eq!(descriptor["inputSchema"]["additionalProperties"], false);
    assert!(
        descriptor["inputSchema"]["properties"]
            .get("command")
            .is_none()
    );
    assert_eq!(
        descriptor["inputSchema"]["properties"]["profile"]["oneOf"][2]["required"],
        json!(["type", "profileId", "profileDigest", "definitionDigest"])
    );
}

#[test]
fn profile_proposal_tool_is_read_only_metadata_routing_with_human_handoff() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let context = context_with_roots(fixture_copy.path(), &app_state_root);
    let profile_directory = unpin_core::config::get_workspace_profiles_dir(&context.project_root);
    fs::create_dir_all(&profile_directory).expect("workspace profile directory");
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "review".to_string(),
        display_name: "Peer review".to_string(),
        description: Some("review changes for correctness and security".to_string()),
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    fs::write(
        profile_directory.join("review.json"),
        definition.to_export_json().expect("export profile"),
    )
    .expect("write workspace profile");
    let descriptor = tool_descriptor(&context, "unpin_propose_session_profile");
    assert_eq!(descriptor["annotations"]["readOnlyHint"], true);

    let proposed = call_tool(
        &context,
        "unpin_propose_session_profile",
        json!({
            "prompt": "Please perform peer review with security focus",
            "provider": "codex",
        }),
    );
    assert_eq!(proposed["status"], "proposed");
    assert_eq!(proposed["proposal"]["recommended"]["profileId"], "review");
    assert_eq!(proposed["proposal"]["confirmationRequired"], true);
    assert_eq!(proposed["proposal"]["mutatesState"], false);
    assert_eq!(proposed["humanAction"]["code"], "confirm-session-profile");
    assert!(
        !serde_json::to_string(&proposed)
            .unwrap()
            .contains("Please perform peer review")
    );
    assert!(!app_state_root.join("policies").exists());
}

#[test]
fn session_launch_plan_returns_exact_argv_handoff_without_writes_or_authority() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let context = context_with_roots(fixture_copy.path(), &app_state_root);
    let workspace = resolve_workspace_identity(&context.project_root).expect("workspace identity");
    let exposure_revision = "a".repeat(64);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "review-profile".to_string(),
        display_name: "Review profile".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    let profile_directory = unpin_core::config::get_workspace_profiles_dir(&context.project_root);
    fs::create_dir_all(&profile_directory).expect("workspace profile directory");
    fs::write(
        profile_directory.join("review-profile.json"),
        definition.to_export_json().expect("export profile"),
    )
    .expect("write workspace profile");
    let discovery = discover_all(&context.discovery_roots).expect("fixture discovery");
    let catalog = Catalog::from_discovery(&discovery).expect("fixture catalog");
    let revision = compile_profile(&definition, &catalog, ProfileSourceScope::Workspace)
        .expect("compile workspace profile");
    let profile_digest = revision.digest.clone();
    let definition_digest = revision.origin.definition_digest.clone();
    let lock_snapshot = CapabilityLockSnapshot::empty(ProviderId::Codex);

    let planned = call_tool(
        &context,
        "unpin_plan_session_launch",
        json!({
            "provider": "codex",
            "exposureRevision": exposure_revision,
            "profile": {
                "type": "profile",
                "profileId": "review-profile",
                "profileDigest": profile_digest.clone(),
                "definitionDigest": definition_digest.clone(),
            }
        }),
    );

    assert_eq!(planned["status"], "human-action-required");
    assert_eq!(planned["humanAction"]["code"], "run-session-launch");
    assert_eq!(planned["handoff"]["version"], 1);
    assert_eq!(planned["handoff"]["kind"], "unpin-cli-session-launch");
    assert_eq!(planned["handoff"]["provider"], "codex");
    assert_eq!(
        planned["handoff"]["workspace"],
        json!({
            "projectRoot": workspace.canonical_root,
            "repositoryKey": workspace.repository_key,
            "workspaceKey": workspace.workspace_key,
            "workspaceRevision": workspace.diagnostics.head,
        })
    );
    assert_eq!(
        planned["handoff"]["exposure"],
        json!({
            "revision": "a".repeat(64),
            "profile": {
                "type": "profile",
                "profileId": "review-profile",
                "profileDigest": profile_digest.clone(),
                "originScope": "workspace",
                "definitionDigest": definition_digest.clone(),
            },
            "capabilityLocks": lock_snapshot,
        })
    );
    assert_eq!(
        planned["handoff"]["cli"],
        json!({
            "executable": "unpin",
            "arguments": [
                "session",
                "launch",
                "--project-root",
                workspace.canonical_root.to_string_lossy(),
                "--fixture-root",
                fixture_copy.path().to_string_lossy(),
                "--app-state-root",
                app_state_root.to_string_lossy(),
                "--provider",
                "codex",
                "--exposure-revision",
                "a".repeat(64),
                "--capability-lock-revision",
                lock_snapshot.digest,
                "--profile-id",
                "review-profile",
                "--profile-digest",
                profile_digest,
                "--definition-digest",
                definition_digest,
                "--profile-origin",
                "workspace",
                "--json",
                "--"
            ],
            "appendChildCommandAfterSeparator": true,
        })
    );
    assert_eq!(
        planned["constraints"],
        json!({
            "commandAccepted": false,
            "processSpawned": false,
            "stateWritten": false,
            "approvalMinted": false,
            "authorityExposed": false,
        })
    );
    assert_eq!(
        fs::read_dir(&app_state_root)
            .expect("read app state")
            .count(),
        0,
        "MCP session launch planning must not write runtime state"
    );
    let serialized = serde_json::to_string(&planned).expect("planned handoff serializes");
    for forbidden in [
        "sessionAuthority",
        "bootstrapSecret",
        "ownerSecret",
        "approvalReceipt",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn session_launch_plan_validates_selection_and_never_accepts_command_input() {
    let context = context();
    let revision = "d".repeat(64);
    let command_error = call_tool_error(
        &context,
        "unpin_plan_session_launch",
        json!({
            "provider": "claude",
            "exposureRevision": revision,
            "profile": {"type": "native"},
            "command": ["claude", "--dangerously-skip-permissions"]
        }),
    );
    assert_eq!(
        command_error,
        "unsupported session launch arguments field: command"
    );

    let mixed_selection_error = call_tool_error(
        &context,
        "unpin_plan_session_launch",
        json!({
            "provider": "claude",
            "exposureRevision": "d".repeat(64),
            "profile": {"type": "native", "profileId": "unexpected"}
        }),
    );
    assert_eq!(
        mixed_selection_error,
        "unsupported session launch profile field: profileId"
    );

    let unresolved_profile_error = call_tool_error(
        &context,
        "unpin_plan_session_launch",
        json!({
            "provider": "claude",
            "exposureRevision": "d".repeat(64),
            "profile": {
                "type": "profile",
                "profileId": "missing-session-profile",
                "profileDigest": "e".repeat(64),
                "definitionDigest": "f".repeat(64),
            }
        }),
    );
    assert_eq!(unresolved_profile_error, "profile not found");

    let malformed_digest_error = call_tool_error(
        &context,
        "unpin_plan_session_launch",
        json!({
            "provider": "claude",
            "exposureRevision": "not-a-digest",
            "profile": {"type": "none"}
        }),
    );
    assert!(malformed_digest_error.contains("exposure revision"));
}

#[test]
fn control_mcp_reuses_profile_gateway_and_hook_models_with_human_handoff() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let context = context_with_roots(fixture_copy.path(), &app_state_root);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "mcp-review".to_string(),
        display_name: "MCP review".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    let store = ProfileStore::new(&app_state_root);
    store
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("mcp-control-test", 1).unwrap(),
        )
        .expect("save profile definition");

    let status = call_tool(&context, "unpin_get_control_status", json!({}));
    assert_eq!(status["status"], "ok");
    assert!(status["control"]["catalog"]["total"].as_u64().unwrap() > 0);
    assert_eq!(status["control"]["sessions"], json!([]));

    let hooks = call_tool(&context, "unpin_list_hooks", json!({"provider": "codex"}));
    assert_eq!(hooks["status"], "ok");
    assert!(!hooks["hooks"].as_array().unwrap().is_empty());
    assert!(hooks["hooks"][0].get("sourcePath").is_none());
    assert!(
        hooks["hooks"][0]["handler"]
            .get("actionReference")
            .is_some()
    );
    assert_eq!(hooks["hooks"][0]["storedTrustDecision"], false);

    let gateway_args = json!({
        "action": "install",
        "scope": "workspace",
        "provider": "codex"
    });
    let gateway_plan = call_tool(&context, "unpin_plan_gateway_mode", gateway_args.clone());
    assert_eq!(gateway_plan["status"], "planned");
    assert_eq!(gateway_plan["nativeMcpReferences"], "not-managed");
    assert_eq!(
        gateway_plan["operation"]["details"]["nativeMcpReferences"],
        "not-managed"
    );
    let gateway_fingerprint = gateway_plan["plan"]["planFingerprint"].as_str().unwrap();
    let mut gateway_apply = gateway_args;
    gateway_apply["confirm"] = json!(true);
    gateway_apply["planFingerprint"] = json!(gateway_fingerprint);
    let handoff = call_tool(&context, "unpin_apply_gateway_mode", gateway_apply);
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(
        handoff["operation"]["details"]["nativeMcpReferences"],
        "not-managed"
    );
    assert!(
        handoff["continuation"]
            .as_str()
            .unwrap()
            .contains("MCP cannot mint")
    );

    let profile_args = json!({
        "profileId": "mcp-review",
        "mode": "gateway",
        "scope": "workspace",
        "provider": "codex"
    });
    let profile_plan = call_tool(&context, "unpin_plan_profile_policy", profile_args.clone());
    assert_eq!(profile_plan["status"], "planned");
    let compiled_digest = profile_plan["profile"]["digest"]
        .as_str()
        .expect("compiled profile digest");
    assert!(
        store
            .load_revision(compiled_digest)
            .expect("load compiled revision")
            .is_none(),
        "MCP planning must not require or materialize a compiled revision"
    );
    let profile_fingerprint = profile_plan["plan"]["planFingerprint"].as_str().unwrap();
    let mut profile_apply = profile_args;
    profile_apply["confirm"] = json!(true);
    profile_apply["planFingerprint"] = json!(profile_fingerprint);
    let handoff = call_tool(&context, "unpin_apply_profile_policy", profile_apply);
    assert_eq!(handoff["status"], "human-action-required");

    let lock_args = json!({
        "provider": "codex",
        "capabilityId": "skill.review",
        "state": "hard-disabled"
    });
    let lock_plan = call_tool(&context, "unpin_plan_capability_lock", lock_args.clone());
    assert_eq!(lock_plan["status"], "planned");
    assert_eq!(lock_plan["plan"]["target"]["scope"], "global");
    assert_eq!(lock_plan["plan"]["activation"], "next-session-only");
    let lock_fingerprint = lock_plan["plan"]["planFingerprint"].as_str().unwrap();
    let mut lock_apply = lock_args;
    lock_apply["planFingerprint"] = json!(lock_fingerprint);
    let handoff = call_tool(&context, "unpin_apply_capability_lock", lock_apply);
    assert_eq!(handoff["status"], "human-action-required");
    let lock_status = call_tool(
        &context,
        "unpin_get_capability_locks",
        json!({"provider": "codex"}),
    );
    assert_eq!(lock_status["status"], "ok");
    assert_eq!(lock_status["locks"][0]["provider"], "codex");
    assert_eq!(lock_status["locks"][0]["activation"], "next-session-only");
    assert_eq!(
        lock_status["locks"][0]["digest"].as_str().unwrap().len(),
        64
    );

    let unchanged = call_tool(&context, "unpin_get_control_status", json!({}));
    assert!(unchanged["control"]["policies"]["workspace"].is_null());
    assert!(
        unchanged["control"]["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["mode"].is_null())
    );
}

#[test]
fn discovery_backed_mcp_tools_report_advisory_warnings() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    fs::write(&config_path, "[plugins.incomplete\nenabled = true\n")
        .expect("malformed Codex config");
    let context = context_with_roots(fixture_copy.path(), &app_state_root);

    for (tool, arguments) in [
        ("unpin_get_control_status", json!({})),
        ("unpin_list_catalog", json!({})),
        ("unpin_list_hooks", json!({"provider": "codex"})),
        ("unpin_get_capability_locks", json!({"provider": "codex"})),
    ] {
        let response = call_tool(&context, tool, arguments);
        assert_eq!(response["status"], "ok", "{tool} status");
        assert!(
            response["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|warning| warning["code"] == "invalid-toml-table-header"),
            "{tool} omitted discovery warnings"
        );
    }
}

#[test]
fn catalog_adoption_mcp_plans_exact_transition_and_hands_off_without_writing() {
    let root = TempDir::new().expect("temporary root");
    let root = fs::canonicalize(root.path()).expect("canonical root");
    let fixture_copy = root.join("fixtures");
    let app_state_root = root.join("state");
    fs::create_dir(&app_state_root).expect("app state root");
    copy_dir_all(&fixtures_root(), &fixture_copy);
    let context = context_with_roots(&fixture_copy, &app_state_root);
    let discovery = discover_all(&context.discovery_roots).expect("discovery");
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
    let provider_root = Path::new(&item.source_path)
        .parent()
        .expect("provider skill root");
    let source = PathBuf::from(&item.source_path);
    let arguments = json!({
        "provider": "codex",
        "id": item.id,
        "providerRoot": provider_root,
    });

    let planned = call_tool(&context, "unpin_plan_catalog_adoption", arguments.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["operation"]["operationKind"], "adopt-capability");
    assert_eq!(planned["operation"]["lifecycle"], "planned");
    assert_eq!(planned["operation"]["providerCoverage"], json!(["codex"]));
    assert_eq!(
        planned["planFingerprint"],
        planned["transition"]["effectGraphDigest"]
    );
    assert!(source.exists());
    assert!(!app_state_root.join("catalog").exists());

    let mut reviewed = arguments.as_object().expect("arguments").clone();
    reviewed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    reviewed.insert("confirm".to_string(), json!(true));
    let handoff = call_tool(
        &context,
        "unpin_apply_catalog_adoption",
        serde_json::Value::Object(reviewed),
    );
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(handoff["operation"]["lifecycle"], "awaiting-human-action");
    assert_eq!(handoff["planFingerprint"], planned["planFingerprint"]);
    assert!(source.exists());
    assert!(!app_state_root.join("catalog").exists());
}

#[test]
fn hook_trust_mcp_hands_off_and_list_hooks_reports_profile_bound_decision() {
    let root = TempDir::new().expect("temporary root");
    let root = fs::canonicalize(root.path()).expect("canonical root");
    let fixture_copy = root.join("fixtures");
    let app_state_root = root.join("state");
    fs::create_dir(&app_state_root).expect("app state root");
    copy_dir_all(&fixtures_root(), &fixture_copy);
    let context = context_with_roots(&fixture_copy, &app_state_root);
    let discovery = discover_all(&context.discovery_roots).expect("discovery");
    let catalog = Catalog::from_discovery(&discovery).expect("catalog");
    let hook = discovery
        .items
        .iter()
        .find(|item| item.provider == ProviderId::Codex && item.kind == DiscoveryKind::Hook)
        .expect("discovered Codex hook");
    let hook_id = hook.id.clone();
    let capability_id = catalog
        .find_provider_view(ProviderId::Codex, &hook_id)
        .expect("Codex hook capability")
        .id
        .clone();
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "mcp-hook-review".to_string(),
        display_name: "MCP hook review".to_string(),
        description: None,
        members: vec![capability_id.clone()],
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: std::collections::BTreeSet::new(),
    };
    let revision = compile_profile(&definition, &catalog, ProfileSourceScope::Global)
        .expect("compile hook profile");
    assert!(
        revision.selects(&capability_id, ProviderId::Codex),
        "compiled hook profile should select {capability_id}: {revision:#?}"
    );
    ProfileStore::new(&app_state_root)
        .materialize_revision(
            &revision,
            OwnerGeneration::new("mcp-hook-trust-test", 1).unwrap(),
        )
        .expect("materialize hook profile");
    let arguments = json!({
        "provider": "codex",
        "id": hook_id,
        "profileDigest": revision.digest,
        "sessionId": "profile-policy",
    });

    let planned = call_tool(&context, "unpin_plan_hook_trust", arguments.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["activation"], "next-session-only");
    assert_eq!(planned["operation"]["operationKind"], "hook-trust");
    assert_eq!(planned["operation"]["lifecycle"], "planned");
    let operation_id = planned["expectation"]["operationId"]
        .as_str()
        .expect("hook trust operation id");
    assert!(
        HookTrustStore::new(&app_state_root)
            .load(operation_id)
            .expect("load trust record")
            .is_none()
    );

    let mut reviewed = arguments.as_object().expect("arguments").clone();
    reviewed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    reviewed.insert("confirm".to_string(), json!(true));
    let handoff = call_tool(
        &context,
        "unpin_apply_hook_trust",
        serde_json::Value::Object(reviewed),
    );
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(handoff["operation"]["lifecycle"], "awaiting-human-action");
    assert_eq!(handoff["planFingerprint"], planned["planFingerprint"]);
    assert!(
        HookTrustStore::new(&app_state_root)
            .load(operation_id)
            .expect("load trust record")
            .is_none()
    );

    let metadata = hook.hook.as_ref().expect("hook metadata");
    let identity = resolve_workspace_identity(&context.project_root).expect("workspace identity");
    let expectation = metadata
        .trust_approval_expectation(
            ProviderId::Codex,
            &hook_id,
            &revision.digest,
            "unpin-cli-human",
            "unpin-core-hook-trust",
            &identity.repository_key,
            &identity.workspace_key,
            "profile-policy",
        )
        .expect("hook trust expectation");
    let key = ApprovalKey::new([0x24; 32]);
    let receipt = ApprovalIssuer::new(
        key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer")
    .issue(ApprovalReceiptClaims {
        version: 1,
        receipt_id: "mcp-hook-list-receipt".to_string(),
        nonce: "mcp-hook-list-nonce".to_string(),
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
        issued_at_unix: 1_000,
        expires_at_unix: 1_600,
    })
    .expect("approval receipt");
    HookTrustStore::new(&app_state_root)
        .record(
            ProviderId::Codex,
            &hook_id,
            metadata,
            &revision.digest,
            &receipt,
            &ApprovalVerifier::new(key),
            1_100,
            OwnerGeneration::new("mcp-hook-list-test", 1).unwrap(),
            "unpin-cli-human",
            "unpin-core-hook-trust",
            &identity.repository_key,
            &identity.workspace_key,
            "profile-policy",
        )
        .expect("store hook trust decision");

    let listed = call_tool(
        &context,
        "unpin_list_hooks",
        json!({"provider": "codex", "profileDigest": revision.digest}),
    );
    let listed_hook = listed["hooks"]
        .as_array()
        .expect("listed hooks")
        .iter()
        .find(|item| item["id"] == hook_id)
        .expect("listed trusted hook");
    assert_eq!(listed_hook["storedTrustDecision"], true);
    assert!(listed_hook.get("storedTrustReceipt").is_none());
    assert!(listed_hook.get("approval").is_none());
    assert!(listed_hook.get("trustReceipt").is_none());

    let trust_state = AtomicJsonStore::new(get_hook_trust_path(&app_state_root, operation_id), 1);
    let mut stale = trust_state
        .load::<HookTrustRecord>()
        .expect("load trust state")
        .expect("stored trust state");
    stale.value.handler_fingerprint = "stale-handler-fingerprint".to_string();
    trust_state
        .compare_and_swap(
            Some(&stale.revision),
            OwnerGeneration::new("mcp-hook-list-test", 2).unwrap(),
            &stale.value,
        )
        .expect("replace trust state with stale fingerprint");
    let stale_list = call_tool(
        &context,
        "unpin_list_hooks",
        json!({"provider": "codex", "profileDigest": revision.digest}),
    );
    assert_eq!(
        stale_list["hooks"]
            .as_array()
            .expect("stale listed hooks")
            .iter()
            .find(|item| item["id"] == hook_id)
            .expect("stale listed hook")["storedTrustDecision"],
        false,
        "stored trust must be ignored when handler fingerprint drifts"
    );

    let unscoped = call_tool(&context, "unpin_list_hooks", json!({"provider": "codex"}));
    assert_eq!(
        unscoped["hooks"]
            .as_array()
            .expect("unscoped hooks")
            .iter()
            .find(|item| item["id"] == hook_id)
            .expect("unscoped trusted hook")["storedTrustDecision"],
        false
    );

    let unselected = call_tool_error(
        &context,
        "unpin_plan_hook_trust",
        json!({
            "provider": "claude",
            "id": discovery.items.iter().find(|item| item.provider == ProviderId::Claude && item.kind == DiscoveryKind::Hook).expect("Claude hook").id,
            "profileDigest": revision.digest,
        }),
    );
    assert!(unselected.contains("hook is not selected by compiled profile"));
}

#[test]
fn control_descriptors_accept_profile_ids_and_profile_bound_hook_listing() {
    let context = context();

    let profile_plan = tool_descriptor(&context, "unpin_plan_profile_policy");
    assert_eq!(
        required_input_fields(&profile_plan),
        vec!["profileId", "mode"]
    );
    assert!(
        profile_plan["inputSchema"]["properties"]
            .get("profileId")
            .is_some()
    );
    assert!(
        profile_plan["inputSchema"]["properties"]
            .get("profileDigest")
            .is_none()
    );

    let profile_apply = tool_descriptor(&context, "unpin_apply_profile_policy");
    assert_eq!(
        required_input_fields(&profile_apply),
        vec!["profileId", "mode", "planFingerprint"]
    );

    let hooks = tool_descriptor(&context, "unpin_list_hooks");
    assert!(
        hooks["inputSchema"]["properties"]
            .get("profileDigest")
            .is_some()
    );
}

#[test]
fn profile_provider_mcp_schema_and_reach_authority_are_bound() {
    let context = context();
    let plan = tool_descriptor(&context, "unpin_plan_profile_provider");
    assert_eq!(
        required_input_fields(&plan),
        vec!["profileId", "mode", "providerReach"]
    );
    assert_eq!(plan["annotations"]["readOnlyHint"], true);
    assert_eq!(
        tool_descriptor(&context, "unpin_apply_profile_provider")["inputSchema"]["required"],
        json!([
            "profileId",
            "mode",
            "providerReach",
            "operationId",
            "planFingerprint"
        ])
    );

    let pinned = context_for_provider(ProviderId::Codex);
    let pinned_plan = tool_descriptor(&pinned, "unpin_plan_profile_provider");
    assert_eq!(
        pinned_plan["inputSchema"]["properties"]["providerReach"]["oneOf"][1]["required"],
        json!(["mode"]),
        "a pinned connection supplies selected-provider authority"
    );
}

#[test]
fn profile_provider_mcp_rejects_unbound_or_widened_reach() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), &app_state_root);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "mcp-provider-reach".to_string(),
        display_name: "MCP provider reach".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: [ProviderId::Codex].into_iter().collect(),
    };
    ProfileStore::new(&context.app_state_root)
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("mcp-profile-provider-reach", 1).expect("owner"),
        )
        .expect("save profile");

    let omitted = call_tool_error(
        &context,
        "unpin_plan_profile_provider",
        json!({"profileId": definition.id, "mode": "native"}),
    );
    assert!(omitted.contains("selected provider"), "{omitted}");

    let mut pinned = context_with_roots(fixture_copy.path(), &app_state_root);
    pinned.provider_scope = McpProviderScope::Provider(ProviderId::Codex);
    let widened = call_tool_error(
        &pinned,
        "unpin_plan_profile_provider",
        json!({
            "profileId": "mcp-provider-reach",
            "mode": "native",
            "providerReach": "all"
        }),
    );
    assert!(widened.contains("widen"), "{widened}");

    let conflicting = call_tool_error(
        &pinned,
        "unpin_plan_profile_provider",
        json!({
            "profileId": "mcp-provider-reach",
            "mode": "native",
            "providerReach": {"mode": "selected", "provider": "claude"}
        }),
    );
    assert!(conflicting.contains("conflicts with"), "{conflicting}");
}

#[test]
fn profile_provider_mcp_handoff_binds_operation_and_fingerprint() {
    let fixture_copy = TempDir::new().expect("fixture copy");
    let app_state = TempDir::new().expect("app state");
    let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), &app_state_root);
    let definition = ProfileDefinition {
        version: PROFILE_DEFINITION_VERSION,
        id: "mcp-profile-provider".to_string(),
        display_name: "MCP profile provider".to_string(),
        description: None,
        members: Vec::new(),
        provider_members: std::collections::BTreeMap::new(),
        supported_providers: [ProviderId::Claude, ProviderId::Codex]
            .into_iter()
            .collect(),
    };
    ProfileStore::new(&context.app_state_root)
        .save_global_definition(
            &definition,
            None,
            OwnerGeneration::new("mcp-profile-provider", 1).expect("owner"),
        )
        .expect("save profile");

    let arguments = json!({
        "profileId": definition.id,
        "mode": "gateway",
        "scope": "global",
        "providerReach": "all"
    });
    let planned = call_tool(&context, "unpin_plan_profile_provider", arguments.clone());
    assert_eq!(planned["schemaVersion"], 2);
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["operation"]["schemaVersion"], 2);
    assert_eq!(planned["operation"]["operationKind"], "apply-profile");
    assert_eq!(
        planned["operation"]["providerReach"],
        planned["providerReach"]
    );
    assert_eq!(
        planned["operation"]["providerCoverage"],
        planned["providerCoverage"]
    );
    assert_eq!(planned["plan"]["coverage"], planned["providerCoverage"]);
    let targets = planned["targets"].as_array().expect("targets");
    assert_eq!(targets.len(), 2);
    assert!(targets.iter().all(|target| {
        target["localPresence"].is_string()
            && target["genericProfileInheritedBefore"].is_boolean()
            && target["genericPolicyEffect"].is_string()
            && target["futureActivation"].is_boolean()
    }));
    let operation_id = planned["operationId"].as_str().expect("operation id");
    let fingerprint = planned["planFingerprint"].as_str().expect("fingerprint");
    assert_eq!(operation_id, format!("profile-provider-{fingerprint}"));

    let mut wrong_operation = arguments.as_object().expect("arguments").clone();
    wrong_operation.insert("operationId".to_string(), json!("profile-provider-wrong"));
    wrong_operation.insert("planFingerprint".to_string(), json!(fingerprint));
    let error = call_tool_error(
        &context,
        "unpin_apply_profile_provider",
        serde_json::Value::Object(wrong_operation),
    );
    assert!(error.contains("operation id does not match"), "{error}");

    let mut apply = arguments.as_object().expect("arguments").clone();
    apply.insert("operationId".to_string(), json!(operation_id));
    apply.insert("planFingerprint".to_string(), json!(fingerprint));
    let handoff = call_tool(
        &context,
        "unpin_apply_profile_provider",
        serde_json::Value::Object(apply),
    );
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(handoff["operationId"], operation_id);
    assert_eq!(handoff["planFingerprint"], fingerprint);
    assert_eq!(handoff["operation"]["operationId"], operation_id);
    assert_eq!(handoff["operation"]["planFingerprint"], fingerprint);
    assert_eq!(handoff["operation"]["expectedLifecycle"], "applied");
    assert!(!app_state.path().join("policies").exists());
}

#[test]
fn control_status_operation_id_is_optional_and_non_disclosing_without_journal() {
    let context = context();
    let ordinary = call_tool(&context, "unpin_get_control_status", json!({}));
    assert_eq!(ordinary["status"], "ok");
    let filtered = call_tool(
        &context,
        "unpin_get_control_status",
        json!({"operationId": "missing-operation"}),
    );
    assert_eq!(filtered["status"], "ok");
    assert!(
        filtered["control"]["operations"]
            .as_array()
            .expect("operations")
            .is_empty()
    );
    let error = call_tool_error(
        &context,
        "unpin_get_control_status",
        json!({"operationId": ""}),
    );
    assert!(error.contains("non-empty string"), "{error}");
}

#[test]
fn bulk_apply_descriptor_requires_review_fields() {
    let context = context();

    let plan = tool_descriptor(&context, "unpin_plan_toggle_items");
    assert_eq!(required_input_fields(&plan), vec!["targetEnabled"]);

    let apply = tool_descriptor(&context, "unpin_apply_toggle_items");
    assert_eq!(
        required_input_fields(&apply),
        vec!["targetEnabled", "planFingerprint", "maxItems"]
    );

    let properties = apply["inputSchema"]["properties"]
        .as_object()
        .expect("bulk apply properties");
    for field in [
        "selector",
        "targetEnabled",
        "requireConfirmation",
        "confirm",
        "planFingerprint",
        "maxItems",
        "allowEmptySelection",
    ] {
        assert!(
            properties.contains_key(field),
            "bulk apply schema should include property {field}"
        );
    }
}

#[test]
fn descriptors_constrain_known_input_values() {
    let context = context();
    let provider_ids = ProviderId::ALL.map(ProviderId::as_str);

    let summary = tool_descriptor(&context, "unpin_get_inventory_summary");
    let summary_properties = summary["inputSchema"]["properties"]
        .as_object()
        .expect("summary properties");
    assert_eq!(
        summary_properties["providers"]["items"]["enum"],
        json!(provider_ids)
    );
    assert_eq!(
        summary_properties["layers"]["items"]["enum"],
        json!(["global", "project"])
    );

    let single = tool_descriptor(&context, "unpin_plan_toggle_item");
    let single_properties = single["inputSchema"]["properties"]
        .as_object()
        .expect("single toggle properties");
    assert_eq!(single_properties["provider"]["enum"], json!(provider_ids));
    assert_eq!(
        single_properties["kind"]["enum"],
        json!(["skill", "mcp", "plugin", "agent", "hook", "setting"])
    );
    assert_eq!(
        single_properties["layer"]["enum"],
        json!(["global", "project"])
    );
    assert_eq!(single_properties["id"]["minLength"], 1);

    let list = tool_descriptor(&context, "unpin_list_items");
    let selector_properties = list["inputSchema"]["properties"]["selector"]["properties"]
        .as_object()
        .expect("selector properties");
    assert_eq!(
        selector_properties["providers"]["items"]["enum"],
        json!(provider_ids)
    );
    assert_eq!(
        selector_properties["kinds"]["items"]["enum"],
        json!(["skill", "mcp", "plugin", "agent", "hook", "setting"])
    );
    assert_eq!(
        selector_properties["categories"]["items"]["enum"],
        json!([
            "skill",
            "configured-mcp",
            "tool",
            "agent",
            "hook",
            "provider-setting",
            "plugin-config",
            "plugin-manifest"
        ])
    );
    assert_eq!(
        selector_properties["layers"]["items"]["enum"],
        json!(["global", "project"])
    );
    assert_eq!(selector_properties["ids"]["items"]["minLength"], 1);
    assert_eq!(
        list["inputSchema"]["properties"]["limit"]["type"],
        "integer"
    );
    assert_eq!(list["inputSchema"]["properties"]["limit"]["minimum"], 1);

    let backups = tool_descriptor(&context, "unpin_list_backups");
    assert_eq!(
        backups["inputSchema"]["properties"]["limit"]["type"],
        "integer"
    );
    assert_eq!(backups["inputSchema"]["properties"]["limit"]["minimum"], 1);

    let restore = tool_descriptor(&context, "unpin_restore_backup");
    assert_eq!(
        restore["inputSchema"]["properties"]["backupId"]["minLength"],
        1
    );
    assert_eq!(
        restore["inputSchema"]["properties"]["requireConfirmation"]["type"],
        "boolean"
    );
    assert_eq!(
        restore["inputSchema"]["properties"]["confirm"]["type"],
        "boolean"
    );
}

#[test]
fn descriptors_include_safety_annotations() {
    let context = context();

    for name in [
        "unpin_get_inventory_summary",
        "unpin_list_items",
        "unpin_plan_toggle_item",
        "unpin_plan_toggle_items",
        "unpin_apply_toggle_item",
        "unpin_apply_toggle_items",
        "unpin_list_backups",
        "unpin_restore_backup",
        "unpin_run_doctor",
    ] {
        let descriptor = tool_descriptor(&context, name);
        assert_eq!(
            descriptor["annotations"],
            json!({ "readOnlyHint": true }),
            "{name} should be annotated as read-only"
        );
    }
}

#[test]
fn returns_filtered_list_items_structured_content() {
    let response = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": "list-items",
            "method": "tools/call",
            "params": {
                "name": "unpin_list_items",
                "arguments": {
                    "selector": {
                        "providers": ["claude"],
                        "layers": ["project"]
                    }
                }
            }
        }),
    );

    assert_eq!(response["id"], "list-items");
    assert_eq!(response["result"]["structuredContent"]["status"], "ok");
    let items = response["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    assert!(items.iter().any(|item| {
        item["id"] == "claude:project:skill:example-claude-skill"
            && item["provider"] == "claude"
            && item["layer"] == "project"
    }));
    assert!(items.iter().all(|item| item["provider"] == "claude"));
    assert!(items.iter().any(|item| {
        item["id"] == "claude:project:agent:claude-project-helper"
            && item["kind"] == "agent"
            && item["mutability"] == "read-write"
    }));
}

#[test]
fn mcp_list_items_returns_total_matched_and_honors_limit() {
    let listed = call_tool(
        &context(),
        "unpin_list_items",
        json!({
            "selector": {
                "categories": ["skill"]
            },
            "limit": 2
        }),
    );

    assert_eq!(listed["status"], "ok");
    assert_eq!(listed["selector"], json!({ "categories": ["skill"] }));
    assert!(listed["totalMatched"].as_u64().expect("totalMatched count") > 2);
    assert_eq!(listed["items"].as_array().expect("items").len(), 2);
    assert!(
        listed["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["category"] == "skill")
    );
    assert!(listed["warnings"].as_array().expect("warnings").is_empty());
}

#[test]
fn mcp_inventory_summary_returns_project_root_and_honors_filters() {
    let summarized = call_tool(
        &context(),
        "unpin_get_inventory_summary",
        json!({
            "providers": ["cursor"],
            "layers": ["global"]
        }),
    );

    assert_eq!(summarized["status"], "ok");
    assert_eq!(
        summarized["projectRoot"],
        fixtures_root()
            .join("cursor")
            .join("project")
            .to_string_lossy()
            .as_ref()
    );
    let providers = summarized["inventory"]["providers"]
        .as_array()
        .expect("providers");
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["provider"], "cursor");
    assert!(providers[0]["totalAvailable"].as_u64().expect("available") > 0);
    assert_eq!(
        providers[0]["layers"]["global"],
        json!({
            "available": providers[0]["totalAvailable"],
            "active": providers[0]["totalActive"]
        })
    );
    assert_eq!(
        providers[0]["layers"]["project"],
        json!({ "available": 0, "active": 0 })
    );
    assert!(
        summarized["warnings"]
            .as_array()
            .expect("warnings")
            .is_empty()
    );
}

#[test]
fn legacy_apply_request_gets_versioned_non_mutating_migration_response() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let target = fixture_copy
        .path()
        .join("pi/project/.pi/skills/example-pi-project-skill/SKILL.md");
    let result = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_apply_toggle_item",
        json!({
            "provider": "pi",
            "kind": "skill",
            "layer": "project",
            "id": "pi:project:skill:example-pi-project-skill",
            "targetEnabled": false,
            "requireConfirmation": true,
            "confirm": true
        }),
    );

    assert_eq!(result["status"], "blocked");
    assert_eq!(
        result["reason"],
        "plan fingerprint does not match current reviewed plan"
    );
    assert_eq!(result["controlContractVersion"], 2);
    assert!(target.exists());
    assert!(!app_state.path().join("vault").exists());
}

#[test]
fn plans_agent_toggle_over_mcp() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_item",
        json!({
            "provider": "claude",
            "kind": "agent",
            "layer": "global",
            "id": "claude:global:agent:claude-global-reviewer",
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["applyMode"], "re-resolve-on-apply");
    assert_eq!(planned["blocked"], json!(null));
    assert_eq!(planned["warnings"], json!([]));
    assert_eq!(planned["controlContractVersion"], 2);
    assert_eq!(planned["operation"]["schemaVersion"], 1);
    assert_eq!(planned["operation"]["operationKind"], "native-toggle");
    assert_eq!(planned["operation"]["lifecycle"], "planned");
    assert_eq!(planned["operation"]["retryable"], true);
    assert!(planned.get("writes").is_none());
    assert_eq!(planned["selection"]["kind"], "agent");
    assert_eq!(planned["operations"][0]["type"], "renamePath");
    assert_eq!(planned["operations"][0]["op"], "renamePath");
    assert!(
        planned["operations"][0]["toPath"]
            .as_str()
            .expect("toPath")
            .contains("/vault/claude/global/agent/")
    );
    assert!(
        planned["operations"][0]["to"]
            .as_str()
            .expect("to")
            .contains("/vault/claude/global/agent/")
    );
    assert!(
        planned["operations"][0]["fromPath"]
            .as_str()
            .expect("fromPath")
            .contains("agents/reviewer.md")
    );
    assert!(
        planned["operations"][0]["from"]
            .as_str()
            .expect("from")
            .contains("agents/reviewer.md")
    );
    assert!(planned["operations"][0].get("operationType").is_none());
    assert!(planned["operations"][0].get("summary").is_none());
    assert_eq!(planned["affectedTargets"][0]["type"], "path");
    assert!(planned["affectedTargets"][0]["path"].as_str().is_some());
    assert!(planned["affectedTargets"][0].get("targetType").is_none());
    assert!(
        planned["affectedPaths"]
            .as_array()
            .expect("affectedPaths")
            .iter()
            .any(|path| path
                .as_str()
                .expect("affected path")
                .contains("agents/reviewer.md"))
    );
}

#[test]
fn plans_claude_plugin_config_toggle_over_mcp() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_item",
        json!({
            "provider": "claude",
            "kind": "plugin",
            "layer": "global",
            "id": "claude:global:tool:settings:safe-shell",
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert!(planned.get("writes").is_none());
    assert_eq!(planned["selection"]["category"], "plugin-config");
    assert_eq!(planned["operations"][0]["type"], "replaceJsonValue");
    assert_eq!(planned["operations"][0]["op"], "replaceJsonValue");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("settings path")
            .ends_with("settings.json")
    );
    assert_eq!(
        planned["operations"][0]["jsonPath"],
        json!(["enabledPlugins", "safe-shell"])
    );
    assert_eq!(
        planned["operations"][0]["pointer"],
        "/enabledPlugins/safe-shell"
    );
    assert_eq!(planned["operations"][0]["value"], false);
    assert!(planned["operations"][0].get("operationType").is_none());
    assert!(planned["operations"][0].get("summary").is_none());
    assert!(
        planned["affectedTargets"][1]["path"]
            .as_str()
            .expect("json path target")
            .contains("enabledPlugins.safe-shell")
    );
}

#[test]
fn plans_configured_mcp_replace_file_toggle_over_mcp() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_item",
        json!({
            "provider": "claude",
            "kind": "mcp",
            "layer": "project",
            "id": "claude:project:configured-mcp:github",
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert!(planned.get("writes").is_none());
    assert_eq!(planned["selection"]["category"], "configured-mcp");
    assert_eq!(planned["operations"][0]["type"], "replaceFile");
    assert_eq!(planned["operations"][0]["op"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("settings path")
            .ends_with(".claude/settings.local.json")
    );
    assert!(planned["operations"][0].get("operationType").is_none());
    assert!(planned["operations"][0].get("summary").is_none());
}

#[test]
fn plans_claude_global_configured_mcp_vault_toggle_over_mcp() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let planned = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_plan_toggle_item",
        json!({
            "provider": "claude",
            "kind": "mcp",
            "layer": "global",
            "id": "claude:global:configured-mcp:global-docs",
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["provider"], "claude");
    assert_eq!(planned["selection"]["layer"], "global");
    assert_eq!(planned["selection"]["category"], "configured-mcp");
    assert_eq!(planned["operations"][0]["type"], "replaceFile");
    assert_eq!(planned["operations"][0]["op"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("Claude user-state path")
            .ends_with("claude/.claude.json")
    );
    assert_eq!(planned["affectedTargets"][0]["type"], "path");
    assert_eq!(planned["affectedTargets"][1]["type"], "path");
    assert_eq!(planned["affectedTargets"][2]["type"], "path");
}

#[test]
fn lists_and_plans_claude_local_configured_mcp_toggle_over_mcp() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_claude_local_mcp_servers(
        fixture_copy.path(),
        json!({ "local-plan": { "command": "local-plan-mcp" } }),
    );
    let context = context_with_roots(fixture_copy.path(), app_state.path());

    let listed = call_tool(
        &context,
        "unpin_list_items",
        json!({
            "selector": {
                "providers": ["claude"],
                "layers": ["project"],
                "categories": ["configured-mcp"]
            },
            "limit": 100
        }),
    );
    let local_item = listed["items"]
        .as_array()
        .expect("listed items")
        .iter()
        .find(|item| item["displayName"] == "local-plan")
        .expect("Claude local MCP");
    let local_id = local_item["id"].as_str().expect("local MCP id");
    assert!(local_id.starts_with("claude:project:configured-mcp:@local/"));

    let planned = call_tool(
        &context,
        "unpin_plan_toggle_item",
        json!({
            "provider": "claude",
            "kind": "mcp",
            "layer": "project",
            "id": local_id,
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["id"], local_id);
    assert_eq!(planned["operations"][0]["type"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("Claude user-state path")
            .ends_with("claude/.claude.json")
    );
}

#[test]
fn plans_project_codex_configured_mcp_native_toggle_over_mcp() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_item",
        json!({
            "kind": "mcp",
            "layer": "project",
            "id": "codex:project:configured-mcp:project-docs",
            "targetEnabled": true
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["provider"], "codex");
    assert_eq!(planned["selection"]["layer"], "project");
    assert_eq!(planned["selection"]["enabled"], false);
    assert_eq!(planned["targetEnabled"], true);
    assert_eq!(planned["providerReach"]["selected"]["provider"], "codex");
    assert_eq!(
        planned["providerReach"]["selected"]["provenance"],
        "exact-individual-target"
    );
    assert_eq!(planned["coverage"]["entries"][0]["provider"], "codex");
    assert_eq!(planned["coverage"]["entries"][0]["included"], true);
    assert_eq!(planned["operations"][0]["type"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("config path")
            .ends_with("codex/project/.codex/config.toml")
    );
}

#[test]
fn individual_toggle_rejects_selected_provider_conflict_before_native_planning() {
    let app_state = TempDir::new().expect("temp app state");
    let mut context = context();
    context.app_state_root = app_state.path().to_path_buf();
    let response = call_tool(
        &context,
        "unpin_plan_toggle_item",
        json!({
            "kind": "mcp",
            "layer": "global",
            "id": "zed:global:configured-mcp:github",
            "targetEnabled": false,
            "providerReach": {
                "mode": "selected",
                "provider": "codex"
            }
        }),
    );

    assert_eq!(response["status"], "blocked");
    assert!(
        response["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("codex")
                && reason.contains("zed")
                && reason.contains("exact target"))
    );
    assert!(
        !app_state.path().join("journals").exists(),
        "provider conflict rejects before native transition planning"
    );
}

#[test]
fn plans_zed_configured_mcp_toggle_over_mcp() {
    let planned = call_tool(
        &context(),
        "unpin_plan_toggle_item",
        json!({
            "provider": "zed",
            "kind": "mcp",
            "layer": "global",
            "id": "zed:global:configured-mcp:github",
            "targetEnabled": false
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert!(planned.get("writes").is_none());
    assert_eq!(planned["selection"]["provider"], "zed");
    assert_eq!(planned["selection"]["category"], "configured-mcp");
    assert_eq!(planned["operations"][0]["type"], "replaceFile");
    assert_eq!(planned["operations"][0]["op"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("settings path")
            .ends_with(".config/zed/settings.json")
    );
    assert!(planned["operations"][0].get("operationType").is_none());
    assert!(planned["operations"][0].get("summary").is_none());
}

#[test]
fn control_plane_configured_mcp_disable_is_blocked_over_single_mcp_tools() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_claude_project_mcp_servers(
        fixture_copy.path(),
        json!({
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"]
            },
            "unpin": {
                "command": "unpin",
                "args": ["mcp"]
            }
        }),
    );
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let mcp_path = fixture_copy
        .path()
        .join("claude")
        .join("project")
        .join(".mcp.json");
    let selector = json!({
        "provider": "claude",
        "kind": "mcp",
        "layer": "project",
        "id": "claude:project:configured-mcp:unpin",
        "targetEnabled": false
    });

    let planned = call_tool(&context, "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "blocked");
    assert_eq!(planned["reason"], "control-plane-protected");
    assert_eq!(planned["reasonCode"], "control-plane-protected");
    assert_eq!(planned["blocked"]["reasonCode"], "control-plane-protected");
    assert_eq!(planned["selection"]["id"], selector["id"]);
    assert_eq!(planned["operations"], json!([]));
    assert_eq!(planned["affectedPaths"], json!([]));

    let mut confirmed_selector = selector.as_object().expect("selector object").clone();
    confirmed_selector.insert("requireConfirmation".to_string(), json!(true));
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(confirmed_selector),
    );
    assert_eq!(applied["status"], "blocked");
    assert_eq!(applied["reasonCode"], "control-plane-protected");
    assert!(
        fs::read_to_string(mcp_path)
            .expect("mcp json remains readable")
            .contains("unpin")
    );
}

#[test]
fn control_plane_configured_mcp_is_blocked_in_bulk_plan() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    write_claude_project_mcp_servers(
        fixture_copy.path(),
        json!({
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"]
            },
            "unpin": {
                "command": "unpin",
                "args": ["mcp"]
            }
        }),
    );
    let context = context_with_roots(fixture_copy.path(), app_state.path());

    let request = json!({
        "selector": {
            "providers": ["claude"],
            "categories": ["configured-mcp"],
            "layers": ["project"],
            "ids": [
                "claude:project:configured-mcp:unpin",
                "claude:project:configured-mcp:github"
            ]
        },
        "targetEnabled": false,
        "providerReach": {
            "mode": "selected",
            "provider": "claude"
        },
        "acknowledgeWholeInventory": true
    });
    let planned = call_tool(&context, "unpin_plan_toggle_items", request.clone());

    assert_eq!(planned["status"], "blocked");
    assert_eq!(planned["lifecycle"], "blocked");
    assert_eq!(planned["matchedCount"], 2);
    assert_eq!(planned["actionableCount"], 1);
    assert_eq!(planned["blockedCount"], 1);
    assert_eq!(
        planned["actionableItems"][0]["id"],
        "claude:project:configured-mcp:github"
    );
    assert_eq!(
        planned["blockedItems"][0]["item"]["id"],
        "claude:project:configured-mcp:unpin"
    );
    assert_eq!(
        planned["blockedItems"][0]["reasonCode"],
        "control-plane-protected"
    );
    assert_eq!(planned["blocked"][0]["reason"], "control-plane-protected");
    assert!(
        planned["planFingerprint"]
            .as_str()
            .expect("fingerprint")
            .starts_with("sha256:")
    );

    let mut apply = request.as_object().expect("bulk request object").clone();
    apply.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    apply.insert("maxItems".to_string(), json!(2));
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_items",
        serde_json::Value::Object(apply),
    );
    assert_eq!(applied["status"], "blocked");
    assert_eq!(applied["lifecycle"], "blocked");
    assert_eq!(
        applied["blockedItems"][0]["reasonCode"],
        "control-plane-protected"
    );
}

#[test]
fn plans_cursor_workspace_sqlite_toggle_over_mcp() {
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
    let context = context_with_roots(fixture_copy.path(), app_state.path());

    let planned = call_tool(
        &context,
        "unpin_plan_toggle_item",
        json!({
            "provider": "cursor",
            "kind": "mcp",
            "layer": "global",
            "id": "cursor:global:configured-mcp:modern-global",
            "targetEnabled": true
        }),
    );

    assert_eq!(planned["status"], "planned");
    assert!(planned.get("writes").is_none());
    assert_eq!(planned["selection"]["category"], "configured-mcp");
    assert_eq!(
        planned["operations"][0]["type"],
        "replaceSqliteItemTableValue"
    );
    assert_eq!(
        planned["operations"][0]["op"],
        "replaceSqliteItemTableValue"
    );
    assert_eq!(
        planned["operations"][0]["path"],
        database_path.to_string_lossy().as_ref()
    );
    assert_eq!(planned["operations"][0]["value"], json!(["user-other"]));
    assert!(planned["operations"][0].get("operationType").is_none());
    assert!(planned["operations"][0].get("summary").is_none());
}

#[test]
fn same_state_single_toggle_plan_is_planned_but_apply_is_no_op() {
    let selector = json!({
        "provider": "claude",
        "kind": "agent",
        "layer": "global",
        "id": "claude:global:agent:claude-global-reviewer",
        "targetEnabled": true
    });

    let planned = call_tool(&context(), "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["targetEnabled"], true);
    assert_eq!(planned["applyMode"], "re-resolve-on-apply");
    assert_eq!(planned["operations"], json!([]));
    assert_eq!(planned["affectedTargets"], json!([]));
    assert_eq!(planned["affectedPaths"], json!([]));
    assert_eq!(planned["blocked"], json!(null));
    assert_eq!(planned["warnings"], json!([]));
    assert_eq!(planned["controlContractVersion"], 2);
    assert_eq!(planned["operation"]["schemaVersion"], 1);
    assert_eq!(planned["operation"]["operationKind"], "native-toggle");
    assert_eq!(planned["operation"]["lifecycle"], "no-op");
    assert_eq!(planned["operation"]["retryable"], false);
    assert!(planned["operation"].get("humanAction").is_none());

    let mut confirmed_selector = selector.as_object().expect("selector object").clone();
    confirmed_selector.insert("requireConfirmation".to_string(), json!(true));
    confirmed_selector.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    let applied = call_tool(
        &context(),
        "unpin_apply_toggle_item",
        serde_json::Value::Object(confirmed_selector),
    );
    assert_eq!(applied["status"], "no-op");
    assert_eq!(applied["targetEnabled"], true);
    assert_eq!(applied["applyMode"], "re-resolve-on-apply");
    assert_eq!(applied["operations"], json!([]));
    assert_eq!(applied["affectedTargets"], json!([]));
    assert_eq!(applied["affectedPaths"], json!([]));
    assert_eq!(applied["blocked"], json!(null));
    assert_eq!(applied["warnings"], json!([]));
    assert_eq!(applied["controlContractVersion"], 2);
    assert_eq!(applied["operation"]["lifecycle"], "no-op");
}

#[test]
fn toggle_planning_refreshes_discovery_after_external_provider_changes() {
    let temp = TempDir::new().expect("temporary MCP fixture");
    let fixture_root = temp.path().join("fixtures");
    let app_state_root = temp.path().join("state");
    copy_dir_all(&fixtures_root(), &fixture_root);
    fs::create_dir_all(&app_state_root).expect("create app state");
    let mut context = context_with_roots(&fixture_root, &app_state_root);
    context.discovery_cache = McpDiscoveryCache::with_ttl(Duration::from_secs(60));

    let selector = json!({
        "provider": "codex",
        "kind": "plugin",
        "layer": "global",
        "id": "codex:global:plugin-config:config:connector-kit@example-marketplace",
        "targetEnabled": false
    });
    let first = call_tool(&context, "unpin_plan_toggle_item", selector);
    assert_eq!(first["status"], "planned");
    assert_eq!(first["selection"]["enabled"], true);

    let config_path = fixture_root
        .join("codex")
        .join("global")
        .join("config.toml");
    let before = fs::read_to_string(&config_path).expect("read Codex fixture");
    let enabled_entry = "[plugins.\"connector-kit@example-marketplace\"]\nenabled = true";
    let disabled_entry = "[plugins.\"connector-kit@example-marketplace\"]\nenabled = false";
    let after = before.replacen(enabled_entry, disabled_entry, 1);
    assert_ne!(after, before, "connector fixture entry must be replaced");
    fs::write(&config_path, after).expect("externally update Codex fixture");

    let reverse = call_tool(
        &context,
        "unpin_plan_toggle_item",
        json!({
            "provider": "codex",
            "kind": "plugin",
            "layer": "global",
            "id": "codex:global:plugin-config:config:connector-kit@example-marketplace",
            "targetEnabled": true
        }),
    );
    assert_eq!(reverse["status"], "planned");
    assert_eq!(reverse["selection"]["enabled"], false);
    assert_ne!(reverse["operations"], json!([]));
    assert_eq!(reverse["operation"]["lifecycle"], "planned");
}

#[test]
fn returns_inventory_summary_and_doctor_structured_content() {
    let summary = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "unpin_get_inventory_summary",
                "arguments": {}
            }
        }),
    );

    assert_eq!(summary["result"]["structuredContent"]["status"], "ok");
    assert_eq!(
        summary["result"]["structuredContent"]["inventory"]["providers"][0]["provider"],
        "claude"
    );
    let claude_summary = &summary["result"]["structuredContent"]["inventory"]["providers"][0];
    assert_eq!(
        claude_summary["kinds"]["skill"],
        json!({"available": 2, "active": 2})
    );
    assert_eq!(
        claude_summary["kinds"]["mcp"],
        json!({"available": 3, "active": 2})
    );
    assert_eq!(
        claude_summary["categories"]["configured-mcp"],
        json!({"available": 3, "active": 2})
    );
    assert_eq!(
        claude_summary["categories"]["plugin-manifest"],
        json!({"available": 0, "active": 0})
    );
    assert_eq!(
        claude_summary["layers"]["project"],
        json!({"available": 9, "active": 7})
    );

    let doctor = handle_mcp_request(
        &context(),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "unpin_run_doctor",
                "arguments": {}
            }
        }),
    );

    assert_eq!(doctor["result"]["structuredContent"]["status"], "ok");
    let expected_items = discover_all(&DiscoveryRoots::fixture_root(fixtures_root()))
        .expect("fixture discovery")
        .items
        .len();
    assert_eq!(
        doctor["result"]["structuredContent"]["itemsDiscovered"],
        expected_items
    );
    let doctor_provider_ids = doctor["result"]["structuredContent"]["providers"]
        .as_array()
        .expect("doctor providers")
        .iter()
        .map(|provider| provider["provider"].as_str().expect("provider id"))
        .collect::<Vec<_>>();
    assert_eq!(doctor_provider_ids, ProviderId::ALL.map(ProviderId::as_str));
    assert!(
        doctor["result"]["structuredContent"]["providers"]
            .as_array()
            .expect("doctor providers")
            .iter()
            .any(|provider| provider["provider"] == "claude"
                && provider["status"] == "ok"
                && provider["issues"] == json!([]))
    );
}

#[test]
fn provider_scoped_mcp_defaults_and_filters_read_contracts() {
    let context = context_for_provider(ProviderId::Zed);
    let initialized = handle_mcp_request(
        &context,
        &json!({
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize"
        }),
    );
    assert_eq!(
        initialized["result"]["capabilities"]["experimental"]["unpinControl"]["providerScope"],
        "zed"
    );

    let tools = handle_mcp_request(
        &context,
        &json!({
            "jsonrpc": "2.0",
            "id": "tools",
            "method": "tools/list"
        }),
    );
    let toggle = tools["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "unpin_plan_toggle_item")
        .expect("toggle descriptor");
    assert_eq!(
        toggle["inputSchema"]["properties"]["provider"]["enum"],
        json!(["zed"])
    );
    assert!(
        !toggle["inputSchema"]["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .any(|field| field == "provider")
    );

    let summary = call_tool(&context, "unpin_get_inventory_summary", json!({}));
    assert_eq!(summary["providerScope"], "zed");
    assert_eq!(
        summary["inventory"]["providers"]
            .as_array()
            .expect("providers")
            .len(),
        1
    );
    assert_eq!(summary["inventory"]["providers"][0]["provider"], "zed");

    let items = call_tool(&context, "unpin_list_items", json!({}));
    assert!(
        items["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item["provider"] == "zed")
    );
    assert!(
        items["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .all(|warning| warning["provider"] == "zed")
    );

    let doctor = call_tool(&context, "unpin_run_doctor", json!({}));
    assert_eq!(
        doctor["providers"]
            .as_array()
            .expect("doctor providers")
            .len(),
        1
    );
    assert_eq!(doctor["providers"][0]["provider"], "zed");
    let expected_zed_items = discover_all(&DiscoveryRoots::fixture_root(fixtures_root()))
        .expect("fixture discovery")
        .items
        .into_iter()
        .filter(|item| item.provider == ProviderId::Zed)
        .count();
    assert_eq!(doctor["itemsDiscovered"], expected_zed_items);

    let status = call_tool(&context, "unpin_get_control_status", json!({}));
    for field in ["gateways", "sessions", "hooks"] {
        assert!(
            status["control"][field]
                .as_array()
                .expect("provider-scoped control rows")
                .iter()
                .all(|row| row["provider"] == "zed")
        );
    }
    for scope in ["global", "repository", "workspace", "session"] {
        let Some(providers) = status["control"]["policies"][scope]["providers"].as_object() else {
            continue;
        };
        assert!(providers.keys().all(|provider| provider == "zed"));
    }
}

#[test]
fn provider_scoped_mcp_defaults_required_provider_and_rejects_widening() {
    let context = context_for_provider(ProviderId::Zed);
    let item = discover_all(&context.discovery_roots)
        .expect("fixture discovery")
        .items
        .into_iter()
        .find(|item| item.provider == ProviderId::Zed)
        .expect("zed item");
    let planned = call_tool(
        &context,
        "unpin_plan_toggle_item",
        json!({
            "kind": item.kind.as_str(),
            "layer": item.layer.as_str(),
            "id": item.id,
            "targetEnabled": item.enabled
        }),
    );
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["provider"], "zed");

    for arguments in [
        json!({"provider": "claude"}),
        json!({"providers": ["zed", "claude"]}),
        json!({"selector": {"providers": ["claude"]}}),
    ] {
        let name = if arguments.get("provider").is_some() {
            "unpin_list_hooks"
        } else if arguments.get("selector").is_some() {
            "unpin_list_items"
        } else {
            "unpin_get_inventory_summary"
        };
        let response = handle_mcp_request(
            &context,
            &json!({
                "jsonrpc": "2.0",
                "id": "scope",
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments
                }
            }),
        );
        assert_eq!(response["error"]["code"], -32000);
        assert_eq!(
            response["error"]["message"],
            "provider claude is outside MCP provider scope zed"
        );
    }
}

#[test]
fn mcp_doctor_reports_missing_provider_fixture_files() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::remove_file(
        fixture_copy
            .path()
            .join("claude")
            .join("global")
            .join("settings.json"),
    )
    .expect("remove fixture");

    let doctor = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_run_doctor",
        json!({}),
    );

    assert_eq!(doctor["status"], "error");
    assert!(
        doctor["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .any(|provider| provider["provider"] == "claude"
                && provider["status"] == "error"
                && provider["issues"][0]["code"] == "fixture-validation"
                && provider["issues"][0]["message"] == "fixture file is missing")
    );
    assert_eq!(doctor["fixtureIssues"][0]["providerId"], "claude");
    assert_eq!(
        doctor["fixtureIssues"][0]["relativePath"],
        "claude/global/settings.json"
    );
    assert_eq!(
        doctor["fixtureIssues"][0]["message"],
        "fixture file is missing"
    );
    assert!(doctor.get("fixtureValidationIssues").is_none());
    assert_eq!(doctor["warnings"], json!([]));
}

#[test]
fn mcp_doctor_reports_invalid_provider_fixture_shapes() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
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

    let doctor = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_run_doctor",
        json!({}),
    );

    assert_eq!(doctor["status"], "error");
    assert!(
        doctor["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .any(|provider| provider["provider"] == "cursor"
                && provider["status"] == "error"
                && provider["issues"][0]["code"] == "fixture-validation"
                && provider["issues"][0]["message"] == "mcpServers must be an object")
    );
    assert_eq!(doctor["fixtureIssues"][0]["providerId"], "cursor");
    assert_eq!(
        doctor["fixtureIssues"][0]["relativePath"],
        "cursor/home/mcp.json"
    );
    assert_eq!(
        doctor["fixtureIssues"][0]["message"],
        "mcpServers must be an object"
    );
    assert!(doctor.get("fixtureValidationIssues").is_none());
    assert_eq!(doctor["warnings"], json!([]));
}

#[test]
fn mcp_doctor_reports_capability_matrix_issues_before_fixture_issues() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    fs::write(
        fixture_copy.path().join("capability-matrix.json"),
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "providers": {},
            "notes": {}
        }))
        .expect("matrix json"),
    )
    .expect("write stale matrix");
    fs::remove_file(
        fixture_copy
            .path()
            .join("claude")
            .join("global")
            .join("settings.json"),
    )
    .expect("remove fixture");

    let doctor = call_tool(
        &context_with_roots(fixture_copy.path(), app_state.path()),
        "unpin_run_doctor",
        json!({}),
    );

    assert_eq!(doctor["status"], "error");
    assert!(
        doctor["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .any(|provider| provider["provider"] == "claude"
                && provider["status"] == "error"
                && provider["issues"]
                    .as_array()
                    .expect("issues")
                    .iter()
                    .any(|issue| issue["code"] == "capability-matrix"
                        && issue["message"] == "capability-matrix.json is missing claude"))
    );
    assert!(
        doctor["capabilityMatrixIssues"]
            .as_array()
            .expect("capability issues")
            .iter()
            .any(|issue| issue["message"] == "capability-matrix.json is missing claude")
    );
    assert_eq!(doctor["fixtureIssues"], json!([]));
    assert!(doctor.get("fixtureValidationIssues").is_none());
    assert_eq!(doctor["warnings"], json!([]));
}

#[test]
fn mcp_backup_summaries_mark_invalid_restore_manifests_unrestorable() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());

    write_backup_manifest(
        app_state.path(),
        "backup-valid",
        backup_manifest(
            "backup-valid",
            "2026-06-20T12:03:00Z",
            Some("entries/entry-1/payload"),
        ),
    );
    let valid_payload = app_state
        .path()
        .join("backups/backup-valid/entries/entry-1/payload");
    fs::create_dir_all(valid_payload.parent().expect("payload has parent"))
        .expect("create payload parent");
    fs::write(valid_payload, "backup\n").expect("write payload");
    authenticate_legacy_backup(
        app_state.path(),
        "backup-valid",
        &BackupAuthenticationKey::new([0x42; 32]),
    )
    .expect("authenticate valid backup");
    write_backup_manifest(
        app_state.path(),
        "backup-mismatch",
        backup_manifest(
            "backup-other",
            "2026-06-20T12:02:00Z",
            Some("entries/entry-1/payload"),
        ),
    );
    write_backup_manifest(
        app_state.path(),
        "backup-traversal",
        backup_manifest(
            "backup-traversal",
            "2026-06-20T12:01:00Z",
            Some("../../outside-payload"),
        ),
    );
    write_backup_manifest(
        app_state.path(),
        "backup-empty",
        backup_manifest("backup-empty", "2026-06-20T12:00:00Z", None),
    );

    let backups = call_tool(&context, "unpin_list_backups", json!({}));
    let backup_rows = backups["backups"].as_array().expect("backups array");

    assert_eq!(backups["status"], "ok");
    assert_eq!(backups["totalBackups"], 4);
    assert_eq!(backup_rows.len(), 4);
    assert_eq!(backup_rows[0]["backupId"], "backup-valid");
    assert_eq!(backup_rows[0]["restorable"], true);
    assert_eq!(backup_rows[0]["authentication"], "verified");
    assert_eq!(backup_rows[1]["backupId"], "backup-other");
    assert_eq!(backup_rows[1]["restorable"], false);
    assert_eq!(backup_rows[1]["authentication"], "failed");
    assert_eq!(backup_rows[2]["backupId"], "backup-traversal");
    assert_eq!(backup_rows[2]["restorable"], false);
    assert_eq!(backup_rows[3]["backupId"], "backup-empty");
    assert_eq!(backup_rows[3]["restorable"], false);

    let limited = call_tool(&context, "unpin_list_backups", json!({ "limit": 2 }));
    let limited_rows = limited["backups"].as_array().expect("limited backups");
    assert_eq!(limited["status"], "ok");
    assert_eq!(limited["totalBackups"], 4);
    assert_eq!(limited_rows.len(), 2);
    assert_eq!(limited_rows[0]["backupId"], "backup-valid");
    assert_eq!(limited_rows[1]["backupId"], "backup-other");
}

#[test]
fn mcp_restore_confirmation_returns_handoff_and_never_writes_target() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let target = app_state.path().join("restore-target");
    fs::write(&target, "current\n").expect("current target");
    let mut manifest = backup_manifest(
        "backup-handoff",
        "2026-06-20T12:04:00Z",
        Some("entries/entry-1/payload"),
    );
    manifest["entries"][0]["target"]["path"] = json!(target.to_string_lossy());
    manifest["affectedTargets"][0]["path"] = json!(target.to_string_lossy());
    write_backup_manifest(app_state.path(), "backup-handoff", manifest);
    let payload = app_state
        .path()
        .join("backups/backup-handoff/entries/entry-1/payload");
    fs::create_dir_all(payload.parent().unwrap()).unwrap();
    fs::write(payload, "backup\n").unwrap();
    authenticate_legacy_backup(
        app_state.path(),
        "backup-handoff",
        &BackupAuthenticationKey::new([0x42; 32]),
    )
    .unwrap();

    let planned = call_tool(
        &context,
        "unpin_restore_backup",
        json!({"backupId": "backup-handoff"}),
    );
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["operation"]["lifecycle"], "planned");
    let handoff = call_tool(
        &context,
        "unpin_restore_backup",
        json!({
            "backupId": "backup-handoff",
            "confirm": true,
            "planFingerprint": planned["planFingerprint"],
        }),
    );
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(handoff["controlContractVersion"], 2);
    assert_eq!(handoff["operation"]["schemaVersion"], 1);
    assert_eq!(handoff["operation"]["operationKind"], "restore-backup");
    assert_eq!(handoff["operation"]["lifecycle"], "awaiting-human-action");
    assert_eq!(
        handoff["operation"]["planFingerprint"],
        planned["planFingerprint"]
    );
    assert_eq!(fs::read_to_string(target).unwrap(), "current\n");
}

#[test]
fn handles_one_stdio_tools_list_request() {
    let request = line_request(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/list"
    }));
    let output = handle_stdio_request_once(&context(), request.as_slice()).expect("stdio response");
    assert!(output.ends_with(b"\n"));
    let bodies = response_bodies(&output);
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];

    assert_eq!(body["id"], 4);
    assert_eq!(
        body["result"]["tools"][0]["name"],
        "unpin_get_inventory_summary"
    );
}

#[test]
fn stdio_rejects_messages_over_eight_mibibytes() {
    let mut request = vec![b' '; 8 * 1024 * 1024 + 1];
    request.push(b'\n');

    let error = handle_stdio_request_once(&context(), request.as_slice())
        .expect_err("oversized MCP message should fail");

    assert!(error.to_string().contains("MCP message exceeds"));
}

#[test]
fn plans_single_skill_and_hands_off_apply_without_writing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let original_skill = fixture_copy
        .path()
        .join("pi")
        .join("project")
        .join(".pi")
        .join("skills")
        .join("example-pi-project-skill")
        .join("SKILL.md");

    let selector = json!({
        "provider": "pi",
        "kind": "skill",
        "layer": "project",
        "id": "pi:project:skill:example-pi-project-skill",
        "targetEnabled": false
    });

    let planned = call_tool(&context, "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["controlContractVersion"], 2);
    assert_eq!(planned["operation"]["schemaVersion"], 1);
    assert_eq!(planned["operation"]["operationKind"], "native-toggle");
    assert_eq!(planned["operation"]["lifecycle"], "planned");
    assert_eq!(
        planned["operation"]["planFingerprint"],
        planned["planFingerprint"]
    );
    assert!(planned.get("writes").is_none());
    assert!(original_skill.exists());

    let mut reviewed = selector.as_object().expect("selector object").clone();
    reviewed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    reviewed.insert("requireConfirmation".to_string(), json!(true));
    let handoff = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(reviewed),
    );
    assert_eq!(handoff["status"], "human-action-required");
    assert_eq!(handoff["operationKind"], "toggle-item");
    assert_eq!(handoff["planFingerprint"], planned["planFingerprint"]);
    assert_eq!(handoff["controlContractVersion"], 2);
    assert_eq!(handoff["operation"]["schemaVersion"], 1);
    assert_eq!(handoff["operation"]["operationKind"], "native-toggle");
    assert_eq!(handoff["operation"]["lifecycle"], "awaiting-human-action");
    assert_eq!(
        handoff["operation"]["planFingerprint"],
        planned["planFingerprint"]
    );
    assert!(original_skill.exists());
    assert!(!app_state.path().join("backups").exists());

    let backups = call_tool(&context, "unpin_list_backups", json!({}));
    assert_eq!(backups["status"], "ok");
    assert_eq!(backups["totalBackups"], 0);
}

#[test]
fn plans_claude_connector_plugin_and_hands_off_without_writing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let settings_path = fixture_copy.path().join("claude/global/settings.json");
    let connector_path = fixture_copy
        .path()
        .join("claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json");
    let original_settings = fs::read(&settings_path).expect("original settings");
    let original_connector = fs::read(&connector_path).expect("original connector");
    let selector = json!({
        "provider": "claude",
        "kind": "plugin",
        "layer": "global",
        "id": "claude:global:tool:settings:connector-kit@example-marketplace",
        "targetEnabled": false
    });

    let planned = call_tool(&context, "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["operations"][0]["op"], "replaceJsonValue");
    assert!(settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));

    let unconfirmed = call_tool(&context, "unpin_apply_toggle_item", selector.clone());
    assert_eq!(unconfirmed["status"], "blocked");
    assert_eq!(
        unconfirmed["reason"],
        "plan fingerprint does not match current reviewed plan"
    );

    let mut confirmed = selector.as_object().expect("selector object").clone();
    confirmed.insert("requireConfirmation".to_string(), json!(true));
    confirmed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(confirmed),
    );
    assert_eq!(applied["status"], "human-action-required");
    assert!(settings_plugin_enabled(
        &settings_path,
        "connector-kit@example-marketplace"
    ));
    assert_eq!(
        fs::read(&connector_path).expect("connector after disable"),
        original_connector
    );

    assert_eq!(
        fs::read(&settings_path).expect("restored settings"),
        original_settings
    );
    assert_eq!(
        fs::read(&connector_path).expect("connector after restore"),
        original_connector
    );
    assert!(!app_state.path().join("backups").exists());
}

#[test]
fn plans_opencode_npm_plugin_and_hands_off_without_writing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let config_path = fixture_copy.path().join("opencode/global/opencode.jsonc");
    let original_config = fs::read(&config_path).expect("original OpenCode config");
    let selector = json!({
        "provider": "opencode",
        "kind": "plugin",
        "layer": "global",
        "id": "opencode:global:plugin-config:npm:example-opencode-connector",
        "targetEnabled": false
    });

    let planned = call_tool(&context, "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["category"], "plugin-config");
    assert_eq!(planned["operations"][0]["op"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("OpenCode config path")
            .ends_with("opencode.jsonc")
    );

    let mut confirmed = selector.as_object().expect("selector object").clone();
    confirmed.insert("requireConfirmation".to_string(), json!(true));
    confirmed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(confirmed),
    );
    assert_eq!(applied["status"], "human-action-required");
    assert_eq!(
        fs::read(&config_path).expect("unchanged OpenCode config"),
        original_config
    );
    assert!(!app_state.path().join("backups").exists());
}

#[test]
fn plans_pi_package_extensions_and_hands_off_without_writing() {
    let fixture_copy = TempDir::new().expect("temp fixture copy");
    let app_state = TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let context = context_with_roots(fixture_copy.path(), app_state.path());
    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    let original_settings = fs::read(&settings_path).expect("original Pi settings");
    let selector = json!({
        "provider": "pi",
        "kind": "plugin",
        "layer": "global",
        "id": "pi:global:plugin-config:package-extensions:npm:example-pi-connector",
        "targetEnabled": false
    });

    let planned = call_tool(&context, "unpin_plan_toggle_item", selector.clone());
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["selection"]["category"], "plugin-config");
    assert_eq!(planned["operations"][0]["op"], "replaceFile");
    assert!(
        planned["operations"][0]["path"]
            .as_str()
            .expect("Pi settings path")
            .ends_with("settings.json")
    );

    let mut confirmed = selector.as_object().expect("selector object").clone();
    confirmed.insert("requireConfirmation".to_string(), json!(true));
    confirmed.insert(
        "planFingerprint".to_string(),
        planned["planFingerprint"].clone(),
    );
    let applied = call_tool(
        &context,
        "unpin_apply_toggle_item",
        serde_json::Value::Object(confirmed),
    );
    assert_eq!(applied["status"], "human-action-required");
    assert_eq!(
        fs::read(&settings_path).expect("unchanged Pi settings"),
        original_settings
    );
    assert!(!app_state.path().join("backups").exists());
}
