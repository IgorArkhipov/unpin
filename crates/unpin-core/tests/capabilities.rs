use std::{
    fs,
    path::{Path, PathBuf},
};

use tempfile::TempDir;
use unpin_core::capabilities::{
    CAPABILITY_ROWS, load_capability_matrix, validate_capability_matrix, validate_provider_fixtures,
};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
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

fn fixture_copy() -> TempDir {
    let temp = TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), temp.path());
    temp
}

#[test]
fn loads_valid_capability_matrix_for_all_tracked_providers() {
    let matrix = load_capability_matrix(fixtures_root()).expect("capability matrix");

    assert_eq!(matrix.version, 2);
    assert_eq!(
        matrix.provider_ids(),
        vec![
            "claude".to_string(),
            "codex".to_string(),
            "cursor".to_string(),
            "opencode".to_string(),
            "pi".to_string(),
            "zed".to_string()
        ]
    );
    assert_eq!(matrix.providers["claude"].skills, "verified");
    assert_eq!(matrix.providers["claude"].configured_mcps, "verified");
    assert_eq!(matrix.providers["claude"].tools, "unsupported");
    assert_eq!(matrix.providers["claude"].plugin_configs, "verified");
    assert_eq!(matrix.providers["claude"].plugin_global_scope, "verified");
    assert_eq!(matrix.providers["claude"].plugin_project_scope, "verified");
    assert_eq!(matrix.providers["codex"].skills, "verified");
    assert_eq!(matrix.providers["cursor"].plugin_manifests, "verified");
    assert_eq!(matrix.providers["codex"].plugin_configs, "verified");
    assert_eq!(matrix.providers["codex"].plugin_global_scope, "verified");
    assert_eq!(
        matrix.providers["codex"].plugin_project_scope,
        "unsupported"
    );
    assert_eq!(matrix.providers["cursor"].plugin_global_scope, "verified");
    assert_eq!(matrix.providers["cursor"].plugin_project_scope, "read-only");
    assert_eq!(matrix.providers["zed"].configured_mcps, "verified");
    assert_eq!(matrix.providers["pi"].configured_mcps, "unsupported");
    assert_eq!(matrix.providers["opencode"].skills, "needs-verification");
    assert!(matrix.notes["cursor"].contains("every provider"));
    assert_eq!(matrix.providers["zed"].skills, "verified");
    assert_eq!(matrix.providers["zed"].plugin_configs, "out-of-scope");
    assert_eq!(matrix.providers["zed"].plugin_manifests, "out-of-scope");
    assert_eq!(matrix.providers["zed"].plugin_global_scope, "out-of-scope");
    assert_eq!(matrix.providers["zed"].plugin_project_scope, "out-of-scope");
    assert!(matrix.notes["zed"].contains("shared-provider impact"));
}

#[test]
fn checked_in_capability_matrix_matches_cli_rows() {
    let matrix = load_capability_matrix(fixtures_root()).expect("capability matrix");

    for row in CAPABILITY_ROWS {
        let provider = &matrix.providers[row.provider_id];
        assert_eq!(provider.skills, row.skills, "{} skills", row.provider_id);
        assert_eq!(provider.agents, row.agents, "{} agents", row.provider_id);
        assert_eq!(
            provider.configured_mcps, row.configured_mcps,
            "{} configured MCPs",
            row.provider_id
        );
        assert_eq!(provider.tools, row.tools, "{} tools", row.provider_id);
        assert_eq!(provider.hooks, row.hooks, "{} hooks", row.provider_id);
        assert_eq!(
            provider.provider_settings, row.provider_settings,
            "{} provider settings",
            row.provider_id
        );
        assert_eq!(
            provider.plugin_manifests, row.plugin_manifests,
            "{} plugin manifests",
            row.provider_id
        );
        assert_eq!(
            provider.plugin_configs, row.plugin_configs,
            "{} plugin configs",
            row.provider_id
        );
        assert_eq!(
            provider.plugin_global_scope, row.plugin_global_scope,
            "{} global plugin scope",
            row.provider_id
        );
        assert_eq!(
            provider.plugin_project_scope, row.plugin_project_scope,
            "{} project plugin scope",
            row.provider_id
        );
        assert_eq!(
            provider.extensions, row.extensions,
            "{} extensions",
            row.provider_id
        );
        assert_eq!(
            matrix.notes[row.provider_id], row.note,
            "{} note",
            row.provider_id
        );
    }
}

#[test]
fn reports_missing_invalid_and_stale_capability_matrix_issues() {
    let missing = fixture_copy();
    fs::remove_file(missing.path().join("capability-matrix.json")).expect("remove matrix");
    assert_eq!(
        validate_capability_matrix(missing.path()).issues,
        vec!["capability-matrix.json is missing".to_string()]
    );

    let malformed = fixture_copy();
    fs::write(malformed.path().join("capability-matrix.json"), "{").expect("write malformed");
    assert!(
        validate_capability_matrix(malformed.path()).issues[0]
            .contains("capability-matrix.json must be valid JSON")
    );

    let stale = fixture_copy();
    fs::write(
        stale.path().join("capability-matrix.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "providers": {
                "claude": {
                    "skills": "verified",
                    "configuredMcps": "verified",
                    "tools": "verified",
                    "hooks": "installed"
                }
            },
            "notes": {
                "claude": ""
            }
        }))
        .expect("matrix json"),
    )
    .expect("write stale matrix");

    let issues = validate_capability_matrix(stale.path()).issues;
    for expected in [
        "capability-matrix.json must use version 2",
        "capability-matrix.json is missing claude.agents",
        "capability-matrix.json has an invalid claude.hooks value",
        "capability-matrix.json is missing note for claude",
        "capability-matrix.json is missing codex",
        "capability-matrix.json is missing note for codex",
        "capability-matrix.json is missing cursor",
        "capability-matrix.json is missing note for cursor",
        "capability-matrix.json is missing opencode",
        "capability-matrix.json is missing note for opencode",
        "capability-matrix.json is missing pi",
        "capability-matrix.json is missing note for pi",
        "capability-matrix.json is missing zed",
        "capability-matrix.json is missing note for zed",
    ] {
        assert!(
            issues.iter().any(|issue| issue == expected),
            "expected issue {expected:?}; got {issues:#?}"
        );
    }
}

#[test]
fn strict_loading_returns_combined_validation_error() {
    let stale = fixture_copy();
    let mut matrix: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(stale.path().join("capability-matrix.json")).expect("matrix"),
    )
    .expect("matrix json");
    matrix["providers"]["codex"]
        .as_object_mut()
        .expect("codex row")
        .remove("hooks");
    matrix["notes"]
        .as_object_mut()
        .expect("notes")
        .remove("codex");
    fs::write(
        stale.path().join("capability-matrix.json"),
        serde_json::to_string_pretty(&matrix).expect("matrix json"),
    )
    .expect("write stale matrix");

    let error = load_capability_matrix(stale.path()).expect_err("invalid matrix should fail");
    assert_eq!(
        error.to_string(),
        "capability-matrix.json is missing codex.hooks; capability-matrix.json is missing note for codex"
    );
}

#[test]
fn validates_provider_fixture_files_and_shapes() {
    let report = validate_provider_fixtures(fixtures_root());

    assert_eq!(
        report.checked_files,
        vec![
            "claude/.claude.json",
            "claude/global/settings.json",
            "claude/global/settings.local.json",
            "claude/project/.claude/settings.json",
            "claude/project/.claude/settings.local.json",
            "claude/global/skills/example-claude-global-skill/SKILL.md",
            "claude/project/.claude/skills/example-claude-skill/SKILL.md",
            "claude/project/.mcp.json",
            "claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.claude-plugin/plugin.json",
            "claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json",
            "codex/global/config.toml",
            "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.codex-plugin/plugin.json",
            "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json",
            "codex/admin/skills/example-codex-admin-skill/SKILL.md",
            "shared/global/.agents/skills/example-shared-global-skill/SKILL.md",
            "shared/project/.agents/skills/example-shared-project-skill/SKILL.md",
            "cursor/home/skills/example-cursor-skill/SKILL.md",
            "cursor/project/.cursor/skills/example-cursor-project-skill/SKILL.md",
            "cursor/home/mcp.json",
            "cursor/project/.cursor/mcp.json",
            "cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json",
            "cursor/home/plugins/local/example-plugin/mcp.json",
            "cursor/home/plugins/local/claude-compatible/.claude-plugin/plugin.json",
            "pi/global/skills/workflows/example-pi-global-skill/SKILL.md",
            "pi/global/skills/example-pi-file-skill.md",
            "pi/project/.pi/skills/example-pi-project-skill/SKILL.md",
            "pi/project/.pi/skills/example-pi-project-file-skill.md",
            "pi/global/settings.json",
            "pi/project/.pi/settings.json",
            "opencode/global/skills/example-opencode-global-skill/SKILL.md",
            "opencode/global/opencode.jsonc",
            "opencode/project/opencode.json",
            "opencode/global/plugins/example-local.ts",
            "opencode/project/.opencode/plugins/example-project.js",
            "opencode/project/.opencode/skills/example-opencode-project-skill/SKILL.md",
            "zed/global/.config/zed/settings.json",
            "zed/project/.zed/settings.json",
        ]
    );
    assert!(
        report.issues.is_empty(),
        "unexpected issues: {:#?}",
        report.issues
    );
}

#[test]
fn reports_provider_fixture_validation_issues() {
    let missing = fixture_copy();
    fs::remove_file(
        missing
            .path()
            .join("cursor")
            .join("home")
            .join("skills")
            .join("example-cursor-skill")
            .join("SKILL.md"),
    )
    .expect("remove cursor skill");
    let missing_report = validate_provider_fixtures(missing.path());
    assert!(missing_report.issues.iter().any(|issue| {
        issue.provider_id == "cursor"
            && issue.relative_path == "cursor/home/skills/example-cursor-skill/SKILL.md"
            && issue.message == "fixture file is missing"
    }));

    let invalid = fixture_copy();
    fs::write(
        invalid
            .path()
            .join("claude")
            .join("global")
            .join("settings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "enabledPlugins": {
                "safe-shell": "yes"
            },
            "enabledMcpjsonServers": [],
            "disabledMcpjsonServers": [],
            "enableAllProjectMcpServers": "yes"
        }))
        .expect("settings json"),
    )
    .expect("write invalid claude settings");
    fs::write(
        invalid.path().join("claude").join(".claude.json"),
        r#"{"mcpServers":[],"projects":{"/fixture/project":{"mcpServers":[]}}}"#,
    )
    .expect("write invalid Claude user state");
    fs::write(
        invalid
            .path()
            .join("codex")
            .join("global")
            .join("config.toml"),
        "[plugins]\n[mcp_servers.]\n",
    )
    .expect("write invalid codex config");
    fs::write(
        invalid
            .path()
            .join("cursor")
            .join("global")
            .join("mcp.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": []
        }))
        .expect("cursor mcp json"),
    )
    .expect("write invalid cursor mcp");
    fs::write(
        invalid
            .path()
            .join("cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json"),
        r#"{"name":""}"#,
    )
    .expect("write invalid Cursor plugin manifest");
    fs::write(
        invalid
            .path()
            .join("claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json"),
        r#"{"mcpServers":{}}"#,
    )
    .expect("write empty Claude plugin MCP config");
    fs::write(
        invalid.path().join(
            "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.codex-plugin/plugin.json",
        ),
        r#"{"name":"connector-kit"}"#,
    )
    .expect("write unlinked Codex plugin manifest");
    fs::write(
        invalid
            .path()
            .join("cursor/home/plugins/local/example-plugin/mcp.json"),
        r#"{"mcpServers":{"connector-kit":{}}}"#,
    )
    .expect("write incomplete Cursor plugin MCP config");
    fs::write(
        invalid
            .path()
            .join("pi")
            .join("global")
            .join("settings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "packages": [
                "npm:duplicate",
                "npm:duplicate",
                {
                    "source": "npm:not-array",
                    "extensions": "all"
                },
                {
                    "source": "npm:bad-filter",
                    "extensions": ["", "same", "same"]
                },
                {
                    "source": ""
                },
                "",
                42
            ]
        }))
        .expect("Pi settings json"),
    )
    .expect("write invalid Pi settings");

    let issues = validate_provider_fixtures(invalid.path()).issues;
    for (provider_id, relative_path, message) in [
        (
            "claude",
            "claude/.claude.json",
            "mcpServers must be an object",
        ),
        (
            "claude",
            "claude/.claude.json",
            "projects entry 0 mcpServers must be an object",
        ),
        (
            "claude",
            "claude/.claude.json",
            "projects must contain a local mcpServers fixture",
        ),
        (
            "claude",
            "claude/global/settings.json",
            "enabledPlugins.safe-shell must be a boolean",
        ),
        (
            "claude",
            "claude/global/settings.json",
            "enabledMcpjsonServers must be an object",
        ),
        (
            "claude",
            "claude/global/settings.json",
            "disabledMcpjsonServers must be an object",
        ),
        (
            "claude",
            "claude/global/settings.json",
            "enableAllProjectMcpServers must be a boolean",
        ),
        (
            "codex",
            "codex/global/config.toml",
            "line 1 must use [plugins.<id>] or [mcp_servers.<id>]",
        ),
        (
            "codex",
            "codex/global/config.toml",
            "line 2 must use [plugins.<id>] or [mcp_servers.<id>]",
        ),
        (
            "cursor",
            "cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json",
            "Cursor plugin manifest must define a non-empty name",
        ),
        (
            "cursor",
            "cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json",
            "Cursor plugin manifest mcpServers must reference ./mcp.json",
        ),
        (
            "claude",
            "claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json",
            "Claude plugin .mcp.json mcpServers must not be empty",
        ),
        (
            "codex",
            "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.codex-plugin/plugin.json",
            "Codex plugin manifest mcpServers must reference ./.mcp.json",
        ),
        (
            "cursor",
            "cursor/home/plugins/local/example-plugin/mcp.json",
            "Cursor plugin mcp.json mcpServers.connector-kit must define a non-empty command or url",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[1] duplicates source npm:duplicate",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[2] extensions filter must be an array",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[3] extensions filter must contain unique non-empty strings",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[4] object must contain a non-empty source string",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[5] must use a non-empty source string",
        ),
        (
            "pi",
            "pi/global/settings.json",
            "packages[6] must be a source string or object",
        ),
    ] {
        assert!(
            issues.iter().any(|issue| {
                issue.provider_id == provider_id
                    && issue.relative_path == relative_path
                    && issue.message == message
            }),
            "expected issue ({provider_id}, {relative_path}, {message}); got {issues:#?}"
        );
    }
}

#[test]
fn accepts_cursor_mcp_fixture_trailing_commas() {
    let temp = fixture_copy();
    fs::write(
        temp.path().join("cursor").join("home").join("mcp.json"),
        r#"{ "mcpServers": { "example": { "command": "node", }, }, }"#,
    )
    .expect("write cursor mcp");

    let report = validate_provider_fixtures(temp.path());
    assert!(
        !report.issues.iter().any(|issue| {
            issue.provider_id == "cursor" && issue.relative_path == "cursor/home/mcp.json"
        }),
        "cursor mcp trailing commas should be accepted; got {:#?}",
        report.issues
    );
}

#[test]
fn fixture_validation_does_not_require_legacy_cursor_app_support_mcp_json() {
    let temp = fixture_copy();
    let legacy_mcp_path = temp.path().join("cursor").join("global").join("mcp.json");
    assert!(
        !legacy_mcp_path.exists(),
        "legacy Cursor app-support mcp.json fixture should be absent"
    );

    let report = validate_provider_fixtures(temp.path());

    assert!(
        !report.issues.iter().any(|issue| {
            issue.provider_id == "cursor" && issue.relative_path == "cursor/global/mcp.json"
        }),
        "legacy Cursor app-support mcp.json should not be fixture-validated; got {:#?}",
        report.issues
    );
}

#[test]
fn fixture_validation_ignores_invalid_legacy_cursor_app_support_mcp_json() {
    let temp = fixture_copy();
    fs::write(
        temp.path().join("cursor").join("global").join("mcp.json"),
        r#"{"mcpServers":[]}"#,
    )
    .expect("write invalid legacy cursor mcp");

    let report = validate_provider_fixtures(temp.path());

    assert!(
        !report.issues.iter().any(|issue| {
            issue.provider_id == "cursor" && issue.relative_path == "cursor/global/mcp.json"
        }),
        "legacy Cursor app-support mcp.json should not be fixture-validated; got {:#?}",
        report.issues
    );
}
