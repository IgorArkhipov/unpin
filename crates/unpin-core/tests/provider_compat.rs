use std::{fs, path::Path};

use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryMutability, DiscoveryRoots, ProviderId, discover_all,
};

fn write_file(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent directory")).expect("create fixture directory");
    fs::write(path, contents).expect("write fixture");
}

#[test]
fn cursor_uses_config_root_for_global_agents_hooks_and_settings() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    write_file(
        &roots.cursor_config.join("agents/right.md"),
        "# Current agent\n",
    );
    write_file(
        &roots.cursor_global.join("agents/old.md"),
        "# Legacy agent\n",
    );
    write_file(
        &roots.cursor_config.join("hooks.json"),
        r#"{"hooks":{"BeforeShellExecution":[{"command":"/usr/bin/true"}]}}"#,
    );
    write_file(
        &roots.cursor_global.join("hooks.json"),
        r#"{"hooks":{"AfterFileEdit":[{"command":"/usr/bin/false"}]}}"#,
    );
    for name in ["permissions.json", "sandbox.json", "cli-config.json"] {
        write_file(&roots.cursor_config.join(name), "{}\n");
        write_file(&roots.cursor_global.join(name), "{}\n");
    }

    let result = discover_all(&roots).expect("discover fixture");
    let cursor = result
        .items
        .iter()
        .filter(|item| item.provider == ProviderId::Cursor)
        .collect::<Vec<_>>();
    assert!(
        cursor
            .iter()
            .any(|item| item.id == "cursor:global:agent:right")
    );
    assert!(
        cursor
            .iter()
            .all(|item| item.id != "cursor:global:agent:old")
    );
    assert!(cursor.iter().any(|item| {
        item.category == DiscoveryCategory::Hook
            && item.source_path == roots.cursor_config.join("hooks.json").to_string_lossy()
    }));
    assert!(cursor.iter().all(|item| {
        item.category != DiscoveryCategory::Hook
            || item.source_path != roots.cursor_global.join("hooks.json").to_string_lossy()
    }));
    for name in ["permissions.json", "sandbox.json", "cli-config.json"] {
        assert!(cursor.iter().any(|item| {
            item.category == DiscoveryCategory::ProviderSetting
                && item.source_path == roots.cursor_config.join(name).to_string_lossy()
        }));
        assert!(
            cursor.iter().all(|item| {
                item.source_path != roots.cursor_global.join(name).to_string_lossy()
            })
        );
    }
}

#[test]
fn cursor_discovers_portable_local_plugin_manifest() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let plugin_root = roots.cursor_config.join("plugins/local/portable");
    write_file(
        &plugin_root.join("plugin.json"),
        r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"portable"}"#,
    );
    write_file(
        &roots
            .cursor_config
            .join("plugins/local/invalid/plugin.json"),
        r#"{"name":"invalid"}"#,
    );

    let result = discover_all(&roots).expect("discover fixture");
    let plugin = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:portable")
        .expect("portable plugin inventory row");
    assert_eq!(plugin.category, DiscoveryCategory::PluginManifest);
    assert_eq!(
        plugin.source_path,
        plugin_root.join("plugin.json").to_string_lossy()
    );
    assert_eq!(plugin.state_path, plugin_root.to_string_lossy());
    assert_eq!(plugin.mutability, DiscoveryMutability::ReadWrite);
    assert!(
        result
            .items
            .iter()
            .all(|item| { item.id != "cursor:global:plugin-manifest:local:invalid" })
    );
    assert!(result.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Cursor && warning.code == "invalid-shape"
    }));
}

#[test]
fn unreadable_cursor_manifest_does_not_hide_other_plugins_or_expose_paths() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let broken = roots.cursor_config.join("plugins/local/broken/plugin.json");
    fs::create_dir_all(broken.parent().expect("plugin parent")).expect("create plugin");
    fs::write(&broken, [0xff]).expect("invalid UTF-8 manifest");
    write_file(
        &roots
            .cursor_config
            .join("plugins/local/healthy/plugin.json"),
        r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"healthy"}"#,
    );

    let result = discover_all(&roots).expect("discover remaining plugin");
    assert!(
        result
            .items
            .iter()
            .any(|item| { item.id == "cursor:global:plugin-manifest:local:healthy" })
    );
    assert!(
        result.warnings.iter().any(|warning| {
            warning.provider == ProviderId::Cursor && warning.code == "read-error"
        })
    );
    assert!(result.warnings.iter().all(|warning| {
        !warning
            .message
            .contains(&fixture.path().to_string_lossy().to_string())
    }));
}

#[test]
fn claude_disable_all_hooks_reflects_effective_settings_precedence() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    write_file(
        &roots.claude_global.join("settings.json"),
        r#"{"disableAllHooks":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
    );
    let disabled = discover_all(&roots).expect("discover disabled fixture");
    let hook = disabled
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Claude && item.category == DiscoveryCategory::Hook
        })
        .expect("Claude hook");
    assert!(!hook.enabled);

    write_file(
        &roots.claude_project.join(".claude/settings.json"),
        r#"{"disableAllHooks":false}"#,
    );
    let enabled = discover_all(&roots).expect("discover project override fixture");
    let hook = enabled
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Claude && item.category == DiscoveryCategory::Hook
        })
        .expect("Claude hook");
    assert!(hook.enabled);

    write_file(
        &roots.claude_project.join(".claude/settings.local.json"),
        r#"{"disableAllHooks":true}"#,
    );
    let disabled_local = discover_all(&roots).expect("discover local override fixture");
    assert!(
        disabled_local
            .items
            .iter()
            .filter(|item| {
                item.provider == ProviderId::Claude && item.category == DiscoveryCategory::Hook
            })
            .all(|item| !item.enabled)
    );
}

#[test]
fn codex_hook_matcher_is_scoped_to_each_group() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    write_file(
        &roots.codex_global.join("config.toml"),
        "[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"true\"\n\n[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"true\"\n",
    );
    let result = discover_all(&roots).expect("discover fixture");
    let mut matchers = result
        .items
        .iter()
        .filter(|item| {
            item.provider == ProviderId::Codex && item.category == DiscoveryCategory::Hook
        })
        .map(|item| item.hook.as_ref().expect("hook metadata").matcher.clone())
        .collect::<Vec<_>>();
    matchers.sort();
    assert_eq!(matchers, ["*", "Bash"]);
}
