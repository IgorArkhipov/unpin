use std::{fs, path::Path};

use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryMutability, DiscoveryRoots, ProviderId, discover_all,
};
use unpin_core::mutation::{TogglePlanRequest, ToggleStatus, plan_toggle};

fn write_file(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("fixture parent directory"))
        .expect("create fixture directory");
    fs::write(path, contents).expect("write fixture file");
}

#[test]
fn claude_skill_overrides_are_effective_scoped_and_do_not_leak_to_compatibility_views() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());

    write_file(
        &roots.claude_global.join("skills/plain/SKILL.md"),
        "# Plain\n",
    );
    write_file(
        &roots.claude_global.join("skills/normal/SKILL.md"),
        "# Normal\n",
    );
    write_file(
        &roots.claude_project.join(".claude/skills/plain/SKILL.md"),
        "# Project Plain\n",
    );
    write_file(
        &roots
            .claude_project
            .join(".claude/skills/project-only/SKILL.md"),
        "# Project Only\n",
    );
    write_file(
        &roots.claude_global.join("settings.json"),
        r#"{
            "skillOverrides": {
                "plain": "off",
                "normal": "on",
                "project-only": "name-only"
            }
        }"#,
    );
    write_file(
        &roots.claude_project.join(".claude/settings.json"),
        r#"{"skillOverrides":{"plain":"name-only"}}"#,
    );
    write_file(
        &roots.claude_project.join(".claude/settings.local.json"),
        r#"{"skillOverrides":{"project-only":"off"}}"#,
    );

    let result = discover_all(&roots).expect("discover fixture");

    let item = |id: &str| {
        result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items))
    };

    let global_plain = item("claude:global:skill:plain");
    assert!(!global_plain.enabled);
    assert_eq!(global_plain.mutability, DiscoveryMutability::ReadOnly);

    let global_normal = item("claude:global:skill:normal");
    assert!(global_normal.enabled);
    assert_eq!(global_normal.mutability, DiscoveryMutability::ReadWrite);

    let project_plain = item("claude:project:skill:plain");
    assert!(project_plain.enabled);
    assert_eq!(project_plain.mutability, DiscoveryMutability::ReadOnly);

    let project_only = item("claude:project:skill:project-only");
    assert!(!project_only.enabled);
    assert_eq!(project_only.mutability, DiscoveryMutability::ReadOnly);

    let cursor_compat_plain = item("cursor:global:skill:@compat/claude/plain");
    assert!(cursor_compat_plain.enabled);
    assert_eq!(
        cursor_compat_plain.mutability,
        DiscoveryMutability::ReadWrite
    );
}

#[test]
fn claude_skill_directory_plugins_have_read_only_identity_and_bundled_hooks() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let plugin_root = roots.claude_global.join("skills/local-bundle");
    let manifest_hooks_root = roots.claude_global.join("skills/file-bundle");
    let default_hooks_root = roots.claude_global.join("skills/default-bundle");

    write_file(&plugin_root.join("SKILL.md"), "# Local bundle\n");
    write_file(
        &plugin_root.join(".claude-plugin/plugin.json"),
        r#"{
            "name": "local-bundle",
            "version": "1.0.0",
            "hooks": {
                "PreToolUse": [{"hooks":[{"type":"command","command":"true"}]}]
            }
        }"#,
    );
    write_file(&manifest_hooks_root.join("SKILL.md"), "# File bundle\n");
    write_file(
        &manifest_hooks_root.join(".claude-plugin/plugin.json"),
        r#"{
            "name": "file-bundle",
            "hooks": "./hooks/hooks.json"
        }"#,
    );
    write_file(
        &manifest_hooks_root.join("hooks/hooks.json"),
        r#"{
            "hooks": {
                "PostToolUse": [{"hooks":[{"type":"command","command":"true"}]}]
            }
        }"#,
    );
    write_file(&default_hooks_root.join("SKILL.md"), "# Default bundle\n");
    write_file(
        &default_hooks_root.join(".claude-plugin/plugin.json"),
        r#"{"name":"default-bundle"}"#,
    );
    write_file(
        &default_hooks_root.join("hooks/hooks.json"),
        r#"{
            "hooks": {
                "Stop": [{"hooks":[{"type":"command","command":"true"}]}]
            }
        }"#,
    );
    write_file(
        &roots.claude_global.join("settings.json"),
        r#"{"skillOverrides":{"local-bundle":"off"}}"#,
    );

    let result = discover_all(&roots).expect("discover fixture");
    let plugin = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:plugin-manifest:skills-dir:local-bundle")
        .expect("skill-directory plugin inventory row");
    assert_eq!(plugin.provider, ProviderId::Claude);
    assert_eq!(plugin.category, DiscoveryCategory::PluginManifest);
    assert!(plugin.enabled);
    assert_eq!(plugin.mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(
        plugin.source_path,
        plugin_root
            .join(".claude-plugin/plugin.json")
            .to_string_lossy()
    );
    assert_eq!(plugin.state_path, plugin_root.to_string_lossy());
    assert!(plugin.source_fingerprint.is_some());

    let skill = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:local-bundle")
        .expect("bundle skill inventory row");
    assert!(
        skill.enabled,
        "skillOverrides do not apply to plugin skills"
    );
    assert_eq!(skill.mutability, DiscoveryMutability::ReadOnly);
    let app_state_root = fixture.path().join("app-state");
    for guarded_item in [skill, plugin] {
        let plan = plan_toggle(TogglePlanRequest {
            app_state_root: app_state_root.clone(),
            item: guarded_item.clone(),
        });
        assert_eq!(plan.status, ToggleStatus::Blocked);
        assert!(plan.operations.is_empty());
    }
    assert!(!app_state_root.exists());

    let hook = result
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Claude
                && item.category == DiscoveryCategory::Hook
                && item.source_path == plugin.source_path
        })
        .expect("bundled hook inventory row");
    assert!(hook.enabled);
    assert_eq!(hook.mutability, DiscoveryMutability::ReadOnly);
    assert!(hook.hook.is_some());

    let file_hook = result
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Claude
                && item.category == DiscoveryCategory::Hook
                && item.source_path
                    == manifest_hooks_root
                        .join("hooks/hooks.json")
                        .to_string_lossy()
        })
        .expect("manifest path bundled hook inventory row");
    assert!(file_hook.enabled);
    assert_eq!(file_hook.mutability, DiscoveryMutability::ReadOnly);

    let default_hook = result
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Claude
                && item.category == DiscoveryCategory::Hook
                && item.source_path
                    == default_hooks_root
                        .join("hooks/hooks.json")
                        .to_string_lossy()
        })
        .expect("default bundled hook inventory row");
    assert!(default_hook.enabled);
    assert_eq!(default_hook.mutability, DiscoveryMutability::ReadOnly);
}

#[test]
fn invalid_plugin_hook_warning_does_not_expose_absolute_source_path() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let plugin_root = roots.claude_global.join("skills/invalid-hook-bundle");
    write_file(&plugin_root.join("SKILL.md"), "# Invalid hook bundle\n");
    write_file(
        &plugin_root.join(".claude-plugin/plugin.json"),
        r#"{"name":"invalid-hook-bundle","hooks":{"PreToolUse":123}}"#,
    );

    let result = discover_all(&roots).expect("discover fixture");
    let warning = result
        .warnings
        .iter()
        .find(|warning| {
            warning.provider == ProviderId::Claude && warning.code.starts_with("invalid-hook-")
        })
        .expect("invalid bundled hook warning");
    assert!(warning.message.contains("plugin.json"));
    assert!(
        !warning
            .message
            .contains(&fixture.path().to_string_lossy().to_string())
    );
}

#[cfg(unix)]
#[test]
fn claude_skill_directory_plugin_detection_follows_skill_root_symlinks() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let real_root = fixture.path().join("real-skill");
    let linked_root = roots.claude_global.join("skills/linked-bundle");

    write_file(&real_root.join("SKILL.md"), "# Linked bundle\n");
    write_file(
        &real_root.join(".claude-plugin/plugin.json"),
        r#"{"name":"linked-bundle"}"#,
    );
    fs::create_dir_all(linked_root.parent().expect("skills root")).expect("create skills root");
    symlink(&real_root, &linked_root).expect("link skill directory");

    let result = discover_all(&roots).expect("discover fixture");
    let plugin = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:plugin-manifest:skills-dir:linked-bundle")
        .expect("symlinked skill-directory plugin inventory row");
    assert_eq!(plugin.mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(plugin.state_path, linked_root.to_string_lossy());

    let skill = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:linked-bundle")
        .expect("symlinked bundle skill inventory row");
    assert_eq!(skill.mutability, DiscoveryMutability::ReadOnly);
}

#[test]
fn claude_plugin_validation_warnings_do_not_include_manifest_contents() {
    let fixture = tempfile::TempDir::new().expect("fixture");
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let plugin_root = roots.claude_global.join("skills/broken-bundle");
    let marker = "manifest-secret";

    write_file(&plugin_root.join("SKILL.md"), "# Broken bundle\n");
    write_file(
        &plugin_root.join(".claude-plugin/plugin.json"),
        &format!(r#"{{"description":"{marker}","#),
    );

    let result = discover_all(&roots).expect("discover fixture");
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.code == "agent-plugin-invalid")
    );
    assert!(result.warnings.iter().all(|warning| {
        !warning.message.contains(marker)
            && !warning
                .message
                .contains(&fixture.path().to_string_lossy().to_string())
    }));
}
