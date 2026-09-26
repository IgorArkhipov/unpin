use std::{fs, path::Path};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots,
    discover_all,
};

fn write_file(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("fixture file parent")).expect("fixture parent");
    fs::write(path, contents).expect("fixture file");
}

fn discover(
    home: &TempDir,
    project: &TempDir,
    cursor: &TempDir,
) -> unpin_core::discovery::DiscoveryOutput {
    let roots = DiscoveryRoots::from_locations(home.path(), project.path(), cursor.path());
    discover_all(&roots).expect("OpenCode compatibility discovery succeeds")
}

fn item<'a>(output: &'a unpin_core::discovery::DiscoveryOutput, id: &str) -> &'a DiscoveryItem {
    output
        .items
        .iter()
        .find(|candidate| candidate.id == id)
        .unwrap_or_else(|| panic!("missing discovery item {id}"))
}

fn opencode_items(
    output: &unpin_core::discovery::DiscoveryOutput,
    category: DiscoveryCategory,
) -> Vec<&DiscoveryItem> {
    output
        .items
        .iter()
        .filter(|candidate| {
            candidate.provider == unpin_core::discovery::ProviderId::OpenCode
                && candidate.category == category
        })
        .collect()
}

fn fingerprint(value: &Value) -> String {
    let serialized = serde_json::to_string(value).expect("JSON value serializes");
    let digest = Sha256::digest(serialized.as_bytes());
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[test]
fn discovers_json_and_jsonc_layers_with_effective_precedence_and_source_provenance() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let global = home.path().join(".config/opencode");

    write_file(
        &global.join("opencode.json"),
        r#"{
          "mcp": {
            "json-only": {"type": "local", "command": ["json-only"]},
            "shared": {"type": "local", "command": ["json-shared"], "enabled": true}
          },
          "plugin": ["json-plugin", "shared-plugin"],
          "skills": {"paths": ["./configured-json-skills"]}
        }"#,
    );
    write_file(
        &global.join("opencode.jsonc"),
        r#"{
          // JSONC is loaded after JSON in the same OpenCode config layer.
          "mcp": {
            "jsonc-only": {"type": "local", "command": ["jsonc-only"]},
            "shared": {"type": "local", "command": ["jsonc-shared"], "enabled": false},
          },
          "plugin": ["jsonc-plugin", ["shared-plugin", {"mode": "jsonc"}]],
        }"#,
    );
    write_file(
        &project
            .path()
            .join("configured-json-skills/custom-opencode/SKILL.md"),
        "---\nname: custom-opencode\ndescription: configured\n---\nbody\n",
    );

    let output = discover(&home, &project, &cursor);

    let json_only = item(&output, "opencode:global:configured-mcp:json-only");
    assert_eq!(json_only.layer, DiscoveryLayer::Global);
    assert!(json_only.source_path.ends_with("opencode.json"));
    assert!(json_only.enabled);

    let jsonc_only = item(&output, "opencode:global:configured-mcp:jsonc-only");
    assert_eq!(jsonc_only.layer, DiscoveryLayer::Global);
    assert!(jsonc_only.source_path.ends_with("opencode.jsonc"));
    assert!(jsonc_only.enabled);

    let shared = item(&output, "opencode:global:configured-mcp:shared");
    assert!(
        !shared.enabled,
        "the later JSONC layer must win for conflicts"
    );
    assert!(shared.source_path.ends_with("opencode.jsonc"));
    assert!(shared.source_fingerprint.is_some());

    let settings = opencode_items(&output, DiscoveryCategory::ProviderSetting);
    assert!(settings.iter().any(|setting| {
        setting.source_path.ends_with("opencode.json")
            && setting.id == "opencode:global:setting:opencode.json"
    }));
    assert!(settings.iter().any(|setting| {
        setting.source_path.ends_with("opencode.jsonc")
            && setting.id == "opencode:global:setting:opencode.jsonc"
    }));

    let json_plugin = item(&output, "opencode:global:plugin-config:npm:json-plugin");
    assert_eq!(json_plugin.category, DiscoveryCategory::PluginConfig);
    assert_eq!(json_plugin.mutability, DiscoveryMutability::ReadWrite);
    let jsonc_plugin = item(&output, "opencode:global:plugin-config:npm:jsonc-plugin");
    assert_eq!(jsonc_plugin.category, DiscoveryCategory::PluginConfig);
    assert_eq!(jsonc_plugin.mutability, DiscoveryMutability::ReadWrite);
    let shared_plugin = item(&output, "opencode:global:plugin-config:npm:shared-plugin");
    let expected_shared_plugin = json!(["shared-plugin", {"mode": "jsonc"}]);
    let expected_shared_fingerprint = fingerprint(&expected_shared_plugin);
    assert_eq!(shared_plugin.mutability, DiscoveryMutability::ReadOnly);
    assert!(shared_plugin.source_path.ends_with("opencode.jsonc"));
    assert_eq!(
        shared_plugin.source_fingerprint.as_deref(),
        Some(expected_shared_fingerprint.as_str())
    );

    let configured_skill = output
        .items
        .iter()
        .find(|candidate| {
            candidate.provider == unpin_core::discovery::ProviderId::OpenCode
                && candidate.category == DiscoveryCategory::Skill
                && candidate.display_name == "custom-opencode"
        })
        .expect("configured OpenCode skill");
    assert_eq!(configured_skill.mutability, DiscoveryMutability::ReadOnly);
    assert!(
        configured_skill
            .source_path
            .ends_with("custom-opencode/SKILL.md")
    );
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| { !warning.message.contains("plugin entries must be strings") })
    );
}

#[test]
fn recognizes_plugin_options_tuples_as_mutable_without_poisoning_other_entries() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let config = project.path().join("opencode.json");
    let tuple = json!(["tuple-plugin", {"mode": "safe", "timeout": 5}]);
    write_file(
        &config,
        &serde_json::to_string_pretty(&json!({
            "plugin": [tuple, "string-plugin"]
        }))
        .expect("plugin fixture JSON"),
    );
    write_file(
        &project.path().join("opencode.jsonc"),
        r#"{
          "plugin": ["separate-string-plugin"]
        }"#,
    );

    let output = discover(&home, &project, &cursor);
    let tuple_item = item(&output, "opencode:project:plugin-config:npm:tuple-plugin");
    let expected_tuple_fingerprint = fingerprint(&tuple);
    assert_eq!(tuple_item.display_name, "tuple-plugin");
    assert_eq!(tuple_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(tuple_item.source_path, config.to_string_lossy());
    assert_eq!(
        tuple_item.source_fingerprint.as_deref(),
        Some(expected_tuple_fingerprint.as_str())
    );

    let string_item = item(&output, "opencode:project:plugin-config:npm:string-plugin");
    assert_eq!(
        string_item.mutability,
        DiscoveryMutability::ReadWrite,
        "a valid tuple in the same plugin array must not block string entries"
    );
    assert!(string_item.source_fingerprint.is_some());
    assert!(
        output.warnings.iter().all(|warning| {
            warning.provider != unpin_core::discovery::ProviderId::OpenCode
                || !warning.message.contains("plugin entries must be strings")
        }),
        "valid tuple syntax must not be rejected as a string-only entry"
    );
    let separate_string_item = item(
        &output,
        "opencode:project:plugin-config:npm:separate-string-plugin",
    );
    assert_eq!(
        separate_string_item.mutability,
        DiscoveryMutability::ReadWrite,
        "a string-only plugin source remains independently mutable"
    );
}

#[test]
fn discovers_configured_skill_paths_as_read_only_with_resolved_provenance() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let absolute_root = TempDir::new().expect("absolute skill root");
    let home_relative_root = home.path().join("shared-opencode-skills");

    write_file(
        &project
            .path()
            .join("relative-opencode-skills/team/custom-relative/SKILL.md"),
        "---\nname: custom-relative\ndescription: relative\n---\nbody\n",
    );
    write_file(
        &home_relative_root.join("custom-home/SKILL.md"),
        "---\nname: custom-home\ndescription: home\n---\nbody\n",
    );
    write_file(
        &absolute_root.path().join("custom-absolute/SKILL.md"),
        "---\nname: custom-absolute\ndescription: absolute\n---\nbody\n",
    );
    write_file(
        &project.path().join("opencode.json"),
        &serde_json::to_string_pretty(&json!({
            "skills": {
                "paths": [
                    "./relative-opencode-skills",
                    "~/shared-opencode-skills",
                    absolute_root.path().to_string_lossy()
                ]
            }
        }))
        .expect("skills fixture JSON"),
    );

    let output = discover(&home, &project, &cursor);
    let configured = output
        .items
        .iter()
        .find(|candidate| {
            candidate.provider == unpin_core::discovery::ProviderId::OpenCode
                && candidate.category == DiscoveryCategory::Skill
                && candidate.display_name == "custom-relative"
        })
        .expect("missing configured skill custom-relative");
    assert_eq!(configured.layer, DiscoveryLayer::Project);
    assert_eq!(configured.mutability, DiscoveryMutability::ReadOnly);
    assert!(
        configured
            .source_path
            .ends_with("relative-opencode-skills/team/custom-relative/SKILL.md")
    );
    assert!(
        configured
            .state_path
            .ends_with("relative-opencode-skills/team/custom-relative")
    );

    let configured_skills = output
        .items
        .iter()
        .filter(|candidate| {
            candidate.provider == unpin_core::discovery::ProviderId::OpenCode
                && candidate.category == DiscoveryCategory::Skill
                && ["custom-relative", "custom-home", "custom-absolute"]
                    .contains(&candidate.display_name.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(configured_skills.len(), 1);
    assert_eq!(
        output
            .warnings
            .iter()
            .filter(|warning| {
                warning.provider == unpin_core::discovery::ProviderId::OpenCode
                    && warning.code == "scope-outside-project"
            })
            .count(),
        2
    );
    assert!(output.warnings.iter().all(|warning| {
        warning.provider != unpin_core::discovery::ProviderId::OpenCode
            || !warning.message.contains("skill path not found")
    }));
}

#[test]
fn global_config_can_inventory_external_skill_paths_read_only() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let external = TempDir::new().expect("external root");
    write_file(&external.path().join("global-skill/SKILL.md"), "# Global\n");
    write_file(
        &home.path().join(".config/opencode/opencode.json"),
        &serde_json::to_string(&json!({
            "skills": {"paths": [external.path().to_string_lossy()]}
        }))
        .expect("global config"),
    );

    let output = discover(&home, &project, &cursor);
    let skill = output
        .items
        .iter()
        .find(|item| {
            item.provider == unpin_core::discovery::ProviderId::OpenCode
                && item.display_name == "global-skill"
        })
        .expect("globally configured external skill");
    assert_eq!(skill.layer, DiscoveryLayer::Global);
    assert_eq!(skill.mutability, DiscoveryMutability::ReadOnly);
}

#[cfg(unix)]
#[test]
fn project_config_cannot_scan_external_or_symlinked_skill_roots() {
    use std::os::unix::fs::symlink;

    let home = TempDir::new().expect("home root");
    let fixture = TempDir::new().expect("fixture root");
    let cursor = TempDir::new().expect("cursor root");
    let project = fixture.path().join("project");
    let outside = fixture.path().join("outside");
    write_file(&outside.join("private-skill/SKILL.md"), "# Private\n");
    fs::create_dir_all(&project).expect("project directory");
    symlink(&outside, project.join("linked-skills")).expect("linked skills");
    let scoped_skills = project.join("scoped-skills");
    fs::create_dir_all(scoped_skills.join("inside")).expect("scoped skills");
    symlink(
        outside.join("private-skill"),
        scoped_skills.join("linked-child"),
    )
    .expect("linked child skill");
    symlink(
        outside.join("private-skill/SKILL.md"),
        scoped_skills.join("inside/SKILL.md"),
    )
    .expect("linked skill file");
    write_file(
        &project.join("opencode.json"),
        &serde_json::to_string(&json!({
            "skills": {"paths": [
                "../outside",
                outside.to_string_lossy(),
                "./linked-skills",
                "./scoped-skills"
            ]}
        }))
        .expect("project config"),
    );

    let roots = DiscoveryRoots::from_locations(home.path(), &project, cursor.path());
    let output = discover_all(&roots).expect("bounded project discovery");
    assert!(!output.items.iter().any(|item| {
        item.provider == unpin_core::discovery::ProviderId::OpenCode
            && item.category == DiscoveryCategory::Skill
            && item.display_name == "private-skill"
    }));
    assert_eq!(
        output
            .warnings
            .iter()
            .filter(|warning| {
                warning.provider == unpin_core::discovery::ProviderId::OpenCode
                    && warning.code == "scope-outside-project"
            })
            .count(),
        3
    );
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == unpin_core::discovery::ProviderId::OpenCode
            && matches!(
                warning.code.as_str(),
                "scope-scan-incomplete" | "scope-scan-limited"
            )
    }));
    assert!(output.warnings.iter().all(|warning| {
        !warning
            .message
            .contains(&outside.to_string_lossy().to_string())
    }));
}

#[test]
fn discovers_skill_at_configured_root() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let skill = project.path().join("direct-skill/SKILL.md");
    write_file(
        &skill,
        "---\nname: direct-skill\ndescription: direct\n---\nbody\n",
    );
    write_file(
        &project.path().join("opencode.json"),
        r#"{"skills":{"paths":["./direct-skill"]}}"#,
    );

    let output = discover(&home, &project, &cursor);
    let direct = output.items.iter().find(|candidate| {
        candidate.provider == unpin_core::discovery::ProviderId::OpenCode
            && candidate.category == DiscoveryCategory::Skill
            && candidate.display_name == "direct-skill"
            && candidate.source_path.ends_with("direct-skill/SKILL.md")
    });
    assert_eq!(
        direct.expect("configured root skill").mutability,
        DiscoveryMutability::ReadOnly
    );
}

#[test]
fn unreadable_json_candidate_does_not_hide_valid_jsonc_candidate() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    fs::write(project.path().join("opencode.json"), [0xff]).expect("invalid UTF-8 candidate");
    write_file(
        &project.path().join("opencode.jsonc"),
        r#"{"plugin":["healthy-plugin"]}"#,
    );

    let output = discover(&home, &project, &cursor);
    item(&output, "opencode:project:plugin-config:npm:healthy-plugin");
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == unpin_core::discovery::ProviderId::OpenCode
            && warning.code == "read-error"
            && !warning
                .message
                .contains(&project.path().to_string_lossy().to_string())
    }));
}

#[test]
fn configured_skill_scan_stops_at_depth_limit() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let mut deep = project.path().join("configured-skills");
    for _ in 0..34 {
        deep.push("d");
    }
    write_file(&deep.join("SKILL.md"), "# beyond configured scan limit\n");
    write_file(
        &project.path().join("opencode.json"),
        r#"{"skills":{"paths":["./configured-skills"]}}"#,
    );

    let output = discover(&home, &project, &cursor);
    assert!(!output.items.iter().any(|item| {
        item.provider == unpin_core::discovery::ProviderId::OpenCode
            && item.source_path == deep.join("SKILL.md").to_string_lossy()
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == unpin_core::discovery::ProviderId::OpenCode
            && warning.code == "scope-scan-limited"
    }));
}

#[test]
fn rejects_legacy_skill_arrays_without_disclosing_configured_paths() {
    let home = TempDir::new().expect("home root");
    let project = TempDir::new().expect("project root");
    let cursor = TempDir::new().expect("cursor root");
    let legacy_root = project.path().join("private-legacy-skills");
    let legacy_root_string = legacy_root.to_string_lossy().into_owned();
    write_file(
        &legacy_root.join("legacy-skill/SKILL.md"),
        "---\nname: legacy-skill\ndescription: legacy\n---\nbody\n",
    );
    write_file(
        &project.path().join("opencode.json"),
        &serde_json::to_string_pretty(&json!({
            "skills": [legacy_root_string.clone()]
        }))
        .expect("legacy skills fixture JSON"),
    );

    let output = discover(&home, &project, &cursor);
    assert!(!output.items.iter().any(|candidate| {
        candidate.provider == unpin_core::discovery::ProviderId::OpenCode
            && candidate.category == DiscoveryCategory::Skill
            && candidate.display_name == "legacy-skill"
    }));
    let warning = output
        .warnings
        .iter()
        .find(|warning| {
            warning.provider == unpin_core::discovery::ProviderId::OpenCode
                && warning.code == "invalid-shape"
        })
        .expect("invalid current skills object warning");
    assert_eq!(warning.message, "opencode.json skills must be an object");
    assert!(!warning.message.contains(legacy_root_string.as_str()));
}
