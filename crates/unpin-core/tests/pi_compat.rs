use std::{
    fs,
    path::{Path, PathBuf},
};

use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots, ProviderId,
    discover_all,
};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn discovers_global_and_project_configured_skills_with_external_roots_read_only() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let external_root = tempfile::TempDir::new().expect("external skill root");

    let cross_provider_skill = fixture_copy
        .path()
        .join("claude/global/skills/pi-foreign/SKILL.md");
    write_skill(&cross_provider_skill, "Pi Foreign");
    let global_settings = fixture_copy.path().join("pi/global/settings.json");
    fs::write(
        &global_settings,
        r#"{"skills":["./extra-skills","./extra-skills/../extra-skills","../../claude/global/skills/pi-foreign"]}"#,
    )
    .expect("write global Pi settings");
    write_skill(
        &fixture_copy
            .path()
            .join("pi/global/extra-skills/custom-pi/SKILL.md"),
        "Custom Pi",
    );

    let project_settings = fixture_copy.path().join("pi/project/.pi/settings.json");
    let external_skills = external_root.path().join("external-skills");
    fs::write(
        &project_settings,
        serde_json::to_vec(&serde_json::json!({
            "skills": ["./extra-skills", external_skills],
        }))
        .expect("serialize project Pi settings"),
    )
    .expect("write project Pi settings");
    write_skill(
        &fixture_copy
            .path()
            .join("pi/project/.pi/extra-skills/project-pi/SKILL.md"),
        "Project Pi",
    );
    write_skill(&external_skills.join("external-pi/SKILL.md"), "External Pi");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");

    let global = result
        .items
        .iter()
        .find(|item| {
            item.source_path
                .ends_with("pi/global/extra-skills/custom-pi/SKILL.md")
        })
        .expect("configured global skill");
    assert_eq!(global.provider, ProviderId::Pi);
    assert_eq!(global.category, DiscoveryCategory::Skill);
    assert_eq!(global.layer, DiscoveryLayer::Global);
    assert!(global.id.starts_with("pi:global:skill:@settings/"));
    assert_eq!(global.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(
        result
            .items
            .iter()
            .filter(|item| {
                item.provider == ProviderId::Pi
                    && item
                        .source_path
                        .ends_with("pi/global/extra-skills/custom-pi/SKILL.md")
            })
            .count(),
        1,
        "duplicate normalized settings roots must not duplicate a Pi item"
    );

    let project = result
        .items
        .iter()
        .find(|item| {
            item.source_path
                .ends_with("pi/project/.pi/extra-skills/project-pi/SKILL.md")
        })
        .expect("configured project skill");
    assert_eq!(project.provider, ProviderId::Pi);
    assert_eq!(project.category, DiscoveryCategory::Skill);
    assert_eq!(project.layer, DiscoveryLayer::Project);
    assert!(project.id.starts_with("pi:project:skill:@settings/"));
    assert_eq!(project.mutability, DiscoveryMutability::ReadWrite);

    let external_source = external_root
        .path()
        .join("external-skills/external-pi/SKILL.md");
    assert!(!result.items.iter().any(|item| {
        item.provider == ProviderId::Pi && item.source_path == external_source.to_string_lossy()
    }));
    assert!(result.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi
            && warning.layer == Some(DiscoveryLayer::Project)
            && warning.code == "scope-outside-project"
    }));

    let foreign_items = result
        .items
        .iter()
        .filter(|item| item.source_path == cross_provider_skill.to_string_lossy())
        .collect::<Vec<_>>();
    assert!(
        foreign_items
            .iter()
            .any(|item| item.provider == ProviderId::Pi),
        "Pi configured view must survive a shared source path"
    );
    let foreign_pi = foreign_items
        .iter()
        .find(|item| item.provider == ProviderId::Pi)
        .expect("Pi configured view");
    assert_ne!(
        global.id, foreign_pi.id,
        "distinct normalized settings roots need distinct scoped IDs"
    );
    assert!(
        foreign_items
            .iter()
            .any(|item| item.provider == ProviderId::Claude),
        "cross-provider skill view must remain discoverable"
    );

    let global_id = global.id.clone();
    fs::write(
        &global_settings,
        r#"{"skills":["../../claude/global/skills/pi-foreign","./extra-skills"]}"#,
    )
    .expect("reorder global Pi settings");
    let reordered = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("reordered discovery succeeds");
    let reordered_global = reordered
        .items
        .iter()
        .find(|item| {
            item.source_path
                .ends_with("pi/global/extra-skills/custom-pi/SKILL.md")
        })
        .expect("reordered configured global skill");
    assert_eq!(reordered_global.id, global_id);
    assert!(result.warnings.iter().all(|warning| {
        warning.code == "scope-outside-project"
            && !warning
                .message
                .contains(&external_root.path().to_string_lossy().to_string())
    }));
}

#[test]
fn absent_packages_are_valid_but_wrong_type_packages_warn() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());

    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    fs::write(
        &settings_path,
        r#"{"skills":["./extra-skills"],"packages":{"not":"an array"}}"#,
    )
    .expect("write malformed Pi settings");
    write_skill(
        &fixture_copy
            .path()
            .join("pi/global/extra-skills/custom-pi/SKILL.md"),
        "Custom Pi",
    );

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");

    assert!(result.items.iter().any(|item| {
        item.provider == ProviderId::Pi
            && item
                .source_path
                .ends_with("pi/global/extra-skills/custom-pi/SKILL.md")
    }));
    let warning = result
        .warnings
        .iter()
        .find(|warning| {
            warning.provider == ProviderId::Pi
                && warning.layer == Some(DiscoveryLayer::Global)
                && warning.code == "invalid-shape"
        })
        .expect("wrong-type packages warning");
    assert!(warning.message.contains("packages must be an array"));
    assert!(
        !warning
            .message
            .contains(&fixture_copy.path().to_string_lossy().to_string())
    );
}

#[test]
fn configured_skill_scan_stops_at_depth_limit() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings = fixture_copy.path().join("pi/project/.pi/settings.json");
    fs::write(&settings, r#"{"skills":["./configured-skills"]}"#)
        .expect("write project Pi settings");
    let mut deep = fixture_copy.path().join("pi/project/.pi/configured-skills");
    for _ in 0..34 {
        deep.push("d");
    }
    write_skill(&deep.join("SKILL.md"), "Too Deep");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    assert!(!output.items.iter().any(|item| {
        item.provider == ProviderId::Pi
            && item.source_path == deep.join("SKILL.md").to_string_lossy()
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-scan-limited"
    }));
}

#[cfg(unix)]
#[test]
fn project_settings_cannot_scan_external_or_symlinked_skill_roots() {
    use std::os::unix::fs::symlink;

    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let outside = fixture_copy.path().join("pi/outside");
    write_skill(&outside.join("private-skill/SKILL.md"), "Private Pi");
    symlink(&outside, project.join(".pi/linked-skills")).expect("linked skills");
    let scoped_skills = project.join(".pi/scoped-skills");
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
    fs::write(
        project.join(".pi/settings.json"),
        serde_json::to_vec(&serde_json::json!({
            "skills": ["../../outside", outside, "./linked-skills", "./scoped-skills"]
        }))
        .expect("project Pi config"),
    )
    .expect("write Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded project discovery");
    assert!(!output.items.iter().any(|item| {
        item.provider == ProviderId::Pi
            && item.layer == DiscoveryLayer::Project
            && item.display_name == "private-skill"
    }));
    assert_eq!(
        output
            .warnings
            .iter()
            .filter(|warning| {
                warning.provider == ProviderId::Pi
                    && warning.layer == Some(DiscoveryLayer::Project)
                    && warning.code == "scope-outside-project"
            })
            .count(),
        3
    );
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi
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

fn copy_dir_all(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("copy fixture file");
        }
    }
}

fn write_skill(path: &Path, name: &str) {
    fs::create_dir_all(path.parent().expect("skill parent")).expect("create skill parent");
    fs::write(
        path,
        format!(
            "---\nname: {name}\ndescription: Synthetic compatibility fixture.\n---\nNever execute anything.\n"
        ),
    )
    .expect("write skill fixture");
}
