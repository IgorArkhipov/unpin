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
fn project_configured_markdown_files_stay_within_project_boundary() {
    use std::os::unix::fs::symlink;

    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let outside = fixture_copy.path().join("private.md");
    fs::write(&outside, "private content").expect("outside file");
    let configured = project.join(".pi/markdown-skills");
    fs::create_dir_all(&configured).expect("configured directory");
    symlink(&outside, configured.join("linked.md")).expect("linked markdown");
    symlink(&outside, project.join(".pi/direct-linked.md")).expect("direct linked markdown");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills","./direct-linked.md"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded project discovery");
    assert!(output.items.iter().all(|item| {
        item.provider != ProviderId::Pi || !item.source_path.ends_with("linked.md")
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-outside-project"
    }));
    assert!(output.warnings.iter().all(|warning| {
        !warning
            .message
            .contains(&outside.to_string_lossy().to_string())
    }));
}

#[test]
fn configured_markdown_directory_has_a_fingerprint_budget() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let directory = project.join(".pi/markdown-skills");
    fs::create_dir_all(&directory).expect("configured directory");
    fs::write(directory.join("large.md"), vec![b'x'; 8 * 1024 * 1024 + 1]).expect("large markdown");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded project discovery");
    assert!(output.items.iter().all(|item| {
        item.provider != ProviderId::Pi || !item.source_path.ends_with("markdown-skills/large.md")
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-scan-limited"
    }));
}

#[test]
fn configured_markdown_directory_applies_aggregate_byte_budget() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let directory = project.join(".pi/markdown-skills");
    fs::create_dir_all(&directory).expect("configured directory");
    fs::write(directory.join("a.md"), vec![b'a'; 5 * 1024 * 1024]).expect("first skill");
    fs::write(directory.join("b.md"), vec![b'b'; 4 * 1024 * 1024]).expect("over-budget skill");
    fs::write(directory.join("c.md"), "# Small\n").expect("small neighbor");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded project discovery");
    let has_skill = |name: &str| {
        output.items.iter().any(|item| {
            item.provider == ProviderId::Pi
                && item
                    .source_path
                    .ends_with(&format!("markdown-skills/{name}.md"))
        })
    };
    assert!(has_skill("a"));
    assert!(!has_skill("b"));
    assert!(
        has_skill("c"),
        "a valid neighbor must survive an over-budget file"
    );
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-scan-limited"
    }));
}

#[test]
fn configured_markdown_directory_applies_entry_budget() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let directory = project.join(".pi/markdown-skills");
    fs::create_dir_all(&directory).expect("configured directory");
    for index in 0..4097 {
        fs::write(directory.join(format!("{index:04}.md")), "# Small\n").expect("markdown skill");
    }
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded project discovery");
    assert_eq!(
        output
            .items
            .iter()
            .filter(|item| {
                item.provider == ProviderId::Pi
                    && item.source_path.contains("markdown-skills/")
                    && item.source_path.ends_with(".md")
            })
            .count(),
        4096
    );
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-scan-limited"
    }));
}

#[test]
fn configured_skill_patterns_follow_pi_override_precedence() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let collection = project.join(".pi/collection");
    for name in ["regular", "private", "restored", "blocked"] {
        write_skill(&collection.join(name).join("SKILL.md"), name);
    }
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./collection","./collection/*","!./collection/private","!./collection/restored","+./collection/restored","-./collection/blocked"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discover configured Pi skills");
    let skill = |name: &str| {
        output
            .items
            .iter()
            .find(|item| {
                item.provider == ProviderId::Pi
                    && item.layer == DiscoveryLayer::Project
                    && item
                        .source_path
                        .ends_with(&format!("collection/{name}/SKILL.md"))
            })
            .unwrap_or_else(|| panic!("missing Pi skill {name}"))
    };
    assert!(skill("regular").enabled);
    assert!(!skill("private").enabled);
    assert!(skill("restored").enabled);
    assert!(!skill("blocked").enabled);
    assert_eq!(skill("restored").mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(skill("private").mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(skill("blocked").mutability, DiscoveryMutability::ReadOnly);
}

#[test]
fn configured_direct_markdown_patterns_follow_pi_override_precedence() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let directory = project.join(".pi/markdown-skills");
    fs::create_dir_all(&directory).expect("markdown skills");
    for name in ["regular", "private", "restored", "blocked"] {
        fs::write(directory.join(format!("{name}.md")), format!("# {name}\n"))
            .expect("markdown skill");
    }
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills","./markdown-skills/*.md","!./markdown-skills/private.md","!./markdown-skills/restored.md","+./markdown-skills/restored.md","-./markdown-skills/blocked.md"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discover direct Pi Markdown skills");
    let skill = |name: &str| {
        output
            .items
            .iter()
            .find(|item| {
                item.provider == ProviderId::Pi
                    && item.layer == DiscoveryLayer::Project
                    && item
                        .source_path
                        .ends_with(&format!("markdown-skills/{name}.md"))
            })
            .unwrap_or_else(|| panic!("missing direct Pi Markdown skill {name}"))
    };
    assert!(skill("regular").enabled);
    assert!(!skill("private").enabled);
    assert!(skill("restored").enabled);
    assert!(!skill("blocked").enabled);
    for name in ["regular", "private", "restored", "blocked"] {
        assert_eq!(skill(name).mutability, DiscoveryMutability::ReadOnly);
    }
}

#[cfg(unix)]
#[test]
fn malformed_markdown_entry_does_not_abort_pi_discovery() {
    use std::os::unix::fs::symlink;

    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let directory = project.join(".pi/markdown-skills");
    fs::create_dir_all(&directory).expect("markdown skills");
    fs::write(directory.join("good.md"), "# Good\n").expect("good skill");
    symlink("loop.md", directory.join("loop.md")).expect("self-linked skill");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./markdown-skills"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery continues past malformed entry");
    assert!(output.items.iter().any(|item| {
        item.provider == ProviderId::Pi && item.source_path.ends_with("markdown-skills/good.md")
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "scope-scan-incomplete"
    }));
}

#[test]
fn configured_patterns_override_pi_native_skill_view() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    write_skill(&project.join(".pi/skills/hidden/SKILL.md"), "Hidden");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./skills","!./skills/hidden"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discover Pi native skill");
    let hidden = output
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Pi
                && item.layer == DiscoveryLayer::Project
                && item.source_path.ends_with(".pi/skills/hidden/SKILL.md")
        })
        .expect("native Pi skill row");
    assert!(!hidden.enabled);
    assert_eq!(hidden.mutability, DiscoveryMutability::ReadOnly);
}

#[test]
fn pattern_disabled_pi_skill_does_not_duplicate_stale_vault_identity() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    let app_state = tempfile::TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let collection = project.join(".pi/collection");
    write_skill(&collection.join("active/SKILL.md"), "Active");
    write_skill(&collection.join("hidden/SKILL.md"), "Hidden");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./collection","!./collection/hidden"]}"#,
    )
    .expect("project Pi settings");
    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let before = discover_all(&roots).expect("discover configured Pi skills");
    let hidden = before
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Pi
                && item.layer == DiscoveryLayer::Project
                && item.id.contains("@settings/")
                && item.source_path.ends_with("collection/hidden/SKILL.md")
        })
        .expect("configured hidden skill");
    assert!(!hidden.enabled);

    let encoded_id = hidden
        .id
        .bytes()
        .enumerate()
        .map(|(index, byte)| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'
                if byte != b'.' || index != 0 =>
            {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect::<String>();
    let vault_entry = app_state
        .path()
        .join("vault/pi/project/skill")
        .join(encoded_id);
    let payload = vault_entry.join("payload");
    write_skill(&payload.join("SKILL.md"), "Hidden");
    fs::write(
        vault_entry.join("entry.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "provider": "pi",
            "kind": "skill",
            "layer": "project",
            "itemId": hidden.id,
            "displayName": hidden.display_name,
            "originalPath": collection.join("hidden"),
            "vaultedPath": payload,
            "payloadKind": "path"
        }))
        .expect("serialize vault entry"),
    )
    .expect("vault entry");

    let after = discover_all(&roots).expect("discover conflicting Pi vault");
    assert_eq!(
        after
            .items
            .iter()
            .filter(|item| item.id == hidden.id)
            .count(),
        1,
        "physical Pi skill must suppress stale vault identity"
    );
    assert!(after.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "invalid-vault-entry"
    }));
}

#[test]
fn wildcard_only_pi_settings_entry_does_not_invent_loaded_skills() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    write_skill(&project.join(".pi/team-one/SKILL.md"), "Team One");
    fs::write(
        project.join(".pi/settings.json"),
        r#"{"skills":["./team-*"]}"#,
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discover Pi project");
    assert!(output.items.iter().all(|item| {
        item.provider != ProviderId::Pi || !item.source_path.ends_with("team-one/SKILL.md")
    }));
}

#[test]
fn excessive_pi_skill_rules_leave_configured_skills_read_only() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    let collection = project.join(".pi/collection");
    write_skill(&collection.join("one/SKILL.md"), "One");
    let mut skills = vec!["./collection".to_string()];
    skills.extend(std::iter::repeat_n("./collection/*".to_string(), 513));
    fs::write(
        project.join(".pi/settings.json"),
        serde_json::to_vec(&serde_json::json!({ "skills": skills }))
            .expect("serialize Pi settings"),
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded Pi rule discovery");
    let skill = output
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Pi && item.source_path.ends_with("collection/one/SKILL.md")
        })
        .expect("configured skill");
    assert_eq!(skill.mutability, DiscoveryMutability::ReadOnly);
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "pi-skill-rules-limited"
    }));
}

#[test]
fn oversized_pi_skill_rule_leaves_configured_skills_read_only() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let project = fixture_copy.path().join("pi/project");
    write_skill(&project.join(".pi/collection/one/SKILL.md"), "One");
    fs::write(
        project.join(".pi/settings.json"),
        serde_json::to_vec(&serde_json::json!({
            "skills": ["./collection", format!("+{}", "x".repeat(65 * 1024))]
        }))
        .expect("serialize Pi settings"),
    )
    .expect("project Pi settings");

    let output = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("bounded Pi rule discovery");
    let skill = output
        .items
        .iter()
        .find(|item| {
            item.provider == ProviderId::Pi && item.source_path.ends_with("collection/one/SKILL.md")
        })
        .expect("configured skill");
    assert_eq!(skill.mutability, DiscoveryMutability::ReadOnly);
    assert!(output.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Pi && warning.code == "pi-skill-rules-limited"
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
