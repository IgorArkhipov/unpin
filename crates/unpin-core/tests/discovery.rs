use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots,
    ProviderId, discover_all,
};
use unpin_core::hooks::{HookActionType, HookFailurePolicy, HookMatcherMode, HookRouteOwner};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn discovers_current_provider_and_shared_skill_roots() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    let codex_admin_root = tempfile::TempDir::new().expect("temp Codex admin root");

    for (relative_path, heading) in [
        (".claude/skills/claude-global/SKILL.md", "Claude Global"),
        (".agents/skills/shared-global/SKILL.md", "Shared Global"),
        (".cursor/skills/cursor-global/SKILL.md", "Cursor Global"),
        (".pi/agent/skills/workflows/pi-global/SKILL.md", "Pi Global"),
        (".pi/agent/skills/pi-file.md", "Pi File"),
        (
            ".config/opencode/skills/opencode-global/SKILL.md",
            "OpenCode Global",
        ),
        (
            ".codex/skills/legacy-global/SKILL.md",
            "Legacy Codex Global",
        ),
    ] {
        write_file(
            &home_root.path().join(relative_path),
            &format!("# {heading}\n"),
        );
    }
    for (relative_path, heading) in [
        (".claude/skills/claude-project/SKILL.md", "Claude Project"),
        (".agents/skills/shared-project/SKILL.md", "Shared Project"),
        (".cursor/skills/cursor-project/SKILL.md", "Cursor Project"),
        (".pi/skills/pi-project/SKILL.md", "Pi Project"),
        (".pi/skills/pi-project-file.md", "Pi Project File"),
        (
            ".opencode/skills/opencode-project/SKILL.md",
            "OpenCode Project",
        ),
        (
            ".codex/skills/legacy-project/SKILL.md",
            "Legacy Codex Project",
        ),
    ] {
        write_file(
            &project_root.path().join(relative_path),
            &format!("# {heading}\n"),
        );
    }
    write_file(
        &codex_admin_root.path().join("skills/codex-admin/SKILL.md"),
        "# Codex Admin\n",
    );

    let mut roots =
        DiscoveryRoots::from_locations(home_root.path(), project_root.path(), cursor_root.path());
    roots.codex_admin = codex_admin_root.path().to_path_buf();
    let result = discover_all(&roots).expect("discovery succeeds");

    let cases = [
        (
            "claude:global:skill:claude-global",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-global/SKILL.md",
        ),
        (
            "claude:project:skill:claude-project",
            ProviderId::Claude,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-project/SKILL.md",
        ),
        (
            "codex:global:skill:shared-global",
            ProviderId::Codex,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-global/SKILL.md",
        ),
        (
            "codex:global:skill:admin/codex-admin",
            ProviderId::Codex,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "skills/codex-admin/SKILL.md",
        ),
        (
            "codex:project:skill:shared-project",
            ProviderId::Codex,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-project/SKILL.md",
        ),
        (
            "cursor:global:skill:cursor-global",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".cursor/skills/cursor-global/SKILL.md",
        ),
        (
            "cursor:project:skill:cursor-project",
            ProviderId::Cursor,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".cursor/skills/cursor-project/SKILL.md",
        ),
        (
            "cursor:global:skill:@compat/agents/shared-global",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-global/SKILL.md",
        ),
        (
            "cursor:project:skill:@compat/agents/shared-project",
            ProviderId::Cursor,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-project/SKILL.md",
        ),
        (
            "cursor:global:skill:@compat/claude/claude-global",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-global/SKILL.md",
        ),
        (
            "cursor:project:skill:@compat/claude/claude-project",
            ProviderId::Cursor,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-project/SKILL.md",
        ),
        (
            "cursor:global:skill:@compat/codex/legacy-global",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".codex/skills/legacy-global/SKILL.md",
        ),
        (
            "cursor:project:skill:@compat/codex/legacy-project",
            ProviderId::Cursor,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".codex/skills/legacy-project/SKILL.md",
        ),
        (
            "zed:global:skill:shared-global",
            ProviderId::Zed,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-global/SKILL.md",
        ),
        (
            "zed:project:skill:shared-project",
            ProviderId::Zed,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-project/SKILL.md",
        ),
        (
            "pi:global:skill:workflows/pi-global",
            ProviderId::Pi,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".pi/agent/skills/workflows/pi-global/SKILL.md",
        ),
        (
            "pi:project:skill:pi-project",
            ProviderId::Pi,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".pi/skills/pi-project/SKILL.md",
        ),
        (
            "pi:global:skill:@file/pi-file",
            ProviderId::Pi,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".pi/agent/skills/pi-file.md",
        ),
        (
            "pi:project:skill:@file/pi-project-file",
            ProviderId::Pi,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".pi/skills/pi-project-file.md",
        ),
        (
            "pi:global:skill:@compat/agents/shared-global",
            ProviderId::Pi,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-global/SKILL.md",
        ),
        (
            "pi:project:skill:@compat/agents/shared-project",
            ProviderId::Pi,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-project/SKILL.md",
        ),
        (
            "opencode:global:skill:opencode-global",
            ProviderId::OpenCode,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".config/opencode/skills/opencode-global/SKILL.md",
        ),
        (
            "opencode:project:skill:opencode-project",
            ProviderId::OpenCode,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".opencode/skills/opencode-project/SKILL.md",
        ),
        (
            "opencode:global:skill:@compat/agents/shared-global",
            ProviderId::OpenCode,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-global/SKILL.md",
        ),
        (
            "opencode:project:skill:@compat/agents/shared-project",
            ProviderId::OpenCode,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".agents/skills/shared-project/SKILL.md",
        ),
        (
            "opencode:global:skill:@compat/claude/claude-global",
            ProviderId::OpenCode,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-global/SKILL.md",
        ),
        (
            "opencode:project:skill:@compat/claude/claude-project",
            ProviderId::OpenCode,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            ".claude/skills/claude-project/SKILL.md",
        ),
    ];

    for (id, provider, layer, mutability, path_suffix) in cases {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));
        assert_eq!(item.provider, provider, "{id} provider");
        assert_eq!(item.layer, layer, "{id} layer");
        assert_eq!(item.mutability, mutability, "{id} mutability");
        assert!(item.source_path.ends_with(path_suffix), "{id} source path");
    }

    assert!(
        result
            .items
            .iter()
            .all(|item| { item.provider == ProviderId::Cursor || !item.id.contains("legacy-") }),
        "historical .codex/skills roots must remain ignored by providers other than Cursor's current compatibility loader; got {:#?}",
        result.items
    );
}

#[test]
fn discovers_recursive_cursor_skill_roots_with_stable_scoped_ids() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let repository_root = tempfile::TempDir::new().expect("temp repository root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(
        &repository_root.path().join(".git"),
        "gitdir: /tmp/example.git\n",
    );

    for (relative_path, heading) in [
        (
            ".cursor/skills/workflows/native-global/SKILL.md",
            "Native Global",
        ),
        (
            ".agents/skills/team/shared-global/SKILL.md",
            "Shared Global",
        ),
        (
            ".claude/skills/team/claude-global/SKILL.md",
            "Claude Global",
        ),
        (".codex/skills/team/codex-global/SKILL.md", "Codex Global"),
    ] {
        write_file(
            &home_root.path().join(relative_path),
            &format!("# {heading}\n"),
        );
    }

    let package_root = repository_root.path().join("packages/app");
    for (relative_path, heading) in [
        (
            ".cursor/skills/workflows/native-project/SKILL.md",
            "Native Project",
        ),
        (
            ".agents/skills/team/shared-project/SKILL.md",
            "Shared Project",
        ),
        (
            ".claude/skills/team/claude-project/SKILL.md",
            "Claude Project",
        ),
        (".codex/skills/team/codex-project/SKILL.md", "Codex Project"),
    ] {
        write_file(&package_root.join(relative_path), &format!("# {heading}\n"));
    }

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        repository_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    for (id, mutability) in [
        (
            "cursor:global:skill:workflows/native-global",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:global:skill:@compat/agents/team/shared-global",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:global:skill:@compat/claude/team/claude-global",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:global:skill:@compat/codex/team/codex-global",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:project:skill:@scope/packages/app/workflows/native-project",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:project:skill:@compat/agents/@scope/packages/app/team/shared-project",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:project:skill:@compat/claude/@scope/packages/app/team/claude-project",
            DiscoveryMutability::ReadWrite,
        ),
        (
            "cursor:project:skill:@compat/codex/@scope/packages/app/team/codex-project",
            DiscoveryMutability::ReadWrite,
        ),
    ] {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));
        assert_eq!(item.provider, ProviderId::Cursor, "{id} provider");
        assert_eq!(item.mutability, mutability, "{id} mutability");
    }

    assert_eq!(
        result
            .items
            .iter()
            .filter(|item| item.provider == ProviderId::Cursor)
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        result
            .items
            .iter()
            .filter(|item| item.provider == ProviderId::Cursor)
            .count(),
        "recursive Cursor skill ids must remain unique"
    );
}

#[test]
fn cursor_native_and_compatibility_skill_ids_cannot_collide() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(
        &home_root
            .path()
            .join(".cursor/skills/@compat/agents/collision/SKILL.md"),
        "# Native Cursor Skill\n",
    );
    write_file(
        &home_root.path().join(".agents/skills/collision/SKILL.md"),
        "# Compatibility Skill\n",
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    for id in [
        "cursor:global:skill:%40compat/agents/collision",
        "cursor:global:skill:@compat/agents/collision",
    ] {
        let matches = result.items.iter().filter(|item| item.id == id).count();
        assert_eq!(matches, 1, "{id} must identify exactly one source");
    }
}

#[cfg(unix)]
#[test]
fn recursive_cursor_skill_scan_warns_and_continues_past_unreadable_categories() {
    use std::os::unix::fs::PermissionsExt as _;

    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(
        &home_root.path().join(".cursor/skills/readable/SKILL.md"),
        "# Readable\n",
    );
    let unreadable = home_root.path().join(".cursor/skills/private");
    fs::create_dir_all(&unreadable).expect("create unreadable category");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
        .expect("make category unreadable");
    if fs::read_dir(&unreadable).is_ok() {
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700))
            .expect("restore category permissions");
        return;
    }

    let discovery = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ));
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700))
        .expect("restore category permissions");
    let result = discovery.expect("unreadable category should not abort discovery");

    assert!(result.items.iter().any(|item| {
        item.id == "cursor:global:skill:readable"
            && item.mutability == DiscoveryMutability::ReadWrite
    }));
    assert!(result.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Cursor
            && warning.layer == Some(DiscoveryLayer::Global)
            && warning.code == "scope-scan-incomplete"
            && !warning
                .message
                .contains(unreadable.to_string_lossy().as_ref())
    }));
}

#[test]
fn applies_codex_native_config_state_only_to_non_shared_skills() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let shared_skill_path = fixture_copy
        .path()
        .join("shared/global/.agents/skills/example-shared-global-skill/SKILL.md");
    let admin_skill_path = fixture_copy
        .path()
        .join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let config = fs::read_to_string(&config_path).expect("Codex config fixture");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]] # stale shared override\npath = {:?}\nenabled = false\n\n[[skills.config]] # native override\npath = {:?}\nenabled = false\n",
            shared_skill_path.to_string_lossy(),
            admin_skill_path.to_string_lossy(),
        ),
    )
    .expect("write Codex skill config");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    let codex_item = result
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:example-shared-global-skill")
        .expect("Codex shared skill");
    assert!(codex_item.enabled);
    assert_eq!(codex_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(codex_item.source_path, shared_skill_path.to_string_lossy());
    assert_ne!(codex_item.state_path, config_path.to_string_lossy());

    let cursor_item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:@compat/agents/example-shared-global-skill")
        .expect("Cursor view of shared skill");
    assert!(cursor_item.enabled);
    assert_eq!(cursor_item.mutability, DiscoveryMutability::ReadWrite);
    assert_ne!(cursor_item.state_path, config_path.to_string_lossy());

    let admin_item = result
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex admin skill");
    assert!(!admin_item.enabled);
    assert_eq!(admin_item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(admin_item.source_path, admin_skill_path.to_string_lossy());
    assert_eq!(admin_item.state_path, config_path.to_string_lossy());
    assert!(result.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Codex
            && warning.layer == Some(DiscoveryLayer::Global)
            && warning.code == "shared-skill-native-config-ignored"
            && warning
                .message
                .contains(shared_skill_path.to_string_lossy().as_ref())
    }));
}

#[test]
fn malformed_codex_skill_config_warns_and_keeps_skill_inventory_available() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let config = fs::read_to_string(&config_path).expect("Codex config fixture");
    fs::write(
        &config_path,
        format!("{config}\n[[skills.config]]\npath = 42\nenabled = false\n"),
    )
    .expect("write malformed Codex skill config");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:example-shared-global-skill")
        .expect("Codex skill remains discoverable");
    assert!(item.enabled);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert!(result.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Codex
            && warning.code == "toml-parse-error"
            && warning
                .message
                .contains("path must be a quoted TOML string")
    }));
}

#[test]
fn malformed_codex_skill_enabled_value_is_redacted_from_warning() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let skill_path = fixture_copy
        .path()
        .join("shared/global/.agents/skills/example-shared-global-skill/SKILL.md");
    let config_path = fixture_copy.path().join("codex/global/config.toml");
    let config = fs::read_to_string(&config_path).expect("Codex config fixture");
    fs::write(
        &config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = sensitive-token\n",
            skill_path.to_string_lossy()
        ),
    )
    .expect("write malformed Codex skill state");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    let warning = result
        .warnings
        .iter()
        .find(|warning| warning.provider == ProviderId::Codex && warning.code == "toml-parse-error")
        .expect("Codex warning");
    assert_eq!(
        warning.message,
        "Codex skills.config could not be read: enabled must be true or false"
    );
    assert!(!warning.message.contains("sensitive-token"));
}

#[test]
fn discovers_project_skills_from_cwd_to_repository_root() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let repository_parent = tempfile::TempDir::new().expect("temp repository parent");
    let repository_root = repository_parent.path().join("repository");
    let apps_root = repository_root.join("apps");
    let project_root = apps_root.join("api");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(&repository_root.join(".git"), "gitdir: /tmp/example.git\n");

    for (base, scope_name) in [
        (repository_root.as_path(), "root"),
        (apps_root.as_path(), "apps"),
        (project_root.as_path(), "current"),
    ] {
        write_file(
            &base.join(format!(".claude/skills/{scope_name}-claude/SKILL.md")),
            &format!("# {scope_name} Claude\n"),
        );
        write_file(
            &base.join(format!(".agents/skills/{scope_name}-shared/SKILL.md")),
            &format!("# {scope_name} Shared\n"),
        );
        write_file(
            &base.join(format!(".cursor/skills/{scope_name}-cursor/SKILL.md")),
            &format!("# {scope_name} Cursor\n"),
        );
    }
    let descendant_root = project_root.join("packages").join("feature");
    write_file(
        &descendant_root.join(".claude/skills/descendant-claude/SKILL.md"),
        "# Descendant Claude\n",
    );
    write_file(
        &descendant_root.join(".agents/skills/descendant-shared/SKILL.md"),
        "# Descendant Shared\n",
    );
    let sibling_root = repository_root.join("tools");
    write_file(
        &sibling_root.join(".claude/skills/sibling-claude/SKILL.md"),
        "# Sibling Claude\n",
    );
    write_file(
        &sibling_root.join(".cursor/skills/repository-cursor/SKILL.md"),
        "# Repository Cursor\n",
    );
    write_file(
        &sibling_root.join(".agents/skills/repository-shared/SKILL.md"),
        "# Repository Shared\n",
    );
    write_file(
        &repository_root.join(".claude/skills/collision/SKILL.md"),
        "# Root Collision\n",
    );
    write_file(
        &apps_root.join(".claude/skills/collision/SKILL.md"),
        "# Apps Collision\n",
    );
    write_file(
        &repository_root.join(".claude/skills/@scope/SKILL.md"),
        "# Reserved ID Segment\n",
    );
    write_file(
        &repository_parent
            .path()
            .join(".claude/skills/outside/SKILL.md"),
        "# Outside\n",
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        &project_root,
        cursor_root.path(),
    ))
    .expect("discovery succeeds");
    let ids = result
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids.iter().copied().collect::<BTreeSet<_>>().len(),
        ids.len(),
        "scoped skill ids must remain unique; got {ids:#?}"
    );

    for expected in [
        "claude:project:skill:root-claude",
        "claude:project:skill:@scope/apps/apps-claude",
        "claude:project:skill:@scope/apps/api/current-claude",
        "claude:project:skill:@scope/apps/api/packages/feature/descendant-claude",
        "claude:project:skill:collision",
        "claude:project:skill:@scope/apps/collision",
        "claude:project:skill:%40scope",
        "codex:project:skill:root-shared",
        "codex:project:skill:@scope/apps/apps-shared",
        "codex:project:skill:@scope/apps/api/current-shared",
        "cursor:project:skill:root-cursor",
        "cursor:project:skill:@scope/apps/apps-cursor",
        "cursor:project:skill:@scope/apps/api/current-cursor",
        "cursor:project:skill:@scope/tools/repository-cursor",
        "cursor:project:skill:@compat/agents/root-shared",
        "cursor:project:skill:@compat/agents/@scope/apps/apps-shared",
        "cursor:project:skill:@compat/agents/@scope/apps/api/current-shared",
        "cursor:project:skill:@compat/agents/@scope/apps/api/packages/feature/descendant-shared",
        "cursor:project:skill:@compat/agents/@scope/tools/repository-shared",
    ] {
        assert!(ids.contains(&expected), "missing {expected}; got {ids:#?}");
    }
    assert!(
        ids.iter().all(|id| !id.contains("outside")),
        "ancestor scanning must stop at repository root; got {ids:#?}"
    );
    for unexpected in [
        "claude:project:skill:@scope/tools/sibling-claude",
        "codex:project:skill:@scope/apps/api/packages/feature/descendant-shared",
        "codex:project:skill:@scope/tools/repository-shared",
        "zed:project:skill:descendant-shared",
        "zed:project:skill:repository-shared",
    ] {
        assert!(
            !ids.contains(&unexpected),
            "provider scope should exclude {unexpected}; got {ids:#?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn discovers_only_direct_skills_and_allows_provider_owned_symlinks() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    let bundle_root = tempfile::TempDir::new().expect("temp bundle root");
    let linked_skill_root = tempfile::TempDir::new().expect("temp linked skill root");
    let linked_file_root = tempfile::TempDir::new().expect("temp linked file root");
    let linked_project_skills_root =
        tempfile::TempDir::new().expect("temp linked project skills root");
    let linked_scope_root = tempfile::TempDir::new().expect("temp linked scope root");
    let claude_skills = home_root.path().join(".claude").join("skills");
    fs::create_dir_all(&claude_skills).expect("create Claude skills root");
    write_file(
        &bundle_root
            .path()
            .join(".agents/skills/bundled-skill/SKILL.md"),
        "# Bundled Skill\n",
    );
    write_file(
        &claude_skills.join("container/nested-skill/SKILL.md"),
        "# Nested Skill\n",
    );
    write_file(
        &linked_skill_root.path().join("SKILL.md"),
        "# Linked Skill\n",
    );
    write_file(
        &linked_file_root.path().join("skill-body.md"),
        "# Linked Skill File\n",
    );
    write_file(
        &linked_project_skills_root
            .path()
            .join("linked-project-skill/SKILL.md"),
        "# Linked Project Skill\n",
    );
    write_file(
        &linked_scope_root
            .path()
            .join(".claude/skills/escaped-skill/SKILL.md"),
        "# Escaped Skill\n",
    );
    fs::create_dir_all(claude_skills.join("file-linked-skill")).expect("create file-linked skill");
    std::os::unix::fs::symlink(bundle_root.path(), claude_skills.join("bundle"))
        .expect("link bundle");
    std::os::unix::fs::symlink(bundle_root.path(), bundle_root.path().join("loop"))
        .expect("link bundle cycle");
    std::os::unix::fs::symlink(linked_skill_root.path(), claude_skills.join("linked-skill"))
        .expect("link skill");
    let cursor_nested_skills = home_root.path().join(".cursor/skills/workflows");
    fs::create_dir_all(&cursor_nested_skills).expect("create nested Cursor skills root");
    std::os::unix::fs::symlink(
        linked_skill_root.path(),
        cursor_nested_skills.join("linked-skill"),
    )
    .expect("link nested Cursor skill");
    std::os::unix::fs::symlink(
        linked_file_root.path().join("skill-body.md"),
        claude_skills.join("file-linked-skill/SKILL.md"),
    )
    .expect("link skill file");
    fs::create_dir_all(project_root.path().join(".claude"))
        .expect("create project Claude directory");
    std::os::unix::fs::symlink(
        linked_project_skills_root.path(),
        project_root.path().join(".claude/skills"),
    )
    .expect("link project skills root");
    std::os::unix::fs::symlink(
        linked_scope_root.path(),
        project_root.path().join("linked-scope"),
    )
    .expect("link external project scope");

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");
    let linked = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:linked-skill")
        .expect("directly linked skill");
    let file_linked = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:skill:file-linked-skill")
        .expect("skill with linked SKILL.md");
    let project_linked = result
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:linked-project-skill")
        .expect("skill under linked project root");
    let cursor_nested_linked = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:workflows/linked-skill")
        .expect("nested linked Cursor skill");

    assert_eq!(
        result
            .items
            .iter()
            .filter(|item| {
                item.provider == ProviderId::Claude
                    && item.kind == DiscoveryKind::Skill
                    && item.layer == DiscoveryLayer::Global
            })
            .count(),
        2,
        "only direct child skill directories should be inventoried"
    );
    assert!(
        result.items.iter().all(|item| {
            item.provider != ProviderId::Claude
                || (!item.id.contains("bundle/")
                    && !item.id.contains("nested-skill")
                    && !item.id.contains("escaped-skill"))
        }),
        "Claude must keep direct-child skill semantics and skip external scopes"
    );
    let cursor_compatible_nested = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:skill:@compat/claude/container/nested-skill")
        .expect("Cursor-compatible nested Claude skill");
    assert_eq!(
        cursor_compatible_nested.mutability,
        DiscoveryMutability::ReadWrite
    );
    assert_eq!(linked.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(file_linked.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(project_linked.mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(
        cursor_nested_linked.mutability,
        DiscoveryMutability::ReadWrite
    );
}

#[cfg(unix)]
#[test]
fn project_skill_scope_scan_warns_and_continues_past_unreadable_descendants() {
    use std::os::unix::fs::PermissionsExt as _;

    let home_root = tempfile::TempDir::new().expect("temp home root");
    let repository_root = tempfile::TempDir::new().expect("temp repository root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(
        &repository_root.path().join(".git"),
        "gitdir: /tmp/example.git\n",
    );
    write_file(
        &repository_root
            .path()
            .join(".claude/skills/root-skill/SKILL.md"),
        "# Root Skill\n",
    );
    let unreadable = repository_root.path().join("private");
    fs::create_dir_all(&unreadable).expect("create unreadable directory");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
        .expect("make directory unreadable");
    if fs::read_dir(&unreadable).is_ok() {
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700))
            .expect("restore directory permissions");
        return;
    }

    let discovery = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        repository_root.path(),
        cursor_root.path(),
    ));
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700))
        .expect("restore directory permissions");
    let result = discovery.expect("unreadable descendant should not abort discovery");

    assert!(
        result
            .items
            .iter()
            .any(|item| item.id == "claude:project:skill:root-skill"),
        "readable scopes should still be inventoried; got {:#?}",
        result.items
    );
    assert!(
        result.warnings.iter().any(|warning| {
            warning.layer == Some(DiscoveryLayer::Project)
                && warning.code == "scope-scan-incomplete"
                && !warning
                    .message
                    .contains(unreadable.to_string_lossy().as_ref())
        }),
        "partial scope scan should emit a path-safe warning; got {:#?}",
        result.warnings
    );
}

#[test]
fn discovers_skills_and_configured_mcps_from_fixture_roots() {
    let root = fixtures_root();
    let result = discover_all(&DiscoveryRoots::fixture_root(&root)).expect("discovery succeeds");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );

    let ids = result
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();

    for expected in [
        "claude:global:skill:example-claude-global-skill",
        "claude:global:configured-mcp:global-docs",
        "claude:project:skill:example-claude-skill",
        "claude:project:configured-mcp:github",
        "codex:global:skill:example-shared-global-skill",
        "codex:global:skill:admin/example-codex-admin-skill",
        "codex:project:skill:example-shared-project-skill",
        "codex:global:configured-mcp:github",
        "cursor:global:skill:example-cursor-skill",
        "cursor:project:skill:example-cursor-project-skill",
        "cursor:global:skill:@compat/agents/example-shared-global-skill",
        "cursor:project:skill:@compat/agents/example-shared-project-skill",
        "cursor:global:configured-mcp:modern-global",
        "pi:global:skill:workflows/example-pi-global-skill",
        "pi:global:skill:@file/example-pi-file-skill",
        "pi:project:skill:example-pi-project-skill",
        "pi:project:skill:@file/example-pi-project-file-skill",
        "pi:global:plugin-config:package-extensions:npm:example-pi-connector",
        "pi:project:plugin-config:package-extensions:npm:example-pi-project-connector",
        "opencode:global:skill:example-opencode-global-skill",
        "opencode:project:skill:example-opencode-project-skill",
        "opencode:global:configured-mcp:example-global",
        "opencode:project:configured-mcp:example-project",
        "opencode:global:plugin-config:npm:example-opencode-connector",
        "opencode:project:plugin-config:npm:example-opencode-project-connector",
        "opencode:global:plugin-manifest:local:example-local.ts",
        "opencode:project:plugin-manifest:local:example-project.js",
        "zed:global:skill:example-shared-global-skill",
        "zed:project:skill:example-shared-project-skill",
        "zed:global:configured-mcp:github",
        "zed:project:configured-mcp:local-docs",
    ] {
        assert!(ids.contains(&expected), "missing {expected}; got {ids:#?}");
    }

    let claude_skill = result
        .items
        .iter()
        .find(|item| item.id == "claude:project:skill:example-claude-skill")
        .expect("claude skill");

    assert_eq!(claude_skill.provider, ProviderId::Claude);
    assert_eq!(claude_skill.kind, DiscoveryKind::Skill);
    assert_eq!(claude_skill.category, DiscoveryCategory::Skill);
    assert_eq!(claude_skill.layer, DiscoveryLayer::Project);
    assert_eq!(claude_skill.mutability, DiscoveryMutability::ReadWrite);
    assert!(claude_skill.enabled);
    assert!(
        claude_skill
            .source_path
            .ends_with(".claude/skills/example-claude-skill/SKILL.md")
    );

    for id in [
        "pi:global:plugin-config:package-extensions:npm:example-pi-connector",
        "pi:project:plugin-config:package-extensions:npm:example-pi-project-connector",
    ] {
        let package = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing Pi package {id}"));
        assert_eq!(package.provider, ProviderId::Pi);
        assert_eq!(package.kind, DiscoveryKind::Plugin);
        assert_eq!(package.category, DiscoveryCategory::PluginConfig);
        assert_eq!(package.mutability, DiscoveryMutability::ReadWrite);
        assert!(package.enabled);
        assert!(package.source_fingerprint.is_some());
    }

    let claude_global_mcp = result
        .items
        .iter()
        .find(|item| item.id == "claude:global:configured-mcp:global-docs")
        .expect("Claude global MCP");
    assert_eq!(claude_global_mcp.provider, ProviderId::Claude);
    assert_eq!(claude_global_mcp.kind, DiscoveryKind::Mcp);
    assert_eq!(claude_global_mcp.category, DiscoveryCategory::ConfiguredMcp);
    assert_eq!(claude_global_mcp.layer, DiscoveryLayer::Global);
    assert_eq!(claude_global_mcp.mutability, DiscoveryMutability::ReadWrite);
    assert!(claude_global_mcp.enabled);
    assert!(
        claude_global_mcp
            .source_path
            .ends_with("claude/.claude.json")
    );
    assert_eq!(claude_global_mcp.state_path, claude_global_mcp.source_path);
    assert!(claude_global_mcp.source_fingerprint.is_some());

    let opencode_project_mcp = result
        .items
        .iter()
        .find(|item| item.id == "opencode:project:configured-mcp:example-project")
        .expect("OpenCode project MCP");
    assert!(!opencode_project_mcp.enabled);
    assert_eq!(
        opencode_project_mcp.mutability,
        DiscoveryMutability::ReadWrite
    );
    let opencode_npm_plugin = result
        .items
        .iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:example-opencode-connector")
        .expect("OpenCode npm plugin");
    assert_eq!(
        opencode_npm_plugin.mutability,
        DiscoveryMutability::ReadWrite
    );
    let opencode_local_plugin = result
        .items
        .iter()
        .find(|item| item.id == "opencode:global:plugin-manifest:local:example-local.ts")
        .expect("OpenCode local plugin");
    assert_eq!(
        opencode_local_plugin.mutability,
        DiscoveryMutability::ReadOnly
    );
}

#[test]
fn malformed_opencode_plugin_array_keeps_valid_inventory_read_only() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let config_path = fixture_copy.path().join("opencode/global/opencode.jsonc");
    fs::write(
        &config_path,
        r#"{
  "mcp": {},
  "plugin": ["good-plugin", "", 42, "good-plugin"]
}
"#,
    )
    .expect("write malformed OpenCode config");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("OpenCode discovery continues");
    let plugin = result
        .items
        .iter()
        .find(|item| item.id == "opencode:global:plugin-config:npm:good-plugin")
        .expect("valid OpenCode plugin remains inventoried");
    assert_eq!(plugin.mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(
        result
            .warnings
            .iter()
            .filter(|warning| {
                warning.provider == ProviderId::OpenCode
                    && warning.layer == Some(DiscoveryLayer::Global)
            })
            .count(),
        3
    );
}

#[test]
fn malformed_pi_package_array_keeps_valid_inventory_read_only() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy.path().join("pi/global/settings.json");
    fs::write(
        &settings_path,
        r#"{
  "packages": [
    "npm:good-package",
    { "source": "npm:broken-filter", "extensions": "connector" },
    "npm:good-package"
  ]
}
"#,
    )
    .expect("write malformed Pi settings");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("Pi discovery continues");
    let package = result
        .items
        .iter()
        .find(|item| item.id == "pi:global:plugin-config:package-extensions:npm:good-package")
        .expect("valid Pi package remains inventoried");
    assert_eq!(package.mutability, DiscoveryMutability::ReadOnly);
    assert_eq!(
        result
            .warnings
            .iter()
            .filter(|warning| {
                warning.provider == ProviderId::Pi && warning.layer == Some(DiscoveryLayer::Global)
            })
            .count(),
        2
    );
}

#[test]
fn discovers_only_selected_claude_local_scope_mcp_servers() {
    let root = fixtures_root();
    let mut roots = DiscoveryRoots::fixture_root(&root);
    roots.claude_project = PathBuf::from("/fixture/project");

    let result = discover_all(&roots).expect("project-local discovery succeeds");
    let local_mcp = result
        .items
        .iter()
        .find(|item| item.display_name == "local-search")
        .expect("selected Claude local MCP");
    assert_eq!(local_mcp.provider, ProviderId::Claude);
    assert_eq!(local_mcp.kind, DiscoveryKind::Mcp);
    assert_eq!(local_mcp.category, DiscoveryCategory::ConfiguredMcp);
    assert_eq!(local_mcp.layer, DiscoveryLayer::Project);
    assert_eq!(local_mcp.mutability, DiscoveryMutability::ReadWrite);
    assert!(local_mcp.enabled);
    assert!(
        local_mcp
            .id
            .starts_with("claude:project:configured-mcp:@local/")
    );
    assert!(local_mcp.source_path.ends_with("claude/.claude.json"));
    assert_eq!(local_mcp.state_path, local_mcp.source_path);
    assert!(local_mcp.source_fingerprint.is_some());
    assert!(
        !result
            .items
            .iter()
            .any(|item| item.display_name == "other-local")
    );

    roots.claude_project = PathBuf::from("/fixture/other-project");
    let other = discover_all(&roots).expect("other local discovery succeeds");
    assert!(
        other
            .items
            .iter()
            .any(|item| item.display_name == "other-local")
    );
    assert!(
        !other
            .items
            .iter()
            .any(|item| item.display_name == "local-search")
    );
}

#[test]
fn discovers_repository_root_claude_local_mcp_from_nested_project_path() {
    let home = tempfile::TempDir::new().expect("temp home");
    let repository = tempfile::TempDir::new().expect("temp repository");
    let cursor = tempfile::TempDir::new().expect("temp cursor root");
    fs::create_dir_all(repository.path().join(".git")).expect("create git marker");
    let nested_project = repository.path().join("apps").join("api");
    fs::create_dir_all(&nested_project).expect("create nested project");
    let repository_key = repository.path().to_string_lossy().to_string();
    let mut projects = serde_json::Map::new();
    projects.insert(
        repository_key,
        serde_json::json!({
            "mcpServers": {
                "repo-local": { "command": "repo-local-mcp" }
            }
        }),
    );
    fs::write(
        home.path().join(".claude.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {},
            "projects": projects
        }))
        .expect("Claude user state serializes"),
    )
    .expect("write Claude user state");

    let result = discover_all(&DiscoveryRoots::from_locations(
        home.path(),
        &nested_project,
        cursor.path(),
    ))
    .expect("nested project discovery succeeds");

    assert!(result.items.iter().any(|item| {
        item.display_name == "repo-local"
            && item.provider == ProviderId::Claude
            && item.layer == DiscoveryLayer::Project
            && item.id.starts_with("claude:project:configured-mcp:@local/")
    }));
}

#[test]
fn discovers_codex_mcp_layers_and_native_enabled_state() {
    let root = fixtures_root();
    let result = discover_all(&DiscoveryRoots::fixture_root(&root)).expect("discovery succeeds");

    let cases = [
        (
            "codex:global:configured-mcp:github",
            DiscoveryLayer::Global,
            true,
            "codex/global/config.toml",
        ),
        (
            "codex:global:configured-mcp:disabled-docs",
            DiscoveryLayer::Global,
            false,
            "codex/global/config.toml",
        ),
        (
            "codex:project:configured-mcp:project-docs",
            DiscoveryLayer::Project,
            false,
            "codex/project/.codex/config.toml",
        ),
    ];

    for (id, layer, enabled, path_suffix) in cases {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));
        assert_eq!(item.provider, ProviderId::Codex, "{id} provider");
        assert_eq!(item.kind, DiscoveryKind::Mcp, "{id} kind");
        assert_eq!(
            item.category,
            DiscoveryCategory::ConfiguredMcp,
            "{id} category"
        );
        assert_eq!(item.layer, layer, "{id} layer");
        assert_eq!(item.enabled, enabled, "{id} enabled state");
        assert_eq!(
            item.mutability,
            DiscoveryMutability::ReadWrite,
            "{id} mutability"
        );
        assert!(item.source_path.ends_with(path_suffix), "{id} source path");
        assert_eq!(item.state_path, item.source_path, "{id} state path");
    }
}

#[test]
fn discovers_codex_mcp_config_from_repository_ancestors_with_scoped_ids() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let repository_parent = tempfile::TempDir::new().expect("temp repository parent");
    let repository_root = repository_parent.path().join("repository");
    let apps_root = repository_root.join("apps");
    let project_root = apps_root.join("api");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    write_file(&repository_root.join(".git"), "gitdir: /tmp/example.git\n");

    for (scope_root, server_id) in [
        (repository_root.as_path(), "root-docs"),
        (apps_root.as_path(), "apps-docs"),
        (project_root.as_path(), "api-docs"),
    ] {
        write_file(
            &scope_root.join(".codex/config.toml"),
            &format!("[mcp_servers.{server_id}]\ncommand = \"echo\"\n"),
        );
    }

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        &project_root,
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    for (id, path_suffix) in [
        (
            "codex:project:configured-mcp:root-docs",
            "repository/.codex/config.toml",
        ),
        (
            "codex:project:configured-mcp:@scope/apps/apps-docs",
            "repository/apps/.codex/config.toml",
        ),
        (
            "codex:project:configured-mcp:@scope/apps/api/api-docs",
            "repository/apps/api/.codex/config.toml",
        ),
    ] {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));
        assert_eq!(item.layer, DiscoveryLayer::Project, "{id} layer");
        assert_eq!(item.mutability, DiscoveryMutability::ReadWrite, "{id}");
        assert!(item.source_path.ends_with(path_suffix), "{id} source path");
    }
}

#[test]
fn discovers_zed_skills_instructions_settings_and_context_servers_from_fixture_roots() {
    let root = fixtures_root();
    let result = discover_all(&DiscoveryRoots::fixture_root(&root)).expect("discovery succeeds");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );

    let cases = [
        (
            "zed:global:skill:example-shared-global-skill",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "example-shared-global-skill",
            "shared/global/.agents/skills/example-shared-global-skill/SKILL.md",
        ),
        (
            "zed:project:skill:example-shared-project-skill",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            "example-shared-project-skill",
            "shared/project/.agents/skills/example-shared-project-skill/SKILL.md",
        ),
        (
            "zed:global:configured-mcp:github",
            DiscoveryKind::Mcp,
            DiscoveryCategory::ConfiguredMcp,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "github",
            "zed/global/.config/zed/settings.json",
        ),
        (
            "zed:project:configured-mcp:local-docs",
            DiscoveryKind::Mcp,
            DiscoveryCategory::ConfiguredMcp,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadWrite,
            "local-docs",
            "zed/project/.zed/settings.json",
        ),
        (
            "zed:global:setting:agents-md",
            DiscoveryKind::Setting,
            DiscoveryCategory::ProviderSetting,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadOnly,
            "AGENTS.md",
            "zed/global/.config/zed/AGENTS.md",
        ),
        (
            "zed:project:setting:agents-md",
            DiscoveryKind::Setting,
            DiscoveryCategory::ProviderSetting,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadOnly,
            "AGENTS.md",
            "zed/project/AGENTS.md",
        ),
        (
            "zed:global:setting:settings-json",
            DiscoveryKind::Setting,
            DiscoveryCategory::ProviderSetting,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadOnly,
            "settings.json",
            "zed/global/.config/zed/settings.json",
        ),
        (
            "zed:project:setting:settings-json",
            DiscoveryKind::Setting,
            DiscoveryCategory::ProviderSetting,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadOnly,
            ".zed/settings.json",
            "zed/project/.zed/settings.json",
        ),
    ];

    for (id, kind, category, layer, mutability, display_name, source_suffix) in cases {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));

        assert_eq!(item.provider, ProviderId::Zed, "{id} provider");
        assert_eq!(item.kind, kind, "{id} kind");
        assert_eq!(item.category, category, "{id} category");
        assert_eq!(item.layer, layer, "{id} layer");
        assert_eq!(item.display_name, display_name, "{id} display name");
        assert_eq!(item.mutability, mutability, "{id} mutability");
        assert!(item.enabled, "{id} should be enabled");
        assert!(
            item.source_path.ends_with(source_suffix),
            "{id} source path should end with {source_suffix:?}; got {}",
            item.source_path
        );
        if kind == DiscoveryKind::Skill {
            assert!(
                item.state_path
                    .ends_with(source_suffix.trim_end_matches("/SKILL.md")),
                "{id} state path should point at the skill directory; got {}",
                item.state_path
            );
        } else {
            assert_eq!(item.state_path, item.source_path, "{id} state path");
        }
        if category == DiscoveryCategory::ConfiguredMcp {
            assert!(
                item.source_fingerprint.is_some(),
                "{id} should include source fingerprint"
            );
        }
    }
}

#[test]
fn discovers_zed_settings_with_jsonc_comments_and_trailing_commas() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let settings_path = fixture_copy
        .path()
        .join("zed")
        .join("global")
        .join(".config")
        .join("zed")
        .join("settings.json");
    fs::write(
        &settings_path,
        r#"// Zed settings may contain comments.
{
  "context_servers": {
    "jsonc-docs": {
      "command": "echo",
      "args": ["zed-jsonc"],
    },
  },
}
"#,
    )
    .expect("write zed JSONC settings");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );
    assert!(
        result
            .items
            .iter()
            .any(|item| item.id == "zed:global:configured-mcp:jsonc-docs"),
        "missing JSONC Zed MCP item; got {:#?}",
        result.items
    );
}

#[test]
fn discovers_cursor_configured_mcp_disabled_flag_as_disabled() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");
    fs::write(
        &mcp_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "modern-global": {
                    "command": "npx",
                    "disabled": true
                }
            }
        }))
        .expect("mcp json"),
    )
    .expect("write cursor mcp");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    assert!(!item.enabled);
    assert_eq!(item.provider, ProviderId::Cursor);
    assert_eq!(item.kind, DiscoveryKind::Mcp);
    assert_eq!(item.category, DiscoveryCategory::ConfiguredMcp);
    assert_eq!(item.layer, DiscoveryLayer::Global);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.source_path, mcp_path.to_string_lossy());
    assert_eq!(item.state_path, item.source_path);
}

#[test]
fn discovers_cursor_mcp_from_modern_global_and_project_paths() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor app-support root");

    write_file(
        &home_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"modern-global":{"command":"npx"}}}"#,
    );
    write_file(
        &project_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"project-docs":{"command":"node","args":["tools/project-docs-mcp.js"]}}}"#,
    );
    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );

    let global_item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .unwrap_or_else(|| panic!("missing modern global cursor MCP; got {:#?}", result.items));
    assert_eq!(global_item.provider, ProviderId::Cursor);
    assert_eq!(global_item.layer, DiscoveryLayer::Global);
    assert_eq!(global_item.kind, DiscoveryKind::Mcp);
    assert_eq!(global_item.category, DiscoveryCategory::ConfiguredMcp);
    assert_eq!(global_item.mutability, DiscoveryMutability::ReadWrite);
    assert!(global_item.enabled);
    assert_eq!(
        global_item.source_path,
        home_root
            .path()
            .join(".cursor")
            .join("mcp.json")
            .to_string_lossy()
    );
    assert_eq!(global_item.state_path, global_item.source_path);

    let project_item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:project:configured-mcp:project-docs")
        .unwrap_or_else(|| panic!("missing project cursor MCP; got {:#?}", result.items));
    assert_eq!(project_item.layer, DiscoveryLayer::Project);
    assert_eq!(
        project_item.source_path,
        project_root
            .path()
            .join(".cursor")
            .join("mcp.json")
            .to_string_lossy()
    );
    assert_eq!(project_item.state_path, project_item.source_path);
}

#[test]
fn cursor_modern_global_mcp_path_wins_over_legacy_duplicate() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor app-support root");

    write_file(
        &home_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"duplicate":{"command":"modern"}}}"#,
    );
    write_file(
        &cursor_root.path().join("mcp.json"),
        r#"{"mcpServers":{"duplicate":{"command":"legacy"}}}"#,
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    let matches = result
        .items
        .iter()
        .filter(|item| item.id == "cursor:global:configured-mcp:duplicate")
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "duplicate global Cursor MCP ids should collapse to one item; got {matches:#?}"
    );
    assert_eq!(
        matches[0].source_path,
        home_root
            .path()
            .join(".cursor")
            .join("mcp.json")
            .to_string_lossy()
    );
}

#[test]
fn ignores_legacy_cursor_app_support_mcp_json_when_modern_global_exists() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor app-support root");

    write_file(
        &home_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"modern-global":{"command":"modern"}}}"#,
    );
    write_file(
        &cursor_root.path().join("mcp.json"),
        r#"{"mcpServers":{"legacy-only":{"command":"legacy"}}}"#,
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");
    let ids = result
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();

    assert!(
        ids.contains(&"cursor:global:configured-mcp:modern-global"),
        "modern Cursor MCP should be discovered; got {ids:#?}"
    );
    assert!(
        !ids.contains(&"cursor:global:configured-mcp:legacy-only"),
        "legacy Cursor app-support mcp.json should be ignored; got {ids:#?}"
    );
}

#[test]
fn discovers_cursor_configured_mcp_workspace_disabled_state_as_disabled() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path = write_cursor_workspace_disabled_servers(
        &cursor_root,
        &project_root,
        r#"["user-modern-global"]"#,
    );
    let mcp_path = fixture_copy
        .path()
        .join("cursor")
        .join("home")
        .join("mcp.json");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );
    assert!(!item.enabled);
    assert_eq!(item.provider, ProviderId::Cursor);
    assert_eq!(item.kind, DiscoveryKind::Mcp);
    assert_eq!(item.category, DiscoveryCategory::ConfiguredMcp);
    assert_eq!(item.layer, DiscoveryLayer::Global);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.source_path, mcp_path.to_string_lossy());
    assert_eq!(item.state_path, database_path.to_string_lossy());
}

#[test]
fn discovers_cursor_workspace_state_from_percent_encoded_project_url() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_parent = tempfile::TempDir::new().expect("temp project parent");
    let project_root = project_parent.path().join("project with spaces");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor app-support root");
    fs::create_dir_all(&project_root).expect("create project root");
    write_file(
        &home_root.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"modern-global":{"command":"modern"}}}"#,
    );
    let encoded_project_url = format!("file://{}", project_root.display()).replace(' ', "%20");
    let database_path = write_cursor_workspace_disabled_servers_with_folder(
        cursor_root.path(),
        &encoded_project_url,
        r#"["user-modern-global"]"#,
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        &project_root,
        cursor_root.path(),
    ))
    .expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .expect("cursor mcp");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );
    assert!(!item.enabled);
    assert_eq!(item.state_path, database_path.to_string_lossy());
}

#[test]
fn warns_on_malformed_cursor_workspace_disabled_state() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let cursor_root = fixture_copy.path().join("cursor").join("global");
    let project_root = fixture_copy.path().join("cursor").join("project");
    let database_path =
        write_cursor_workspace_disabled_servers(&cursor_root, &project_root, r#"{"bad":true}"#);

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds with warning");

    assert!(
        result.warnings.iter().any(|warning| {
            warning.provider == ProviderId::Cursor
                && warning.layer == Some(DiscoveryLayer::Global)
                && warning.code == "invalid-shape"
                && warning.message.contains("cursor/disabledMcpServers")
                && warning
                    .message
                    .contains(&database_path.to_string_lossy().to_string())
        }),
        "expected malformed Cursor workspace warning; got {:#?}",
        result.warnings
    );
}

#[test]
fn discovers_modern_provider_surfaces_with_expected_mutability() {
    let root = fixtures_root();
    let result = discover_all(&DiscoveryRoots::fixture_root(&root)).expect("discovery succeeds");

    assert!(
        result.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        result.warnings
    );

    let cases = [
        (
            "claude:global:agent:claude-global-reviewer",
            ProviderId::Claude,
            DiscoveryKind::Agent,
            DiscoveryCategory::Agent,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "claude-global-reviewer",
            "claude/global/agents/reviewer.md",
        ),
        (
            "claude:global:tool:settings:safe-shell",
            ProviderId::Claude,
            DiscoveryKind::Plugin,
            DiscoveryCategory::PluginConfig,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "safe-shell",
            "claude/global/settings.json",
        ),
        (
            "codex:global:agent:codex-global-reviewer",
            ProviderId::Codex,
            DiscoveryKind::Agent,
            DiscoveryCategory::Agent,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "codex-global-reviewer",
            "codex/global/agents/reviewer.toml",
        ),
        (
            "codex:global:plugin-config:config:safe-shell",
            ProviderId::Codex,
            DiscoveryKind::Plugin,
            DiscoveryCategory::PluginConfig,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "safe-shell",
            "codex/global/config.toml",
        ),
        (
            "cursor:global:agent:cursor-global-reviewer",
            ProviderId::Cursor,
            DiscoveryKind::Agent,
            DiscoveryCategory::Agent,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "cursor-global-reviewer",
            "cursor/global/agents/reviewer.md",
        ),
        (
            "cursor:global:plugin-manifest:local:example-plugin",
            ProviderId::Cursor,
            DiscoveryKind::Plugin,
            DiscoveryCategory::PluginManifest,
            DiscoveryLayer::Global,
            DiscoveryMutability::ReadWrite,
            "Example Cursor Plugin",
            "cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json",
        ),
        (
            "cursor:project:setting:sandbox-json",
            ProviderId::Cursor,
            DiscoveryKind::Setting,
            DiscoveryCategory::ProviderSetting,
            DiscoveryLayer::Project,
            DiscoveryMutability::ReadOnly,
            ".cursor/sandbox.json",
            "cursor/project/.cursor/sandbox.json",
        ),
    ];

    for (id, provider, kind, category, layer, mutability, display_name, source_suffix) in cases {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));

        assert_eq!(item.provider, provider, "{id} provider");
        assert_eq!(item.kind, kind, "{id} kind");
        assert_eq!(item.category, category, "{id} category");
        assert_eq!(item.layer, layer, "{id} layer");
        assert_eq!(item.display_name, display_name, "{id} display name");
        assert_eq!(item.mutability, mutability, "{id} mutability");
        assert!(item.enabled, "{id} should be enabled");
        assert!(
            item.source_path.ends_with(source_suffix),
            "{id} source path should end with {source_suffix:?}; got {}",
            item.source_path
        );
        if id == "cursor:global:plugin-manifest:local:example-plugin" {
            assert!(
                item.state_path
                    .ends_with("cursor/home/plugins/local/example-plugin"),
                "{id} state path should point at plugin directory; got {}",
                item.state_path
            );
            assert!(item.source_fingerprint.is_some(), "{id} fingerprint");
        } else {
            assert_eq!(item.state_path, item.source_path, "{id} state path");
        }
    }

    let mut claude_pre_tool = result
        .items
        .iter()
        .filter(|item| {
            item.provider == ProviderId::Claude
                && item
                    .hook
                    .as_ref()
                    .is_some_and(|hook| hook.native_event == "PreToolUse")
        })
        .collect::<Vec<_>>();
    claude_pre_tool.sort_by_key(|item| item.hook.as_ref().unwrap().order);
    assert_eq!(
        claude_pre_tool.len(),
        2,
        "one event must expose two handlers"
    );
    assert_eq!(claude_pre_tool[0].hook.as_ref().unwrap().order, 0);
    assert_eq!(claude_pre_tool[1].hook.as_ref().unwrap().order, 1);
    assert_eq!(
        claude_pre_tool[0].hook.as_ref().unwrap().matcher_mode,
        HookMatcherMode::ExactSet
    );
    assert_eq!(claude_pre_tool[0].hook.as_ref().unwrap().matcher, "Bash");
    assert_eq!(
        claude_pre_tool[0].hook.as_ref().unwrap().action_type,
        HookActionType::Command
    );
    assert_eq!(
        claude_pre_tool[1].hook.as_ref().unwrap().action_type,
        HookActionType::Http
    );
    assert_eq!(
        claude_pre_tool[1].hook.as_ref().unwrap().failure_policy,
        HookFailurePolicy::ContinueDegraded
    );

    for (provider, layer, native_event, source_suffix) in [
        (
            ProviderId::Claude,
            DiscoveryLayer::Project,
            "PostToolUse",
            "claude/project/.claude/settings.local.json",
        ),
        (
            ProviderId::Codex,
            DiscoveryLayer::Global,
            "PreToolUse",
            "codex/global/config.toml",
        ),
        (
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            "BeforeShellExecution",
            "cursor/global/hooks.json",
        ),
    ] {
        let item = result
            .items
            .iter()
            .find(|item| {
                item.provider == provider
                    && item.layer == layer
                    && item.hook.as_ref().is_some_and(|hook| {
                        hook.native_event == native_event
                            && hook.route_owner == HookRouteOwner::NativeDispatcher
                    })
            })
            .unwrap_or_else(|| panic!("missing granular {provider:?} {native_event} hook"));
        assert_eq!(item.kind, DiscoveryKind::Hook);
        assert_eq!(item.category, DiscoveryCategory::Hook);
        assert_eq!(item.mutability, DiscoveryMutability::ReadOnly);
        assert!(item.enabled);
        assert!(item.source_path.ends_with(source_suffix));
        assert_eq!(item.state_path, item.source_path);
        assert_eq!(
            item.source_fingerprint.as_deref(),
            item.hook.as_ref().map(|hook| hook.fingerprint.as_str())
        );
        let serialized = serde_json::to_string(item).expect("hook inventory JSON");
        assert!(!serialized.contains("/usr/bin/true"));
        assert!(!serialized.contains("hooks.example.test"));
    }

    assert!(
        result
            .items
            .iter()
            .all(|item| !item.id.contains(":extension:")),
        "IDE extensions are outside Unpin provider scope"
    );

    let claude_compatible = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:claude-compatible")
        .expect("Claude-compatible Cursor plugin");
    assert_eq!(
        claude_compatible.display_name,
        "Claude-Compatible Cursor Plugin"
    );
    assert_eq!(claude_compatible.mutability, DiscoveryMutability::ReadWrite);
    assert!(
        claude_compatible
            .source_path
            .ends_with("cursor/home/plugins/local/claude-compatible/.claude-plugin/plugin.json")
    );
    assert!(
        claude_compatible
            .state_path
            .ends_with("cursor/home/plugins/local/claude-compatible")
    );

    let disabled_project_plugin = result
        .items
        .iter()
        .find(|item| item.id == "claude:project:tool:settings-local:local-shell")
        .expect("project Claude plugin config");
    assert_eq!(disabled_project_plugin.provider, ProviderId::Claude);
    assert_eq!(disabled_project_plugin.kind, DiscoveryKind::Plugin);
    assert_eq!(
        disabled_project_plugin.category,
        DiscoveryCategory::PluginConfig
    );
    assert_eq!(disabled_project_plugin.layer, DiscoveryLayer::Project);
    assert_eq!(
        disabled_project_plugin.mutability,
        DiscoveryMutability::ReadWrite
    );
    assert!(!disabled_project_plugin.enabled);
    assert!(
        disabled_project_plugin
            .source_path
            .ends_with("claude/project/.claude/settings.local.json")
    );
    assert_eq!(
        disabled_project_plugin.state_path,
        disabled_project_plugin.source_path
    );

    let disabled_codex_plugin = result
        .items
        .iter()
        .find(|item| item.id == "codex:global:plugin-config:config:disabled-helper")
        .expect("disabled Codex plugin");
    assert_eq!(disabled_codex_plugin.provider, ProviderId::Codex);
    assert_eq!(disabled_codex_plugin.kind, DiscoveryKind::Plugin);
    assert_eq!(
        disabled_codex_plugin.category,
        DiscoveryCategory::PluginConfig
    );
    assert_eq!(disabled_codex_plugin.layer, DiscoveryLayer::Global);
    assert_eq!(
        disabled_codex_plugin.mutability,
        DiscoveryMutability::ReadWrite
    );
    assert!(!disabled_codex_plugin.enabled);
    assert!(disabled_codex_plugin.source_fingerprint.is_some());
    assert_eq!(
        disabled_codex_plugin.state_path,
        disabled_codex_plugin.source_path
    );
    assert!(
        result.items.iter().all(|item| {
            item.id != "codex:project:plugin-config:config:project-only@example-marketplace"
        }),
        "Codex project plugin state must not be exposed as a writable host contract"
    );
}

#[test]
fn discovers_cursor_marketplace_plugins_read_only_without_exposing_account_id() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp Cursor root");
    let database_path = write_cursor_marketplace_plugins(
        cursor_root.path(),
        &[
            (
                "cursor.plugins.installedIds.secret-account|no-workspace",
                serde_json::json!([
                    {"id": "42", "sources": ["user"]},
                    {"id": "84", "sources": ["dashboard", "team"]}
                ]),
            ),
            (
                &format!(
                    "cursor.plugins.installedIds.secret-account|{}",
                    project_file_url(project_root.path())
                ),
                serde_json::json!([
                    {"id": "99", "sources": ["project"]}
                ]),
            ),
            (
                "cursor.plugins.installedIds.secret-account|file:///other/repository",
                serde_json::json!([
                    {"id": "123", "sources": ["project"]}
                ]),
            ),
        ],
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");

    for (id, layer, display_name) in [
        (
            "cursor:global:plugin-config:marketplace:42",
            DiscoveryLayer::Global,
            "Cursor marketplace plugin 42",
        ),
        (
            "cursor:global:plugin-config:marketplace:84",
            DiscoveryLayer::Global,
            "Cursor marketplace plugin 84",
        ),
        (
            "cursor:project:plugin-config:marketplace:99",
            DiscoveryLayer::Project,
            "Cursor marketplace plugin 99",
        ),
    ] {
        let item = result
            .items
            .iter()
            .find(|item| item.id == id)
            .unwrap_or_else(|| panic!("missing {id}; got {:#?}", result.items));
        assert_eq!(item.provider, ProviderId::Cursor);
        assert_eq!(item.kind, DiscoveryKind::Plugin);
        assert_eq!(item.category, DiscoveryCategory::PluginConfig);
        assert_eq!(item.layer, layer);
        assert_eq!(item.display_name, display_name);
        assert_eq!(item.mutability, DiscoveryMutability::ReadOnly);
        assert!(item.enabled);
        assert_eq!(item.source_path, database_path.to_string_lossy());
        assert_eq!(item.state_path, database_path.to_string_lossy());
        assert!(item.source_fingerprint.is_some());
    }

    assert!(
        result
            .items
            .iter()
            .all(|item| !item.id.contains("secret-account")
                && !item.display_name.contains("secret-account")),
        "account identifier must stay private"
    );
    assert!(
        result
            .items
            .iter()
            .all(|item| item.id != "cursor:project:plugin-config:marketplace:123"),
        "unrelated workspace plugin must be ignored"
    );
}

#[test]
fn malformed_cursor_marketplace_state_warns_without_leaking_row_identity() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp Cursor root");
    write_cursor_marketplace_plugins(
        cursor_root.path(),
        &[
            (
                "cursor.plugins.installedIds.private-account|no-workspace",
                serde_json::json!([
                    {"id": "not-numeric", "sources": ["user"]}
                ]),
            ),
            (
                "cursor.plugins.installedIds.other-private-account|no-workspace",
                serde_json::json!([
                    {"id": "7", "sources": ["user"]}
                ]),
            ),
        ],
    );

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery continues");

    assert!(
        result
            .items
            .iter()
            .any(|item| item.id == "cursor:global:plugin-config:marketplace:7"),
        "valid marketplace rows must remain discoverable"
    );
    let warning = result
        .warnings
        .iter()
        .find(|warning| {
            warning.provider == ProviderId::Cursor
                && warning.code == "invalid-shape"
                && warning.message.contains("numeric plugin id")
        })
        .expect("malformed marketplace warning");
    assert!(!warning.message.contains("private-account"));
    assert!(!warning.message.contains("not-numeric"));
}

#[cfg(unix)]
#[test]
fn marks_symlinked_cursor_local_plugin_read_only() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let project_root = tempfile::TempDir::new().expect("temp project root");
    let cursor_root = tempfile::TempDir::new().expect("temp Cursor root");
    let external_plugin = tempfile::TempDir::new().expect("external plugin root");
    write_file(
        &external_plugin
            .path()
            .join(".cursor-plugin")
            .join("plugin.json"),
        r#"{"name":"linked-plugin"}"#,
    );
    let local_plugins_root = home_root.path().join(".cursor/plugins/local");
    fs::create_dir_all(&local_plugins_root).expect("create local plugins root");
    std::os::unix::fs::symlink(
        external_plugin.path(),
        local_plugins_root.join("linked-plugin"),
    )
    .expect("link local plugin");

    let result = discover_all(&DiscoveryRoots::from_locations(
        home_root.path(),
        project_root.path(),
        cursor_root.path(),
    ))
    .expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:plugin-manifest:local:linked-plugin")
        .expect("linked Cursor local plugin");

    assert_eq!(item.mutability, DiscoveryMutability::ReadOnly);
}

#[test]
fn malformed_cursor_local_plugin_manifest_warns_and_skips_item() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let manifest_path = fixture_copy
        .path()
        .join("cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json");
    fs::write(&manifest_path, "[]\n").expect("write malformed plugin shape");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("discovery succeeds with warning");

    assert!(
        result.warnings.iter().any(|warning| {
            warning.provider == ProviderId::Cursor
                && warning.layer == Some(DiscoveryLayer::Global)
                && warning.code == "invalid-shape"
                && warning.message.contains("must be a JSON object")
        }),
        "expected Cursor plugin warning; got {:#?}",
        result.warnings
    );
    assert!(
        result
            .items
            .iter()
            .all(|item| { item.id != "cursor:global:plugin-manifest:local:example-plugin" }),
        "malformed Cursor plugin should be skipped"
    );
}

#[test]
fn malformed_zed_settings_returns_warning_and_continues_discovery() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let bad_settings = fixture_copy
        .path()
        .join("zed")
        .join("global")
        .join(".config")
        .join("zed")
        .join("settings.json");
    fs::write(&bad_settings, "{ invalid json").expect("write malformed settings");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("malformed optional JSON should not abort discovery");

    assert!(
        result
            .items
            .iter()
            .any(|item| item.id == "zed:project:skill:example-shared-project-skill"),
        "discovery should continue to independent Zed surfaces; got {:#?}",
        result.items
    );
    assert!(
        !result
            .items
            .iter()
            .any(|item| item.id == "zed:global:setting:settings-json"),
        "malformed Zed settings should not produce a settings item"
    );
    assert!(
        result.warnings.iter().any(|warning| {
            warning.provider == ProviderId::Zed
                && warning.layer == Some(DiscoveryLayer::Global)
                && warning.code == "json-parse-error"
                && warning.message.contains("settings.json")
        }),
        "expected Zed json warning; got {:#?}",
        result.warnings
    );
}

#[test]
fn vaulted_project_skills_stay_scoped_to_selected_repository() {
    let home_root = tempfile::TempDir::new().expect("temp home root");
    let projects_root = tempfile::TempDir::new().expect("temp projects root");
    let cursor_root = tempfile::TempDir::new().expect("temp cursor root");
    let app_state = tempfile::TempDir::new().expect("temp app state");
    let project_a = projects_root.path().join("project-a");
    let project_b = projects_root.path().join("project-b");
    let original_path = project_a.join(".claude").join("skills").join("reviewer");
    fs::create_dir_all(original_path.parent().expect("skill root"))
        .expect("create project A skill root");
    fs::create_dir_all(&project_b).expect("create project B");

    let vault_root = app_state
        .path()
        .join("vault")
        .join("claude")
        .join("project")
        .join("skill")
        .join("claude%3Aproject%3Askill%3Areviewer");
    let payload = vault_root.join("payload");
    write_file(&payload.join("SKILL.md"), "# Vaulted Reviewer\n");
    write_file(
        &vault_root.join("entry.json"),
        &format!(
            "{}\n",
            serde_json::json!({
                "version": 1,
                "provider": "claude",
                "kind": "skill",
                "layer": "project",
                "itemId": "claude:project:skill:reviewer",
                "displayName": "reviewer",
                "originalPath": original_path.to_string_lossy(),
                "vaultedPath": payload.to_string_lossy(),
                "payloadKind": "path"
            })
        ),
    );

    let project_a_result = discover_all(
        &DiscoveryRoots::from_locations(home_root.path(), &project_a, cursor_root.path())
            .with_app_state_root(app_state.path()),
    )
    .expect("project A discovery succeeds");
    assert!(
        project_a_result
            .items
            .iter()
            .any(|item| { item.id == "claude:project:skill:reviewer" && !item.enabled }),
        "selected repository should include its vaulted skill; got {:#?}",
        project_a_result.items
    );

    let project_b_result = discover_all(
        &DiscoveryRoots::from_locations(home_root.path(), &project_b, cursor_root.path())
            .with_app_state_root(app_state.path()),
    )
    .expect("project B discovery succeeds");
    assert!(
        project_b_result
            .items
            .iter()
            .all(|item| item.id != "claude:project:skill:reviewer"),
        "another repository must not expose project A's vaulted skill; got {:#?}",
        project_b_result.items
    );
}

#[test]
fn discovers_vaulted_agent_as_disabled_when_app_state_root_is_configured() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    let app_state = tempfile::TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_path = fixture_copy
        .path()
        .join("cursor")
        .join("global")
        .join("agents")
        .join("reviewer.md");
    fs::remove_file(&original_path).expect("remove live agent");
    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("agent")
        .join("cursor%3Aglobal%3Aagent%3Acursor-global-reviewer");
    fs::create_dir_all(&vault_root).expect("vault root");
    let payload = vault_root.join("payload");
    fs::write(&payload, "# Vaulted Cursor Agent\n").expect("vault payload");
    fs::write(
        vault_root.join("entry.json"),
        format!(
            "{}\n",
            serde_json::json!({
                "version": 1,
                "provider": "cursor",
                "kind": "agent",
                "layer": "global",
                "itemId": "cursor:global:agent:cursor-global-reviewer",
                "displayName": "cursor-global-reviewer",
                "originalPath": original_path.to_string_lossy(),
                "vaultedPath": payload.to_string_lossy(),
                "payloadKind": "path"
            })
        ),
    )
    .expect("vault entry");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let result = discover_all(&roots).expect("discovery succeeds");
    let item = result
        .items
        .iter()
        .find(|item| item.id == "cursor:global:agent:cursor-global-reviewer")
        .expect("disabled vaulted cursor agent");

    assert!(!item.enabled);
    assert_eq!(item.kind, DiscoveryKind::Agent);
    assert_eq!(item.category, DiscoveryCategory::Agent);
    assert_eq!(item.mutability, DiscoveryMutability::ReadWrite);
    assert_eq!(item.source_path, original_path.to_string_lossy());
    assert!(item.state_path.ends_with("entry.json"));
}

#[test]
fn invalid_vault_identity_warns_and_skips_item() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    let app_state = tempfile::TempDir::new().expect("temp app state");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let original_path = fixture_copy
        .path()
        .join("cursor")
        .join("global")
        .join("agents")
        .join("injected.md");
    let vault_root = app_state
        .path()
        .join("vault")
        .join("cursor")
        .join("global")
        .join("agent")
        .join("bogus");
    fs::create_dir_all(&vault_root).expect("vault root");
    let payload = vault_root.join("payload");
    fs::write(&payload, "# Bogus Agent\n").expect("vault payload");
    fs::write(
        vault_root.join("entry.json"),
        format!(
            "{}\n",
            serde_json::json!({
                "version": 1,
                "provider": "cursor",
                "kind": "agent",
                "layer": "global",
                "itemId": "bogus",
                "displayName": "bogus",
                "originalPath": original_path.to_string_lossy(),
                "vaultedPath": payload.to_string_lossy(),
                "payloadKind": "path"
            })
        ),
    )
    .expect("vault entry");

    let roots =
        DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
    let result = discover_all(&roots).expect("discovery succeeds");

    assert!(result.items.iter().all(|item| item.id != "bogus"));
    let warning = result
        .warnings
        .iter()
        .find(|warning| warning.code == "invalid-vault-entry")
        .expect("invalid vault warning");
    assert_eq!(warning.provider, ProviderId::Cursor);
    assert_eq!(warning.layer, Some(DiscoveryLayer::Global));
    assert!(
        warning
            .message
            .contains("itemId must start with cursor:global:agent:")
    );
}

#[test]
fn malformed_provider_json_returns_warning_and_continues_discovery() {
    let fixture_copy = tempfile::TempDir::new().expect("temp fixture copy");
    copy_dir_all(&fixtures_root(), fixture_copy.path());
    let bad_settings = fixture_copy
        .path()
        .join("claude")
        .join("global")
        .join("settings.json");
    fs::write(&bad_settings, "{ invalid json").expect("write malformed settings");

    let result = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
        .expect("malformed optional JSON should not abort discovery");

    assert!(
        result
            .items
            .iter()
            .any(|item| item.id == "codex:global:skill:example-shared-global-skill"),
        "discovery should continue to independent providers; got {:#?}",
        result.items
    );
    assert!(
        !result
            .items
            .iter()
            .any(|item| item.id == "claude:global:setting:settings"),
        "malformed settings file should not produce a setting item"
    );
    assert_eq!(result.warnings.len(), 1);

    let warning = &result.warnings[0];
    assert_eq!(warning.provider, ProviderId::Claude);
    assert_eq!(warning.layer, Some(DiscoveryLayer::Global));
    assert_eq!(warning.code, "json-parse-error");
    assert!(
        warning.message.contains("settings.json"),
        "warning message should include the file path; got {}",
        warning.message
    );
}

#[test]
fn sorts_items_by_provider_layer_category_and_id() {
    let root = fixtures_root();
    let result = discover_all(&DiscoveryRoots::fixture_root(&root)).expect("discovery succeeds");
    let ids = result
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();

    let mut sorted = ids.clone();
    sorted.sort();

    assert_ne!(
        ids, sorted,
        "test should prove domain-specific ordering, not plain lexical sorting"
    );
    assert_eq!(
        ids.first().copied(),
        Some("claude:global:skill:example-claude-global-skill")
    );
    assert_eq!(
        ids.last().copied(),
        Some("zed:project:setting:settings-json")
    );
}

fn copy_dir_all(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("create destination");
    for entry in std::fs::read_dir(source).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).expect("copy file");
        }
    }
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, contents).expect("write file");
}

fn write_cursor_workspace_disabled_servers(
    cursor_root: &Path,
    project_root: &Path,
    raw_value: &str,
) -> PathBuf {
    write_cursor_workspace_disabled_servers_with_folder(
        cursor_root,
        &project_file_url(project_root),
        raw_value,
    )
}

fn write_cursor_marketplace_plugins(
    cursor_root: &Path,
    rows: &[(&str, serde_json::Value)],
) -> PathBuf {
    let database_path = cursor_root.join("globalStorage").join("state.vscdb");
    fs::create_dir_all(database_path.parent().expect("database parent"))
        .expect("create Cursor global storage");
    let connection = Connection::open(&database_path).expect("open Cursor global database");
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )
        .expect("create ItemTable");
    for (key, value) in rows {
        connection
            .execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                (
                    *key,
                    serde_json::to_vec(value).expect("marketplace plugin state"),
                ),
            )
            .expect("write marketplace plugin state");
    }

    database_path
}

fn write_cursor_workspace_disabled_servers_with_folder(
    cursor_root: &Path,
    folder_url: &str,
    raw_value: &str,
) -> PathBuf {
    let workspace_root = cursor_root
        .join("workspaceStorage")
        .join("sandbox-workspace");
    let database_path = workspace_root.join("state.vscdb");
    fs::create_dir_all(&workspace_root).expect("create cursor workspace storage");
    fs::write(
        workspace_root.join("workspace.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "folder": folder_url
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
    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("cursor/disabledMcpServers", raw_value.as_bytes()),
        )
        .expect("write disabled MCP state");

    database_path
}

fn project_file_url(project_root: &Path) -> String {
    format!("file://{}", project_root.display())
}
