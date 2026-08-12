mod support;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use tempfile::TempDir;
use unpin_core::{
    config::{UnpinConfig, UnpinConfigPaths, get_workspace_groups_dir},
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput, DiscoveryRoots, ProviderId,
    },
    groups::{
        GroupAccessContext, GroupContextBinding, GroupController, GroupDefinitionV1,
        GroupMemberIdentity, GroupOperationLifecycle, GroupPlanDisposition, GroupPlanMode,
        GroupPlanner, GroupRef, GroupResolver, GroupScope, GroupState, GroupTargetState,
        PersonalGroupStore, RepositoryGroupStore, validate_new_group_members,
    },
    mutation::BackupAuthenticationKey,
    sessions::SessionAuthorityKey,
    state::atomic_json::OwnerGeneration,
};

use support::{control_authorization, control_context};

fn trusted_context(root: &TempDir) -> GroupAccessContext {
    let workspace = root.path().join("workspace");
    let app_state = root.path().join("state");
    fs::create_dir_all(workspace.join(".git")).expect("workspace");
    fs::create_dir_all(&app_state).expect("state");
    let config = UnpinConfig {
        version: 1,
        app_state_root: app_state,
        cursor_root: root.path().join("cursor"),
        project_root: workspace,
        config_paths: UnpinConfigPaths {
            user_config_path: root.path().join("user.json"),
            project_config_path: root.path().join("project.json"),
        },
    };
    let roots =
        DiscoveryRoots::fixture_root(root.path()).with_app_state_root(&config.app_state_root);
    GroupAccessContext::from_config(&config, &roots, None, None).expect("trusted context")
}

fn member(id: &str, layer: DiscoveryLayer) -> GroupMemberIdentity {
    GroupMemberIdentity::new(
        ProviderId::Codex,
        DiscoveryKind::Skill,
        DiscoveryCategory::Skill,
        layer,
        id,
    )
    .expect("member")
}

fn item(identity: &GroupMemberIdentity, enabled: bool) -> DiscoveryItem {
    DiscoveryItem {
        provider: identity.provider,
        kind: identity.kind,
        category: identity.category,
        layer: identity.layer,
        id: identity.id.clone(),
        display_name: identity.id.clone(),
        enabled,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: format!("/fixture/{}", identity.id),
        state_path: format!("/fixture/state/{}", identity.id),
        source_fingerprint: Some("fixture".to_string()),
        hook: None,
    }
}

#[test]
fn canonical_definition_revision_is_order_independent_and_validated() {
    let context_root = TempDir::new().expect("tempdir");
    let context = trusted_context(&context_root);
    let first = member("codex:global:skill:alpha", DiscoveryLayer::Global);
    let second = member("codex:global:skill:beta", DiscoveryLayer::Global);
    let left = GroupDefinitionV1::new("brainstorming", vec![second.clone(), first.clone()])
        .expect("definition");
    let right = GroupDefinitionV1::new("brainstorming", vec![first, second]).expect("definition");

    assert_eq!(left, right);
    assert_eq!(
        left.revision(&GroupContextBinding::Global)
            .expect("left revision"),
        right
            .revision(&GroupContextBinding::Global)
            .expect("right revision")
    );
    assert!(GroupDefinitionV1::new("Brainstorming", left.members.clone()).is_err());
    assert!(GroupDefinitionV1::new("empty", Vec::new()).is_err());
    assert_eq!(
        context.binding_for_personal(&left),
        GroupContextBinding::Global
    );
    assert_eq!(
        serde_json::to_value(GroupContextBinding::Workspace {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
        })
        .expect("binding JSON"),
        serde_json::json!({
            "kind": "workspace",
            "repositoryKey": "repository",
            "workspaceKey": "workspace",
        })
    );
}

#[test]
fn committed_group_definition_fixtures_cover_personal_and_repository_shapes() {
    let mut personal: GroupDefinitionV1 = serde_json::from_str(
        &fs::read_to_string(fixtures_root().join("unpin/groups/brainstorming-personal-v1.json"))
            .expect("personal group fixture"),
    )
    .expect("personal group definition");
    let mut repository: GroupDefinitionV1 = serde_json::from_str(
        &fs::read_to_string(fixtures_root().join("unpin/groups/implementation-repository-v1.json"))
            .expect("repository group fixture"),
    )
    .expect("repository group definition");

    personal
        .canonicalize_and_validate()
        .expect("personal fixture verifies");
    repository
        .canonicalize_and_validate()
        .expect("repository fixture verifies");
    assert_eq!(personal.name, "brainstorming");
    assert!(
        personal
            .members
            .iter()
            .all(|member| member.layer == DiscoveryLayer::Global)
    );
    assert!(
        personal
            .members
            .iter()
            .map(|member| member.provider)
            .collect::<BTreeSet<_>>()
            .len()
            >= 4
    );
    assert_eq!(repository.name, "implementation");
    assert!(
        repository
            .members
            .iter()
            .all(|member| member.layer == DiscoveryLayer::Project)
    );
}

#[test]
fn personal_store_enforces_revision_and_workspace_binding() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let store = PersonalGroupStore::new(context.clone());
    let definition = GroupDefinitionV1::new(
        "implementation",
        vec![member(
            "codex:project:skill:implementation",
            DiscoveryLayer::Project,
        )],
    )
    .expect("definition");
    let owner = OwnerGeneration::new("groups-test", 1).expect("owner");

    let created = store
        .create(&definition, owner.clone())
        .expect("create personal group");
    assert!(matches!(
        created.binding,
        GroupContextBinding::Workspace { .. }
    ));
    assert!(store.replace(&definition, None, owner.clone()).is_err());

    let replacement = GroupDefinitionV1::new(
        "implementation",
        vec![
            member(
                "codex:project:skill:implementation",
                DiscoveryLayer::Project,
            ),
            member("codex:global:skill:shared", DiscoveryLayer::Global),
        ],
    )
    .expect("replacement");
    let replaced = store
        .replace(&replacement, Some(&created.revision), owner)
        .expect("replace personal group");
    assert_ne!(created.revision, replaced.revision);
}

#[test]
fn malformed_untrusted_repository_groups_do_not_hide_personal_groups() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let owner = OwnerGeneration::new("groups-test", 1).expect("owner");
    let personal = PersonalGroupStore::new(context.clone());
    let repository = RepositoryGroupStore::new(context.clone());
    personal
        .create(
            &GroupDefinitionV1::new(
                "personal-visible",
                vec![member(
                    "codex:global:skill:personal-visible",
                    DiscoveryLayer::Global,
                )],
            )
            .expect("definition"),
            owner,
        )
        .expect("create personal group");
    let repository_directory = get_workspace_groups_dir(context.workspace_root());
    fs::create_dir_all(&repository_directory).expect("repository groups directory");
    fs::write(repository_directory.join("groups.json"), b"{not-json")
        .expect("malformed repository group document");
    let resolver = GroupResolver::new(context, personal, repository);

    let (groups, warnings) = resolver
        .list_views_with_warnings(&DiscoveryOutput::default())
        .expect("partial group list");

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].qualified_name, "personal:personal-visible");
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].scope, GroupScope::Repository);
    assert_eq!(warnings[0].code, "repository-groups-unavailable");
}

#[test]
fn repository_store_uses_one_cas_document_and_qualified_collisions_are_ambiguous() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let owner = OwnerGeneration::new("groups-test", 1).expect("owner");
    let personal = PersonalGroupStore::new(context.clone());
    let repository = RepositoryGroupStore::new(context.clone());
    let definition = GroupDefinitionV1::new(
        "brainstorming",
        vec![member(
            "codex:global:skill:brainstorming",
            DiscoveryLayer::Global,
        )],
    )
    .expect("definition");

    personal
        .create(&definition, owner.clone())
        .expect("personal");
    repository.create(&definition, owner).expect("repository");

    let document = get_workspace_groups_dir(context.workspace_root()).join("groups.json");
    let raw = fs::read_to_string(document).expect("repository document");
    assert!(raw.contains("\"groups\""));
    assert_eq!(repository.list().expect("repository groups").len(), 1);

    let resolver = GroupResolver::new(context, personal, repository);
    let error = resolver
        .resolve_definition(&GroupRef::unqualified("brainstorming").expect("reference"))
        .expect_err("collision must be qualified");
    assert_eq!(error.candidates().len(), 2);
    assert!(
        resolver
            .resolve_definition(
                &GroupRef::qualified(GroupScope::Repository, "brainstorming").expect("reference")
            )
            .is_ok()
    );
}

#[test]
fn resolver_derives_tri_state_from_full_identity() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let owner = OwnerGeneration::new("groups-test", 1).expect("owner");
    let personal = PersonalGroupStore::new(context.clone());
    let repository = RepositoryGroupStore::new(context.clone());
    let first = member("codex:global:skill:one", DiscoveryLayer::Global);
    let second = member("codex:global:skill:two", DiscoveryLayer::Global);
    personal
        .create(
            &GroupDefinitionV1::new("mixed", vec![first.clone(), second.clone()])
                .expect("definition"),
            owner,
        )
        .expect("create");
    let discovery = DiscoveryOutput {
        items: vec![item(&first, true), item(&second, false)],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    };

    let resolver = GroupResolver::new(context, personal, repository);
    let view = resolver
        .inspect(
            &GroupRef::qualified(GroupScope::Personal, "mixed").expect("reference"),
            &discovery,
        )
        .expect("inspect");

    assert_eq!(view.state, Some(GroupState::Mixed));
    assert_eq!(view.counts.enabled, 1);
    assert_eq!(view.counts.disabled, 1);
    assert_eq!(view.fresh, Some(true));
    assert_eq!(view.provider_coverage, BTreeSet::from([ProviderId::Codex]));
}

#[test]
fn resolver_derives_uniform_state_from_blocked_members_observation() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let owner = OwnerGeneration::new("groups-test", 1).expect("owner");
    let personal = PersonalGroupStore::new(context.clone());
    let repository = RepositoryGroupStore::new(context.clone());
    let identity = member("codex:global:skill:blocked", DiscoveryLayer::Global);
    personal
        .create(
            &GroupDefinitionV1::new("blocked", vec![identity.clone()]).expect("definition"),
            owner,
        )
        .expect("create");
    let resolver = GroupResolver::new(context, personal, repository);
    let reference =
        GroupRef::qualified(GroupScope::Personal, "blocked").expect("qualified reference");

    for enabled in [true, false] {
        let mut blocked = item(&identity, enabled);
        blocked.mutability = DiscoveryMutability::ReadOnly;
        let view = resolver
            .inspect(
                &reference,
                &DiscoveryOutput {
                    items: vec![blocked],
                    warnings: Vec::new(),
                    ..DiscoveryOutput::default()
                },
            )
            .expect("inspect");

        assert_eq!(
            view.state,
            Some(if enabled {
                GroupState::On
            } else {
                GroupState::Off
            })
        );
        assert_eq!(view.counts.blocked, 1);
        assert_eq!(view.counts.enabled, usize::from(enabled));
        assert_eq!(view.counts.disabled, usize::from(!enabled));
    }
}

#[test]
fn new_member_validation_allows_retained_unresolved_members_only() {
    let root = TempDir::new().expect("tempdir");
    let context = trusted_context(&root);
    let identity = member("codex:global:skill:missing", DiscoveryLayer::Global);
    let definition =
        GroupDefinitionV1::new("retained", vec![identity.clone()]).expect("definition");

    let error = validate_new_group_members(&context, &definition, &BTreeSet::new())
        .expect_err("a new unresolved member must be rejected");
    assert!(
        error
            .to_string()
            .contains("new group member is not uniquely discoverable")
    );
    validate_new_group_members(&context, &definition, &BTreeSet::from([identity]))
        .expect("a retained unresolved member stays diagnosable");
}

#[test]
fn actionable_group_plan_applies_through_existing_toggle_safety_path() {
    let root = TempDir::new().expect("tempdir");
    let fixture_copy = root.path().join("fixtures");
    copy_dir_all(&fixtures_root(), &fixture_copy);
    let workspace = root.path().join("workspace");
    let app_state = root.path().join("state");
    fs::create_dir_all(workspace.join(".git")).expect("workspace");
    fs::create_dir_all(&app_state).expect("state");
    let roots = DiscoveryRoots::fixture_root(&fixture_copy).with_app_state_root(&app_state);
    let config_path = fixture_copy.join("codex/global/config.toml");
    let skill_path = fixture_copy.join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
    let config_source = fs::read_to_string(&config_path).expect("Codex fixture");
    fs::write(
        &config_path,
        format!(
            "{config_source}\n[[skills.config]]\npath = {:?}\nenabled = true\n",
            skill_path.to_string_lossy()
        ),
    )
    .expect("Codex skill override");
    let config = UnpinConfig {
        version: 1,
        app_state_root: app_state.clone(),
        cursor_root: root.path().join("cursor"),
        project_root: workspace,
        config_paths: UnpinConfigPaths {
            user_config_path: root.path().join("user.json"),
            project_config_path: root.path().join("project.json"),
        },
    };
    let context =
        GroupAccessContext::from_config(&config, &roots, None, None).expect("group context");
    let discovery = unpin_core::discovery::discover_all(&roots).expect("discovery");
    let discovered = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
        .expect("Codex skill");
    let identity = GroupMemberIdentity::try_from(discovered).expect("identity");
    let personal = PersonalGroupStore::new(context.clone());
    let repository = RepositoryGroupStore::new(context.clone());
    personal
        .create(
            &GroupDefinitionV1::new("implementation", vec![identity]).expect("definition"),
            OwnerGeneration::new("group-control-test", 1).expect("owner"),
        )
        .expect("create");
    let planner = GroupPlanner::new(GroupResolver::new(context.clone(), personal, repository));
    let controller = GroupController::new(
        planner,
        BackupAuthenticationKey::new([0x62; 32]),
        SessionAuthorityKey::new([0x53; 32]),
    );
    let plan = controller
        .plan(
            &GroupRef::qualified(GroupScope::Personal, "implementation").expect("reference"),
            GroupTargetState::Disable,
            10,
            GroupPlanMode::TuiDirect,
        )
        .expect("plan");
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(plan.cohorts.len(), 1);

    let expectation = plan
        .approval_expectation(&control_context(
            context.repository_key(),
            context.workspace_key(),
        ))
        .expect("expectation");
    let authorization =
        control_authorization(context.app_state_root(), &expectation, "group", 1_000);
    let result = controller.apply(&plan, authorization).expect("apply group");

    assert_eq!(result.lifecycle, GroupOperationLifecycle::Completed);
    assert_eq!(result.final_state, GroupState::Off);
    assert!(result.observation_fresh);
    let updated = fs::read_to_string(config_path).expect("updated config");
    assert!(updated.contains("enabled = false"));
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn copy_dir_all(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_dir_all(&entry.path(), &destination_path);
        } else {
            fs::copy(entry.path(), destination_path).expect("copy fixture file");
        }
    }
}
