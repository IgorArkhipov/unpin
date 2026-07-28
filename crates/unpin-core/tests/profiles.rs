use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    thread,
};

use tempfile::TempDir as RawTempDir;
use unpin_core::{
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ContributionControl, ContributionEdge, ProviderView, ToolNamespace,
    },
    discovery::DiscoveryLayer,
    profiles::{
        ActivationRequirement, CapabilityLockSnapshot, CapabilityLockState, EnforcementKind,
        GatewaySelection, MAX_PROFILE_DEFINITION_BYTES, MemberSelectionKind, PolicyResolutionError,
        PolicyScope, ProfileDefinition, ProfileDefinitionEntry, ProfileProviderOperationController,
        ProfileProviderOperationError, ProfileProviderOperationStatus,
        ProfileProviderTargetClassification, ProfileReference, ProfileRevisionSet,
        ProfileSelection, ProfileSourceScope, ProfileValidationError, ProviderPolicy,
        ResolutionPolicies, ResolvedGatewayMode, ResolvedProfileSelection, ScopePolicy,
        capability_lock_enforcement, compile_profile, propose_profile,
        resolve_effective_capabilities, resolve_effective_gateway, resolve_effective_policy,
        store::{ProfileStore, ProfileStoreError},
    },
    provider_reach::{ProviderReach, SelectedProviderProvenance},
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

fn profile_entry(
    id: &str,
    display_name: &str,
    description: &str,
    scope: ProfileSourceScope,
) -> ProfileDefinitionEntry {
    ProfileDefinitionEntry {
        scope,
        definition: ProfileDefinition {
            version: 1,
            id: id.to_string(),
            display_name: display_name.to_string(),
            description: Some(description.to_string()),
            members: Vec::new(),
            provider_members: BTreeMap::new(),
            supported_providers: BTreeSet::new(),
        },
        revision: None,
    }
}

#[test]
fn profile_proposal_is_metadata_only_scoped_and_requires_confirmation() {
    let proposal = propose_profile(
        "Please run peer review for this patch with security focus",
        "repository-key",
        "workspace-key",
        Some(ProviderId::Codex),
        [
            profile_entry(
                "review",
                "Global review",
                "peer review",
                ProfileSourceScope::Global,
            ),
            profile_entry(
                "review",
                "Workspace review",
                "peer review security",
                ProfileSourceScope::Workspace,
            ),
            profile_entry(
                "deploy",
                "Deploy",
                "release production",
                ProfileSourceScope::Global,
            ),
        ],
    )
    .expect("profile proposal");

    let recommended = proposal
        .recommended
        .as_ref()
        .expect("unique recommendation");
    assert_eq!(recommended.profile_id, "review");
    assert_eq!(recommended.scope, ProfileSourceScope::Workspace);
    assert!(recommended.matched_terms.contains(&"review".to_string()));
    assert!(proposal.confirmation_required);
    assert!(!proposal.mutates_state);
    assert_eq!(proposal.activation, "session-only-after-explicit-launch");
    assert_eq!(proposal.prompt_digest.len(), 64);
    assert_eq!(proposal.proposal_fingerprint.len(), 64);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("Please run peer review"));
}

#[test]
fn tied_profile_proposal_does_not_choose_for_user() {
    let proposal = propose_profile(
        "review",
        "repository-key",
        "workspace-key",
        None,
        [
            profile_entry("review-a", "Review A", "", ProfileSourceScope::Global),
            profile_entry("review-b", "Review B", "", ProfileSourceScope::Global),
        ],
    )
    .expect("profile proposal");

    assert_eq!(proposal.candidates.len(), 2);
    assert!(proposal.recommended.is_none());
    assert!(proposal.confirmation_required);
}

impl TempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary directory");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private temporary directory");
        }
        Self {
            _inner: inner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("valid test capability id")
}

fn record(value: &str, kind: CapabilityKind, providers: &[ProviderId]) -> CatalogRecord {
    let capability_id = id(value);
    let provider_views = providers
        .iter()
        .map(|provider| ProviderView {
            provider: *provider,
            discovery_id: format!("{}:{value}", provider.as_str()),
            layer: DiscoveryLayer::Global,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: format!("provider://{}/{value}", provider.as_str()),
            state_path: format!("provider-state://{}/{value}", provider.as_str()),
            source_fingerprint: Some(format!("source-{value}")),
        })
        .collect();
    CatalogRecord {
        id: capability_id,
        kind,
        display_name: value.to_string(),
        origin: CanonicalOrigin {
            canonical_key: format!("origin-{value}"),
            source_path: format!("local-source-{value}"),
            state_path: format!("local-state-{value}"),
            scope: CapabilityScope::Global,
            source_fingerprint: Some(format!("source-{value}")),
        },
        ownership: CapabilityOwnership::User,
        fingerprint: format!("fingerprint-{value}"),
        lifecycle: CapabilityLifecycle::discovered(true),
        state_evidence: CapabilityStateEvidence {
            observation: "fixture".to_string(),
            observed_enabled: true,
        },
        trust_requirements: CapabilityTrustRequirements::default(),
        provider_views,
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    }
}

fn profile_catalog() -> Catalog {
    let mut review = record(
        "skill.review",
        CapabilityKind::Skill,
        &[ProviderId::Claude, ProviderId::Codex, ProviderId::Cursor],
    );
    review.fingerprint = "review-v1".to_string();
    let tests = record(
        "skill.tests",
        CapabilityKind::Skill,
        &[ProviderId::Claude, ProviderId::Codex],
    );
    let base = record("skill.base", CapabilityKind::Skill, &[ProviderId::Claude]);
    let mut dependent = record(
        "skill.dependent",
        CapabilityKind::Skill,
        &[ProviderId::Claude, ProviderId::Codex],
    );
    dependent.dependencies.push(base.id.clone());
    let mut mcp = record(
        "mcp.review",
        CapabilityKind::McpServer,
        &[ProviderId::Claude, ProviderId::Codex],
    );
    mcp.trust_requirements = CapabilityTrustRequirements {
        executable_review: true,
        network_review: true,
        credential_authorization: true,
    };
    let codex_only = record(
        "skill.codex-only",
        CapabilityKind::Skill,
        &[ProviderId::Codex],
    );
    let mut tool_one = record("tool.one", CapabilityKind::McpTool, &[ProviderId::Claude]);
    tool_one.tool_namespace = Some(ToolNamespace {
        namespace: "review".to_string(),
        name: "run".to_string(),
    });
    let mut tool_two = record("tool.two", CapabilityKind::McpTool, &[ProviderId::Claude]);
    tool_two.tool_namespace = tool_one.tool_namespace.clone();

    let mut plugin = record(
        "plugin.bundle",
        CapabilityKind::Plugin,
        &[ProviderId::Claude],
    );
    let mut child = record(
        "plugin.bundle.skill",
        CapabilityKind::Skill,
        &[ProviderId::Claude],
    );
    child.contributed_by = Some(plugin.id.clone());
    child.dependencies.push(plugin.id.clone());
    plugin.contributions.push(ContributionEdge {
        capability_id: child.id.clone(),
        control: ContributionControl::Atomic,
    });

    let mut hook_one = record("hook.one", CapabilityKind::Hook, &[ProviderId::Claude]);
    hook_one.hook_conflict_key = Some("before-tool:exclusive".to_string());
    let mut hook_two = record("hook.two", CapabilityKind::Hook, &[ProviderId::Claude]);
    hook_two.hook_conflict_key = hook_one.hook_conflict_key.clone();

    Catalog::from_records([
        review, tests, base, dependent, mcp, codex_only, tool_one, tool_two, plugin, child,
        hook_one, hook_two,
    ])
    .expect("valid profile catalog")
}

fn fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/unpin/profiles")
            .join(name),
    )
    .expect("profile fixture")
}

fn definition(profile_id: &str, members: &[&str]) -> ProfileDefinition {
    ProfileDefinition {
        version: 1,
        id: profile_id.to_string(),
        display_name: profile_id.to_string(),
        description: None,
        members: members.iter().map(|value| id(value)).collect(),
        provider_members: BTreeMap::new(),
        supported_providers: BTreeSet::new(),
    }
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("profile-test", 1).expect("valid owner")
}

fn profile_policy(reference: ProfileReference) -> ScopePolicy {
    ScopePolicy {
        profile: ProfileSelection::Profile { reference },
        ..ScopePolicy::default()
    }
}

fn named_profile_revision() -> unpin_core::profiles::CompiledProfileRevision {
    let mut definition = definition("named", &["skill.review"]);
    definition.supported_providers =
        BTreeSet::from([ProviderId::Claude, ProviderId::Codex, ProviderId::Zed]);
    compile_profile(&definition, &profile_catalog(), ProfileSourceScope::Global)
        .expect("named profile revision")
}

#[test]
fn selected_provider_profile_materializes_absent_override_without_touching_generic_policy() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let store = unpin_core::profiles::PolicyStore::new(&state);
    let target = unpin_core::profiles::PolicyTarget::Global;
    store
        .save(
            &target,
            &ScopePolicy {
                profile: ProfileSelection::Native,
                ..ScopePolicy::default()
            },
            None,
            owner(),
        )
        .expect("seed generic policy");
    let revision = named_profile_revision();
    let controller = ProfileProviderOperationController::new(&state);
    let plan = controller
        .plan(
            &target,
            &revision,
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
        )
        .expect("selected provider plan");

    assert_eq!(plan.targets.len(), 1);
    assert_eq!(
        plan.targets[0].classification,
        ProfileProviderTargetClassification::Create
    );
    assert!(plan.targets[0].prior_provider_policy.is_none());
    let applied = controller
        .apply(&plan, "profile-provider-test")
        .expect("apply");
    assert_eq!(applied.status, ProfileProviderOperationStatus::Applied);
    let snapshot = store
        .load(&target)
        .expect("load policy")
        .expect("policy snapshot");
    assert_eq!(snapshot.policy.profile, ProfileSelection::Native);
    assert!(matches!(
        snapshot
            .policy
            .providers
            .get(&ProviderId::Codex)
            .expect("Codex override")
            .profile,
        ProfileSelection::Profile { .. }
    ));
}

#[test]
fn existing_inherit_provider_override_is_classified_as_replace() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let target = unpin_core::profiles::PolicyTarget::Global;
    let store = unpin_core::profiles::PolicyStore::new(&state);
    store
        .save(
            &target,
            &ScopePolicy {
                providers: BTreeMap::from([(ProviderId::Codex, ProviderPolicy::default())]),
                ..ScopePolicy::default()
            },
            None,
            owner(),
        )
        .expect("seed inherited provider override");
    let controller = ProfileProviderOperationController::new(&state);
    let plan = controller
        .plan(
            &target,
            &named_profile_revision(),
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
        )
        .expect("selected provider plan");
    assert_eq!(
        plan.targets[0].classification,
        ProfileProviderTargetClassification::Replace
    );
}

#[test]
fn all_provider_profile_operation_is_one_scope_cas_with_inverse_evidence() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let target = unpin_core::profiles::PolicyTarget::Global;
    let revision = named_profile_revision();
    let store = unpin_core::profiles::PolicyStore::new(&state);
    let prior = ScopePolicy {
        providers: BTreeMap::from([(
            ProviderId::Claude,
            ProviderPolicy {
                profile: ProfileSelection::Native,
                ..ProviderPolicy::default()
            },
        )]),
        ..ScopePolicy::default()
    };
    let seeded = store
        .save(
            &target,
            &prior,
            None,
            OwnerGeneration::new("seed", 1).expect("seed owner"),
        )
        .expect("seed policy");
    let controller = ProfileProviderOperationController::new(&state);
    let plan = controller
        .plan(&target, &revision, ProviderReach::all())
        .expect("all-provider plan");
    assert_eq!(
        plan.targets
            .iter()
            .map(|target| target.provider)
            .collect::<BTreeSet<_>>(),
        revision.supported_providers().clone()
    );
    assert!(
        plan.targets
            .iter()
            .any(|target| target.classification == ProfileProviderTargetClassification::Replace)
    );
    assert!(
        plan.targets
            .iter()
            .any(|target| target.classification == ProfileProviderTargetClassification::Create)
    );
    let applied = controller
        .apply(&plan, "profile-provider-test")
        .expect("apply");
    assert_eq!(applied.status, ProfileProviderOperationStatus::Applied);
    let applied_revision = applied.revision.clone().expect("applied revision");
    assert_eq!(applied_revision.sequence, seeded.sequence + 1);
    assert_eq!(applied.inverse_evidence.len(), 3);
    let current = store
        .load(&target)
        .expect("load final policy")
        .expect("final policy");
    assert_eq!(current.revision, applied_revision);
    for provider in revision.supported_providers() {
        assert!(matches!(
            current
                .policy
                .providers
                .get(provider)
                .map(|policy| &policy.profile),
            Some(ProfileSelection::Profile { .. })
        ));
    }
}

#[test]
fn provider_profile_operation_blocks_stale_pre_state_before_write() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let target = unpin_core::profiles::PolicyTarget::Global;
    let revision = named_profile_revision();
    let store = unpin_core::profiles::PolicyStore::new(&state);
    store
        .save(
            &target,
            &ScopePolicy::default(),
            None,
            OwnerGeneration::new("seed", 1).expect("seed owner"),
        )
        .expect("seed policy");
    let controller = ProfileProviderOperationController::new(&state);
    let plan = controller
        .plan(&target, &revision, ProviderReach::all())
        .expect("plan");
    store
        .save(
            &target,
            &ScopePolicy {
                gateway: GatewaySelection::Native,
                ..ScopePolicy::default()
            },
            plan.expected_revision.as_ref(),
            OwnerGeneration::new("other", 2).expect("concurrent owner"),
        )
        .expect("mutate stale state");
    assert!(matches!(
        controller.apply(&plan, "profile-provider-test"),
        Err(ProfileProviderOperationError::StalePreState { .. })
    ));
}

#[test]
fn provider_profile_fingerprint_is_stable_for_target_order_and_recovery_is_not_partial() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let target = unpin_core::profiles::PolicyTarget::Global;
    let revision = named_profile_revision();
    let controller = ProfileProviderOperationController::new(&state);
    let first = controller
        .plan(&target, &revision, ProviderReach::all())
        .expect("first plan");
    let second = controller
        .plan(&target, &revision, ProviderReach::all())
        .expect("second plan");
    assert_eq!(first.plan_fingerprint, second.plan_fingerprint);
    let mut reordered = first.clone();
    reordered.targets.reverse();
    reordered.inverse_evidence.reverse();
    assert!(reordered.verify().is_ok());
    assert_eq!(reordered.plan_fingerprint, first.plan_fingerprint);

    let mut removed = first.clone();
    removed.targets.pop();
    assert!(removed.verify().is_err());
    let mut added = first.clone();
    added.targets.push(added.targets[0].clone());
    assert!(added.verify().is_err());
    let mut changed = first.clone();
    changed.targets[0].post_state_fingerprint.push('0');
    assert!(changed.verify().is_err());

    let result = controller
        .apply_with_verifier(&first, "profile-provider-test", |_| {
            Err("injected post-commit verification failure".to_string())
        })
        .expect_err("post-commit failure");
    assert!(matches!(
        result,
        ProfileProviderOperationError::RecoveryRequired { .. }
    ));
}

#[test]
fn all_provider_restore_removes_created_and_restores_replaced_overrides_atomically() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let target = unpin_core::profiles::PolicyTarget::Global;
    let revision = named_profile_revision();
    let store = unpin_core::profiles::PolicyStore::new(&state);
    let prior = ScopePolicy {
        profile: ProfileSelection::Native,
        providers: BTreeMap::from([(
            ProviderId::Claude,
            ProviderPolicy {
                profile: ProfileSelection::Native,
                ..ProviderPolicy::default()
            },
        )]),
        ..ScopePolicy::default()
    };
    let seeded = store
        .save(
            &target,
            &prior,
            None,
            OwnerGeneration::new("seed", 1).expect("seed owner"),
        )
        .expect("seed policy");
    let controller = ProfileProviderOperationController::new(&state);
    let plan = controller
        .plan(&target, &revision, ProviderReach::all())
        .expect("all-provider plan");
    let applied = controller
        .apply(&plan, "profile-provider-test")
        .expect("apply all providers");
    let applied_revision = applied.revision.clone().expect("applied revision");
    assert_eq!(applied_revision.sequence, seeded.sequence + 1);
    let restored_revision = controller
        .restore(&plan, &applied, "profile-provider-restore")
        .expect("restore all providers");
    assert_eq!(restored_revision.sequence, applied_revision.sequence + 1);

    let restored = store
        .load(&target)
        .expect("load restored policy")
        .expect("restored policy");
    assert_eq!(restored.revision, restored_revision);
    assert_eq!(restored.policy.profile, ProfileSelection::Native);
    assert_eq!(
        restored
            .policy
            .providers
            .get(&ProviderId::Claude)
            .expect("replaced provider")
            .profile,
        ProfileSelection::Native
    );
    assert!(!restored.policy.providers.contains_key(&ProviderId::Codex));
    assert!(!restored.policy.providers.contains_key(&ProviderId::Zed));
}

#[test]
fn profile_fixture_compiles_to_immutable_fingerprint_pinned_revision() {
    let catalog = profile_catalog();
    let definition =
        ProfileDefinition::from_json(&fixture("review-v1.json")).expect("profile definition");
    let revision = compile_profile(&definition, &catalog, ProfileSourceScope::Global)
        .expect("compiled profile");

    revision.verify_digest().expect("revision digest");
    assert_eq!(revision.profile_id, "review");
    assert_eq!(revision.members.len(), 2);
    assert!(revision.requires_local_review);
    assert!(revision.members.iter().any(|member| {
        member.capability_id == id("skill.review")
            && member.capability_fingerprint == "review-v1"
            && member.selection_kind == MemberSelectionKind::Generic
    }));
    assert_eq!(revision.members_for_provider(ProviderId::Codex).count(), 2);
    assert_eq!(revision.members_for_provider(ProviderId::Cursor).count(), 1);
    let exported = definition.to_export_json().expect("exportable definition");
    assert!(!exported.contains("sourcePath"));
    assert!(!exported.contains("statePath"));
    assert!(!exported.contains("credentialAlias"));
    assert_eq!(
        ProfileDefinition::from_json(&exported).expect("round-trip definition"),
        definition
    );
}

#[test]
fn profile_validation_rejects_dependency_namespace_mapping_atomicity_and_hook_conflicts() {
    let catalog = profile_catalog();

    assert!(matches!(
        compile_profile(
            &definition("missing-dependency", &["skill.dependent"]),
            &catalog,
            ProfileSourceScope::Global,
        ),
        Err(ProfileValidationError::MissingDependency { .. })
    ));
    assert!(matches!(
        compile_profile(
            &definition(
                "dependency-provider-mismatch",
                &["skill.dependent", "skill.base"]
            ),
            &catalog,
            ProfileSourceScope::Global,
        ),
        Err(ProfileValidationError::DependencyProviderMismatch { .. })
    ));
    assert!(matches!(
        compile_profile(
            &definition("ambiguous-tools", &["tool.one", "tool.two"]),
            &catalog,
            ProfileSourceScope::Global,
        ),
        Err(ProfileValidationError::AmbiguousToolNamespace { .. })
    ));

    let mut incompatible = definition("incompatible", &[]);
    incompatible
        .provider_members
        .insert(ProviderId::Claude, vec![id("skill.codex-only")]);
    assert!(matches!(
        compile_profile(&incompatible, &catalog, ProfileSourceScope::Global),
        Err(ProfileValidationError::IncompatibleProviderMapping { .. })
    ));
    assert!(matches!(
        compile_profile(
            &definition("split-plugin", &["plugin.bundle.skill"]),
            &catalog,
            ProfileSourceScope::Global,
        ),
        Err(ProfileValidationError::AtomicContributionSplit { .. })
    ));
    assert!(matches!(
        compile_profile(
            &definition("hook-conflict", &["hook.one", "hook.two"]),
            &catalog,
            ProfileSourceScope::Global,
        ),
        Err(ProfileValidationError::ConflictingHookPolicy { .. })
    ));

    let mut duplicate = definition("duplicate", &["skill.review", "skill.review"]);
    assert!(matches!(
        compile_profile(&duplicate, &catalog, ProfileSourceScope::Global),
        Err(ProfileValidationError::DuplicateMember { .. })
    ));
    duplicate.members.pop();
    duplicate
        .provider_members
        .insert(ProviderId::Claude, vec![id("skill.review")]);
    assert!(matches!(
        compile_profile(&duplicate, &catalog, ProfileSourceScope::Global),
        Err(ProfileValidationError::DuplicateMember { .. })
    ));
}

#[test]
fn export_parser_rejects_credentials_trust_backup_runtime_and_machine_paths() {
    assert!(matches!(
        ProfileDefinition::from_json(&" ".repeat(MAX_PROFILE_DEFINITION_BYTES + 1)),
        Err(ProfileValidationError::DefinitionTooLarge { .. })
    ));
    assert!(matches!(
        ProfileDefinition::from_json(&fixture("forbidden-credential.json")),
        Err(ProfileValidationError::NonExportableField { .. })
    ));
    assert!(matches!(
        ProfileDefinition::from_json(&fixture("forbidden-path.json")),
        Err(ProfileValidationError::NonExportableValue { .. })
    ));
    assert!(matches!(
        ProfileDefinition::from_json(
            r#"{"version":1,"id":"relative-path","displayName":"Relative","description":"../private/hook.sh","members":[]}"#
        ),
        Err(ProfileValidationError::NonExportableValue { .. })
    ));
    for field in ["trust", "backupId", "runtimeLease", "sourcePath", "token"] {
        let raw = format!(
            r#"{{"version":1,"id":"unsafe","displayName":"Unsafe","members":[],"{field}":"value"}}"#
        );
        assert!(matches!(
            ProfileDefinition::from_json(&raw),
            Err(ProfileValidationError::NonExportableField { .. })
        ));
    }
    let invalid_member: ProfileDefinition = serde_json::from_value(serde_json::json!({
        "version": 1,
        "id": "unsafe-member",
        "displayName": "Unsafe member",
        "members": ["private/path"]
    }))
    .expect("serde shape permits validation test");
    assert!(matches!(
        invalid_member.to_export_json(),
        Err(ProfileValidationError::InvalidCapabilityId { .. })
    ));
}

#[test]
fn untrusted_workspace_profile_compiles_risky_capability_without_side_effects_or_credentials() {
    let temp = TempDir::new();
    let sentinel = temp.path().join("must-not-exist");
    let credential_alias = "machine-keychain-production";
    let mut catalog = profile_catalog();
    let mcp = catalog
        .records
        .get_mut(&id("mcp.review"))
        .expect("risky MCP record");
    mcp.origin.source_path = format!("command:touch {}", sentinel.display());
    mcp.origin.state_path = credential_alias.to_string();

    let revision = compile_profile(
        &definition("untrusted-branch", &["mcp.review"]),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("compile untrusted profile as inert intent");
    assert!(
        !sentinel.exists(),
        "profile compilation must not execute commands"
    );
    assert!(revision.requires_local_review);
    let serialized = serde_json::to_string(&revision).expect("compiled revision JSON");
    assert!(!serialized.contains(sentinel.to_string_lossy().as_ref()));
    assert!(!serialized.contains(credential_alias));
}

#[test]
fn selecting_atomic_plugin_expands_all_declared_contributions() {
    let mut catalog = profile_catalog();
    let mut grandchild = record(
        "plugin.bundle.skill.hook",
        CapabilityKind::Hook,
        &[ProviderId::Claude],
    );
    grandchild.contributed_by = Some(id("plugin.bundle.skill"));
    grandchild.dependencies.push(id("plugin.bundle.skill"));
    catalog
        .records
        .get_mut(&id("plugin.bundle.skill"))
        .expect("nested atomic parent")
        .contributions
        .push(ContributionEdge {
            capability_id: grandchild.id.clone(),
            control: ContributionControl::Atomic,
        });
    catalog.insert(grandchild).expect("nested contribution");
    let revision = compile_profile(
        &definition("plugin", &["plugin.bundle"]),
        &catalog,
        ProfileSourceScope::Global,
    )
    .expect("atomic plugin profile");
    assert_eq!(revision.members.len(), 3);
    let child = revision
        .members
        .iter()
        .find(|member| member.capability_id == id("plugin.bundle.skill"))
        .expect("expanded child");
    assert_eq!(
        child.selection_kind,
        MemberSelectionKind::AtomicContribution
    );
    assert_eq!(child.contributed_by.as_ref(), Some(&id("plugin.bundle")));
    let grandchild = revision
        .members
        .iter()
        .find(|member| member.capability_id == id("plugin.bundle.skill.hook"))
        .expect("nested expanded child");
    assert_eq!(
        grandchild.contributed_by.as_ref(),
        Some(&id("plugin.bundle.skill"))
    );
}

#[test]
fn resolver_uses_replace_not_merge_precedence_for_profile_and_gateway_slots() {
    let catalog = profile_catalog();
    let global_revision = compile_profile(
        &definition("global", &["skill.review"]),
        &catalog,
        ProfileSourceScope::Global,
    )
    .expect("global revision");
    let session_revision = compile_profile(
        &definition("session", &["skill.tests"]),
        &catalog,
        ProfileSourceScope::Session,
    )
    .expect("session revision");
    let mut revisions = ProfileRevisionSet::default();
    revisions
        .insert(global_revision.clone())
        .expect("global revision set");
    revisions
        .insert(session_revision.clone())
        .expect("session revision set");

    let mut policies = ResolutionPolicies {
        global: ScopePolicy {
            profile: ProfileSelection::Profile {
                reference: (&global_revision).into(),
            },
            gateway: GatewaySelection::Gateway,
            providers: BTreeMap::new(),
        },
        repository: Some(ScopePolicy {
            profile: ProfileSelection::None,
            gateway: GatewaySelection::Inherit,
            providers: BTreeMap::new(),
        }),
        workspace: Some(ScopePolicy {
            profile: ProfileSelection::Native,
            gateway: GatewaySelection::Native,
            providers: BTreeMap::new(),
        }),
        session: Some(ScopePolicy {
            profile: ProfileSelection::Profile {
                reference: (&session_revision).into(),
            },
            gateway: GatewaySelection::Gateway,
            providers: BTreeMap::from([(
                ProviderId::Cursor,
                ProviderPolicy {
                    profile: ProfileSelection::None,
                    gateway: GatewaySelection::Native,
                    ..ProviderPolicy::default()
                },
            )]),
        }),
    };

    let cursor =
        resolve_effective_policy(ProviderId::Cursor, &policies, &revisions).expect("Cursor policy");
    assert!(matches!(cursor.profile, ResolvedProfileSelection::None));
    assert_eq!(cursor.profile_source.scope, PolicyScope::Session);
    assert!(cursor.profile_source.provider_specific);
    assert_eq!(cursor.gateway, ResolvedGatewayMode::Native);
    assert!(cursor.gateway_source.provider_specific);

    let codex =
        resolve_effective_policy(ProviderId::Codex, &policies, &revisions).expect("Codex policy");
    assert!(matches!(
        codex.profile,
        ResolvedProfileSelection::Profile(ref revision)
            if revision.digest == session_revision.digest
    ));
    assert_eq!(codex.profile_source.scope, PolicyScope::Session);
    assert!(!codex.profile_source.provider_specific);
    assert_eq!(codex.gateway, ResolvedGatewayMode::Gateway);

    policies.session = None;
    let workspace = resolve_effective_policy(ProviderId::Codex, &policies, &revisions)
        .expect("workspace native sentinel");
    assert!(matches!(
        workspace.profile,
        ResolvedProfileSelection::Native
    ));
    assert_eq!(workspace.profile_source.scope, PolicyScope::Workspace);
    assert_eq!(workspace.gateway, ResolvedGatewayMode::Native);
    assert_eq!(
        resolve_effective_gateway(ProviderId::Codex, &policies),
        (ResolvedGatewayMode::Native, workspace.gateway_source)
    );

    policies.workspace = None;
    let repository = resolve_effective_policy(ProviderId::Codex, &policies, &revisions)
        .expect("repository none sentinel");
    assert!(matches!(repository.profile, ResolvedProfileSelection::None));
    assert_eq!(repository.profile_source.scope, PolicyScope::Repository);
    assert_eq!(repository.gateway, ResolvedGatewayMode::Gateway);
    assert_eq!(repository.gateway_source.scope, PolicyScope::Global);
}

#[test]
fn global_provider_locks_apply_after_workspace_profile_selection() {
    let catalog = profile_catalog();
    let workspace_revision = compile_profile(
        &definition("workspace", &["skill.review"]),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("workspace revision");
    let mut revisions = ProfileRevisionSet::default();
    revisions
        .insert(workspace_revision.clone())
        .expect("revision set");

    let policies = ResolutionPolicies {
        global: ScopePolicy {
            providers: BTreeMap::from([(
                ProviderId::Claude,
                ProviderPolicy {
                    capability_locks: BTreeMap::from([
                        (id("skill.review"), CapabilityLockState::HardDisabled),
                        (id("skill.tests"), CapabilityLockState::HardEnabled),
                    ]),
                    ..ProviderPolicy::default()
                },
            )]),
            ..ScopePolicy::default()
        },
        repository: Some(ScopePolicy {
            providers: BTreeMap::from([(
                ProviderId::Claude,
                ProviderPolicy {
                    capability_locks: BTreeMap::from([(
                        id("skill.tests"),
                        CapabilityLockState::HardDisabled,
                    )]),
                    ..ProviderPolicy::default()
                },
            )]),
            ..ScopePolicy::default()
        }),
        workspace: Some(profile_policy((&workspace_revision).into())),
        session: None,
    };

    let effective =
        resolve_effective_policy(ProviderId::Claude, &policies, &revisions).expect("policy");
    assert_eq!(effective.profile_source.scope, PolicyScope::Workspace);
    assert_eq!(effective.capability_locks.provider, ProviderId::Claude);
    effective
        .capability_locks
        .verify()
        .expect("lock snapshot digest");

    let selected =
        resolve_effective_capabilities(&effective, &catalog).expect("effective capabilities");
    assert_eq!(selected, BTreeSet::from([id("skill.tests")]));
}

#[test]
fn capability_lock_enforcement_reports_strength_without_overclaiming_native_support() {
    let mut catalog = profile_catalog();
    catalog
        .records
        .get_mut(&id("skill.tests"))
        .unwrap()
        .provider_views
        .iter_mut()
        .find(|view| view.provider == ProviderId::Claude)
        .unwrap()
        .mutability = CapabilityMutability::ReadOnly;
    let snapshot = CapabilityLockSnapshot::compile(
        ProviderId::Claude,
        BTreeMap::from([
            (id("skill.review"), CapabilityLockState::HardDisabled),
            (id("mcp.review"), CapabilityLockState::HardEnabled),
            (id("skill.tests"), CapabilityLockState::HardEnabled),
            (id("skill.codex-only"), CapabilityLockState::HardDisabled),
            (id("skill.missing"), CapabilityLockState::HardDisabled),
        ]),
    )
    .unwrap();

    let reports = capability_lock_enforcement(&snapshot, &catalog, ResolvedGatewayMode::Gateway);
    let enforcement = |capability: &str| {
        reports
            .iter()
            .find(|report| report.capability_id == id(capability))
            .unwrap()
    };
    assert_eq!(
        enforcement("skill.review").enforcement,
        EnforcementKind::GatewayStrict
    );
    assert_eq!(
        enforcement("mcp.review").enforcement,
        EnforcementKind::NativeBestEffort
    );
    assert_eq!(
        enforcement("skill.tests").enforcement,
        EnforcementKind::ReadOnly
    );
    assert_eq!(
        enforcement("skill.codex-only").enforcement,
        EnforcementKind::Unsupported
    );
    assert_eq!(
        enforcement("skill.missing").enforcement,
        EnforcementKind::Unsupported
    );
    assert!(reports.iter().all(|report| {
        report.source == PolicyScope::Global
            && report.activation == ActivationRequirement::NextSessionOnly
    }));
}

#[test]
fn repository_default_is_shared_while_workspace_override_and_branch_digests_stay_isolated() {
    let catalog = profile_catalog();
    let global = compile_profile(
        &definition("review", &["skill.review"]),
        &catalog,
        ProfileSourceScope::Global,
    )
    .expect("global revision");
    let workspace_a = compile_profile(
        &ProfileDefinition::from_json(&fixture("review-v1.json")).expect("workspace v1"),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("workspace revision one");
    let workspace_b = compile_profile(
        &ProfileDefinition::from_json(&fixture("review-v2.json")).expect("workspace v2"),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("workspace revision two");
    assert_eq!(workspace_a.profile_id, workspace_b.profile_id);
    assert_ne!(workspace_a.digest, workspace_b.digest);
    assert_ne!(
        workspace_a.origin.definition_digest,
        workspace_b.origin.definition_digest
    );
    assert!(workspace_a.requires_local_review);
    let compiled_json = serde_json::to_string(&workspace_a).expect("compiled profile JSON");
    assert!(!compiled_json.contains("local-source"));
    assert!(!compiled_json.contains("provider://"));

    let mut revisions = ProfileRevisionSet::default();
    for revision in [&global, &workspace_a, &workspace_b] {
        revisions.insert(revision.clone()).expect("revision set");
    }
    let repository = profile_policy((&global).into());
    let common = ResolutionPolicies {
        global: ScopePolicy::default(),
        repository: Some(repository.clone()),
        workspace: None,
        session: None,
    };
    let first_worktree = resolve_effective_policy(ProviderId::Claude, &common, &revisions)
        .expect("repository default in first worktree");
    let second_worktree = resolve_effective_policy(ProviderId::Claude, &common, &revisions)
        .expect("repository default in second worktree");
    assert_eq!(first_worktree, second_worktree);

    let branch_a_policies = ResolutionPolicies {
        workspace: Some(profile_policy((&workspace_a).into())),
        ..common.clone()
    };
    let branch_b_policies = ResolutionPolicies {
        workspace: Some(profile_policy((&workspace_b).into())),
        ..common
    };
    let pinned_a = resolve_effective_policy(ProviderId::Claude, &branch_a_policies, &revisions)
        .expect("branch A revision");
    let pinned_b = resolve_effective_policy(ProviderId::Claude, &branch_b_policies, &revisions)
        .expect("branch B revision");
    assert!(matches!(
        pinned_a.profile,
        ResolvedProfileSelection::Profile(ref revision)
            if revision.digest == workspace_a.digest
    ));
    assert!(matches!(
        pinned_b.profile,
        ResolvedProfileSelection::Profile(ref revision)
            if revision.digest == workspace_b.digest
    ));

    let session_a_snapshot = pinned_a.clone();
    let session_b = resolve_effective_policy(ProviderId::Claude, &branch_b_policies, &revisions)
        .expect("new session B revision");
    assert_eq!(session_a_snapshot, pinned_a);
    assert_ne!(session_a_snapshot.profile, session_b.profile);
}

#[test]
fn repository_policy_rejects_checked_out_workspace_revision() {
    let revision = compile_profile(
        &definition("workspace", &["skill.review"]),
        &profile_catalog(),
        ProfileSourceScope::Workspace,
    )
    .expect("workspace revision");
    let mut revisions = ProfileRevisionSet::default();
    revisions.insert(revision.clone()).expect("revision set");
    let policies = ResolutionPolicies {
        repository: Some(profile_policy((&revision).into())),
        ..ResolutionPolicies::default()
    };
    assert!(matches!(
        resolve_effective_policy(ProviderId::Claude, &policies, &revisions),
        Err(PolicyResolutionError::InvalidOriginForPolicy { .. })
    ));
}

#[test]
fn resolver_rejects_profile_without_selected_provider_coverage() {
    let revision = compile_profile(
        &definition("claude-only", &["skill.base"]),
        &profile_catalog(),
        ProfileSourceScope::Global,
    )
    .expect("Claude-only revision");
    let mut revisions = ProfileRevisionSet::default();
    revisions.insert(revision.clone()).expect("revision set");
    let policies = ResolutionPolicies {
        global: profile_policy((&revision).into()),
        ..ResolutionPolicies::default()
    };
    assert!(matches!(
        resolve_effective_policy(ProviderId::Codex, &policies, &revisions),
        Err(PolicyResolutionError::ProfileUnavailableForProvider { .. })
    ));
}

#[test]
fn simultaneous_resolvers_are_pure_and_keep_worktree_results_disjoint() {
    let catalog = profile_catalog();
    let first = compile_profile(
        &definition("first", &["skill.review"]),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("first revision");
    let second = compile_profile(
        &definition("second", &["skill.tests"]),
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("second revision");
    let mut revisions = ProfileRevisionSet::default();
    revisions.insert(first.clone()).expect("first revision set");
    revisions
        .insert(second.clone())
        .expect("second revision set");

    let handles = [first.clone(), second.clone()].map(|revision| {
        let revisions = revisions.clone();
        thread::spawn(move || {
            resolve_effective_policy(
                ProviderId::Claude,
                &ResolutionPolicies {
                    workspace: Some(profile_policy((&revision).into())),
                    ..ResolutionPolicies::default()
                },
                &revisions,
            )
            .expect("parallel resolution")
        })
    });
    let results = handles.map(|handle| handle.join().expect("resolver thread"));
    let digests = results
        .iter()
        .map(|result| match &result.profile {
            ResolvedProfileSelection::Profile(revision) => revision.digest.clone(),
            other => panic!("expected profile, got {other:?}"),
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(digests, BTreeSet::from([first.digest, second.digest]));
}

#[test]
fn profile_store_keeps_definitions_mutable_and_revisions_content_addressed() {
    let temp = TempDir::new();
    let store = ProfileStore::new(temp.path().join("state"));
    let catalog = profile_catalog();
    let first_definition =
        ProfileDefinition::from_json(&fixture("review-v1.json")).expect("first definition");
    let first_state_revision = store
        .save_global_definition(&first_definition, None, owner())
        .expect("save first definition");
    let compiled = compile_profile(&first_definition, &catalog, ProfileSourceScope::Global)
        .expect("compiled definition");
    let materialized = store
        .materialize_revision(&compiled, owner())
        .expect("materialize revision");
    assert_eq!(
        store
            .load_revision(&compiled.digest)
            .expect("load revision"),
        Some(compiled.clone())
    );
    assert_eq!(
        store
            .materialize_revision(&compiled, owner())
            .expect("idempotent materialization"),
        materialized
    );

    let second_definition =
        ProfileDefinition::from_json(&fixture("review-v2.json")).expect("second definition");
    store
        .save_global_definition(&second_definition, Some(&first_state_revision), owner())
        .expect("replace global definition");
    assert_eq!(
        store
            .load_global_definition("review")
            .expect("load definition")
            .expect("saved definition")
            .value,
        second_definition
    );
    assert!(matches!(
        store.load_global_definition("../outside"),
        Err(ProfileStoreError::InvalidProfileId { .. })
    ));
    assert!(matches!(
        store.load_revision("../outside"),
        Err(ProfileStoreError::InvalidDigest { .. })
    ));
}

#[test]
fn profile_inventory_keeps_global_and_workspace_definitions_explicit() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let store = ProfileStore::new(&state);
    let global =
        ProfileDefinition::from_json(&fixture("review-v1.json")).expect("global definition");
    store
        .save_global_definition(&global, None, owner())
        .expect("save global definition");
    let workspace_definition = ProfileDefinition {
        id: "workspace-review".to_string(),
        display_name: "Workspace review".to_string(),
        ..global.clone()
    };
    let workspace_profiles = unpin_core::config::get_workspace_profiles_dir(&workspace);
    fs::create_dir_all(&workspace_profiles).unwrap();
    fs::write(
        workspace_profiles.join("workspace-review.json"),
        workspace_definition.to_export_json().unwrap(),
    )
    .unwrap();

    let global_entries = store.list_global_definitions().unwrap();
    let workspace_entries = ProfileStore::list_workspace_definitions(&workspace).unwrap();
    assert_eq!(global_entries.len(), 1);
    assert_eq!(global_entries[0].scope, ProfileSourceScope::Global);
    assert!(global_entries[0].revision.is_some());
    assert_eq!(workspace_entries.len(), 1);
    assert_eq!(workspace_entries[0].scope, ProfileSourceScope::Workspace);
    assert!(workspace_entries[0].revision.is_none());
    assert_eq!(
        ProfileStore::load_workspace_definition(&workspace, "workspace-review")
            .unwrap()
            .unwrap()
            .definition,
        workspace_definition
    );
}
