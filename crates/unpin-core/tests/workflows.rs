use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use unpin_core::{
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ProviderView,
    },
    discovery::DiscoveryLayer,
    profiles::{
        CapabilityLockSnapshot, CapabilityLockState, PROFILE_DEFINITION_VERSION, ProfileDefinition,
        ProfileSourceScope, compile_profile,
    },
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration},
    workflows::{
        GENERAL_MODE, IMPLEMENTATION_MODE, PLANNING_MODE, REVIEW_MODE, WORKFLOW_DEFINITION_VERSION,
        WorkflowControl, WorkflowControlEffect, WorkflowDefinition, WorkflowModeDefinition,
        WorkflowStore, WorkflowStoreError, WorkflowValidationError, compile_workflow, preset_modes,
        workspace_workflows_dir,
    },
};

fn id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("valid capability id")
}

fn record(value: &str, kind: CapabilityKind) -> CatalogRecord {
    CatalogRecord {
        id: id(value),
        kind,
        display_name: value.to_string(),
        origin: CanonicalOrigin {
            canonical_key: format!("origin-{value}"),
            source_path: format!("fixture-source-{value}"),
            state_path: format!("fixture-state-{value}"),
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
        provider_views: vec![ProviderView {
            provider: ProviderId::Codex,
            discovery_id: format!("codex:{value}"),
            layer: DiscoveryLayer::Global,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: format!("provider-source-{value}"),
            state_path: format!("provider-state-{value}"),
            source_fingerprint: Some(format!("source-{value}")),
        }],
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    }
}

fn profile(
    profile_id: &str,
    members: &[&str],
    catalog: &Catalog,
) -> unpin_core::profiles::CompiledProfileRevision {
    compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: profile_id.to_string(),
            display_name: profile_id.to_string(),
            description: None,
            members: members.iter().map(|value| id(value)).collect(),
            provider_members: BTreeMap::new(),
            supported_providers: BTreeSet::new(),
        },
        catalog,
        ProfileSourceScope::Global,
    )
    .expect("compiled profile")
}

fn workflow_definition() -> WorkflowDefinition {
    WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: "delivery".to_string(),
        display_name: "Delivery".to_string(),
        description: None,
        baseline_profile_id: "baseline".to_string(),
        entry_mode: "planning".to_string(),
        modes: vec![
            WorkflowModeDefinition::new("planning", "planning"),
            WorkflowModeDefinition::new("implementation", "implementation"),
        ],
    }
}

fn workflow_fixture() -> (
    Catalog,
    BTreeMap<String, unpin_core::profiles::CompiledProfileRevision>,
) {
    let catalog = Catalog::from_records([
        record("skill.shared", CapabilityKind::Skill),
        record("skill.plan", CapabilityKind::Skill),
        record("skill.build", CapabilityKind::Skill),
        record("skill.outside", CapabilityKind::Skill),
    ])
    .expect("catalog");
    let profiles = BTreeMap::from([
        (
            "baseline".to_string(),
            profile("baseline", &["skill.shared"], &catalog),
        ),
        (
            "planning".to_string(),
            profile("planning", &["skill.plan", "skill.shared"], &catalog),
        ),
        (
            "implementation".to_string(),
            profile("implementation", &["skill.build"], &catalog),
        ),
    ]);
    (catalog, profiles)
}

fn locks(entries: &[(&str, CapabilityLockState)]) -> CapabilityLockSnapshot {
    CapabilityLockSnapshot::compile(
        ProviderId::Codex,
        entries
            .iter()
            .map(|(capability, state)| (id(capability), *state))
            .collect(),
    )
    .expect("capability locks")
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("workflow-test", 1).expect("owner")
}

fn compile_fixture(
    definition: &WorkflowDefinition,
) -> unpin_core::workflows::CompiledWorkflowRevision {
    let (catalog, profiles) = workflow_fixture();
    compile_workflow(
        definition,
        &profiles,
        &catalog,
        &CapabilityLockSnapshot::empty(ProviderId::Codex),
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("compiled workflow")
}

#[test]
fn workflow_compilation_is_deterministic_and_uses_baseline_plus_one_mode() {
    let (catalog, profiles) = workflow_fixture();
    let definition = workflow_definition();
    let locks = CapabilityLockSnapshot::empty(ProviderId::Codex);
    let first = compile_workflow(
        &definition,
        &profiles,
        &catalog,
        &locks,
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("compiled workflow");
    let mut reordered = definition.clone();
    reordered.modes.reverse();
    let second = compile_workflow(
        &reordered,
        &profiles,
        &catalog,
        &locks,
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("reordered workflow");

    assert_eq!(first.digest, second.digest);
    assert_eq!(first.effective_profiles["planning"].members.len(), 2);
    assert_eq!(first.effective_profiles["implementation"].members.len(), 2);
    assert_eq!(first.maximum_envelope.members.len(), 3);
}

#[test]
fn hard_enabled_capability_in_the_envelope_is_added_to_every_mode() {
    let (catalog, profiles) = workflow_fixture();
    let compiled = compile_workflow(
        &workflow_definition(),
        &profiles,
        &catalog,
        &locks(&[("skill.build", CapabilityLockState::HardEnabled)]),
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("hard-enabled in-envelope capability");

    assert!(compiled.effective_profiles["planning"].contains(&id("skill.build")));
    assert!(compiled.maximum_envelope.contains(&id("skill.build")));
}

#[test]
fn hard_enabled_capability_outside_the_envelope_is_rejected() {
    let (catalog, profiles) = workflow_fixture();
    assert!(matches!(
        compile_workflow(
            &workflow_definition(),
            &profiles,
            &catalog,
            &locks(&[("skill.outside", CapabilityLockState::HardEnabled)]),
            ProviderId::Codex,
            ProfileSourceScope::Workspace,
        ),
        Err(WorkflowValidationError::HardEnabledOutsideEnvelope(capability))
            if capability == id("skill.outside")
    ));
}

#[test]
fn controls_and_general_preset_are_typed_and_separate_from_authored_exposure() {
    assert_eq!(
        WorkflowControl::ALL.map(WorkflowControl::name),
        [
            "unpin_workflow_status",
            "unpin_workflow_modes",
            "unpin_workflow_enter_mode",
            "unpin_workflow_cancel_transition",
        ]
    );
    assert_eq!(
        WorkflowControl::ALL.map(WorkflowControl::effect),
        [
            WorkflowControlEffect::ReadOnly,
            WorkflowControlEffect::ReadOnly,
            WorkflowControlEffect::NonExpandingMutation,
            WorkflowControlEffect::NonExpandingMutation,
        ]
    );
    assert_eq!(
        preset_modes()
            .iter()
            .map(|mode| mode.name.as_str())
            .collect::<Vec<_>>(),
        [
            GENERAL_MODE,
            PLANNING_MODE,
            IMPLEMENTATION_MODE,
            REVIEW_MODE
        ]
    );

    let (catalog, mut profiles) = workflow_fixture();
    profiles.insert(
        GENERAL_MODE.to_string(),
        profile(GENERAL_MODE, &["skill.plan"], &catalog),
    );
    let mut definition = workflow_definition();
    definition.entry_mode = GENERAL_MODE.to_string();
    definition.modes = vec![WorkflowModeDefinition::new(GENERAL_MODE, GENERAL_MODE)];
    let compiled = compile_workflow(
        &definition,
        &profiles,
        &catalog,
        &CapabilityLockSnapshot::empty(ProviderId::Codex),
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("general is an ordinary active preset");
    assert_eq!(compiled.entry_mode, GENERAL_MODE);
    assert_eq!(compiled.system_controls, WorkflowControl::ALL);
    assert_eq!(compiled.maximum_envelope.authored_member_count, 2);
    assert!(
        compiled
            .maximum_envelope
            .members
            .iter()
            .all(|member| !member.capability_id.as_str().starts_with("unpin_workflow_"))
    );
}

#[test]
fn definitions_fail_closed_for_protected_roots_modes_profiles_and_catalog_drift() {
    let protected = r#"{
        "version": 1,
        "id": "unsafe",
        "displayName": "Unsafe",
        "baselineProfileId": "baseline",
        "entryMode": "planning",
        "modes": [{"name":"planning","profileId":"planning"}],
        "projectRoot": "/tmp/redirect"
    }"#;
    assert!(matches!(
        WorkflowDefinition::from_json(protected),
        Err(WorkflowValidationError::ProtectedAuthorityRoot(field)) if field == "projectRoot"
    ));

    let mut invalid = workflow_definition();
    invalid.modes.push(invalid.modes[0].clone());
    assert!(matches!(
        invalid.validate(),
        Err(WorkflowValidationError::DuplicateMode(mode)) if mode == "planning"
    ));
    invalid = workflow_definition();
    invalid.entry_mode = "missing".to_string();
    assert!(matches!(
        invalid.validate(),
        Err(WorkflowValidationError::MissingEntryMode(mode)) if mode == "missing"
    ));

    let (mut catalog, profiles) = workflow_fixture();
    let mut missing_profiles = profiles.clone();
    missing_profiles.remove("planning");
    assert!(matches!(
        compile_workflow(
            &workflow_definition(),
            &missing_profiles,
            &catalog,
            &CapabilityLockSnapshot::empty(ProviderId::Codex),
            ProviderId::Codex,
            ProfileSourceScope::Workspace,
        ),
        Err(WorkflowValidationError::MissingProfile(profile)) if profile == "planning"
    ));
    catalog
        .records
        .get_mut(&id("skill.plan"))
        .unwrap()
        .fingerprint = "changed".to_string();
    assert!(matches!(
        compile_workflow(
            &workflow_definition(),
            &profiles,
            &catalog,
            &CapabilityLockSnapshot::empty(ProviderId::Codex),
            ProviderId::Codex,
            ProfileSourceScope::Workspace,
        ),
        Err(WorkflowValidationError::StaleCapability(capability))
            if capability == id("skill.plan")
    ));

    let unsupported_catalog =
        Catalog::from_records([record("native.server", CapabilityKind::McpServer)]).unwrap();
    let unsupported_profiles = BTreeMap::from([(
        "native".to_string(),
        profile("native", &["native.server"], &unsupported_catalog),
    )]);
    let unsupported = WorkflowDefinition {
        baseline_profile_id: "native".to_string(),
        entry_mode: "general".to_string(),
        modes: vec![WorkflowModeDefinition::new("general", "native")],
        ..workflow_definition()
    };
    assert!(matches!(
        compile_workflow(
            &unsupported,
            &unsupported_profiles,
            &unsupported_catalog,
            &CapabilityLockSnapshot::empty(ProviderId::Codex),
            ProviderId::Codex,
            ProfileSourceScope::Workspace,
        ),
        Err(WorkflowValidationError::UnsupportedCapability { capability_id, .. })
            if capability_id == id("native.server")
    ));
}

#[test]
fn compiled_revision_verification_rejects_semantic_tampering_before_digest_mismatch() {
    let compiled = compile_fixture(&workflow_definition());

    let mut tampered = compiled.clone();
    tampered.system_controls.pop();
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::InvalidSystemControls)
    ));
    tampered = compiled.clone();
    tampered.entry_mode = "missing".to_string();
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::MissingEntryMode(mode)) if mode == "missing"
    ));
    tampered = compiled.clone();
    tampered.effective_profiles.remove("planning");
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::ModeProfileKeyMismatch)
    ));
    tampered = compiled.clone();
    tampered
        .modes
        .get_mut("planning")
        .unwrap()
        .effective_profile_digest = "0".repeat(64);
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::EffectiveProfileDigestMismatch { .. })
    ));
    tampered = compiled.clone();
    tampered.catalog_fingerprints.clear();
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::CatalogFingerprintsMismatch)
    ));
    tampered = compiled.clone();
    tampered.maximum_envelope.members.reverse();
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::UnsortedProfileMembers { .. })
    ));
    tampered = compiled;
    tampered.maximum_envelope.authored_member_count += 1;
    assert!(matches!(
        tampered.verify_digest(),
        Err(WorkflowValidationError::AuthoredMemberCountMismatch { .. })
    ));
}

#[test]
fn workflow_store_round_trips_trusted_definitions_and_immutable_revisions() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let app_state = root.join("state");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let store = WorkflowStore::new(&app_state);
    let definition = workflow_definition();
    store
        .save_global_definition(&definition, None, owner())
        .unwrap();
    assert_eq!(
        store
            .load_global_definition("delivery")
            .unwrap()
            .unwrap()
            .value,
        definition
    );

    fs::create_dir_all(workspace_workflows_dir(&workspace)).unwrap();
    fs::write(
        workspace_workflows_dir(&workspace).join("delivery.json"),
        definition.to_export_json().unwrap(),
    )
    .unwrap();
    assert_eq!(
        WorkflowStore::load_workspace_definition(&workspace, "delivery")
            .unwrap()
            .unwrap()
            .definition,
        definition
    );

    let compiled = compile_fixture(&definition);
    store.materialize_revision(&compiled, owner()).unwrap();
    assert_eq!(
        store.load_revision(&compiled.digest).unwrap(),
        Some(compiled)
    );
}

#[cfg(unix)]
#[test]
fn workspace_store_rejects_symlinked_definition_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let workspace = root.join("workspace");
    let outside = root.join("outside");
    fs::create_dir_all(workspace.join(".unpin")).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, workspace_workflows_dir(&workspace)).unwrap();
    assert!(matches!(
        WorkflowStore::list_workspace_definitions(&workspace),
        Err(WorkflowStoreError::UnsafeDefinitionEntry)
    ));
}

#[test]
fn immutable_store_rejects_tampering_and_content_collision() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let app_state = root.join("state");
    let store = WorkflowStore::new(&app_state);
    let first = compile_fixture(&workflow_definition());
    let mut second_definition = workflow_definition();
    second_definition.display_name = "Changed".to_string();
    let second = compile_fixture(&second_definition);
    let collision_path = app_state
        .join("workflows/revisions")
        .join(format!("{}.json", first.digest));
    AtomicJsonStore::new(&collision_path, 1)
        .compare_and_swap(None, owner(), &second)
        .unwrap();
    assert!(matches!(
        store.materialize_revision(&first, owner()),
        Err(WorkflowStoreError::ImmutableCollision(digest)) if digest == first.digest
    ));

    let clean_root = root.join("clean-state");
    let clean_store = WorkflowStore::new(&clean_root);
    clean_store.materialize_revision(&first, owner()).unwrap();
    let revision_path = clean_root
        .join("workflows/revisions")
        .join(format!("{}.json", first.digest));
    let raw = fs::read_to_string(&revision_path).unwrap();
    fs::write(
        &revision_path,
        raw.replace(
            "unpin_workflow_cancel_transition",
            "unpin_workflow_enter_mode",
        ),
    )
    .unwrap();
    assert!(matches!(
        clean_store.load_revision(&first.digest),
        Err(WorkflowStoreError::Validation(
            WorkflowValidationError::InvalidSystemControls
        ))
    ));
}
