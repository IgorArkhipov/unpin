use std::{collections::BTreeSet, fs, path::Path, process::Command};

use tempfile::TempDir;
use unpin_core::{
    approval::{ApprovalExpectation, ApprovalResourceBinding},
    bridges::HookCoverageStatus,
    control::build_control_status,
    control_operation::{
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION, ControlHumanAction, ControlOperationEnvelope,
        ControlOperationLifecycle, ControlResolvedContext, ReachAwareControlOperationEnvelope,
        ReachAwareOperationFamily, ReachAwarePayloadReference, ReachAwareRootBinding,
    },
    discovery::{DiscoveryRoots, ProviderId, discover_all},
    profiles::{PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileStore},
    provider_reach::{
        ConnectionBoundary, ProviderReach, ProviderReachCoverage, ProviderReachLifecycle,
        SelectedProviderAuthority, SelectedProviderProvenance,
    },
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
    state::{atomic_json::OwnerGeneration, workspace::resolve_workspace_identity},
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionJournalStore, TransitionKind, TransitionLifecycle,
        TransitionPlan,
    },
};

fn fixtures_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn control_operation_envelope_is_surface_neutral_and_deterministic() {
    let expectation = ApprovalExpectation {
        issuer: "unpin-cli-human".to_string(),
        audience: "unpin-core-control".to_string(),
        operation_id: "profile-policy-abc".to_string(),
        operation_kind: "profile-policy".to_string(),
        effect_graph_digest: "a".repeat(64),
        repository_key: "repository".to_string(),
        workspace_key: "workspace".to_string(),
        session_id: None,
        profile_digest: None,
        resources: vec![ApprovalResourceBinding {
            resource_id: "policy".to_string(),
            pre_state_fingerprint: None,
        }],
    };
    let envelope = ControlOperationEnvelope::from_expectation(
        &expectation,
        "b".repeat(64),
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(ControlHumanAction {
            code: "confirm-and-apply".to_string(),
            guidance: "Review fingerprint before apply".to_string(),
        }),
        true,
        vec![ProviderId::Codex, ProviderId::Claude, ProviderId::Codex],
        serde_json::json!({"plan": "redacted"}),
    );

    assert_eq!(
        envelope.schema_version,
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION
    );
    assert_eq!(
        envelope.provider_coverage,
        vec![ProviderId::Claude, ProviderId::Codex]
    );
    let rendered = serde_json::to_string(&envelope).unwrap();
    assert!(rendered.contains("\"lifecycle\":\"planned\""));
    assert!(rendered.contains("\"code\":\"confirm-and-apply\""));
    assert!(!rendered.contains("issuer"));
    assert!(!rendered.contains("resources"));
}

#[test]
fn reach_aware_v2_envelope_binds_provider_material_without_changing_v1() {
    let temp = TempDir::new().expect("temporary roots");
    let state_root = temp.path().join("state");
    let provider_root = temp.path().join("codex");
    fs::create_dir(&state_root).expect("state root");
    fs::create_dir(&provider_root).expect("provider root");
    let key = SessionAuthorityKey::new([7; 32]);
    let principal =
        unpin_core::control_operation::ReachAwarePrincipal::sign("session", "scope", &key)
            .expect("signed principal");
    let roots = ReachAwareRootBinding::from_provider_paths(
        &state_root,
        vec![(
            ProviderId::Codex,
            provider_root,
            "fixture-codex".to_string(),
        )],
        "fixture",
    )
    .expect("trusted roots");
    let owner = OwnerGeneration::new("reach-aware-test", 1).expect("owner");
    let revision = unpin_core::state::atomic_json::StateRevision {
        sequence: 1,
        fingerprint: "r".repeat(64),
    };
    let provider_reach = ProviderReach::selected(
        ProviderId::Codex,
        SelectedProviderProvenance::ExactIndividualTarget,
    );
    let envelope = ReachAwareControlOperationEnvelope::builder()
        .family(ReachAwareOperationFamily::NativeToggle, 1)
        .operation("native-operation", "native-toggle", "plan-fingerprint")
        .context(ControlResolvedContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("session".to_string()),
            profile_digest: None,
        })
        .reach(
            ConnectionBoundary::All,
            provider_reach,
            Some(SelectedProviderAuthority::new(
                ProviderId::Codex,
                SelectedProviderProvenance::ExactIndividualTarget,
            )),
            ProviderReachCoverage::new(Vec::new()),
        )
        .lifecycle(
            ProviderReachLifecycle::Applied,
            ProviderReachLifecycle::Applied,
            EffectActivation::RestartRequired,
        )
        .trusted_roots(roots)
        .authority(principal, "unpin-test-audience", 100, 200)
        .journal_binding(owner, revision)
        .payload_reference(ReachAwarePayloadReference {
            family: ReachAwareOperationFamily::NativeToggle,
            schema_version: 1,
            reference: "native-operation".to_string(),
            payload_digest: "p".repeat(64),
        })
        .build()
        .expect("reach-aware envelope");
    assert_eq!(envelope.schema_version, 2);
    let fingerprint = envelope.fingerprint().expect("fingerprint");
    assert_eq!(envelope.envelope_fingerprint, fingerprint);
    let mut tampered = envelope.clone();
    tampered.provider_reach = ProviderReach::All;
    assert!(tampered.verify().is_err());
    assert_eq!(CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION, 1);
}

#[test]
fn reach_aware_v2_builder_is_fail_closed_without_authority_and_journal_binding() {
    let error = ReachAwareControlOperationEnvelope::builder()
        .family(ReachAwareOperationFamily::NativeToggle, 1)
        .operation("native-operation", "native-toggle", "plan-fingerprint")
        .build()
        .expect_err("incomplete reach-aware records must not be constructible");
    assert!(error.to_string().contains("context"));
}

#[test]
fn reach_aware_v2_journal_attachment_binds_revision_and_redacts_provider_roots() {
    let temp = TempDir::new().expect("temporary state root");
    let state_root = temp.path().join("state");
    let provider_root = temp.path().join("codex");
    fs::create_dir(&state_root).expect("state root");
    fs::create_dir(&provider_root).expect("provider root");
    let state_root = fs::canonicalize(state_root).expect("canonical state root");
    let provider_root = fs::canonicalize(provider_root).expect("canonical provider root");
    let roots = ReachAwareRootBinding::from_provider_paths(
        &state_root,
        vec![(
            ProviderId::Codex,
            provider_root.clone(),
            "fixture-codex".to_string(),
        )],
        "fixture",
    )
    .expect("trusted provider roots");
    let key = SessionAuthorityKey::new([8; 32]);
    let principal =
        unpin_core::control_operation::ReachAwarePrincipal::sign("session", "scope", &key)
            .expect("signed principal");
    let plan = TransitionPlan::new(
        "reach-aware-journal-operation",
        TransitionKind::NativeToggle,
        TransitionContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("session".to_string()),
            profile_digest: None,
        },
        vec![TransitionEffect {
            effect_id: "effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: "resource".to_string(),
            target_type: "native-provider-state".to_string(),
            summary: "toggle provider state".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some("a".repeat(64)),
            expected_post_fingerprint: Some("b".repeat(64)),
            provider_views: vec![ProviderId::Codex],
        }],
    )
    .expect("transition plan");
    let owner = OwnerGeneration::new("reach-aware-journal-test", 1).expect("owner");
    let store = TransitionJournalStore::new(&state_root);
    let mut handle = store
        .create_or_attach(&plan, owner.clone())
        .expect("create journal");
    let make_builder = || {
        ReachAwareControlOperationEnvelope::builder()
            .family(ReachAwareOperationFamily::NativeToggle, 1)
            .operation(
                plan.operation_id.clone(),
                plan.kind.as_str(),
                "c".repeat(64),
            )
            .context(ControlResolvedContext {
                repository_key: "repository".to_string(),
                workspace_key: "workspace".to_string(),
                session_id: Some("session".to_string()),
                profile_digest: None,
            })
            .reach(
                ConnectionBoundary::All,
                ProviderReach::selected(
                    ProviderId::Codex,
                    SelectedProviderProvenance::ExactIndividualTarget,
                ),
                Some(SelectedProviderAuthority::new(
                    ProviderId::Codex,
                    SelectedProviderProvenance::ExactIndividualTarget,
                )),
                ProviderReachCoverage::new(Vec::new()),
            )
            .lifecycle(
                ProviderReachLifecycle::Applied,
                ProviderReachLifecycle::Applied,
                EffectActivation::RestartRequired,
            )
            .trusted_roots(roots.clone())
            .authority(principal.clone(), "unpin-test-audience", 100, 200)
            .payload_reference(ReachAwarePayloadReference {
                family: ReachAwareOperationFamily::NativeToggle,
                schema_version: 1,
                reference: plan.operation_id.clone(),
                payload_digest: "c".repeat(64),
            })
    };
    store
        .attach_reach_aware_builder(&mut handle, make_builder(), &key)
        .expect("attach v2 envelope");
    let envelope = handle
        .journal
        .reach_aware
        .clone()
        .expect("attached envelope");
    assert_eq!(envelope.owner, owner);
    assert_eq!(envelope.revision.sequence, 1);
    let redacted = envelope.redacted();
    let rendered = serde_json::to_string(&redacted).expect("redacted envelope");
    assert!(!rendered.contains(provider_root.to_string_lossy().as_ref()));
    let mut tampered = envelope.clone();
    tampered.provider_reach = ProviderReach::All;
    assert!(tampered.verify_authenticated(&key).is_err());
    let mut tampered_roots = envelope.clone();
    tampered_roots.roots.provider_roots[0].root = "/tmp/tampered".to_string();
    assert!(tampered_roots.verify_authenticated(&key).is_err());
    let mut unsigned_journal = store
        .load(&plan, owner.clone())
        .expect("reload attached journal");
    unsigned_journal
        .journal
        .reach_aware
        .as_mut()
        .expect("attached envelope")
        .authentication_tag
        .clear();
    assert!(store.save(&mut unsigned_journal).is_err());
    let mut tampered_journal = store
        .load(&plan, owner.clone())
        .expect("reload attached journal");
    tampered_journal
        .journal
        .reach_aware
        .as_mut()
        .expect("attached envelope")
        .provider_reach = ProviderReach::All;
    assert!(store.save(&mut tampered_journal).is_err());

    handle
        .journal
        .record(TransitionLifecycle::Committed, "committed", None)
        .expect("terminal journal");
    store.save(&mut handle).expect("save terminal journal");
    let mut terminal = store.load(&plan, owner).expect("reload terminal journal");
    store
        .attach_reach_aware_builder(&mut terminal, make_builder(), &key)
        .expect("idempotent terminal attach");
}

#[test]
fn control_status_is_shared_redacted_state_and_persistent_metadata_excludes_runtime() {
    let temp = TempDir::new().expect("temporary control root");
    let root = fs::canonicalize(temp.path()).expect("canonical control root");
    let project = root.join("project");
    let state = root.join("state");
    fs::create_dir(&project).expect("project directory");
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&project)
        .output()
        .expect("git init");
    assert!(git.status.success());
    ProfileStore::new(&state)
        .save_global_definition(
            &ProfileDefinition {
                version: PROFILE_DEFINITION_VERSION,
                id: "review".to_string(),
                display_name: "Review".to_string(),
                description: None,
                members: Vec::new(),
                provider_members: std::collections::BTreeMap::new(),
                supported_providers: std::collections::BTreeSet::new(),
            },
            None,
            OwnerGeneration::new("control-test", 1).unwrap(),
        )
        .expect("save profile");
    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("discovery");

    let status = build_control_status(
        &discovery,
        &state,
        &project,
        &SessionAuthorityKey::new([0x53; 32]),
    )
    .expect("control status");
    assert!(status.catalog.total > 0);
    assert_eq!(status.profiles.len(), 1);
    assert!(status.sessions.is_empty());
    assert!(status.operations.is_empty());
    assert_eq!(status.hooks.len(), ProviderId::ALL.len());
    assert_eq!(
        status
            .hooks
            .iter()
            .find(|row| row.provider == ProviderId::Zed)
            .expect("Zed coverage")
            .built_in_tools,
        HookCoverageStatus::Unsupported
    );

    let rendered = serde_json::to_string(&status).expect("control JSON");
    assert!(!rendered.contains(project.to_str().unwrap()));
    assert!(!rendered.contains(fixtures_root().to_str().unwrap()));
    assert!(!rendered.contains("secretDigest"));
    assert!(!rendered.contains("process"));

    let persistent = serde_json::to_value(status.persistent_metadata()).expect("metadata JSON");
    assert!(persistent.get("sessions").is_none());
    assert!(persistent.get("gateways").is_none());
    assert!(persistent.get("operations").is_none());
    assert!(persistent.get("trust").is_none());
}

#[test]
fn control_status_filters_foreign_workspace_sessions_and_operations() {
    let temp = TempDir::new().expect("temporary control root");
    let root = fs::canonicalize(temp.path()).expect("canonical control root");
    let project = root.join("project");
    let state = root.join("state");
    fs::create_dir(&project).expect("project directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .status()
            .expect("git init")
            .success()
    );
    let identity = resolve_workspace_identity(&project).expect("workspace identity");
    let authority_key = SessionAuthorityKey::new([0x53; 32]);
    let sessions = SessionManager::with_authority_key(&state, authority_key.clone());
    for (workspace_key, marker) in [
        (identity.workspace_key.as_str(), "local"),
        ("foreign-workspace", "foreign"),
    ] {
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: identity.repository_key.clone(),
            workspace_key: workspace_key.to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "a".repeat(64),
                profile: PinnedProfile::Native,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: format!("control-{marker}"),
            },
            connection_scope_id: format!("connection-{marker}"),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: 10_000,
        };
        let claim = ConnectionClaim {
            connection_owner_id: format!("owner-{marker}"),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let bootstrap = sessions.prepare_bootstrap(request, 1_000).unwrap();
        sessions.claim_bootstrap(&bootstrap, &claim, 1_001).unwrap();
    }
    for (workspace_key, operation_id) in [
        (identity.workspace_key.as_str(), "local-operation"),
        ("foreign-workspace", "foreign-operation"),
    ] {
        let plan = TransitionPlan::new(
            operation_id,
            TransitionKind::ApplyProfile,
            TransitionContext {
                repository_key: identity.repository_key.clone(),
                workspace_key: workspace_key.to_string(),
                session_id: None,
                profile_digest: None,
            },
            vec![TransitionEffect {
                effect_id: format!("effect-{operation_id}"),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: format!("resource-{operation_id}"),
                target_type: "policy".to_string(),
                summary: "test control status filtering".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::NextSessionOnly,
                expected_pre_fingerprint: None,
                expected_post_fingerprint: Some("b".repeat(64)),
                provider_views: vec![ProviderId::Codex],
            }],
        )
        .unwrap();
        TransitionJournalStore::new(&state)
            .create_or_attach(
                &plan,
                OwnerGeneration::new(format!("owner-{operation_id}"), 1).unwrap(),
            )
            .unwrap();
    }

    let discovery =
        discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("discovery");
    let status =
        build_control_status(&discovery, &state, &project, &authority_key).expect("control status");

    assert_eq!(status.sessions.len(), 1);
    assert_eq!(status.sessions[0].workspace_key, identity.workspace_key);
    assert_eq!(status.operations.len(), 1);
    assert_eq!(status.operations[0].operation_id, "local-operation");
}
