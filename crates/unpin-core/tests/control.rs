use std::{collections::BTreeSet, fs, path::Path, process::Command};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;
use unpin_core::{
    approval::{ApprovalExpectation, ApprovalResourceBinding},
    bridges::HookCoverageStatus,
    control::{
        ReachAwareStatusAuthorization, ReachAwareStatusFilter, build_control_status,
        project_reach_aware_operation_status, project_reach_aware_operations,
    },
    control_operation::{
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION, ControlHumanAction, ControlOperationEnvelope,
        ControlOperationLifecycle, ControlResolvedContext, ReachAwareControlOperationEnvelope,
        ReachAwareOperationFamily, ReachAwarePayloadReference, ReachAwareRootBinding,
        ReachAwareTransferCapability,
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
    let principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "session",
        "scope",
        ConnectionBoundary::All,
        &key,
    )
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
    let principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "session",
        "scope",
        ConnectionBoundary::All,
        &key,
    )
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

#[test]
fn reach_aware_transfer_capability_rejects_invalid_contexts_and_is_consumed_once() {
    let temp = TempDir::new().expect("temporary control root");
    let state_root = fs::canonicalize(temp.path()).expect("canonical state root");
    let provider_root = state_root.join("codex");
    fs::create_dir(&provider_root).expect("provider root");
    let authority_key = SessionAuthorityKey::new([0x71; 32]);
    let issuer = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "issuer-session",
        "issuer-scope",
        ConnectionBoundary::All,
        &authority_key,
    )
    .expect("issuer principal");
    let recipient = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "recipient-session",
        "recipient-scope",
        ConnectionBoundary::pinned(ProviderId::Codex),
        &authority_key,
    )
    .expect("recipient principal");
    let wrong_boundary_recipient = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "recipient-session",
        "recipient-scope",
        ConnectionBoundary::All,
        &authority_key,
    )
    .expect("wrong-boundary recipient principal");
    let mut forged_recipient = recipient.clone();
    forged_recipient.authentication_tag = "forged".to_string();
    assert!(
        ReachAwareTransferCapability::issue(
            "forged-transfer",
            "control-audience",
            "scope-digest",
            "transfer-operation",
            &forged_recipient,
            100,
            200,
            &authority_key,
        )
        .is_err(),
        "capability issuance must authenticate the recipient principal"
    );
    let capability = ReachAwareTransferCapability::issue(
        "transfer-1",
        "control-audience",
        "scope-digest",
        "transfer-operation",
        &recipient,
        100,
        200,
        &authority_key,
    )
    .expect("signed capability");
    capability
        .validate_for(
            "transfer-operation",
            "control-audience",
            "scope-digest",
            &recipient,
            150,
            &authority_key,
        )
        .expect("valid capability");
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "control-audience",
                "scope-digest",
                &wrong_boundary_recipient,
                150,
                &authority_key,
            )
            .is_err(),
        "capability validation must bind the recipient connection boundary"
    );
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "control-audience",
                "scope-digest",
                &forged_recipient,
                150,
                &authority_key,
            )
            .is_err(),
        "capability validation must authenticate the recipient principal"
    );
    assert!(
        capability
            .validate_for(
                "wrong-operation",
                "control-audience",
                "scope-digest",
                &recipient,
                150,
                &authority_key,
            )
            .is_err()
    );
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "wrong-audience",
                "scope-digest",
                &recipient,
                150,
                &authority_key,
            )
            .is_err()
    );
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "control-audience",
                "wrong-scope",
                &recipient,
                150,
                &authority_key,
            )
            .is_err()
    );
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "control-audience",
                "scope-digest",
                &issuer,
                150,
                &authority_key,
            )
            .is_err()
    );
    assert!(
        capability
            .validate_for(
                "transfer-operation",
                "control-audience",
                "scope-digest",
                &recipient,
                250,
                &authority_key,
            )
            .is_err()
    );

    let provider_root = fs::canonicalize(provider_root).expect("canonical provider root");
    let roots = ReachAwareRootBinding::from_provider_paths(
        &state_root,
        vec![(ProviderId::Codex, provider_root, "fixture".to_string())],
        "fixture",
    )
    .expect("trusted roots");
    let plan = TransitionPlan::new(
        "transfer-operation",
        TransitionKind::NativeToggle,
        TransitionContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("issuer-session".to_string()),
            profile_digest: None,
        },
        vec![TransitionEffect {
            effect_id: "effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: "resource".to_string(),
            target_type: "native-provider-state".to_string(),
            summary: "transfer test".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some("a".repeat(64)),
            expected_post_fingerprint: Some("b".repeat(64)),
            provider_views: vec![ProviderId::Codex],
        }],
    )
    .expect("transition plan");
    let owner = OwnerGeneration::new("transfer-owner", 1).expect("owner");
    let revision = unpin_core::state::atomic_json::StateRevision {
        sequence: 1,
        fingerprint: "r".repeat(64),
    };
    let builder = ReachAwareControlOperationEnvelope::builder()
        .family(ReachAwareOperationFamily::NativeToggle, 1)
        .operation(
            plan.operation_id.clone(),
            plan.kind.as_str(),
            "p".repeat(64),
        )
        .context(ControlResolvedContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("issuer-session".to_string()),
            profile_digest: None,
        })
        .reach(
            ConnectionBoundary::All,
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
            Some(SelectedProviderAuthority::new(
                ProviderId::Codex,
                SelectedProviderProvenance::ExplicitInput,
            )),
            ProviderReachCoverage::new(vec![
                unpin_core::provider_reach::ProviderCoverageEntry::included(
                    ProviderId::Codex,
                    "codex-target",
                ),
                unpin_core::provider_reach::ProviderCoverageEntry::excluded(
                    ProviderId::Zed,
                    "zed-private-target",
                ),
            ]),
        )
        .lifecycle(
            ProviderReachLifecycle::Partial,
            ProviderReachLifecycle::Partial,
            EffectActivation::RestartRequired,
        )
        .trusted_roots(roots)
        .authority(issuer, "control-audience", 100, 200)
        .journal_binding(owner.clone(), revision)
        .payload_reference(ReachAwarePayloadReference {
            family: ReachAwareOperationFamily::NativeToggle,
            schema_version: 1,
            reference: plan.operation_id.clone(),
            payload_digest: "p".repeat(64),
        })
        .transfer_capability(Some(capability.clone()));
    let store = TransitionJournalStore::new(&state_root);
    let mut handle = store
        .create_or_attach(&plan, owner)
        .expect("create journal");
    store
        .attach_reach_aware_builder(&mut handle, builder, &authority_key)
        .expect("attach envelope");
    store
        .consume_reach_aware_transfer_capability(
            &mut handle,
            &capability,
            "control-audience",
            "scope-digest",
            &recipient,
            150,
            &authority_key,
        )
        .expect("first durable consumption");
    let transferred_authorization = ReachAwareStatusAuthorization::new(
        recipient.clone(),
        "control-audience",
        "scope-digest",
        150,
        None,
    );
    project_reach_aware_operation_status(
        &handle.journal,
        &transferred_authorization,
        &authority_key,
    )
    .expect("consumed transfer establishes durable recipient status access");
    let mut tampered_journal = handle.journal.clone();
    tampered_journal
        .consumed_transfer_capabilities
        .get_mut(&capability.capability_id)
        .expect("consumption receipt")
        .authentication_tag = "forged".to_string();
    assert!(
        project_reach_aware_operation_status(
            &tampered_journal,
            &transferred_authorization,
            &authority_key,
        )
        .is_err(),
        "consumed capability adoption must be authenticated"
    );
    assert!(
        project_reach_aware_operation_status(
            &handle.journal,
            &ReachAwareStatusAuthorization::new(
                recipient.clone(),
                "control-audience",
                "wrong-scope",
                150,
                None,
            ),
            &authority_key,
        )
        .is_err()
    );
    assert!(
        store
            .consume_reach_aware_transfer_capability(
                &mut handle,
                &capability,
                "control-audience",
                "scope-digest",
                &recipient,
                150,
                &authority_key,
            )
            .is_err()
    );
}

#[test]
fn reach_aware_status_projection_authorizes_filters_and_redacts_excluded_targets() {
    let temp = TempDir::new().expect("temporary control root");
    let root = fs::canonicalize(temp.path()).expect("canonical root");
    let provider_root = root.join("codex");
    fs::create_dir(&provider_root).expect("provider root");
    let authority_key = SessionAuthorityKey::new([0x72; 32]);
    let principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "status-session",
        "status-scope",
        ConnectionBoundary::All,
        &authority_key,
    )
    .expect("principal");
    let roots = ReachAwareRootBinding::from_provider_paths(
        &root,
        vec![(
            ProviderId::Codex,
            fs::canonicalize(provider_root).expect("canonical provider root"),
            "fixture".to_string(),
        )],
        "fixture",
    )
    .expect("roots");
    let plan = TransitionPlan::new(
        "status-operation",
        TransitionKind::NativeToggle,
        TransitionContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("status-session".to_string()),
            profile_digest: None,
        },
        vec![TransitionEffect {
            effect_id: "effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: "resource".to_string(),
            target_type: "native-provider-state".to_string(),
            summary: "status test".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: None,
            expected_post_fingerprint: Some("b".repeat(64)),
            provider_views: vec![ProviderId::Codex],
        }],
    )
    .expect("plan");
    let pinned_principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "status-pinned-session",
        "status-pinned-scope",
        ConnectionBoundary::pinned(ProviderId::Codex),
        &authority_key,
    )
    .expect("pinned principal");
    let pinned_capability = ReachAwareTransferCapability::issue(
        "status-transfer",
        "control-audience",
        "status-scope-digest",
        &plan.operation_id,
        &pinned_principal,
        100,
        200,
        &authority_key,
    )
    .expect("status transfer capability");
    let store = TransitionJournalStore::new(&root);
    let mut handle = store
        .create_or_attach(
            &plan,
            OwnerGeneration::new("status-owner", 1).expect("owner"),
        )
        .expect("journal");
    let builder = ReachAwareControlOperationEnvelope::builder()
        .family(ReachAwareOperationFamily::NativeToggle, 1)
        .operation(
            plan.operation_id.clone(),
            plan.kind.as_str(),
            "s".repeat(64),
        )
        .context(ControlResolvedContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some("status-session".to_string()),
            profile_digest: None,
        })
        .reach(
            ConnectionBoundary::All,
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
            Some(SelectedProviderAuthority::new(
                ProviderId::Codex,
                SelectedProviderProvenance::ExplicitInput,
            )),
            ProviderReachCoverage::new(vec![
                unpin_core::provider_reach::ProviderCoverageEntry::included(
                    ProviderId::Codex,
                    "codex-visible-target",
                ),
                unpin_core::provider_reach::ProviderCoverageEntry::excluded(
                    ProviderId::Zed,
                    "zed-secret-path",
                ),
            ]),
        )
        .lifecycle(
            ProviderReachLifecycle::Partial,
            ProviderReachLifecycle::Partial,
            EffectActivation::RestartRequired,
        )
        .trusted_roots(roots)
        .authority(principal.clone(), "control-audience", 100, 200)
        .payload_reference(ReachAwarePayloadReference {
            family: ReachAwareOperationFamily::NativeToggle,
            schema_version: 1,
            reference: plan.operation_id.clone(),
            payload_digest: "s".repeat(64),
        })
        .transfer_capability(Some(pinned_capability.clone()));
    store
        .attach_reach_aware_builder(&mut handle, builder, &authority_key)
        .expect("attach envelope");
    let journal = handle.journal.clone();
    let authorization = ReachAwareStatusAuthorization::new(
        pinned_principal,
        "control-audience",
        "status-scope-digest",
        150,
        Some(pinned_capability),
    );
    let projection = project_reach_aware_operation_status(&journal, &authorization, &authority_key)
        .expect("authorized projection");
    let rendered = serde_json::to_string(&projection).expect("projection JSON");
    assert!(rendered.contains("codex-visible-target"));
    assert!(!rendered.contains("zed-secret-path"));
    assert!(
        projection
            .excluded_provider_counts
            .get(&ProviderId::Zed)
            .is_some()
    );
    let zed_unauthorized = {
        let zed_principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
            "status-zed-session",
            "status-zed-scope",
            ConnectionBoundary::pinned(ProviderId::Zed),
            &authority_key,
        )
        .expect("Zed principal");
        project_reach_aware_operation_status(
            &journal,
            &ReachAwareStatusAuthorization::new(
                zed_principal,
                "control-audience",
                "status-scope-digest",
                150,
                None,
            ),
            &authority_key,
        )
        .is_err()
    };
    assert!(
        zed_unauthorized,
        "pinned status cannot observe an operation selected for another provider"
    );
    let all_provider_projection = project_reach_aware_operation_status(
        &journal,
        &ReachAwareStatusAuthorization::new(
            principal.clone(),
            "control-audience",
            "status-scope-digest",
            150,
            None,
        ),
        &authority_key,
    )
    .expect("all-provider projection");
    assert!(
        serde_json::to_string(&all_provider_projection)
            .expect("all-provider projection JSON")
            .contains("zed-secret-path")
    );

    let filter = ReachAwareStatusFilter {
        operation_id: Some("status-operation".to_string()),
        family: Some(ReachAwareOperationFamily::NativeToggle),
        lifecycle: Some(ProviderReachLifecycle::Partial),
        provider: Some(ProviderId::Codex),
    };
    let projections = project_reach_aware_operations(
        std::slice::from_ref(&journal),
        &filter,
        &authorization,
        &authority_key,
    )
    .expect("filtered projections");
    assert_eq!(projections.len(), 1);
    let wrong_principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        "wrong-session",
        "wrong-scope",
        ConnectionBoundary::All,
        &authority_key,
    )
    .expect("wrong principal");
    let unauthorized = ReachAwareStatusAuthorization::new(
        wrong_principal,
        "control-audience",
        "status-scope-digest",
        150,
        None,
    );
    assert!(project_reach_aware_operation_status(&journal, &unauthorized, &authority_key).is_err());
    assert!(
        project_reach_aware_operations(
            std::slice::from_ref(&journal),
            &ReachAwareStatusFilter {
                operation_id: Some("status-operation".to_string()),
                family: None,
                lifecycle: None,
                provider: Some(ProviderId::Zed),
            },
            &unauthorized,
            &authority_key,
        )
        .expect("unauthorized list is non-disclosing")
        .is_empty()
    );
}

#[test]
fn reach_aware_gc_retains_live_records_removes_expired_records_and_keeps_v1_readable() {
    let temp = TempDir::new().expect("temporary state root");
    let root = fs::canonicalize(temp.path()).expect("canonical root");
    let store = TransitionJournalStore::new(&root);
    let legacy_plan = TransitionPlan::new(
        "legacy-operation",
        TransitionKind::ApplyProfile,
        TransitionContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: None,
            profile_digest: None,
        },
        vec![TransitionEffect {
            effect_id: "legacy-effect".to_string(),
            kind: TransitionEffectKind::PublishView,
            resource_id: "legacy-resource".to_string(),
            target_type: "profile-policy".to_string(),
            summary: "legacy".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::Live,
            expected_pre_fingerprint: None,
            expected_post_fingerprint: Some("b".repeat(64)),
            provider_views: Vec::new(),
        }],
    )
    .expect("legacy plan");
    store
        .create_or_attach(
            &legacy_plan,
            OwnerGeneration::new("legacy-owner", 1).expect("owner"),
        )
        .expect("legacy journal");
    let authority_key = SessionAuthorityKey::new([0x73; 32]);
    create_reach_aware_gc_journal(
        &store,
        &root,
        &authority_key,
        "expired-committed",
        200,
        TransitionLifecycle::Committed,
    );
    create_reach_aware_gc_journal(
        &store,
        &root,
        &authority_key,
        "expired-applying",
        200,
        TransitionLifecycle::Applying,
    );
    create_reach_aware_gc_journal(
        &store,
        &root,
        &authority_key,
        "expired-needs-repair",
        200,
        TransitionLifecycle::NeedsRepair,
    );
    create_reach_aware_gc_journal(
        &store,
        &root,
        &authority_key,
        "fresh-committed",
        995,
        TransitionLifecycle::Committed,
    );
    let report = store.gc_reach_aware(1_000, 10).expect("reach-aware GC");
    assert_eq!(report.scanned, 4);
    assert_eq!(report.removed, 1);
    assert_eq!(report.retained, 3);
    assert_eq!(report.legacy_records, 1);
    assert_eq!(
        report.removed_operation_ids,
        vec!["expired-committed".to_string()]
    );
    let operation_ids = store
        .list()
        .expect("journals")
        .into_iter()
        .map(|journal| journal.operation_id)
        .collect::<BTreeSet<_>>();
    assert!(!operation_ids.contains("expired-committed"));
    for retained in [
        "legacy-operation",
        "expired-applying",
        "expired-needs-repair",
        "fresh-committed",
    ] {
        assert!(operation_ids.contains(retained), "{retained} is retained");
    }

    #[cfg(unix)]
    {
        let transaction_root = root.join("transactions");
        let mode = fs::metadata(&transaction_root)
            .expect("private transaction directory")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        let journal_path = fs::read_dir(transaction_root)
            .expect("transaction entries")
            .next()
            .expect("legacy journal entry")
            .expect("journal directory entry")
            .path();
        assert_eq!(
            fs::metadata(journal_path)
                .expect("private journal")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

fn create_reach_aware_gc_journal(
    store: &TransitionJournalStore,
    root: &Path,
    authority_key: &SessionAuthorityKey,
    operation_id: &str,
    expires_at_unix: i64,
    lifecycle: TransitionLifecycle,
) {
    let provider_root = root.join(format!("{operation_id}-provider"));
    fs::create_dir(&provider_root).expect("provider root");
    let roots = ReachAwareRootBinding::from_provider_paths(
        root,
        vec![(ProviderId::Codex, provider_root, "fixture".to_string())],
        "fixture",
    )
    .expect("trusted roots");
    let plan = TransitionPlan::new(
        operation_id,
        TransitionKind::NativeToggle,
        TransitionContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some(format!("{operation_id}-session")),
            profile_digest: None,
        },
        vec![TransitionEffect {
            effect_id: format!("{operation_id}-effect"),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: format!("{operation_id}-resource"),
            target_type: "native-provider-state".to_string(),
            summary: "reach-aware GC test".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some("a".repeat(64)),
            expected_post_fingerprint: Some("b".repeat(64)),
            provider_views: vec![ProviderId::Codex],
        }],
    )
    .expect("transition plan");
    let principal = unpin_core::control_operation::ReachAwarePrincipal::sign(
        format!("{operation_id}-session"),
        format!("{operation_id}-scope"),
        ConnectionBoundary::All,
        authority_key,
    )
    .expect("principal");
    let builder = ReachAwareControlOperationEnvelope::builder()
        .family(ReachAwareOperationFamily::NativeToggle, 1)
        .operation(
            operation_id,
            TransitionKind::NativeToggle.as_str(),
            "g".repeat(64),
        )
        .context(ControlResolvedContext {
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: Some(format!("{operation_id}-session")),
            profile_digest: None,
        })
        .reach(
            ConnectionBoundary::All,
            ProviderReach::All,
            None,
            ProviderReachCoverage::new(vec![
                unpin_core::provider_reach::ProviderCoverageEntry::included(
                    ProviderId::Codex,
                    format!("{operation_id}-target"),
                ),
            ]),
        )
        .lifecycle(
            ProviderReachLifecycle::Applied,
            ProviderReachLifecycle::Applied,
            EffectActivation::RestartRequired,
        )
        .trusted_roots(roots)
        .authority(principal, "control-audience", 100, expires_at_unix)
        .payload_reference(ReachAwarePayloadReference {
            family: ReachAwareOperationFamily::NativeToggle,
            schema_version: 1,
            reference: operation_id.to_string(),
            payload_digest: "g".repeat(64),
        });
    let owner = OwnerGeneration::new(format!("{operation_id}-owner"), 1).expect("owner");
    let mut handle = store
        .create_or_attach(&plan, owner)
        .expect("create journal");
    store
        .attach_reach_aware_builder(&mut handle, builder, authority_key)
        .expect("attach reach-aware envelope");
    handle
        .journal
        .record(lifecycle, lifecycle.as_str(), None)
        .expect("record lifecycle");
    store.save(&mut handle).expect("save lifecycle");
}
