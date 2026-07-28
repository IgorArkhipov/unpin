use std::{collections::BTreeSet, fs, path::Path, process::Command};

use tempfile::TempDir;
use unpin_core::{
    approval::{ApprovalExpectation, ApprovalResourceBinding},
    bridges::HookCoverageStatus,
    control::build_control_status,
    control_operation::{
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION, ControlHumanAction, ControlOperationEnvelope,
        ControlOperationLifecycle,
    },
    discovery::{DiscoveryRoots, ProviderId, discover_all},
    profiles::{PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileStore},
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
    state::{atomic_json::OwnerGeneration, workspace::resolve_workspace_identity},
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionJournalStore, TransitionKind, TransitionPlan,
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
