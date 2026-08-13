use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use tempfile::TempDir as RawTempDir;
use unpin_core::{
    catalog::Catalog,
    gateway::{
        GatewayConnectionRole, GatewayError, GatewayExposure, GatewayLimits, GatewayRefreshOutcome,
        GatewayService, ListChangeSupport,
    },
    profiles::{
        CapabilityLockSnapshot, PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope,
        compile_profile,
    },
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, PinnedWorkflowEnvelope, ProcessEvidence, SessionAuthorityKey,
        SessionManager, WorkflowOperationLifecycle, WorkflowTransitionRequest,
    },
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowDefinition, WorkflowModeDefinition, compile_workflow,
    },
};

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

struct PrivateTempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl PrivateTempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary root");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private temporary root");
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

fn empty_exposure(revision: char) -> (PinnedExposure, GatewayExposure) {
    let pinned = PinnedExposure {
        revision: digest(revision),
        profile: PinnedProfile::None,
        capability_locks: None,
    };
    let exposure = GatewayExposure::compile(
        pinned.clone(),
        ProviderId::Codex,
        &Catalog::default(),
        None,
        Vec::new(),
        GatewayLimits::default(),
    )
    .expect("empty exposure");
    (pinned, exposure)
}

fn service(root: &Path) -> GatewayService {
    service_named(
        root,
        "workflow-integrity-workspace",
        "workflow-integrity-connection",
        "workflow-integrity-owner",
    )
}

fn service_named(
    root: &Path,
    workspace_key: &str,
    connection_scope_id: &str,
    connection_owner_id: &str,
) -> GatewayService {
    let (pinned, exposure) = empty_exposure('e');
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x73; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "workflow-integrity-repository".to_string(),
        workspace_key: workspace_key.to_string(),
        workspace_revision: Some(digest('1')),
        exposure: pinned,
        process: ProcessEvidence {
            pid: 42,
            start_marker: format!("process-{workspace_key}"),
        },
        connection_scope_id: connection_scope_id.to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([format!("resource-{workspace_key}")]),
        lease_expires_at_unix: 20_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: connection_owner_id.to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = manager
        .prepare_bootstrap(request, 1_000)
        .expect("prepare bootstrap");
    let session = manager
        .claim_bootstrap(&authority, &claim, 1_001)
        .expect("claim bootstrap");
    let control = unpin_core::gateway::GatewayControlPlane::new(
        manager,
        session.handle,
        GatewayLimits::default().maximum_concurrent_calls,
    )
    .expect("control plane");
    GatewayService::new(control, exposure, GatewayLimits::default()).expect("gateway service")
}

fn workflow_service(root: &Path) -> GatewayService {
    let catalog = Catalog::default();
    let profile = |id: &str| {
        compile_profile(
            &ProfileDefinition {
                version: PROFILE_DEFINITION_VERSION,
                id: id.to_string(),
                display_name: id.to_string(),
                description: None,
                members: Vec::new(),
                provider_members: BTreeMap::new(),
                supported_providers: BTreeSet::from([ProviderId::Codex]),
            },
            &catalog,
            ProfileSourceScope::Session,
        )
        .unwrap()
    };
    let baseline_profile = profile("baseline");
    let planning_profile = profile("planning");
    let implementation_profile = profile("implementation");
    let profiles = BTreeMap::from([
        (baseline_profile.profile_id.clone(), baseline_profile),
        (planning_profile.profile_id.clone(), planning_profile),
        (
            implementation_profile.profile_id.clone(),
            implementation_profile,
        ),
    ]);
    let compiled_workflow = compile_workflow(
        &WorkflowDefinition {
            version: WORKFLOW_DEFINITION_VERSION,
            id: "delivery".to_string(),
            display_name: "Delivery".to_string(),
            description: None,
            baseline_profile_id: "baseline".to_string(),
            entry_mode: "planning".to_string(),
            modes: vec![
                WorkflowModeDefinition::new("implementation", "implementation"),
                WorkflowModeDefinition::new("planning", "planning"),
            ],
        },
        &profiles,
        &catalog,
        &CapabilityLockSnapshot::empty(ProviderId::Codex),
        ProviderId::Codex,
        ProfileSourceScope::Session,
    )
    .unwrap();
    let pinned = |mode: &str| {
        let profile = &compiled_workflow.effective_profiles[mode];
        PinnedExposure {
            revision: profile.digest.clone(),
            profile: PinnedProfile::Profile {
                profile_id: profile.profile_id.clone(),
                profile_digest: profile.digest.clone(),
                origin_scope: ProfileSourceScope::Session,
                definition_digest: compiled_workflow.digest.clone(),
            },
            capability_locks: None,
        }
    };
    let planning = pinned("planning");
    let implementation = pinned("implementation");
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x73; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "workflow-integrity-repository".to_string(),
        workspace_key: "workflow-integrity-workspace".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: planning.clone(),
        process: ProcessEvidence {
            pid: 42,
            start_marker: "workflow-integrity-process".to_string(),
        },
        connection_scope_id: "workflow-integrity-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["resource-workflow-integrity".to_string()]),
        lease_expires_at_unix: 2_000,
    };
    let authority = manager.prepare_bootstrap(request.clone(), 1_000).unwrap();
    let claimed = manager
        .claim_bootstrap(
            &authority,
            &ConnectionClaim {
                connection_owner_id: "workflow-integrity-owner".to_string(),
                provider: request.provider,
                repository_key: request.repository_key.clone(),
                workspace_key: request.workspace_key.clone(),
                process: request.process.clone(),
                connection_scope_id: request.connection_scope_id.clone(),
            },
            1_001,
        )
        .unwrap();
    let workflow = PinnedWorkflowEnvelope {
        workflow_id: "delivery".to_string(),
        workflow_revision: compiled_workflow.digest.clone(),
        baseline_profile_id: compiled_workflow.baseline_profile_id.clone(),
        baseline_profile_digest: compiled_workflow.baseline_profile_digest.clone(),
        profile_revisions: compiled_workflow
            .effective_profiles
            .iter()
            .map(|(mode, profile)| (mode.clone(), profile.digest.clone()))
            .collect(),
        active_mode: "planning".to_string(),
        active_effective_profile_digest: planning.revision.clone(),
        maximum_envelope_digest: compiled_workflow.maximum_envelope.digest.clone(),
        capability_lock_digest: compiled_workflow.capability_lock_digest.clone(),
        catalog_revision: digest('c'),
        proposal_id: "workflow-integrity-proposal".to_string(),
        proposal_fingerprint: digest('f'),
        state_sequence: 1,
        sealed_generation: 1,
    };
    manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow,
            planning.clone(),
            1_002,
        )
        .unwrap();
    let limits = GatewayLimits::default();
    let planning_exposure = GatewayExposure::compile_workflow_profile(
        planning,
        ProviderId::Codex,
        &catalog,
        &compiled_workflow.effective_profiles["planning"],
        Vec::new(),
        limits,
    )
    .unwrap();
    let implementation_exposure = GatewayExposure::compile_workflow_profile(
        implementation,
        ProviderId::Codex,
        &catalog,
        &compiled_workflow.effective_profiles["implementation"],
        Vec::new(),
        limits,
    )
    .unwrap();
    let control = unpin_core::gateway::GatewayControlPlane::new(
        manager,
        claimed.handle,
        limits.maximum_concurrent_calls,
    )
    .unwrap();
    let service = GatewayService::new(control, planning_exposure, limits).unwrap();
    service
        .register_workflow_exposure(implementation_exposure)
        .unwrap();
    service
}

#[test]
fn auxiliary_control_stages_only_the_primary_workflow_exposure() {
    let root = PrivateTempDir::new();
    let service = workflow_service(root.path());
    let primary = service.issue_connection_claim().unwrap();
    let auxiliary = service.accept_connection().unwrap();
    let snapshot = service.control_plane().snapshot().unwrap();
    let implementation_revision =
        snapshot.lease.workflow.as_ref().unwrap().profile_revisions["implementation"].clone();
    let request = WorkflowTransitionRequest {
        operation_id: "enter-implementation".to_string(),
        operation_fingerprint: digest('8'),
        source_state_sequence: snapshot.revision.sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_010,
    };
    let (transition, outcome) = service
        .enter_workflow_mode_for_connection(
            &auxiliary,
            request,
            ListChangeSupport::Negotiated,
            1_010,
        )
        .unwrap();
    assert_eq!(transition.lifecycle, WorkflowOperationLifecycle::Staged);
    assert_eq!(outcome, GatewayRefreshOutcome::NotificationRequired);
    assert_eq!(
        service
            .connection_status(&primary)
            .unwrap()
            .pending_exposure_revision,
        Some(implementation_revision.clone())
    );
    assert_eq!(
        service
            .connection_status(&auxiliary)
            .unwrap()
            .pending_exposure_revision,
        None
    );
    service
        .notify_tools_changed_for_connection(&primary, 1_011)
        .unwrap();
    service.list_tools_for_connection(&primary, 1_012).unwrap();
    let observed = service.control_plane().snapshot().unwrap();
    let planning_revision =
        observed.lease.workflow.as_ref().unwrap().profile_revisions["planning"].clone();
    let second = WorkflowTransitionRequest {
        operation_id: "return-planning".to_string(),
        operation_fingerprint: digest('9'),
        source_state_sequence: observed.revision.sequence,
        target_mode: "planning".to_string(),
        requested_at_unix: 1_013,
    };
    let (second_transition, second_outcome) = service
        .enter_workflow_mode_for_connection(
            &auxiliary,
            second,
            ListChangeSupport::Negotiated,
            1_013,
        )
        .expect("observed transition is terminal before next transition");
    assert_eq!(
        second_transition.desired_exposure_revision,
        planning_revision
    );
    assert_eq!(second_outcome, GatewayRefreshOutcome::NotificationRequired);
    service
        .cancel_transition_for_connection(&auxiliary, &second_transition.operation_id, 1_014)
        .expect("cancel second transition");
    service.connection_registry().disconnect(&primary).unwrap();
    let replacement = service.issue_connection_claim().unwrap();
    assert_eq!(replacement.role(), GatewayConnectionRole::Primary);
    assert_eq!(
        service
            .connection_status(&replacement)
            .unwrap()
            .observed_exposure_revision,
        implementation_revision
    );
}

#[test]
fn terminal_operation_cancellation_cannot_clear_a_new_pending_transition() {
    let root = PrivateTempDir::new();
    let service = workflow_service(root.path());
    let primary = service.issue_connection_claim().unwrap();
    let auxiliary = service.accept_connection().unwrap();
    let initial = service.control_plane().snapshot().unwrap();

    let first = WorkflowTransitionRequest {
        operation_id: "first-transition".to_string(),
        operation_fingerprint: digest('1'),
        source_state_sequence: initial.revision.sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_010,
    };
    let (first_transition, _) = service
        .enter_workflow_mode_for_connection(&primary, first, ListChangeSupport::Negotiated, 1_010)
        .expect("stage first transition");
    service
        .notify_tools_changed_for_connection(&primary, 1_011)
        .expect("notify first transition");
    service
        .list_tools_for_connection(&primary, 1_012)
        .expect("observe first transition");

    let after_first = service.control_plane().snapshot().unwrap();
    let second = WorkflowTransitionRequest {
        operation_id: "second-transition".to_string(),
        operation_fingerprint: digest('2'),
        source_state_sequence: after_first.revision.sequence,
        target_mode: "planning".to_string(),
        requested_at_unix: 1_013,
    };
    let (_, outcome) = service
        .enter_workflow_mode_for_connection(&primary, second, ListChangeSupport::Negotiated, 1_013)
        .expect("stage second transition");
    assert_eq!(outcome, GatewayRefreshOutcome::NotificationRequired);
    let pending_before = service.connection_status(&primary).unwrap();
    assert_eq!(
        pending_before.pending_exposure_revision,
        Some(
            service
                .control_plane()
                .snapshot()
                .unwrap()
                .lease
                .desired_exposure
                .revision
                .clone()
        )
    );

    assert!(
        service
            .cancel_transition_for_connection(&primary, &first_transition.operation_id, 1_014)
            .is_err()
    );
    let pending_after_terminal = service.connection_status(&primary).unwrap();
    assert_eq!(
        pending_after_terminal.pending_exposure_revision,
        pending_before.pending_exposure_revision
    );

    assert!(matches!(
        service.cancel_transition_for_connection(&auxiliary, &first_transition.operation_id, 1_015),
        Err(GatewayError::Workflow(_))
    ));
    let pending_after_auxiliary = service.connection_status(&primary).unwrap();
    assert_eq!(
        pending_after_auxiliary.pending_exposure_revision,
        pending_before.pending_exposure_revision
    );
}

#[test]
fn cancellation_and_primary_relist_are_serialized() {
    let root = PrivateTempDir::new();
    let service = Arc::new(workflow_service(root.path()));
    let primary = service.issue_connection_claim().unwrap();
    let snapshot = service.control_plane().snapshot().unwrap();
    let request = WorkflowTransitionRequest {
        operation_id: "cancel-vs-relist".to_string(),
        operation_fingerprint: digest('3'),
        source_state_sequence: snapshot.revision.sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_010,
    };
    let (transition, outcome) = service
        .enter_workflow_mode_for_connection(&primary, request, ListChangeSupport::Negotiated, 1_010)
        .expect("stage transition");
    assert_eq!(outcome, GatewayRefreshOutcome::NotificationRequired);
    service
        .notify_tools_changed_for_connection(&primary, 1_011)
        .expect("notify transition");

    let barrier = Arc::new(Barrier::new(3));
    let cancel_service = Arc::clone(&service);
    let cancel_claim = primary.clone();
    let cancel_barrier = Arc::clone(&barrier);
    let operation_id = transition.operation_id.clone();
    let cancel = thread::spawn(move || {
        cancel_barrier.wait();
        cancel_service.cancel_transition_for_connection(&cancel_claim, &operation_id, 1_012)
    });
    let relist_service = Arc::clone(&service);
    let relist_claim = primary.clone();
    let relist_barrier = Arc::clone(&barrier);
    let relist = thread::spawn(move || {
        relist_barrier.wait();
        relist_service.list_tools_for_connection(&relist_claim, 1_013)
    });
    barrier.wait();

    let cancel_result = cancel.join().expect("cancel worker");
    let relist_result = relist.join().expect("relist worker");
    assert!(relist_result.is_ok(), "relist result: {relist_result:?}");
    assert!(
        cancel_result.is_ok() || matches!(cancel_result, Err(GatewayError::Workflow(_))),
        "cancel result: {cancel_result:?}"
    );
    let status = service.connection_status(&primary).unwrap();
    assert_eq!(status.pending_exposure_revision, None);
    let final_snapshot = service.control_plane().snapshot().unwrap();
    assert_eq!(
        final_snapshot.lease.desired_exposure,
        final_snapshot.lease.observed_exposure
    );
}

#[test]
fn journal_failure_quarantines_and_operation_specific_cancel_recovers() {
    let root = PrivateTempDir::new();
    let service = workflow_service(root.path());
    let primary = service.issue_connection_claim().unwrap();
    let snapshot = service.control_plane().snapshot().unwrap();
    let target_revision =
        snapshot.lease.workflow.as_ref().unwrap().profile_revisions["implementation"].clone();
    let request = WorkflowTransitionRequest {
        operation_id: "journal-failure-transition".to_string(),
        operation_fingerprint: digest('7'),
        source_state_sequence: snapshot.revision.sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_010,
    };
    service
        .enter_workflow_mode_for_connection(&primary, request, ListChangeSupport::Negotiated, 1_010)
        .expect("stage transition");

    let journal_root = root.path().join("sessions").join("workflow-operations");
    let operation_dir = fs::read_dir(&journal_root)
        .expect("workflow operation directory")
        .next()
        .expect("session operation directory")
        .expect("session operation entry")
        .path();
    fs::write(operation_dir.join("malformed-entry"), b"fault")
        .expect("inject journal read failure");
    service
        .notify_tools_changed_for_connection(&primary, 1_011)
        .expect("notify transition");
    service
        .list_tools_for_connection(&primary, 1_012)
        .expect_err("journal failure must stop relist");
    fs::remove_file(operation_dir.join("malformed-entry")).expect("remove fault");
    let quarantined = service.connection_status(&primary).unwrap();
    assert!(quarantined.recovery_required, "status: {quarantined:?}");
    let lease = service.control_plane().snapshot().unwrap();
    assert_eq!(
        lease.lease.live_status,
        unpin_core::sessions::LiveExposureStatus::Unknown
    );
    assert!(!lease.lease.admission_open);
    assert_eq!(lease.lease.observed_exposure.revision, target_revision);
    assert_eq!(
        service
            .pending_workflow_operations_for_connection(&primary)
            .unwrap()
            .len(),
        1
    );
    service
        .cancel_transition_for_connection(&primary, "journal-failure-transition", 1_013)
        .expect("operation-specific quarantine cancellation");
    let recovered = service.control_plane().snapshot().unwrap();
    assert_eq!(
        recovered.lease.live_status,
        unpin_core::sessions::LiveExposureStatus::ObservedRefresh
    );
    assert!(recovered.lease.admission_open);
    assert_eq!(
        recovered.lease.desired_exposure,
        recovered.lease.observed_exposure
    );
}

#[test]
fn failed_transition_compensation_restores_pending_connection_state() {
    let root = PrivateTempDir::new();
    let service = workflow_service(root.path());
    let primary = service.issue_connection_claim().expect("primary claim");
    let snapshot = service
        .control_plane()
        .snapshot()
        .expect("workflow snapshot");
    let planning_revision = snapshot.lease.observed_exposure.revision.clone();
    let request = WorkflowTransitionRequest {
        operation_id: "compensation-failure-transition".to_string(),
        operation_fingerprint: digest('8'),
        source_state_sequence: snapshot.revision.sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_010,
    };
    service
        .enter_workflow_mode_for_connection(&primary, request, ListChangeSupport::Negotiated, 1_010)
        .expect("stage transition");
    let staged = service
        .connection_status(&primary)
        .expect("staged connection status");
    let pending_revision = staged
        .pending_exposure_revision
        .clone()
        .expect("pending exposure revision");

    let journal_root = root.path().join("sessions").join("workflow-operations");
    let operation_dir = fs::read_dir(&journal_root)
        .expect("workflow operation directory")
        .next()
        .expect("session operation directory")
        .expect("session operation entry")
        .path();
    let operation_path = operation_dir.join("compensation-failure-transition.json");
    let operation_bytes = fs::read(&operation_path).expect("read staged operation");
    fs::write(&operation_path, b"fault").expect("inject journal cancellation failure");

    assert!(
        service
            .cancel_transition_for_connection(&primary, "compensation-failure-transition", 1_011,)
            .is_err()
    );
    let restored = service
        .connection_status(&primary)
        .expect("connection status after failed compensation");
    assert_eq!(
        restored.pending_exposure_revision.as_deref(),
        Some(pending_revision.as_str())
    );
    assert_eq!(restored.observed_exposure_revision, planning_revision);

    fs::write(&operation_path, operation_bytes).expect("restore staged operation");
    service
        .cancel_transition_for_connection(&primary, "compensation-failure-transition", 1_012)
        .expect("retry compensation");
    let recovered = service
        .connection_status(&primary)
        .expect("recovered connection status");
    assert_eq!(recovered.pending_exposure_revision, None);
    assert_eq!(recovered.observed_exposure_revision, planning_revision);
}

#[test]
fn connection_claims_make_auxiliary_connections_control_only() {
    let root = PrivateTempDir::new();
    let service = service(root.path());
    let primary = service.issue_connection_claim().expect("primary claim");
    let auxiliary = service.accept_connection().expect("auxiliary claim");

    assert_eq!(primary.role(), GatewayConnectionRole::Primary);
    assert_eq!(auxiliary.role(), GatewayConnectionRole::Auxiliary);
    assert_ne!(primary.connection_epoch(), auxiliary.connection_epoch());
    assert!(
        service
            .list_tools_for_connection(&primary, 1_010)
            .expect("primary list")
            .is_empty()
    );
    assert!(matches!(
        service.list_tools_for_connection(&auxiliary, 1_011),
        Err(GatewayError::ConnectionControlOnly)
    ));
    assert!(matches!(
        service.search_skills_for_connection(&auxiliary, "", 10, 1_012),
        Err(GatewayError::ConnectionControlOnly)
    ));
    assert_eq!(
        service
            .connection_status(&auxiliary)
            .expect("auxiliary status")
            .role,
        GatewayConnectionRole::Auxiliary
    );
}

#[test]
fn only_the_same_primary_relist_promotes_pending_exposure() {
    let root = PrivateTempDir::new();
    let service = service(root.path());
    let primary = service.issue_connection_claim().expect("primary claim");
    let auxiliary = service.accept_connection().expect("auxiliary claim");
    let (next_pinned, next_exposure) = empty_exposure('f');

    service
        .control_plane()
        .request_exposure(next_pinned, 1_011)
        .expect("request exposure");
    assert_eq!(
        service
            .stage_refresh_for_connection(
                &primary,
                next_exposure,
                ListChangeSupport::Negotiated,
                1_012,
            )
            .expect("stage refresh"),
        GatewayRefreshOutcome::NotificationRequired
    );
    assert!(
        service
            .list_tools_for_connection(&primary, 1_013)
            .expect("pre-notification list keeps observed exposure")
            .is_empty()
    );
    let staged = service
        .connection_status(&primary)
        .expect("staged status before notification");
    assert_eq!(staged.observed_exposure_revision, digest('e'));
    assert_eq!(staged.pending_exposure_revision, Some(digest('f')));
    assert_eq!(
        service
            .notify_tools_changed_for_connection(&primary, 1_014)
            .expect("notify primary"),
        GatewayRefreshOutcome::NotificationSent
    );
    let before = service
        .connection_status(&primary)
        .expect("primary status before relist");
    assert_eq!(before.observed_exposure_revision, digest('e'));
    assert_eq!(before.pending_exposure_revision, Some(digest('f')));
    assert!(before.recovery_required);
    assert!(matches!(
        service.list_tools_for_connection(&auxiliary, 1_015),
        Err(GatewayError::ConnectionControlOnly)
    ));

    assert!(
        service
            .list_tools_for_connection(&primary, 1_016)
            .expect("same-connection relist")
            .is_empty()
    );
    let after = service
        .connection_status(&primary)
        .expect("primary status after relist");
    assert_eq!(after.observed_exposure_revision, digest('f'));
    assert_eq!(after.pending_exposure_revision, None);
    assert!(!after.recovery_required);
    assert_eq!(
        service
            .observe_refresh_for_connection(&primary, &digest('f'), 1_017)
            .expect("observed refresh")
            .observed_exposure_revision,
        digest('f')
    );
}

#[test]
fn concurrent_same_primary_relists_serialize_one_observation() {
    let root = PrivateTempDir::new();
    let service = Arc::new(service(root.path()));
    let primary = service.issue_connection_claim().expect("primary claim");
    let (next_pinned, next_exposure) = empty_exposure('f');
    service
        .control_plane()
        .request_exposure(next_pinned, 1_011)
        .expect("request exposure");
    service
        .stage_refresh_for_connection(
            &primary,
            next_exposure,
            ListChangeSupport::Negotiated,
            1_012,
        )
        .expect("stage refresh");
    service
        .notify_tools_changed_for_connection(&primary, 1_013)
        .expect("notify primary");

    let barrier = Arc::new(Barrier::new(3));
    let workers = [1_014, 1_015].map(|now_unix| {
        let service = Arc::clone(&service);
        let primary = primary.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            service.list_tools_for_connection(&primary, now_unix)
        })
    });
    barrier.wait();
    for worker in workers {
        assert!(worker.join().expect("relist worker").is_ok());
    }

    let status = service
        .connection_status(&primary)
        .expect("primary status after concurrent relists");
    assert_eq!(status.observed_exposure_revision, digest('f'));
    assert_eq!(status.pending_exposure_revision, None);
    assert!(!status.recovery_required);
}

#[test]
fn refresh_fallbacks_preserve_observed_set_and_cancel_restores_it() {
    let root = PrivateTempDir::new();
    let service = service(root.path());
    let primary = service.issue_connection_claim().expect("primary claim");

    let (reload_pinned, reload_exposure) = empty_exposure('f');
    service
        .control_plane()
        .request_exposure(reload_pinned, 1_011)
        .expect("request reload exposure");
    assert_eq!(
        service
            .stage_refresh_for_connection(
                &primary,
                reload_exposure,
                ListChangeSupport::Unsupported,
                1_012,
            )
            .expect("reload fallback"),
        GatewayRefreshOutcome::ReloadRequired
    );
    assert!(
        service
            .list_tools_for_connection(&primary, 1_013)
            .expect("reload keeps old list")
            .is_empty()
    );
    assert_eq!(
        service
            .connection_status(&primary)
            .expect("reload status")
            .observed_exposure_revision,
        digest('e')
    );
    service
        .cancel_refresh_for_connection(&primary, 1_014)
        .expect("cancel reload");
    let restored = service
        .connection_status(&primary)
        .expect("restored status");
    assert_eq!(restored.observed_exposure_revision, digest('e'));
    assert_eq!(restored.pending_exposure_revision, None);
    assert!(!restored.recovery_required);
    assert!(
        service
            .control_plane()
            .status()
            .expect("restored lease status")
            .admission_open
    );

    let (next_pinned, next_exposure) = empty_exposure('d');
    service
        .control_plane()
        .request_exposure(next_pinned, 1_015)
        .expect("request next-session exposure");
    assert_eq!(
        service
            .stage_refresh_for_connection(
                &primary,
                next_exposure,
                ListChangeSupport::NextSessionOnly,
                1_016,
            )
            .expect("next-session fallback"),
        GatewayRefreshOutcome::NextSessionOnly
    );
    let next = service
        .connection_status(&primary)
        .expect("next-session status");
    assert_eq!(next.observed_exposure_revision, digest('e'));
    assert_eq!(next.pending_exposure_revision, None);
    let next_lease = service
        .control_plane()
        .snapshot()
        .expect("next-session lease snapshot");
    assert!(next_lease.lease.admission_open);
    assert_eq!(
        next_lease.lease.desired_exposure,
        next_lease.lease.observed_exposure
    );
    assert!(
        service
            .list_tools_for_connection(&primary, 1_017)
            .expect("current exposure remains callable")
            .is_empty()
    );
    service
        .cancel_refresh_for_connection(&primary, 1_018)
        .expect("cancel next-session proposal");
    assert_eq!(
        service
            .connection_status(&primary)
            .expect("cancelled next-session status")
            .observed_exposure_revision,
        digest('e')
    );
}

#[test]
fn stale_connection_epochs_cannot_observe_after_replacement_or_disconnect() {
    let root = PrivateTempDir::new();
    let service = service(root.path());
    let old_primary = service.issue_connection_claim().expect("old primary");
    let _auxiliary = service.accept_connection().expect("auxiliary");
    let (next_pinned, next_exposure) = empty_exposure('f');
    service
        .control_plane()
        .request_exposure(next_pinned, 1_009)
        .expect("request disconnected refresh");
    service
        .stage_refresh_for_connection(
            &old_primary,
            next_exposure,
            ListChangeSupport::Negotiated,
            1_010,
        )
        .expect("stage disconnected refresh");
    service
        .connection_registry()
        .disconnect(&old_primary)
        .expect("disconnect old primary");
    let replacement = service
        .issue_connection_claim()
        .expect("replacement primary");
    assert!(replacement.connection_epoch() > old_primary.connection_epoch());
    assert!(
        service
            .connection_status(&replacement)
            .expect("replacement status")
            .recovery_required
    );
    assert!(matches!(
        service.list_tools_for_connection(&old_primary, 1_011),
        Err(GatewayError::ConnectionEpochStale)
    ));
    assert!(
        service
            .list_tools_for_connection(&replacement, 1_012)
            .expect("replacement list")
            .is_empty()
    );

    service
        .disconnect_connection(&replacement, 1_013)
        .expect("disconnect and reconcile runtime");
    assert!(matches!(
        service.connection_status(&replacement),
        Err(GatewayError::ConnectionEpochStale)
    ));
    assert!(matches!(
        service.issue_connection_claim(),
        Err(GatewayError::ConnectionClaimInvalid)
    ));
}

#[test]
fn claims_cannot_cross_session_registries() {
    let root = PrivateTempDir::new();
    let first = service_named(
        root.path(),
        "workflow-integrity-workspace-a",
        "workflow-integrity-connection-a",
        "workflow-integrity-owner-a",
    );
    let second = service_named(
        root.path(),
        "workflow-integrity-workspace-b",
        "workflow-integrity-connection-b",
        "workflow-integrity-owner-b",
    );
    let first_claim = first.issue_connection_claim().expect("first claim");
    let _second_claim = second.issue_connection_claim().expect("second claim");

    assert!(matches!(
        second.connection_status(&first_claim),
        Err(GatewayError::ConnectionClaimInvalid)
    ));
    assert!(matches!(
        second.list_tools_for_connection(&first_claim, 1_010),
        Err(GatewayError::ConnectionClaimInvalid)
    ));
}
