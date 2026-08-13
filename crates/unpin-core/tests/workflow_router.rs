use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::mpsc,
    thread,
    time::Duration,
};

use tempfile::TempDir as RawTempDir;
use unpin_core::{
    config::{get_session_lease_path, get_session_registry_lock_path},
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, LeaseError,
        LiveExposureStatus, PinnedExposure, PinnedProfile, PinnedWorkflowEnvelope, ProcessEvidence,
        SessionAuthorityKey, SessionManager, WORKFLOW_OPERATION_SCHEMA_VERSION, WorkflowHighWater,
        WorkflowHighWaterError, WorkflowHighWaterStore, WorkflowJournal,
        WorkflowOperationLifecycle, WorkflowOperationRecord, WorkflowProposalV1,
        WorkflowReloadLimitation, WorkflowRouter, WorkflowRouterError, WorkflowTransitionRequest,
    },
    state::atomic_json::{OwnerGeneration, StateResourceLock},
};

struct FirstPinFaultFixture {
    manager: SessionManager,
    claimed: unpin_core::sessions::ClaimedSession,
    lease_path: std::path::PathBuf,
    high_water_path: std::path::PathBuf,
    source_lease: Vec<u8>,
    target_lease: Vec<u8>,
}

fn owner(generation: u64) -> OwnerGeneration {
    OwnerGeneration::new("workflow-test-owner", generation).expect("owner")
}

fn private_temp() -> (RawTempDir, std::path::PathBuf) {
    let temp = RawTempDir::new().expect("temporary state");
    let path = fs::canonicalize(temp.path()).expect("canonical temporary state");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("private temporary state");
    }
    (temp, path)
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'
                if byte != b'.' || index != 0 =>
            {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn exposure(character: char) -> PinnedExposure {
    PinnedExposure {
        revision: digest(character),
        profile: PinnedProfile::Profile {
            profile_id: format!("workflow-{character}"),
            profile_digest: digest(character),
            origin_scope: unpin_core::profiles::ProfileSourceScope::Workspace,
            definition_digest: digest('d'),
        },
        capability_locks: None,
    }
}

fn workflow() -> PinnedWorkflowEnvelope {
    PinnedWorkflowEnvelope {
        workflow_id: "delivery".to_string(),
        workflow_revision: digest('e'),
        baseline_profile_id: "baseline".to_string(),
        baseline_profile_digest: digest('b'),
        profile_revisions: BTreeMap::from([
            ("implementation".to_string(), digest('a')),
            ("planning".to_string(), digest('b')),
        ]),
        active_mode: "planning".to_string(),
        active_effective_profile_digest: digest('b'),
        maximum_envelope_digest: digest('c'),
        capability_lock_digest: digest('d'),
        catalog_revision: digest('c'),
        proposal_id: "workflow-proposal-test".to_string(),
        proposal_fingerprint: digest('f'),
        state_sequence: 1,
        sealed_generation: 1,
    }
}

fn claimed_session(
    root: &std::path::Path,
) -> (SessionManager, unpin_core::sessions::ClaimedSession) {
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x53; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository-key".to_string(),
        workspace_key: "workspace-key".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: exposure('b'),
        process: ProcessEvidence {
            pid: 42,
            start_marker: "process-start".to_string(),
        },
        connection_scope_id: "connection-scope".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["provider-config".to_string()]),
        lease_expires_at_unix: 10_000,
    };
    let authority = manager
        .prepare_bootstrap(request.clone(), 1_000)
        .expect("bootstrap");
    let claim = ConnectionClaim {
        connection_owner_id: "connection-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key,
        workspace_key: request.workspace_key,
        process: request.process,
        connection_scope_id: request.connection_scope_id,
    };
    let claimed = manager
        .claim_bootstrap(&authority, &claim, 1_001)
        .expect("claim");
    (manager, claimed)
}

fn first_pin_fault_fixture(root: &std::path::Path) -> FirstPinFaultFixture {
    let (manager, claimed) = claimed_session(root);
    let lease_path = get_session_lease_path(root, claimed.handle.session_id());
    let source_lease = fs::read(&lease_path).expect("capture source lease");
    let source: serde_json::Value =
        serde_json::from_slice(&source_lease).expect("source lease JSON");
    let source_tag = source["value"]["lease"]["authenticationTag"]
        .as_str()
        .expect("source lease authentication tag")
        .to_string();
    manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("complete first pin");
    let target_lease = fs::read(&lease_path).expect("capture target lease");
    let target: serde_json::Value =
        serde_json::from_slice(&target_lease).expect("target lease JSON");
    let target_tag = target["value"]["lease"]["authenticationTag"]
        .as_str()
        .expect("target lease authentication tag")
        .to_string();
    let high_water_path = root
        .join("sessions")
        .join("workflow-high-water")
        .join(format!(
            "{}.json",
            encode_path_segment(claimed.handle.session_id())
        ));
    fs::remove_file(&high_water_path).expect("remove finalized high water");
    fs::write(&lease_path, &source_lease).expect("restore source lease");
    let pending = WorkflowHighWater::new(claimed.handle.session_id(), 3, 1, 1, &source_tag)
        .expect("first-pin high-water base")
        .prepare_transition(
            claimed.lease.revision.clone(),
            source_tag,
            3,
            1,
            1,
            target_tag,
        )
        .expect("first-pin pending transition");
    WorkflowHighWaterStore::new(root, [0x53; 32])
        .publish(claimed.handle.session_id(), None, owner(1), pending)
        .expect("publish first-pin pending transition");
    FirstPinFaultFixture {
        manager,
        claimed,
        lease_path,
        high_water_path,
        source_lease,
        target_lease,
    }
}

fn operation_path(
    root: &std::path::Path,
    session_id: &str,
    operation_id: &str,
) -> std::path::PathBuf {
    root.join("sessions")
        .join("workflow-operations")
        .join(encode_path_segment(session_id))
        .join(format!("{}.json", encode_path_segment(operation_id)))
}

fn transition_request(operation_id: &str, source_state_sequence: u64) -> WorkflowTransitionRequest {
    WorkflowTransitionRequest {
        operation_id: operation_id.to_string(),
        operation_fingerprint: digest('1'),
        source_state_sequence,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_003,
    }
}

#[test]
fn pre_session_proposal_serialization_omits_session_bound_placeholders() {
    let proposal = WorkflowProposalV1::new(
        "delivery",
        "planning",
        ProviderId::Codex,
        "repository-key",
        "workspace-key",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        5,
        true,
        WorkflowReloadLimitation::LiveRefreshExpected,
    )
    .expect("proposal");

    let value = serde_json::to_value(&proposal).expect("serialize proposal");
    for forbidden in [
        "sessionId",
        "process",
        "connectionOwnerId",
        "connectionEpoch",
        "exposureRevision",
        "operationId",
    ] {
        assert!(value.get(forbidden).is_none(), "unexpected {forbidden}");
    }
    assert_eq!(proposal.prompt_digest.len(), 64);
    assert_eq!(proposal.proposal_fingerprint.len(), 64);
}

#[test]
fn sealed_workflow_high_water_rejects_version_generation_and_sequence_replay() {
    let (_temp, root) = private_temp();
    let store = WorkflowHighWaterStore::new(&root, [0x53; 32]);
    let first = store
        .publish(
            "session-one",
            None,
            owner(1),
            WorkflowHighWater::new("session-one", 3, 7, 4, digest('7')).expect("high water"),
        )
        .expect("publish high water");

    for replay in [
        WorkflowHighWater::new("session-one", 2, 8, 5, digest('8')).unwrap(),
        WorkflowHighWater::new("session-one", 3, 6, 5, digest('8')).unwrap(),
        WorkflowHighWater::new("session-one", 3, 8, 3, digest('8')).unwrap(),
    ] {
        assert!(matches!(
            store.publish("session-one", Some(&first), owner(2), replay),
            Err(WorkflowHighWaterError::Replay)
        ));
    }

    let path = root.join("sessions/workflow-high-water/session-one.json");
    let raw = fs::read_to_string(&path).expect("read high water");
    fs::write(
        &path,
        raw.replace("\"stateSequence\": 7", "\"stateSequence\": 9"),
    )
    .expect("tamper high water");
    assert!(matches!(
        store.load("session-one"),
        Err(WorkflowHighWaterError::AuthenticationFailed)
    ));
}

#[test]
fn transition_stages_exact_mode_and_cancel_restores_observed_exposure_idempotently() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let router = WorkflowRouter::new(manager.clone());
    let request = transition_request("transition-one", pinned.revision.sequence);
    let staged = router
        .enter_mode(&claimed.handle, &pinned.revision, request)
        .expect("stage transition");
    assert_eq!(staged.lifecycle, WorkflowOperationLifecycle::Staged);
    let current = manager
        .load_for_handle(&claimed.handle)
        .expect("staged lease");
    assert_eq!(current.lease.desired_exposure.revision, digest('a'));
    assert_eq!(current.lease.observed_exposure.revision, digest('b'));
    assert!(!current.lease.admission_open);
    assert_eq!(
        current.lease.workflow.as_ref().unwrap().active_mode,
        "implementation"
    );
    let operation = WorkflowJournal::new(&root)
        .load(claimed.handle.session_id(), "transition-one")
        .expect("journal")
        .expect("operation");
    assert_eq!(
        operation.value.lifecycle,
        WorkflowOperationLifecycle::Staged
    );
    let mut proposed = operation.value;
    proposed.lifecycle = WorkflowOperationLifecycle::Proposed;
    proposed.reason_code = "workflow-transition-requested".to_string();
    WorkflowJournal::new(&root)
        .compare_and_swap(
            &proposed,
            Some(&operation.revision),
            OwnerGeneration::new(claimed.handle.owner_id(), current.revision.sequence).unwrap(),
        )
        .expect("simulate proposed-to-lease crash window");

    let cancelled = router
        .cancel_transition(&claimed.handle, &current.revision, "transition-one", 1_004)
        .expect("cancel transition");
    assert_eq!(
        cancelled.lease.desired_exposure,
        cancelled.lease.observed_exposure
    );
    assert_eq!(
        cancelled.lease.workflow.as_ref().unwrap().active_mode,
        "planning"
    );
    assert!(cancelled.lease.admission_open);
    let operation = WorkflowJournal::new(&root)
        .load(claimed.handle.session_id(), "transition-one")
        .unwrap()
        .unwrap();
    assert_eq!(
        operation.value.lifecycle,
        WorkflowOperationLifecycle::Cancelled
    );
    assert_eq!(
        router
            .cancel_transition(
                &claimed.handle,
                &cancelled.revision,
                "transition-one",
                1_005
            )
            .expect("idempotent cancel")
            .revision,
        cancelled.revision
    );
    assert!(matches!(
        router.cancel_transition(&claimed.handle, &pinned.revision, "transition-one", 1_006),
        Err(WorkflowRouterError::StaleOperation)
    ));
}

#[test]
fn staged_transition_remains_cancellable_after_expected_live_status_publication() {
    for (status, label) in [
        (LiveExposureStatus::NotificationSent, "notification-sent"),
        (LiveExposureStatus::ReloadRequired, "reload-required"),
    ] {
        let (_temp, root) = private_temp();
        let (manager, claimed) = claimed_session(&root);
        let pinned = manager
            .pin_workflow(
                &claimed.handle,
                &claimed.lease.revision,
                workflow(),
                exposure('b'),
                1_002,
            )
            .expect("pin workflow");
        let router = WorkflowRouter::new(manager.clone());
        let operation_id = format!("transition-{label}");
        router
            .enter_mode(
                &claimed.handle,
                &pinned.revision,
                transition_request(&operation_id, pinned.revision.sequence),
            )
            .expect("stage transition");
        let staged = manager
            .load_for_handle(&claimed.handle)
            .expect("staged lease");
        let published = manager
            .observe_exposure(&claimed.handle, &staged.revision, status, 1_004)
            .expect("publish live status");

        let cancelled = router
            .cancel_transition(&claimed.handle, &published.revision, &operation_id, 1_005)
            .expect("cancel after live-status publication");
        assert_eq!(
            cancelled.lease.desired_exposure,
            cancelled.lease.observed_exposure
        );
        assert_eq!(
            cancelled.lease.workflow.as_ref().unwrap().active_mode,
            "planning"
        );
        assert!(cancelled.lease.admission_open);
    }
}

#[test]
fn unrelated_state_drift_does_not_extend_transition_cancellation_binding() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let router = WorkflowRouter::new(manager.clone());
    router
        .enter_mode(
            &claimed.handle,
            &pinned.revision,
            transition_request("transition-with-drift", pinned.revision.sequence),
        )
        .expect("stage transition");
    let staged = manager
        .load_for_handle(&claimed.handle)
        .expect("staged lease");
    let published = manager
        .observe_exposure(
            &claimed.handle,
            &staged.revision,
            LiveExposureStatus::NotificationSent,
            1_004,
        )
        .expect("publish notification status");
    let drifted = manager
        .report_workspace_revision(
            &claimed.handle,
            &published.revision,
            Some(digest('9')),
            1_005,
        )
        .expect("report unrelated workspace drift");

    assert!(matches!(
        router.cancel_transition(
            &claimed.handle,
            &drifted.revision,
            "transition-with-drift",
            1_006,
        ),
        Err(WorkflowRouterError::OperationBindingMismatch)
    ));
    let current = manager
        .load_for_handle(&claimed.handle)
        .expect("lease after rejected cancellation");
    assert_eq!(current.revision, drifted.revision);
    assert_ne!(
        current.lease.desired_exposure,
        current.lease.observed_exposure
    );
}

#[test]
fn out_of_envelope_and_stale_or_foreign_requests_do_not_mutate_lease_or_journal() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let router = WorkflowRouter::new(manager.clone());
    let request = WorkflowTransitionRequest {
        operation_id: "private-hidden-capability".to_string(),
        operation_fingerprint: digest('2'),
        source_state_sequence: pinned.revision.sequence,
        target_mode: "secret-mode".to_string(),
        requested_at_unix: 1_003,
    };
    assert!(matches!(
        router.enter_mode(&claimed.handle, &pinned.revision, request),
        Err(WorkflowRouterError::ExpansionRequiresOperatorReview)
    ));
    assert_eq!(
        manager.load_for_handle(&claimed.handle).unwrap().revision,
        pinned.revision
    );
    let directory = root
        .join("sessions")
        .join("workflow-operations")
        .join(encode_path_segment(claimed.handle.session_id()));
    let paths = fs::read_dir(&directory)
        .expect("denial journal directory")
        .map(|entry| entry.expect("denial journal entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    let raw = fs::read_to_string(&paths[0]).expect("denial journal");
    let document: serde_json::Value = serde_json::from_str(&raw).expect("denial JSON");
    let value = &document["value"];
    assert_eq!(value["lifecycle"], "denied");
    assert_eq!(
        value["reasonCode"],
        "workflow-envelope-expansion-review-required"
    );
    assert!(value.get("sourceMode").is_none());
    assert!(value.get("targetMode").is_none());
    for private in [
        "private-hidden-capability",
        "secret-mode",
        "profileId\": \"workflow-e",
        "opening prompt payload",
    ] {
        assert!(!raw.contains(private), "denial leaked {private}");
    }

    let stale = WorkflowTransitionRequest {
        operation_id: "stale-transition".to_string(),
        operation_fingerprint: digest('3'),
        source_state_sequence: pinned.revision.sequence - 1,
        target_mode: "implementation".to_string(),
        requested_at_unix: 1_003,
    };
    assert!(matches!(
        router.enter_mode(&claimed.handle, &pinned.revision, stale),
        Err(WorkflowRouterError::StaleOperation)
    ));
    let foreign = unpin_core::sessions::SessionHandle::read_secret(
        claimed.handle.session_id().to_string(),
        "foreign-owner".to_string(),
        std::io::Cursor::new("00".repeat(32)),
    )
    .expect("foreign handle");
    assert!(matches!(
        manager.load_for_handle(&foreign),
        Err(LeaseError::OwnerAuthenticationFailed)
    ));
}

#[test]
fn overlapping_and_surviving_nonterminal_transitions_are_rejected() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let router = WorkflowRouter::new(manager.clone());
    router
        .enter_mode(
            &claimed.handle,
            &pinned.revision,
            transition_request("transition-one", pinned.revision.sequence),
        )
        .expect("stage first transition");
    let staged = manager
        .load_for_handle(&claimed.handle)
        .expect("staged lease");
    assert!(matches!(
        router.enter_mode(
            &claimed.handle,
            &staged.revision,
            transition_request("transition-two", staged.revision.sequence),
        ),
        Err(WorkflowRouterError::TransitionInProgress)
    ));
    assert!(!operation_path(&root, claimed.handle.session_id(), "transition-two").exists());

    let restored = router
        .cancel_transition(&claimed.handle, &staged.revision, "transition-one", 1_004)
        .expect("restore lease");
    let journal = WorkflowJournal::new(&root);
    let cancelled = journal
        .load(claimed.handle.session_id(), "transition-one")
        .unwrap()
        .unwrap();
    let mut surviving = cancelled.value;
    surviving.lifecycle = WorkflowOperationLifecycle::Staged;
    surviving.reason_code = "workflow-transition-staged".to_string();
    surviving.target_state_sequence = restored.revision.sequence;
    surviving.terminal_at_unix = None;
    let path = operation_path(&root, claimed.handle.session_id(), "transition-one");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("journal bytes")).expect("journal JSON");
    document["value"] = serde_json::to_value(surviving).expect("staged record");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("journal document"),
    )
    .expect("simulate lease-before-terminal crash");
    assert!(matches!(
        router.enter_mode(
            &claimed.handle,
            &restored.revision,
            transition_request("transition-three", restored.revision.sequence),
        ),
        Err(WorkflowRouterError::TransitionInProgress)
    ));
    let recovered = router
        .cancel_transition(&claimed.handle, &restored.revision, "transition-one", 1_005)
        .expect("terminalize surviving operation");
    assert_eq!(recovered.revision, restored.revision);
}

#[test]
fn exact_proposed_retry_stages_but_unrelated_transition_remains_blocked() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let request = transition_request("crash-after-proposed", pinned.revision.sequence);
    let record = WorkflowOperationRecord {
        schema_version: WORKFLOW_OPERATION_SCHEMA_VERSION,
        session_id: claimed.handle.session_id().to_string(),
        operation_id: request.operation_id.clone(),
        kind: unpin_core::sessions::WorkflowOperationKind::Transition,
        lifecycle: WorkflowOperationLifecycle::Proposed,
        reason_code: "workflow-transition-requested".to_string(),
        source_state_sequence: pinned.revision.sequence,
        target_state_sequence: pinned.revision.sequence + 1,
        operation_fingerprint: request.operation_fingerprint.clone(),
        source_mode: Some("planning".to_string()),
        target_mode: Some("implementation".to_string()),
        created_at_unix: request.requested_at_unix,
        terminal_at_unix: None,
    };
    WorkflowJournal::new(&root)
        .compare_and_swap(
            &record,
            None,
            OwnerGeneration::new(claimed.handle.owner_id(), pinned.revision.sequence)
                .expect("journal owner"),
        )
        .expect("persist proposed before lease CAS");
    let router = WorkflowRouter::new(manager.clone());

    let mut unrelated = request.clone();
    unrelated.operation_id = "unrelated-transition".to_string();
    unrelated.operation_fingerprint = digest('8');
    assert!(matches!(
        router.enter_mode(&claimed.handle, &pinned.revision, unrelated),
        Err(WorkflowRouterError::TransitionInProgress)
    ));

    let staged = router
        .enter_mode(&claimed.handle, &pinned.revision, request)
        .expect("exact proposed retry stages transition");
    assert_eq!(staged.lifecycle, WorkflowOperationLifecycle::Staged);
    let persisted = WorkflowJournal::new(&root)
        .load(claimed.handle.session_id(), "crash-after-proposed")
        .expect("load retried operation")
        .expect("retried operation");
    assert_eq!(
        persisted.value.lifecycle,
        WorkflowOperationLifecycle::Staged
    );
}

#[test]
fn cancel_checks_revision_and_operation_binding_before_mutation() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let router = WorkflowRouter::new(manager.clone());
    router
        .enter_mode(
            &claimed.handle,
            &pinned.revision,
            transition_request("transition-one", pinned.revision.sequence),
        )
        .expect("stage transition");
    let staged = manager
        .load_for_handle(&claimed.handle)
        .expect("staged lease");
    let journal = WorkflowJournal::new(&root);
    let operation = journal
        .load(claimed.handle.session_id(), "transition-one")
        .unwrap()
        .unwrap();
    let mut tampered = operation.value;
    tampered.target_mode = Some("planning".to_string());
    journal
        .compare_and_swap(
            &tampered,
            Some(&operation.revision),
            OwnerGeneration::new(claimed.handle.owner_id(), staged.revision.sequence).unwrap(),
        )
        .expect("tamper binding through journal CAS");
    assert!(matches!(
        router.cancel_transition(&claimed.handle, &staged.revision, "transition-one", 1_004),
        Err(WorkflowRouterError::OperationBindingMismatch)
    ));
    assert_eq!(
        manager.load_for_handle(&claimed.handle).unwrap().revision,
        staged.revision
    );
}

#[test]
fn terminal_journal_records_are_immutable_idempotent_and_retained() {
    let (_temp, root) = private_temp();
    let journal = WorkflowJournal::new(&root);
    let record = WorkflowOperationRecord {
        schema_version: WORKFLOW_OPERATION_SCHEMA_VERSION,
        session_id: "session-one".to_string(),
        operation_id: "denial-one".to_string(),
        kind: unpin_core::sessions::WorkflowOperationKind::Denial,
        lifecycle: WorkflowOperationLifecycle::Denied,
        reason_code: "workflow-envelope-expansion-review-required".to_string(),
        source_state_sequence: 1,
        target_state_sequence: 1,
        operation_fingerprint: digest('9'),
        source_mode: None,
        target_mode: None,
        created_at_unix: 100,
        terminal_at_unix: Some(100),
    };
    let revision = journal
        .compare_and_swap(&record, None, owner(1))
        .expect("create terminal record");
    assert_eq!(
        journal
            .compare_and_swap(&record, Some(&revision), owner(2))
            .expect("identical terminal retry"),
        revision
    );
    let mut changed = record.clone();
    changed.reason_code = "different-reason".to_string();
    assert!(matches!(
        journal.compare_and_swap(&changed, Some(&revision), owner(2)),
        Err(unpin_core::sessions::WorkflowJournalError::TerminalMutation)
    ));
    let retention = unpin_core::sessions::WORKFLOW_TERMINAL_RETENTION_SECONDS;
    assert!(!record.prune_eligible(100 + retention - 1, false));
    assert!(record.prune_eligible(100 + retention, false));
    assert!(!record.prune_eligible(100 + retention, true));
}

#[test]
fn missing_finalized_high_water_fails_closed() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");
    let high_water_path = root
        .join("sessions")
        .join("workflow-high-water")
        .join(format!(
            "{}.json",
            encode_path_segment(claimed.handle.session_id())
        ));
    fs::remove_file(&high_water_path).expect("remove high water after lease write");
    assert!(matches!(
        manager.load_for_handle(&claimed.handle),
        Err(LeaseError::WorkflowHighWaterMissing)
    ));
}

#[test]
fn high_water_ahead_of_authenticated_lease_is_rejected() {
    let (_temp, root) = private_temp();
    let (manager, claimed) = claimed_session(&root);
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            workflow(),
            exposure('b'),
            1_002,
        )
        .expect("pin workflow");

    let advanced = manager
        .observe_exposure(
            &claimed.handle,
            &pinned.revision,
            LiveExposureStatus::NotificationSent,
            1_003,
        )
        .expect("advance authenticated lease");
    let high_water = WorkflowHighWaterStore::new(&root, [0x53; 32]);
    let current = high_water
        .load(claimed.handle.session_id())
        .expect("load high water")
        .expect("high water");
    high_water
        .publish(
            claimed.handle.session_id(),
            Some(&current.revision),
            current.owner,
            WorkflowHighWater::new(
                claimed.handle.session_id(),
                3,
                advanced.lease.workflow.as_ref().unwrap().state_sequence + 1,
                advanced.lease.workflow.as_ref().unwrap().sealed_generation,
                digest('9'),
            )
            .unwrap(),
        )
        .expect("publish high water ahead of lease");
    assert!(matches!(
        manager.load_for_handle(&claimed.handle),
        Err(LeaseError::WorkflowReplay)
    ));
}

#[test]
fn first_pin_pending_with_source_lease_is_cleared_on_load() {
    let (_temp, root) = private_temp();
    let fixture = first_pin_fault_fixture(&root);

    let loaded = fixture
        .manager
        .load_for_handle(&fixture.claimed.handle)
        .expect("source lease remains valid");
    assert_eq!(loaded.revision, fixture.claimed.lease.revision);
    assert!(loaded.lease.workflow.is_none());
    assert!(!fixture.high_water_path.exists());
}

#[test]
fn first_pin_pending_with_target_lease_is_finalized_on_load() {
    let (_temp, root) = private_temp();
    let fixture = first_pin_fault_fixture(&root);
    fs::write(&fixture.lease_path, &fixture.target_lease).expect("restore target lease");

    let loaded = fixture
        .manager
        .load_for_handle(&fixture.claimed.handle)
        .expect("target lease remains valid");
    assert!(loaded.lease.workflow.is_some());
    let target: serde_json::Value =
        serde_json::from_slice(&fixture.target_lease).expect("target lease JSON");
    let target_tag = target["value"]["lease"]["authenticationTag"]
        .as_str()
        .expect("target lease authentication tag");
    let high_water = WorkflowHighWaterStore::new(&root, [0x53; 32])
        .load(fixture.claimed.handle.session_id())
        .expect("load finalized high water")
        .expect("finalized high water");
    assert!(high_water.value.pending.is_none());
    assert_eq!(high_water.value.lease_authentication_tag, target_tag);
}

#[test]
fn reader_cannot_clear_pending_between_publish_and_lease_cas() {
    let (_temp, root) = private_temp();
    let fixture = first_pin_fault_fixture(&root);
    let writer_lock =
        StateResourceLock::acquire(get_session_registry_lock_path(&root)).expect("writer lock");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let reader_manager = fixture.manager.clone();
    let session_id = fixture.claimed.handle.session_id().to_string();
    let reader_handle = fixture.claimed.handle;
    let reader = thread::spawn(move || {
        started_tx.send(()).expect("reader started");
        done_tx
            .send(reader_manager.load_for_handle(&reader_handle))
            .expect("reader result");
    });
    started_rx.recv().expect("reader ready");
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let pending = WorkflowHighWaterStore::new(&root, [0x53; 32])
        .load(&session_id)
        .expect("load pending high water")
        .expect("pending high water");
    assert!(pending.value.pending.is_some());

    fs::write(&fixture.lease_path, &fixture.target_lease).expect("lease CAS");
    drop(writer_lock);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("reader completes after writer")
        .expect("reader finalizes target");
    reader.join().expect("reader thread");
    let finalized = WorkflowHighWaterStore::new(&root, [0x53; 32])
        .load(&session_id)
        .expect("load finalized high water")
        .expect("finalized high water");
    assert!(finalized.value.pending.is_none());
}

#[test]
fn finalized_first_pin_rejects_replayed_authenticated_source_lease() {
    let (_temp, root) = private_temp();
    let fixture = first_pin_fault_fixture(&root);
    fs::write(&fixture.lease_path, &fixture.target_lease).expect("restore target lease");
    fixture
        .manager
        .load_for_handle(&fixture.claimed.handle)
        .expect("finalize first pin");
    fs::write(&fixture.lease_path, &fixture.source_lease).expect("replay source lease");

    assert!(matches!(
        fixture.manager.load_for_handle(&fixture.claimed.handle),
        Err(LeaseError::WorkflowReplay)
    ));
}
