use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Barrier, mpsc},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    catalog::CapabilityId,
    config::{get_session_lease_path, get_session_overlay_root},
    profiles::{CapabilityLockSnapshot, CapabilityLockState, ProfileSourceScope},
    providers::ProviderId,
    sessions::{
        BootstrapAuthority, BootstrapRequest, ConnectionClaim, CoverageLevel, ForceMode,
        GatewayInstallState, GatewayModeManager, GatewayModeTarget, GatewayRoutingState,
        IsolationLevel, LeaseError, LeaseLifecycle, LiveExposureStatus, PinnedExposure,
        PinnedProfile, ProcessEvidence, ProcessInspector, SESSION_OVERLAY_MARKER,
        SessionAuthorityKey, SessionEndControlError, SessionEndController, SessionEndStatus,
        SessionHandle, SessionManager, capture_process_evidence,
    },
    state::atomic_json::StateError,
    transitions::{
        EffectActivation, EffectAuthority, TransitionConflictChecker, TransitionContext,
        TransitionEffect, TransitionEffectKind, TransitionJournalStore, TransitionKind,
        TransitionLifecycle, TransitionPlan,
    },
};

mod support;
use support::{control_authorization, control_context};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
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

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn session_authority_key() -> SessionAuthorityKey {
    SessionAuthorityKey::new([0x53; 32])
}

fn authenticated_manager(path: &Path) -> SessionManager {
    SessionManager::with_authority_key(path, session_authority_key())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn legacy_pending_integrity(claim: &serde_json::Value) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct LegacyPending<'a> {
        session_id: &'a serde_json::Value,
        provider: &'a serde_json::Value,
        repository_key: &'a serde_json::Value,
        workspace_key: &'a serde_json::Value,
        workspace_revision: &'a serde_json::Value,
        exposure: &'a serde_json::Value,
        process: &'a serde_json::Value,
        connection_scope_digest: &'a serde_json::Value,
        isolation: &'a serde_json::Value,
        coverage: &'a serde_json::Value,
        protected_resources: &'a serde_json::Value,
        lease_expires_at_unix: &'a serde_json::Value,
        issued_at_unix: &'a serde_json::Value,
        bootstrap_expires_at_unix: &'a serde_json::Value,
        secret_digest: &'a serde_json::Value,
    }

    let raw = serde_json::to_vec(&LegacyPending {
        session_id: &claim["sessionId"],
        provider: &claim["provider"],
        repository_key: &claim["repositoryKey"],
        workspace_key: &claim["workspaceKey"],
        workspace_revision: &claim["workspaceRevision"],
        exposure: &claim["exposure"],
        process: &claim["process"],
        connection_scope_digest: &claim["connectionScopeDigest"],
        isolation: &claim["isolation"],
        coverage: &claim["coverage"],
        protected_resources: &claim["protectedResources"],
        lease_expires_at_unix: &claim["leaseExpiresAtUnix"],
        issued_at_unix: &claim["issuedAtUnix"],
        bootstrap_expires_at_unix: &claim["bootstrapExpiresAtUnix"],
        secret_digest: &claim["secretDigest"],
    })
    .expect("legacy pending integrity body");
    hex_digest(&Sha256::digest(raw))
}

fn legacy_lease_integrity(lease: &serde_json::Value) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct LegacyLease<'a> {
        session_id: &'a serde_json::Value,
        provider: &'a serde_json::Value,
        repository_key: &'a serde_json::Value,
        workspace_key: &'a serde_json::Value,
        workspace_start_revision: &'a serde_json::Value,
        last_workspace_revision: &'a serde_json::Value,
        workspace_drifted: &'a serde_json::Value,
        desired_exposure: &'a serde_json::Value,
        observed_exposure: &'a serde_json::Value,
        live_status: &'a serde_json::Value,
        process: &'a serde_json::Value,
        isolation: &'a serde_json::Value,
        coverage: &'a serde_json::Value,
        protected_resources: &'a serde_json::Value,
        lifecycle: &'a serde_json::Value,
        admission_open: &'a serde_json::Value,
        in_flight_calls: &'a serde_json::Value,
        in_flight_call_ids: &'a serde_json::Value,
        heartbeat_at_unix: &'a serde_json::Value,
        lease_expires_at_unix: &'a serde_json::Value,
        connection_owner_id: &'a serde_json::Value,
        closed_reason: &'a serde_json::Value,
        connection_scope_digest: &'a serde_json::Value,
        owner_secret_digest: &'a serde_json::Value,
    }

    let empty_call_ids = serde_json::json!([]);
    let raw = serde_json::to_vec(&LegacyLease {
        session_id: &lease["sessionId"],
        provider: &lease["provider"],
        repository_key: &lease["repositoryKey"],
        workspace_key: &lease["workspaceKey"],
        workspace_start_revision: &lease["workspaceStartRevision"],
        last_workspace_revision: &lease["lastWorkspaceRevision"],
        workspace_drifted: &lease["workspaceDrifted"],
        desired_exposure: &lease["desiredExposure"],
        observed_exposure: &lease["observedExposure"],
        live_status: &lease["liveStatus"],
        process: &lease["process"],
        isolation: &lease["isolation"],
        coverage: &lease["coverage"],
        protected_resources: &lease["protectedResources"],
        lifecycle: &lease["lifecycle"],
        admission_open: &lease["admissionOpen"],
        in_flight_calls: &lease["inFlightCalls"],
        in_flight_call_ids: lease.get("inFlightCallIds").unwrap_or(&empty_call_ids),
        heartbeat_at_unix: &lease["heartbeatAtUnix"],
        lease_expires_at_unix: &lease["leaseExpiresAtUnix"],
        connection_owner_id: &lease["connectionOwnerId"],
        closed_reason: &lease["closedReason"],
        connection_scope_digest: &lease["connectionScopeDigest"],
        owner_secret_digest: &lease["ownerSecretDigest"],
    })
    .expect("legacy lease integrity body");
    hex_digest(&Sha256::digest(raw))
}

fn profile(character: char) -> PinnedProfile {
    PinnedProfile::Profile {
        profile_id: format!("profile-{character}"),
        profile_digest: digest(character),
        origin_scope: ProfileSourceScope::Workspace,
        definition_digest: digest('d'),
    }
}

fn process(pid: u32, marker: &str) -> ProcessEvidence {
    ProcessEvidence {
        pid,
        start_marker: marker.to_string(),
    }
}

fn request(
    workspace_key: &str,
    connection_scope_id: &str,
    profile: PinnedProfile,
) -> BootstrapRequest {
    BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository-key".to_string(),
        workspace_key: workspace_key.to_string(),
        workspace_revision: Some(digest('1')),
        exposure: PinnedExposure {
            revision: digest('e'),
            profile,
            capability_locks: None,
        },
        process: process(41, &format!("start-{workspace_key}")),
        connection_scope_id: connection_scope_id.to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["provider-global-config".to_string()]),
        lease_expires_at_unix: 10_000,
    }
}

fn claim_for(request: &BootstrapRequest, owner: &str) -> ConnectionClaim {
    ConnectionClaim {
        connection_owner_id: owner.to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    }
}

fn establish(
    manager: &SessionManager,
    request: BootstrapRequest,
    now_unix: i64,
    owner: &str,
) -> unpin_core::sessions::ClaimedSession {
    let claim = claim_for(&request, owner);
    let authority = manager
        .prepare_bootstrap(request, now_unix)
        .expect("prepare bootstrap");
    manager
        .claim_bootstrap(&authority, &claim, now_unix + 1)
        .expect("claim bootstrap")
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

#[test]
fn bootstrap_is_single_use_context_bound_and_secret_free_on_disk() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let request = request("workspace-a", "connection-a", profile('a'));
    let authority = manager
        .prepare_bootstrap(request.clone(), 1_000)
        .expect("prepare bootstrap");

    let mut delivered = Vec::new();
    authority
        .write_secret(&mut delivered)
        .expect("serialize bootstrap authority");
    let raw_secret = String::from_utf8(delivered).expect("secret transport is utf8");
    let persisted = fs::read_to_string(get_session_lease_path(temp.path(), authority.session_id()))
        .expect("pending bootstrap state");
    assert!(!persisted.contains(raw_secret.trim()));
    assert!(!format!("{authority:?}").contains(raw_secret.trim()));

    let mut wrong = claim_for(&request, "connection-owner-a");
    wrong.workspace_key = "workspace-b".to_string();
    assert!(matches!(
        manager.claim_bootstrap(&authority, &wrong, 1_001),
        Err(LeaseError::BindingMismatch)
    ));

    let claimed = manager
        .claim_bootstrap(
            &authority,
            &claim_for(&request, "connection-owner-a"),
            1_001,
        )
        .expect("claim bootstrap");
    assert_eq!(claimed.lease.lease.workspace_key, "workspace-a");
    assert_eq!(claimed.lease.lease.lifecycle, LeaseLifecycle::Active);
    assert!(matches!(
        manager.claim_bootstrap(
            &authority,
            &claim_for(&request, "connection-owner-b"),
            1_002,
        ),
        Err(LeaseError::BootstrapAlreadyConsumed)
    ));

    let transported = BootstrapAuthority::read_secret(
        authority.session_id().to_string(),
        Cursor::new(raw_secret),
    )
    .expect("read transported authority");
    assert!(matches!(
        manager.claim_bootstrap(
            &transported,
            &claim_for(&request, "connection-owner-a"),
            1_002,
        ),
        Err(LeaseError::BootstrapAlreadyConsumed)
    ));
}

#[test]
fn pending_bootstrap_authentication_binds_every_persisted_field_and_rejects_legacy_checksum() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let request = request("workspace-a", "connection-a", profile('a'));
    let authority = manager
        .prepare_bootstrap(request.clone(), 1_000)
        .expect("prepare bootstrap");
    let path = get_session_lease_path(temp.path(), authority.session_id());
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("pending state")).expect("pending JSON");

    let mutations = [
        ("sessionId", serde_json::json!("session-forged")),
        ("provider", serde_json::json!("claude")),
        ("repositoryKey", serde_json::json!("repository-forged")),
        ("workspaceKey", serde_json::json!("workspace-forged")),
        ("workspaceRevision", serde_json::json!(digest('2'))),
        (
            "exposure",
            serde_json::json!({"revision": digest('f'), "profile": {"type": "none"}}),
        ),
        (
            "process",
            serde_json::json!({"pid": 42, "startMarker": "start-forged"}),
        ),
        ("connectionScopeDigest", serde_json::json!(digest('3'))),
        ("isolation", serde_json::json!("connection-scoped")),
        (
            "coverage",
            serde_json::json!({"state": "external-degraded", "reasons": ["forged-reason"]}),
        ),
        (
            "protectedResources",
            serde_json::json!(["provider-global-config", "forged-resource"]),
        ),
        ("leaseExpiresAtUnix", serde_json::json!(9_999)),
        ("issuedAtUnix", serde_json::json!(999)),
        ("bootstrapExpiresAtUnix", serde_json::json!(1_299)),
        ("secretDigest", serde_json::json!(digest('4'))),
        ("authenticationAlgorithm", serde_json::json!("hmac-sha512")),
        (
            "authorityKeyId",
            serde_json::json!("sha256:0000000000000000"),
        ),
    ];

    for (field, replacement) in mutations {
        let mut forged = original.clone();
        forged["value"]["claim"][field] = replacement;
        fs::write(
            &path,
            serde_json::to_vec_pretty(&forged).expect("forged pending JSON"),
        )
        .expect("write forged pending state");
        assert!(
            matches!(
                manager.claim_bootstrap(
                    &authority,
                    &claim_for(&request, "connection-owner-a"),
                    1_001,
                ),
                Err(LeaseError::IntegrityMismatch | LeaseError::InvalidState(_))
            ),
            "field {field} must be authenticated"
        );
    }

    let mut legacy_forgery = original.clone();
    legacy_forgery["value"]["claim"]["workspaceKey"] = serde_json::json!("workspace-forged");
    let legacy_checksum = legacy_pending_integrity(&legacy_forgery["value"]["claim"]);
    legacy_forgery["value"]["claim"]["authenticationTag"] = serde_json::json!(legacy_checksum);
    fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy_forgery).expect("legacy forged pending JSON"),
    )
    .expect("write legacy forged pending state");
    assert!(matches!(
        manager.claim_bootstrap(
            &authority,
            &claim_for(&request, "connection-owner-a"),
            1_001,
        ),
        Err(LeaseError::IntegrityMismatch)
    ));

    fs::write(
        &path,
        serde_json::to_vec_pretty(&original).expect("original pending JSON"),
    )
    .expect("restore pending state");
    manager
        .claim_bootstrap(
            &authority,
            &claim_for(&request, "connection-owner-a"),
            1_001,
        )
        .expect("untampered bootstrap remains claimable");
}

#[test]
fn bootstrap_authority_rejects_wrong_state_key_and_cross_session_secret() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let request_a = request("workspace-a", "connection-a", profile('a'));
    let request_b = request("workspace-b", "connection-b", profile('b'));
    let authority_a = manager
        .prepare_bootstrap(request_a, 1_000)
        .expect("prepare bootstrap A");
    let authority_b = manager
        .prepare_bootstrap(request_b.clone(), 1_000)
        .expect("prepare bootstrap B");

    let wrong_key_manager =
        SessionManager::with_authority_key(temp.path(), SessionAuthorityKey::new([0x54; 32]));
    assert!(matches!(
        wrong_key_manager.claim_bootstrap(&authority_b, &claim_for(&request_b, "owner-b"), 1_001,),
        Err(LeaseError::IntegrityMismatch)
    ));

    let mut authority_a_secret = Vec::new();
    authority_a
        .write_secret(&mut authority_a_secret)
        .expect("authority A transport");
    let cross_session = BootstrapAuthority::read_secret(
        authority_b.session_id().to_string(),
        Cursor::new(authority_a_secret),
    )
    .expect("cross-session authority shape");
    assert!(matches!(
        manager.claim_bootstrap(&cross_session, &claim_for(&request_b, "owner-b"), 1_001,),
        Err(LeaseError::BootstrapAuthenticationFailed)
    ));
}

#[test]
fn simultaneous_bootstrap_claims_establish_exactly_one_owner() {
    let temp = TempDir::new();
    let manager = Arc::new(authenticated_manager(temp.path()));
    let request = request("workspace-a", "connection-a", profile('a'));
    let authority = manager
        .prepare_bootstrap(request.clone(), 1_000)
        .expect("prepare bootstrap");
    let mut secret = Vec::new();
    authority
        .write_secret(&mut secret)
        .expect("serialize bootstrap authority");
    let authority_a = BootstrapAuthority::read_secret(
        authority.session_id().to_string(),
        Cursor::new(secret.clone()),
    )
    .expect("authority A");
    let authority_b =
        BootstrapAuthority::read_secret(authority.session_id().to_string(), Cursor::new(secret))
            .expect("authority B");
    let barrier = Arc::new(Barrier::new(3));

    let manager_a = Arc::clone(&manager);
    let barrier_a = Arc::clone(&barrier);
    let request_a = request.clone();
    let claim_a = thread::spawn(move || {
        barrier_a.wait();
        manager_a.claim_bootstrap(&authority_a, &claim_for(&request_a, "owner-a"), 1_001)
    });
    let manager_b = Arc::clone(&manager);
    let barrier_b = Arc::clone(&barrier);
    let claim_b = thread::spawn(move || {
        barrier_b.wait();
        manager_b.claim_bootstrap(&authority_b, &claim_for(&request, "owner-b"), 1_001)
    });
    barrier.wait();

    let results = [
        claim_a.join().expect("claim A thread"),
        claim_b.join().expect("claim B thread"),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(LeaseError::BootstrapAlreadyConsumed)))
            .count(),
        1
    );
    let claimed = results
        .into_iter()
        .find_map(Result::ok)
        .expect("one established owner");
    manager
        .close_owned(
            &claimed.handle,
            &claimed.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close winning owner");
}

#[test]
fn cancelled_bootstrap_removes_claim_and_cannot_establish_lease() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let request = request("workspace-a", "connection-a", profile('a'));
    let claim = claim_for(&request, "owner-a");
    let authority = manager
        .prepare_bootstrap(request, 1_000)
        .expect("prepare bootstrap");
    let path = get_session_lease_path(temp.path(), authority.session_id());
    manager
        .cancel_bootstrap(&authority)
        .expect("cancel bootstrap");
    assert!(!path.exists());
    assert!(matches!(
        manager.claim_bootstrap(&authority, &claim, 1_001),
        Err(LeaseError::SessionNotFound)
    ));
}

#[test]
fn reviewed_session_end_fences_admission_and_keeps_owner_cleanup_state() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let controller = SessionEndController::with_authority_key(temp.path(), session_authority_key());
    let approval_context = control_context("repository-key", "workspace-a");
    let plan = controller
        .plan(&session.lease.lease.session_id, &approval_context)
        .expect("session end plan");
    assert!(!plan.no_op);
    let authorization = control_authorization(
        temp.path(),
        &plan.approval_expectation(&approval_context).unwrap(),
        "session-end",
        1_002,
    );

    let result = controller
        .apply(
            &plan,
            authorization,
            &approval_context,
            "session-admin",
            1_002,
        )
        .expect("session end apply");
    assert_eq!(result.status, SessionEndStatus::RevocationRequested);
    assert_eq!(result.lifecycle, Some(LeaseLifecycle::Revoking));
    let persisted = manager.list().expect("persisted revoking lease");
    assert_eq!(persisted.len(), 1);
    assert!(!persisted[0].lease.admission_open);
    assert_eq!(
        persisted[0].lease.closed_reason.as_deref(),
        Some("session-end-requested")
    );
    let revision_after_apply = persisted[0].revision.clone();
    let journals = TransitionJournalStore::new(temp.path()).list().unwrap();
    assert!(journals.iter().any(|journal| {
        journal.operation_kind == "session-end"
            && journal.lifecycle == TransitionLifecycle::Committed
            && journal.authorization_decision_digest.is_some()
    }));

    let exact_retry_authorization = control_authorization(
        temp.path(),
        &plan.approval_expectation(&approval_context).unwrap(),
        "session-end",
        1_002,
    );
    assert_eq!(
        controller
            .apply(
                &plan,
                exact_retry_authorization,
                &approval_context,
                "session-admin",
                1_002,
            )
            .expect("exact session-end retry"),
        result
    );
    assert_eq!(
        manager.list().expect("session after retry")[0].revision,
        revision_after_apply
    );

    let repeated = controller
        .plan(&session.lease.lease.session_id, &approval_context)
        .expect("repeat session end plan");
    assert!(repeated.no_op);
    let authorization = control_authorization(
        temp.path(),
        &repeated.approval_expectation(&approval_context).unwrap(),
        "session-end-noop",
        1_003,
    );
    let no_op = controller
        .apply(
            &repeated,
            authorization,
            &approval_context,
            "session-admin",
            1_003,
        )
        .expect("repeat session end");
    assert_eq!(no_op.status, SessionEndStatus::AlreadyEnding);
    let exact_no_op_authorization = control_authorization(
        temp.path(),
        &repeated.approval_expectation(&approval_context).unwrap(),
        "session-end-noop",
        1_003,
    );
    assert_eq!(
        controller
            .apply(
                &repeated,
                exact_no_op_authorization,
                &approval_context,
                "session-admin",
                1_003,
            )
            .expect("exact already-ending retry"),
        no_op
    );
}

#[test]
fn cached_session_end_retry_reports_live_closed_state() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let controller = SessionEndController::with_authority_key(temp.path(), session_authority_key());
    let approval_context = control_context("repository-key", "workspace-a");
    let plan = controller
        .plan(&session.lease.lease.session_id, &approval_context)
        .expect("session end plan");
    let authorization = control_authorization(
        temp.path(),
        &plan.approval_expectation(&approval_context).unwrap(),
        "session-end-close-before-retry",
        1_002,
    );
    controller
        .apply(
            &plan,
            authorization,
            &approval_context,
            "session-admin",
            1_002,
        )
        .expect("session end apply");
    let revoking = manager.list().expect("revoking lease").remove(0);
    manager
        .close_owned(&session.handle, &revoking.revision, "owner-finished", 1_003)
        .expect("close session");

    let retry_authorization = control_authorization(
        temp.path(),
        &plan.approval_expectation(&approval_context).unwrap(),
        "session-end-close-before-retry",
        1_002,
    );
    let retry = controller
        .apply(
            &plan,
            retry_authorization,
            &approval_context,
            "session-admin",
            1_004,
        )
        .expect("cached session end retry");

    assert_eq!(retry.status, SessionEndStatus::NoOp);
    assert_eq!(retry.lifecycle, None);
    assert_eq!(retry.in_flight_calls, 0);
}

#[test]
fn session_end_rejects_reviewed_plan_after_lease_revision_changes() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let controller = SessionEndController::with_authority_key(temp.path(), session_authority_key());
    let approval_context = control_context("repository-key", "workspace-a");
    let plan = controller
        .plan(&session.lease.lease.session_id, &approval_context)
        .expect("session end plan");
    manager
        .heartbeat(&session.handle, &session.lease.revision, 1_002)
        .expect("heartbeat changes revision");
    let authorization = control_authorization(
        temp.path(),
        &plan.approval_expectation(&approval_context).unwrap(),
        "session-end-stale",
        1_003,
    );

    assert!(matches!(
        controller.apply(
            &plan,
            authorization,
            &approval_context,
            "session-admin",
            1_003,
        ),
        Err(SessionEndControlError::PlanFingerprintMismatch)
    ));
}

#[test]
fn session_end_rejects_foreign_workspace_session() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let controller = SessionEndController::with_authority_key(temp.path(), session_authority_key());
    let foreign_context = control_context("repository-key", "workspace-b");

    assert!(matches!(
        controller.plan(&session.lease.lease.session_id, &foreign_context),
        Err(SessionEndControlError::ContextMismatch)
    ));
}

#[test]
fn worktree_and_same_worktree_sessions_keep_pinned_exposure_disjoint() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let lock_snapshot = |capability: &str, state| {
        CapabilityLockSnapshot::compile(
            ProviderId::Codex,
            BTreeMap::from([(CapabilityId::new(capability).unwrap(), state)]),
        )
        .unwrap()
    };
    let mut request_a = request("workspace-a", "connection-a", profile('a'));
    request_a.exposure.capability_locks = Some(Box::new(lock_snapshot(
        "skill.a",
        CapabilityLockState::HardDisabled,
    )));
    let mut request_b = request("workspace-b", "connection-b", profile('b'));
    request_b.exposure.capability_locks = Some(Box::new(lock_snapshot(
        "skill.b",
        CapabilityLockState::HardEnabled,
    )));
    let mut request_c = request("workspace-a", "connection-c", profile('c'));
    request_c.exposure.capability_locks = Some(Box::new(lock_snapshot(
        "skill.c",
        CapabilityLockState::HardDisabled,
    )));
    let session_a = establish(&manager, request_a, 1_000, "owner-a");
    let session_b = establish(&manager, request_b, 1_000, "owner-b");
    let session_c = establish(&manager, request_c, 1_000, "owner-c");
    let session_b_lock_digest = session_b
        .lease
        .lease
        .desired_exposure
        .capability_locks
        .as_ref()
        .unwrap()
        .digest
        .clone();
    let session_c_lock_digest = session_c
        .lease
        .lease
        .desired_exposure
        .capability_locks
        .as_ref()
        .unwrap()
        .digest
        .clone();

    let updated_a = manager
        .request_exposure(
            &session_a.handle,
            &session_a.lease.revision,
            PinnedExposure {
                revision: digest('f'),
                profile: profile('d'),
                capability_locks: Some(Box::new(lock_snapshot(
                    "skill.d",
                    CapabilityLockState::HardEnabled,
                ))),
            },
            1_010,
        )
        .expect("update session A desired exposure");
    let observed_a = manager
        .observe_exposure(
            &session_a.handle,
            &updated_a.revision,
            LiveExposureStatus::ObservedRefresh,
            1_011,
        )
        .expect("observe session A exposure");
    assert_eq!(
        observed_a.lease.desired_exposure,
        observed_a.lease.observed_exposure
    );

    let loaded_b = manager
        .load_for_handle(&session_b.handle)
        .expect("load session B");
    let loaded_c = manager
        .load_for_handle(&session_c.handle)
        .expect("load same-worktree session C");
    assert_eq!(loaded_b.lease.desired_exposure.profile, profile('b'));
    assert_eq!(loaded_c.lease.desired_exposure.profile, profile('c'));
    assert_eq!(
        loaded_b
            .lease
            .desired_exposure
            .capability_locks
            .as_ref()
            .unwrap()
            .digest,
        session_b_lock_digest
    );
    assert_eq!(
        loaded_c
            .lease
            .desired_exposure
            .capability_locks
            .as_ref()
            .unwrap()
            .digest,
        session_c_lock_digest
    );
    assert_ne!(
        observed_a
            .lease
            .desired_exposure
            .capability_locks
            .as_ref()
            .unwrap()
            .digest,
        loaded_b
            .lease
            .desired_exposure
            .capability_locks
            .as_ref()
            .unwrap()
            .digest
    );
    assert_ne!(loaded_b.lease.session_id, loaded_c.lease.session_id);
    assert_eq!(manager.list().expect("list sessions").len(), 3);

    let drifted = manager
        .report_workspace_revision(
            &session_a.handle,
            &observed_a.revision,
            Some(digest('2')),
            1_012,
        )
        .expect("record workspace drift");
    assert!(drifted.lease.workspace_drifted);
    assert_eq!(drifted.lease.desired_exposure.profile, profile('d'));
}

#[test]
fn strict_isolation_rejects_multiplexing_and_unverified_native_coverage() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let first_request = request("workspace-a", "shared-connection", profile('a'));
    let _first = establish(&manager, first_request, 1_000, "owner-a");

    let second_request = request("workspace-b", "shared-connection", profile('b'));
    let second_claim = claim_for(&second_request, "owner-b");
    let second_authority = manager
        .prepare_bootstrap(second_request, 1_000)
        .expect("prepare second bootstrap");
    assert!(matches!(
        manager.claim_bootstrap(&second_authority, &second_claim, 1_001),
        Err(LeaseError::MultiplexedConnection)
    ));

    let mut degraded = request("workspace-c", "connection-c", profile('c'));
    degraded.coverage = CoverageLevel::ExternalDegraded {
        reasons: vec!["unadopted-native-skill".to_string()],
    };
    assert!(matches!(
        manager.prepare_bootstrap(degraded.clone(), 1_000),
        Err(LeaseError::StrictIsolationUnavailable)
    ));

    degraded.isolation = IsolationLevel::ConnectionScoped;
    let scoped = establish(&manager, degraded, 1_000, "owner-c");
    assert_eq!(
        scoped.lease.lease.isolation,
        IsolationLevel::ConnectionScoped
    );
    assert!(matches!(
        scoped.lease.lease.coverage,
        CoverageLevel::ExternalDegraded { .. }
    ));
}

#[test]
fn handle_context_is_opaque_and_foreign_context_rejects_without_lookup() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );

    assert!(
        manager
            .assert_bound_context(
                &session.handle,
                ProviderId::Codex,
                "repository-key",
                "workspace-a",
            )
            .is_ok()
    );
    assert!(matches!(
        manager.assert_bound_context(
            &session.handle,
            ProviderId::Claude,
            "other-repository",
            "workspace-b",
        ),
        Err(LeaseError::ContextMismatch)
    ));
}

#[test]
fn lease_tamper_and_owner_token_forgery_fail_closed() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let forged_handle = SessionHandle::read_secret(
        session.handle.session_id().to_string(),
        session.handle.owner_id().to_string(),
        Cursor::new("00".repeat(32)),
    )
    .expect("forged handle shape");
    assert!(matches!(
        manager.load_for_handle(&forged_handle),
        Err(LeaseError::OwnerAuthenticationFailed)
    ));
    assert!(matches!(
        manager.request_exposure(
            &forged_handle,
            &session.lease.revision,
            PinnedExposure {
                revision: digest('f'),
                profile: profile('f'),
                capability_locks: None,
            },
            1_002,
        ),
        Err(LeaseError::OwnerAuthenticationFailed)
    ));

    let path = get_session_lease_path(temp.path(), &session.lease.lease.session_id);
    let mut json: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read lease state")).expect("lease json");
    json["value"]["lease"]["workspaceKey"] = serde_json::json!("workspace-tampered");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json).expect("tampered json"),
    )
    .expect("write tampered lease");
    assert!(matches!(
        manager.load_for_handle(&session.handle),
        Err(LeaseError::IntegrityMismatch)
    ));
}

#[test]
fn established_lease_authentication_binds_every_persisted_field_and_rejects_legacy_checksum() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let path = get_session_lease_path(temp.path(), &session.lease.lease.session_id);
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("lease state")).expect("lease JSON");
    let mutations = [
        ("sessionId", serde_json::json!("session-forged")),
        ("provider", serde_json::json!("claude")),
        ("repositoryKey", serde_json::json!("repository-forged")),
        ("workspaceKey", serde_json::json!("workspace-forged")),
        ("workspaceStartRevision", serde_json::json!(digest('2'))),
        ("lastWorkspaceRevision", serde_json::json!(digest('2'))),
        ("workspaceDrifted", serde_json::json!(true)),
        (
            "desiredExposure",
            serde_json::json!({"revision": digest('f'), "profile": {"type": "none"}}),
        ),
        (
            "observedExposure",
            serde_json::json!({"revision": digest('f'), "profile": {"type": "none"}}),
        ),
        ("liveStatus", serde_json::json!("reload-required")),
        (
            "process",
            serde_json::json!({"pid": 42, "startMarker": "start-forged"}),
        ),
        ("isolation", serde_json::json!("connection-scoped")),
        (
            "coverage",
            serde_json::json!({"state": "external-degraded", "reasons": ["forged-reason"]}),
        ),
        (
            "protectedResources",
            serde_json::json!(["forged-resource", "provider-global-config"]),
        ),
        ("lifecycle", serde_json::json!("revoking")),
        ("admissionOpen", serde_json::json!(false)),
        ("inFlightCalls", serde_json::json!(1)),
        ("inFlightCallIds", serde_json::json!([digest('5')])),
        ("heartbeatAtUnix", serde_json::json!(1_002)),
        ("leaseExpiresAtUnix", serde_json::json!(9_999)),
        ("connectionOwnerId", serde_json::json!("owner-forged")),
        ("closedReason", serde_json::json!("forged-reason")),
        ("connectionScopeDigest", serde_json::json!(digest('6'))),
        ("ownerSecretDigest", serde_json::json!(digest('7'))),
        ("authenticationAlgorithm", serde_json::json!("hmac-sha512")),
        (
            "authorityKeyId",
            serde_json::json!("sha256:0000000000000000"),
        ),
    ];

    for (field, replacement) in mutations {
        let mut forged = original.clone();
        forged["value"]["lease"][field] = replacement;
        fs::write(
            &path,
            serde_json::to_vec_pretty(&forged).expect("forged lease JSON"),
        )
        .expect("write forged lease state");
        assert!(
            manager.load_for_handle(&session.handle).is_err(),
            "field {field} must be authenticated"
        );
    }

    let mut legacy_forgery = original.clone();
    legacy_forgery["value"]["lease"]["workspaceKey"] = serde_json::json!("workspace-forged");
    let legacy_checksum = legacy_lease_integrity(&legacy_forgery["value"]["lease"]);
    legacy_forgery["value"]["lease"]["authenticationTag"] = serde_json::json!(legacy_checksum);
    fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy_forgery).expect("legacy forged lease JSON"),
    )
    .expect("write legacy forged lease state");
    assert!(matches!(
        manager.load_for_handle(&session.handle),
        Err(LeaseError::IntegrityMismatch)
    ));

    fs::write(
        &path,
        serde_json::to_vec_pretty(&original).expect("original lease JSON"),
    )
    .expect("restore lease state");
    assert!(manager.load_for_handle(&session.handle).is_ok());
}

#[test]
fn unauthenticated_manager_cannot_read_or_mutate_session_state() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let unauthenticated = SessionManager::new(temp.path());
    assert!(matches!(
        unauthenticated.list(),
        Err(LeaseError::SessionAuthorityUnavailable)
    ));
    assert!(matches!(
        unauthenticated.load_for_handle(&session.handle),
        Err(LeaseError::SessionAuthorityUnavailable)
    ));
    assert!(matches!(
        unauthenticated.heartbeat(&session.handle, &session.lease.revision, 1_002),
        Err(LeaseError::SessionAuthorityUnavailable)
    ));
}

struct NeverMatches;

impl ProcessInspector for NeverMatches {
    fn matches(&self, _evidence: &ProcessEvidence) -> bool {
        false
    }
}

struct AlwaysMatches;

impl ProcessInspector for AlwaysMatches {
    fn matches(&self, _evidence: &ProcessEvidence) -> bool {
        true
    }
}

#[test]
fn stale_heartbeat_and_process_identity_expire_only_target_lease() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let stale = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let live = establish(
        &manager,
        request("workspace-b", "connection-b", profile('b')),
        1_020,
        "owner-b",
    );

    let expired = manager
        .expire_stale(1_101, 100, &NeverMatches)
        .expect("expire stale leases");
    assert_eq!(expired, vec![stale.lease.lease.session_id.clone()]);
    assert!(matches!(
        manager.load_for_handle(&stale.handle),
        Err(LeaseError::SessionNotFound)
    ));
    assert!(manager.load_for_handle(&live.handle).is_ok());
}

#[test]
fn hard_expiry_is_reapable_even_when_process_still_matches() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let mut expiring = request("workspace-a", "connection-a", profile('a'));
    expiring.lease_expires_at_unix = 1_100;
    let session = establish(&manager, expiring, 1_000, "owner-a");

    assert_eq!(
        manager
            .expire_stale(1_100, 10_000, &AlwaysMatches)
            .expect("reap hard-expired lease"),
        vec![session.lease.lease.session_id]
    );
    assert!(manager.list().expect("post-expiry sessions").is_empty());
}

#[test]
fn gateway_off_reaps_crashed_launcher_lease_and_authenticated_overlay() {
    let temp = TempDir::new();
    let sessions = authenticated_manager(temp.path());
    let modes = GatewayModeManager::new(temp.path(), sessions.clone());
    let target = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
        .expect("mode target");
    modes
        .install(target.clone(), "mode-control", 990)
        .expect("install gateway");
    modes
        .activate(target.clone(), "mode-control", 995)
        .expect("activate gateway");

    let mut stale_request = request("workspace-a", "connection-a", profile('a'));
    stale_request.process = process(std::process::id(), "ps:not-the-current-start-marker");
    let stale = establish(&sessions, stale_request, 1_000, "owner-a");
    let overlay = get_session_overlay_root(temp.path(), &stale.lease.lease.session_id);
    fs::create_dir_all(&overlay).expect("create managed overlay");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [
            temp.path().join("runtime"),
            temp.path().join("runtime/overlays"),
            overlay.clone(),
        ] {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private overlay path");
        }
    }
    let marker = overlay.join(SESSION_OVERLAY_MARKER);
    fs::write(
        &marker,
        serde_json::json!({
            "version": 1,
            "sessionId": stale.lease.lease.session_id,
        })
        .to_string(),
    )
    .expect("write overlay marker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("private overlay marker");
    }

    let off = modes
        .turn_off(target, ForceMode::No, "mode-control", 1_032)
        .expect("stale launcher does not block gateway off");
    assert_eq!(off.mode.routing, GatewayRoutingState::Off);
    assert!(off.draining_sessions.is_empty());
    assert!(!overlay.exists());
    assert!(matches!(
        sessions.load_for_handle(&stale.handle),
        Err(LeaseError::SessionNotFound)
    ));
}

#[test]
fn call_admission_tokens_are_single_use_and_cannot_under_count_drain() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let first = manager
        .admit_call(&session.handle, &session.lease.revision, 1_010)
        .expect("first admission");
    let after_first = manager
        .load_for_handle(&session.handle)
        .expect("after first admission");
    let second = manager
        .admit_call(&session.handle, &after_first.revision, 1_011)
        .expect("second admission");
    let after_second = manager
        .load_for_handle(&session.handle)
        .expect("after second admission");
    assert_eq!(after_second.lease.in_flight_calls, 2);

    let after_finish = manager
        .finish_call(
            &session.handle,
            &after_second.revision,
            first.clone(),
            1_012,
        )
        .expect("finish first call");
    assert_eq!(after_finish.lease.in_flight_calls, 1);
    assert!(matches!(
        manager.finish_call(&session.handle, &after_finish.revision, first, 1_013,),
        Err(LeaseError::InvalidCallAdmission)
    ));
    let still_draining = manager
        .load_for_handle(&session.handle)
        .expect("replayed finish preserved count");
    assert_eq!(still_draining.lease.in_flight_calls, 1);
    let drained = manager
        .finish_call(&session.handle, &still_draining.revision, second, 1_014)
        .expect("finish second call");
    assert_eq!(drained.lease.in_flight_calls, 0);
}

#[test]
fn stale_reaper_abandons_phantom_in_flight_calls_after_owner_death() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let session = establish(
        &manager,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let admitted = manager
        .admit_call(&session.handle, &session.lease.revision, 1_010)
        .expect("admit call before owner death");
    assert_eq!(admitted.exposure_revision(), digest('e'));

    assert_eq!(
        manager
            .expire_stale(1_110, 100, &NeverMatches)
            .expect("dead owner abandons phantom in-flight call"),
        vec![session.lease.lease.session_id]
    );
    assert!(manager.list().expect("post-reap leases").is_empty());

    let authority = manager
        .prepare_bootstrap(request("workspace-b", "connection-b", profile('b')), 1_111)
        .expect("new session writes remain available");
    manager
        .cancel_bootstrap(&authority)
        .expect("cancel proof bootstrap");
}

#[test]
fn stale_unconsumed_bootstrap_is_removed_without_touching_live_session() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let live = establish(
        &manager,
        request("workspace-live", "connection-live", profile('b')),
        1_000,
        "owner-live",
    );
    let stale = manager
        .prepare_bootstrap(
            request("workspace-stale", "connection-stale", profile('a')),
            1_000,
        )
        .expect("prepare stale bootstrap");
    assert!(get_session_lease_path(temp.path(), stale.session_id()).exists());

    manager
        .expire_stale(1_301, 100, &AlwaysMatches)
        .expect("reap stale bootstrap");
    assert!(!get_session_lease_path(temp.path(), stale.session_id()).exists());
    assert!(manager.load_for_handle(&live.handle).is_ok());
}

#[test]
fn parallel_process_sessions_for_separate_worktrees_are_isolated() {
    let temp = TempDir::new();
    let manager = authenticated_manager(temp.path());
    let executable = env::current_exe().expect("session test executable");
    let release = temp.path().join("release-workers");
    let mut workers = Vec::new();

    for (index, workspace, profile_character) in [(0, "workspace-a", 'a'), (1, "workspace-b", 'b')]
    {
        let result_path = temp.path().join(format!("worker-{index}.json"));
        let owner = format!("process-owner-{index}");
        let connection = format!("process-connection-{index}");
        let mut child = Command::new(&executable)
            .args([
                "--exact",
                "session_process_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("UNPIN_SESSION_TEST_ROOT", temp.path())
            .env("UNPIN_SESSION_TEST_WORKSPACE", workspace)
            .env("UNPIN_SESSION_TEST_OWNER", &owner)
            .env("UNPIN_SESSION_TEST_CONNECTION", &connection)
            .env("UNPIN_SESSION_TEST_RESULT", &result_path)
            .env("UNPIN_SESSION_TEST_RELEASE", &release)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn session worker");
        let evidence = capture_process_evidence(child.id()).expect("worker process evidence");
        let mut bootstrap_request = request(workspace, &connection, profile(profile_character));
        bootstrap_request.process = evidence;
        let authority = manager
            .prepare_bootstrap(bootstrap_request, 1_000)
            .expect("prepare worker bootstrap");
        let mut raw = Vec::new();
        authority.write_secret(&mut raw).expect("authority bytes");
        let mut child_stdin = child.stdin.take().expect("worker stdin");
        writeln!(child_stdin, "{}", authority.session_id()).expect("deliver session id");
        child_stdin
            .write_all(&raw)
            .expect("deliver authority through stdin");
        drop(child_stdin);
        workers.push((child, result_path, authority.session_id().to_string()));
    }

    for (_, result_path, _) in &workers {
        assert!(
            wait_for_path(result_path, Duration::from_secs(10)),
            "worker did not establish lease"
        );
    }
    let leases = manager.list().expect("list concurrent leases");
    assert_eq!(leases.len(), 2);
    assert_eq!(
        leases
            .iter()
            .map(|lease| lease.lease.workspace_key.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["workspace-a", "workspace-b"])
    );
    assert_ne!(
        leases[0].lease.desired_exposure.profile,
        leases[1].lease.desired_exposure.profile
    );

    fs::write(&release, b"release").expect("release workers");
    for (child, _, _) in &mut workers {
        assert!(child.wait().expect("worker exit").success());
    }
    assert!(
        manager
            .list()
            .expect("leases cleaned after exit")
            .is_empty()
    );
}

#[test]
#[ignore = "subprocess helper"]
fn session_process_worker() {
    let Ok(root) = env::var("UNPIN_SESSION_TEST_ROOT") else {
        return;
    };
    let workspace = env::var("UNPIN_SESSION_TEST_WORKSPACE").expect("worker workspace");
    let owner = env::var("UNPIN_SESSION_TEST_OWNER").expect("worker owner");
    let connection = env::var("UNPIN_SESSION_TEST_CONNECTION").expect("worker connection scope");
    let result_path =
        PathBuf::from(env::var_os("UNPIN_SESSION_TEST_RESULT").expect("worker result path"));
    let release_path =
        PathBuf::from(env::var_os("UNPIN_SESSION_TEST_RELEASE").expect("worker release path"));
    let mut transport = String::new();
    std::io::stdin()
        .read_to_string(&mut transport)
        .expect("read bootstrap transport");
    let (session_id, secret) = transport
        .split_once('\n')
        .expect("session id and authority transport");
    let authority = BootstrapAuthority::read_secret(session_id.to_string(), Cursor::new(secret))
        .expect("read authority from stdin");
    let evidence = capture_process_evidence(std::process::id()).expect("own process evidence");
    let claimed = authenticated_manager(Path::new(&root))
        .claim_bootstrap(
            &authority,
            &ConnectionClaim {
                connection_owner_id: owner,
                provider: ProviderId::Codex,
                repository_key: "repository-key".to_string(),
                workspace_key: workspace.clone(),
                process: evidence,
                connection_scope_id: connection,
            },
            1_001,
        )
        .expect("claim process session");
    fs::write(
        &result_path,
        serde_json::to_vec(&serde_json::json!({
            "sessionId": claimed.lease.lease.session_id,
            "workspaceKey": claimed.lease.lease.workspace_key,
            "profile": claimed.lease.lease.desired_exposure.profile,
        }))
        .expect("worker result JSON"),
    )
    .expect("write worker result");
    assert!(
        wait_for_path(&release_path, Duration::from_secs(10)),
        "worker release timeout"
    );
    authenticated_manager(Path::new(&root))
        .close_owned(
            &claimed.handle,
            &claimed.lease.revision,
            "worker-exit",
            1_002,
        )
        .expect("close worker lease");
}

#[test]
fn mode_off_blocks_active_leases_and_force_drains_before_detach() {
    let temp = TempDir::new();
    let sessions = authenticated_manager(temp.path());
    let modes = GatewayModeManager::new(temp.path(), sessions.clone());
    let target = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
        .expect("mode target");
    let installed = modes
        .install(target.clone(), "mode-control", 990)
        .expect("install");
    assert_eq!(installed.mode.installation, GatewayInstallState::Installed);
    assert!(!installed.mode.admission_open);
    let active = modes
        .activate(target.clone(), "mode-control", 995)
        .expect("activate");
    assert_eq!(active.mode.routing, GatewayRoutingState::Active);
    assert!(active.mode.admission_open);

    let session = establish(
        &sessions,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let admitted = sessions
        .admit_call(&session.handle, &session.lease.revision, 1_010)
        .expect("admit in-flight call");
    assert!(matches!(
        modes.turn_off(target.clone(), ForceMode::No, "mode-control", 1_011),
        Err(LeaseError::ActiveLeases { .. })
    ));
    let draining = modes
        .turn_off(target.clone(), ForceMode::Yes, "mode-control", 1_011)
        .expect("begin forced off");
    assert_eq!(draining.mode.routing, GatewayRoutingState::Active);
    assert!(!draining.mode.admission_open);
    assert_eq!(
        draining.draining_sessions,
        vec![session.lease.lease.session_id.clone()]
    );
    let revoked = sessions
        .load_for_handle(&session.handle)
        .expect("load revoked lease");
    assert_eq!(revoked.lease.lifecycle, LeaseLifecycle::Revoking);
    assert!(matches!(
        sessions.admit_call(&session.handle, &revoked.revision, 1_012),
        Err(LeaseError::AdmissionClosed)
    ));
    let fenced_request = request("workspace-b", "connection-b", profile('b'));
    let fenced_claim = claim_for(&fenced_request, "owner-b");
    let fenced_authority = sessions
        .prepare_bootstrap(fenced_request, 1_012)
        .expect("prepare while force-off drains");
    assert!(matches!(
        sessions.claim_bootstrap(&fenced_authority, &fenced_claim, 1_013),
        Err(LeaseError::GatewayAdmissionClosed)
    ));

    let drained = sessions
        .finish_call(&session.handle, &revoked.revision, admitted, 1_013)
        .expect("finish admitted call");
    assert_eq!(drained.lease.in_flight_calls, 0);
    let off = modes
        .turn_off(target.clone(), ForceMode::Yes, "mode-control", 1_014)
        .expect("finish forced off");
    assert_eq!(off.mode.routing, GatewayRoutingState::Off);
    assert!(!off.mode.admission_open);
    assert!(off.draining_sessions.is_empty());
    assert!(sessions.list().expect("list sessions").is_empty());

    let detached = modes
        .detach(target, ForceMode::No, "mode-control", 1_015)
        .expect("detach");
    assert_eq!(detached.mode.installation, GatewayInstallState::Detached);
    assert_eq!(detached.mode.routing, GatewayRoutingState::Off);
}

#[test]
fn heartbeat_after_force_off_rebases_onto_revoking_revision() {
    let temp = TempDir::new();
    let sessions = authenticated_manager(temp.path());
    let modes = GatewayModeManager::new(temp.path(), sessions.clone());
    let target = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
        .expect("mode target");
    modes
        .install(target.clone(), "mode-control", 990)
        .expect("install gateway");
    modes
        .activate(target.clone(), "mode-control", 995)
        .expect("activate gateway");
    let session = establish(
        &sessions,
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    sessions
        .admit_call(&session.handle, &session.lease.revision, 1_010)
        .expect("keep force-off draining");
    let before_revoke = sessions
        .load_for_handle(&session.handle)
        .expect("heartbeat revision");

    let off = modes
        .turn_off(target, ForceMode::Yes, "mode-control", 1_011)
        .expect("force off");
    assert_eq!(
        off.draining_sessions,
        vec![session.lease.lease.session_id.clone()]
    );
    let heartbeat = sessions
        .heartbeat(&session.handle, &before_revoke.revision, 1_011)
        .expect("heartbeat observes force-off revocation without stale revision");
    assert_eq!(heartbeat.lease.lifecycle, LeaseLifecycle::Revoking);
    assert_eq!(
        heartbeat.lease.closed_reason.as_deref(),
        Some("gateway-force-off")
    );
    assert_ne!(heartbeat.revision, before_revoke.revision);
}

#[test]
fn heartbeat_and_force_off_revoke_share_registry_serialization() {
    for _ in 0..16 {
        let temp = TempDir::new();
        let sessions = Arc::new(authenticated_manager(temp.path()));
        let modes = GatewayModeManager::new(temp.path(), sessions.as_ref().clone());
        let target = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
            .expect("mode target");
        modes
            .install(target.clone(), "mode-control", 990)
            .expect("install gateway");
        modes
            .activate(target.clone(), "mode-control", 995)
            .expect("activate gateway");
        let session = establish(
            sessions.as_ref(),
            request("workspace-a", "connection-a", profile('a')),
            1_000,
            "owner-a",
        );
        sessions
            .admit_call(&session.handle, &session.lease.revision, 1_010)
            .expect("keep force-off draining");
        let current = sessions
            .load_for_handle(&session.handle)
            .expect("heartbeat revision");
        let barrier = Arc::new(Barrier::new(3));

        let heartbeat_sessions = Arc::clone(&sessions);
        let heartbeat_barrier = Arc::clone(&barrier);
        let heartbeat_handle = session.handle;
        let heartbeat_revision = current.revision;
        let heartbeat = thread::spawn(move || {
            heartbeat_barrier.wait();
            heartbeat_sessions.heartbeat(&heartbeat_handle, &heartbeat_revision, 1_011)
        });
        let off_barrier = Arc::clone(&barrier);
        let off = thread::spawn(move || {
            off_barrier.wait();
            modes.turn_off(target, ForceMode::Yes, "mode-control", 1_011)
        });
        barrier.wait();

        let heartbeat_result = heartbeat.join().expect("heartbeat thread");
        let off_result = off.join().expect("force-off thread");
        assert!(
            off_result.is_ok(),
            "force-off must not surface stale revision"
        );
        assert!(
            !matches!(
                heartbeat_result,
                Err(LeaseError::State(StateError::StaleRevision { .. }))
            ),
            "heartbeat must serialize with force-off"
        );
    }
}

#[test]
fn concurrent_detach_and_activation_never_orphan_an_active_lease() {
    for _ in 0..16 {
        let temp = TempDir::new();
        let sessions = authenticated_manager(temp.path());
        let modes = GatewayModeManager::new(temp.path(), sessions.clone());
        let target = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
            .expect("mode target");
        modes
            .install(target.clone(), "mode-control", 990)
            .expect("install gateway");
        let request = request("workspace-a", "connection-a", profile('a'));
        let claim = claim_for(&request, "owner-a");
        let authority = sessions
            .prepare_bootstrap(request, 1_000)
            .expect("prepare bootstrap");
        let barrier = Arc::new(Barrier::new(3));

        let detach_modes = modes.clone();
        let detach_target = target.clone();
        let detach_barrier = Arc::clone(&barrier);
        let detach_thread = thread::spawn(move || {
            detach_barrier.wait();
            detach_modes.detach(detach_target, ForceMode::No, "detach-control", 1_001)
        });

        let activate_modes = modes.clone();
        let activate_sessions = sessions.clone();
        let activate_target = target.clone();
        let activate_barrier = Arc::clone(&barrier);
        let activate_thread = thread::spawn(move || {
            activate_barrier.wait();
            activate_modes
                .activate(activate_target, "activate-control", 1_001)
                .and_then(|_| activate_sessions.claim_bootstrap(&authority, &claim, 1_002))
        });

        barrier.wait();
        let detach_result = detach_thread.join().expect("detach thread");
        let claim_result = activate_thread.join().expect("activate thread");
        let mode = modes.load(&target).expect("load mode").expect("mode state");
        let leases = sessions.list().expect("list leases");
        assert!(
            mode.mode.installation != GatewayInstallState::Detached || leases.is_empty(),
            "detached gateway must never retain active lease"
        );

        if let Ok(claimed) = claim_result {
            assert!(matches!(
                detach_result,
                Err(LeaseError::ActiveLeases { .. })
            ));
            sessions
                .close_owned(
                    &claimed.handle,
                    &claimed.lease.revision,
                    "test-complete",
                    1_003,
                )
                .expect("close raced lease");
        }
    }
}

#[test]
fn workspace_mode_override_reopens_only_matching_worktree_after_repository_off() {
    let temp = TempDir::new();
    let sessions = authenticated_manager(temp.path());
    let modes = GatewayModeManager::new(temp.path(), sessions.clone());
    let repository = GatewayModeTarget::repository_provider("repository-key", ProviderId::Codex)
        .expect("repository target");
    modes
        .install(repository, "mode-control", 900)
        .expect("repository gateway installed off");
    let workspace =
        GatewayModeTarget::workspace_provider("repository-key", "workspace-a", ProviderId::Codex)
            .expect("workspace target");
    modes
        .install(workspace.clone(), "mode-control", 901)
        .expect("workspace install");
    modes
        .activate(workspace, "mode-control", 902)
        .expect("workspace activate");

    let allowed_request = request("workspace-a", "connection-a", profile('a'));
    let allowed_claim = claim_for(&allowed_request, "owner-a");
    let allowed_authority = sessions
        .prepare_bootstrap(allowed_request, 1_000)
        .expect("allowed bootstrap");
    let allowed = sessions
        .claim_bootstrap(&allowed_authority, &allowed_claim, 1_001)
        .expect("workspace override admits matching worktree");

    let blocked_request = request("workspace-b", "connection-b", profile('b'));
    let blocked_claim = claim_for(&blocked_request, "owner-b");
    let blocked_authority = sessions
        .prepare_bootstrap(blocked_request, 1_000)
        .expect("blocked bootstrap proposal");
    assert!(matches!(
        sessions.claim_bootstrap(&blocked_authority, &blocked_claim, 1_001),
        Err(LeaseError::GatewayAdmissionClosed)
    ));
    sessions
        .cancel_bootstrap(&blocked_authority)
        .expect("cancel blocked bootstrap");
    let native_request = request("workspace-b", "connection-native", PinnedProfile::Native);
    let native_claim = claim_for(&native_request, "owner-native");
    let native_authority = sessions
        .prepare_bootstrap(native_request, 1_000)
        .expect("native bootstrap proposal");
    let native = sessions
        .claim_bootstrap(&native_authority, &native_claim, 1_001)
        .expect("native session bypasses gateway admission state");
    sessions
        .close_owned(
            &allowed.handle,
            &allowed.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close allowed lease");
    sessions
        .close_owned(
            &native.handle,
            &native.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close native lease");
}

#[test]
fn active_lease_conflict_checker_blocks_overlapping_native_transition() {
    let temp = TempDir::new();
    let sessions = Arc::new(authenticated_manager(temp.path()));
    let session = establish(
        sessions.as_ref(),
        request("workspace-a", "connection-a", profile('a')),
        1_000,
        "owner-a",
    );
    let overlapping = transition_plan("provider-global-config");
    let conflict = match TransitionConflictChecker::acquire(sessions.as_ref(), &overlapping) {
        Err(conflict) => conflict,
        Ok(_) => panic!("overlapping native transition must block"),
    };
    assert_eq!(conflict.code(), "active-lease-provider-global-config");

    let forged_same_session = transition_plan_with_context(
        "provider-global-config",
        Some(session.lease.lease.session_id.clone()),
        Some(digest('a')),
    );
    let forged_conflict =
        match TransitionConflictChecker::acquire(sessions.as_ref(), &forged_same_session) {
            Err(conflict) => conflict,
            Ok(_) => panic!("public lease context must not bypass active-session guard"),
        };
    assert_eq!(
        forged_conflict.code(),
        "active-lease-provider-global-config"
    );

    let unrelated = transition_plan("other-provider-config");
    let guard = TransitionConflictChecker::acquire(sessions.as_ref(), &unrelated)
        .expect("unrelated transition guard");
    drop(guard);
    assert!(sessions.load_for_handle(&session.handle).is_ok());
}

#[test]
fn transition_admission_fences_only_matching_resources_and_blocks_claim_races() {
    let temp = TempDir::new();
    let sessions = Arc::new(authenticated_manager(temp.path()));
    let guarded = transition_plan("resource-a");
    let guard = TransitionConflictChecker::acquire(sessions.as_ref(), &guarded)
        .expect("acquire resource A transition guard");

    let (unrelated_tx, unrelated_rx) = mpsc::channel();
    let unrelated_sessions = Arc::clone(&sessions);
    let unrelated_thread = thread::spawn(move || {
        let unrelated = transition_plan("resource-b");
        let acquired = TransitionConflictChecker::acquire(unrelated_sessions.as_ref(), &unrelated)
            .map(drop)
            .is_ok();
        unrelated_tx
            .send(acquired)
            .expect("report unrelated acquisition");
    });
    assert!(
        unrelated_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("unrelated transition must not wait")
    );
    unrelated_thread.join().expect("unrelated guard thread");

    let mut matching_request = request("workspace-a", "connection-a", profile('a'));
    matching_request.protected_resources = BTreeSet::from(["resource-a".to_string()]);
    let matching_claim = claim_for(&matching_request, "owner-a");
    let authority = sessions
        .prepare_bootstrap(matching_request, 1_000)
        .expect("prepare matching bootstrap");
    let (claim_tx, claim_rx) = mpsc::channel();
    let claim_sessions = Arc::clone(&sessions);
    let claim_thread = thread::spawn(move || {
        let result = claim_sessions
            .claim_bootstrap(&authority, &matching_claim, 1_001)
            .map_err(|error| error.to_string());
        claim_tx.send(result).expect("report matching claim");
    });
    assert!(matches!(
        claim_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    drop(guard);
    let claimed = claim_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("matching claim resumes after transition")
        .expect("matching claim succeeds after transition");
    claim_thread.join().expect("matching claim thread");
    sessions
        .close_owned(
            &claimed.handle,
            &claimed.lease.revision,
            "test-complete",
            1_002,
        )
        .expect("close claimed session");
}

fn transition_plan(resource_id: &str) -> TransitionPlan {
    transition_plan_with_context(resource_id, None, Some(digest('f')))
}

fn transition_plan_with_context(
    resource_id: &str,
    session_id: Option<String>,
    profile_digest: Option<String>,
) -> TransitionPlan {
    TransitionPlan::new(
        format!("operation-{resource_id}"),
        TransitionKind::ApplyProfile,
        TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-b".to_string(),
            session_id,
            profile_digest,
        },
        vec![TransitionEffect {
            effect_id: "effect-one".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: resource_id.to_string(),
            target_type: "file".to_string(),
            summary: "replace provider configuration".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::ReloadRequired,
            expected_pre_fingerprint: Some(digest('1')),
            expected_post_fingerprint: Some(digest('2')),
            provider_views: vec![ProviderId::Codex],
        }],
    )
    .expect("transition plan")
}

#[test]
fn state_errors_remain_structured_through_session_manager() {
    let temp = TempDir::new();
    let sessions_path = temp.path().join("runtime/sessions");
    fs::create_dir_all(sessions_path.parent().expect("sessions parent")).expect("runtime root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            sessions_path.parent().expect("sessions parent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private runtime root");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(temp.path(), &sessions_path).expect("symlink sessions root");

    #[cfg(unix)]
    assert!(matches!(
        authenticated_manager(temp.path()).list(),
        Err(LeaseError::State(StateError::SymlinkRejected { .. }))
    ));
}
