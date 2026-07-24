use std::collections::BTreeSet;

use tempfile::TempDir;
use unpin_core::{
    mutation::BackupAuthenticationKey,
    profiles::{PolicyControlError, PolicyStore, PolicyTarget, ScopePolicy},
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, GatewayModeAction,
        GatewayModeApplyStatus, GatewayModeControlError, GatewayModeController, GatewayModeManager,
        GatewayModeTarget, GatewayRoutingState, GatewayWorkflowController, GatewayWorkflowError,
        IsolationLevel, PinnedExposure, PinnedProfile, ProcessEvidence, SessionAuthorityKey,
        SessionManager, gateway_mode_resource_id,
    },
    state::atomic_json::{OwnerGeneration, StateError},
    transitions::{TransitionJournalStore, TransitionLifecycle},
};

mod support;
use support::{control_authorization, control_context};

fn controller() -> (TempDir, GatewayWorkflowController) {
    let temp = TempDir::new().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    (
        temp,
        GatewayWorkflowController::with_authority_keys(
            root,
            authority_key(),
            backup_authentication_key(),
        ),
    )
}

fn authority_key() -> SessionAuthorityKey {
    SessionAuthorityKey::new([0x53; 32])
}

fn backup_authentication_key() -> BackupAuthenticationKey {
    BackupAuthenticationKey::new([0x42; 32])
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

#[test]
fn gateway_lifecycle_requires_reviewed_fingerprint_and_reports_noop() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target =
        GatewayModeTarget::workspace_provider("repository", "workspace-a", ProviderId::Codex)
            .unwrap();
    let install = controller
        .plan(
            target.clone(),
            PolicyTarget::workspace("repository", "workspace-a").unwrap(),
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    install.verify().unwrap();
    let install_expectation = install.approval_expectation(&approval_context).unwrap();
    let authorization = control_authorization(&root, &install_expectation, "mode-install", 1_000);
    let applied = controller
        .apply(
            &install,
            authorization,
            &approval_context,
            "mode-test",
            1_000,
        )
        .unwrap();
    assert_eq!(applied.mode.status, GatewayModeApplyStatus::Applied);
    assert!(
        !root
            .join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &install.plan_fingerprint[..32]
            ))
            .is_file()
    );
    let replay_authorization =
        control_authorization(&root, &install_expectation, "mode-install", 1_000);
    let replayed = controller
        .apply(
            &install,
            replay_authorization,
            &approval_context,
            "mode-test",
            1_000,
        )
        .unwrap();
    assert_eq!(replayed, applied);
    assert!(
        !root
            .join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &install.plan_fingerprint[..32]
            ))
            .is_file()
    );
    let journals = TransitionJournalStore::new(&root).list().unwrap();
    assert!(journals.iter().any(|journal| {
        journal.operation_kind == "gateway-workflow"
            && journal.lifecycle == TransitionLifecycle::Committed
            && journal.effects.len() == 1
    }));
    let no_op = controller
        .plan(
            target,
            PolicyTarget::workspace("repository", "workspace-a").unwrap(),
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    assert!(no_op.mode.no_op);
    let authorization = control_authorization(
        &root,
        &no_op.approval_expectation(&approval_context).unwrap(),
        "mode-noop",
        1_001,
    );
    let result = controller
        .apply(&no_op, authorization, &approval_context, "mode-test", 1_001)
        .unwrap();
    assert_eq!(result.mode.status, GatewayModeApplyStatus::NoOp);
    assert!(
        !root
            .join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &no_op.plan_fingerprint[..32]
            ))
            .is_file()
    );
}

#[test]
fn gateway_cached_replay_requires_matching_live_policy_post_state() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target =
        GatewayModeTarget::workspace_provider("repository", "workspace-a", ProviderId::Codex)
            .unwrap();
    let policy_target = PolicyTarget::workspace("repository", "workspace-a").unwrap();
    let install = controller
        .plan(
            target.clone(),
            policy_target.clone(),
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    let install_authorization = control_authorization(
        &root,
        &install.approval_expectation(&approval_context).unwrap(),
        "cached-policy-install",
        1_000,
    );
    controller
        .apply(
            &install,
            install_authorization,
            &approval_context,
            "mode-test",
            1_000,
        )
        .unwrap();
    let activate = controller
        .plan(
            target,
            policy_target.clone(),
            Some(ProviderId::Codex),
            GatewayModeAction::Activate,
            false,
        )
        .unwrap();
    let expectation = activate.approval_expectation(&approval_context).unwrap();
    let authorization = control_authorization(&root, &expectation, "cached-policy-activate", 1_001);
    controller
        .apply(
            &activate,
            authorization,
            &approval_context,
            "mode-test",
            1_001,
        )
        .unwrap();

    let policy_store = PolicyStore::new(&root);
    let snapshot = policy_store
        .load(&policy_target)
        .unwrap()
        .expect("activated policy");
    policy_store
        .save(
            &policy_target,
            &ScopePolicy::default(),
            Some(&snapshot.revision),
            OwnerGeneration::new("cached-policy-divergence", 2).unwrap(),
        )
        .unwrap();
    let retry_authorization =
        control_authorization(&root, &expectation, "cached-policy-activate", 1_001);

    assert!(matches!(
        controller.apply(
            &activate,
            retry_authorization,
            &approval_context,
            "mode-test",
            1_001,
        ),
        Err(GatewayWorkflowError::RecoveryRequired {
            phase: "cached-post-state-diverged",
            ..
        })
    ));
}

#[test]
fn gateway_apply_without_backup_authentication_fails_before_first_effect() {
    let (temp, _) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let controller = GatewayWorkflowController::with_authority_key(&root, authority_key());
    let approval_context = control_context("repository", "workspace-a");
    let target = GatewayModeTarget::global_provider(ProviderId::Codex);
    let install = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &install.approval_expectation(&approval_context).unwrap(),
        "mode-install-no-backup-key",
        1_000,
    );

    assert!(matches!(
        controller.apply(
            &install,
            authorization,
            &approval_context,
            "mode-test",
            1_000,
        ),
        Err(GatewayWorkflowError::BackupAuthenticationRequired)
    ));
    assert_eq!(
        GatewayModeController::with_authority_key(&root, authority_key())
            .status(&target)
            .unwrap(),
        None
    );
    assert!(
        TransitionJournalStore::new(&root)
            .list()
            .unwrap()
            .is_empty()
    );
    assert!(!root.join("transactions").join("checkpoints").exists());
}

#[test]
fn gateway_workflow_apply_honors_active_session_conflict_guard_before_journal() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target =
        GatewayModeTarget::workspace_provider("repository", "workspace-a", ProviderId::Codex)
            .unwrap();
    let install = controller
        .plan(
            target.clone(),
            PolicyTarget::workspace("repository", "workspace-a").unwrap(),
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    let expectation = install.approval_expectation(&approval_context).unwrap();
    let protected_resource = expectation.resources[0].resource_id.clone();
    let sessions = SessionManager::with_authority_key(&root, authority_key());
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "workspace-a".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: PinnedExposure {
            revision: digest('e'),
            profile: PinnedProfile::Native,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: 42,
            start_marker: "gateway-conflict-test".to_string(),
        },
        connection_scope_id: "gateway-conflict-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([protected_resource]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "gateway-conflict-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = sessions.prepare_bootstrap(request, 1_000).unwrap();
    sessions.claim_bootstrap(&authority, &claim, 1_001).unwrap();
    let authorization =
        control_authorization(&root, &expectation, "gateway-session-conflict", 1_002);

    assert!(matches!(
        controller.apply(
            &install,
            authorization,
            &approval_context,
            "mode-test",
            1_002,
        ),
        Err(GatewayWorkflowError::Blocked(reason))
            if reason.contains("active session conflict: active-lease-")
    ));
    assert_eq!(
        GatewayModeController::with_authority_key(&root, authority_key())
            .status(&target)
            .unwrap(),
        None
    );
    assert!(
        TransitionJournalStore::new(&root)
            .list()
            .unwrap()
            .is_empty()
    );
    assert!(!root.join("transactions").join("checkpoints").exists());
}

#[test]
fn stale_gateway_plan_cannot_overwrite_newer_lifecycle() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = GatewayModeTarget::global_provider(ProviderId::Claude);
    let install = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Claude),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &install.approval_expectation(&approval_context).unwrap(),
        "mode-global-install",
        1_000,
    );
    controller
        .apply(
            &install,
            authorization,
            &approval_context,
            "mode-test",
            1_000,
        )
        .unwrap();
    let stale_off = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Claude),
            GatewayModeAction::Off,
            false,
        )
        .unwrap();
    let activate = controller
        .plan(
            target,
            PolicyTarget::Global,
            Some(ProviderId::Claude),
            GatewayModeAction::Activate,
            false,
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &activate.approval_expectation(&approval_context).unwrap(),
        "mode-global-activate",
        1_001,
    );
    controller
        .apply(
            &activate,
            authorization,
            &approval_context,
            "mode-test",
            1_001,
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &stale_off.approval_expectation(&approval_context).unwrap(),
        "mode-global-stale",
        1_002,
    );
    assert!(matches!(
        controller.apply(
            &stale_off,
            authorization,
            &approval_context,
            "mode-test",
            1_002,
        ),
        Err(GatewayWorkflowError::Mode(
            GatewayModeControlError::PlanFingerprintMismatch
        )) | Err(GatewayWorkflowError::Policy(
            PolicyControlError::PlanFingerprintMismatch
        )) | Err(GatewayWorkflowError::PlanFingerprintMismatch)
    ));
}

#[test]
fn policy_failure_restores_gateway_mode_and_rolls_back_workflow() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = GatewayModeTarget::global_provider(ProviderId::Codex);
    let install = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            GatewayModeAction::Install,
            false,
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &install.approval_expectation(&approval_context).unwrap(),
        "mode-install-before-policy-failure",
        1_000,
    );
    controller
        .apply(
            &install,
            authorization,
            &approval_context,
            "mode-test",
            1_000,
        )
        .unwrap();

    PolicyStore::new(&root)
        .save(
            &PolicyTarget::Global,
            &ScopePolicy::default(),
            None,
            OwnerGeneration::new("policy-test", u64::MAX - 1).unwrap(),
        )
        .unwrap();
    let before = GatewayModeController::with_authority_key(&root, authority_key())
        .status(&target)
        .unwrap()
        .unwrap();
    let activate = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            GatewayModeAction::Activate,
            false,
        )
        .unwrap();
    let expectation = activate.approval_expectation(&approval_context).unwrap();
    let operation_id = expectation.operation_id.clone();
    let authorization =
        control_authorization(&root, &expectation, "mode-activate-policy-failure", 1_001);

    let result = controller.apply(
        &activate,
        authorization,
        &approval_context,
        "mode-test",
        1_001,
    );
    assert!(
        matches!(
            &result,
            Err(GatewayWorkflowError::Policy(PolicyControlError::State(
                StateError::InvalidOwnerGeneration
            )))
        ),
        "{result:?}"
    );
    assert_eq!(
        GatewayModeController::with_authority_key(&root, authority_key())
            .status(&target)
            .unwrap(),
        Some(before)
    );
    let journal = TransitionJournalStore::new(&root)
        .list()
        .unwrap()
        .into_iter()
        .find(|journal| journal.operation_id == operation_id)
        .unwrap();
    assert_eq!(journal.lifecycle, TransitionLifecycle::RolledBack);
    assert!(
        !root
            .join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &activate.plan_fingerprint[..32]
            ))
            .is_file()
    );
}

#[test]
fn mode_failure_restores_policy_and_rolls_back_workflow() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = GatewayModeTarget::global_provider(ProviderId::Codex);
    let sessions = SessionManager::with_authority_key(&root, authority_key());
    let modes = GatewayModeManager::new(&root, sessions);
    modes.install(target.clone(), "mode-seed", 1_000).unwrap();
    modes.activate(target.clone(), "mode-seed", 1_001).unwrap();
    assert!(
        PolicyStore::new(&root)
            .load(&PolicyTarget::Global)
            .unwrap()
            .is_none()
    );
    let mode_before = GatewayModeController::with_authority_key(&root, authority_key())
        .status(&target)
        .unwrap();
    let off = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            GatewayModeAction::Off,
            false,
        )
        .unwrap();
    let expectation = off.approval_expectation(&approval_context).unwrap();
    let operation_id = expectation.operation_id.clone();
    let authorization = control_authorization(&root, &expectation, "mode-off-invalid-actor", 1_002);

    let result = controller.apply(
        &off,
        authorization,
        &approval_context,
        "invalid\nactor",
        1_002,
    );
    assert!(matches!(result, Err(GatewayWorkflowError::Mode(_))));
    assert_eq!(
        PolicyStore::new(&root).load(&PolicyTarget::Global).unwrap(),
        None
    );
    assert_eq!(
        GatewayModeController::with_authority_key(&root, authority_key())
            .status(&target)
            .unwrap(),
        mode_before
    );
    let journal = TransitionJournalStore::new(&root)
        .list()
        .unwrap()
        .into_iter()
        .find(|journal| journal.operation_id == operation_id)
        .unwrap();
    assert_eq!(journal.lifecycle, TransitionLifecycle::RolledBack);
}

#[test]
fn force_off_with_draining_session_resumes_same_reviewed_plan() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = GatewayModeTarget::global_provider(ProviderId::Codex);
    for (action, now_unix) in [
        (GatewayModeAction::Install, 1_000),
        (GatewayModeAction::Activate, 1_001),
    ] {
        let plan = controller
            .plan(
                target.clone(),
                PolicyTarget::Global,
                Some(ProviderId::Codex),
                action,
                false,
            )
            .unwrap();
        let authorization = control_authorization(
            &root,
            &plan.approval_expectation(&approval_context).unwrap(),
            &format!("drain-{action:?}"),
            now_unix,
        );
        controller
            .apply(
                &plan,
                authorization,
                &approval_context,
                "mode-test",
                now_unix,
            )
            .unwrap();
    }
    let sessions = SessionManager::with_authority_key(&root, authority_key());
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "workspace-a".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: PinnedExposure {
            revision: digest('e'),
            profile: PinnedProfile::None,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: 41,
            start_marker: "mode-control-test".to_string(),
        },
        connection_scope_id: "connection-a".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([gateway_mode_resource_id(&target).unwrap()]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "owner-a".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = sessions.prepare_bootstrap(request, 1_002).unwrap();
    let session = sessions.claim_bootstrap(&authority, &claim, 1_003).unwrap();
    let admitted = sessions
        .admit_call(&session.handle, &session.lease.revision, 1_004)
        .unwrap();
    let off = controller
        .plan(
            target.clone(),
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            GatewayModeAction::Off,
            true,
        )
        .unwrap();
    let expectation = off.approval_expectation(&approval_context).unwrap();
    let operation_id = expectation.operation_id.clone();
    let authorization =
        control_authorization(&root, &expectation, "mode-force-off-draining", 1_005);

    assert!(matches!(
        controller.apply(&off, authorization, &approval_context, "mode-test", 1_005,),
        Err(GatewayWorkflowError::Draining { .. })
    ));
    let mode = GatewayModeController::with_authority_key(&root, authority_key())
        .status(&target)
        .unwrap()
        .unwrap();
    assert_eq!(mode.routing, GatewayRoutingState::Active);
    assert!(!mode.admission_open);
    let journal = TransitionJournalStore::new(&root)
        .list()
        .unwrap()
        .into_iter()
        .find(|journal| journal.operation_id == operation_id)
        .unwrap();
    assert_eq!(journal.lifecycle, TransitionLifecycle::Applying);
    assert!(
        root.join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &off.plan_fingerprint[..32]
            ))
            .is_file()
    );

    let revoked = sessions.load_for_handle(&session.handle).unwrap();
    sessions
        .finish_call(&session.handle, &revoked.revision, admitted, 1_006)
        .unwrap();
    assert_eq!(
        controller
            .pending_plan(&off.plan_fingerprint)
            .unwrap()
            .as_ref(),
        Some(&off)
    );
    let retry_authorization =
        control_authorization(&root, &expectation, "mode-force-off-draining", 1_005);
    let applied = controller
        .apply(
            &off,
            retry_authorization,
            &approval_context,
            "mode-test",
            1_007,
        )
        .expect("resume forced off after calls drain");
    assert_eq!(
        applied.mode.mode.as_ref().map(|mode| mode.routing),
        Some(GatewayRoutingState::Off)
    );
    let journal = TransitionJournalStore::new(&root)
        .list()
        .unwrap()
        .into_iter()
        .find(|journal| journal.operation_id == operation_id)
        .unwrap();
    assert_eq!(journal.lifecycle, TransitionLifecycle::Committed);
    assert!(
        !root
            .join("transactions")
            .join("checkpoints")
            .join(format!(
                "gateway-workflow-{}.json",
                &off.plan_fingerprint[..32]
            ))
            .exists()
    );
}
