use std::collections::{BTreeMap, BTreeSet};

use tempfile::TempDir;
use unpin_core::{
    approval::ApprovalError,
    catalog::CapabilityId,
    control_operation::DurableControlError,
    profiles::{
        CapabilityLockChange, CapabilityLockSnapshot, CapabilityLockState, GatewaySelection,
        PolicyChange, PolicyControlError, PolicyTarget, ProfilePolicyController,
        policy_resource_id,
    },
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
    transitions::{TransitionJournalStore, TransitionLifecycle},
};

mod support;
use support::{control_authorization, control_context};

fn controller() -> (TempDir, ProfilePolicyController) {
    let temp = TempDir::new().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    (
        temp,
        ProfilePolicyController::with_session_authority_key(root, authority_key()),
    )
}

fn authority_key() -> SessionAuthorityKey {
    SessionAuthorityKey::new([0x53; 32])
}

#[test]
fn capability_lock_policy_is_global_provider_specific_durable_and_replay_safe() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let capability_id = CapabilityId::new("skill.review").unwrap();
    let change = PolicyChange {
        capability_lock: Some(CapabilityLockChange {
            capability_id: capability_id.clone(),
            state: Some(CapabilityLockState::HardDisabled),
        }),
        ..PolicyChange::default()
    };

    assert!(matches!(
        controller.plan(
            PolicyTarget::repository("repository").unwrap(),
            Some(ProviderId::Codex),
            change.clone(),
        ),
        Err(PolicyControlError::CapabilityLocksRequireGlobalTarget)
    ));
    assert!(matches!(
        controller.plan(PolicyTarget::Global, None, change.clone()),
        Err(PolicyControlError::CapabilityLocksRequireProvider)
    ));

    let plan = controller
        .plan(
            PolicyTarget::Global,
            Some(ProviderId::Codex),
            change.clone(),
        )
        .unwrap();
    assert!(!plan.no_op);
    assert_eq!(
        plan.resulting_policy.providers[&ProviderId::Codex].capability_locks[&capability_id],
        CapabilityLockState::HardDisabled
    );
    let sessions = SessionManager::with_authority_key(&root, authority_key());
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "workspace-a".to_string(),
        workspace_revision: None,
        exposure: PinnedExposure {
            revision: "e".repeat(64),
            profile: PinnedProfile::Native,
            capability_locks: Some(Box::new(CapabilityLockSnapshot::empty(ProviderId::Codex))),
        },
        process: ProcessEvidence {
            pid: 42,
            start_marker: "capability-lock-active-session".to_string(),
        },
        connection_scope_id: "capability-lock-active-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([policy_resource_id(&PolicyTarget::Global).unwrap()]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "capability-lock-active-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let bootstrap = sessions.prepare_bootstrap(request, 1_000).unwrap();
    let active_session = sessions.claim_bootstrap(&bootstrap, &claim, 1_001).unwrap();
    let authorization = control_authorization(
        &root,
        &plan.approval_expectation(&approval_context).unwrap(),
        "capability-lock-apply",
        1_000,
    );
    let applied = controller
        .apply(
            &plan,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    assert_eq!(
        applied.status,
        unpin_core::profiles::PolicyApplyStatus::Applied
    );
    assert!(
        sessions
            .load_for_handle(&active_session.handle)
            .unwrap()
            .lease
            .desired_exposure
            .capability_locks
            .as_ref()
            .unwrap()
            .entries
            .is_empty(),
        "active session must retain its previously pinned lock revision"
    );

    let replay = controller
        .plan(PolicyTarget::Global, Some(ProviderId::Codex), change)
        .unwrap();
    assert!(replay.no_op);
    assert_eq!(replay.expected_revision, applied.revision);
}

#[test]
fn signed_control_authorization_cannot_cross_workspace_context() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let reviewed_context = control_context("repository", "workspace-a");
    let wrong_context = control_context("repository", "workspace-b");
    let plan = controller
        .plan(
            PolicyTarget::workspace("repository", "workspace-a").unwrap(),
            Some(ProviderId::Codex),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &plan.approval_expectation(&reviewed_context).unwrap(),
        "wrong-workspace",
        1_000,
    );

    assert!(matches!(
        controller.apply(&plan, authorization, &wrong_context, "policy-control-test"),
        Err(PolicyControlError::Approval(ApprovalError::BindingMismatch))
    ));
    assert!(
        !controller
            .plan(
                PolicyTarget::workspace("repository", "workspace-a").unwrap(),
                Some(ProviderId::Codex),
                PolicyChange {
                    profile: None,
                    gateway: Some(GatewaySelection::Gateway),
                    capability_lock: None,
                },
            )
            .unwrap()
            .no_op
    );
}

#[test]
fn policy_apply_without_session_authority_fails_before_journal() {
    let temp = TempDir::new().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let controller = ProfilePolicyController::new(&root);
    let approval_context = control_context("repository", "workspace-a");
    let plan = controller
        .plan(
            PolicyTarget::workspace("repository", "workspace-a").unwrap(),
            Some(ProviderId::Codex),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &plan.approval_expectation(&approval_context).unwrap(),
        "policy-no-session-authority",
        1_000,
    );

    assert!(matches!(
        controller.apply(
            &plan,
            authorization,
            &approval_context,
            "policy-control-test"
        ),
        Err(PolicyControlError::SessionAuthorityRequired)
    ));
    assert!(
        TransitionJournalStore::new(&root)
            .list()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn policy_plan_is_stable_apply_is_cas_bound_and_replay_is_noop() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = PolicyTarget::workspace("repository", "workspace-a").unwrap();
    let change = PolicyChange {
        profile: None,
        gateway: Some(GatewaySelection::Gateway),
        capability_lock: None,
    };
    let plan = controller
        .plan(target.clone(), Some(ProviderId::Codex), change.clone())
        .unwrap();
    assert!(!plan.no_op);
    plan.verify().unwrap();
    let authorization = control_authorization(
        &root,
        &plan.approval_expectation(&approval_context).unwrap(),
        "policy-apply",
        1_000,
    );
    let applied = controller
        .apply(
            &plan,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    assert_eq!(
        applied.status,
        unpin_core::profiles::PolicyApplyStatus::Applied
    );
    let journals = TransitionJournalStore::new(&root).list().unwrap();
    assert!(journals.iter().any(|journal| {
        journal.operation_kind == "apply-profile"
            && journal.lifecycle == TransitionLifecycle::Committed
            && journal.authorization_decision_digest.is_some()
    }));

    let exact_retry_authorization = control_authorization(
        &root,
        &plan.approval_expectation(&approval_context).unwrap(),
        "policy-apply",
        1_000,
    );
    let exact_retry = controller
        .apply(
            &plan,
            exact_retry_authorization,
            &approval_context,
            "policy-control-test",
        )
        .expect("exact applied retry");
    assert_eq!(exact_retry, applied);
    assert_eq!(
        controller
            .plan(target.clone(), Some(ProviderId::Codex), change.clone())
            .unwrap()
            .expected_revision,
        applied.revision
    );

    let replay = controller
        .plan(target, Some(ProviderId::Codex), change)
        .unwrap();
    assert!(replay.no_op);
    let authorization = control_authorization(
        &root,
        &replay.approval_expectation(&approval_context).unwrap(),
        "policy-noop",
        1_001,
    );
    let no_op = controller
        .apply(
            &replay,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    assert_eq!(no_op.status, unpin_core::profiles::PolicyApplyStatus::NoOp);
    let exact_no_op_authorization = control_authorization(
        &root,
        &replay.approval_expectation(&approval_context).unwrap(),
        "policy-noop",
        1_001,
    );
    assert_eq!(
        controller
            .apply(
                &replay,
                exact_no_op_authorization,
                &approval_context,
                "policy-control-test",
            )
            .expect("exact no-op retry"),
        no_op
    );
}

#[test]
fn cached_noop_policy_replay_requires_matching_live_post_state() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = PolicyTarget::workspace("repository", "workspace-a").unwrap();
    let gateway_change = PolicyChange {
        profile: None,
        gateway: Some(GatewaySelection::Gateway),
        capability_lock: None,
    };
    let applied = controller
        .plan(
            target.clone(),
            Some(ProviderId::Codex),
            gateway_change.clone(),
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &applied.approval_expectation(&approval_context).unwrap(),
        "policy-noop-seed",
        1_000,
    );
    controller
        .apply(
            &applied,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    let no_op = controller
        .plan(target.clone(), Some(ProviderId::Codex), gateway_change)
        .unwrap();
    assert!(no_op.no_op);
    let no_op_expectation = no_op.approval_expectation(&approval_context).unwrap();
    let authorization =
        control_authorization(&root, &no_op_expectation, "policy-noop-cache", 1_001);
    controller
        .apply(
            &no_op,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    let native = controller
        .plan(
            target,
            Some(ProviderId::Codex),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Native),
                capability_lock: None,
            },
        )
        .unwrap();
    let authorization = control_authorization(
        &root,
        &native.approval_expectation(&approval_context).unwrap(),
        "policy-noop-diverge",
        1_002,
    );
    controller
        .apply(
            &native,
            authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();
    let retry_authorization =
        control_authorization(&root, &no_op_expectation, "policy-noop-cache", 1_001);

    assert!(matches!(
        controller.apply(
            &no_op,
            retry_authorization,
            &approval_context,
            "policy-control-test",
        ),
        Err(PolicyControlError::Durable(
            DurableControlError::RecoveryRequired(_)
        ))
    ));
}

#[test]
fn policy_apply_honors_active_session_conflict_guard_before_journal() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = PolicyTarget::workspace("repository", "workspace-a").unwrap();
    let plan = controller
        .plan(
            target.clone(),
            Some(ProviderId::Codex),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    let expectation = plan.approval_expectation(&approval_context).unwrap();
    let protected_resource = expectation.resources[0].resource_id.clone();
    let sessions = SessionManager::with_authority_key(&root, authority_key());
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "workspace-a".to_string(),
        workspace_revision: Some("1".repeat(64)),
        exposure: PinnedExposure {
            revision: "e".repeat(64),
            profile: PinnedProfile::Native,
            capability_locks: None,
        },
        process: ProcessEvidence {
            pid: 42,
            start_marker: "policy-conflict-test".to_string(),
        },
        connection_scope_id: "policy-conflict-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([protected_resource]),
        lease_expires_at_unix: 10_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "policy-conflict-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = sessions.prepare_bootstrap(request, 1_000).unwrap();
    sessions.claim_bootstrap(&authority, &claim, 1_001).unwrap();
    let authorization =
        control_authorization(&root, &expectation, "policy-session-conflict", 1_002);

    assert!(matches!(
        controller.apply(
            &plan,
            authorization,
            &approval_context,
            "policy-control-test",
        ),
        Err(PolicyControlError::TransitionConflict(_))
    ));
    assert!(
        TransitionJournalStore::new(&root)
            .list()
            .unwrap()
            .is_empty()
    );
    assert!(
        !controller
            .plan(
                target,
                Some(ProviderId::Codex),
                PolicyChange {
                    profile: None,
                    gateway: Some(GatewaySelection::Gateway),
                    capability_lock: None,
                },
            )
            .unwrap()
            .no_op
    );
}

#[test]
fn stale_reviewed_plan_cannot_overwrite_newer_provider_policy() {
    let (temp, controller) = controller();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let approval_context = control_context("repository", "workspace-a");
    let target = PolicyTarget::repository("repository").unwrap();
    let stale = controller
        .plan(
            target.clone(),
            Some(ProviderId::Codex),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    let other = controller
        .plan(
            target,
            Some(ProviderId::Claude),
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    let other_authorization = control_authorization(
        &root,
        &other.approval_expectation(&approval_context).unwrap(),
        "policy-other",
        1_000,
    );
    controller
        .apply(
            &other,
            other_authorization,
            &approval_context,
            "policy-control-test",
        )
        .unwrap();

    let stale_authorization = control_authorization(
        &root,
        &stale.approval_expectation(&approval_context).unwrap(),
        "policy-stale",
        1_001,
    );

    assert!(matches!(
        controller.apply(
            &stale,
            stale_authorization,
            &approval_context,
            "policy-control-test"
        ),
        Err(PolicyControlError::PlanFingerprintMismatch)
    ));
}

#[test]
fn generic_policy_change_remains_distinct_from_provider_override() {
    let (_temp, controller) = controller();
    let target = PolicyTarget::Global;
    let plan = controller
        .plan(
            target,
            None,
            PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            },
        )
        .unwrap();
    assert_eq!(plan.resulting_policy.gateway, GatewaySelection::Gateway);
    assert_eq!(plan.resulting_policy.providers, BTreeMap::new());
}
