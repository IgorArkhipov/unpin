use std::{
    cell::Cell,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims,
        ApprovalResourceBinding, ApprovalVerifier, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
        ControlOperationKind, authorize_control,
    },
    mutation::BackupAuthenticationKey,
    profiles::{
        GatewaySelection, PolicyMaintenanceAction, PolicyMaintenanceApproval,
        PolicyMaintenanceController, PolicyMaintenanceError, PolicyMaintenanceLifecycle,
        PolicyStore, PolicyTarget, ProtectedPolicyChangeError, PublicPolicyMaintenanceAction,
        ScopePolicy, UnmanagedPolicyStatus, WorkspacePolicyClassification, policy_resource_id,
    },
    state::atomic_json::OwnerGeneration,
};

fn init_repository(path: &Path) {
    fs::create_dir_all(path).expect("repository directory");
    let output = Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(path)
        .output()
        .expect("git init");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_legacy_policy(repository: &Path, policy: &ScopePolicy) -> PathBuf {
    let directory = repository.join(".unpin");
    fs::create_dir_all(&directory).expect("legacy policy directory");
    let path = directory.join("policy.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(policy).expect("serialize policy"),
    )
    .expect("write legacy policy");
    path
}

fn owner(generation: u64) -> OwnerGeneration {
    OwnerGeneration::new("policy-maintenance-test", generation).expect("owner")
}

fn fresh_owner(operation: &str) -> OwnerGeneration {
    OwnerGeneration::new(format!("policy-maintenance-{operation}"), 1).expect("fresh owner")
}

fn fixture_root(temp: &TempDir) -> PathBuf {
    fs::canonicalize(temp.path()).expect("canonical tempdir")
}

fn only_policy_backup_id(app_state_root: &Path) -> String {
    fs::read_dir(app_state_root.join("backups").join("policies"))
        .expect("backup directory")
        .map(|entry| entry.expect("backup entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .and_then(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
        })
        .expect("policy backup")
}

fn approval(plan_fingerprint: &str) -> PolicyMaintenanceApproval {
    PolicyMaintenanceApproval {
        confirmed: true,
        plan_fingerprint: plan_fingerprint.to_string(),
        actor_id: "fixture-reviewer".to_string(),
        reviewed_at_unix: 1_785_370_000,
        decision_digest: "ab".repeat(32),
    }
}

fn external_authorization(
    app_state_root: &Path,
    target: &PolicyTarget,
    reviewed_plan_fingerprint: &str,
    marker: u64,
) -> (ControlAuthorization, ApprovalExpectation) {
    let expectation = ApprovalExpectation {
        issuer: CONTROL_APPROVAL_ISSUER.to_string(),
        audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
        operation_id: format!("profile-change-{marker}"),
        operation_kind: ControlOperationKind::ProfilePolicy.as_str().to_string(),
        effect_graph_digest: reviewed_plan_fingerprint.to_string(),
        repository_key: "repository".to_string(),
        workspace_key: "workspace".to_string(),
        session_id: None,
        profile_digest: None,
        resources: vec![ApprovalResourceBinding {
            resource_id: policy_resource_id(target).expect("policy target resource"),
            pre_state_fingerprint: None,
        }],
    };
    let key = ApprovalKey::new([0x6a; 32]);
    let issuer = ApprovalIssuer::new(
        key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer");
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("policy-maintenance-external-receipt-{marker}"),
            nonce: format!("policy-maintenance-external-nonce-{marker}"),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: 1_785_370_000,
            expires_at_unix: 1_785_370_060,
        })
        .expect("approval receipt");
    let authorization = authorize_control(
        app_state_root,
        &receipt,
        &ApprovalVerifier::new(key),
        &expectation,
        1_785_370_000,
        OwnerGeneration::new(format!("policy-maintenance-external-approval-{marker}"), 1)
            .expect("approval owner"),
    )
    .expect("control authorization");
    (authorization, expectation)
}

fn external_approval(
    plan_fingerprint: &str,
    authorization: &ControlAuthorization,
) -> PolicyMaintenanceApproval {
    let mut approval = approval(plan_fingerprint);
    approval.decision_digest = authorization.decision_digest().to_string();
    approval
}

fn authorization(
    app_state_root: &Path,
    plan: &unpin_core::profiles::PolicyMaintenancePlan,
    marker: u64,
) -> (
    ControlAuthorization,
    ControlApprovalContext,
    PolicyMaintenanceApproval,
) {
    let context = ControlApprovalContext::new("repository", "workspace").expect("approval context");
    let expectation = plan
        .approval_expectation(&context)
        .expect("approval expectation");
    let key = ApprovalKey::new([0x6a; 32]);
    let issuer = ApprovalIssuer::new(
        key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer");
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("policy-maintenance-receipt-{marker}"),
            nonce: format!("policy-maintenance-nonce-{marker}"),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: 1_785_370_000,
            expires_at_unix: 1_785_370_060,
        })
        .expect("approval receipt");
    let authorization = authorize_control(
        app_state_root,
        &receipt,
        &ApprovalVerifier::new(key),
        &expectation,
        1_785_370_000,
        OwnerGeneration::new(format!("policy-maintenance-approval-{marker}"), 1)
            .expect("approval owner"),
    )
    .expect("control authorization");
    let mut approval = approval(&plan.plan_fingerprint);
    approval.decision_digest = authorization.decision_digest().to_string();
    (authorization, context, approval)
}

fn apply_reviewed(
    controller: &PolicyMaintenanceController,
    app_state_root: &Path,
    plan: &unpin_core::profiles::PolicyMaintenancePlan,
    generation: u64,
) -> Result<unpin_core::profiles::PolicyMaintenanceOutcome, PolicyMaintenanceError> {
    let (authorization, context, approval) = authorization(app_state_root, plan, generation);
    controller.apply(plan, authorization, &context, &approval, owner(generation))
}

fn apply_reviewed_with_owner(
    controller: &PolicyMaintenanceController,
    app_state_root: &Path,
    plan: &unpin_core::profiles::PolicyMaintenancePlan,
    marker: u64,
    owner: OwnerGeneration,
) -> Result<unpin_core::profiles::PolicyMaintenanceOutcome, PolicyMaintenanceError> {
    let (authorization, context, approval) = authorization(app_state_root, plan, marker);
    controller.apply(plan, authorization, &context, &approval, owner)
}

fn controller(app_state_root: &Path, project_root: &Path) -> PolicyMaintenanceController {
    PolicyMaintenanceController::new(
        app_state_root,
        project_root,
        BackupAuthenticationKey::new([0x5a; 32]),
    )
}

fn migration_target(plan: &unpin_core::profiles::PolicyMaintenancePlan) -> PolicyTarget {
    match &plan.action {
        PolicyMaintenanceAction::Migrate { workspace, .. } => PolicyTarget::workspace(
            workspace.repository_key.clone(),
            workspace.workspace_key.clone(),
        )
        .expect("workspace target"),
        _ => panic!("migration plan"),
    }
}

#[test]
fn fixed_source_migration_is_authenticated_reviewed_and_exactly_restorable() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policy = ScopePolicy::default();
    let source_path = write_legacy_policy(&repository, &policy);
    let controller = controller(&app_state, &repository);

    let plan = controller.plan_migration().expect("migration plan");
    plan.verify().expect("sealed plan");
    let target = migration_target(&plan);
    let outcome = apply_reviewed(&controller, &app_state, &plan, 1).expect("migration apply");

    assert!(
        source_path.exists(),
        "migration must leave the source untouched"
    );
    let stored = PolicyStore::new(&app_state)
        .load(&target)
        .expect("load policy")
        .expect("migrated policy");
    assert_eq!(stored.policy, policy);
    let status = controller
        .status(&target, None)
        .expect("maintenance status")
        .expect("maintenance record");
    assert_eq!(
        status.classification,
        WorkspacePolicyClassification::Attached
    );
    assert_eq!(status.lifecycle, PolicyMaintenanceLifecycle::Active);
    let backup = controller
        .load_backup(&outcome.backup_id)
        .expect("load backup")
        .expect("migration backup");
    assert!(backup.finalized);
    assert_eq!(backup.review.plan_fingerprint, plan.plan_fingerprint);
    assert!(!backup.authentication_tag.is_empty());

    let restore = controller
        .plan_restore(&outcome.backup_id)
        .expect("restore plan");
    apply_reviewed(&controller, &app_state, &restore, 2).expect("restore apply");
    assert!(
        PolicyStore::new(&app_state)
            .load(&target)
            .expect("load restored policy")
            .is_none()
    );
    assert!(
        controller
            .status(&target, None)
            .expect("restored status")
            .is_none()
    );
    assert!(source_path.exists());
}

#[test]
fn sequential_maintenance_operations_accept_fresh_generation_one_owners() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policy = ScopePolicy::default();
    write_legacy_policy(&repository, &policy);
    let initial_controller = controller(&app_state, &repository);

    let migration = initial_controller.plan_migration().expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed_with_owner(
        &initial_controller,
        &app_state,
        &migration,
        60,
        fresh_owner("migration"),
    )
    .expect("migration with fresh owner");
    let moved_aside = root.join("moved-aside");
    fs::rename(&repository, &moved_aside).expect("move repository aside");
    let controller = controller(&app_state, &moved_aside);

    let discard = controller
        .plan_discard(target.clone())
        .expect("discard plan");
    let discarded = apply_reviewed_with_owner(
        &controller,
        &app_state,
        &discard,
        61,
        fresh_owner("discard"),
    )
    .expect("discard with fresh owner");

    let restore = controller
        .plan_restore(&discarded.backup_id)
        .expect("restore plan");
    apply_reviewed_with_owner(
        &controller,
        &app_state,
        &restore,
        62,
        fresh_owner("restore"),
    )
    .expect("restore with fresh owner");

    assert_eq!(
        PolicyStore::new(&app_state)
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        policy
    );
}

#[test]
fn protected_changes_advance_record_owner_from_existing_state() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let controller = controller(&app_state, &repository);

    let migration = controller.plan_migration().expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed_with_owner(
        &controller,
        &app_state,
        &migration,
        63,
        fresh_owner("protected-migration"),
    )
    .expect("migration with fresh owner");

    for (operation_id, fingerprint, marker) in [
        ("protected-owner-first", "51".repeat(32), 64),
        ("protected-owner-second", "52".repeat(32), 65),
    ] {
        let (authorization, expectation) =
            external_authorization(&app_state, &target, &fingerprint, marker);
        controller
            .protect_policy_change(
                &target,
                operation_id,
                &fingerprint,
                &expectation,
                &external_approval(&fingerprint, &authorization),
                authorization,
                fresh_owner(operation_id),
                |_authorization| Ok::<(), ()>(()),
            )
            .expect("protected change with fresh owner");
    }
}

#[test]
fn failed_workspace_protected_change_returns_a_recoverable_restore_handoff() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let original = ScopePolicy::default();
    write_legacy_policy(&repository, &original);
    let controller = controller(&app_state, &repository);

    let migration = controller.plan_migration().expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed_with_owner(
        &controller,
        &app_state,
        &migration,
        66,
        fresh_owner("workspace-recovery-migration"),
    )
    .expect("migration");
    let policies = PolicyStore::new(&app_state);
    let before_change = policies
        .load(&target)
        .expect("load migrated policy")
        .expect("migrated policy");
    let changed = ScopePolicy {
        gateway: GatewaySelection::Gateway,
        ..ScopePolicy::default()
    };
    let fingerprint = "53".repeat(32);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &fingerprint, 67);
    let backup_id = match controller
        .protect_policy_change(
            &target,
            "workspace-protected-change",
            &fingerprint,
            &expectation,
            &external_approval(&fingerprint, &authorization),
            authorization,
            fresh_owner("workspace-protected-change"),
            |_authorization| {
                policies
                    .save(&target, &changed, Some(&before_change.revision), owner(2))
                    .expect("rewrite policy");
                Err::<(), _>("simulated apply failure")
            },
        )
        .expect_err("failed change must preserve a restore backup")
    {
        ProtectedPolicyChangeError::Apply { backup_id, .. } => backup_id,
        other => panic!("expected protected apply failure, got {other:?}"),
    };

    let (retry_authorization, retry_expectation) =
        external_authorization(&app_state, &target, &fingerprint, 68);
    let retry_error = controller
        .protect_policy_change(
            &target,
            "workspace-protected-change",
            &fingerprint,
            &retry_expectation,
            &external_approval(&fingerprint, &retry_authorization),
            retry_authorization,
            fresh_owner("workspace-protected-change-retry"),
            |_authorization| Ok::<(), ()>(()),
        )
        .expect_err("drifted workspace record must require its known recovery backup");
    assert!(matches!(
        retry_error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::RecoveryRequired {
            backup_id: Some(ref actual),
            ..
        }) if actual == &backup_id
    ));

    let restore = controller
        .plan_restore(&backup_id)
        .expect("restore plan for drifted workspace record");
    apply_reviewed_with_owner(
        &controller,
        &app_state,
        &restore,
        69,
        fresh_owner("workspace-protected-restore"),
    )
    .expect("restore drifted workspace record");

    assert_eq!(
        policies
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        original
    );
    assert_eq!(
        controller
            .status(&target, None)
            .expect("restored workspace status")
            .expect("restored workspace record")
            .lifecycle,
        PolicyMaintenanceLifecycle::Active
    );
}

#[test]
fn migration_rejects_source_drift_before_any_private_state_write() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let source = write_legacy_policy(&repository, &ScopePolicy::default());
    let controller = controller(&app_state, &repository);
    let plan = controller.plan_migration().expect("migration plan");
    let target = migration_target(&plan);
    let mut drifted = serde_json::to_vec_pretty(&ScopePolicy::default()).expect("serialize drift");
    drifted.push(b'\n');
    fs::write(source, drifted).expect("write drift");

    let error = apply_reviewed(&controller, &app_state, &plan, 1).expect_err("source drift");
    assert!(matches!(error, PolicyMaintenanceError::PlanDrift));
    assert!(
        PolicyStore::new(&app_state)
            .load(&target)
            .expect("load policy")
            .is_none()
    );
    assert!(!app_state.join("backups").exists());
}

#[test]
fn authorization_binding_mismatch_rejects_before_any_private_state_write() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let controller = controller(&app_state, &repository);
    let plan = controller.plan_migration().expect("migration plan");
    let target = migration_target(&plan);
    let (authorization, _context, approval) = authorization(&app_state, &plan, 1);
    let wrong_context = ControlApprovalContext::new("different-repository", "different-workspace")
        .expect("wrong context");

    let error = controller
        .apply(&plan, authorization, &wrong_context, &approval, owner(1))
        .expect_err("mismatched authorization must fail");

    assert!(matches!(error, PolicyMaintenanceError::ApprovalRejected));
    assert!(
        PolicyStore::new(&app_state)
            .load(&target)
            .expect("load policy")
            .is_none()
    );
    assert!(!app_state.join("backups").exists());
}

#[test]
fn unmanaged_existing_policy_does_not_advertise_migration() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let controller = controller(&app_state, &repository);
    let initial_plan = controller.plan_migration().expect("initial migration plan");
    let target = migration_target(&initial_plan);
    PolicyStore::new(&app_state)
        .save(&target, &ScopePolicy::default(), None, owner(1))
        .expect("seed unmanaged policy");

    assert_eq!(
        controller
            .unmanaged_status(&target)
            .expect("unmanaged status"),
        UnmanagedPolicyStatus::ExistingPolicy
    );
    assert!(matches!(
        controller
            .plan_migration()
            .expect_err("existing destination must not be migrated"),
        PolicyMaintenanceError::DestinationExists
    ));
}

#[test]
fn unmanaged_status_propagates_workspace_errors() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    fs::create_dir_all(&repository).expect("repository directory");
    write_legacy_policy(&repository, &ScopePolicy::default());
    fs::write(repository.join(".git"), "gitdir: missing\n").expect("invalid gitdir marker");

    let error = controller(&app_state, &repository)
        .unmanaged_status(&PolicyTarget::Global)
        .expect_err("workspace failure must remain actionable");

    assert!(matches!(error, PolicyMaintenanceError::Workspace(_)));
}

#[cfg(unix)]
#[test]
fn migration_rejects_symlinked_and_hard_linked_sources() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    for (name, link_source) in [
        ("symlink", root.join("symlink-source.json")),
        ("hard-link", root.join("hard-link-source.json")),
    ] {
        let repository = root.join(name);
        init_repository(&repository);
        fs::write(
            &link_source,
            serde_json::to_vec_pretty(&ScopePolicy::default()).expect("serialize policy"),
        )
        .expect("write link source");
        let policy_path = write_legacy_policy(&repository, &ScopePolicy::default());
        fs::remove_file(&policy_path).expect("remove regular source");
        if name == "symlink" {
            symlink(&link_source, &policy_path).expect("create symlink");
        } else {
            fs::hard_link(&link_source, &policy_path).expect("create hard link");
        }

        let error = controller(&root.join(format!("{name}-state")), &repository)
            .plan_migration()
            .expect_err("linked source must be rejected");
        assert!(matches!(error, PolicyMaintenanceError::InvalidSource));
    }
}

#[test]
fn migration_rejects_oversized_source() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    init_repository(&repository);
    let policy_path = write_legacy_policy(&repository, &ScopePolicy::default());
    fs::write(&policy_path, vec![b' '; 1024 * 1024 + 1]).expect("write oversized source");

    let error = controller(&root.join("state"), &repository)
        .plan_migration()
        .expect_err("oversized source must be rejected");
    assert!(matches!(error, PolicyMaintenanceError::InvalidSource));
}

#[test]
fn moved_workspace_requires_physical_proof_and_reattaches_without_copying_identity() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let original = root.join("original");
    let moved = root.join("moved");
    let unrelated = root.join("unrelated");
    let app_state = root.join("state");
    init_repository(&original);
    write_legacy_policy(&original, &ScopePolicy::default());
    let original_controller = controller(&app_state, &original);
    let migration = original_controller
        .plan_migration()
        .expect("migration plan");
    let original_target = migration_target(&migration);
    apply_reviewed(&original_controller, &app_state, &migration, 1).expect("migration");

    fs::rename(&original, &moved).expect("move repository");
    let moved_controller = controller(&app_state, &moved);
    let moved_status = moved_controller
        .status(&original_target, Some(&moved))
        .expect("moved status")
        .expect("record");
    assert_eq!(
        moved_status.classification,
        WorkspacePolicyClassification::Moved
    );

    init_repository(&unrelated);
    let unrelated_controller = controller(&app_state, &unrelated);
    let unrelated_status = unrelated_controller
        .status(&original_target, Some(&unrelated))
        .expect("unrelated status")
        .expect("record");
    assert_eq!(
        unrelated_status.classification,
        WorkspacePolicyClassification::Unknown
    );
    let error = unrelated_controller
        .plan_reattach(original_target.clone())
        .expect_err("unrelated checkout must not reattach");
    assert!(matches!(error, PolicyMaintenanceError::ReattachNotProven));

    let reattach = moved_controller
        .plan_reattach(original_target.clone())
        .expect("reattach plan");
    let new_target = match &reattach.action {
        PolicyMaintenanceAction::Reattach { to_target, .. } => to_target.clone(),
        _ => panic!("reattach action"),
    };
    apply_reviewed(&moved_controller, &app_state, &reattach, 2).expect("reattach");
    assert!(
        PolicyStore::new(&app_state)
            .load(&original_target)
            .expect("old policy")
            .is_none()
    );
    assert!(
        PolicyStore::new(&app_state)
            .load(&new_target)
            .expect("new policy")
            .is_some()
    );
    assert_eq!(
        moved_controller
            .status(&new_target, None)
            .expect("new status")
            .expect("new record")
            .classification,
        WorkspacePolicyClassification::Attached
    );
}

#[test]
fn workspace_recreated_at_same_path_is_not_treated_as_attached() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let original = root.join("original");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let original_controller = controller(&app_state, &repository);
    let migration = original_controller
        .plan_migration()
        .expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed(&original_controller, &app_state, &migration, 1).expect("migration");

    fs::rename(&repository, &original).expect("move original repository");
    init_repository(&repository);
    let recreated = controller(&app_state, &repository)
        .status(&target, None)
        .expect("recreated status")
        .expect("record");

    assert_eq!(
        recreated.classification,
        WorkspacePolicyClassification::Recreated
    );
    assert!(recreated.allowed_actions.contains(&"discard".to_string()));
}

#[test]
fn deleted_workspace_discard_is_explicit_and_cleanup_never_runs_automatically() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let moved_aside = root.join("moved-aside");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let original_controller = controller(&app_state, &repository);
    let migration = original_controller
        .plan_migration()
        .expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed(&original_controller, &app_state, &migration, 1).expect("migration");
    fs::rename(&repository, &moved_aside).expect("move repository aside");

    let controller = controller(&app_state, &moved_aside);
    let status = controller
        .status(&target, None)
        .expect("orphan status")
        .expect("record");
    assert_eq!(
        status.classification,
        WorkspacePolicyClassification::Deleted
    );
    assert!(status.allowed_actions.contains(&"discard".to_string()));

    let discard = controller
        .plan_discard(target.clone())
        .expect("discard plan");
    apply_reviewed(&controller, &app_state, &discard, 2).expect("discard");
    let discarded = controller
        .status(&target, None)
        .expect("discarded status")
        .expect("discarded record");
    assert_eq!(discarded.lifecycle, PolicyMaintenanceLifecycle::Discarded);
    assert!(discarded.allowed_actions.contains(&"cleanup".to_string()));

    let cleanup = controller
        .plan_cleanup(target.clone())
        .expect("cleanup plan");
    apply_reviewed(&controller, &app_state, &cleanup, 3).expect("cleanup");
    assert!(
        controller
            .status(&target, None)
            .expect("cleaned status")
            .is_none()
    );
}

#[test]
fn authenticated_record_rejects_tampering_and_key_substitution() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let original_controller = controller(&app_state, &repository);
    let migration = original_controller
        .plan_migration()
        .expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed(&original_controller, &app_state, &migration, 1).expect("migration");
    let status = original_controller
        .status(&target, None)
        .expect("status")
        .expect("record");
    let record_path = app_state
        .join("policies")
        .join("maintenance")
        .join("records")
        .join(format!("{}.json", status.record_id));
    let raw = fs::read_to_string(&record_path).expect("record");
    fs::write(&record_path, raw.replace("\"active\"", "\"discarded\"")).expect("tamper record");
    let error = original_controller
        .status(&target, None)
        .expect_err("tampering must fail closed");
    assert!(matches!(
        error,
        PolicyMaintenanceError::AuthenticationFailed | PolicyMaintenanceError::InvalidRecord
    ));

    let wrong_key = PolicyMaintenanceController::new(
        &app_state,
        &repository,
        BackupAuthenticationKey::new([0x33; 32]),
    );
    let error = wrong_key
        .status(&target, None)
        .expect_err("key substitution must fail closed");
    assert!(matches!(
        error,
        PolicyMaintenanceError::AuthenticationFailed | PolicyMaintenanceError::InvalidRecord
    ));
}

#[test]
fn migration_public_view_includes_the_policy_effect() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policy = ScopePolicy {
        gateway: GatewaySelection::Gateway,
        ..ScopePolicy::default()
    };
    write_legacy_policy(&repository, &policy);
    let plan = controller(&app_state, &repository)
        .plan_migration()
        .expect("migration plan");

    let public = plan.public_view().expect("public migration plan");
    let PublicPolicyMaintenanceAction::Migrate { policy: actual, .. } = public.action else {
        panic!("expected migration action");
    };
    assert_eq!(actual, policy);
}

#[test]
fn generic_policy_change_gets_authenticated_prechange_backup_and_reviewed_restore() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policies = PolicyStore::new(&app_state);
    let target = PolicyTarget::Global;
    let original = ScopePolicy::default();
    let original_revision = policies
        .save(&target, &original, None, owner(1))
        .expect("seed global policy");
    let changed = ScopePolicy {
        gateway: GatewaySelection::Gateway,
        ..ScopePolicy::default()
    };
    let reviewed_fingerprint = "cd".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 20);
    let protected = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| {
                policies
                    .save(&target, &changed, Some(&original_revision), owner(2))
                    .map(|_| ())
            },
        )
        .expect("protected policy change");
    assert_eq!(
        policies
            .load(&target)
            .expect("load changed policy")
            .expect("changed policy")
            .policy,
        changed
    );
    let backup = controller
        .load_backup(&protected.backup_id)
        .expect("load backup")
        .expect("change backup");
    assert!(backup.finalized);
    assert_eq!(backup.entries[0].prior_policy.as_ref(), Some(&original));

    let restore = controller
        .plan_restore(&protected.backup_id)
        .expect("restore plan");
    let public = restore.public_view().expect("public restore plan");
    let PublicPolicyMaintenanceAction::Restore { backup_id, targets } = public.action else {
        panic!("expected restore action");
    };
    assert_eq!(backup_id, protected.backup_id);
    assert_eq!(targets, vec![target.clone()]);
    let restore_context =
        ControlApprovalContext::new("repository", "workspace").expect("restore context");
    let restore_expectation = restore
        .approval_expectation(&restore_context)
        .expect("restore approval expectation");
    assert_eq!(restore_expectation.resources.len(), 3);
    assert!(
        restore_expectation
            .resources
            .iter()
            .any(|binding| binding.resource_id == protected.backup_id)
    );
    assert!(
        restore_expectation
            .resources
            .iter()
            .any(|binding| binding.resource_id.ends_with("-policy"))
    );
    assert!(restore_expectation.resources.iter().any(|binding| {
        binding.resource_id != protected.backup_id && !binding.resource_id.ends_with("-policy")
    }));
    apply_reviewed(&controller, &app_state, &restore, 3).expect("restore");
    assert_eq!(
        policies
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        original
    );
}

#[test]
fn failed_protected_change_without_residue_can_be_retried() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let target = PolicyTarget::Global;
    let reviewed_fingerprint = "46".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 45);

    let backup_id = match controller
        .protect_policy_change(
            &target,
            "retryable-profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| Err::<(), _>("simulated apply failure"),
        )
        .expect_err("failed apply must retain its backup")
    {
        ProtectedPolicyChangeError::Apply { backup_id, .. } => backup_id,
        other => panic!("expected protected apply failure, got {other:?}"),
    };
    assert!(
        controller
            .load_backup(&backup_id)
            .expect("load failed backup")
            .expect("failed backup")
            .finalized
    );

    let (retry_authorization, retry_expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 46);
    let called = Cell::new(false);
    let retried = controller
        .protect_policy_change(
            &target,
            "retryable-profile-change",
            &reviewed_fingerprint,
            &retry_expectation,
            &external_approval(&reviewed_fingerprint, &retry_authorization),
            retry_authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), &str>(())
            },
        )
        .expect("retry without observable residue must proceed");

    assert!(called.get());
    assert_eq!(retried.backup_id, backup_id);
    assert!(
        controller
            .load_backup(&retried.backup_id)
            .expect("load retried backup")
            .expect("retried backup")
            .finalized
    );
}

#[test]
fn interrupted_protected_change_without_residue_can_be_retried() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let target = PolicyTarget::Global;
    let reviewed_fingerprint = "47".repeat(32);
    let controller = controller(&app_state, &repository);

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        let (authorization, expectation) =
            external_authorization(&app_state, &target, &reviewed_fingerprint, 47);
        let _ = controller.protect_policy_change(
            &target,
            "interrupted-profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| -> Result<(), ()> { panic!("simulated interruption") },
        );
    }));
    assert!(interrupted.is_err());

    let backup_id = only_policy_backup_id(&app_state);
    assert!(
        !controller
            .load_backup(&backup_id)
            .expect("load interrupted backup")
            .expect("interrupted backup")
            .finalized
    );

    let (retry_authorization, retry_expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 48);
    let retried = controller
        .protect_policy_change(
            &target,
            "interrupted-profile-change",
            &reviewed_fingerprint,
            &retry_expectation,
            &external_approval(&reviewed_fingerprint, &retry_authorization),
            retry_authorization,
            owner(2),
            |_authorization| Ok::<(), ()>(()),
        )
        .expect("interrupted change without residue must retry");

    assert_eq!(retried.backup_id, backup_id);
    assert!(
        controller
            .load_backup(&retried.backup_id)
            .expect("load retried backup")
            .expect("retried backup")
            .finalized
    );
}

#[test]
fn protected_change_rejects_authorization_bound_to_another_operation() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let target = PolicyTarget::Global;
    let reviewed_fingerprint = "ac".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, mut expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 21);
    expectation.operation_id = "profile-policy-other-operation".to_string();
    let called = Cell::new(false);

    let error = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), ()>(())
            },
        )
        .expect_err("foreign authorization must not protect this change");

    assert!(!called.get());
    assert!(matches!(
        error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::ApprovalRejected)
    ));
    assert!(!app_state.join("backups").join("policies").exists());
}

#[test]
fn protected_change_rejects_authorization_bound_to_another_target() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let target = PolicyTarget::Global;
    let other_target =
        PolicyTarget::workspace("other-repository", "other-workspace").expect("other target");
    let reviewed_fingerprint = "ba".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, expectation) =
        external_authorization(&app_state, &other_target, &reviewed_fingerprint, 22);
    let called = Cell::new(false);

    let error = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), ()>(())
            },
        )
        .expect_err("foreign authorization must not protect this target");

    assert!(!called.get());
    assert!(matches!(
        error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::ApprovalRejected)
    ));
    assert!(!app_state.join("backups").join("policies").exists());
}

#[test]
fn recovery_errors_expose_only_valid_redacted_policy_backup_ids() {
    let backup_id = format!("policy-backup-{}", "ab".repeat(16));
    let recovery = PolicyMaintenanceError::RecoveryRequired {
        detail: format!("backup={backup_id}; cause=policy-maintenance-unavailable"),
        backup_id: Some(backup_id.clone()),
    };
    assert_eq!(recovery.recovery_backup_id(), Some(backup_id.as_str()));
    assert_eq!(
        recovery
            .recovery_handoff()
            .expect("validated recovery handoff")
            .restore_command,
        format!("unpin profile policy restore --backup-id {backup_id}")
    );
    assert_eq!(
        PolicyMaintenanceError::RecoveryRequired {
            detail: "backup=unexpected; cause=test".to_string(),
            backup_id: None,
        }
        .recovery_backup_id(),
        None
    );
}

#[test]
fn concurrent_maintenance_apply_keeps_the_completed_backup() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let controller = controller(&app_state, &repository);
    let plan = controller.plan_migration().expect("migration plan");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();

    for marker in [50, 51] {
        let controller = controller.clone();
        let app_state = app_state.clone();
        let plan = plan.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            apply_reviewed(&controller, &app_state, &plan, marker)
        }));
    }

    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("maintenance worker"))
        .collect::<Vec<_>>();
    let successful = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok())
        .collect::<Vec<_>>();
    assert_eq!(
        successful.len(),
        1,
        "exactly one reviewed apply may proceed"
    );
    assert_eq!(outcomes.len() - successful.len(), 1);

    let backup = controller
        .load_backup(&successful[0].backup_id)
        .expect("load completed backup")
        .expect("completed backup remains available");
    assert!(backup.finalized);
}

#[test]
fn generic_protected_change_rejects_a_decision_digest_not_bound_to_authorization() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policies = PolicyStore::new(&app_state);
    let target = PolicyTarget::Global;
    policies
        .save(&target, &ScopePolicy::default(), None, owner(1))
        .expect("seed global policy");
    let reviewed_fingerprint = "34".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 25);
    let called = Cell::new(false);

    let error = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &expectation,
            &approval(&reviewed_fingerprint),
            authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), ()>(())
            },
        )
        .expect_err("approval must bind the authenticated decision");

    assert!(!called.get());
    assert!(matches!(
        error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::ApprovalRejected)
    ));
    assert!(!app_state.join("backups").join("policies").exists());
}

#[test]
fn protected_change_rejects_inactive_lifecycle_before_callback() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let moved_aside = root.join("moved-aside");
    let app_state = root.join("state");
    init_repository(&repository);
    write_legacy_policy(&repository, &ScopePolicy::default());
    let original_controller = controller(&app_state, &repository);
    let migration = original_controller
        .plan_migration()
        .expect("migration plan");
    let target = migration_target(&migration);
    apply_reviewed(&original_controller, &app_state, &migration, 1).expect("migration");
    fs::rename(&repository, &moved_aside).expect("move repository aside");
    let controller = controller(&app_state, &moved_aside);
    let discard = controller
        .plan_discard(target.clone())
        .expect("discard plan");
    apply_reviewed(&controller, &app_state, &discard, 2).expect("discard");
    let called = Cell::new(false);
    let reviewed_fingerprint = "ef".repeat(32);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 30);

    let error = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(3),
            |_authorization| {
                called.set(true);
                Ok::<(), ()>(())
            },
        )
        .expect_err("inactive lifecycle must fail before callback");

    assert!(!called.get());
    assert!(matches!(
        error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::InvalidLifecycle)
    ));
}

#[test]
fn failed_protected_change_finalizes_backup_for_authenticated_restore() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policies = PolicyStore::new(&app_state);
    let target = PolicyTarget::Global;
    let original = ScopePolicy::default();
    let original_revision = policies
        .save(&target, &original, None, owner(1))
        .expect("seed global policy");
    let changed = ScopePolicy {
        gateway: GatewaySelection::Gateway,
        ..ScopePolicy::default()
    };
    let reviewed_fingerprint = "12".repeat(32);
    let controller = controller(&app_state, &repository);
    let (authorization, expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 40);

    let error = controller
        .protect_policy_change(
            &target,
            "failed-profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| {
                policies
                    .save(&target, &changed, Some(&original_revision), owner(2))
                    .expect("partially apply policy change");
                Err::<(), _>("simulated apply failure")
            },
        )
        .expect_err("failed apply must be reported");
    assert!(matches!(
        error,
        ProtectedPolicyChangeError::Apply {
            error: "simulated apply failure",
            backup_id: _,
        }
    ));

    let backup_path = fs::read_dir(app_state.join("backups").join("policies"))
        .expect("backup directory")
        .map(|entry| entry.expect("backup entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("failed-change backup");
    let backup_id = backup_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("backup id");
    let backup = controller
        .load_backup(backup_id)
        .expect("load failed-change backup")
        .expect("failed-change backup");
    assert!(backup.finalized);

    let (retry_authorization, retry_expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 41);
    let called = Cell::new(false);
    let retry_error = controller
        .protect_policy_change(
            &target,
            "failed-profile-change",
            &reviewed_fingerprint,
            &retry_expectation,
            &external_approval(&reviewed_fingerprint, &retry_authorization),
            retry_authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), &str>(())
            },
        )
        .expect_err("partial failed change must require recovery before retry");
    assert!(!called.get());
    assert!(matches!(
        retry_error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::RecoveryRequired {
            backup_id: Some(ref actual),
            ..
        }) if actual == backup_id
    ));

    let restore = controller
        .plan_restore(backup_id)
        .expect("authenticated restore plan");
    apply_reviewed(&controller, &app_state, &restore, 3).expect("restore");
    assert_eq!(
        policies
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        original
    );
}

#[test]
fn interrupted_protected_change_with_residue_requires_recovery_and_is_restorable() {
    let temp = TempDir::new().expect("tempdir");
    let root = fixture_root(&temp);
    let repository = root.join("repository");
    let app_state = root.join("state");
    init_repository(&repository);
    let policies = PolicyStore::new(&app_state);
    let target = PolicyTarget::Global;
    let original = ScopePolicy::default();
    let original_revision = policies
        .save(&target, &original, None, owner(1))
        .expect("seed policy");
    let changed = ScopePolicy {
        gateway: GatewaySelection::Gateway,
        ..ScopePolicy::default()
    };
    let reviewed_fingerprint = "48".repeat(32);
    let controller = controller(&app_state, &repository);

    let interrupted = catch_unwind(AssertUnwindSafe(|| {
        let (authorization, expectation) =
            external_authorization(&app_state, &target, &reviewed_fingerprint, 49);
        let _ = controller.protect_policy_change(
            &target,
            "interrupted-partial-profile-change",
            &reviewed_fingerprint,
            &expectation,
            &external_approval(&reviewed_fingerprint, &authorization),
            authorization,
            owner(2),
            |_authorization| -> Result<(), ()> {
                policies
                    .save(&target, &changed, Some(&original_revision), owner(2))
                    .expect("partially apply policy change");
                panic!("simulated interruption");
            },
        );
    }));
    assert!(interrupted.is_err());

    let backup_id = only_policy_backup_id(&app_state);
    assert!(
        !controller
            .load_backup(&backup_id)
            .expect("load interrupted backup")
            .expect("interrupted backup")
            .finalized
    );

    let (retry_authorization, retry_expectation) =
        external_authorization(&app_state, &target, &reviewed_fingerprint, 50);
    let called = Cell::new(false);
    let retry_error = controller
        .protect_policy_change(
            &target,
            "interrupted-partial-profile-change",
            &reviewed_fingerprint,
            &retry_expectation,
            &external_approval(&reviewed_fingerprint, &retry_authorization),
            retry_authorization,
            owner(2),
            |_authorization| {
                called.set(true);
                Ok::<(), ()>(())
            },
        )
        .expect_err("interrupted partial change must require recovery");
    assert!(!called.get());
    assert!(matches!(
        retry_error,
        ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::RecoveryRequired {
            backup_id: Some(ref actual),
            ..
        }) if actual == &backup_id
    ));

    let restore = controller
        .plan_restore(&backup_id)
        .expect("interrupted backup restore plan");
    assert_eq!(
        controller
            .plan_restore(&backup_id)
            .expect("stable interrupted backup restore plan"),
        restore
    );
    apply_reviewed(&controller, &app_state, &restore, 3).expect("restore interrupted change");
    assert_eq!(
        policies
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        original
    );
}
