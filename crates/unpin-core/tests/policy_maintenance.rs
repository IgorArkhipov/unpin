use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use tempfile::TempDir;
use unpin_core::{
    mutation::BackupAuthenticationKey,
    profiles::{
        GatewaySelection, PolicyMaintenanceAction, PolicyMaintenanceApproval,
        PolicyMaintenanceController, PolicyMaintenanceError, PolicyMaintenanceLifecycle,
        PolicyStore, PolicyTarget, ScopePolicy, WorkspacePolicyClassification,
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

fn fixture_root(temp: &TempDir) -> PathBuf {
    fs::canonicalize(temp.path()).expect("canonical tempdir")
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
    let outcome = controller
        .apply(&plan, &approval(&plan.plan_fingerprint), owner(1))
        .expect("migration apply");

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
    controller
        .apply(&restore, &approval(&restore.plan_fingerprint), owner(2))
        .expect("restore apply");
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

    let error = controller
        .apply(&plan, &approval(&plan.plan_fingerprint), owner(1))
        .expect_err("source drift");
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
    original_controller
        .apply(&migration, &approval(&migration.plan_fingerprint), owner(1))
        .expect("migration");

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
    moved_controller
        .apply(&reattach, &approval(&reattach.plan_fingerprint), owner(2))
        .expect("reattach");
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
    original_controller
        .apply(&migration, &approval(&migration.plan_fingerprint), owner(1))
        .expect("migration");
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
    controller
        .apply(&discard, &approval(&discard.plan_fingerprint), owner(2))
        .expect("discard");
    let discarded = controller
        .status(&target, None)
        .expect("discarded status")
        .expect("discarded record");
    assert_eq!(discarded.lifecycle, PolicyMaintenanceLifecycle::Discarded);
    assert!(discarded.allowed_actions.contains(&"cleanup".to_string()));

    let cleanup = controller
        .plan_cleanup(target.clone())
        .expect("cleanup plan");
    controller
        .apply(&cleanup, &approval(&cleanup.plan_fingerprint), owner(3))
        .expect("cleanup");
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
    let controller = controller(&app_state, &repository);
    let migration = controller.plan_migration().expect("migration plan");
    let target = migration_target(&migration);
    controller
        .apply(&migration, &approval(&migration.plan_fingerprint), owner(1))
        .expect("migration");
    let status = controller
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
    let error = controller
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
    let protected = controller
        .protect_policy_change(
            &target,
            "profile-change",
            &reviewed_fingerprint,
            &approval(&reviewed_fingerprint),
            owner(2),
            || {
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
    controller
        .apply(&restore, &approval(&restore.plan_fingerprint), owner(3))
        .expect("restore");
    assert_eq!(
        policies
            .load(&target)
            .expect("load restored policy")
            .expect("restored policy")
            .policy,
        original
    );
}
