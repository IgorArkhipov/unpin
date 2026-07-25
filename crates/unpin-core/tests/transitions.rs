use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        ApprovalIssuer, ApprovalKey, ApprovalNonceStore, ApprovalReceipt, ApprovalReceiptClaims,
        ApprovalVerifier,
    },
    config::get_transition_journal_path,
    state::atomic_json::OwnerGeneration,
    transitions::{
        AuthenticatedBackup, BackendFailure, EffectActivation, EffectAuthority,
        EffectCheckpointStatus, TransitionBackend, TransitionConflict, TransitionConflictChecker,
        TransitionConflictGuard, TransitionContext, TransitionCoordinator, TransitionEffect,
        TransitionEffectKind, TransitionJournalStore, TransitionKind, TransitionLifecycle,
        TransitionOutcomeStatus, TransitionPlan,
    },
};

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

#[derive(Default)]
struct MockBackend {
    state: Mutex<BTreeMap<String, Vec<u8>>>,
    desired: BTreeMap<String, Vec<u8>>,
    backups: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    backup_calls: AtomicUsize,
    apply_calls: Mutex<BTreeMap<String, usize>>,
    rollback_calls: Mutex<BTreeMap<String, usize>>,
    fail_apply: Mutex<Option<String>>,
    drift_on_failure: Mutex<Option<(String, Vec<u8>)>>,
    panic_after_apply: Mutex<BTreeSet<String>>,
    panic_after_rollback: Mutex<BTreeSet<String>>,
}

impl MockBackend {
    fn new(initial: [(&str, &[u8]); 2], desired: [(&str, &[u8]); 2]) -> Self {
        Self {
            state: Mutex::new(
                initial
                    .into_iter()
                    .map(|(resource, bytes)| (resource.to_string(), bytes.to_vec()))
                    .collect(),
            ),
            desired: desired
                .into_iter()
                .map(|(effect, bytes)| (effect.to_string(), bytes.to_vec()))
                .collect(),
            ..Self::default()
        }
    }

    fn bytes(&self, resource: &str) -> Vec<u8> {
        self.state.lock().expect("state lock")[resource].clone()
    }

    fn set_bytes(&self, resource: &str, bytes: &[u8]) {
        self.state
            .lock()
            .expect("state lock")
            .insert(resource.to_string(), bytes.to_vec());
    }

    fn fail_on(&self, effect_id: &str) {
        *self.fail_apply.lock().expect("failure lock") = Some(effect_id.to_string());
    }

    fn drift_when_failing(&self, resource: &str, bytes: &[u8]) {
        *self.drift_on_failure.lock().expect("drift lock") =
            Some((resource.to_string(), bytes.to_vec()));
    }

    fn panic_after_apply_once(&self, effect_id: &str) {
        self.panic_after_apply
            .lock()
            .expect("panic lock")
            .insert(effect_id.to_string());
    }

    fn panic_after_rollback_once(&self, effect_id: &str) {
        self.panic_after_rollback
            .lock()
            .expect("panic lock")
            .insert(effect_id.to_string());
    }

    fn apply_count(&self, effect_id: &str) -> usize {
        self.apply_calls
            .lock()
            .expect("apply calls lock")
            .get(effect_id)
            .copied()
            .unwrap_or_default()
    }
}

impl TransitionBackend for MockBackend {
    fn current_fingerprint(
        &self,
        effect: &TransitionEffect,
    ) -> Result<Option<String>, BackendFailure> {
        Ok(self
            .state
            .lock()
            .expect("state lock")
            .get(&effect.resource_id)
            .map(|bytes| fingerprint(bytes)))
    }

    fn backup_transition(
        &self,
        plan: &TransitionPlan,
        backup_id: &str,
    ) -> Result<AuthenticatedBackup, BackendFailure> {
        self.backup_calls.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("state lock");
        let snapshot = plan
            .effects
            .iter()
            .map(|effect| {
                (
                    effect.resource_id.clone(),
                    state[&effect.resource_id].clone(),
                )
            })
            .collect();
        self.backups
            .lock()
            .expect("backups lock")
            .entry(backup_id.to_string())
            .or_insert(snapshot);
        AuthenticatedBackup::new(fingerprint(backup_id.as_bytes()))
            .map_err(|_| failure("backup-evidence"))
    }

    fn apply_effect(&self, effect: &TransitionEffect) -> Result<(), BackendFailure> {
        *self
            .apply_calls
            .lock()
            .expect("apply calls lock")
            .entry(effect.effect_id.clone())
            .or_default() += 1;
        if self.fail_apply.lock().expect("failure lock").as_deref()
            == Some(effect.effect_id.as_str())
        {
            if let Some((resource, bytes)) =
                self.drift_on_failure.lock().expect("drift lock").clone()
            {
                self.set_bytes(&resource, &bytes);
            }
            return Err(failure("injected-apply-failure"));
        }
        let desired = self.desired[&effect.effect_id].clone();
        self.set_bytes(&effect.resource_id, &desired);
        if self
            .panic_after_apply
            .lock()
            .expect("panic lock")
            .remove(&effect.effect_id)
        {
            panic!("injected crash after provider write");
        }
        Ok(())
    }

    fn rollback_effect(
        &self,
        effect: &TransitionEffect,
        backup_id: &str,
    ) -> Result<(), BackendFailure> {
        *self
            .rollback_calls
            .lock()
            .expect("rollback calls lock")
            .entry(effect.effect_id.clone())
            .or_default() += 1;
        let bytes =
            self.backups.lock().expect("backups lock")[backup_id][&effect.resource_id].clone();
        self.set_bytes(&effect.resource_id, &bytes);
        if self
            .panic_after_rollback
            .lock()
            .expect("panic lock")
            .remove(&effect.effect_id)
        {
            panic!("injected crash after rollback write");
        }
        Ok(())
    }
}

fn failure(code: &str) -> BackendFailure {
    BackendFailure::new(code).expect("safe backend code")
}

fn fingerprint(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("transition-test-owner", 1).expect("owner")
}

fn coordinator(root: &Path) -> TransitionCoordinator {
    TransitionCoordinator::new(root, "unpin-cli-human", "unpin-core-transition")
        .expect("coordinator")
}

fn verifier() -> ApprovalVerifier {
    ApprovalVerifier::new(ApprovalKey::new([0x31; 32]))
}

fn plan(operation_id: &str) -> TransitionPlan {
    TransitionPlan::new(
        operation_id,
        TransitionKind::ApplyProfile,
        TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: Some("session-key".to_string()),
            profile_digest: Some("d".repeat(64)),
        },
        vec![
            effect(
                "effect-one",
                "provider-a",
                b"provider-a-old",
                b"provider-a-new",
            ),
            effect(
                "effect-two",
                "provider-b",
                b"provider-b-old",
                b"provider-b-new",
            ),
        ],
    )
    .expect("transition plan")
}

fn effect(
    effect_id: &str,
    resource_id: &str,
    pre_state: &[u8],
    post_state: &[u8],
) -> TransitionEffect {
    TransitionEffect {
        effect_id: effect_id.to_string(),
        kind: TransitionEffectKind::ReplaceProviderConfig,
        resource_id: resource_id.to_string(),
        target_type: "provider-config".to_string(),
        summary: format!("Update {resource_id}"),
        authority: EffectAuthority::UserManaged,
        activation: EffectActivation::ReloadRequired,
        expected_pre_fingerprint: Some(fingerprint(pre_state)),
        expected_post_fingerprint: Some(fingerprint(post_state)),
        provider_views: Vec::new(),
    }
}

fn receipt(plan: &TransitionPlan, nonce: &str) -> ApprovalReceipt {
    ApprovalIssuer::new(
        ApprovalKey::new([0x31; 32]),
        "unpin-cli-human",
        "unpin-core-transition",
    )
    .expect("issuer")
    .issue(ApprovalReceiptClaims {
        version: 1,
        receipt_id: format!("receipt-{}", plan.operation_id),
        nonce: nonce.to_string(),
        issuer: "assigned-by-issuer".to_string(),
        audience: "assigned-by-issuer".to_string(),
        operation_id: plan.operation_id.clone(),
        operation_kind: plan.kind.as_str().to_string(),
        effect_graph_digest: plan.effect_graph_digest.clone(),
        repository_key: plan.context.repository_key.clone(),
        workspace_key: plan.context.workspace_key.clone(),
        session_id: plan.context.session_id.clone(),
        profile_digest: plan.context.profile_digest.clone(),
        resources: plan.resource_bindings(),
        issued_at_unix: 1_000,
        expires_at_unix: 1_100,
    })
    .expect("receipt")
}

fn backend() -> MockBackend {
    MockBackend::new(
        [
            ("provider-a", b"provider-a-old"),
            ("provider-b", b"provider-b-old"),
        ],
        [
            ("effect-one", b"provider-a-new"),
            ("effect-two", b"provider-b-new"),
        ],
    )
}

#[test]
fn second_provider_failure_rolls_first_back_byte_for_byte_with_one_backup_and_audit_chain() {
    let temp = TempDir::new();
    let plan = plan("operation-rollback");
    let receipt = receipt(&plan, "nonce-rollback");
    let backend = backend();
    backend.fail_on("effect-two");

    let outcome = coordinator(temp.path())
        .execute(&plan, Some(&receipt), &verifier(), 1_050, owner(), &backend)
        .expect("rolled-back outcome");

    assert_eq!(outcome.status, TransitionOutcomeStatus::RolledBack);
    assert_eq!(outcome.reason_code.as_deref(), Some("apply-failed"));
    assert_eq!(backend.bytes("provider-a"), b"provider-a-old");
    assert_eq!(backend.bytes("provider-b"), b"provider-b-old");
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 1);

    let handle = TransitionJournalStore::new(temp.path())
        .load(&plan, owner())
        .expect("journal");
    assert_eq!(handle.journal.lifecycle, TransitionLifecycle::RolledBack);
    handle.journal.verify_audit_chain().expect("audit chain");
    assert_eq!(
        handle.journal.effects[0].status,
        EffectCheckpointStatus::RolledBack
    );
}

#[test]
fn external_edit_before_rollback_is_preserved_and_marks_needs_repair() {
    let temp = TempDir::new();
    let plan = plan("operation-rollback-drift");
    let receipt = receipt(&plan, "nonce-rollback-drift");
    let backend = backend();
    backend.fail_on("effect-two");
    backend.drift_when_failing("provider-a", b"external-writer");

    let outcome = coordinator(temp.path())
        .execute(&plan, Some(&receipt), &verifier(), 1_050, owner(), &backend)
        .expect("needs-repair outcome");

    assert_eq!(outcome.status, TransitionOutcomeStatus::NeedsRepair);
    assert_eq!(outcome.reason_code.as_deref(), Some("rollback-state-drift"));
    assert_eq!(backend.bytes("provider-a"), b"external-writer");
    assert_eq!(backend.bytes("provider-b"), b"provider-b-old");
}

#[test]
fn crash_after_provider_write_resumes_same_operation_without_duplicate_backup_or_apply() {
    let temp = TempDir::new();
    let plan = plan("operation-resume-apply");
    let receipt = receipt(&plan, "nonce-resume-apply");
    let backend = backend();
    backend.panic_after_apply_once("effect-one");

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        coordinator(temp.path()).execute(
            &plan,
            Some(&receipt),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
    }));
    assert!(crashed.is_err());
    assert_eq!(backend.bytes("provider-a"), b"provider-a-new");

    let resumed = coordinator(temp.path())
        .execute(
            &plan,
            None,
            &verifier(),
            1_500,
            OwnerGeneration::new("replacement-process", 1).expect("replacement owner"),
            &backend,
        )
        .expect("resumed transition");
    let duplicate = coordinator(temp.path())
        .execute(&plan, None, &verifier(), 2_000, owner(), &backend)
        .expect("terminal retry");

    assert_eq!(resumed.status, TransitionOutcomeStatus::Committed);
    assert_eq!(duplicate, resumed);
    assert_eq!(backend.bytes("provider-a"), b"provider-a-new");
    assert_eq!(backend.bytes("provider-b"), b"provider-b-new");
    assert_eq!(backend.apply_count("effect-one"), 1);
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 1);

    let raw = fs::read_to_string(get_transition_journal_path(temp.path(), &plan.operation_id))
        .expect("journal JSON");
    assert!(!raw.contains("nonce-resume-apply"));
    assert!(!raw.contains(&receipt.tag));
}

#[test]
fn exact_committed_retry_requires_matching_live_post_state() {
    let temp = TempDir::new();
    let plan = plan("operation-terminal-post-state-drift");
    let backend = backend();

    let applied = coordinator(temp.path())
        .execute(
            &plan,
            Some(&receipt(&plan, "nonce-terminal-post-state-drift")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect("committed transition");
    assert_eq!(applied.status, TransitionOutcomeStatus::Committed);

    backend.set_bytes("provider-a", b"external-after-commit");
    let error = coordinator(temp.path())
        .execute(&plan, None, &verifier(), 1_500, owner(), &backend)
        .expect_err("cached terminal replay must verify live post-state");

    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::RecoveryRequired(ref operation_id)
            if operation_id == "operation-terminal-post-state-drift"
    ));
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.apply_count("effect-one"), 1);
}

#[test]
fn different_operation_cannot_cross_orphaned_write_until_original_is_recovered() {
    let temp = TempDir::new();
    let original = plan("operation-orphaned-write");
    let backend = backend();
    backend.panic_after_apply_once("effect-one");

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        coordinator(temp.path()).execute(
            &original,
            Some(&receipt(&original, "nonce-orphaned-write")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
    }));
    assert!(crashed.is_err());
    assert_eq!(backend.bytes("provider-a"), b"provider-a-new");

    let replacement = TransitionPlan::new(
        "operation-crossing-orphan",
        TransitionKind::ApplyProfile,
        original.context.clone(),
        vec![
            effect(
                "replacement-one",
                "provider-a",
                b"provider-a-new",
                b"replacement-a",
            ),
            effect(
                "replacement-two",
                "provider-b",
                b"provider-b-old",
                b"replacement-b",
            ),
        ],
    )
    .expect("replacement plan");
    let error = coordinator(temp.path())
        .execute(
            &replacement,
            Some(&receipt(&replacement, "nonce-crossing-orphan")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect_err("orphaned write must be recovered first");
    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::RecoveryRequired(ref operation_id)
            if operation_id == "operation-orphaned-write"
    ));
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.apply_count("replacement-one"), 0);
    assert_eq!(backend.apply_count("replacement-two"), 0);
}

#[test]
fn crash_after_rollback_write_resumes_idempotently_without_overwrite() {
    let temp = TempDir::new();
    let plan = plan("operation-resume-rollback");
    let receipt = receipt(&plan, "nonce-resume-rollback");
    let backend = backend();
    backend.fail_on("effect-two");
    backend.panic_after_rollback_once("effect-one");

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        coordinator(temp.path()).execute(
            &plan,
            Some(&receipt),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
    }));
    assert!(crashed.is_err());
    assert_eq!(backend.bytes("provider-a"), b"provider-a-old");

    let resumed = coordinator(temp.path())
        .execute(&plan, None, &verifier(), 1_500, owner(), &backend)
        .expect("resumed rollback");
    assert_eq!(resumed.status, TransitionOutcomeStatus::RolledBack);
    assert_eq!(backend.bytes("provider-a"), b"provider-a-old");
    assert_eq!(backend.bytes("provider-b"), b"provider-b-old");
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn pre_state_drift_is_detected_before_backup_and_external_bytes_survive() {
    let temp = TempDir::new();
    let plan = plan("operation-pre-drift");
    let receipt = receipt(&plan, "nonce-pre-drift");
    let backend = backend();
    backend.set_bytes("provider-a", b"external-before-lock");

    let outcome = coordinator(temp.path())
        .execute(&plan, Some(&receipt), &verifier(), 1_050, owner(), &backend)
        .expect("needs-repair outcome");
    assert_eq!(outcome.status, TransitionOutcomeStatus::NeedsRepair);
    assert_eq!(outcome.reason_code.as_deref(), Some("pre-state-drift"));
    assert_eq!(backend.bytes("provider-a"), b"external-before-lock");
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn receiptless_persistent_transition_is_rejected_before_backup_or_write() {
    let temp = TempDir::new();
    let plan = plan("operation-without-approval");
    let backend = backend();

    let error = coordinator(temp.path())
        .execute(&plan, None, &verifier(), 1_050, owner(), &backend)
        .expect_err("generic confirmation cannot authorize a persistent transition");

    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::ApprovalRequired
    ));
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.apply_count("effect-one"), 0);
    assert_eq!(backend.apply_count("effect-two"), 0);
}

#[test]
fn consumed_receipt_can_close_crash_gap_after_expiry_but_cannot_be_reused_elsewhere() {
    let temp = TempDir::new();
    let plan = plan("operation-expired-recovery");
    let receipt = receipt(&plan, "nonce-expired-recovery");
    let verified = verifier()
        .verify(
            &receipt,
            &plan.approval_expectation("unpin-cli-human", "unpin-core-transition"),
            1_050,
        )
        .expect("valid approval before crash");
    ApprovalNonceStore::new(temp.path())
        .consume_or_attach(&verified, 1_050, owner())
        .expect("simulated nonce consumption before crash");

    let outcome = coordinator(temp.path())
        .execute(
            &plan,
            Some(&receipt),
            &verifier(),
            1_500,
            owner(),
            &backend(),
        )
        .expect("expired consumed receipt resumes original operation");
    assert_eq!(outcome.status, TransitionOutcomeStatus::Committed);
}

struct ActiveLeaseConflict;

impl TransitionConflictChecker for ActiveLeaseConflict {
    fn acquire(
        &self,
        _plan: &TransitionPlan,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict> {
        Err(TransitionConflict::new("divergent-active-lease").expect("conflict code"))
    }
}

#[test]
fn active_lease_conflict_blocks_before_receipt_consumption_or_backup() {
    let temp = TempDir::new();
    let plan = plan("operation-active-lease-conflict");
    let approval = receipt(&plan, "nonce-active-lease-conflict");
    let backend = backend();
    let coordinator = coordinator(temp.path()).with_conflict_checker(Arc::new(ActiveLeaseConflict));

    let error = coordinator
        .execute(
            &plan,
            Some(&approval),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect_err("active lease conflict");
    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::TransitionConflict(ref code)
            if code == "divergent-active-lease"
    ));
    assert_eq!(backend.backup_calls.load(Ordering::SeqCst), 0);
    assert!(
        TransitionJournalStore::new(temp.path())
            .list()
            .expect("transition journals")
            .is_empty()
    );

    let verified = verifier()
        .verify(
            &approval,
            &plan.approval_expectation("unpin-cli-human", "unpin-core-transition"),
            1_050,
        )
        .expect("approval remains valid");
    assert_eq!(
        ApprovalNonceStore::new(temp.path())
            .consume_or_attach(&verified, 1_050, owner())
            .expect("nonce was not consumed by blocked transition"),
        unpin_core::approval::NonceConsumption::Consumed
    );
}

struct ProcessBackend {
    state_root: PathBuf,
    ready: Option<PathBuf>,
    release: Option<PathBuf>,
    blocked_once: AtomicBool,
}

impl ProcessBackend {
    fn immediate(state_root: impl Into<PathBuf>) -> Self {
        Self {
            state_root: state_root.into(),
            ready: None,
            release: None,
            blocked_once: AtomicBool::new(false),
        }
    }

    fn blocking(
        state_root: impl Into<PathBuf>,
        ready: impl Into<PathBuf>,
        release: impl Into<PathBuf>,
    ) -> Self {
        Self {
            state_root: state_root.into(),
            ready: Some(ready.into()),
            release: Some(release.into()),
            blocked_once: AtomicBool::new(false),
        }
    }

    fn path(&self, effect: &TransitionEffect) -> PathBuf {
        self.state_root.join(&effect.resource_id)
    }
}

impl TransitionBackend for ProcessBackend {
    fn current_fingerprint(
        &self,
        effect: &TransitionEffect,
    ) -> Result<Option<String>, BackendFailure> {
        match fs::read(self.path(effect)) {
            Ok(bytes) => Ok(Some(fingerprint(&bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(failure("process-state-read-failed")),
        }
    }

    fn backup_transition(
        &self,
        _plan: &TransitionPlan,
        backup_id: &str,
    ) -> Result<AuthenticatedBackup, BackendFailure> {
        AuthenticatedBackup::new(fingerprint(backup_id.as_bytes()))
            .map_err(|_| failure("process-backup-failed"))
    }

    fn apply_effect(&self, effect: &TransitionEffect) -> Result<(), BackendFailure> {
        if !self.blocked_once.swap(true, Ordering::SeqCst)
            && let (Some(ready), Some(release)) = (&self.ready, &self.release)
        {
            fs::write(ready, b"locked").map_err(|_| failure("process-ready-failed"))?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !release.exists() {
                if Instant::now() >= deadline {
                    return Err(failure("process-release-timeout"));
                }
                thread::yield_now();
            }
        }
        fs::write(self.path(effect), b"new").map_err(|_| failure("process-state-write-failed"))
    }

    fn rollback_effect(
        &self,
        effect: &TransitionEffect,
        _backup_id: &str,
    ) -> Result<(), BackendFailure> {
        fs::write(self.path(effect), b"old").map_err(|_| failure("process-state-write-failed"))
    }
}

fn process_plan(operation_id: &str, resources: &[&str]) -> TransitionPlan {
    TransitionPlan::new(
        operation_id,
        TransitionKind::ApplyProfile,
        TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: None,
            profile_digest: None,
        },
        resources
            .iter()
            .enumerate()
            .map(|(index, resource)| effect(&format!("effect-{index}"), resource, b"old", b"new"))
            .collect(),
    )
    .expect("process transition plan")
}

#[test]
fn cross_process_resource_locks_serialize_overlap_while_unrelated_work_proceeds() {
    let temp = TempDir::new();
    let state_root = temp.path().join("provider-state");
    fs::create_dir(&state_root).expect("provider state root");
    for resource in ["resource-a", "resource-b", "resource-c"] {
        fs::write(state_root.join(resource), b"old").expect("provider state");
    }
    let app_state_root = temp.path().join("unpin-state");
    let child_plan = process_plan("process-lock-holder", &["resource-b", "resource-a"]);
    let child_receipt = receipt(&child_plan, "nonce-process-lock-holder");
    let plan_path = temp.path().join("process-plan.json");
    let receipt_path = temp.path().join("process-receipt.json");
    fs::write(
        &plan_path,
        serde_json::to_vec(&child_plan).expect("process plan JSON"),
    )
    .expect("write process plan");
    fs::write(
        &receipt_path,
        serde_json::to_vec(&child_receipt).expect("process receipt JSON"),
    )
    .expect("write process receipt");
    let ready = temp.path().join("lock-ready");
    let release = temp.path().join("lock-release");
    let result = temp.path().join("process-result");
    let executable = env::current_exe().expect("test executable");
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "transition_process_lock_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("UNPIN_TRANSITION_TEST_APP_STATE", &app_state_root)
        .env("UNPIN_TRANSITION_TEST_PROVIDER_STATE", &state_root)
        .env("UNPIN_TRANSITION_TEST_PLAN", &plan_path)
        .env("UNPIN_TRANSITION_TEST_RECEIPT", &receipt_path)
        .env("UNPIN_TRANSITION_TEST_READY", &ready)
        .env("UNPIN_TRANSITION_TEST_RELEASE", &release)
        .env("UNPIN_TRANSITION_TEST_RESULT", &result)
        .spawn()
        .expect("spawn lock holder");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "lock holder start timeout");
        thread::yield_now();
    }

    let conflicting = process_plan("process-lock-conflict", &["resource-a", "resource-b"]);
    let conflicting_receipt = receipt(&conflicting, "nonce-process-lock-conflict");
    let error = coordinator(&app_state_root)
        .execute(
            &conflicting,
            Some(&conflicting_receipt),
            &verifier(),
            1_050,
            owner(),
            &ProcessBackend::immediate(&state_root),
        )
        .expect_err("overlapping process is serialized");
    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::ResourceBusy(_)
    ));

    let unrelated = process_plan("process-lock-unrelated", &["resource-c"]);
    let unrelated_outcome = coordinator(&app_state_root)
        .execute(
            &unrelated,
            Some(&receipt(&unrelated, "nonce-process-lock-unrelated")),
            &verifier(),
            1_050,
            owner(),
            &ProcessBackend::immediate(&state_root),
        )
        .expect("unrelated transition proceeds");
    assert_eq!(unrelated_outcome.status, TransitionOutcomeStatus::Committed);

    fs::write(&release, b"continue").expect("release lock holder");
    assert!(child.wait().expect("lock holder status").success());
    assert_eq!(
        fs::read_to_string(&result).expect("holder result"),
        "committed"
    );

    let retry = coordinator(&app_state_root)
        .execute(
            &conflicting,
            Some(&conflicting_receipt),
            &verifier(),
            1_050,
            owner(),
            &ProcessBackend::immediate(&state_root),
        )
        .expect("serialized retry detects drift");
    assert_eq!(retry.status, TransitionOutcomeStatus::NeedsRepair);
    assert_eq!(retry.reason_code.as_deref(), Some("pre-state-drift"));
}

#[test]
#[ignore = "subprocess helper"]
fn transition_process_lock_worker() {
    let Ok(app_state_root) = env::var("UNPIN_TRANSITION_TEST_APP_STATE") else {
        return;
    };
    let provider_state =
        env::var("UNPIN_TRANSITION_TEST_PROVIDER_STATE").expect("provider state path");
    let plan: TransitionPlan = serde_json::from_slice(
        &fs::read(env::var("UNPIN_TRANSITION_TEST_PLAN").expect("plan path"))
            .expect("process plan"),
    )
    .expect("decode process plan");
    let approval: ApprovalReceipt = serde_json::from_slice(
        &fs::read(env::var("UNPIN_TRANSITION_TEST_RECEIPT").expect("receipt path"))
            .expect("process receipt"),
    )
    .expect("decode process receipt");
    let ready = env::var("UNPIN_TRANSITION_TEST_READY").expect("ready path");
    let release = env::var("UNPIN_TRANSITION_TEST_RELEASE").expect("release path");
    let outcome = coordinator(Path::new(&app_state_root))
        .execute(
            &plan,
            Some(&approval),
            &verifier(),
            1_050,
            owner(),
            &ProcessBackend::blocking(provider_state, ready, release),
        )
        .expect("process transition");
    fs::write(
        env::var("UNPIN_TRANSITION_TEST_RESULT").expect("result path"),
        match outcome.status {
            TransitionOutcomeStatus::Committed => "committed",
            TransitionOutcomeStatus::RolledBack => "rolled-back",
            TransitionOutcomeStatus::NeedsRepair => "needs-repair",
        },
    )
    .expect("write process result");
}
