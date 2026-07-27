use std::{
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalNonceStore, ApprovalReceipt, ApprovalVerifier, VerifiedApproval,
    },
    config::get_transition_lock_dir,
    mutation::{MutationLock, acquire_mutation_lock},
    state::atomic_json::{OwnerGeneration, StateError},
};

use super::{
    journal::{
        EffectCheckpointStatus, JournalError, JournalHandle, TransitionJournal,
        TransitionJournalStore, TransitionLifecycle,
    },
    plan::{TransitionEffect, TransitionKind, TransitionPlan, TransitionPlanError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBackup {
    pub manifest_digest: String,
}

impl AuthenticatedBackup {
    pub fn new(manifest_digest: impl Into<String>) -> Result<Self, CoordinatorError> {
        let manifest_digest = manifest_digest.into();
        validate_digest(&manifest_digest).map_err(|_| CoordinatorError::InvalidBackupEvidence)?;
        Ok(Self { manifest_digest })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFailure {
    code: String,
}

impl BackendFailure {
    pub fn new(code: impl Into<String>) -> Result<Self, CoordinatorError> {
        let code = code.into();
        validate_code(&code).map_err(|_| CoordinatorError::InvalidBackendFailureCode)?;
        Ok(Self { code })
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for BackendFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.code)
    }
}

impl std::error::Error for BackendFailure {}

pub trait TransitionBackend {
    fn current_fingerprint(
        &self,
        effect: &TransitionEffect,
    ) -> Result<Option<String>, BackendFailure>;

    fn backup_transition(
        &self,
        plan: &TransitionPlan,
        backup_id: &str,
    ) -> Result<AuthenticatedBackup, BackendFailure>;

    fn apply_effect(&self, effect: &TransitionEffect) -> Result<(), BackendFailure>;

    fn rollback_effect(
        &self,
        effect: &TransitionEffect,
        backup_id: &str,
    ) -> Result<(), BackendFailure>;
}

pub trait TransitionConflictGuard: Send {}

impl<T: Send> TransitionConflictGuard for T {}

pub trait TransitionConflictChecker: Send + Sync {
    /// Checks active session intent and returns a guard held through the full transition.
    fn acquire(
        &self,
        plan: &TransitionPlan,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionConflict {
    code: String,
}

impl TransitionConflict {
    pub fn new(code: impl Into<String>) -> Result<Self, CoordinatorError> {
        let code = code.into();
        validate_code(&code).map_err(|_| CoordinatorError::InvalidConflictCode)?;
        Ok(Self { code })
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[derive(Debug)]
struct NoActiveLeaseConflicts;

impl TransitionConflictChecker for NoActiveLeaseConflicts {
    fn acquire(
        &self,
        _plan: &TransitionPlan,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict> {
        Ok(Box::new(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionOutcomeStatus {
    Committed,
    RolledBack,
    NeedsRepair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionOutcome {
    pub operation_id: String,
    pub status: TransitionOutcomeStatus,
    pub backup_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionRecoveryPolicy {
    ResumeSafe,
    NoResumeWrites,
}

#[derive(Clone)]
pub struct TransitionCoordinator {
    app_state_root: PathBuf,
    approval_issuer: String,
    approval_audience: String,
    conflict_checker: Arc<dyn TransitionConflictChecker>,
}

impl TransitionCoordinator {
    pub fn new(
        app_state_root: impl Into<PathBuf>,
        approval_issuer: impl Into<String>,
        approval_audience: impl Into<String>,
    ) -> Result<Self, CoordinatorError> {
        let approval_issuer = approval_issuer.into();
        let approval_audience = approval_audience.into();
        validate_identifier(&approval_issuer)?;
        validate_identifier(&approval_audience)?;
        Ok(Self {
            app_state_root: app_state_root.into(),
            approval_issuer,
            approval_audience,
            conflict_checker: Arc::new(NoActiveLeaseConflicts),
        })
    }

    #[must_use]
    pub fn with_conflict_checker(
        mut self,
        conflict_checker: Arc<dyn TransitionConflictChecker>,
    ) -> Self {
        self.conflict_checker = conflict_checker;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        receipt: Option<&ApprovalReceipt>,
        verifier: &ApprovalVerifier,
        now_unix: i64,
        owner: OwnerGeneration,
        backend: &B,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        self.execute_with_recovery_policy(
            plan,
            receipt,
            verifier,
            now_unix,
            owner,
            backend,
            TransitionRecoveryPolicy::ResumeSafe,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_recovery_policy<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        receipt: Option<&ApprovalReceipt>,
        verifier: &ApprovalVerifier,
        now_unix: i64,
        owner: OwnerGeneration,
        backend: &B,
        recovery_policy: TransitionRecoveryPolicy,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        plan.verify()?;
        let nonce_owner = owner;
        let owner = transition_journal_owner(plan)?;
        // Guard remains live until apply, rollback, or terminal failure returns.
        let _conflict_guard = self
            .conflict_checker
            .acquire(plan)
            .map_err(|conflict| CoordinatorError::TransitionConflict(conflict.code))?;
        let journal_store = TransitionJournalStore::new(&self.app_state_root);
        let mut handle = journal_store.create_or_attach(plan, owner.clone())?;
        let resource_ids = plan
            .effects
            .iter()
            .map(|effect| effect.resource_id.as_str())
            .collect::<Vec<_>>();
        let _locks = ResourceLockSet::try_acquire(&self.app_state_root, &resource_ids)?;
        let _legacy_mutation_lock =
            legacy_mutation_compatibility_lock(&self.app_state_root, plan.kind)?;
        if handle.journal.lifecycle.is_terminal() {
            return self.cached_terminal_outcome(plan, &handle.journal, backend);
        }
        if recovery_policy == TransitionRecoveryPolicy::NoResumeWrites
            && handle.journal.lifecycle != TransitionLifecycle::Planned
        {
            return self.needs_repair(&journal_store, &mut handle, "no-resume-writes", None);
        }

        self.ensure_authorized(
            plan,
            receipt,
            verifier,
            now_unix,
            &nonce_owner,
            &owner,
            &journal_store,
            &mut handle,
        )?;
        if let Some(operation_id) = journal_store.blocking_operation_for(plan)? {
            return Err(CoordinatorError::RecoveryRequired(operation_id));
        }

        let mut handle = journal_store.load(plan, owner)?;
        if handle.journal.lifecycle.is_terminal() {
            return self.cached_terminal_outcome(plan, &handle.journal, backend);
        }
        let receipt_digest = receipt.map(ApprovalReceipt::decision_digest);
        if let Some(receipt_digest) = receipt_digest
            && handle.journal.authorization_decision_digest.as_deref()
                != Some(receipt_digest.as_str())
        {
            return Err(CoordinatorError::AuthorizationDecisionConflict);
        }

        let resume_rollback = matches!(
            handle.journal.lifecycle,
            TransitionLifecycle::Cancelling | TransitionLifecycle::RollingBack
        );

        let (locked_lifecycle, lock_code) = match handle.journal.lifecycle {
            lifecycle @ (TransitionLifecycle::Applying
            | TransitionLifecycle::Cancelling
            | TransitionLifecycle::RollingBack
            | TransitionLifecycle::Recovering) => (lifecycle, "resources-relocked"),
            _ => (TransitionLifecycle::Locked, "resources-locked"),
        };
        handle.journal.record(locked_lifecycle, lock_code, None)?;
        journal_store.save(&mut handle)?;

        if handle.journal.backup_manifest_digest.is_none() {
            if let Some(effect_id) = self.first_pre_state_drift(plan, backend)? {
                return self.needs_repair(
                    &journal_store,
                    &mut handle,
                    "pre-state-drift",
                    Some(&effect_id),
                );
            }
            self.create_backup(plan, backend, &journal_store, &mut handle)?;
        }

        if resume_rollback {
            return self.rollback(
                plan,
                backend,
                &journal_store,
                &mut handle,
                "resume-rollback",
            );
        }

        self.apply(plan, backend, &journal_store, &mut handle)
    }

    fn cached_terminal_outcome<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        journal: &TransitionJournal,
        backend: &B,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        let expected_post_state = match journal.lifecycle {
            TransitionLifecycle::Committed => true,
            TransitionLifecycle::RolledBack => false,
            TransitionLifecycle::NeedsRepair => return terminal_outcome(journal),
            _ => return Err(CoordinatorError::NotTerminal),
        };
        for effect in &plan.effects {
            let current = backend
                .current_fingerprint(effect)
                .map_err(|_| CoordinatorError::RecoveryRequired(journal.operation_id.clone()))?;
            let expected = if expected_post_state {
                &effect.expected_post_fingerprint
            } else {
                &effect.expected_pre_fingerprint
            };
            if current.as_ref() != expected.as_ref() {
                return Err(CoordinatorError::RecoveryRequired(
                    journal.operation_id.clone(),
                ));
            }
        }
        terminal_outcome(journal)
    }

    fn first_pre_state_drift<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        backend: &B,
    ) -> Result<Option<String>, CoordinatorError> {
        for effect in &plan.effects {
            if backend.current_fingerprint(effect)? != effect.expected_pre_fingerprint {
                return Ok(Some(effect.effect_id.clone()));
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_authorized(
        &self,
        plan: &TransitionPlan,
        receipt: Option<&ApprovalReceipt>,
        verifier: &ApprovalVerifier,
        now_unix: i64,
        nonce_owner: &OwnerGeneration,
        journal_owner: &OwnerGeneration,
        journal_store: &TransitionJournalStore,
        handle: &mut JournalHandle,
    ) -> Result<(), CoordinatorError> {
        if let Some(decision_digest) = &handle.journal.authorization_decision_digest {
            if receipt
                .map(ApprovalReceipt::decision_digest)
                .as_deref()
                .is_some_and(|digest| digest != decision_digest)
            {
                return Err(CoordinatorError::AuthorizationDecisionConflict);
            }
            return Ok(());
        }

        let receipt = receipt.ok_or(CoordinatorError::ApprovalRequired)?;
        let expectation =
            plan.approval_expectation(self.approval_issuer.clone(), self.approval_audience.clone());
        let approval = verifier.verify_binding(receipt, &expectation)?;
        let nonce_store = ApprovalNonceStore::new(&self.app_state_root);
        authorize_nonce(&nonce_store, &approval, now_unix, nonce_owner.clone())?;

        handle.journal.authorization_decision_digest = Some(approval.decision_digest);
        handle
            .journal
            .record(TransitionLifecycle::Approved, "approval-recorded", None)?;
        match journal_store.save(handle) {
            Ok(()) => Ok(()),
            Err(JournalError::State(StateError::StaleRevision { .. })) => {
                let loaded = journal_store.load(plan, journal_owner.clone())?;
                if loaded.journal.authorization_decision_digest
                    == handle.journal.authorization_decision_digest
                {
                    *handle = loaded;
                    Ok(())
                } else {
                    Err(CoordinatorError::AuthorizationDecisionConflict)
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn create_backup<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        backend: &B,
        journal_store: &TransitionJournalStore,
        handle: &mut JournalHandle,
    ) -> Result<(), CoordinatorError> {
        let backup = match backend.backup_transition(plan, &handle.journal.backup_id) {
            Ok(backup) => backup,
            Err(error) => {
                handle.journal.record(
                    TransitionLifecycle::Recovering,
                    format!("backup-{}", error.code()),
                    None,
                )?;
                journal_store.save(handle)?;
                return Err(CoordinatorError::Backend(error));
            }
        };
        validate_digest(&backup.manifest_digest)
            .map_err(|_| CoordinatorError::InvalidBackupEvidence)?;
        handle.journal.backup_manifest_digest = Some(backup.manifest_digest);
        for checkpoint in &mut handle.journal.effects {
            checkpoint.status = EffectCheckpointStatus::BackedUp;
        }
        handle
            .journal
            .record(TransitionLifecycle::BackedUp, "backup-authenticated", None)?;
        journal_store.save(handle)?;
        Ok(())
    }

    fn apply<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        backend: &B,
        journal_store: &TransitionJournalStore,
        handle: &mut JournalHandle,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        handle
            .journal
            .record(TransitionLifecycle::Applying, "apply-started", None)?;
        journal_store.save(handle)?;

        for (index, effect) in plan.effects.iter().enumerate() {
            let checkpoint = &handle.journal.effects[index];
            let current = match backend.current_fingerprint(effect) {
                Ok(current) => current,
                Err(_) => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "state-observation-failed",
                        Some(&effect.effect_id),
                    );
                }
            };
            match checkpoint.status {
                EffectCheckpointStatus::Applied => {
                    if current != effect.expected_post_fingerprint {
                        return self.needs_repair(
                            journal_store,
                            handle,
                            "applied-state-drift",
                            Some(&effect.effect_id),
                        );
                    }
                    continue;
                }
                EffectCheckpointStatus::RolledBack => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "unexpected-rolled-back-effect",
                        Some(&effect.effect_id),
                    );
                }
                EffectCheckpointStatus::NeedsRepair => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "checkpoint-needs-repair",
                        Some(&effect.effect_id),
                    );
                }
                EffectCheckpointStatus::Pending | EffectCheckpointStatus::BackedUp => {}
            }

            if current == effect.expected_post_fingerprint {
                handle.journal.effects[index].status = EffectCheckpointStatus::Applied;
                handle.journal.record(
                    TransitionLifecycle::Recovering,
                    "effect-recovered",
                    Some(&effect.effect_id),
                )?;
                journal_store.save(handle)?;
                continue;
            }
            if current != effect.expected_pre_fingerprint {
                return self.needs_repair(
                    journal_store,
                    handle,
                    "pre-state-drift",
                    Some(&effect.effect_id),
                );
            }

            if let Err(error) = backend.apply_effect(effect) {
                handle.journal.record(
                    TransitionLifecycle::Cancelling,
                    format!("apply-{}", error.code()),
                    Some(&effect.effect_id),
                )?;
                journal_store.save(handle)?;
                return self.rollback(plan, backend, journal_store, handle, "apply-failed");
            }
            let current = match backend.current_fingerprint(effect) {
                Ok(current) => current,
                Err(_) => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "post-state-unobservable",
                        Some(&effect.effect_id),
                    );
                }
            };
            if current != effect.expected_post_fingerprint {
                return self.needs_repair(
                    journal_store,
                    handle,
                    "post-state-unverified",
                    Some(&effect.effect_id),
                );
            }
            handle.journal.effects[index].status = EffectCheckpointStatus::Applied;
            handle.journal.record(
                TransitionLifecycle::Applying,
                "effect-applied",
                Some(&effect.effect_id),
            )?;
            journal_store.save(handle)?;
        }

        handle.journal.terminal_code = Some("committed".to_string());
        handle
            .journal
            .record(TransitionLifecycle::Committed, "committed", None)?;
        journal_store.save(handle)?;
        terminal_outcome(&handle.journal)
    }

    fn rollback<B: TransitionBackend>(
        &self,
        plan: &TransitionPlan,
        backend: &B,
        journal_store: &TransitionJournalStore,
        handle: &mut JournalHandle,
        terminal_code: &str,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        handle
            .journal
            .record(TransitionLifecycle::RollingBack, "rollback-started", None)?;
        journal_store.save(handle)?;

        for (index, effect) in plan.effects.iter().enumerate().rev() {
            let status = handle.journal.effects[index].status;
            let current = match backend.current_fingerprint(effect) {
                Ok(current) => current,
                Err(_) => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "rollback-state-unobservable",
                        Some(&effect.effect_id),
                    );
                }
            };
            if current == effect.expected_pre_fingerprint {
                if status == EffectCheckpointStatus::Applied {
                    handle.journal.effects[index].status = EffectCheckpointStatus::RolledBack;
                    handle.journal.record(
                        TransitionLifecycle::RollingBack,
                        "rollback-recovered",
                        Some(&effect.effect_id),
                    )?;
                    journal_store.save(handle)?;
                }
                continue;
            }
            if current != effect.expected_post_fingerprint {
                return self.needs_repair(
                    journal_store,
                    handle,
                    "rollback-state-drift",
                    Some(&effect.effect_id),
                );
            }

            if let Err(error) = backend.rollback_effect(effect, &handle.journal.backup_id) {
                return self.needs_repair(
                    journal_store,
                    handle,
                    &format!("rollback-{}", error.code()),
                    Some(&effect.effect_id),
                );
            }
            let rolled_back = match backend.current_fingerprint(effect) {
                Ok(current) => current,
                Err(_) => {
                    return self.needs_repair(
                        journal_store,
                        handle,
                        "rollback-state-unobservable",
                        Some(&effect.effect_id),
                    );
                }
            };
            if rolled_back != effect.expected_pre_fingerprint {
                return self.needs_repair(
                    journal_store,
                    handle,
                    "rollback-unverified",
                    Some(&effect.effect_id),
                );
            }
            handle.journal.effects[index].status = EffectCheckpointStatus::RolledBack;
            handle.journal.record(
                TransitionLifecycle::RollingBack,
                "effect-rolled-back",
                Some(&effect.effect_id),
            )?;
            journal_store.save(handle)?;
        }

        handle.journal.terminal_code = Some(terminal_code.to_string());
        handle
            .journal
            .record(TransitionLifecycle::RolledBack, "rolled-back", None)?;
        journal_store.save(handle)?;
        terminal_outcome(&handle.journal)
    }

    fn needs_repair(
        &self,
        journal_store: &TransitionJournalStore,
        handle: &mut JournalHandle,
        code: &str,
        effect_id: Option<&str>,
    ) -> Result<TransitionOutcome, CoordinatorError> {
        validate_code(code).map_err(|_| CoordinatorError::InvalidBackendFailureCode)?;
        if let Some(effect_id) = effect_id
            && let Some(checkpoint) = handle
                .journal
                .effects
                .iter_mut()
                .find(|checkpoint| checkpoint.effect_id == effect_id)
        {
            checkpoint.status = EffectCheckpointStatus::NeedsRepair;
        }
        handle.journal.terminal_code = Some(code.to_string());
        handle
            .journal
            .record(TransitionLifecycle::NeedsRepair, code, effect_id)?;
        journal_store.save(handle)?;
        terminal_outcome(&handle.journal)
    }
}

fn legacy_mutation_compatibility_lock(
    app_state_root: &Path,
    kind: TransitionKind,
) -> Result<Option<MutationLock>, CoordinatorError> {
    if matches!(
        kind,
        TransitionKind::AdoptCapability | TransitionKind::RestoreNative
    ) {
        acquire_mutation_lock(app_state_root)
            .map(Some)
            .map_err(CoordinatorError::LegacyMutationBusy)
    } else {
        Ok(None)
    }
}

fn authorize_nonce(
    nonce_store: &ApprovalNonceStore,
    approval: &VerifiedApproval,
    now_unix: i64,
    owner: OwnerGeneration,
) -> Result<(), CoordinatorError> {
    if now_unix < approval.issued_at_unix {
        return Err(CoordinatorError::Approval(ApprovalError::NotYetValid));
    }
    if now_unix < approval.expires_at_unix {
        nonce_store.consume_or_attach(approval, now_unix, owner)?;
    } else {
        nonce_store.attach_existing(approval)?;
    }
    Ok(())
}

fn terminal_outcome(journal: &TransitionJournal) -> Result<TransitionOutcome, CoordinatorError> {
    let status = match journal.lifecycle {
        TransitionLifecycle::Committed => TransitionOutcomeStatus::Committed,
        TransitionLifecycle::RolledBack => TransitionOutcomeStatus::RolledBack,
        TransitionLifecycle::NeedsRepair => TransitionOutcomeStatus::NeedsRepair,
        _ => return Err(CoordinatorError::NotTerminal),
    };
    Ok(TransitionOutcome {
        operation_id: journal.operation_id.clone(),
        status,
        backup_id: journal.backup_id.clone(),
        reason_code: journal.terminal_code.clone(),
    })
}

struct ResourceLockSet {
    _files: Vec<File>,
}

impl ResourceLockSet {
    fn try_acquire(app_state_root: &Path, resource_ids: &[&str]) -> Result<Self, CoordinatorError> {
        let lock_dir = get_transition_lock_dir(app_state_root);
        ensure_private_lock_directory(&lock_dir)?;
        let canonical_before = fs::canonicalize(&lock_dir)
            .map_err(|error| CoordinatorError::Io(lock_dir.clone(), error.to_string()))?;
        let identity_before = directory_identity(&canonical_before)?;
        let mut resource_ids = resource_ids.to_vec();
        resource_ids.sort_unstable();
        resource_ids.dedup();
        let mut files = Vec::with_capacity(resource_ids.len());
        for resource_id in resource_ids {
            validate_identifier(resource_id)?;
            let digest = crate::encode_lower_hex(&Sha256::digest(resource_id.as_bytes()));
            let path = canonical_before.join(format!("{digest}.lock"));
            let file = open_private_lock_file(&path)?;
            match file.try_lock() {
                Ok(()) => files.push(file),
                Err(TryLockError::WouldBlock) => {
                    return Err(CoordinatorError::ResourceBusy(resource_id.to_string()));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(CoordinatorError::Io(path, error.to_string()));
                }
            }
        }
        let canonical_after = fs::canonicalize(&lock_dir)
            .map_err(|error| CoordinatorError::Io(lock_dir.clone(), error.to_string()))?;
        if canonical_before != canonical_after
            || identity_before != directory_identity(&canonical_after)?
        {
            return Err(CoordinatorError::LockDirectoryChanged);
        }
        Ok(Self { _files: files })
    }
}

fn ensure_private_lock_directory(path: &Path) -> Result<(), CoordinatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(CoordinatorError::Io(path.to_path_buf(), error.to_string()));
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Err(CoordinatorError::PrivatePermissionsUnsupported(
                    path.to_path_buf(),
                ));
            }
        }
        Err(error) => {
            return Err(CoordinatorError::Io(path.to_path_buf(), error.to_string()));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()));
        }
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    }
    Ok(())
}

fn open_private_lock_file(path: &Path) -> Result<File, CoordinatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CoordinatorError::Io(path.to_path_buf(), error.to_string()));
        }
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    validate_open_lock_file(path, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_open_lock_file(path: &Path, file: &File) -> Result<(), CoordinatorError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
        || file_metadata.permissions().mode() & 0o077 != 0
    {
        Err(CoordinatorError::UnsafeLockPath(path.to_path_buf()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_open_lock_file(path: &Path, _file: &File) -> Result<(), CoordinatorError> {
    Err(CoordinatorError::PrivatePermissionsUnsupported(
        path.to_path_buf(),
    ))
}

fn validate_identifier(value: &str) -> Result<(), CoordinatorError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err(CoordinatorError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn transition_journal_owner(plan: &TransitionPlan) -> Result<OwnerGeneration, CoordinatorError> {
    OwnerGeneration::new(format!("transition:{}", plan.operation_id), 1)
        .map_err(|error| CoordinatorError::JournalOwner(error.to_string()))
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<(u64, u64), CoordinatorError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)
        .map_err(|error| CoordinatorError::Io(path.to_path_buf(), error.to_string()))?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn directory_identity(path: &Path) -> Result<(u64, u64), CoordinatorError> {
    Err(CoordinatorError::PrivatePermissionsUnsupported(
        path.to_path_buf(),
    ))
}

fn validate_code(value: &str) -> Result<(), ()> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_digest(value: &str) -> Result<(), ()> {
    if crate::is_lower_hex_digest(value) {
        Ok(())
    } else {
        Err(())
    }
}

#[derive(Debug)]
pub enum CoordinatorError {
    InvalidIdentifier,
    InvalidBackendFailureCode,
    InvalidConflictCode,
    InvalidBackupEvidence,
    ApprovalRequired,
    AuthorizationDecisionConflict,
    TransitionConflict(String),
    ResourceBusy(String),
    LegacyMutationBusy(String),
    RecoveryRequired(String),
    UnsafeLockPath(PathBuf),
    LockDirectoryChanged,
    PrivatePermissionsUnsupported(PathBuf),
    Io(PathBuf, String),
    NotTerminal,
    JournalOwner(String),
    Plan(TransitionPlanError),
    Approval(ApprovalError),
    Journal(JournalError),
    Backend(BackendFailure),
}

impl From<TransitionPlanError> for CoordinatorError {
    fn from(error: TransitionPlanError) -> Self {
        Self::Plan(error)
    }
}

impl From<ApprovalError> for CoordinatorError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<JournalError> for CoordinatorError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<BackendFailure> for CoordinatorError {
    fn from(error: BackendFailure) -> Self {
        Self::Backend(error)
    }
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => formatter.write_str("transition identifier is invalid"),
            Self::InvalidBackendFailureCode => {
                formatter.write_str("transition backend failure code is invalid")
            }
            Self::InvalidConflictCode => formatter.write_str("transition conflict code is invalid"),
            Self::InvalidBackupEvidence => {
                formatter.write_str("transition backup authentication evidence is invalid")
            }
            Self::ApprovalRequired => formatter.write_str("human approval receipt is required"),
            Self::AuthorizationDecisionConflict => {
                formatter.write_str("operation is bound to another approval decision")
            }
            Self::TransitionConflict(code) => {
                write!(formatter, "transition blocked by session state: {code}")
            }
            Self::ResourceBusy(resource_id) => {
                write!(formatter, "transition resource is busy: {resource_id}")
            }
            Self::LegacyMutationBusy(reason) => {
                write!(formatter, "legacy mutation resource is busy: {reason}")
            }
            Self::RecoveryRequired(operation_id) => {
                write!(formatter, "transition requires recovery: {operation_id}")
            }
            Self::UnsafeLockPath(path) => {
                write!(
                    formatter,
                    "transition lock path is unsafe: {}",
                    path.display()
                )
            }
            Self::LockDirectoryChanged => {
                formatter.write_str("transition lock directory changed while acquiring locks")
            }
            Self::PrivatePermissionsUnsupported(path) => write!(
                formatter,
                "private transition lock permissions are unsupported: {}",
                path.display()
            ),
            Self::Io(path, message) => write!(formatter, "{}: {message}", path.display()),
            Self::NotTerminal => formatter.write_str("transition has no terminal outcome"),
            Self::JournalOwner(message) => {
                write!(formatter, "transition journal owner is invalid: {message}")
            }
            Self::Plan(error) => error.fmt(formatter),
            Self::Approval(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::Backend(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CoordinatorError {}
