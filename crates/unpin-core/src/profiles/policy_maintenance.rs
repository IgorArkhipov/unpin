use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::get_workspace_policy_path,
    encode_lower_hex,
    mutation::BackupAuthenticationKey,
    profiles::{PolicyStore, PolicyStoreError, PolicyTarget, ScopePolicy},
    state::{
        atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot},
        workspace::{WorkspacePhysicalEvidence, capture_workspace_physical_evidence},
    },
};

const POLICY_MAINTENANCE_PLAN_SCHEMA_VERSION: u32 = 1;
const POLICY_MAINTENANCE_RECORD_SCHEMA_VERSION: u32 = 1;
const POLICY_MAINTENANCE_BACKUP_SCHEMA_VERSION: u32 = 1;
const POLICY_MAINTENANCE_STATE_SCHEMA_VERSION: u32 = 1;
const POLICY_MAINTENANCE_RECORD_PURPOSE: &[u8] = b"unpin-policy-maintenance-record-v1\0";
const POLICY_MAINTENANCE_BACKUP_PURPOSE: &[u8] = b"unpin-policy-maintenance-backup-v1\0";
const MAX_LEGACY_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspacePolicyClassification {
    Attached,
    Moved,
    Deleted,
    Recreated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyMaintenanceLifecycle {
    Active,
    Reattached { target: PolicyTarget },
    Discarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyMaintenanceProvenance {
    WorkspaceFileMigration {
        source_path: PathBuf,
        source_fingerprint: String,
        source_identity: String,
    },
    Reattached {
        prior_target: PolicyTarget,
        prior_record_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyReviewEvidence {
    pub actor_id: String,
    pub reviewed_at_unix: u64,
    pub decision_digest: String,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenanceRecord {
    pub schema_version: u32,
    pub record_id: String,
    pub target: PolicyTarget,
    pub workspace: WorkspacePhysicalEvidence,
    pub provenance: PolicyMaintenanceProvenance,
    pub review: PolicyReviewEvidence,
    pub lifecycle: PolicyMaintenanceLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_policy_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_policy_fingerprint: Option<String>,
    pub last_operation_id: String,
    pub authentication_key_id: String,
    pub authentication_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyMaintenanceAction {
    Migrate {
        source_path: PathBuf,
        source_fingerprint: String,
        source_identity: String,
        policy: ScopePolicy,
        workspace: WorkspacePhysicalEvidence,
    },
    Reattach {
        from_target: PolicyTarget,
        to_target: PolicyTarget,
        workspace: WorkspacePhysicalEvidence,
    },
    Discard {
        target: PolicyTarget,
    },
    Cleanup {
        target: PolicyTarget,
    },
    Restore {
        backup_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenancePlan {
    pub schema_version: u32,
    pub operation_id: String,
    pub action: PolicyMaintenanceAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_policy_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_record_revision: Option<StateRevision>,
    pub plan_fingerprint: String,
}

impl PolicyMaintenancePlan {
    pub fn verify(&self) -> Result<(), PolicyMaintenanceError> {
        if self.schema_version != POLICY_MAINTENANCE_PLAN_SCHEMA_VERSION
            || self.operation_id.is_empty()
            || self.plan_fingerprint.len() != 64
        {
            return Err(PolicyMaintenanceError::InvalidPlan);
        }
        let calculated = calculate_plan_fingerprint(self)?;
        if calculated != self.plan_fingerprint
            || self.operation_id != format!("policy-maintenance-{}", &calculated[..32])
        {
            return Err(PolicyMaintenanceError::PlanFingerprintMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenanceApproval {
    pub confirmed: bool,
    pub plan_fingerprint: String,
    pub actor_id: String,
    pub reviewed_at_unix: u64,
    pub decision_digest: String,
}

impl PolicyMaintenanceApproval {
    fn review(&self) -> PolicyReviewEvidence {
        PolicyReviewEvidence {
            actor_id: self.actor_id.clone(),
            reviewed_at_unix: self.reviewed_at_unix,
            decision_digest: self.decision_digest.clone(),
            plan_fingerprint: self.plan_fingerprint.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenanceStatus {
    pub target: PolicyTarget,
    pub record_id: String,
    pub classification: WorkspacePolicyClassification,
    pub lifecycle: PolicyMaintenanceLifecycle,
    pub active_policy_revision: Option<StateRevision>,
    pub active_policy_fingerprint: Option<String>,
    pub allowed_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenanceOutcome {
    pub operation_id: String,
    pub backup_id: String,
    pub affected_targets: Vec<PolicyTarget>,
    pub lifecycle: PolicyMaintenanceLifecycle,
}

#[derive(Debug)]
pub struct ProtectedPolicyChange<T> {
    pub result: T,
    pub backup_id: String,
}

#[derive(Debug)]
pub enum ProtectedPolicyChangeError<E> {
    Apply(E),
    Maintenance(PolicyMaintenanceError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyBackupEntry {
    pub target: PolicyTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_policy: Option<ScopePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_policy_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_record: Option<PolicyMaintenanceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_record_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_policy_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_record_revision: Option<StateRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyMaintenanceBackup {
    pub schema_version: u32,
    pub backup_id: String,
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub review: PolicyReviewEvidence,
    pub entries: Vec<PolicyBackupEntry>,
    pub finalized: bool,
    pub authentication_key_id: String,
    pub authentication_tag: String,
}

#[derive(Debug, Clone)]
pub struct PolicyMaintenanceController {
    app_state_root: PathBuf,
    project_root: PathBuf,
    policies: PolicyStore,
    authentication_key: BackupAuthenticationKey,
}

impl PolicyMaintenanceController {
    #[must_use]
    pub fn new(
        app_state_root: impl Into<PathBuf>,
        project_root: impl Into<PathBuf>,
        authentication_key: BackupAuthenticationKey,
    ) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            policies: PolicyStore::new(&app_state_root),
            app_state_root,
            project_root: project_root.into(),
            authentication_key,
        }
    }

    pub fn plan_migration(&self) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        let source = read_legacy_policy(&self.project_root)?;
        let workspace = capture_workspace_physical_evidence(&self.project_root)?;
        let target = PolicyTarget::workspace(
            workspace.repository_key.clone(),
            workspace.workspace_key.clone(),
        )?;
        if self.policies.load(&target)?.is_some() || self.load_record_snapshot(&target)?.is_some() {
            return Err(PolicyMaintenanceError::DestinationExists);
        }
        seal_plan(
            PolicyMaintenanceAction::Migrate {
                source_path: source.path,
                source_fingerprint: source.fingerprint,
                source_identity: source.identity,
                policy: source.policy,
                workspace,
            },
            None,
            None,
        )
    }

    pub fn plan_reattach(
        &self,
        from_target: PolicyTarget,
    ) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        let record = self
            .load_record_snapshot(&from_target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        if record.value.lifecycle != PolicyMaintenanceLifecycle::Active {
            return Err(PolicyMaintenanceError::InvalidLifecycle);
        }
        let workspace = capture_workspace_physical_evidence(&self.project_root)?;
        if classify_workspace(&record.value.workspace, Some(&workspace))
            != WorkspacePolicyClassification::Moved
        {
            return Err(PolicyMaintenanceError::ReattachNotProven);
        }
        let to_target = PolicyTarget::workspace(
            workspace.repository_key.clone(),
            workspace.workspace_key.clone(),
        )?;
        if to_target == from_target
            || self.policies.load(&to_target)?.is_some()
            || self.load_record_snapshot(&to_target)?.is_some()
        {
            return Err(PolicyMaintenanceError::DestinationExists);
        }
        let policy = self
            .policies
            .load(&from_target)?
            .ok_or(PolicyMaintenanceError::PolicyNotFound)?;
        seal_plan(
            PolicyMaintenanceAction::Reattach {
                from_target,
                to_target,
                workspace,
            },
            Some(policy.revision),
            Some(record.revision),
        )
    }

    pub fn plan_discard(
        &self,
        target: PolicyTarget,
    ) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        let record = self
            .load_record_snapshot(&target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        if record.value.lifecycle != PolicyMaintenanceLifecycle::Active {
            return Err(PolicyMaintenanceError::InvalidLifecycle);
        }
        let classification = self.classification(&record.value, None)?;
        if classification == WorkspacePolicyClassification::Attached {
            return Err(PolicyMaintenanceError::WorkspaceStillAttached);
        }
        let policy = self
            .policies
            .load(&target)?
            .ok_or(PolicyMaintenanceError::PolicyNotFound)?;
        seal_plan(
            PolicyMaintenanceAction::Discard { target },
            Some(policy.revision),
            Some(record.revision),
        )
    }

    pub fn plan_cleanup(
        &self,
        target: PolicyTarget,
    ) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        let record = self
            .load_record_snapshot(&target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        if !matches!(
            record.value.lifecycle,
            PolicyMaintenanceLifecycle::Discarded | PolicyMaintenanceLifecycle::Reattached { .. }
        ) || self.policies.load(&target)?.is_some()
        {
            return Err(PolicyMaintenanceError::InvalidLifecycle);
        }
        seal_plan(
            PolicyMaintenanceAction::Cleanup { target },
            None,
            Some(record.revision),
        )
    }

    pub fn plan_restore(
        &self,
        backup_id: impl Into<String>,
    ) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        let backup_id = backup_id.into();
        let snapshot = self
            .load_backup_snapshot(&backup_id)?
            .ok_or(PolicyMaintenanceError::BackupNotFound)?;
        if !snapshot.value.finalized {
            return Err(PolicyMaintenanceError::BackupIncomplete);
        }
        for entry in &snapshot.value.entries {
            ensure_revision(
                self.policies
                    .load(&entry.target)?
                    .as_ref()
                    .map(|policy| &policy.revision),
                entry.post_policy_revision.as_ref(),
            )?;
            ensure_revision(
                self.load_record_snapshot(&entry.target)?
                    .as_ref()
                    .map(|record| &record.revision),
                entry.post_record_revision.as_ref(),
            )?;
        }
        seal_plan(
            PolicyMaintenanceAction::Restore { backup_id },
            None,
            Some(snapshot.revision),
        )
    }

    pub fn status(
        &self,
        target: &PolicyTarget,
        candidate_root: Option<&Path>,
    ) -> Result<Option<PolicyMaintenanceStatus>, PolicyMaintenanceError> {
        let Some(record) = self.load_record_snapshot(target)? else {
            return Ok(None);
        };
        let candidate = candidate_root
            .map(capture_workspace_physical_evidence)
            .transpose()?;
        let classification = self.classification(&record.value, candidate.as_ref())?;
        let allowed_actions = match (&record.value.lifecycle, classification) {
            (PolicyMaintenanceLifecycle::Active, WorkspacePolicyClassification::Moved) => {
                vec!["reattach".to_string(), "discard".to_string()]
            }
            (PolicyMaintenanceLifecycle::Active, WorkspacePolicyClassification::Attached) => {
                Vec::new()
            }
            (PolicyMaintenanceLifecycle::Active, _) => vec!["discard".to_string()],
            (
                PolicyMaintenanceLifecycle::Discarded
                | PolicyMaintenanceLifecycle::Reattached { .. },
                _,
            ) => vec!["cleanup".to_string()],
        };
        Ok(Some(PolicyMaintenanceStatus {
            target: target.clone(),
            record_id: record.value.record_id,
            classification,
            lifecycle: record.value.lifecycle,
            active_policy_revision: record.value.active_policy_revision,
            active_policy_fingerprint: record.value.active_policy_fingerprint,
            allowed_actions,
        }))
    }

    pub fn load_backup(
        &self,
        backup_id: &str,
    ) -> Result<Option<PolicyMaintenanceBackup>, PolicyMaintenanceError> {
        self.load_backup_snapshot(backup_id)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.value))
    }

    pub fn apply(
        &self,
        reviewed: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        reviewed.verify()?;
        validate_approval(reviewed, approval)?;
        let current = self.replan(reviewed)?;
        if &current != reviewed {
            return Err(PolicyMaintenanceError::PlanDrift);
        }
        match &reviewed.action {
            PolicyMaintenanceAction::Migrate {
                source_path,
                source_fingerprint,
                source_identity,
                policy,
                workspace,
            } => self.apply_migration(
                reviewed,
                approval,
                owner,
                source_path,
                source_fingerprint,
                source_identity,
                policy,
                workspace,
            ),
            PolicyMaintenanceAction::Reattach {
                from_target,
                to_target,
                workspace,
            } => self.apply_reattach(reviewed, approval, owner, from_target, to_target, workspace),
            PolicyMaintenanceAction::Discard { target } => {
                self.apply_discard(reviewed, approval, owner, target)
            }
            PolicyMaintenanceAction::Cleanup { target } => {
                self.apply_cleanup(reviewed, approval, owner, target)
            }
            PolicyMaintenanceAction::Restore { backup_id } => {
                self.apply_restore(reviewed, approval, owner, backup_id)
            }
        }
    }

    pub fn protect_policy_change<T, E>(
        &self,
        target: &PolicyTarget,
        operation_id: &str,
        reviewed_plan_fingerprint: &str,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        apply: impl FnOnce() -> Result<T, E>,
    ) -> Result<ProtectedPolicyChange<T>, ProtectedPolicyChangeError<E>> {
        validate_external_approval(reviewed_plan_fingerprint, approval)
            .map_err(ProtectedPolicyChangeError::Maintenance)?;
        validate_component("operation id", operation_id)
            .map_err(ProtectedPolicyChangeError::Maintenance)?;
        let mut entries = vec![
            self.backup_entry(target)
                .map_err(ProtectedPolicyChangeError::Maintenance)?,
        ];
        let backup_id = external_backup_id(operation_id, reviewed_plan_fingerprint, target)
            .map_err(ProtectedPolicyChangeError::Maintenance)?;
        let backup_revision = self
            .write_named_backup(
                &backup_id,
                operation_id,
                reviewed_plan_fingerprint,
                approval,
                &entries,
                owner.clone(),
            )
            .map_err(ProtectedPolicyChangeError::Maintenance)?;
        let result = match apply() {
            Ok(result) => result,
            Err(error) => {
                let current_policy = self
                    .policies
                    .load(target)
                    .map_err(PolicyMaintenanceError::from)
                    .map_err(ProtectedPolicyChangeError::Maintenance)?;
                let current_record = self
                    .load_record_snapshot(target)
                    .map_err(ProtectedPolicyChangeError::Maintenance)?;
                entries[0].post_policy_revision = current_policy.map(|snapshot| snapshot.revision);
                entries[0].post_record_revision = current_record.map(|snapshot| snapshot.revision);
                self.finalize_backup(
                    &backup_id,
                    &backup_revision,
                    entries,
                    rollback_owner(&owner, "failed-change-backup")
                        .map_err(ProtectedPolicyChangeError::Maintenance)?,
                )
                .map_err(ProtectedPolicyChangeError::Maintenance)?;
                return Err(ProtectedPolicyChangeError::Apply(error));
            }
        };
        let current_policy = self
            .policies
            .load(target)
            .map_err(PolicyMaintenanceError::from)
            .map_err(ProtectedPolicyChangeError::Maintenance)?;
        let mut post_record_revision = entries[0].prior_record_revision.clone();
        if let Some(mut record) = entries[0].prior_record.clone() {
            if record.lifecycle != PolicyMaintenanceLifecycle::Active {
                return Err(ProtectedPolicyChangeError::Maintenance(
                    PolicyMaintenanceError::InvalidLifecycle,
                ));
            }
            let policy = current_policy.as_ref().ok_or_else(|| {
                ProtectedPolicyChangeError::Maintenance(PolicyMaintenanceError::PolicyNotFound)
            })?;
            record.active_policy_revision = Some(policy.revision.clone());
            record.active_policy_fingerprint = Some(
                policy_fingerprint(&policy.policy)
                    .map_err(ProtectedPolicyChangeError::Maintenance)?,
            );
            record.review = approval.review();
            record.last_operation_id = operation_id.to_string();
            self.sign_record(&mut record)
                .map_err(ProtectedPolicyChangeError::Maintenance)?;
            post_record_revision = Some(
                self.write_record(
                    &record,
                    entries[0].prior_record_revision.as_ref(),
                    rollback_owner(&owner, "protected-change-record")
                        .map_err(ProtectedPolicyChangeError::Maintenance)?,
                )
                .map_err(ProtectedPolicyChangeError::Maintenance)?,
            );
        }
        entries[0].post_policy_revision = current_policy.map(|snapshot| snapshot.revision);
        entries[0].post_record_revision = post_record_revision;
        self.finalize_backup(
            &backup_id,
            &backup_revision,
            entries,
            rollback_owner(&owner, "protected-change-backup")
                .map_err(ProtectedPolicyChangeError::Maintenance)?,
        )
        .map_err(ProtectedPolicyChangeError::Maintenance)?;
        Ok(ProtectedPolicyChange { result, backup_id })
    }

    fn replan(
        &self,
        reviewed: &PolicyMaintenancePlan,
    ) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
        match &reviewed.action {
            PolicyMaintenanceAction::Migrate { .. } => self.plan_migration(),
            PolicyMaintenanceAction::Reattach { from_target, .. } => {
                self.plan_reattach(from_target.clone())
            }
            PolicyMaintenanceAction::Discard { target } => self.plan_discard(target.clone()),
            PolicyMaintenanceAction::Cleanup { target } => self.plan_cleanup(target.clone()),
            PolicyMaintenanceAction::Restore { backup_id } => self.plan_restore(backup_id.clone()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_migration(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        source_path: &Path,
        source_fingerprint: &str,
        source_identity: &str,
        policy: &ScopePolicy,
        workspace: &WorkspacePhysicalEvidence,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        let target = PolicyTarget::workspace(
            workspace.repository_key.clone(),
            workspace.workspace_key.clone(),
        )?;
        let mut entries = vec![self.backup_entry(&target)?];
        let (backup_revision, backup_id) =
            self.write_backup(plan, approval, &entries, owner.clone())?;
        let policy_revision = self.policies.save(&target, policy, None, owner.clone())?;
        let mut record = PolicyMaintenanceRecord {
            schema_version: POLICY_MAINTENANCE_RECORD_SCHEMA_VERSION,
            record_id: record_id(&target)?,
            target: target.clone(),
            workspace: workspace.clone(),
            provenance: PolicyMaintenanceProvenance::WorkspaceFileMigration {
                source_path: source_path.to_path_buf(),
                source_fingerprint: source_fingerprint.to_string(),
                source_identity: source_identity.to_string(),
            },
            review: approval.review(),
            lifecycle: PolicyMaintenanceLifecycle::Active,
            active_policy_revision: Some(policy_revision.clone()),
            active_policy_fingerprint: Some(policy_fingerprint(policy)?),
            last_operation_id: plan.operation_id.clone(),
            authentication_key_id: self.authentication_key.key_id().to_string(),
            authentication_tag: String::new(),
        };
        self.sign_record(&mut record)?;
        let record_revision = match self.write_record(&record, None, owner.clone()) {
            Ok(revision) => revision,
            Err(error) => {
                self.policies
                    .restore_checkpoint(
                        &target,
                        None,
                        &policy_revision,
                        rollback_owner(&owner, "migration-policy")?,
                    )
                    .map_err(|rollback| {
                        PolicyMaintenanceError::RecoveryRequired(format!(
                            "{error}; policy rollback failed: {rollback}"
                        ))
                    })?;
                return Err(error);
            }
        };
        entries[0].post_policy_revision = Some(policy_revision);
        entries[0].post_record_revision = Some(record_revision);
        self.finalize_backup(
            &backup_id,
            &backup_revision,
            entries,
            rollback_owner(&owner, "migration-backup")?,
        )?;
        Ok(PolicyMaintenanceOutcome {
            operation_id: plan.operation_id.clone(),
            backup_id,
            affected_targets: vec![target],
            lifecycle: PolicyMaintenanceLifecycle::Active,
        })
    }

    fn apply_reattach(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        from_target: &PolicyTarget,
        to_target: &PolicyTarget,
        workspace: &WorkspacePhysicalEvidence,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        let old_policy = self
            .policies
            .load(from_target)?
            .ok_or(PolicyMaintenanceError::PolicyNotFound)?;
        let old_record = self
            .load_record_snapshot(from_target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        let mut entries = vec![
            self.backup_entry(from_target)?,
            self.backup_entry(to_target)?,
        ];
        let (backup_revision, backup_id) =
            self.write_backup(plan, approval, &entries, owner.clone())?;

        let new_policy_revision =
            self.policies
                .save(to_target, &old_policy.policy, None, owner.clone())?;
        let mut new_record = PolicyMaintenanceRecord {
            schema_version: POLICY_MAINTENANCE_RECORD_SCHEMA_VERSION,
            record_id: record_id(to_target)?,
            target: to_target.clone(),
            workspace: workspace.clone(),
            provenance: PolicyMaintenanceProvenance::Reattached {
                prior_target: from_target.clone(),
                prior_record_id: old_record.value.record_id.clone(),
            },
            review: approval.review(),
            lifecycle: PolicyMaintenanceLifecycle::Active,
            active_policy_revision: Some(new_policy_revision.clone()),
            active_policy_fingerprint: Some(policy_fingerprint(&old_policy.policy)?),
            last_operation_id: plan.operation_id.clone(),
            authentication_key_id: self.authentication_key.key_id().to_string(),
            authentication_tag: String::new(),
        };
        self.sign_record(&mut new_record)?;
        let new_record_revision = match self.write_record(&new_record, None, owner.clone()) {
            Ok(revision) => revision,
            Err(error) => {
                self.policies
                    .restore_checkpoint(
                        to_target,
                        None,
                        &new_policy_revision,
                        rollback_owner(&owner, "reattach-new-policy")?,
                    )
                    .map_err(|rollback| {
                        PolicyMaintenanceError::RecoveryRequired(format!(
                            "{error}; new-policy rollback failed: {rollback}"
                        ))
                    })?;
                return Err(error);
            }
        };
        if let Err(error) = self
            .policies
            .remove_if_revision(from_target, &old_policy.revision)
        {
            self.rollback_new_target(
                to_target,
                &new_policy_revision,
                &new_record_revision,
                &owner,
            )?;
            return Err(error.into());
        }
        let mut old_tombstone = old_record.value.clone();
        old_tombstone.review = approval.review();
        old_tombstone.lifecycle = PolicyMaintenanceLifecycle::Reattached {
            target: to_target.clone(),
        };
        old_tombstone.active_policy_revision = None;
        old_tombstone.active_policy_fingerprint = None;
        old_tombstone
            .last_operation_id
            .clone_from(&plan.operation_id);
        self.sign_record(&mut old_tombstone)?;
        let old_record_revision = match self.write_record(
            &old_tombstone,
            Some(&old_record.revision),
            rollback_owner(&owner, "reattach-old-record")?,
        ) {
            Ok(revision) => revision,
            Err(error) => {
                let restored = self.policies.save(
                    from_target,
                    &old_policy.policy,
                    None,
                    rollback_owner(&owner, "reattach-old-policy")?,
                );
                let new_rollback = self.rollback_new_target(
                    to_target,
                    &new_policy_revision,
                    &new_record_revision,
                    &owner,
                );
                if let Err(rollback) = restored {
                    return Err(PolicyMaintenanceError::RecoveryRequired(format!(
                        "{error}; old-policy rollback failed: {rollback}"
                    )));
                }
                if let Err(rollback) = new_rollback {
                    return Err(PolicyMaintenanceError::RecoveryRequired(format!(
                        "{error}; new-target rollback failed: {rollback}"
                    )));
                }
                return Err(error);
            }
        };
        entries[0].post_policy_revision = None;
        entries[0].post_record_revision = Some(old_record_revision);
        entries[1].post_policy_revision = Some(new_policy_revision);
        entries[1].post_record_revision = Some(new_record_revision);
        self.finalize_backup(
            &backup_id,
            &backup_revision,
            entries,
            rollback_owner(&owner, "reattach-backup")?,
        )?;
        Ok(PolicyMaintenanceOutcome {
            operation_id: plan.operation_id.clone(),
            backup_id,
            affected_targets: vec![from_target.clone(), to_target.clone()],
            lifecycle: PolicyMaintenanceLifecycle::Active,
        })
    }

    fn apply_discard(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        target: &PolicyTarget,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        let policy = self
            .policies
            .load(target)?
            .ok_or(PolicyMaintenanceError::PolicyNotFound)?;
        let record = self
            .load_record_snapshot(target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        let mut entries = vec![self.backup_entry(target)?];
        let (backup_revision, backup_id) =
            self.write_backup(plan, approval, &entries, owner.clone())?;
        self.policies.remove_if_revision(target, &policy.revision)?;
        let mut tombstone = record.value;
        tombstone.review = approval.review();
        tombstone.lifecycle = PolicyMaintenanceLifecycle::Discarded;
        tombstone.active_policy_revision = None;
        tombstone.active_policy_fingerprint = None;
        tombstone.last_operation_id.clone_from(&plan.operation_id);
        self.sign_record(&mut tombstone)?;
        let record_revision = match self.write_record(
            &tombstone,
            Some(&record.revision),
            rollback_owner(&owner, "discard-record")?,
        ) {
            Ok(revision) => revision,
            Err(error) => {
                self.policies
                    .save(
                        target,
                        &policy.policy,
                        None,
                        rollback_owner(&owner, "discard-policy")?,
                    )
                    .map_err(|rollback| {
                        PolicyMaintenanceError::RecoveryRequired(format!(
                            "{error}; discard rollback failed: {rollback}"
                        ))
                    })?;
                return Err(error);
            }
        };
        entries[0].post_policy_revision = None;
        entries[0].post_record_revision = Some(record_revision);
        self.finalize_backup(
            &backup_id,
            &backup_revision,
            entries,
            rollback_owner(&owner, "discard-backup")?,
        )?;
        Ok(PolicyMaintenanceOutcome {
            operation_id: plan.operation_id.clone(),
            backup_id,
            affected_targets: vec![target.clone()],
            lifecycle: PolicyMaintenanceLifecycle::Discarded,
        })
    }

    fn apply_cleanup(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        target: &PolicyTarget,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        let record = self
            .load_record_snapshot(target)?
            .ok_or(PolicyMaintenanceError::RecordNotFound)?;
        let mut entries = vec![self.backup_entry(target)?];
        let (backup_revision, backup_id) =
            self.write_backup(plan, approval, &entries, owner.clone())?;
        self.record_store(target)?
            .remove_if_revision(&record.revision)?;
        entries[0].post_policy_revision = None;
        entries[0].post_record_revision = None;
        self.finalize_backup(
            &backup_id,
            &backup_revision,
            entries,
            rollback_owner(&owner, "cleanup-backup")?,
        )?;
        Ok(PolicyMaintenanceOutcome {
            operation_id: plan.operation_id.clone(),
            backup_id,
            affected_targets: vec![target.clone()],
            lifecycle: record.value.lifecycle,
        })
    }

    fn apply_restore(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        owner: OwnerGeneration,
        backup_id: &str,
    ) -> Result<PolicyMaintenanceOutcome, PolicyMaintenanceError> {
        let source = self
            .load_backup_snapshot(backup_id)?
            .ok_or(PolicyMaintenanceError::BackupNotFound)?;
        let mut rollback_entries = source
            .value
            .entries
            .iter()
            .map(|entry| self.backup_entry(&entry.target))
            .collect::<Result<Vec<_>, _>>()?;
        let (restore_backup_revision, restore_backup_id) =
            self.write_backup(plan, approval, &rollback_entries, owner.clone())?;
        let mut affected_targets = Vec::with_capacity(source.value.entries.len());
        for entry in &source.value.entries {
            let policy_revision =
                self.restore_policy_entry(entry, rollback_owner(&owner, "restore-policy")?)?;
            let record_revision = self.restore_record_entry(
                entry,
                policy_revision.as_ref(),
                approval,
                &plan.operation_id,
                rollback_owner(&owner, "restore-record")?,
            )?;
            let rollback = rollback_entries
                .iter_mut()
                .find(|candidate| candidate.target == entry.target)
                .ok_or(PolicyMaintenanceError::InvalidBackup)?;
            rollback.post_policy_revision = policy_revision;
            rollback.post_record_revision = record_revision;
            affected_targets.push(entry.target.clone());
        }
        self.finalize_backup(
            &restore_backup_id,
            &restore_backup_revision,
            rollback_entries,
            rollback_owner(&owner, "restore-backup")?,
        )?;
        let lifecycle = source
            .value
            .entries
            .iter()
            .find_map(|entry| {
                entry
                    .prior_record
                    .as_ref()
                    .map(|record| record.lifecycle.clone())
            })
            .unwrap_or(PolicyMaintenanceLifecycle::Discarded);
        Ok(PolicyMaintenanceOutcome {
            operation_id: plan.operation_id.clone(),
            backup_id: restore_backup_id,
            affected_targets,
            lifecycle,
        })
    }

    fn classification(
        &self,
        record: &PolicyMaintenanceRecord,
        candidate: Option<&WorkspacePhysicalEvidence>,
    ) -> Result<WorkspacePolicyClassification, PolicyMaintenanceError> {
        if let Some(candidate) = candidate {
            return Ok(classify_workspace(&record.workspace, Some(candidate)));
        }
        let recorded_path = &record.workspace.workspace_root.canonical_path;
        if !recorded_path.exists() {
            return Ok(WorkspacePolicyClassification::Deleted);
        }
        let observed = capture_workspace_physical_evidence(recorded_path)?;
        Ok(classify_workspace(&record.workspace, Some(&observed)))
    }

    fn backup_entry(
        &self,
        target: &PolicyTarget,
    ) -> Result<PolicyBackupEntry, PolicyMaintenanceError> {
        let policy = self.policies.load(target)?;
        let record = self.load_record_snapshot(target)?;
        Ok(PolicyBackupEntry {
            target: target.clone(),
            prior_policy: policy.as_ref().map(|snapshot| snapshot.policy.clone()),
            prior_policy_revision: policy.map(|snapshot| snapshot.revision),
            prior_record: record.as_ref().map(|snapshot| snapshot.value.clone()),
            prior_record_revision: record.map(|snapshot| snapshot.revision),
            post_policy_revision: None,
            post_record_revision: None,
        })
    }

    fn write_backup(
        &self,
        plan: &PolicyMaintenancePlan,
        approval: &PolicyMaintenanceApproval,
        entries: &[PolicyBackupEntry],
        owner: OwnerGeneration,
    ) -> Result<(StateRevision, String), PolicyMaintenanceError> {
        let backup_id = format!("policy-backup-{}", &plan.plan_fingerprint[..32]);
        let revision = self.write_named_backup(
            &backup_id,
            &plan.operation_id,
            &plan.plan_fingerprint,
            approval,
            entries,
            owner,
        )?;
        Ok((revision, backup_id))
    }

    #[allow(clippy::too_many_arguments)]
    fn write_named_backup(
        &self,
        backup_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        approval: &PolicyMaintenanceApproval,
        entries: &[PolicyBackupEntry],
        owner: OwnerGeneration,
    ) -> Result<StateRevision, PolicyMaintenanceError> {
        if self.load_backup_snapshot(backup_id)?.is_some() {
            return Err(PolicyMaintenanceError::BackupAlreadyExists);
        }
        let mut backup = PolicyMaintenanceBackup {
            schema_version: POLICY_MAINTENANCE_BACKUP_SCHEMA_VERSION,
            backup_id: backup_id.to_string(),
            operation_id: operation_id.to_string(),
            plan_fingerprint: plan_fingerprint.to_string(),
            review: approval.review(),
            entries: entries.to_vec(),
            finalized: false,
            authentication_key_id: self.authentication_key.key_id().to_string(),
            authentication_tag: String::new(),
        };
        self.sign_backup(&mut backup)?;
        let revision = self
            .backup_store(backup_id)?
            .compare_and_swap(None, owner, &backup)?;
        Ok(revision)
    }

    fn finalize_backup(
        &self,
        backup_id: &str,
        expected: &StateRevision,
        entries: Vec<PolicyBackupEntry>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, PolicyMaintenanceError> {
        let snapshot = self
            .load_backup_snapshot(backup_id)?
            .ok_or(PolicyMaintenanceError::BackupNotFound)?;
        if &snapshot.revision != expected || snapshot.value.finalized {
            return Err(PolicyMaintenanceError::BackupDrift);
        }
        let mut backup = snapshot.value;
        backup.entries = entries;
        backup.finalized = true;
        self.sign_backup(&mut backup)?;
        self.backup_store(backup_id)?
            .compare_and_swap(Some(expected), owner, &backup)
            .map_err(Into::into)
    }

    fn rollback_new_target(
        &self,
        target: &PolicyTarget,
        policy_revision: &StateRevision,
        record_revision: &StateRevision,
        owner: &OwnerGeneration,
    ) -> Result<(), PolicyMaintenanceError> {
        self.record_store(target)?
            .remove_if_revision(record_revision)?;
        self.policies.restore_checkpoint(
            target,
            None,
            policy_revision,
            rollback_owner(owner, "reattach-new-target")?,
        )?;
        Ok(())
    }

    fn restore_policy_entry(
        &self,
        entry: &PolicyBackupEntry,
        owner: OwnerGeneration,
    ) -> Result<Option<StateRevision>, PolicyMaintenanceError> {
        let current = self.policies.load(&entry.target)?;
        ensure_revision(
            current.as_ref().map(|snapshot| &snapshot.revision),
            entry.post_policy_revision.as_ref(),
        )?;
        match (current, entry.prior_policy.as_ref()) {
            (Some(current), Some(prior)) => self
                .policies
                .save(&entry.target, prior, Some(&current.revision), owner)
                .map(Some)
                .map_err(Into::into),
            (Some(current), None) => {
                self.policies
                    .remove_if_revision(&entry.target, &current.revision)?;
                Ok(None)
            }
            (None, Some(prior)) => self
                .policies
                .save(&entry.target, prior, None, owner)
                .map(Some)
                .map_err(Into::into),
            (None, None) => Ok(None),
        }
    }

    fn restore_record_entry(
        &self,
        entry: &PolicyBackupEntry,
        restored_policy_revision: Option<&StateRevision>,
        approval: &PolicyMaintenanceApproval,
        operation_id: &str,
        owner: OwnerGeneration,
    ) -> Result<Option<StateRevision>, PolicyMaintenanceError> {
        let current = self.load_record_raw(&entry.target)?;
        ensure_revision(
            current.as_ref().map(|snapshot| &snapshot.revision),
            entry.post_record_revision.as_ref(),
        )?;
        match (current, entry.prior_record.as_ref()) {
            (Some(current), Some(prior)) => {
                let mut restored = prior.clone();
                restored.review = approval.review();
                restored.last_operation_id = operation_id.to_string();
                if restored.lifecycle == PolicyMaintenanceLifecycle::Active {
                    restored.active_policy_revision = restored_policy_revision.cloned();
                    restored.active_policy_fingerprint = entry
                        .prior_policy
                        .as_ref()
                        .map(policy_fingerprint)
                        .transpose()?;
                }
                self.sign_record(&mut restored)?;
                self.write_record(&restored, Some(&current.revision), owner)
                    .map(Some)
            }
            (Some(current), None) => {
                self.record_store(&entry.target)?
                    .remove_if_revision(&current.revision)?;
                Ok(None)
            }
            (None, Some(prior)) => {
                let mut restored = prior.clone();
                restored.review = approval.review();
                restored.last_operation_id = operation_id.to_string();
                if restored.lifecycle == PolicyMaintenanceLifecycle::Active {
                    restored.active_policy_revision = restored_policy_revision.cloned();
                    restored.active_policy_fingerprint = entry
                        .prior_policy
                        .as_ref()
                        .map(policy_fingerprint)
                        .transpose()?;
                }
                self.sign_record(&mut restored)?;
                self.write_record(&restored, None, owner).map(Some)
            }
            (None, None) => Ok(None),
        }
    }

    fn sign_record(
        &self,
        record: &mut PolicyMaintenanceRecord,
    ) -> Result<(), PolicyMaintenanceError> {
        record.authentication_key_id = self.authentication_key.key_id().to_string();
        record.authentication_tag.clear();
        let payload = serde_json::to_vec(record)
            .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
        record.authentication_tag = self
            .authentication_key
            .authenticate_purpose(POLICY_MAINTENANCE_RECORD_PURPOSE, &payload)
            .map_err(PolicyMaintenanceError::AuthenticationKey)?;
        Ok(())
    }

    fn verify_record(
        &self,
        requested_target: &PolicyTarget,
        record: &PolicyMaintenanceRecord,
    ) -> Result<(), PolicyMaintenanceError> {
        if record.schema_version != POLICY_MAINTENANCE_RECORD_SCHEMA_VERSION
            || record.authentication_key_id != self.authentication_key.key_id()
            || &record.target != requested_target
            || record.record_id != record_id(requested_target)?
        {
            return Err(PolicyMaintenanceError::InvalidRecord);
        }
        let mut unsigned = record.clone();
        let tag = std::mem::take(&mut unsigned.authentication_tag);
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
        self.authentication_key
            .verify_purpose(POLICY_MAINTENANCE_RECORD_PURPOSE, &payload, &tag)
            .map_err(|_| PolicyMaintenanceError::AuthenticationFailed)?;
        match requested_target {
            PolicyTarget::Workspace {
                repository_key,
                workspace_key,
            } if repository_key == &record.workspace.repository_key
                && workspace_key == &record.workspace.workspace_key => {}
            _ => return Err(PolicyMaintenanceError::InvalidRecord),
        }
        Ok(())
    }

    fn verify_record_live_binding(
        &self,
        record: &PolicyMaintenanceRecord,
    ) -> Result<(), PolicyMaintenanceError> {
        let policy = self.policies.load(&record.target)?;
        match &record.lifecycle {
            PolicyMaintenanceLifecycle::Active => {
                let policy = policy.ok_or(PolicyMaintenanceError::PolicyNotFound)?;
                if record.active_policy_revision.as_ref() != Some(&policy.revision)
                    || record.active_policy_fingerprint.as_deref()
                        != Some(&policy_fingerprint(&policy.policy)?)
                {
                    return Err(PolicyMaintenanceError::RecordPolicyDrift);
                }
            }
            PolicyMaintenanceLifecycle::Reattached { .. }
            | PolicyMaintenanceLifecycle::Discarded => {
                if policy.is_some()
                    || record.active_policy_revision.is_some()
                    || record.active_policy_fingerprint.is_some()
                {
                    return Err(PolicyMaintenanceError::RecordPolicyDrift);
                }
            }
        }
        Ok(())
    }

    fn write_record(
        &self,
        record: &PolicyMaintenanceRecord,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, PolicyMaintenanceError> {
        self.verify_record(&record.target, record)?;
        self.record_store(&record.target)?
            .compare_and_swap(expected, owner, record)
            .map_err(Into::into)
    }

    fn load_record_raw(
        &self,
        target: &PolicyTarget,
    ) -> Result<Option<StateSnapshot<PolicyMaintenanceRecord>>, PolicyMaintenanceError> {
        let snapshot = self
            .record_store(target)?
            .load::<PolicyMaintenanceRecord>()?;
        if let Some(snapshot) = &snapshot {
            self.verify_record(target, &snapshot.value)?;
        }
        Ok(snapshot)
    }

    fn load_record_snapshot(
        &self,
        target: &PolicyTarget,
    ) -> Result<Option<StateSnapshot<PolicyMaintenanceRecord>>, PolicyMaintenanceError> {
        let snapshot = self.load_record_raw(target)?;
        if let Some(snapshot) = &snapshot {
            self.verify_record_live_binding(&snapshot.value)?;
        }
        Ok(snapshot)
    }

    fn sign_backup(
        &self,
        backup: &mut PolicyMaintenanceBackup,
    ) -> Result<(), PolicyMaintenanceError> {
        backup.authentication_key_id = self.authentication_key.key_id().to_string();
        backup.authentication_tag.clear();
        let payload = serde_json::to_vec(backup)
            .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
        backup.authentication_tag = self
            .authentication_key
            .authenticate_purpose(POLICY_MAINTENANCE_BACKUP_PURPOSE, &payload)
            .map_err(PolicyMaintenanceError::AuthenticationKey)?;
        Ok(())
    }

    fn verify_backup(
        &self,
        requested_id: &str,
        backup: &PolicyMaintenanceBackup,
    ) -> Result<(), PolicyMaintenanceError> {
        if backup.schema_version != POLICY_MAINTENANCE_BACKUP_SCHEMA_VERSION
            || backup.backup_id != requested_id
            || backup.entries.is_empty()
            || backup.authentication_key_id != self.authentication_key.key_id()
        {
            return Err(PolicyMaintenanceError::InvalidBackup);
        }
        let mut unsigned = backup.clone();
        let tag = std::mem::take(&mut unsigned.authentication_tag);
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
        self.authentication_key
            .verify_purpose(POLICY_MAINTENANCE_BACKUP_PURPOSE, &payload, &tag)
            .map_err(|_| PolicyMaintenanceError::AuthenticationFailed)?;
        Ok(())
    }

    fn load_backup_snapshot(
        &self,
        backup_id: &str,
    ) -> Result<Option<StateSnapshot<PolicyMaintenanceBackup>>, PolicyMaintenanceError> {
        validate_component("backup id", backup_id)?;
        let snapshot = self
            .backup_store(backup_id)?
            .load::<PolicyMaintenanceBackup>()?;
        if let Some(snapshot) = &snapshot {
            self.verify_backup(backup_id, &snapshot.value)?;
        }
        Ok(snapshot)
    }

    fn record_store(
        &self,
        target: &PolicyTarget,
    ) -> Result<AtomicJsonStore, PolicyMaintenanceError> {
        Ok(AtomicJsonStore::new(
            self.app_state_root
                .join("policies")
                .join("maintenance")
                .join("records")
                .join(format!("{}.json", record_id(target)?)),
            POLICY_MAINTENANCE_STATE_SCHEMA_VERSION,
        ))
    }

    fn backup_store(&self, backup_id: &str) -> Result<AtomicJsonStore, PolicyMaintenanceError> {
        validate_component("backup id", backup_id)?;
        Ok(AtomicJsonStore::new(
            self.app_state_root
                .join("backups")
                .join("policies")
                .join(format!("{backup_id}.json")),
            POLICY_MAINTENANCE_STATE_SCHEMA_VERSION,
        ))
    }
}

#[derive(Debug)]
struct LegacyPolicySnapshot {
    path: PathBuf,
    fingerprint: String,
    identity: String,
    policy: ScopePolicy,
}

fn read_legacy_policy(project_root: &Path) -> Result<LegacyPolicySnapshot, PolicyMaintenanceError> {
    let canonical_root =
        fs::canonicalize(project_root).map_err(|error| io_error(project_root, error))?;
    let path = get_workspace_policy_path(&canonical_root);
    let parent = path.parent().ok_or(PolicyMaintenanceError::InvalidSource)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| io_error(parent, error))?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(PolicyMaintenanceError::InvalidSource);
    }
    let before = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() > MAX_LEGACY_POLICY_BYTES
    {
        return Err(PolicyMaintenanceError::InvalidSource);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.nlink() != 1 {
            return Err(PolicyMaintenanceError::InvalidSource);
        }
    }
    let first = fs::read(&path).map_err(|error| io_error(&path, error))?;
    let after = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
    let second = fs::read(&path).map_err(|error| io_error(&path, error))?;
    let before_identity = source_metadata_identity(&before)?;
    let after_identity = source_metadata_identity(&after)?;
    if before_identity != after_identity || first != second {
        return Err(PolicyMaintenanceError::SourceDrift);
    }
    let policy = serde_json::from_slice(&first)
        .map_err(|error| PolicyMaintenanceError::InvalidSourceJson(error.to_string()))?;
    Ok(LegacyPolicySnapshot {
        path,
        fingerprint: encode_lower_hex(&Sha256::digest(&first)),
        identity: before_identity,
        policy,
    })
}

fn source_metadata_identity(metadata: &fs::Metadata) -> Result<String, PolicyMaintenanceError> {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-policy-migration-source-v1\0");
    hasher.update(metadata.len().to_le_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        hasher.update(metadata.mtime().to_le_bytes());
        hasher.update(metadata.mtime_nsec().to_le_bytes());
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .map_err(|error| PolicyMaintenanceError::SourceMetadata(error.to_string()))?;
        let duration = modified
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| PolicyMaintenanceError::SourceMetadata(error.to_string()))?;
        hasher.update(duration.as_secs().to_le_bytes());
        hasher.update(duration.subsec_nanos().to_le_bytes());
    }
    Ok(encode_lower_hex(&hasher.finalize()))
}

fn classify_workspace(
    recorded: &WorkspacePhysicalEvidence,
    candidate: Option<&WorkspacePhysicalEvidence>,
) -> WorkspacePolicyClassification {
    let Some(candidate) = candidate else {
        return WorkspacePolicyClassification::Deleted;
    };
    if !recorded.is_reliable_git_workspace() || !candidate.is_reliable_git_workspace() {
        return WorkspacePolicyClassification::Unknown;
    }
    if recorded.same_physical_workspace(candidate) {
        if recorded.workspace_root.canonical_path == candidate.workspace_root.canonical_path
            && recorded.repository_key == candidate.repository_key
            && recorded.workspace_key == candidate.workspace_key
        {
            WorkspacePolicyClassification::Attached
        } else {
            WorkspacePolicyClassification::Moved
        }
    } else if recorded.workspace_root.canonical_path == candidate.workspace_root.canonical_path {
        WorkspacePolicyClassification::Recreated
    } else {
        WorkspacePolicyClassification::Unknown
    }
}

fn seal_plan(
    action: PolicyMaintenanceAction,
    expected_policy_revision: Option<StateRevision>,
    expected_record_revision: Option<StateRevision>,
) -> Result<PolicyMaintenancePlan, PolicyMaintenanceError> {
    let mut plan = PolicyMaintenancePlan {
        schema_version: POLICY_MAINTENANCE_PLAN_SCHEMA_VERSION,
        operation_id: String::new(),
        action,
        expected_policy_revision,
        expected_record_revision,
        plan_fingerprint: String::new(),
    };
    let fingerprint = calculate_plan_fingerprint(&plan)?;
    plan.operation_id = format!("policy-maintenance-{}", &fingerprint[..32]);
    plan.plan_fingerprint = calculate_plan_fingerprint(&plan)?;
    plan.operation_id = format!("policy-maintenance-{}", &plan.plan_fingerprint[..32]);
    let final_fingerprint = calculate_plan_fingerprint(&plan)?;
    if final_fingerprint != plan.plan_fingerprint {
        plan.plan_fingerprint = final_fingerprint;
        plan.operation_id = format!("policy-maintenance-{}", &plan.plan_fingerprint[..32]);
    }
    Ok(plan)
}

fn calculate_plan_fingerprint(
    plan: &PolicyMaintenancePlan,
) -> Result<String, PolicyMaintenanceError> {
    let mut unsigned = plan.clone();
    unsigned.plan_fingerprint.clear();
    unsigned.operation_id.clear();
    let payload = serde_json::to_vec(&unsigned)
        .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
    Ok(encode_lower_hex(&Sha256::digest(
        [
            b"unpin-policy-maintenance-plan-v1\0".as_slice(),
            payload.as_slice(),
        ]
        .concat(),
    )))
}

fn validate_approval(
    plan: &PolicyMaintenancePlan,
    approval: &PolicyMaintenanceApproval,
) -> Result<(), PolicyMaintenanceError> {
    if !approval.confirmed
        || approval.plan_fingerprint != plan.plan_fingerprint
        || approval.actor_id.trim().is_empty()
        || approval.actor_id.len() > 512
        || approval.decision_digest.len() != 64
        || !approval
            .decision_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PolicyMaintenanceError::ApprovalRejected);
    }
    Ok(())
}

fn validate_external_approval(
    reviewed_plan_fingerprint: &str,
    approval: &PolicyMaintenanceApproval,
) -> Result<(), PolicyMaintenanceError> {
    if reviewed_plan_fingerprint.len() != 64
        || approval.plan_fingerprint != reviewed_plan_fingerprint
        || !approval.confirmed
        || approval.actor_id.trim().is_empty()
        || approval.decision_digest.len() != 64
    {
        return Err(PolicyMaintenanceError::ApprovalRejected);
    }
    validate_approval(
        &PolicyMaintenancePlan {
            schema_version: POLICY_MAINTENANCE_PLAN_SCHEMA_VERSION,
            operation_id: "external-policy-change".to_string(),
            action: PolicyMaintenanceAction::Restore {
                backup_id: "external".to_string(),
            },
            expected_policy_revision: None,
            expected_record_revision: None,
            plan_fingerprint: reviewed_plan_fingerprint.to_string(),
        },
        approval,
    )
}

fn ensure_revision(
    actual: Option<&StateRevision>,
    expected: Option<&StateRevision>,
) -> Result<(), PolicyMaintenanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PolicyMaintenanceError::PlanDrift)
    }
}

fn policy_fingerprint(policy: &ScopePolicy) -> Result<String, PolicyMaintenanceError> {
    let payload = serde_json::to_vec(policy)
        .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
    Ok(encode_lower_hex(&Sha256::digest(
        [b"unpin-policy-value-v1\0".as_slice(), payload.as_slice()].concat(),
    )))
}

fn record_id(target: &PolicyTarget) -> Result<String, PolicyMaintenanceError> {
    let payload = serde_json::to_vec(target)
        .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
    Ok(format!(
        "policy-record-{}",
        &encode_lower_hex(&Sha256::digest(
            [
                b"unpin-policy-maintenance-target-v1\0".as_slice(),
                payload.as_slice(),
            ]
            .concat(),
        ))[..32]
    ))
}

fn external_backup_id(
    operation_id: &str,
    plan_fingerprint: &str,
    target: &PolicyTarget,
) -> Result<String, PolicyMaintenanceError> {
    let target = serde_json::to_vec(target)
        .map_err(|error| PolicyMaintenanceError::Serialization(error.to_string()))?;
    Ok(format!(
        "policy-backup-{}",
        &encode_lower_hex(&Sha256::digest(
            [
                b"unpin-external-policy-change-backup-v1\0".as_slice(),
                operation_id.as_bytes(),
                b"\0",
                plan_fingerprint.as_bytes(),
                b"\0",
                target.as_slice(),
            ]
            .concat(),
        ))[..32]
    ))
}

fn validate_component(label: &'static str, value: &str) -> Result<(), PolicyMaintenanceError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(PolicyMaintenanceError::InvalidComponent { label })
    } else {
        Ok(())
    }
}

fn rollback_owner(
    owner: &OwnerGeneration,
    suffix: &str,
) -> Result<OwnerGeneration, PolicyMaintenanceError> {
    OwnerGeneration::new(
        format!("{}-{suffix}", owner.owner_id),
        owner.generation.saturating_add(1),
    )
    .map_err(Into::into)
}

fn io_error(path: &Path, error: io::Error) -> PolicyMaintenanceError {
    PolicyMaintenanceError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[derive(Debug)]
pub enum PolicyMaintenanceError {
    Policy(PolicyStoreError),
    State(StateError),
    Workspace(crate::state::workspace::WorkspaceIdentityError),
    Io { path: PathBuf, message: String },
    Serialization(String),
    InvalidSourceJson(String),
    SourceMetadata(String),
    InvalidSource,
    SourceDrift,
    DestinationExists,
    RecordNotFound,
    PolicyNotFound,
    BackupNotFound,
    BackupAlreadyExists,
    BackupIncomplete,
    BackupDrift,
    InvalidPlan,
    PlanFingerprintMismatch,
    PlanDrift,
    ApprovalRejected,
    InvalidRecord,
    InvalidBackup,
    AuthenticationFailed,
    AuthenticationKey(String),
    RecordPolicyDrift,
    InvalidLifecycle,
    WorkspaceStillAttached,
    ReattachNotProven,
    InvalidComponent { label: &'static str },
    RecoveryRequired(String),
}

impl fmt::Display for PolicyMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::Workspace(error) => error.fmt(formatter),
            Self::Io { path, message } => {
                write!(
                    formatter,
                    "policy maintenance I/O failed at {}: {message}",
                    path.display()
                )
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "policy maintenance serialization failed: {message}"
                )
            }
            Self::InvalidSourceJson(message) => {
                write!(
                    formatter,
                    "workspace policy source is invalid JSON: {message}"
                )
            }
            Self::SourceMetadata(message) => {
                write!(
                    formatter,
                    "workspace policy metadata is unavailable: {message}"
                )
            }
            Self::InvalidSource => formatter.write_str("workspace policy source is unsafe"),
            Self::SourceDrift => {
                formatter.write_str("workspace policy source changed during review")
            }
            Self::DestinationExists => {
                formatter.write_str("policy maintenance destination already exists")
            }
            Self::RecordNotFound => formatter.write_str("policy maintenance record was not found"),
            Self::PolicyNotFound => formatter.write_str("bound policy was not found"),
            Self::BackupNotFound => formatter.write_str("policy backup was not found"),
            Self::BackupAlreadyExists => formatter.write_str("policy backup already exists"),
            Self::BackupIncomplete => formatter.write_str("policy backup is incomplete"),
            Self::BackupDrift => formatter.write_str("policy backup changed"),
            Self::InvalidPlan => formatter.write_str("policy maintenance plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("policy maintenance plan fingerprint mismatch")
            }
            Self::PlanDrift => formatter.write_str("policy maintenance plan inputs changed"),
            Self::ApprovalRejected => {
                formatter.write_str("policy maintenance approval does not match the reviewed plan")
            }
            Self::InvalidRecord => formatter.write_str("policy maintenance record is invalid"),
            Self::InvalidBackup => formatter.write_str("policy maintenance backup is invalid"),
            Self::AuthenticationFailed => {
                formatter.write_str("policy maintenance authentication failed")
            }
            Self::AuthenticationKey(message) => {
                write!(formatter, "policy authentication key failed: {message}")
            }
            Self::RecordPolicyDrift => {
                formatter.write_str("policy maintenance record no longer matches the live policy")
            }
            Self::InvalidLifecycle => {
                formatter.write_str("policy lifecycle does not allow this action")
            }
            Self::WorkspaceStillAttached => {
                formatter.write_str("attached workspace policy cannot be discarded")
            }
            Self::ReattachNotProven => formatter.write_str(
                "workspace reattachment requires reliable proof of the same physical checkout",
            ),
            Self::InvalidComponent { label } => write!(formatter, "invalid {label}"),
            Self::RecoveryRequired(message) => {
                write!(formatter, "policy maintenance recovery required: {message}")
            }
        }
    }
}

impl std::error::Error for PolicyMaintenanceError {}

impl From<PolicyStoreError> for PolicyMaintenanceError {
    fn from(error: PolicyStoreError) -> Self {
        Self::Policy(error)
    }
}

impl From<StateError> for PolicyMaintenanceError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<crate::state::workspace::WorkspaceIdentityError> for PolicyMaintenanceError {
    fn from(error: crate::state::workspace::WorkspaceIdentityError) -> Self {
        Self::Workspace(error)
    }
}
