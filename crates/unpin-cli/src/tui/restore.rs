use std::path::Path;

use serde_json::json;
use unpin_core::approval::ControlApprovalContext;
use unpin_core::control::ControlOperationStatus;
use unpin_core::control_operation::{
    ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle, DurableControlError,
};
use unpin_core::mutation::{
    BackupAuthenticationKey, BackupDeletionPlan, BackupSummary, RestoreControlError,
    RestoreControlPlan, RestoreController, RestoreStatus, delete_backup, plan_backup_deletion,
};
use unpin_core::sessions::SessionAuthorityKey;

use crate::{credentials, unix_now};

use super::{WorkflowPhase, backup_authentication_label, backup_display_label};

#[derive(Debug, Clone)]
pub(super) struct ReviewedRestorePlan {
    pub(super) plan: RestoreControlPlan,
    pub(super) envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct RestoreWorkflow {
    pub(super) backups: Vec<BackupSummary>,
    pub(super) operations: Vec<ControlOperationStatus>,
    pub(super) selected: usize,
    pub(super) reviewed: Option<ReviewedRestorePlan>,
    pub(super) deletion: Option<BackupDeletionPlan>,
    pub(super) phase: WorkflowPhase,
    pub(super) last_envelope: Option<ControlOperationEnvelope>,
    pub(super) last_error: Option<String>,
}

impl RestoreWorkflow {
    pub(super) fn new(
        backups: Vec<BackupSummary>,
        operations: Vec<ControlOperationStatus>,
    ) -> Self {
        Self {
            backups,
            operations,
            selected: 0,
            reviewed: None,
            deletion: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    pub(super) fn select_next(&mut self) {
        if !self.backups.is_empty() {
            self.selected = (self.selected + 1) % self.backups.len();
            self.reset_review();
        }
    }

    pub(super) fn select_previous(&mut self) {
        if !self.backups.is_empty() {
            self.selected = if self.selected == 0 {
                self.backups.len() - 1
            } else {
                self.selected - 1
            };
            self.reset_review();
        }
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.backups
            .iter()
            .enumerate()
            .map(|(index, backup)| {
                format!(
                    "{} {} entries={} restorable={} auth={}",
                    if index == self.selected { ">" } else { " " },
                    backup_display_label(backup),
                    backup.item_count,
                    backup.restorable,
                    backup_authentication_label(backup.authentication)
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let recovery_count = self
            .operations
            .iter()
            .filter(|operation| operation.recovery_required)
            .count();
        let mut details = vec![format!(
            "Restore: backups={} operations={} recovery={} phase={}",
            self.backups.len(),
            self.operations.len(),
            recovery_count,
            self.phase.label()
        )];
        if let Some(backup) = self.backups.get(self.selected) {
            details.push(format!("selected: {}", backup.backup_id));
            details.push(format!("target: {}", backup_display_label(backup)));
            details.push(format!("created: {}", backup.created_at));
            details.push(format!("targets: {}", backup.paths.len()));
        } else {
            details.push("selected: none".to_string());
        }
        for operation in &self.operations {
            details.push(format!(
                "operation: {} {} {:?} recovery={}",
                operation.operation_id,
                operation.operation_kind,
                operation.lifecycle,
                operation.recovery_required
            ));
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.plan.plan_fingerprint));
            details.push(format!(
                "resources: {}",
                reviewed.plan.affected_resources.len()
            ));
        }
        if let Some(deletion) = &self.deletion {
            details.push(format!("delete backup: {}", deletion.backup_id));
        }
        if let Some(envelope) = &self.last_envelope {
            details.push(format!(
                "result: {:?} {}",
                envelope.lifecycle, envelope.operation_id
            ));
        }
        if let Some(error) = &self.last_error {
            details.push(format!("error: {error}"));
        }
        details
    }

    pub(super) fn plan(
        &mut self,
        app_state_root: &Path,
        context: &ControlApprovalContext,
        backup_key: Option<&BackupAuthenticationKey>,
    ) -> Result<&ControlOperationEnvelope, String> {
        let backup = self
            .backups
            .get(self.selected)
            .ok_or_else(|| "no backup selected".to_string())?;
        let plan = RestoreController::new(app_state_root)
            .plan(&backup.backup_id, context, backup_key)
            .map_err(|error| error.to_string())?;
        let expectation = plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            plan.activation,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Review authenticated backup and every affected target before restore."
                    .to_string(),
            }),
            false,
            plan.providers.clone(),
            json!({"plan": plan}),
        );
        self.reviewed = Some(ReviewedRestorePlan { plan, envelope });
        self.deletion = None;
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(&self.reviewed.as_ref().expect("reviewed plan set").envelope)
    }

    pub(super) fn confirm(&mut self) -> bool {
        if self.reviewed.is_none() && self.deletion.is_none() {
            return false;
        }
        self.phase = WorkflowPhase::Confirmed;
        true
    }

    pub(super) fn plan_deletion(&mut self, app_state_root: &Path) -> Result<(), String> {
        let backup = self
            .backups
            .get(self.selected)
            .ok_or_else(|| "no backup selected".to_string())?;
        self.deletion = Some(plan_backup_deletion(app_state_root, &backup.backup_id)?);
        self.reviewed = None;
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(())
    }

    pub(super) fn has_pending_deletion(&self) -> bool {
        self.deletion.is_some()
    }

    pub(super) fn deletion_is_confirmed(&self) -> bool {
        self.deletion.is_some() && self.phase == WorkflowPhase::Confirmed
    }

    pub(super) fn apply_deletion(
        &mut self,
        app_state_root: &Path,
    ) -> Result<unpin_core::mutation::BackupDeletionResult, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("backup deletion must be confirmed before apply".to_string());
        }
        let plan = self
            .deletion
            .as_ref()
            .ok_or_else(|| "backup deletion plan is missing".to_string())?;
        let result = delete_backup(app_state_root, plan)?;
        self.deletion = None;
        self.phase = WorkflowPhase::Applied;
        self.last_error = None;
        Ok(result)
    }

    pub(super) fn replace_backups(&mut self, backups: Vec<BackupSummary>) {
        self.backups = backups;
        self.selected = self.selected.min(self.backups.len().saturating_sub(1));
        self.reset_review();
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        backup_key: &BackupAuthenticationKey,
        fixture_mode: bool,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("restore plan must be confirmed before apply".to_string());
        }
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "restore plan is missing".to_string())?;
        let mut fixture_paths = vec![app_state_root, project_root];
        fixture_paths.extend(
            reviewed
                .plan
                .affected_resources
                .iter()
                .map(|resource| Path::new(resource.path.as_str())),
        );
        unpin_core::fixture::require_fixture_write_sandbox(fixture_mode, fixture_paths)?;
        let expectation = reviewed
            .plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let authorization = credentials::authorize_reviewed_control_decision(
            fixture_mode,
            app_state_root,
            &expectation,
            &reviewed.plan.plan_fingerprint,
            Some(&reviewed.plan.plan_fingerprint),
            "unpin-tui-restore-approval",
            unix_now(),
        )?;
        let result = match RestoreController::with_session_authority_key(
            app_state_root,
            authority_key.clone(),
        )
        .apply(
            &reviewed.plan,
            authorization,
            context,
            Some(backup_key.clone()),
        ) {
            Ok(result) => result,
            Err(error) => {
                if matches!(
                    &error,
                    RestoreControlError::Durable(DurableControlError::RecoveryRequired(_))
                ) {
                    self.phase = WorkflowPhase::RecoveryRequired;
                }
                return Err(error.to_string());
            }
        };
        let lifecycle = if result.status == RestoreStatus::Restored {
            ControlOperationLifecycle::Applied
        } else {
            ControlOperationLifecycle::RecoveryRequired
        };
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &expectation,
            &reviewed.plan.plan_fingerprint,
            reviewed.plan.activation,
            lifecycle,
            None,
            lifecycle == ControlOperationLifecycle::RecoveryRequired,
            reviewed.plan.providers.clone(),
            json!({"result": result}),
        ));
        self.phase = if lifecycle == ControlOperationLifecycle::RecoveryRequired {
            WorkflowPhase::RecoveryRequired
        } else {
            WorkflowPhase::Applied
        };
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
    }

    pub(super) fn reset_review(&mut self) {
        self.reviewed = None;
        self.deletion = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }
}
