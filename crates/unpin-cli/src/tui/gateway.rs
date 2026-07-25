use std::path::Path;

use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    control::GatewayControlStatus,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    mutation::BackupAuthenticationKey,
    profiles::PolicyTarget,
    sessions::{
        GatewayModeAction, GatewayModeApplyStatus, GatewayRoutingState, GatewayWorkflowController,
        GatewayWorkflowError, GatewayWorkflowPlan, SessionAuthorityKey,
    },
};

use crate::{credentials, unix_now};

use super::WorkflowPhase;

#[derive(Debug, Clone)]
struct ReviewedGatewayPlan {
    plan: GatewayWorkflowPlan,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct GatewayWorkflow {
    repository_key: String,
    workspace_key: String,
    rows: Vec<GatewayControlStatus>,
    selected: usize,
    action: GatewayModeAction,
    force: bool,
    reviewed: Option<ReviewedGatewayPlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
}

impl GatewayWorkflow {
    pub(super) fn new(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        rows: Vec<GatewayControlStatus>,
    ) -> Self {
        let action = default_action(rows.first());
        Self {
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            rows,
            selected: 0,
            action,
            force: false,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    pub(super) fn empty() -> Self {
        Self::new("unavailable", "unavailable", Vec::new())
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    pub(super) fn action(&self) -> GatewayModeAction {
        self.action
    }

    pub(super) fn force(&self) -> bool {
        self.force
    }

    pub(super) fn select_next(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1) % self.rows.len();
            self.action = default_action(self.rows.get(self.selected));
            self.reset_review();
        }
    }

    pub(super) fn select_previous(&mut self) {
        if !self.rows.is_empty() {
            self.selected = if self.selected == 0 {
                self.rows.len() - 1
            } else {
                self.selected - 1
            };
            self.action = default_action(self.rows.get(self.selected));
            self.reset_review();
        }
    }

    pub(super) fn cycle_action(&mut self) {
        self.action = match self.action {
            GatewayModeAction::Install => GatewayModeAction::Activate,
            GatewayModeAction::Activate => GatewayModeAction::Off,
            GatewayModeAction::Off => GatewayModeAction::Detach,
            GatewayModeAction::Detach => GatewayModeAction::Install,
        };
        self.reset_review();
    }

    pub(super) fn toggle_force(&mut self) {
        self.force = !self.force;
        self.reset_review();
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let lifecycle = row.mode.as_ref().map_or_else(
                    || "detached".to_string(),
                    |mode| format!("{:?}/{:?}", mode.installation, mode.routing),
                );
                format!(
                    "{} {} {lifecycle}",
                    if index == self.selected { ">" } else { " " },
                    row.provider.as_str()
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![format!(
            "Gateways: {} | action={} | force={} | phase={}",
            self.rows.len(),
            action_label(self.action()),
            self.force(),
            self.phase().label()
        )];
        if let Some(row) = self.rows.get(self.selected) {
            details.push(format!("selected: {}", row.provider.as_str()));
            details.push(format!("target: {}", row.target));
        } else {
            details.push("selected: none".to_string());
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.plan.plan_fingerprint));
            if let Some(reason) = &reviewed.plan.mode.blocked_reason {
                details.push(format!("blocked: {reason}"));
            }
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
        authority_key: &SessionAuthorityKey,
        backup_key: &BackupAuthenticationKey,
    ) -> Result<&ControlOperationEnvelope, String> {
        let row = self
            .rows
            .get(self.selected)
            .ok_or_else(|| "no gateway target selected".to_string())?;
        let policy_target = PolicyTarget::workspace(&self.repository_key, &self.workspace_key)
            .map_err(|error| error.to_string())?;
        let plan = GatewayWorkflowController::with_authority_keys(
            app_state_root,
            authority_key.clone(),
            backup_key.clone(),
        )
        .plan(
            row.target.clone(),
            policy_target,
            Some(row.provider),
            self.action,
            self.force,
        )
        .map_err(|error| error.to_string())?;
        let expectation = plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            plan.mode.activation,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Review provider, lifecycle action, drain behavior, and fingerprint."
                    .to_string(),
            }),
            false,
            vec![row.provider],
            json!({"plan": plan}),
        );
        self.reviewed = Some(ReviewedGatewayPlan { plan, envelope });
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(&self.reviewed.as_ref().expect("reviewed plan set").envelope)
    }

    pub(super) fn confirm(&mut self) -> bool {
        if self.reviewed.is_none() {
            return false;
        }
        self.phase = WorkflowPhase::Confirmed;
        true
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
            return Err("gateway plan must be confirmed before apply".to_string());
        }
        unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [app_state_root, project_root],
        )?;
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "gateway plan is missing".to_string())?;
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
            "unpin-tui-gateway-approval",
            unix_now(),
        )?;
        let result = match GatewayWorkflowController::with_authority_keys(
            app_state_root,
            authority_key.clone(),
            backup_key.clone(),
        )
        .apply(
            &reviewed.plan,
            authorization,
            context,
            "unpin-tui-gateway",
            unix_now(),
        ) {
            Ok(result) => result,
            Err(error @ GatewayWorkflowError::RecoveryRequired { .. }) => {
                let message = error.to_string();
                self.phase = WorkflowPhase::RecoveryRequired;
                self.last_error = Some(message.clone());
                return Err(message);
            }
            Err(error @ GatewayWorkflowError::Draining { .. }) => {
                let message = error.to_string();
                self.phase = WorkflowPhase::Blocked;
                self.last_error = Some(message.clone());
                return Err(message);
            }
            Err(error) => return Err(error.to_string()),
        };
        let lifecycle = if result.mode.status == GatewayModeApplyStatus::NoOp
            && result
                .policy
                .as_ref()
                .is_none_or(|policy| policy.status == unpin_core::profiles::PolicyApplyStatus::NoOp)
            && result.native_views.as_ref().is_none_or(|views| {
                views.status == unpin_core::sessions::GatewayNativeViewApplyStatus::NoOp
            }) {
            ControlOperationLifecycle::NoOp
        } else {
            ControlOperationLifecycle::Applied
        };
        let provider = self
            .rows
            .get(self.selected)
            .map(|row| row.provider)
            .into_iter()
            .collect();
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &expectation,
            &reviewed.plan.plan_fingerprint,
            reviewed.plan.mode.activation,
            lifecycle,
            None,
            false,
            provider,
            json!({
                "result": result,
                "nativeMcpReferences": "not-managed",
            }),
        ));
        self.phase = WorkflowPhase::Applied;
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
    }

    fn reset_review(&mut self) {
        self.reviewed = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }
}

fn default_action(row: Option<&GatewayControlStatus>) -> GatewayModeAction {
    match row.and_then(|row| row.mode.as_ref()) {
        None => GatewayModeAction::Install,
        Some(mode) if mode.routing == GatewayRoutingState::Active => GatewayModeAction::Off,
        Some(_) => GatewayModeAction::Activate,
    }
}

pub(super) const fn action_label(action: GatewayModeAction) -> &'static str {
    match action {
        GatewayModeAction::Install => "install",
        GatewayModeAction::Activate => "on",
        GatewayModeAction::Off => "off",
        GatewayModeAction::Detach => "detach",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use unpin_core::{
        profiles::{GatewaySelection, PolicyStore, ScopePolicy},
        providers::ProviderId,
        sessions::{
            BootstrapRequest, ConnectionClaim, CoverageLevel, GatewayModeTarget, IsolationLevel,
            PinnedExposure, PinnedProfile, ProcessEvidence, SessionManager,
        },
        state::atomic_json::OwnerGeneration,
    };

    fn workflow() -> GatewayWorkflow {
        GatewayWorkflow::new(
            "repo",
            "worktree",
            vec![GatewayControlStatus {
                provider: ProviderId::Codex,
                target: GatewayModeTarget::workspace_provider(
                    "repo",
                    "worktree",
                    ProviderId::Codex,
                )
                .unwrap(),
                mode: None,
            }],
        )
    }

    #[test]
    fn gateway_workflow_plans_shared_mode_and_policy_transition() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let key = SessionAuthorityKey::new([0x53; 32]);
        let backup_key = BackupAuthenticationKey::new([0x42; 32]);
        let mut workflow = workflow();
        let envelope = workflow.plan(&root, &context, &key, &backup_key).unwrap();

        assert_eq!(
            envelope.lifecycle,
            ControlOperationLifecycle::AwaitingHumanAction
        );
        assert_eq!(workflow.phase(), WorkflowPhase::Planned);
        assert!(workflow.confirm());
        assert_eq!(workflow.phase(), WorkflowPhase::Confirmed);
        let result = workflow
            .apply(&root, &root, &context, &key, &backup_key, true)
            .expect("fixture gateway apply");
        assert_eq!(result.lifecycle, ControlOperationLifecycle::Applied);
        assert_eq!(workflow.phase(), WorkflowPhase::Applied);
    }

    #[test]
    fn action_or_force_change_invalidates_review() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let key = SessionAuthorityKey::new([0x53; 32]);
        let backup_key = BackupAuthenticationKey::new([0x42; 32]);
        let mut workflow = workflow();
        workflow.plan(&root, &context, &key, &backup_key).unwrap();
        workflow.cycle_action();
        assert_eq!(workflow.action(), GatewayModeAction::Activate);
        assert_eq!(workflow.phase(), WorkflowPhase::Browsing);
        workflow.toggle_force();
        assert!(workflow.force());
        assert!(!workflow.confirm());
    }

    #[test]
    fn gateway_recovery_required_phase_survives_shared_error_recording() {
        let mut workflow = workflow();
        workflow.phase = WorkflowPhase::RecoveryRequired;

        workflow.record_error("durable repair required".to_string());

        assert_eq!(workflow.phase(), WorkflowPhase::RecoveryRequired);
        assert_eq!(workflow.phase().label(), "recovery-required");
    }

    #[test]
    fn gateway_draining_keeps_reviewed_plan_and_reports_resume_divergence() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let key = SessionAuthorityKey::new([0x53; 32]);
        let backup_key = BackupAuthenticationKey::new([0x42; 32]);
        let mut workflow = workflow();
        for action in [GatewayModeAction::Install, GatewayModeAction::Activate] {
            workflow.action = action;
            workflow.reset_review();
            workflow.plan(&root, &context, &key, &backup_key).unwrap();
            assert!(workflow.confirm());
            workflow
                .apply(&root, &root, &context, &key, &backup_key, true)
                .unwrap();
        }

        let manager = SessionManager::with_authority_key(&root, key.clone());
        let now = unix_now();
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "e".repeat(64),
                profile: PinnedProfile::None,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "tui-gateway-drain-test".to_string(),
            },
            connection_scope_id: "tui-gateway-drain-connection".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: now + 3_600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "tui-gateway-drain-owner".to_string(),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let authority = manager.prepare_bootstrap(request, now).unwrap();
        let session = manager
            .claim_bootstrap(&authority, &claim, now + 1)
            .unwrap();
        let admitted = manager
            .admit_call(&session.handle, &session.lease.revision, now + 2)
            .unwrap();

        workflow.action = GatewayModeAction::Off;
        workflow.force = true;
        workflow.reset_review();
        workflow.plan(&root, &context, &key, &backup_key).unwrap();
        let fingerprint = workflow
            .reviewed
            .as_ref()
            .unwrap()
            .plan
            .plan_fingerprint
            .clone();
        assert!(workflow.confirm());
        let error = workflow
            .apply(&root, &root, &context, &key, &backup_key, true)
            .expect_err("active call must drain");
        assert!(error.contains("draining"));
        assert_eq!(workflow.phase(), WorkflowPhase::Blocked);
        assert_eq!(
            workflow.reviewed.as_ref().unwrap().plan.plan_fingerprint,
            fingerprint
        );

        let draining = manager.load_for_handle(&session.handle).unwrap();
        manager
            .finish_call(&session.handle, &draining.revision, admitted, now + 3)
            .unwrap();
        let policy_target = PolicyTarget::workspace("repo", "worktree").unwrap();
        let policy_store = PolicyStore::new(&root);
        let current_policy = policy_store.load(&policy_target).unwrap().unwrap();
        let divergent_policy = ScopePolicy {
            gateway: GatewaySelection::Inherit,
            ..ScopePolicy::default()
        };
        policy_store
            .save(
                &policy_target,
                &divergent_policy,
                Some(&current_policy.revision),
                OwnerGeneration::new("unpin-tui-gateway", 2).unwrap(),
            )
            .unwrap();
        assert!(workflow.confirm());
        let error = workflow
            .apply(&root, &root, &context, &key, &backup_key, true)
            .expect_err("divergent resume must require recovery");
        assert!(error.contains("recovery"), "{error}");
        assert_eq!(workflow.phase(), WorkflowPhase::RecoveryRequired);
        assert!(workflow.details().iter().any(|line| line.contains(&error)));
    }
}
