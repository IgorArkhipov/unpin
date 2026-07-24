use std::path::Path;

use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    control::SessionControlStatus,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    sessions::{SessionAuthorityKey, SessionEndController, SessionEndPlan, SessionEndStatus},
};

use crate::{credentials, unix_now};

use super::WorkflowPhase;

#[derive(Debug, Clone)]
struct ReviewedSessionPlan {
    plan: SessionEndPlan,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct SessionWorkflow {
    rows: Vec<SessionControlStatus>,
    selected: usize,
    reviewed: Option<ReviewedSessionPlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
}

impl SessionWorkflow {
    pub(super) fn new(rows: Vec<SessionControlStatus>) -> Self {
        Self {
            rows,
            selected: 0,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    pub(super) fn select_next(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1) % self.rows.len();
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
            self.reset_review();
        }
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.rows
            .iter()
            .enumerate()
            .map(|(index, session)| {
                format!(
                    "{} {} {} {:?} calls={} repo={} workspace={}",
                    if index == self.selected { ">" } else { " " },
                    session.session_id,
                    session.provider.as_str(),
                    session.lifecycle,
                    session.in_flight_calls,
                    session.repository_key,
                    session.workspace_key,
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![format!(
            "Sessions: {} | phase={}",
            self.rows.len(),
            self.phase().label()
        )];
        if let Some(session) = self.rows.get(self.selected) {
            details.push(format!("selected: {}", session.session_id));
            details.push(format!("provider: {}", session.provider.as_str()));
            details.push(format!("repository: {}", session.repository_key));
            details.push(format!("workspace: {}", session.workspace_key));
            details.push(format!("lifecycle: {:?}", session.lifecycle));
            details.push(format!("live exposure: {:?}", session.live_status));
            details.push(format!("coverage: {:?}", session.coverage));
        } else {
            details.push("selected: none".to_string());
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.plan.plan_fingerprint));
            details.push(format!(
                "in-flight calls: {}",
                reviewed.plan.in_flight_calls
            ));
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
    ) -> Result<&ControlOperationEnvelope, String> {
        let session = self
            .rows
            .get(self.selected)
            .ok_or_else(|| "no session selected".to_string())?;
        let plan = SessionEndController::with_authority_key(app_state_root, authority_key.clone())
            .plan(&session.session_id, context)
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
                guidance: "Review session identity, lifecycle, and in-flight call count."
                    .to_string(),
            }),
            false,
            plan.provider.into_iter().collect(),
            json!({"plan": plan}),
        );
        self.reviewed = Some(ReviewedSessionPlan { plan, envelope });
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

    pub(super) fn apply(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        fixture_mode: bool,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("session end plan must be confirmed before apply".to_string());
        }
        unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [app_state_root, project_root],
        )?;
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "session end plan is missing".to_string())?;
        let expectation = reviewed
            .plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let now = unix_now();
        let authorization = credentials::authorize_reviewed_control_decision(
            fixture_mode,
            app_state_root,
            &expectation,
            &reviewed.plan.plan_fingerprint,
            Some(&reviewed.plan.plan_fingerprint),
            "unpin-tui-session-approval",
            now,
        )?;
        let result =
            SessionEndController::with_authority_key(app_state_root, authority_key.clone())
                .apply(
                    &reviewed.plan,
                    authorization,
                    context,
                    "unpin-tui-session",
                    now,
                )
                .map_err(|error| error.to_string())?;
        let lifecycle = match result.status {
            SessionEndStatus::RevocationRequested => ControlOperationLifecycle::Applied,
            SessionEndStatus::AlreadyEnding | SessionEndStatus::NoOp => {
                ControlOperationLifecycle::NoOp
            }
        };
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &expectation,
            &reviewed.plan.plan_fingerprint,
            result.activation,
            lifecycle,
            None,
            false,
            reviewed.plan.provider.into_iter().collect(),
            json!({"result": result}),
        ));
        self.phase = WorkflowPhase::Applied;
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        self.phase = WorkflowPhase::Blocked;
    }

    fn reset_review(&mut self) {
        self.reviewed = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use unpin_core::{
        providers::ProviderId,
        sessions::{
            BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, LeaseLifecycle,
            LiveExposureStatus, PinnedExposure, PinnedProfile, ProcessEvidence, SessionManager,
        },
    };

    fn workflow() -> SessionWorkflow {
        SessionWorkflow::new(vec![SessionControlStatus {
            session_id: "session-one".to_string(),
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            profile_digest: None,
            desired_exposure_revision: "a".repeat(64),
            observed_exposure_revision: "a".repeat(64),
            live_status: LiveExposureStatus::Configured,
            isolation: IsolationLevel::ConnectionScoped,
            coverage: CoverageLevel::VerifiedMasked,
            lifecycle: LeaseLifecycle::Active,
            in_flight_calls: 0,
        }])
    }

    #[test]
    fn session_workflow_plans_via_authenticated_controller() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let key = SessionAuthorityKey::new([0x53; 32]);
        let mut workflow = workflow();
        let lifecycle = workflow.plan(&root, &context, &key).unwrap().lifecycle;

        assert!(workflow.rows()[0].contains("repo=repo workspace=worktree"));
        assert!(
            workflow
                .details()
                .contains(&"workspace: worktree".to_string())
        );
        assert_eq!(lifecycle, ControlOperationLifecycle::AwaitingHumanAction);
        assert_eq!(workflow.phase(), WorkflowPhase::Planned);
        assert!(workflow.confirm());
        assert_eq!(workflow.phase(), WorkflowPhase::Confirmed);
        let result = workflow
            .apply(&root, &root, &context, &key, true)
            .expect("fixture no-op session end apply");
        assert_eq!(result.lifecycle, ControlOperationLifecycle::NoOp);
        assert_eq!(workflow.phase(), WorkflowPhase::Applied);
    }

    #[test]
    fn session_rows_distinguish_parallel_worktrees() {
        let first = workflow().rows.remove(0);
        let mut second = first.clone();
        second.session_id = "session-two".to_string();
        second.workspace_key = "worktree-two".to_string();
        let mut workflow = SessionWorkflow::new(vec![first, second]);

        let rows = workflow.rows();
        assert!(rows[0].contains("workspace=worktree"));
        assert!(rows[1].contains("workspace=worktree-two"));
        workflow.select_next();
        assert!(
            workflow
                .details()
                .contains(&"workspace: worktree-two".to_string())
        );
    }

    #[test]
    fn session_workflow_revokes_active_owned_session() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let key = SessionAuthorityKey::new([0x53; 32]);
        let manager = SessionManager::with_authority_key(&root, key.clone());
        let now = unix_now();
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "e".repeat(64),
                profile: PinnedProfile::Native,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "tui-session-end-test".to_string(),
            },
            connection_scope_id: "tui-session-end-connection".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: now + 3_600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "tui-session-end-owner".to_string(),
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
        let lease = &session.lease.lease;
        let mut workflow = SessionWorkflow::new(vec![SessionControlStatus {
            session_id: lease.session_id.clone(),
            provider: lease.provider,
            repository_key: lease.repository_key.clone(),
            workspace_key: lease.workspace_key.clone(),
            profile_digest: None,
            desired_exposure_revision: lease.desired_exposure.revision.clone(),
            observed_exposure_revision: lease.observed_exposure.revision.clone(),
            live_status: lease.live_status,
            isolation: lease.isolation,
            coverage: lease.coverage.clone(),
            lifecycle: lease.lifecycle,
            in_flight_calls: lease.in_flight_calls,
        }]);

        workflow.plan(&root, &context, &key).unwrap();
        assert!(workflow.confirm());
        let result = workflow
            .apply(&root, &root, &context, &key, true)
            .expect("revoke active session");

        assert_eq!(result.lifecycle, ControlOperationLifecycle::Applied);
        let leases = manager.list().unwrap();
        assert_eq!(leases[0].lease.lifecycle, LeaseLifecycle::Revoking);
        assert!(!leases[0].lease.admission_open);
    }
}
