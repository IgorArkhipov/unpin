use std::{collections::BTreeMap, path::Path};

use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    control::SessionControlStatus,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    sessions::{
        CoverageLevel, LeaseLifecycle, LiveExposureStatus, PinnedWorkflowEnvelope,
        SessionAuthorityKey, SessionEndController, SessionEndPlan, SessionEndStatus,
        SessionManager,
    },
};

use crate::{credentials, unix_now};

use super::WorkflowPhase;

#[derive(Debug, Clone)]
struct ReviewedSessionPlan {
    plan: SessionEndPlan,
    envelope: ControlOperationEnvelope,
}

/// Connection-local workflow state projected by the compact TUI.
///
/// This intentionally is not the operation phase used by the existing
/// session-end workflow. The TUI is an inspection and handoff surface; it
/// does not transition a routed session itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkflowProjectionState {
    Observed,
    NotificationSent,
    ReloadRequired,
    RefreshUnconfirmed,
    NextSessionOnly,
    RecoveryRequired,
    NoWorkflow,
    Ended,
}

impl WorkflowProjectionState {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NotificationSent => "notification-sent",
            Self::ReloadRequired => "reload-required",
            Self::RefreshUnconfirmed => "refresh-unconfirmed",
            Self::NextSessionOnly => "next-session-only",
            Self::RecoveryRequired => "recovery-required",
            Self::NoWorkflow => "no-workflow",
            Self::Ended => "ended",
        }
    }

    const fn default_reason(self) -> &'static str {
        match self {
            Self::Observed => "workflow-observed",
            Self::NotificationSent => "workflow-notification-sent",
            Self::ReloadRequired => "workflow-reload-required",
            Self::RefreshUnconfirmed => "workflow-refresh-unconfirmed",
            Self::NextSessionOnly => "workflow-next-session-only",
            Self::RecoveryRequired => "workflow-recovery-required",
            Self::NoWorkflow => "no-workflow-pinned",
            Self::Ended => "session-ended",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkflowProjectionEvent {
    session_id: String,
    state: WorkflowProjectionState,
    workflow_id: Option<String>,
    active_mode: Option<String>,
    desired_revision: Option<String>,
    observed_revision: Option<String>,
    coverage: String,
    reason_code: String,
}

impl WorkflowProjectionEvent {
    fn from_status(
        status: &SessionControlStatus,
        workflow: Option<&PinnedWorkflowEnvelope>,
    ) -> Self {
        let state = workflow
            .map(|_| {
                projection_state(
                    status.lifecycle,
                    status.live_status,
                    &status.desired_exposure_revision,
                    &status.observed_exposure_revision,
                )
            })
            .unwrap_or(WorkflowProjectionState::NoWorkflow);
        Self::new(
            status.session_id.clone(),
            state,
            workflow.map(|workflow| workflow.workflow_id.clone()),
            workflow.map(|workflow| workflow.active_mode.clone()),
            Some(status.desired_exposure_revision.clone()),
            Some(status.observed_exposure_revision.clone()),
            coverage_label(&status.coverage),
            state.default_reason(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        session_id: impl Into<String>,
        state: WorkflowProjectionState,
        workflow_id: Option<impl Into<String>>,
        active_mode: Option<impl Into<String>>,
        desired_revision: Option<impl Into<String>>,
        observed_revision: Option<impl Into<String>>,
        coverage: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            state,
            workflow_id: workflow_id.map(Into::into),
            active_mode: active_mode.map(Into::into),
            desired_revision: desired_revision.map(Into::into),
            observed_revision: observed_revision.map(Into::into),
            coverage: coverage.into(),
            reason_code: reason_code.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkflowProjection {
    state: WorkflowProjectionState,
    workflow_id: Option<String>,
    workflow_revision: Option<String>,
    active_mode: Option<String>,
    desired_revision: String,
    observed_revision: String,
    coverage: String,
    native_unmanaged: bool,
    reason_code: String,
    handoff: String,
}

impl WorkflowProjection {
    fn from_status(
        status: &SessionControlStatus,
        workflow: Option<&PinnedWorkflowEnvelope>,
        native_unmanaged: bool,
    ) -> Self {
        let state = workflow
            .map(|_| {
                projection_state(
                    status.lifecycle,
                    status.live_status,
                    &status.desired_exposure_revision,
                    &status.observed_exposure_revision,
                )
            })
            .unwrap_or(WorkflowProjectionState::NoWorkflow);
        let coverage = coverage_label(&status.coverage);
        Self {
            state,
            workflow_id: workflow.map(|workflow| workflow.workflow_id.clone()),
            workflow_revision: workflow.map(|workflow| workflow.workflow_revision.clone()),
            active_mode: workflow.map(|workflow| workflow.active_mode.clone()),
            desired_revision: status.desired_exposure_revision.clone(),
            observed_revision: status.observed_exposure_revision.clone(),
            native_unmanaged: native_unmanaged || coverage.contains("native-unmanaged"),
            coverage,
            reason_code: state.default_reason().to_string(),
            handoff: handoff_for(&status.session_id, state),
        }
    }

    fn apply_event(&mut self, event: WorkflowProjectionEvent) {
        self.state = event.state;
        self.workflow_id = event.workflow_id;
        self.active_mode = event.active_mode;
        if event.state == WorkflowProjectionState::NoWorkflow {
            self.workflow_revision = None;
        }
        if let Some(desired) = event.desired_revision {
            self.desired_revision = desired;
        }
        if let Some(observed) = event.observed_revision {
            self.observed_revision = observed;
        }
        self.coverage = event.coverage;
        self.native_unmanaged = self.native_unmanaged || self.coverage.contains("native-unmanaged");
        self.reason_code = if event.reason_code.is_empty() {
            event.state.default_reason().to_string()
        } else {
            event.reason_code
        };
        self.handoff = handoff_for(&event.session_id, event.state);
    }

    fn row_label(&self) -> String {
        format!(
            "workflow={} mode={} state={} d={} o={} next={}",
            self.workflow_id.as_deref().unwrap_or("none"),
            self.active_mode.as_deref().unwrap_or("none"),
            self.state.label(),
            compact_revision(&self.desired_revision),
            compact_revision(&self.observed_revision),
            self.next_label(),
        )
    }

    fn next_label(&self) -> &'static str {
        match self.state {
            WorkflowProjectionState::ReloadRequired
            | WorkflowProjectionState::RefreshUnconfirmed
            | WorkflowProjectionState::RecoveryRequired => "recover",
            WorkflowProjectionState::NextSessionOnly => "new-session",
            WorkflowProjectionState::NoWorkflow
            | WorkflowProjectionState::Observed
            | WorkflowProjectionState::NotificationSent => "status",
            WorkflowProjectionState::Ended => "status",
        }
    }

    fn detail_lines(&self) -> Vec<String> {
        vec![
            format!(
                "workflow: {}",
                self.workflow_id.as_deref().unwrap_or("none")
            ),
            format!("mode: {}", self.active_mode.as_deref().unwrap_or("none")),
            format!(
                "workflow revision: {}",
                self.workflow_revision.as_deref().unwrap_or("none")
            ),
            format!(
                "revisions: desired={} observed={} relation={}",
                self.desired_revision,
                self.observed_revision,
                if self.desired_revision == self.observed_revision {
                    "in-sync"
                } else {
                    "pending"
                }
            ),
            format!("state: {}", self.state.label()),
            format!(
                "coverage: {} | native-unmanaged={}",
                self.coverage, self.native_unmanaged
            ),
            format!("reason: {}", self.reason_code),
            format!("handoff: {}", self.handoff),
        ]
    }
}

fn projection_state(
    lifecycle: LeaseLifecycle,
    live_status: LiveExposureStatus,
    desired_revision: &str,
    observed_revision: &str,
) -> WorkflowProjectionState {
    if matches!(lifecycle, LeaseLifecycle::Closed | LeaseLifecycle::Expired) {
        return WorkflowProjectionState::Ended;
    }
    match live_status {
        LiveExposureStatus::ObservedRefresh => WorkflowProjectionState::Observed,
        LiveExposureStatus::NotificationSent => WorkflowProjectionState::NotificationSent,
        LiveExposureStatus::ReloadRequired => WorkflowProjectionState::ReloadRequired,
        LiveExposureStatus::NextSessionOnly => WorkflowProjectionState::NextSessionOnly,
        LiveExposureStatus::Configured if desired_revision == observed_revision => {
            WorkflowProjectionState::Observed
        }
        LiveExposureStatus::Configured => WorkflowProjectionState::RefreshUnconfirmed,
        LiveExposureStatus::Unknown => WorkflowProjectionState::RecoveryRequired,
    }
}

fn coverage_label(coverage: &CoverageLevel) -> String {
    match coverage {
        CoverageLevel::VerifiedMasked => "verified-masked".to_string(),
        CoverageLevel::ExternalDegraded { reasons } => {
            format!("external-degraded({})", reasons.join(","))
        }
    }
}

fn handoff_for(session_id: &str, state: WorkflowProjectionState) -> String {
    match state {
        WorkflowProjectionState::ReloadRequired
        | WorkflowProjectionState::RefreshUnconfirmed
        | WorkflowProjectionState::RecoveryRequired => {
            format!("CLI: unpin session recovery --id {session_id} --json")
        }
        WorkflowProjectionState::NextSessionOnly => {
            format!("CLI: unpin session status --id {session_id} --json (launch a new session)")
        }
        WorkflowProjectionState::NoWorkflow => {
            format!("CLI: unpin session status --id {session_id} --json (no workflow pinned)")
        }
        WorkflowProjectionState::Ended => {
            format!("CLI: unpin session status --id {session_id} --json (session ended)")
        }
        WorkflowProjectionState::Observed | WorkflowProjectionState::NotificationSent => {
            format!("CLI: unpin session status --id {session_id} --json")
        }
    }
}

fn compact_revision(revision: &str) -> &str {
    revision.get(..12).unwrap_or(revision)
}

#[derive(Debug, Clone)]
pub(super) struct SessionWorkflow {
    rows: Vec<SessionControlStatus>,
    projections: Vec<WorkflowProjection>,
    selected: usize,
    reviewed: Option<ReviewedSessionPlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
}

impl SessionWorkflow {
    pub(super) fn load_workflows(
        app_state_root: &Path,
        authority_key: &SessionAuthorityKey,
    ) -> BTreeMap<String, PinnedWorkflowEnvelope> {
        SessionManager::with_authority_key(app_state_root, authority_key.clone())
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|snapshot| {
                snapshot
                    .lease
                    .workflow
                    .map(|workflow| (snapshot.lease.session_id, *workflow))
            })
            .collect()
    }

    pub(super) fn new(rows: Vec<SessionControlStatus>) -> Self {
        Self::new_with_workflows(rows, &BTreeMap::new())
    }

    pub(super) fn new_with_workflows(
        rows: Vec<SessionControlStatus>,
        workflows: &BTreeMap<String, PinnedWorkflowEnvelope>,
    ) -> Self {
        let projections = rows
            .iter()
            .map(|status| {
                WorkflowProjection::from_status(
                    status,
                    workflows.get(&status.session_id),
                    workflows.get(&status.session_id).is_none() && status.profile_digest.is_none(),
                )
            })
            .collect();
        let mut session_workflow = Self {
            rows,
            projections,
            selected: 0,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        };
        let events = session_workflow
            .rows
            .iter()
            .map(|status| {
                WorkflowProjectionEvent::from_status(status, workflows.get(&status.session_id))
            })
            .collect::<Vec<_>>();
        for event in events {
            session_workflow.apply_projection_event(event);
        }
        session_workflow
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
                let projection = self
                    .projections
                    .get(index)
                    .expect("session projection parallels session rows");
                format!(
                    "{} {} | {} {} {:?} calls={} repo={} workspace={}",
                    if index == self.selected { ">" } else { " " },
                    projection.row_label(),
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
            if let Some(projection) = self.projections.get(self.selected) {
                details.extend(projection.detail_lines());
            }
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

    pub(super) fn apply_projection_event(&mut self, event: WorkflowProjectionEvent) -> bool {
        let Some(index) = self
            .rows
            .iter()
            .position(|row| row.session_id == event.session_id)
        else {
            return false;
        };
        if let Some(projection) = self.projections.get_mut(index) {
            projection.apply_event(event);
            true
        } else {
            false
        }
    }

    pub(super) fn projection_rows(&self) -> Vec<String> {
        if self.rows.is_empty() {
            return vec!["no workflow sessions".to_string()];
        }
        self.rows()
            .into_iter()
            .map(|row| row.trim_start_matches('>').trim_start().to_string())
            .collect()
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

    #[test]
    fn routed_projection_events_keep_reason_and_handoff_context() {
        let mut workflow = workflow();
        let session_id = "session-one";
        let cases = [
            (
                WorkflowProjectionState::Observed,
                "workflow-observed",
                "unpin session status",
            ),
            (
                WorkflowProjectionState::NotificationSent,
                "workflow-notification-sent",
                "unpin session status",
            ),
            (
                WorkflowProjectionState::ReloadRequired,
                "workflow-reload-required",
                "unpin session recovery",
            ),
            (
                WorkflowProjectionState::RefreshUnconfirmed,
                "workflow-refresh-unconfirmed",
                "unpin session recovery",
            ),
            (
                WorkflowProjectionState::NextSessionOnly,
                "workflow-next-session-only",
                "unpin session status",
            ),
            (
                WorkflowProjectionState::RecoveryRequired,
                "workflow-recovery-required",
                "unpin session recovery",
            ),
            (
                WorkflowProjectionState::NoWorkflow,
                "no-workflow-pinned",
                "unpin session status",
            ),
            (
                WorkflowProjectionState::Ended,
                "session-ended",
                "unpin session status",
            ),
        ];

        for (state, reason, handoff) in cases {
            assert!(
                workflow.apply_projection_event(WorkflowProjectionEvent::new(
                    session_id,
                    state,
                    Some("delivery"),
                    Some("planning"),
                    Some("desired-revision"),
                    Some("observed-revision"),
                    "verified-masked",
                    reason,
                ))
            );
            let details = workflow.details();
            assert!(
                details
                    .iter()
                    .any(|line| line == &format!("state: {}", state.label()))
            );
            assert!(
                details
                    .iter()
                    .any(|line| line == &format!("reason: {reason}"))
            );
            assert!(details.iter().any(|line| line.contains(handoff)));
        }
    }

    #[test]
    fn routed_projection_distinguishes_revision_relationship_and_native_unmanaged_coverage() {
        let mut workflow = workflow();
        let before = workflow.details();
        assert!(
            !workflow.apply_projection_event(WorkflowProjectionEvent::new(
                "foreign-session",
                WorkflowProjectionState::ReloadRequired,
                Some("foreign"),
                Some("review"),
                Some("b"),
                Some("a"),
                "verified-masked",
                "foreign-context",
            ))
        );
        assert_eq!(
            workflow.details(),
            before,
            "foreign events do not mutate TUI state"
        );
        assert!(
            workflow.apply_projection_event(WorkflowProjectionEvent::new(
                "session-one",
                WorkflowProjectionState::ReloadRequired,
                Some("delivery"),
                Some("implementation"),
                Some("b"),
                Some("a"),
                "external-degraded(native-mcp-unmanaged)",
                "host-relist-required",
            ))
        );
        let details = workflow.details();
        assert!(
            details
                .iter()
                .any(|line| { line == "revisions: desired=b observed=a relation=pending" })
        );
        assert!(details.iter().any(|line| line
            == "coverage: external-degraded(native-mcp-unmanaged) | native-unmanaged=true"));
        assert!(
            details
                .iter()
                .any(|line| line.contains("CLI: unpin session recovery --id session-one --json"))
        );
    }
}
