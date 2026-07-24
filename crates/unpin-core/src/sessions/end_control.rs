use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
        ControlOperationKind, approval_binding_digest,
    },
    control_operation::{
        DurableControlError, DurableControlJournal, DurableControlStart, DurableControlTerminal,
        DurableControlTerminalStatus,
    },
    providers::ProviderId,
    sessions::{LeaseError, LeaseLifecycle, SessionAuthorityKey, SessionManager},
    state::atomic_json::StateRevision,
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionKind, TransitionPlan, TransitionPlanError,
    },
};

pub const SESSION_END_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionEndPlan {
    pub schema_version: u32,
    pub session_id: String,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LeaseLifecycle>,
    pub in_flight_calls: u32,
    pub no_op: bool,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

impl SessionEndPlan {
    pub fn verify(&self) -> Result<(), SessionEndControlError> {
        if self.schema_version != SESSION_END_PLAN_SCHEMA_VERSION {
            return Err(SessionEndControlError::InvalidPlan);
        }
        let actual = fingerprint(
            &self.session_id,
            &self.repository_key,
            &self.workspace_key,
            self.expected_revision.as_ref(),
            self.provider,
            self.profile_digest.as_deref(),
            self.lifecycle,
            self.in_flight_calls,
            self.no_op,
            self.activation,
        )?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(SessionEndControlError::PlanFingerprintMismatch)
        }
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, SessionEndControlError> {
        self.verify()?;
        if self.repository_key != context.repository_key()
            || self.workspace_key != context.workspace_key()
        {
            return Err(SessionEndControlError::ContextMismatch);
        }
        Ok(ApprovalExpectation {
            issuer: CONTROL_APPROVAL_ISSUER.to_string(),
            audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
            operation_id: format!("session-end-{}", self.plan_fingerprint),
            operation_kind: ControlOperationKind::SessionEnd.as_str().to_string(),
            effect_graph_digest: self.plan_fingerprint.clone(),
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: Some(self.session_id.clone()),
            profile_digest: self.profile_digest.clone(),
            resources: vec![ApprovalResourceBinding {
                resource_id: session_resource_id(&self.session_id),
                pre_state_fingerprint: self
                    .expected_revision
                    .as_ref()
                    .map(|revision| approval_binding_digest(&revision.fingerprint)),
            }],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionEndStatus {
    RevocationRequested,
    AlreadyEnding,
    NoOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionEndResult {
    pub status: SessionEndStatus,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LeaseLifecycle>,
    pub in_flight_calls: u32,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct SessionEndController {
    manager: SessionManager,
    journal: DurableControlJournal,
}

impl SessionEndController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            manager: SessionManager::new(&app_state_root),
            journal: DurableControlJournal::new(app_state_root),
        }
    }

    #[must_use]
    pub fn with_authority_key(
        app_state_root: impl Into<std::path::PathBuf>,
        authority_key: SessionAuthorityKey,
    ) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            manager: SessionManager::with_authority_key(&app_state_root, authority_key),
            journal: DurableControlJournal::new(app_state_root),
        }
    }

    pub fn plan(
        &self,
        session_id: &str,
        context: &ControlApprovalContext,
    ) -> Result<SessionEndPlan, SessionEndControlError> {
        let current = self
            .manager
            .list()?
            .into_iter()
            .find(|snapshot| snapshot.lease.session_id == session_id);
        if current.as_ref().is_some_and(|snapshot| {
            snapshot.lease.repository_key != context.repository_key()
                || snapshot.lease.workspace_key != context.workspace_key()
        }) {
            return Err(SessionEndControlError::ContextMismatch);
        }
        let expected_revision = current.as_ref().map(|snapshot| snapshot.revision.clone());
        let provider = current.as_ref().map(|snapshot| snapshot.lease.provider);
        let profile_digest = current.as_ref().and_then(|snapshot| {
            snapshot
                .lease
                .desired_exposure
                .profile
                .digest()
                .map(ToOwned::to_owned)
        });
        let lifecycle = current.as_ref().map(|snapshot| snapshot.lease.lifecycle);
        let in_flight_calls = current
            .as_ref()
            .map_or(0, |snapshot| snapshot.lease.in_flight_calls);
        let no_op = current.as_ref().is_none_or(|snapshot| {
            !snapshot.lease.lifecycle.contributes_active_intent()
                || snapshot.lease.lifecycle == LeaseLifecycle::Revoking
        });
        let activation = EffectActivation::Live;
        let plan_fingerprint = fingerprint(
            session_id,
            context.repository_key(),
            context.workspace_key(),
            expected_revision.as_ref(),
            provider,
            profile_digest.as_deref(),
            lifecycle,
            in_flight_calls,
            no_op,
            activation,
        )?;
        Ok(SessionEndPlan {
            schema_version: SESSION_END_PLAN_SCHEMA_VERSION,
            session_id: session_id.to_string(),
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            expected_revision,
            provider,
            profile_digest,
            lifecycle,
            in_flight_calls,
            no_op,
            activation,
            plan_fingerprint,
        })
    }

    pub fn apply(
        &self,
        reviewed_plan: &SessionEndPlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<SessionEndResult, SessionEndControlError> {
        let expectation = reviewed_plan.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        reviewed_plan.verify()?;
        let transition = reviewed_plan.transition_plan(context)?;
        let journal = match self.journal.begin(&transition, &authorization, actor_id)? {
            DurableControlStart::Apply(journal) => journal,
            DurableControlStart::Cached(terminal) => {
                return cached_end_result(&self.manager, reviewed_plan, &terminal);
            }
        };
        if journal.is_resumed() {
            let current = self
                .manager
                .list()?
                .into_iter()
                .find(|snapshot| snapshot.lease.session_id == reviewed_plan.session_id);
            match current {
                None => {
                    let status = if reviewed_plan.no_op {
                        DurableControlTerminalStatus::NoOp
                    } else {
                        DurableControlTerminalStatus::Applied
                    };
                    journal.commit_with_terminal_status(status)?;
                    return Ok(SessionEndResult {
                        status: SessionEndStatus::NoOp,
                        session_id: reviewed_plan.session_id.clone(),
                        lifecycle: None,
                        in_flight_calls: 0,
                        activation: reviewed_plan.activation,
                        plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
                    });
                }
                Some(current)
                    if reviewed_plan.provider == Some(current.lease.provider)
                        && reviewed_plan.profile_digest.as_deref()
                            == current.lease.desired_exposure.profile.digest()
                        && reviewed_plan.repository_key == current.lease.repository_key
                        && reviewed_plan.workspace_key == current.lease.workspace_key =>
                {
                    let terminal = match (reviewed_plan.no_op, current.lease.lifecycle) {
                        (false, LeaseLifecycle::Revoking) => Some((
                            DurableControlTerminalStatus::Applied,
                            SessionEndStatus::RevocationRequested,
                        )),
                        (false, LeaseLifecycle::Closed | LeaseLifecycle::Expired) => Some((
                            DurableControlTerminalStatus::Applied,
                            SessionEndStatus::NoOp,
                        )),
                        (true, LeaseLifecycle::Revoking) => Some((
                            DurableControlTerminalStatus::NoOp,
                            SessionEndStatus::AlreadyEnding,
                        )),
                        (true, LeaseLifecycle::Closed | LeaseLifecycle::Expired) => {
                            Some((DurableControlTerminalStatus::NoOp, SessionEndStatus::NoOp))
                        }
                        _ => None,
                    };
                    if let Some((terminal_status, status)) = terminal {
                        let result = SessionEndResult {
                            status,
                            session_id: reviewed_plan.session_id.clone(),
                            lifecycle: Some(current.lease.lifecycle),
                            in_flight_calls: current.lease.in_flight_calls,
                            activation: reviewed_plan.activation,
                            plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
                        };
                        journal.commit_with_terminal_status(terminal_status)?;
                        return Ok(result);
                    }
                    if reviewed_plan.expected_revision.as_ref() != Some(&current.revision) {
                        journal.needs_repair("control-resume-state-diverged")?;
                        return Err(SessionEndControlError::Durable(
                            DurableControlError::RecoveryRequired(expectation.operation_id),
                        ));
                    }
                }
                Some(_) => {
                    journal.needs_repair("control-resume-state-diverged")?;
                    return Err(SessionEndControlError::Durable(
                        DurableControlError::RecoveryRequired(expectation.operation_id),
                    ));
                }
            }
        }
        let current = match self.plan(&reviewed_plan.session_id, context) {
            Ok(current) => current,
            Err(error) => {
                journal.abort("control-plan-invalid")?;
                return Err(error);
            }
        };
        if current.plan_fingerprint != reviewed_plan.plan_fingerprint {
            journal.abort("control-plan-drift")?;
            return Err(SessionEndControlError::PlanFingerprintMismatch);
        }
        let result = if current.no_op {
            Ok(SessionEndResult {
                status: if current.lifecycle == Some(LeaseLifecycle::Revoking) {
                    SessionEndStatus::AlreadyEnding
                } else {
                    SessionEndStatus::NoOp
                },
                session_id: current.session_id,
                lifecycle: current.lifecycle,
                in_flight_calls: current.in_flight_calls,
                activation: current.activation,
                plan_fingerprint: current.plan_fingerprint,
            })
        } else {
            let Some(expected_revision) = current.expected_revision.as_ref() else {
                journal.abort("control-plan-invalid")?;
                return Err(SessionEndControlError::InvalidPlan);
            };
            let updated = self.manager.request_revoke(
                &current.session_id,
                expected_revision,
                actor_id,
                "session-end-requested",
                now_unix,
            );
            updated.map(|updated| SessionEndResult {
                status: SessionEndStatus::RevocationRequested,
                session_id: updated.lease.session_id,
                lifecycle: Some(updated.lease.lifecycle),
                in_flight_calls: updated.lease.in_flight_calls,
                activation: current.activation,
                plan_fingerprint: current.plan_fingerprint,
            })
        };
        match result {
            Ok(result) => {
                let status = match result.status {
                    SessionEndStatus::RevocationRequested => DurableControlTerminalStatus::Applied,
                    SessionEndStatus::AlreadyEnding | SessionEndStatus::NoOp => {
                        DurableControlTerminalStatus::NoOp
                    }
                };
                journal.commit_with_terminal_status(status)?;
                Ok(result)
            }
            Err(error) => {
                journal.abort("control-apply-aborted")?;
                Err(error.into())
            }
        }
    }
}

fn cached_end_result(
    manager: &SessionManager,
    reviewed_plan: &SessionEndPlan,
    terminal: &DurableControlTerminal,
) -> Result<SessionEndResult, SessionEndControlError> {
    let recovery_required = || {
        SessionEndControlError::Durable(DurableControlError::RecoveryRequired(
            terminal.operation_id.clone(),
        ))
    };
    if !matches!(
        (terminal.status, reviewed_plan.no_op),
        (DurableControlTerminalStatus::Applied, false) | (DurableControlTerminalStatus::NoOp, true)
    ) {
        return Err(recovery_required());
    }
    let current = manager
        .list()?
        .into_iter()
        .find(|snapshot| snapshot.lease.session_id == reviewed_plan.session_id);
    let Some(current) = current else {
        return Ok(SessionEndResult {
            status: SessionEndStatus::NoOp,
            session_id: reviewed_plan.session_id.clone(),
            lifecycle: None,
            in_flight_calls: 0,
            activation: reviewed_plan.activation,
            plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
        });
    };
    let current_profile_digest = current.lease.desired_exposure.profile.digest();
    if reviewed_plan.provider != Some(current.lease.provider)
        || reviewed_plan.profile_digest.as_deref() != current_profile_digest
        || reviewed_plan.repository_key != current.lease.repository_key
        || reviewed_plan.workspace_key != current.lease.workspace_key
    {
        return Err(recovery_required());
    }
    let status = match (
        terminal.status,
        reviewed_plan.no_op,
        current.lease.lifecycle,
    ) {
        (DurableControlTerminalStatus::Applied, false, LeaseLifecycle::Revoking) => {
            SessionEndStatus::RevocationRequested
        }
        (
            DurableControlTerminalStatus::Applied,
            false,
            LeaseLifecycle::Closed | LeaseLifecycle::Expired,
        )
        | (
            DurableControlTerminalStatus::NoOp,
            true,
            LeaseLifecycle::Closed | LeaseLifecycle::Expired,
        ) => SessionEndStatus::NoOp,
        (DurableControlTerminalStatus::NoOp, true, LeaseLifecycle::Revoking) => {
            SessionEndStatus::AlreadyEnding
        }
        _ => return Err(recovery_required()),
    };
    Ok(SessionEndResult {
        status,
        session_id: reviewed_plan.session_id.clone(),
        lifecycle: Some(current.lease.lifecycle),
        in_flight_calls: current.lease.in_flight_calls,
        activation: reviewed_plan.activation,
        plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
    })
}

impl SessionEndPlan {
    fn transition_plan(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<TransitionPlan, SessionEndControlError> {
        let expectation = self.approval_expectation(context)?;
        TransitionPlan::new(
            expectation.operation_id,
            TransitionKind::SessionEnd,
            TransitionContext {
                repository_key: self.repository_key.clone(),
                workspace_key: self.workspace_key.clone(),
                session_id: Some(self.session_id.clone()),
                profile_digest: self.profile_digest.clone(),
            },
            vec![TransitionEffect {
                effect_id: "session-end-effect".to_string(),
                kind: TransitionEffectKind::WithdrawView,
                resource_id: session_resource_id(&self.session_id),
                target_type: "session-lease".to_string(),
                summary: "Revoke reviewed session exposure".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: self.activation,
                expected_pre_fingerprint: self
                    .expected_revision
                    .as_ref()
                    .map(|revision| approval_binding_digest(&revision.fingerprint)),
                expected_post_fingerprint: Some(crate::encode_lower_hex(&Sha256::digest(
                    format!("{}:revoking", self.session_id).as_bytes(),
                ))),
                provider_views: self.provider.into_iter().collect(),
            }],
        )
        .map_err(SessionEndControlError::TransitionPlan)
    }
}

fn session_resource_id(session_id: &str) -> String {
    format!(
        "session-lease-{}",
        &crate::encode_lower_hex(&Sha256::digest(session_id.as_bytes()))[..16]
    )
}

#[allow(clippy::too_many_arguments)]
fn fingerprint(
    session_id: &str,
    repository_key: &str,
    workspace_key: &str,
    expected_revision: Option<&StateRevision>,
    provider: Option<ProviderId>,
    profile_digest: Option<&str>,
    lifecycle: Option<LeaseLifecycle>,
    in_flight_calls: u32,
    no_op: bool,
    activation: EffectActivation,
) -> Result<String, SessionEndControlError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        session_id: &'a str,
        repository_key: &'a str,
        workspace_key: &'a str,
        expected_revision: Option<&'a StateRevision>,
        provider: Option<ProviderId>,
        profile_digest: Option<&'a str>,
        lifecycle: Option<LeaseLifecycle>,
        in_flight_calls: u32,
        no_op: bool,
        activation: EffectActivation,
    }
    let bytes = serde_json::to_vec(&FingerprintBody {
        schema_version: SESSION_END_PLAN_SCHEMA_VERSION,
        session_id,
        repository_key,
        workspace_key,
        expected_revision,
        provider,
        profile_digest,
        lifecycle,
        in_flight_calls,
        no_op,
        activation,
    })
    .map_err(|error| SessionEndControlError::Serialization(error.to_string()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug)]
pub enum SessionEndControlError {
    Approval(ApprovalError),
    Lease(LeaseError),
    Durable(DurableControlError),
    TransitionPlan(TransitionPlanError),
    InvalidPlan,
    ContextMismatch,
    PlanFingerprintMismatch,
    Serialization(String),
}

impl From<ApprovalError> for SessionEndControlError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<LeaseError> for SessionEndControlError {
    fn from(error: LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl From<DurableControlError> for SessionEndControlError {
    fn from(error: DurableControlError) -> Self {
        Self::Durable(error)
    }
}

impl fmt::Display for SessionEndControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::Durable(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::InvalidPlan => formatter.write_str("session end plan is invalid"),
            Self::ContextMismatch => {
                formatter.write_str("session belongs to a different repository workspace")
            }
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed session end plan no longer matches current state")
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "session end plan serialization failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for SessionEndControlError {}
