use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
        ControlOperationKind, approval_binding_digest,
    },
    config::{get_gateway_mode_path, get_transition_lock_dir},
    control_operation::{
        DurableControlError, DurableControlJournal, DurableControlStart, DurableControlTerminal,
        DurableControlTerminalStatus,
    },
    mutation::BackupAuthenticationKey,
    profiles::{
        GatewaySelection, PolicyApplyResult, PolicyApplyStatus, PolicyChange, PolicyChangePlan,
        PolicyControlError, PolicySnapshot, PolicyStore, PolicyTarget, ProfilePolicyController,
        ScopePolicy, policy_resource_id,
    },
    providers::ProviderId,
    sessions::{
        GatewayModeAction, GatewayModeApplyResult, GatewayModeApplyStatus, GatewayModeControlError,
        GatewayModeController, GatewayModePlan, GatewayModeState, GatewayModeTarget,
        GatewayNativeViewApplyResult, GatewayNativeViewApplyStatus, GatewayNativeViewController,
        GatewayNativeViewError, GatewayNativeViewPlan, GatewayRoutingState, SessionAuthorityKey,
        SessionManager,
    },
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateResourceLock, StateRevision, StateSnapshot,
    },
    transitions::{
        EffectAuthority, TransitionContext, TransitionEffect, TransitionEffectKind,
        TransitionJournalStore, TransitionKind, TransitionLifecycle, TransitionPlan,
        TransitionPlanError,
    },
};

use super::mode::GATEWAY_MODE_SCHEMA_VERSION;

pub const GATEWAY_WORKFLOW_PLAN_SCHEMA_VERSION: u32 = 1;
const GATEWAY_WORKFLOW_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
const GATEWAY_WORKFLOW_CHECKPOINT_PURPOSE: &[u8] = b"unpin-gateway-workflow-checkpoint-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayWorkflowPlan {
    pub schema_version: u32,
    pub mode: GatewayModePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyChangePlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_views: Option<GatewayNativeViewPlan>,
    pub plan_fingerprint: String,
}

impl GatewayWorkflowPlan {
    pub fn verify(&self) -> Result<(), GatewayWorkflowError> {
        if self.schema_version != GATEWAY_WORKFLOW_PLAN_SCHEMA_VERSION {
            return Err(GatewayWorkflowError::InvalidPlan);
        }
        self.mode.verify()?;
        if let Some(policy) = &self.policy {
            policy.verify()?;
        }
        if let Some(native_views) = &self.native_views {
            native_views.verify()?;
            if native_views.target != self.mode.target || native_views.action != self.mode.action {
                return Err(GatewayWorkflowError::InvalidPlan);
            }
        }
        let actual =
            workflow_fingerprint(&self.mode, self.policy.as_ref(), self.native_views.as_ref())?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(GatewayWorkflowError::PlanFingerprintMismatch)
        }
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, GatewayWorkflowError> {
        self.verify()?;
        let mut resources = vec![ApprovalResourceBinding {
            resource_id: gateway_mode_resource_id(&self.mode.target)?,
            pre_state_fingerprint: self
                .mode
                .expected_revision
                .as_ref()
                .map(|revision| approval_binding_digest(&revision.fingerprint)),
        }];
        if let Some(policy) = &self.policy {
            resources.push(ApprovalResourceBinding {
                resource_id: policy_resource_id(&policy.target)?,
                pre_state_fingerprint: policy
                    .expected_revision
                    .as_ref()
                    .map(|revision| approval_binding_digest(&revision.fingerprint)),
            });
        }
        if let Some(native_views) = &self.native_views {
            for entry in &native_views.entries {
                for resource_id in &entry.resource_ids {
                    resources.push(ApprovalResourceBinding {
                        resource_id: resource_id.clone(),
                        pre_state_fingerprint: Some(approval_binding_digest(match entry.current {
                            crate::catalog::adoption::NativeViewState::Present => {
                                "native-view-present"
                            }
                            crate::catalog::adoption::NativeViewState::Withdrawn => {
                                "native-view-withdrawn"
                            }
                        })),
                    });
                }
            }
        }
        Ok(ApprovalExpectation {
            issuer: CONTROL_APPROVAL_ISSUER.to_string(),
            audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
            operation_id: format!("gateway-workflow-{}", self.plan_fingerprint),
            operation_kind: ControlOperationKind::GatewayWorkflow.as_str().to_string(),
            effect_graph_digest: self.plan_fingerprint.clone(),
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: None,
            profile_digest: None,
            resources,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayWorkflowApplyResult {
    pub plan_fingerprint: String,
    pub mode: GatewayModeApplyResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::profiles::PolicyApplyResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_views: Option<GatewayNativeViewApplyResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointState<T> {
    revision: StateRevision,
    owner: OwnerGeneration,
    value: T,
}

impl<T> From<StateSnapshot<T>> for CheckpointState<T> {
    fn from(snapshot: StateSnapshot<T>) -> Self {
        Self {
            revision: snapshot.revision,
            owner: snapshot.owner,
            value: snapshot.value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModePreState {
    target: GatewayModeTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<CheckpointState<GatewayModeState>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyPreState {
    target: PolicyTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<CheckpointState<ScopePolicy>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayWorkflowCheckpoint {
    plan_fingerprint: String,
    reviewed_plan: GatewayWorkflowPlan,
    mode: ModePreState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<PolicyPreState>,
    authentication_key_id: String,
    authentication_tag: String,
}

impl GatewayWorkflowCheckpoint {
    fn new(
        reviewed: &GatewayWorkflowPlan,
        mode: ModePreState,
        policy: Option<PolicyPreState>,
        backup_authentication_key: &BackupAuthenticationKey,
    ) -> Result<Self, GatewayWorkflowError> {
        let authentication_key_id = backup_authentication_key.key_id();
        let message = checkpoint_authentication_message(
            &reviewed.plan_fingerprint,
            reviewed,
            &mode,
            policy.as_ref(),
            &authentication_key_id,
        )?;
        let authentication_tag = backup_authentication_key
            .authenticate_purpose(GATEWAY_WORKFLOW_CHECKPOINT_PURPOSE, &message)
            .map_err(|_| GatewayWorkflowError::CheckpointAuthenticationFailed)?;
        Ok(Self {
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            reviewed_plan: reviewed.clone(),
            mode,
            policy,
            authentication_key_id,
            authentication_tag,
        })
    }

    fn verify(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), GatewayWorkflowError> {
        if self.plan_fingerprint != reviewed.plan_fingerprint
            || self.reviewed_plan != *reviewed
            || self.mode.target != reviewed.mode.target
            || self.policy.as_ref().map(|policy| &policy.target)
                != reviewed.policy.as_ref().map(|policy| &policy.target)
            || self.authentication_key_id != backup_authentication_key.key_id()
        {
            return Err(GatewayWorkflowError::CheckpointAuthenticationFailed);
        }
        let message = checkpoint_authentication_message(
            &self.plan_fingerprint,
            &self.reviewed_plan,
            &self.mode,
            self.policy.as_ref(),
            &self.authentication_key_id,
        )?;
        backup_authentication_key
            .verify_purpose(
                GATEWAY_WORKFLOW_CHECKPOINT_PURPOSE,
                &message,
                &self.authentication_tag,
            )
            .map_err(|_| GatewayWorkflowError::CheckpointAuthenticationFailed)
    }
}

#[derive(Debug, Clone)]
pub struct GatewayWorkflowController {
    app_state_root: PathBuf,
    workflow_lock_path: PathBuf,
    session_authority_key: Option<SessionAuthorityKey>,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    mode: GatewayModeController,
    policy: ProfilePolicyController,
    journal: DurableControlJournal,
}

impl GatewayWorkflowController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        Self::with_optional_keys(app_state_root.into(), None, None)
    }

    #[must_use]
    pub fn with_authority_key(
        app_state_root: impl Into<std::path::PathBuf>,
        authority_key: SessionAuthorityKey,
    ) -> Self {
        Self::with_optional_keys(app_state_root.into(), Some(authority_key), None)
    }

    #[must_use]
    pub fn with_authority_keys(
        app_state_root: impl Into<std::path::PathBuf>,
        authority_key: SessionAuthorityKey,
        backup_authentication_key: BackupAuthenticationKey,
    ) -> Self {
        Self::with_optional_keys(
            app_state_root.into(),
            Some(authority_key),
            Some(backup_authentication_key),
        )
    }

    fn with_optional_keys(
        root: PathBuf,
        session_authority_key: Option<SessionAuthorityKey>,
        backup_authentication_key: Option<BackupAuthenticationKey>,
    ) -> Self {
        let mode = session_authority_key.as_ref().map_or_else(
            || GatewayModeController::new(&root),
            |key| GatewayModeController::with_authority_key(&root, key.clone()),
        );
        Self {
            app_state_root: root.clone(),
            workflow_lock_path: get_transition_lock_dir(&root).join("gateway-workflow-coordinator"),
            session_authority_key,
            backup_authentication_key,
            mode,
            policy: ProfilePolicyController::new(&root),
            journal: DurableControlJournal::new(root),
        }
    }

    pub fn plan(
        &self,
        mode_target: GatewayModeTarget,
        policy_target: PolicyTarget,
        provider: Option<ProviderId>,
        action: GatewayModeAction,
        force: bool,
    ) -> Result<GatewayWorkflowPlan, GatewayWorkflowError> {
        let mode = self.mode.plan(mode_target, action, force)?;
        let policy = match action {
            GatewayModeAction::Install => None,
            GatewayModeAction::Activate | GatewayModeAction::Off | GatewayModeAction::Detach => {
                Some(self.policy.plan(
                    policy_target,
                    provider,
                    PolicyChange {
                        profile: None,
                        gateway: Some(if action == GatewayModeAction::Activate {
                            GatewaySelection::Gateway
                        } else {
                            GatewaySelection::Native
                        }),
                        capability_lock: None,
                    },
                )?)
            }
        };
        let native_views = self
            .backup_authentication_key
            .as_ref()
            .map(|key| {
                GatewayNativeViewController::new(&self.app_state_root, key.clone())
                    .plan(mode.target.clone(), action)
            })
            .transpose()?;
        let plan_fingerprint = workflow_fingerprint(&mode, policy.as_ref(), native_views.as_ref())?;
        Ok(GatewayWorkflowPlan {
            schema_version: GATEWAY_WORKFLOW_PLAN_SCHEMA_VERSION,
            mode,
            policy,
            native_views,
            plan_fingerprint,
        })
    }

    pub fn pending_plan(
        &self,
        plan_fingerprint: &str,
    ) -> Result<Option<GatewayWorkflowPlan>, GatewayWorkflowError> {
        if !crate::is_lower_hex_digest(plan_fingerprint) {
            return Err(GatewayWorkflowError::PlanFingerprintMismatch);
        }
        let backup_authentication_key = self
            .backup_authentication_key
            .as_ref()
            .ok_or(GatewayWorkflowError::BackupAuthenticationRequired)?;
        let Some(saved) = self
            .workflow_checkpoint_store_for_fingerprint(plan_fingerprint)
            .load::<GatewayWorkflowCheckpoint>()?
        else {
            return Ok(None);
        };
        let reviewed = saved.value.reviewed_plan.clone();
        saved.value.verify(&reviewed, backup_authentication_key)?;
        reviewed.verify()?;
        let operation_id = format!("gateway-workflow-{plan_fingerprint}");
        let applying = TransitionJournalStore::new(&self.app_state_root)
            .list()
            .map_err(|error| GatewayWorkflowError::RecoveryRequired {
                phase: "journal-read-failed",
                reason: error.to_string(),
            })?
            .into_iter()
            .any(|journal| {
                journal.operation_id == operation_id
                    && journal.lifecycle == TransitionLifecycle::Applying
            });
        if !applying {
            return Err(GatewayWorkflowError::CheckpointMismatch);
        }
        Ok(Some(reviewed))
    }

    pub fn apply(
        &self,
        reviewed: &GatewayWorkflowPlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayWorkflowApplyResult, GatewayWorkflowError> {
        let expectation = reviewed.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        if let Some(reason) = &reviewed.mode.blocked_reason {
            return Err(GatewayWorkflowError::Blocked(reason.clone()));
        }
        let backup_authentication_key = self
            .backup_authentication_key
            .as_ref()
            .ok_or(GatewayWorkflowError::BackupAuthenticationRequired)?;
        let session_authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(GatewayWorkflowError::SessionAuthorityRequired)?;
        let _workflow_lock = StateResourceLock::acquire(&self.workflow_lock_path)?;
        let transition = reviewed.transition_plan(&expectation)?;
        let session_manager =
            SessionManager::with_authority_key(&self.app_state_root, session_authority_key.clone());
        let allow_forced_drain = reviewed.mode.force
            && matches!(
                reviewed.mode.action,
                GatewayModeAction::Off | GatewayModeAction::Detach
            );
        let _session_conflict_guard = session_manager
            .acquire_gateway_workflow(&transition, &reviewed.mode.target, allow_forced_drain)
            .map_err(|conflict| {
                GatewayWorkflowError::Blocked(format!(
                    "active session conflict: {}",
                    conflict.code()
                ))
            })?;
        match self.journal.begin(&transition, &authorization, actor_id)? {
            DurableControlStart::Cached(terminal) => {
                let result =
                    self.cached_apply_result(reviewed, backup_authentication_key, &terminal)?;
                if gateway_terminal_status(&result) != terminal.status {
                    return Err(DurableControlError::TerminalOutcomeUnavailable(
                        terminal.operation_id,
                    )
                    .into());
                }
                let _ = self.cleanup_checkpoint(reviewed, backup_authentication_key);
                Ok(result)
            }
            DurableControlStart::Apply(journal) => {
                let result = if journal.is_resumed() {
                    self.resume_reviewed(reviewed, backup_authentication_key, actor_id, now_unix)
                } else {
                    (|| {
                        let current_mode = self.mode.plan(
                            reviewed.mode.target.clone(),
                            reviewed.mode.action,
                            reviewed.mode.force,
                        )?;
                        if current_mode.plan_fingerprint != reviewed.mode.plan_fingerprint {
                            return Err(GatewayWorkflowError::PlanFingerprintMismatch);
                        }
                        if let Some(reviewed_policy) = &reviewed.policy {
                            let current_policy = self.policy.plan(
                                reviewed_policy.target.clone(),
                                reviewed_policy.provider,
                                reviewed_policy.change.clone(),
                            )?;
                            if current_policy.plan_fingerprint != reviewed_policy.plan_fingerprint {
                                return Err(GatewayWorkflowError::PlanFingerprintMismatch);
                            }
                        }
                        self.prepare_checkpoint(reviewed, actor_id, backup_authentication_key)?;
                        self.apply_reviewed(reviewed, backup_authentication_key, actor_id, now_unix)
                    })()
                };
                match result {
                    Ok(result) => {
                        journal.commit_with_terminal_status(gateway_terminal_status(&result))?;
                        let _ = self.cleanup_checkpoint(reviewed, backup_authentication_key);
                        Ok(result)
                    }
                    Err(error @ GatewayWorkflowError::RecoveryRequired { .. }) => {
                        journal.needs_repair("control-partial-apply")?;
                        Err(error)
                    }
                    Err(error @ GatewayWorkflowError::Draining { .. }) => Err(error),
                    Err(error) => {
                        journal.abort("control-apply-aborted")?;
                        let _ = self.cleanup_checkpoint(reviewed, backup_authentication_key);
                        Err(error)
                    }
                }
            }
        }
    }

    fn cached_apply_result(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
        terminal: &DurableControlTerminal,
    ) -> Result<GatewayWorkflowApplyResult, GatewayWorkflowError> {
        let recovery_required = || GatewayWorkflowError::RecoveryRequired {
            phase: "cached-post-state-diverged",
            reason: format!(
                "committed operation {} no longer matches live state",
                terminal.operation_id
            ),
        };
        let current_mode = self
            .mode
            .plan(
                reviewed.mode.target.clone(),
                reviewed.mode.action,
                reviewed.mode.force,
            )
            .map_err(|_| recovery_required())?;
        let applied_post_state_matches = current_mode.current.as_ref().is_some_and(|mode| {
            mode.installation == reviewed.mode.desired_installation
                && mode.routing == reviewed.mode.desired_routing
                && mode.admission_open
                    == matches!(reviewed.mode.action, GatewayModeAction::Activate)
        });
        if !current_mode.no_op || (!reviewed.mode.no_op && !applied_post_state_matches) {
            return Err(recovery_required());
        }
        let mode_status = if reviewed.mode.no_op {
            GatewayModeApplyStatus::NoOp
        } else {
            GatewayModeApplyStatus::Applied
        };
        let draining_sessions = if mode_status == GatewayModeApplyStatus::Applied
            && matches!(
                reviewed.mode.action,
                GatewayModeAction::Off | GatewayModeAction::Detach
            ) {
            reviewed.mode.blocking_sessions.clone()
        } else {
            Vec::new()
        };
        let mode = GatewayModeApplyResult {
            status: mode_status,
            target: reviewed.mode.target.clone(),
            action: reviewed.mode.action,
            mode: current_mode.current,
            draining_sessions,
            activation: reviewed.mode.activation,
            plan_fingerprint: reviewed.mode.plan_fingerprint.clone(),
        };
        let policy = reviewed
            .policy
            .as_ref()
            .map(|plan| -> Result<PolicyApplyResult, GatewayWorkflowError> {
                let snapshot = self
                    .policy_snapshot(&plan.target)
                    .map_err(|_| recovery_required())?;
                let current_policy = snapshot
                    .as_ref()
                    .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
                if current_policy != plan.resulting_policy || (!plan.no_op && snapshot.is_none()) {
                    return Err(recovery_required());
                }
                Ok(PolicyApplyResult {
                    status: if plan.no_op {
                        PolicyApplyStatus::NoOp
                    } else {
                        PolicyApplyStatus::Applied
                    },
                    target: plan.target.clone(),
                    provider: plan.provider,
                    revision: snapshot.as_ref().map(|snapshot| snapshot.revision.clone()),
                    policy: current_policy,
                    activation: plan.activation,
                    plan_fingerprint: plan.plan_fingerprint.clone(),
                })
            })
            .transpose()?;
        let native_view_controller = GatewayNativeViewController::new(
            &self.app_state_root,
            backup_authentication_key.clone(),
        );
        let native_views = reviewed
            .native_views
            .as_ref()
            .map(|plan| {
                native_view_controller
                    .cached_apply_result(plan)
                    .map_err(|_| recovery_required())
            })
            .transpose()?;
        Ok(GatewayWorkflowApplyResult {
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            mode,
            policy,
            native_views,
        })
    }

    fn resume_reviewed(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayWorkflowApplyResult, GatewayWorkflowError> {
        let checkpoint =
            self.verified_checkpoint_for_compensation(reviewed, backup_authentication_key)?;
        let terminal = DurableControlTerminal {
            operation_id: format!("gateway-workflow-{}", reviewed.plan_fingerprint),
            operation_kind: TransitionKind::GatewayWorkflow.as_str().to_string(),
            effect_graph_digest: reviewed.plan_fingerprint.clone(),
            status: gateway_plan_terminal_status(reviewed),
        };
        if let Ok(result) = self.cached_apply_result(reviewed, backup_authentication_key, &terminal)
        {
            return Ok(result);
        }

        let native_view_controller = GatewayNativeViewController::new(
            &self.app_state_root,
            backup_authentication_key.clone(),
        );
        let mut native_views = if reviewed.mode.action == GatewayModeAction::Activate {
            reviewed
                .native_views
                .as_ref()
                .map(|plan| native_view_controller.resume_pending(plan, actor_id))
                .transpose()?
        } else {
            None
        };
        let mode = self.resume_mode(reviewed, &checkpoint, actor_id, now_unix)?;
        if !mode.draining_sessions.is_empty() {
            return Err(GatewayWorkflowError::Draining {
                session_ids: mode.draining_sessions.clone(),
            });
        }
        let policy = reviewed
            .policy
            .as_ref()
            .map(|plan| self.resume_policy(plan, &checkpoint, actor_id))
            .transpose()?;
        match reviewed.mode.action {
            GatewayModeAction::Activate => {
                if let Some(plan) = &reviewed.native_views {
                    native_view_controller.finalize_activate(plan)?;
                }
            }
            GatewayModeAction::Install | GatewayModeAction::Off | GatewayModeAction::Detach => {
                native_views = reviewed
                    .native_views
                    .as_ref()
                    .map(|plan| native_view_controller.resume_pending(plan, actor_id))
                    .transpose()?;
            }
        }
        Ok(GatewayWorkflowApplyResult {
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            mode,
            policy,
            native_views,
        })
    }

    fn resume_mode(
        &self,
        reviewed: &GatewayWorkflowPlan,
        checkpoint: &GatewayWorkflowCheckpoint,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeApplyResult, GatewayWorkflowError> {
        let current = self
            .mode_store(&reviewed.mode.target)?
            .load::<GatewayModeState>()?;
        let expected_admission = reviewed.mode.action == GatewayModeAction::Activate;
        if current.as_ref().is_some_and(|snapshot| {
            snapshot.value.installation == reviewed.mode.desired_installation
                && snapshot.value.routing == reviewed.mode.desired_routing
                && snapshot.value.admission_open == expected_admission
        }) {
            return Ok(GatewayModeApplyResult {
                status: if reviewed.mode.no_op {
                    GatewayModeApplyStatus::NoOp
                } else {
                    GatewayModeApplyStatus::Applied
                },
                target: reviewed.mode.target.clone(),
                action: reviewed.mode.action,
                mode: current.map(|snapshot| snapshot.value),
                draining_sessions: Vec::new(),
                activation: reviewed.mode.activation,
                plan_fingerprint: reviewed.mode.plan_fingerprint.clone(),
            });
        }
        if self
            .mode_matches_pre_state(&checkpoint.mode)
            .map_err(|reason| GatewayWorkflowError::RecoveryRequired {
                phase: "gateway-mode-resume-read-failed",
                reason,
            })?
        {
            return self
                .mode
                .apply_reviewed(&reviewed.mode, actor_id, now_unix)
                .map_err(Into::into);
        }
        if matches!(
            reviewed.mode.action,
            GatewayModeAction::Off | GatewayModeAction::Detach
        ) {
            return self
                .mode
                .resume_shutdown(&reviewed.mode, actor_id, now_unix)
                .map_err(Into::into);
        }
        Err(GatewayWorkflowError::RecoveryRequired {
            phase: "gateway-mode-resume-diverged",
            reason: "gateway mode matches neither reviewed pre-state nor desired post-state"
                .to_string(),
        })
    }

    fn resume_policy(
        &self,
        reviewed: &PolicyChangePlan,
        checkpoint: &GatewayWorkflowCheckpoint,
        actor_id: &str,
    ) -> Result<PolicyApplyResult, GatewayWorkflowError> {
        let current = self.policy_snapshot(&reviewed.target)?;
        let current_policy = current
            .as_ref()
            .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
        if current_policy == reviewed.resulting_policy {
            return Ok(PolicyApplyResult {
                status: if reviewed.no_op {
                    PolicyApplyStatus::NoOp
                } else {
                    PolicyApplyStatus::Applied
                },
                target: reviewed.target.clone(),
                provider: reviewed.provider,
                revision: current.map(|snapshot| snapshot.revision),
                policy: current_policy,
                activation: reviewed.activation,
                plan_fingerprint: reviewed.plan_fingerprint.clone(),
            });
        }
        let expected = checkpoint
            .policy
            .as_ref()
            .ok_or(GatewayWorkflowError::CheckpointMismatch)?;
        let matches_pre_state = match (current.as_ref(), expected.state.as_ref()) {
            (Some(current), Some(expected)) => {
                current.revision == expected.revision
                    && current.owner == expected.owner
                    && current.policy == expected.value
            }
            (None, None) => true,
            _ => false,
        };
        if matches_pre_state {
            return self
                .policy
                .apply_reviewed(reviewed, actor_id)
                .map_err(Into::into);
        }
        Err(GatewayWorkflowError::RecoveryRequired {
            phase: "gateway-policy-resume-diverged",
            reason: "gateway policy matches neither reviewed pre-state nor desired post-state"
                .to_string(),
        })
    }

    fn apply_reviewed(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayWorkflowApplyResult, GatewayWorkflowError> {
        if reviewed.native_views.is_none() && reviewed.mode.action != GatewayModeAction::Install {
            return Err(GatewayWorkflowError::PlanFingerprintMismatch);
        }
        let native_view_controller = GatewayNativeViewController::new(
            &self.app_state_root,
            backup_authentication_key.clone(),
        );
        let mut native_views = if reviewed.mode.action == GatewayModeAction::Activate {
            reviewed
                .native_views
                .as_ref()
                .map(|plan| {
                    native_view_controller
                        .apply_pending(plan, actor_id)
                        .map_err(|error| match error {
                            error @ GatewayNativeViewError::RecoveryRequired { .. } => {
                                GatewayWorkflowError::RecoveryRequired {
                                    phase: "native-view-activate-withdraw-failed",
                                    reason: error.to_string(),
                                }
                            }
                            error => GatewayWorkflowError::NativeViews(error),
                        })
                })
                .transpose()?
        } else {
            None
        };

        let mode_policy = (|| -> Result<_, GatewayWorkflowError> {
            let mode;
            let policy;
            match reviewed.mode.action {
                GatewayModeAction::Install | GatewayModeAction::Activate => {
                    mode = self
                        .mode
                        .apply_reviewed(&reviewed.mode, actor_id, now_unix)?;
                    let mode_effect =
                        self.capture_mode_effect(&reviewed.mode, &mode)
                            .map_err(|reason| GatewayWorkflowError::RecoveryRequired {
                                phase: "lifecycle-changed-checkpoint-failed",
                                reason,
                            })?;
                    policy = match reviewed.policy.as_ref() {
                        Some(plan) => {
                            let policy_before_apply = match self.policy_snapshot(&plan.target) {
                                Ok(checkpoint) => checkpoint,
                                Err(error) => {
                                    return Err(self.mode_then_policy_failure(
                                        reviewed,
                                        backup_authentication_key,
                                        mode_effect.as_ref(),
                                        actor_id,
                                        error,
                                        None,
                                    ));
                                }
                            };
                            match self.policy.apply_reviewed(plan, actor_id) {
                                Ok(result) => {
                                    self.capture_policy_effect(plan, &result).map_err(
                                        |reason| GatewayWorkflowError::RecoveryRequired {
                                            phase: "policy-changed-checkpoint-failed",
                                            reason,
                                        },
                                    )?;
                                    Some(result)
                                }
                                Err(error) => {
                                    return Err(self.mode_then_policy_failure(
                                        reviewed,
                                        backup_authentication_key,
                                        mode_effect.as_ref(),
                                        actor_id,
                                        error,
                                        Some((plan, &policy_before_apply)),
                                    ));
                                }
                            }
                        }
                        None => None,
                    };
                }
                GatewayModeAction::Off | GatewayModeAction::Detach => {
                    mode = match self.mode.apply_reviewed(&reviewed.mode, actor_id, now_unix) {
                        Ok(result) => result,
                        Err(error) => return Err(error.into()),
                    };
                    let mode_effect =
                        self.capture_mode_effect(&reviewed.mode, &mode)
                            .map_err(|reason| GatewayWorkflowError::RecoveryRequired {
                                phase: "lifecycle-changed-checkpoint-failed",
                                reason,
                            })?;
                    if !mode.draining_sessions.is_empty() {
                        return Err(GatewayWorkflowError::Draining {
                            session_ids: mode.draining_sessions.clone(),
                        });
                    }
                    if mode.mode.as_ref().is_some_and(|mode| {
                        mode.routing != GatewayRoutingState::Off || mode.admission_open
                    }) {
                        return Err(GatewayWorkflowError::RecoveryRequired {
                            phase: "gateway-routing-not-off",
                            reason: "gateway routing has not reached off state".to_string(),
                        });
                    }
                    policy = match reviewed.policy.as_ref() {
                        Some(plan) => {
                            let policy_before_apply = self.policy_snapshot(&plan.target)?;
                            match self.policy.apply_reviewed(plan, actor_id) {
                                Ok(result) => {
                                    self.capture_policy_effect(plan, &result).map_err(
                                        |reason| GatewayWorkflowError::RecoveryRequired {
                                            phase: "native-policy-checkpoint-failed",
                                            reason,
                                        },
                                    )?;
                                    Some(result)
                                }
                                Err(error) => {
                                    return Err(self.mode_then_policy_failure(
                                        reviewed,
                                        backup_authentication_key,
                                        mode_effect.as_ref(),
                                        actor_id,
                                        error,
                                        Some((plan, &policy_before_apply)),
                                    ));
                                }
                            }
                        }
                        None => None,
                    };
                }
            }
            Ok((mode, policy))
        })();
        let (mode, policy) = match mode_policy {
            Ok(result) => result,
            Err(error)
                if native_views.as_ref().is_some_and(|result| {
                    result.status == GatewayNativeViewApplyStatus::Applied
                }) =>
            {
                let plan = reviewed
                    .native_views
                    .as_ref()
                    .ok_or(GatewayWorkflowError::PlanFingerprintMismatch)?;
                match native_view_controller.compensate_activate(plan) {
                    Ok(()) => return Err(error),
                    Err(compensation_error) => {
                        return Err(GatewayWorkflowError::RecoveryRequired {
                            phase: "native-views-withdrawn-lifecycle-failed",
                            reason: format!(
                                "{error}; native-view compensation failed: {compensation_error}"
                            ),
                        });
                    }
                }
            }
            Err(error) => return Err(error),
        };

        match reviewed.mode.action {
            GatewayModeAction::Activate => {
                if let Some(plan) = &reviewed.native_views {
                    native_view_controller
                        .finalize_activate(plan)
                        .map_err(|error| GatewayWorkflowError::RecoveryRequired {
                            phase: "native-view-ledger-finalize-failed",
                            reason: error.to_string(),
                        })?;
                }
            }
            GatewayModeAction::Off | GatewayModeAction::Detach | GatewayModeAction::Install => {
                native_views = reviewed
                    .native_views
                    .as_ref()
                    .map(|plan| native_view_controller.apply(plan, actor_id))
                    .transpose()
                    .map_err(|error| GatewayWorkflowError::RecoveryRequired {
                        phase: "native-view-transition-failed",
                        reason: error.to_string(),
                    })?;
            }
        }
        Ok(GatewayWorkflowApplyResult {
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            mode,
            policy,
            native_views,
        })
    }

    fn prepare_checkpoint(
        &self,
        reviewed: &GatewayWorkflowPlan,
        actor_id: &str,
        backup_authentication_key: &BackupAuthenticationKey,
    ) -> Result<GatewayWorkflowCheckpoint, GatewayWorkflowError> {
        let mode_snapshot = self
            .mode_store(&reviewed.mode.target)?
            .load::<GatewayModeState>()?;
        if mode_snapshot.as_ref().map(|snapshot| &snapshot.revision)
            != reviewed.mode.expected_revision.as_ref()
            || mode_snapshot.as_ref().map(|snapshot| &snapshot.value)
                != reviewed.mode.current.as_ref()
        {
            return Err(GatewayWorkflowError::PlanFingerprintMismatch);
        }
        if let Some(snapshot) = &mode_snapshot {
            snapshot
                .value
                .verify()
                .map_err(GatewayModeControlError::from)?;
        }
        let mode = ModePreState {
            target: reviewed.mode.target.clone(),
            state: mode_snapshot.map(CheckpointState::from),
        };
        let policy = reviewed
            .policy
            .as_ref()
            .map(|plan| {
                let snapshot = self.policy_snapshot(&plan.target)?;
                if snapshot.as_ref().map(|snapshot| &snapshot.revision)
                    != plan.expected_revision.as_ref()
                {
                    return Err(GatewayWorkflowError::PlanFingerprintMismatch);
                }
                Ok(PolicyPreState {
                    target: plan.target.clone(),
                    state: snapshot.map(|snapshot| CheckpointState {
                        revision: snapshot.revision,
                        owner: snapshot.owner,
                        value: snapshot.policy,
                    }),
                })
            })
            .transpose()?;
        let expected =
            GatewayWorkflowCheckpoint::new(reviewed, mode, policy, backup_authentication_key)?;
        let store = self.workflow_checkpoint_store(reviewed);
        if let Some(saved) = store.load::<GatewayWorkflowCheckpoint>()? {
            saved.value.verify(reviewed, backup_authentication_key)?;
            if saved.value != expected {
                return Err(GatewayWorkflowError::CheckpointMismatch);
            }
            return Ok(saved.value);
        }
        let revision =
            store.compare_and_swap(None, OwnerGeneration::new(actor_id, 1)?, &expected)?;
        let saved = store
            .load::<GatewayWorkflowCheckpoint>()?
            .ok_or(GatewayWorkflowError::CheckpointMismatch)?;
        saved.value.verify(reviewed, backup_authentication_key)?;
        if saved.revision != revision || saved.value != expected {
            return Err(GatewayWorkflowError::CheckpointMismatch);
        }
        Ok(saved.value)
    }

    fn capture_mode_effect(
        &self,
        reviewed: &GatewayModePlan,
        applied: &GatewayModeApplyResult,
    ) -> Result<Option<StateSnapshot<GatewayModeState>>, String> {
        if applied.status == GatewayModeApplyStatus::NoOp {
            return Ok(None);
        }
        let store = self
            .mode_store(&reviewed.target)
            .map_err(|error| error.to_string())?;
        let checkpoint = store
            .load::<GatewayModeState>()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "applied gateway mode checkpoint is missing".to_string())?;
        checkpoint
            .value
            .verify()
            .map_err(|error| error.to_string())?;
        if applied.mode.as_ref() != Some(&checkpoint.value) {
            return Err("applied gateway mode changed before checkpoint".to_string());
        }
        Ok(Some(checkpoint))
    }

    fn capture_policy_effect(
        &self,
        reviewed: &PolicyChangePlan,
        applied: &PolicyApplyResult,
    ) -> Result<Option<PolicySnapshot>, String> {
        if applied.status == PolicyApplyStatus::NoOp {
            return Ok(None);
        }
        let checkpoint = self
            .policy_snapshot(&reviewed.target)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "applied policy checkpoint is missing".to_string())?;
        if applied.revision.as_ref() != Some(&checkpoint.revision)
            || applied.policy != checkpoint.policy
        {
            return Err("applied policy changed before checkpoint".to_string());
        }
        Ok(Some(checkpoint))
    }

    fn policy_snapshot(
        &self,
        target: &PolicyTarget,
    ) -> Result<Option<PolicySnapshot>, PolicyControlError> {
        PolicyStore::new(&self.app_state_root)
            .load(target)
            .map_err(Into::into)
    }

    fn mode_then_policy_failure(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
        mode_effect: Option<&StateSnapshot<GatewayModeState>>,
        actor_id: &str,
        error: PolicyControlError,
        policy_before_apply: Option<(&PolicyChangePlan, &Option<PolicySnapshot>)>,
    ) -> GatewayWorkflowError {
        let checkpoint =
            match self.verified_checkpoint_for_compensation(reviewed, backup_authentication_key) {
                Ok(checkpoint) => checkpoint,
                Err(error) => return checkpoint_recovery_error(error),
            };
        let policy_state_problem = policy_before_apply.and_then(|(plan, expected)| {
            self.rollback_failed_policy_effect(&checkpoint, plan, expected, actor_id)
                .err()
        });
        let compensation_problem = self
            .compensate_mode(&checkpoint.mode, mode_effect, actor_id)
            .err();
        if policy_state_problem.is_none() && compensation_problem.is_none() {
            return GatewayWorkflowError::Policy(error);
        }

        let mut reason = error.to_string();
        if let Some(problem) = policy_state_problem {
            reason.push_str("; ");
            reason.push_str(&problem);
        }
        if let Some(problem) = compensation_problem {
            reason.push_str("; mode compensation failed: ");
            reason.push_str(&problem);
        }
        GatewayWorkflowError::RecoveryRequired {
            phase: "lifecycle-changed-policy-failed",
            reason,
        }
    }

    fn rollback_failed_policy_effect(
        &self,
        checkpoint: &GatewayWorkflowCheckpoint,
        plan: &PolicyChangePlan,
        before_apply: &Option<PolicySnapshot>,
        actor_id: &str,
    ) -> Result<(), String> {
        let current = self
            .policy_snapshot(&plan.target)
            .map_err(|error| format!("policy state verification failed: {error}"))?;
        if current.as_ref() == before_apply.as_ref() {
            return Ok(());
        }
        let Some(current) = current.as_ref() else {
            return Err("policy state disappeared while policy apply failed".to_string());
        };
        if current.policy != plan.resulting_policy {
            return Err("policy state drifted while policy apply failed".to_string());
        }
        let pre_state = checkpoint
            .policy
            .as_ref()
            .ok_or_else(|| "durable policy checkpoint is missing".to_string())?;
        self.compensate_policy(pre_state, Some(current), actor_id)
    }

    fn compensate_mode(
        &self,
        pre_state: &ModePreState,
        checkpoint: Option<&StateSnapshot<GatewayModeState>>,
        actor_id: &str,
    ) -> Result<(), String> {
        let Some(checkpoint) = checkpoint else {
            return Ok(());
        };
        let store = self
            .mode_store(&pre_state.target)
            .map_err(|error| error.to_string())?;
        match pre_state.state.as_ref() {
            Some(previous) => {
                previous.value.verify().map_err(|error| error.to_string())?;
                let generation = checkpoint
                    .owner
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| "gateway mode owner generation overflow".to_string())?;
                let owner = OwnerGeneration::new(actor_id, generation)
                    .map_err(|error| error.to_string())?;
                store
                    .compare_and_swap(Some(&checkpoint.revision), owner, &previous.value)
                    .map_err(|error| error.to_string())?;
            }
            None => store
                .remove_if_revision(&checkpoint.revision)
                .map_err(|error| error.to_string())?,
        }

        let restored = store
            .load::<GatewayModeState>()
            .map_err(|error| error.to_string())?;
        if restored.as_ref().map(|snapshot| &snapshot.value)
            != pre_state.state.as_ref().map(|snapshot| &snapshot.value)
        {
            return Err("gateway mode compensation could not be verified".to_string());
        }
        Ok(())
    }

    fn compensate_policy(
        &self,
        pre_state: &PolicyPreState,
        checkpoint: Option<&PolicySnapshot>,
        actor_id: &str,
    ) -> Result<(), String> {
        let Some(checkpoint) = checkpoint else {
            return Ok(());
        };
        let generation = checkpoint
            .owner
            .generation
            .checked_add(1)
            .ok_or_else(|| "policy owner generation overflow".to_string())?;
        let owner =
            OwnerGeneration::new(actor_id, generation).map_err(|error| error.to_string())?;
        let store = PolicyStore::new(&self.app_state_root);
        store
            .restore_checkpoint(
                &pre_state.target,
                pre_state.state.as_ref().map(|snapshot| &snapshot.value),
                &checkpoint.revision,
                owner,
            )
            .map_err(|error| error.to_string())?;
        let restored = store
            .load(&pre_state.target)
            .map_err(|error| error.to_string())?;
        if restored.as_ref().map(|snapshot| &snapshot.policy)
            != pre_state.state.as_ref().map(|snapshot| &snapshot.value)
        {
            return Err("policy compensation could not be verified".to_string());
        }
        Ok(())
    }

    fn mode_matches_pre_state(&self, pre_state: &ModePreState) -> Result<bool, String> {
        let current = self
            .mode_store(&pre_state.target)
            .map_err(|error| error.to_string())?
            .load::<GatewayModeState>()
            .map_err(|error| error.to_string())?;
        Ok(match (current.as_ref(), pre_state.state.as_ref()) {
            (None, None) => true,
            (Some(current), Some(expected)) => {
                current.revision == expected.revision
                    && current.owner == expected.owner
                    && current.value == expected.value
            }
            _ => false,
        })
    }

    fn verified_checkpoint_for_compensation(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
    ) -> Result<GatewayWorkflowCheckpoint, GatewayWorkflowError> {
        let saved = self
            .workflow_checkpoint_store(reviewed)
            .load::<GatewayWorkflowCheckpoint>()?
            .ok_or(GatewayWorkflowError::CheckpointMismatch)?;
        saved.value.verify(reviewed, backup_authentication_key)?;
        Ok(saved.value)
    }

    fn cleanup_checkpoint(
        &self,
        reviewed: &GatewayWorkflowPlan,
        backup_authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), GatewayWorkflowError> {
        let store = self.workflow_checkpoint_store(reviewed);
        let Some(saved) = store.load::<GatewayWorkflowCheckpoint>()? else {
            return Ok(());
        };
        saved.value.verify(reviewed, backup_authentication_key)?;
        store.remove_if_revision(&saved.revision)?;
        Ok(())
    }

    fn mode_store(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<AtomicJsonStore, GatewayWorkflowError> {
        let key = target.key().map_err(GatewayModeControlError::from)?;
        Ok(AtomicJsonStore::new(
            get_gateway_mode_path(&self.app_state_root, &key),
            GATEWAY_MODE_SCHEMA_VERSION,
        ))
    }

    fn workflow_checkpoint_store(&self, reviewed: &GatewayWorkflowPlan) -> AtomicJsonStore {
        self.workflow_checkpoint_store_for_fingerprint(&reviewed.plan_fingerprint)
    }

    fn workflow_checkpoint_store_for_fingerprint(&self, plan_fingerprint: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.app_state_root
                .join("transactions")
                .join("checkpoints")
                .join(format!("gateway-workflow-{}.json", &plan_fingerprint[..32])),
            GATEWAY_WORKFLOW_CHECKPOINT_SCHEMA_VERSION,
        )
    }
}

impl GatewayWorkflowPlan {
    fn transition_plan(
        &self,
        expectation: &ApprovalExpectation,
    ) -> Result<TransitionPlan, GatewayWorkflowError> {
        let provider_views = self
            .mode
            .target
            .provider
            .map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]);
        let mut effects = vec![TransitionEffect {
            effect_id: "gateway-mode-effect".to_string(),
            kind: match self.mode.action {
                GatewayModeAction::Install | GatewayModeAction::Activate => {
                    TransitionEffectKind::InstallBridge
                }
                GatewayModeAction::Off | GatewayModeAction::Detach => {
                    TransitionEffectKind::DetachBridge
                }
            },
            resource_id: gateway_mode_resource_id(&self.mode.target)?,
            target_type: "gateway-mode".to_string(),
            summary: "Apply reviewed gateway lifecycle state".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: self.mode.activation,
            expected_pre_fingerprint: self
                .mode
                .expected_revision
                .as_ref()
                .map(|revision| approval_binding_digest(&revision.fingerprint)),
            expected_post_fingerprint: Some(serialized_digest(&self.mode)?),
            provider_views: provider_views.clone(),
        }];
        if let Some(policy) = &self.policy {
            effects.push(TransitionEffect {
                effect_id: "gateway-policy-effect".to_string(),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: policy_resource_id(&policy.target)?,
                target_type: "unpin-policy".to_string(),
                summary: "Apply gateway selection policy for future sessions".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: policy.activation,
                expected_pre_fingerprint: policy
                    .expected_revision
                    .as_ref()
                    .map(|revision| approval_binding_digest(&revision.fingerprint)),
                expected_post_fingerprint: Some(serialized_digest(&policy.resulting_policy)?),
                provider_views: provider_views.clone(),
            });
        }
        if let Some(native_views) = &self.native_views {
            for (entry_index, entry) in native_views.entries.iter().enumerate() {
                for (resource_index, resource_id) in entry.resource_ids.iter().enumerate() {
                    effects.push(TransitionEffect {
                        effect_id: format!("gateway-native-view-{entry_index}-{resource_index}"),
                        kind: match entry.desired {
                            crate::catalog::adoption::NativeViewState::Present => {
                                TransitionEffectKind::PublishView
                            }
                            crate::catalog::adoption::NativeViewState::Withdrawn => {
                                TransitionEffectKind::WithdrawView
                            }
                        },
                        resource_id: resource_id.clone(),
                        target_type: "adopted-native-view".to_string(),
                        summary: format!(
                            "Transition adopted native view for {} to {:?}",
                            entry.capability_id, entry.desired
                        ),
                        authority: EffectAuthority::UserManaged,
                        activation: self.mode.activation,
                        expected_pre_fingerprint: Some(approval_binding_digest(
                            match entry.current {
                                crate::catalog::adoption::NativeViewState::Present => {
                                    "native-view-present"
                                }
                                crate::catalog::adoption::NativeViewState::Withdrawn => {
                                    "native-view-withdrawn"
                                }
                            },
                        )),
                        expected_post_fingerprint: Some(approval_binding_digest(
                            match entry.desired {
                                crate::catalog::adoption::NativeViewState::Present => {
                                    "native-view-present"
                                }
                                crate::catalog::adoption::NativeViewState::Withdrawn => {
                                    "native-view-withdrawn"
                                }
                            },
                        )),
                        provider_views: entry.provider_views.clone(),
                    });
                }
            }
        }
        TransitionPlan::new(
            expectation.operation_id.clone(),
            TransitionKind::GatewayWorkflow,
            TransitionContext {
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: None,
                profile_digest: None,
            },
            effects,
        )
        .map_err(GatewayWorkflowError::TransitionPlan)
    }
}

fn gateway_terminal_status(result: &GatewayWorkflowApplyResult) -> DurableControlTerminalStatus {
    if result.mode.status == GatewayModeApplyStatus::NoOp
        && result
            .policy
            .as_ref()
            .is_none_or(|policy| policy.status == PolicyApplyStatus::NoOp)
        && result
            .native_views
            .as_ref()
            .is_none_or(|views| views.status == GatewayNativeViewApplyStatus::NoOp)
    {
        DurableControlTerminalStatus::NoOp
    } else {
        DurableControlTerminalStatus::Applied
    }
}

fn gateway_plan_terminal_status(plan: &GatewayWorkflowPlan) -> DurableControlTerminalStatus {
    if plan.mode.no_op
        && plan.policy.as_ref().is_none_or(|policy| policy.no_op)
        && plan.native_views.as_ref().is_none_or(|views| {
            views
                .entries
                .iter()
                .all(|entry| entry.current == entry.desired)
        })
    {
        DurableControlTerminalStatus::NoOp
    } else {
        DurableControlTerminalStatus::Applied
    }
}

fn checkpoint_authentication_message(
    plan_fingerprint: &str,
    reviewed_plan: &GatewayWorkflowPlan,
    mode: &ModePreState,
    policy: Option<&PolicyPreState>,
    authentication_key_id: &str,
) -> Result<Vec<u8>, GatewayWorkflowError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CheckpointBody<'a> {
        schema_version: u32,
        plan_fingerprint: &'a str,
        reviewed_plan: &'a GatewayWorkflowPlan,
        mode: &'a ModePreState,
        policy: Option<&'a PolicyPreState>,
        authentication_key_id: &'a str,
    }
    serde_json::to_vec(&CheckpointBody {
        schema_version: GATEWAY_WORKFLOW_CHECKPOINT_SCHEMA_VERSION,
        plan_fingerprint,
        reviewed_plan,
        mode,
        policy,
        authentication_key_id,
    })
    .map_err(|error| GatewayWorkflowError::Serialization(error.to_string()))
}

fn checkpoint_recovery_error(error: GatewayWorkflowError) -> GatewayWorkflowError {
    let phase = match &error {
        GatewayWorkflowError::CheckpointAuthenticationFailed => "checkpoint-authentication-failed",
        GatewayWorkflowError::CheckpointMismatch => "checkpoint-missing-or-mismatched",
        _ => "checkpoint-read-failed",
    };
    GatewayWorkflowError::RecoveryRequired {
        phase,
        reason: error.to_string(),
    }
}

fn workflow_fingerprint(
    mode: &GatewayModePlan,
    policy: Option<&PolicyChangePlan>,
    native_views: Option<&GatewayNativeViewPlan>,
) -> Result<String, GatewayWorkflowError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        mode: &'a GatewayModePlan,
        policy: Option<&'a PolicyChangePlan>,
        native_views: Option<&'a GatewayNativeViewPlan>,
    }
    serialized_digest(&FingerprintBody {
        schema_version: GATEWAY_WORKFLOW_PLAN_SCHEMA_VERSION,
        mode,
        policy,
        native_views,
    })
}

pub fn gateway_mode_resource_id(
    target: &GatewayModeTarget,
) -> Result<String, GatewayWorkflowError> {
    Ok(format!(
        "gateway-mode-{}",
        &serialized_digest(target)?[..16]
    ))
}

fn serialized_digest(value: &impl Serialize) -> Result<String, GatewayWorkflowError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| GatewayWorkflowError::Serialization(error.to_string()))?;
    Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
}

#[derive(Debug)]
pub enum GatewayWorkflowError {
    Approval(ApprovalError),
    Mode(GatewayModeControlError),
    Policy(PolicyControlError),
    NativeViews(GatewayNativeViewError),
    State(crate::state::atomic_json::StateError),
    Durable(DurableControlError),
    TransitionPlan(TransitionPlanError),
    InvalidPlan,
    PlanFingerprintMismatch,
    CheckpointMismatch,
    BackupAuthenticationRequired,
    SessionAuthorityRequired,
    CheckpointAuthenticationFailed,
    Blocked(String),
    Draining { session_ids: Vec<String> },
    RecoveryRequired { phase: &'static str, reason: String },
    Serialization(String),
}

impl From<ApprovalError> for GatewayWorkflowError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<GatewayModeControlError> for GatewayWorkflowError {
    fn from(error: GatewayModeControlError) -> Self {
        Self::Mode(error)
    }
}

impl From<PolicyControlError> for GatewayWorkflowError {
    fn from(error: PolicyControlError) -> Self {
        Self::Policy(error)
    }
}

impl From<GatewayNativeViewError> for GatewayWorkflowError {
    fn from(error: GatewayNativeViewError) -> Self {
        Self::NativeViews(error)
    }
}

impl From<crate::state::atomic_json::StateError> for GatewayWorkflowError {
    fn from(error: crate::state::atomic_json::StateError) -> Self {
        Self::State(error)
    }
}

impl From<DurableControlError> for GatewayWorkflowError {
    fn from(error: DurableControlError) -> Self {
        Self::Durable(error)
    }
}

impl fmt::Display for GatewayWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Mode(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::NativeViews(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::Durable(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::InvalidPlan => formatter.write_str("gateway workflow plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed gateway workflow no longer matches current state")
            }
            Self::CheckpointMismatch => {
                formatter.write_str("gateway workflow checkpoint is invalid or mismatched")
            }
            Self::BackupAuthenticationRequired => {
                formatter.write_str("gateway workflow backup authentication key is required")
            }
            Self::SessionAuthorityRequired => {
                formatter.write_str("session authority key is required to check gateway conflicts")
            }
            Self::CheckpointAuthenticationFailed => {
                formatter.write_str("gateway workflow checkpoint authentication failed")
            }
            Self::Blocked(reason) => write!(formatter, "gateway workflow blocked: {reason}"),
            Self::Draining { session_ids } => write!(
                formatter,
                "gateway workflow draining sessions; retry same plan fingerprint: {}",
                session_ids.join(",")
            ),
            Self::RecoveryRequired { phase, reason } => {
                write!(
                    formatter,
                    "gateway workflow recovery required ({phase}): {reason}"
                )
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "gateway workflow serialization failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for GatewayWorkflowError {}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;
    use tempfile::TempDir;

    use super::*;

    fn private_temp() -> TempDir {
        let temp = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn install_plan(controller: &GatewayWorkflowController) -> GatewayWorkflowPlan {
        controller
            .plan(
                GatewayModeTarget::global_provider(ProviderId::Codex),
                PolicyTarget::Global,
                Some(ProviderId::Codex),
                GatewayModeAction::Install,
                false,
            )
            .unwrap()
    }

    fn controller(
        root: &std::path::Path,
        backup_authentication_key: BackupAuthenticationKey,
    ) -> GatewayWorkflowController {
        GatewayWorkflowController::with_authority_keys(
            root,
            SessionAuthorityKey::new([0x53; 32]),
            backup_authentication_key,
        )
    }

    #[test]
    fn saved_checkpoint_rejects_wrong_backup_authentication_key() {
        let temp = private_temp();
        let root = fs::canonicalize(temp.path()).unwrap();
        let good_key = BackupAuthenticationKey::new([0x42; 32]);
        let controller = controller(&root, good_key.clone());
        let plan = install_plan(&controller);
        controller
            .prepare_checkpoint(&plan, "checkpoint-test", &good_key)
            .unwrap();

        assert!(matches!(
            controller.prepare_checkpoint(
                &plan,
                "checkpoint-test",
                &BackupAuthenticationKey::new([0x24; 32]),
            ),
            Err(GatewayWorkflowError::CheckpointAuthenticationFailed)
        ));
        assert!(
            GatewayModeController::with_authority_key(&root, SessionAuthorityKey::new([0x53; 32]),)
                .status(&plan.mode.target)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn saved_checkpoint_rejects_tampered_authentication_tag() {
        let temp = private_temp();
        let root = fs::canonicalize(temp.path()).unwrap();
        let key = BackupAuthenticationKey::new([0x42; 32]);
        let controller = controller(&root, key.clone());
        let plan = install_plan(&controller);
        controller
            .prepare_checkpoint(&plan, "checkpoint-test", &key)
            .unwrap();
        let path = controller
            .workflow_checkpoint_store(&plan)
            .path()
            .to_path_buf();
        let mut document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        document["value"]["authenticationTag"] = Value::String("00".repeat(32));
        let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();

        assert!(matches!(
            controller.prepare_checkpoint(&plan, "checkpoint-test", &key),
            Err(GatewayWorkflowError::CheckpointAuthenticationFailed)
        ));
    }
}
