use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    sessions::{
        ForceMode, GatewayInstallState, GatewayModeManager, GatewayModeState, GatewayModeTarget,
        GatewayRoutingState, LeaseError, SessionAuthorityKey, SessionManager,
    },
    state::atomic_json::StateRevision,
    transitions::EffectActivation,
};

pub const GATEWAY_MODE_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayModeAction {
    Install,
    Activate,
    Off,
    Detach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayModePlan {
    pub schema_version: u32,
    pub target: GatewayModeTarget,
    pub action: GatewayModeAction,
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<GatewayModeState>,
    pub desired_installation: GatewayInstallState,
    pub desired_routing: GatewayRoutingState,
    pub no_op: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocking_sessions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

impl GatewayModePlan {
    pub fn verify(&self) -> Result<(), GatewayModeControlError> {
        if self.schema_version != GATEWAY_MODE_PLAN_SCHEMA_VERSION {
            return Err(GatewayModeControlError::InvalidPlan);
        }
        let actual = fingerprint(
            &self.target,
            self.action,
            self.force,
            self.expected_revision.as_ref(),
            self.current.as_ref(),
            self.desired_installation,
            self.desired_routing,
            self.no_op,
            &self.blocking_sessions,
            self.blocked_reason.as_deref(),
            self.activation,
        )?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(GatewayModeControlError::PlanFingerprintMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayModeApplyStatus {
    Applied,
    NoOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayModeApplyResult {
    pub status: GatewayModeApplyStatus,
    pub target: GatewayModeTarget,
    pub action: GatewayModeAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<GatewayModeState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub draining_sessions: Vec<String>,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct GatewayModeController {
    modes: GatewayModeManager,
    sessions: SessionManager,
}

impl GatewayModeController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        let app_state_root = app_state_root.into();
        let sessions = SessionManager::new(&app_state_root);
        Self {
            modes: GatewayModeManager::new(app_state_root, sessions.clone()),
            sessions,
        }
    }

    #[must_use]
    pub fn with_authority_key(
        app_state_root: impl Into<std::path::PathBuf>,
        authority_key: SessionAuthorityKey,
    ) -> Self {
        let app_state_root = app_state_root.into();
        let sessions = SessionManager::with_authority_key(&app_state_root, authority_key);
        Self {
            modes: GatewayModeManager::new(app_state_root, sessions.clone()),
            sessions,
        }
    }

    pub fn status(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<Option<GatewayModeState>, GatewayModeControlError> {
        self.modes
            .load(target)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.mode))
            .map_err(Into::into)
    }

    pub fn plan(
        &self,
        target: GatewayModeTarget,
        action: GatewayModeAction,
        force: bool,
    ) -> Result<GatewayModePlan, GatewayModeControlError> {
        let snapshot = self.modes.load(&target)?;
        let expected_revision = snapshot.as_ref().map(|snapshot| snapshot.revision.clone());
        let current = snapshot.map(|snapshot| snapshot.mode);
        let mut blocking_sessions = self
            .sessions
            .list()?
            .into_iter()
            .filter(|snapshot| {
                target.matches(&snapshot.lease)
                    && snapshot
                        .lease
                        .desired_exposure
                        .profile
                        .requires_gateway_routing()
                    && snapshot.lease.lifecycle.contributes_active_intent()
            })
            .map(|snapshot| snapshot.lease.session_id)
            .collect::<Vec<_>>();
        blocking_sessions.sort();
        let (desired_installation, desired_routing) = desired(action);
        let no_op = is_no_op(current.as_ref(), action);
        let blocked_reason = blocked_reason(current.as_ref(), action, force, &blocking_sessions);
        let activation = match action {
            GatewayModeAction::Install | GatewayModeAction::Activate => {
                EffectActivation::NextSessionOnly
            }
            GatewayModeAction::Off | GatewayModeAction::Detach => EffectActivation::Live,
        };
        let plan_fingerprint = fingerprint(
            &target,
            action,
            force,
            expected_revision.as_ref(),
            current.as_ref(),
            desired_installation,
            desired_routing,
            no_op,
            &blocking_sessions,
            blocked_reason.as_deref(),
            activation,
        )?;
        Ok(GatewayModePlan {
            schema_version: GATEWAY_MODE_PLAN_SCHEMA_VERSION,
            target,
            action,
            force,
            expected_revision,
            current,
            desired_installation,
            desired_routing,
            no_op,
            blocking_sessions,
            blocked_reason,
            activation,
            plan_fingerprint,
        })
    }

    pub(crate) fn apply_reviewed(
        &self,
        reviewed_plan: &GatewayModePlan,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeApplyResult, GatewayModeControlError> {
        reviewed_plan.verify()?;
        let current = self.plan(
            reviewed_plan.target.clone(),
            reviewed_plan.action,
            reviewed_plan.force,
        )?;
        if current.plan_fingerprint != reviewed_plan.plan_fingerprint {
            return Err(GatewayModeControlError::PlanFingerprintMismatch);
        }
        if let Some(reason) = current.blocked_reason {
            return Err(GatewayModeControlError::Blocked(reason));
        }
        if current.no_op {
            return Ok(GatewayModeApplyResult {
                status: GatewayModeApplyStatus::NoOp,
                target: current.target,
                action: current.action,
                mode: current.current,
                draining_sessions: Vec::new(),
                activation: current.activation,
                plan_fingerprint: current.plan_fingerprint,
            });
        }
        let (mode, draining_sessions) = match current.action {
            GatewayModeAction::Install => {
                let snapshot = self
                    .modes
                    .install(current.target.clone(), actor_id, now_unix)?;
                (Some(snapshot.mode), Vec::new())
            }
            GatewayModeAction::Activate => {
                let snapshot = self
                    .modes
                    .activate(current.target.clone(), actor_id, now_unix)?;
                (Some(snapshot.mode), Vec::new())
            }
            GatewayModeAction::Off => {
                let outcome = self.modes.turn_off(
                    current.target.clone(),
                    force_mode(current.force),
                    actor_id,
                    now_unix,
                )?;
                (Some(outcome.mode), outcome.draining_sessions)
            }
            GatewayModeAction::Detach => {
                let off = self.modes.turn_off(
                    current.target.clone(),
                    force_mode(current.force),
                    actor_id,
                    now_unix,
                )?;
                if off.draining_sessions.is_empty() {
                    let outcome = self.modes.detach(
                        current.target.clone(),
                        force_mode(current.force),
                        actor_id,
                        now_unix,
                    )?;
                    (Some(outcome.mode), outcome.draining_sessions)
                } else {
                    (Some(off.mode), off.draining_sessions)
                }
            }
        };
        Ok(GatewayModeApplyResult {
            status: GatewayModeApplyStatus::Applied,
            target: current.target,
            action: current.action,
            mode,
            draining_sessions,
            activation: current.activation,
            plan_fingerprint: current.plan_fingerprint,
        })
    }

    pub(crate) fn resume_shutdown(
        &self,
        reviewed_plan: &GatewayModePlan,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeApplyResult, GatewayModeControlError> {
        reviewed_plan.verify()?;
        if !matches!(
            reviewed_plan.action,
            GatewayModeAction::Off | GatewayModeAction::Detach
        ) {
            return Err(GatewayModeControlError::InvalidPlan);
        }
        let current = self
            .modes
            .load(&reviewed_plan.target)?
            .ok_or(GatewayModeControlError::PlanFingerprintMismatch)?;
        let partial_shape_valid = !current.mode.admission_open
            && matches!(
                current.mode.installation,
                GatewayInstallState::Installed | GatewayInstallState::Detached
            )
            && (current.mode.installation == GatewayInstallState::Installed
                || reviewed_plan.action == GatewayModeAction::Detach);
        if !partial_shape_valid {
            return Err(GatewayModeControlError::PlanFingerprintMismatch);
        }
        let off = self.modes.turn_off(
            reviewed_plan.target.clone(),
            force_mode(reviewed_plan.force),
            actor_id,
            now_unix,
        )?;
        let (mode, draining_sessions) = if off.draining_sessions.is_empty()
            && reviewed_plan.action == GatewayModeAction::Detach
        {
            let detached = self.modes.detach(
                reviewed_plan.target.clone(),
                force_mode(reviewed_plan.force),
                actor_id,
                now_unix,
            )?;
            (detached.mode, detached.draining_sessions)
        } else {
            (off.mode, off.draining_sessions)
        };
        Ok(GatewayModeApplyResult {
            status: GatewayModeApplyStatus::Applied,
            target: reviewed_plan.target.clone(),
            action: reviewed_plan.action,
            mode: Some(mode),
            draining_sessions,
            activation: reviewed_plan.activation,
            plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
        })
    }
}

fn desired(action: GatewayModeAction) -> (GatewayInstallState, GatewayRoutingState) {
    match action {
        GatewayModeAction::Install | GatewayModeAction::Off => {
            (GatewayInstallState::Installed, GatewayRoutingState::Off)
        }
        GatewayModeAction::Activate => {
            (GatewayInstallState::Installed, GatewayRoutingState::Active)
        }
        GatewayModeAction::Detach => (GatewayInstallState::Detached, GatewayRoutingState::Off),
    }
}

fn is_no_op(current: Option<&GatewayModeState>, action: GatewayModeAction) -> bool {
    match (current, action) {
        (None, GatewayModeAction::Off | GatewayModeAction::Detach) => true,
        (Some(mode), GatewayModeAction::Install) => {
            mode.installation == GatewayInstallState::Installed
                && mode.routing == GatewayRoutingState::Off
        }
        (Some(mode), GatewayModeAction::Activate) => {
            mode.installation == GatewayInstallState::Installed
                && mode.routing == GatewayRoutingState::Active
                && mode.admission_open
        }
        (Some(mode), GatewayModeAction::Off) => mode.routing == GatewayRoutingState::Off,
        (Some(mode), GatewayModeAction::Detach) => {
            mode.installation == GatewayInstallState::Detached
        }
        (None, GatewayModeAction::Install | GatewayModeAction::Activate) => false,
    }
}

fn blocked_reason(
    current: Option<&GatewayModeState>,
    action: GatewayModeAction,
    force: bool,
    blocking_sessions: &[String],
) -> Option<String> {
    if !force
        && !blocking_sessions.is_empty()
        && matches!(action, GatewayModeAction::Off | GatewayModeAction::Detach)
    {
        return Some("active-sessions".to_string());
    }
    match (current, action) {
        (None, GatewayModeAction::Activate) => Some("gateway-not-installed".to_string()),
        (Some(mode), GatewayModeAction::Activate)
            if mode.installation != GatewayInstallState::Installed =>
        {
            Some("gateway-not-installed".to_string())
        }
        (Some(mode), GatewayModeAction::Install) if mode.routing == GatewayRoutingState::Active => {
            Some("gateway-active".to_string())
        }
        _ => None,
    }
}

const fn force_mode(force: bool) -> ForceMode {
    if force { ForceMode::Yes } else { ForceMode::No }
}

#[allow(clippy::too_many_arguments)]
fn fingerprint(
    target: &GatewayModeTarget,
    action: GatewayModeAction,
    force: bool,
    expected_revision: Option<&StateRevision>,
    current: Option<&GatewayModeState>,
    desired_installation: GatewayInstallState,
    desired_routing: GatewayRoutingState,
    no_op: bool,
    blocking_sessions: &[String],
    blocked_reason: Option<&str>,
    activation: EffectActivation,
) -> Result<String, GatewayModeControlError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        target: &'a GatewayModeTarget,
        action: GatewayModeAction,
        force: bool,
        expected_revision: Option<&'a StateRevision>,
        current: Option<&'a GatewayModeState>,
        desired_installation: GatewayInstallState,
        desired_routing: GatewayRoutingState,
        no_op: bool,
        blocking_sessions: &'a [String],
        blocked_reason: Option<&'a str>,
        activation: EffectActivation,
    }
    let bytes = serde_json::to_vec(&FingerprintBody {
        schema_version: GATEWAY_MODE_PLAN_SCHEMA_VERSION,
        target,
        action,
        force,
        expected_revision,
        current,
        desired_installation,
        desired_routing,
        no_op,
        blocking_sessions,
        blocked_reason,
        activation,
    })
    .map_err(|error| GatewayModeControlError::Serialization(error.to_string()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug)]
pub enum GatewayModeControlError {
    Lease(LeaseError),
    InvalidPlan,
    PlanFingerprintMismatch,
    Blocked(String),
    Serialization(String),
}

impl From<LeaseError> for GatewayModeControlError {
    fn from(error: LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl fmt::Display for GatewayModeControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease(error) => error.fmt(formatter),
            Self::InvalidPlan => formatter.write_str("gateway mode plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed gateway plan no longer matches current state")
            }
            Self::Blocked(reason) => write!(formatter, "gateway mode change blocked: {reason}"),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "gateway mode plan serialization failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for GatewayModeControlError {}
