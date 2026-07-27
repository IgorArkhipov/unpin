use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, CONTROL_APPROVAL_AUDIENCE, CONTROL_APPROVAL_ISSUER,
        ControlApprovalContext, ControlAuthorization,
    },
    discovery::DiscoveryItem,
    mutation::{
        BackupAuthenticationKey, TogglePlanInput, ToggleResult, ToggleStatus,
        apply_authorized_toggle_transaction, plan_toggle_inner,
    },
    sessions::SessionAuthorityKey,
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionJournal, TransitionJournalStore, TransitionKind,
        TransitionPlan, TransitionPlanError, journal::JournalError,
    },
};

pub const NATIVE_TOGGLE_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeTogglePlan {
    pub schema_version: u32,
    pub preview: ToggleResult,
    pub transition: TransitionPlan,
    pub plan_fingerprint: String,
}

impl NativeTogglePlan {
    pub fn verify(&self) -> Result<(), NativeToggleControlError> {
        if self.schema_version != NATIVE_TOGGLE_PLAN_SCHEMA_VERSION
            || self.preview.status != ToggleStatus::DryRun
            || self.transition.kind != TransitionKind::NativeToggle
        {
            return Err(NativeToggleControlError::InvalidPlan);
        }
        self.transition.verify()?;
        if self.plan_fingerprint == toggle_plan_fingerprint(&self.preview, &self.transition)? {
            Ok(())
        } else {
            Err(NativeToggleControlError::PlanFingerprintMismatch)
        }
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, NativeToggleControlError> {
        self.verify()?;
        if self.transition.context.repository_key != context.repository_key()
            || self.transition.context.workspace_key != context.workspace_key()
        {
            return Err(NativeToggleControlError::ContextMismatch);
        }
        let mut expectation = self
            .transition
            .approval_expectation(CONTROL_APPROVAL_ISSUER, CONTROL_APPROVAL_AUDIENCE);
        expectation
            .effect_graph_digest
            .clone_from(&self.plan_fingerprint);
        Ok(expectation)
    }
}

#[derive(Debug, Clone)]
pub struct NativeToggleController {
    app_state_root: PathBuf,
    session_authority_key: Option<SessionAuthorityKey>,
}

impl NativeToggleController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            session_authority_key: None,
        }
    }

    #[must_use]
    pub fn with_session_authority_key(
        app_state_root: impl Into<PathBuf>,
        session_authority_key: SessionAuthorityKey,
    ) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            session_authority_key: Some(session_authority_key),
        }
    }

    pub fn plan(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let journals = self.planning_journals()?;
        self.plan_with_journals(item, context, &journals)
    }

    pub(crate) fn planning_journals(
        &self,
    ) -> Result<Vec<TransitionJournal>, NativeToggleControlError> {
        TransitionJournalStore::new(&self.app_state_root)
            .list()
            .map_err(Into::into)
    }

    pub(crate) fn plan_with_journals(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
        journals: &[TransitionJournal],
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let preview = plan_toggle_inner(TogglePlanInput {
            app_state_root: self.app_state_root.clone(),
            item,
            apply: false,
            backup_authentication_key: None,
            session_authority_key: None,
        });
        if preview.status != ToggleStatus::DryRun {
            return Err(NativeToggleControlError::Blocked(
                preview
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native toggle cannot be planned".to_string()),
            ));
        }
        let transition = toggle_transition(&preview, context, journals)?;
        let plan = NativeTogglePlan {
            schema_version: NATIVE_TOGGLE_PLAN_SCHEMA_VERSION,
            plan_fingerprint: toggle_plan_fingerprint(&preview, &transition)?,
            preview,
            transition,
        };
        plan.verify()?;
        Ok(plan)
    }

    pub fn apply(
        &self,
        reviewed: &NativeTogglePlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        backup_authentication_key: BackupAuthenticationKey,
    ) -> Result<ToggleResult, NativeToggleControlError> {
        let expectation = reviewed.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        let result = apply_authorized_toggle_transaction(
            TogglePlanInput {
                app_state_root: self.app_state_root.clone(),
                item: reviewed.preview.selection.clone(),
                apply: true,
                backup_authentication_key: Some(backup_authentication_key),
                session_authority_key: self.session_authority_key.clone(),
            },
            &reviewed.transition,
            &authorization,
            &reviewed.preview,
        );
        if matches!(
            result.status,
            ToggleStatus::Applied | ToggleStatus::RecoveryRequired
        ) {
            Ok(result)
        } else {
            let reason = result
                .reason
                .unwrap_or_else(|| "native toggle apply was blocked".to_string());
            if let Some(reason) = reason.strip_prefix("recovery-required: ") {
                Err(NativeToggleControlError::RecoveryRequired(
                    reason.to_string(),
                ))
            } else {
                Err(NativeToggleControlError::Blocked(reason))
            }
        }
    }
}

fn toggle_plan_fingerprint(
    preview: &ToggleResult,
    transition: &TransitionPlan,
) -> Result<String, NativeToggleControlError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        preview: &'a ToggleResult,
        kind: TransitionKind,
        context: &'a TransitionContext,
        effects: &'a [TransitionEffect],
    }

    let encoded = serde_json::to_vec(&FingerprintBody {
        schema_version: NATIVE_TOGGLE_PLAN_SCHEMA_VERSION,
        preview,
        kind: transition.kind,
        context: &transition.context,
        effects: &transition.effects,
    })
    .map_err(|error| NativeToggleControlError::Serialization(error.to_string()))?;
    Ok(crate::encode_lower_hex(&Sha256::digest(encoded)))
}

fn toggle_transition(
    preview: &ToggleResult,
    context: &ControlApprovalContext,
    journals: &[TransitionJournal],
) -> Result<TransitionPlan, NativeToggleControlError> {
    let encoded = serde_json::to_vec(preview)
        .map_err(|error| NativeToggleControlError::Serialization(error.to_string()))?;
    let preview_digest = crate::encode_lower_hex(&Sha256::digest(&encoded));
    let resource_bytes = serde_json::to_vec(&preview.affected_targets)
        .map_err(|error| NativeToggleControlError::Serialization(error.to_string()))?;
    let resource_digest = crate::encode_lower_hex(&Sha256::digest(resource_bytes));
    let resource_id = format!("native-resource-{}", &resource_digest[..24]);
    let transition_context = TransitionContext {
        repository_key: context.repository_key().to_string(),
        workspace_key: context.workspace_key().to_string(),
        session_id: None,
        profile_digest: None,
    };
    let context_bytes = serde_json::to_vec(&transition_context)
        .map_err(|error| NativeToggleControlError::Serialization(error.to_string()))?;
    let context_digest = crate::encode_lower_hex(&Sha256::digest(context_bytes));
    let completed_generations = journals
        .iter()
        .filter(|journal| {
            journal.operation_kind == TransitionKind::NativeToggle.as_str()
                && journal.repository_key == transition_context.repository_key
                && journal.workspace_key == transition_context.workspace_key
                && journal.lifecycle.is_terminal()
                && journal
                    .effects
                    .iter()
                    .any(|effect| effect.resource_id == resource_id)
        })
        .count();
    let generation = completed_generations
        .checked_add(1)
        .ok_or(NativeToggleControlError::GenerationOverflow)?;
    TransitionPlan::new(
        format!(
            "native-toggle-{}-{}-{}-g{generation}",
            preview.selection.provider.as_str(),
            &preview_digest[..24],
            &context_digest[..24]
        ),
        TransitionKind::NativeToggle,
        transition_context,
        vec![TransitionEffect {
            effect_id: "native-toggle-effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id,
            target_type: "native-provider-state".to_string(),
            summary: format!("Toggle reviewed native item {}", preview.selection.id),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some(crate::encode_lower_hex(&Sha256::digest(
                [b"pre\0".as_slice(), encoded.as_slice()].concat(),
            ))),
            expected_post_fingerprint: Some(crate::encode_lower_hex(&Sha256::digest(
                [b"post\0".as_slice(), encoded.as_slice()].concat(),
            ))),
            provider_views: vec![preview.selection.provider],
        }],
    )
    .map_err(NativeToggleControlError::TransitionPlan)
}

#[derive(Debug)]
pub enum NativeToggleControlError {
    Approval(ApprovalError),
    Journal(JournalError),
    TransitionPlan(TransitionPlanError),
    InvalidPlan,
    ContextMismatch,
    PlanFingerprintMismatch,
    Blocked(String),
    RecoveryRequired(String),
    GenerationOverflow,
    Serialization(String),
}

impl NativeToggleControlError {
    #[must_use]
    pub(crate) const fn public_reason_code(&self) -> &'static str {
        match self {
            Self::Approval(_) => "approval-unavailable",
            Self::Journal(_) => "transition-state-unavailable",
            Self::TransitionPlan(_)
            | Self::InvalidPlan
            | Self::PlanFingerprintMismatch
            | Self::Serialization(_) => "native-plan-invalid",
            Self::ContextMismatch => "context-scope-conflict",
            Self::Blocked(_) => "native-plan-blocked",
            Self::RecoveryRequired(_) => "recovery-required",
            Self::GenerationOverflow => "native-plan-capacity-exceeded",
        }
    }
}

impl From<ApprovalError> for NativeToggleControlError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<JournalError> for NativeToggleControlError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<TransitionPlanError> for NativeToggleControlError {
    fn from(error: TransitionPlanError) -> Self {
        Self::TransitionPlan(error)
    }
}

impl fmt::Display for NativeToggleControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::InvalidPlan => formatter.write_str("native toggle plan is invalid"),
            Self::ContextMismatch => {
                formatter.write_str("native toggle plan context does not match workspace")
            }
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed native toggle plan no longer matches current state")
            }
            Self::Blocked(reason) => write!(formatter, "native toggle blocked: {reason}"),
            Self::RecoveryRequired(reason) => {
                write!(formatter, "native toggle recovery required: {reason}")
            }
            Self::GenerationOverflow => {
                formatter.write_str("native toggle generation counter overflowed")
            }
            Self::Serialization(message) => {
                write!(formatter, "native toggle serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for NativeToggleControlError {}
