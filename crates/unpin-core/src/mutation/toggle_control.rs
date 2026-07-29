use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, CONTROL_APPROVAL_AUDIENCE, CONTROL_APPROVAL_ISSUER,
        ControlApprovalContext, ControlAuthorization,
    },
    control_operation::{
        ControlResolvedContext, ReachAwareControlOperationEnvelope, ReachAwareOperationFamily,
        ReachAwarePayloadReference, ReachAwarePrincipal, ReachAwareRootBinding,
    },
    discovery::DiscoveryItem,
    mutation::{
        BackupAuthenticationKey, TogglePlanInput, ToggleResult, ToggleStatus,
        apply_authorized_toggle_transaction, apply_authorized_toggle_transaction_reach_aware,
        plan_toggle_inner,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, ProviderCoverageEntry, ProviderReach,
        ProviderReachCoverage, ProviderReachError, ProviderReachInput, ProviderReachLifecycle,
        ProviderReachRequest, SelectedProviderAuthority, SelectedProviderProvenance,
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
    pub provider_reach: ProviderReach,
    pub coverage: ProviderReachCoverage,
    pub plan_fingerprint: String,
}

impl NativeTogglePlan {
    pub fn verify(&self) -> Result<(), NativeToggleControlError> {
        if self.schema_version != NATIVE_TOGGLE_PLAN_SCHEMA_VERSION
            || self.preview.status != ToggleStatus::DryRun
            || self.transition.kind != TransitionKind::NativeToggle
            || self.preview.provider_reach != Some(self.provider_reach)
            || self.preview.coverage.as_ref() != Some(&self.coverage)
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
        let request = ProviderReachRequest::new(
            ConnectionBoundary::All,
            ProviderReachInput::Omitted,
            DerivedTargetKind::Individual,
        );
        self.plan_with_reach_request(item, context, request)
    }

    /// Resolve connection and explicit selected-provider authority before the
    /// native mutation planner is invoked, then reconcile the exact item
    /// provider after derivation.
    pub fn plan_with_reach(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
        boundary: ConnectionBoundary,
        reach: ProviderReachInput,
        authority_candidates: Vec<SelectedProviderAuthority>,
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let request = ProviderReachRequest {
            boundary,
            reach,
            target_kind: DerivedTargetKind::Individual,
            authority_candidates,
        };
        self.plan_with_reach_request(item, context, request)
    }

    /// Request-shaped alias for operation adapters that already construct the
    /// shared two-phase reach request.
    pub fn plan_with_reach_request(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
        request: ProviderReachRequest,
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let resolution = request
            .validate_before_discovery()?
            .reconcile_exact_target(Some(item.provider))?;
        let journals = self.planning_journals()?;
        self.plan_with_resolution_and_journals(item, context, &journals, resolution.reach, None)
    }

    pub(crate) fn plan_with_reach_for_session(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
        boundary: ConnectionBoundary,
        reach: ProviderReachInput,
        authority_candidates: Vec<SelectedProviderAuthority>,
        session_id: &str,
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let request = ProviderReachRequest {
            boundary,
            reach,
            target_kind: DerivedTargetKind::Individual,
            authority_candidates,
        };
        let resolution = request
            .validate_before_discovery()?
            .reconcile_exact_target(Some(item.provider))?;
        let journals = self.planning_journals()?;
        self.plan_with_resolution_and_journals(
            item,
            context,
            &journals,
            resolution.reach,
            Some(session_id),
        )
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
        let request = ProviderReachRequest::new(
            ConnectionBoundary::All,
            ProviderReachInput::Omitted,
            DerivedTargetKind::Individual,
        );
        let resolution = request
            .validate_before_discovery()?
            .reconcile_exact_target(Some(item.provider))?;
        self.plan_with_resolution_and_journals(item, context, journals, resolution.reach, None)
    }

    fn plan_with_resolution_and_journals(
        &self,
        item: DiscoveryItem,
        context: &ControlApprovalContext,
        journals: &[TransitionJournal],
        provider_reach: ProviderReach,
        session_id: Option<&str>,
    ) -> Result<NativeTogglePlan, NativeToggleControlError> {
        let coverage = ProviderReachCoverage::new(vec![ProviderCoverageEntry::included(
            item.provider,
            item.id.clone(),
        )]);
        let mut preview = plan_toggle_inner(TogglePlanInput {
            app_state_root: self.app_state_root.clone(),
            item,
            apply: false,
            backup_authentication_key: None,
            session_authority_key: None,
        });
        preview.provider_reach = Some(provider_reach);
        preview.coverage = Some(coverage.clone());
        if preview.status != ToggleStatus::DryRun {
            return Err(NativeToggleControlError::Blocked(
                preview
                    .reason
                    .clone()
                    .unwrap_or_else(|| "native toggle cannot be planned".to_string()),
            ));
        }
        let transition = toggle_transition(&preview, context, journals, session_id)?;
        let plan = NativeTogglePlan {
            schema_version: NATIVE_TOGGLE_PLAN_SCHEMA_VERSION,
            plan_fingerprint: toggle_plan_fingerprint(&preview, &transition)?,
            preview,
            transition,
            provider_reach,
            coverage,
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
        let mut result = apply_authorized_toggle_transaction(
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
        result.provider_reach = Some(reviewed.provider_reach);
        result.coverage = Some(reviewed.coverage.clone());
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

    /// Apply a native toggle while attaching the durable schema-v2 envelope.
    /// The caller must provide trusted provider roots and a principal that was
    /// signed by the verified session authority; the journal fills owner and
    /// revision immediately after its create/attach CAS.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_with_reach_aware(
        &self,
        reviewed: &NativeTogglePlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        backup_authentication_key: BackupAuthenticationKey,
        roots: ReachAwareRootBinding,
        audience: impl Into<String>,
        issued_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<ToggleResult, NativeToggleControlError> {
        let expectation = reviewed.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        roots
            .verify()
            .map_err(|error| NativeToggleControlError::ReachAware(error.to_string()))?;
        let session_id = expectation.session_id.clone().ok_or_else(|| {
            NativeToggleControlError::ReachAware(
                "reach-aware toggle requires a verified session identity".to_string(),
            )
        })?;
        let session_authority_key = self.session_authority_key.as_ref().ok_or_else(|| {
            NativeToggleControlError::ReachAware(
                "reach-aware toggle requires a session authority key".to_string(),
            )
        })?;
        let scope_digest = crate::encode_lower_hex(&Sha256::digest(
            format!(
                "{}\0{}\0{}",
                expectation.repository_key, expectation.workspace_key, session_id
            )
            .as_bytes(),
        ));
        let connection_boundary = derived_connection_boundary(reviewed.provider_reach);
        let principal = ReachAwarePrincipal::sign(
            session_id,
            scope_digest,
            connection_boundary,
            session_authority_key,
        )
        .map_err(|error| NativeToggleControlError::ReachAware(error.to_string()))?;
        let family = ReachAwareOperationFamily::NativeToggle;
        let provider = reviewed.provider_reach.provider();
        let selected_provider = provider.map(|provider| {
            SelectedProviderAuthority::new(
                provider,
                reviewed
                    .provider_reach
                    .provenance()
                    .unwrap_or(SelectedProviderProvenance::ExactIndividualTarget),
            )
        });
        let envelope_builder = ReachAwareControlOperationEnvelope::builder()
            .family(family, NATIVE_TOGGLE_PLAN_SCHEMA_VERSION)
            .operation(
                reviewed.transition.operation_id.clone(),
                reviewed.transition.kind.as_str(),
                reviewed.plan_fingerprint.clone(),
            )
            .context(ControlResolvedContext {
                repository_key: reviewed.transition.context.repository_key.clone(),
                workspace_key: reviewed.transition.context.workspace_key.clone(),
                session_id: reviewed.transition.context.session_id.clone(),
                profile_digest: reviewed.transition.context.profile_digest.clone(),
            })
            .reach(
                connection_boundary,
                reviewed.provider_reach,
                selected_provider,
                reviewed.coverage.clone(),
            )
            .lifecycle(
                ProviderReachLifecycle::Applied,
                ProviderReachLifecycle::Applied,
                reviewed
                    .transition
                    .effects
                    .first()
                    .map_or(EffectActivation::RestartRequired, |effect| {
                        effect.activation
                    }),
            )
            .trusted_roots(roots)
            .authority(principal, audience, issued_at_unix, expires_at_unix)
            .payload_reference(ReachAwarePayloadReference {
                family,
                schema_version: NATIVE_TOGGLE_PLAN_SCHEMA_VERSION,
                reference: reviewed.transition.operation_id.clone(),
                payload_digest: reviewed.plan_fingerprint.clone(),
            })
            .transfer_capability(None);
        let mut result = apply_authorized_toggle_transaction_reach_aware(
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
            envelope_builder,
        );
        result.provider_reach = Some(reviewed.provider_reach);
        result.coverage = Some(reviewed.coverage.clone());
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

fn derived_connection_boundary(provider_reach: ProviderReach) -> ConnectionBoundary {
    match provider_reach {
        ProviderReach::Selected {
            provider,
            provenance: SelectedProviderProvenance::PinnedMcpBoundary,
        } => ConnectionBoundary::Pinned(provider),
        ProviderReach::All | ProviderReach::Selected { .. } => ConnectionBoundary::All,
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
    session_id: Option<&str>,
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
        session_id: session_id.map(str::to_string),
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
    ProviderReach(ProviderReachError),
    InvalidPlan,
    ContextMismatch,
    PlanFingerprintMismatch,
    Blocked(String),
    RecoveryRequired(String),
    ReachAware(String),
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
            | Self::ProviderReach(_)
            | Self::InvalidPlan
            | Self::PlanFingerprintMismatch
            | Self::Serialization(_) => "native-plan-invalid",
            Self::ContextMismatch => "context-scope-conflict",
            Self::Blocked(_) => "native-plan-blocked",
            Self::RecoveryRequired(_) => "recovery-required",
            Self::ReachAware(_) => "reach-aware-envelope-invalid",
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

impl From<ProviderReachError> for NativeToggleControlError {
    fn from(error: ProviderReachError) -> Self {
        Self::ProviderReach(error)
    }
}

impl fmt::Display for NativeToggleControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::ProviderReach(error) => error.fmt(formatter),
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
            Self::ReachAware(reason) => write!(formatter, "reach-aware toggle blocked: {reason}"),
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
