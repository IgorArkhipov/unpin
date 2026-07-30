//! Explicit provider-target operations for named compiled profiles.
//!
//! Generic profile policy changes continue to use [`super::PolicyChangePlan`].
//! This module is intentionally separate: a named compiled profile writes only
//! provider-specific overrides and commits the complete scope policy in one
//! compare-and-swap.

use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_ISSUER,
        ControlApprovalContext, ControlAuthorization, approval_binding_digest,
    },
    control_operation::{
        ControlResolvedContext, ReachAwareControlOperationEnvelope, ReachAwareOperationFamily,
        ReachAwarePayloadReference, ReachAwarePrincipal, ReachAwarePriorState,
        ReachAwareRecoveryEvidence, ReachAwareRootBinding,
    },
    discovery::DiscoveryOutput,
    provider_reach::{
        ConnectionBoundary, ProviderCoverageEntry, ProviderReach, ProviderReachCoverage,
        ProviderReachLifecycle, SelectedProviderAuthority, SelectedProviderProvenance,
    },
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateResourceLock, StateRevision,
    },
    transitions::{
        EffectActivation, EffectAuthority, JournalError, JournalHandle, TransitionContext,
        TransitionEffect, TransitionEffectKind, TransitionJournalStore, TransitionKind,
        TransitionLifecycle, TransitionPlan, TransitionPlanError,
    },
};

use super::{
    CompiledProfileRevision, GatewaySelection, PolicyStore, PolicyStoreError, PolicyTarget,
    ProfileReference, ProfileSelection, ProviderPolicy, ScopePolicy, policy_resource_id,
};

pub const PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION: u32 = 2;
pub const PROFILE_PROVIDER_APPROVAL_AUDIENCE: &str = "unpin-core-profile-provider-apply-v2";

#[derive(Debug, Clone)]
pub struct ProfileProviderReachAwareApplyContext {
    pub approval_context: ControlApprovalContext,
    pub roots: ReachAwareRootBinding,
    pub principal: ReachAwarePrincipal,
    pub audience: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub now_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileProviderTargetClassification {
    Create,
    Replace,
    AlreadyMatches,
}

impl ProfileProviderTargetClassification {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Replace => "replace",
            Self::AlreadyMatches => "already-matches",
        }
    }
}

/// Trusted local inventory state for one provider target.
///
/// This is intentionally separate from the presence of a persisted policy
/// override: an override may exist even when the provider is not installed or
/// discoverable locally, and an installed provider may have no override yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileProviderLocalPresence {
    Present,
    Absent,
}

impl ProfileProviderLocalPresence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }
}

/// How an explicit provider override changes generic profile inheritance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProfileProviderGenericPolicyEffect {
    /// A newly created override takes this provider out of generic inheritance.
    #[serde(rename = "stop-inheriting")]
    CreateOverride,
    /// An existing provider override is replaced by the reviewed profile.
    #[serde(rename = "replace-override")]
    ReplaceOverride,
    /// The provider-specific profile already matches and inheritance is unchanged.
    #[serde(rename = "already-provider-specific")]
    AlreadyProviderSpecific,
}

impl ProfileProviderGenericPolicyEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateOverride => "stop-inheriting",
            Self::ReplaceOverride => "replace-override",
            Self::AlreadyProviderSpecific => "already-provider-specific",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderTarget {
    pub provider: ProviderId,
    pub prior_provider_policy: Option<ProviderPolicy>,
    pub desired_provider_policy: ProviderPolicy,
    pub classification: ProfileProviderTargetClassification,
    /// Populated by discovery-aware planners. `None` is retained for legacy
    /// callers that cannot provide trusted local inventory state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_presence: Option<ProfileProviderLocalPresence>,
    /// Whether this provider resolved its profile from the generic policy
    /// before the explicit target was considered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_profile_inherited_before: Option<bool>,
    /// The inheritance effect disclosed to a reviewer before apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_policy_effect: Option<ProfileProviderGenericPolicyEffect>,
    /// Absent providers are activated on a future/next session, never by this
    /// policy-store write. The existing `activation` remains authoritative for
    /// the operation as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub future_activation: Option<bool>,
    pub activation: EffectActivation,
    pub pre_state_fingerprint: String,
    pub post_state_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderInverseEvidence {
    pub provider: ProviderId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_provider_policy: Option<ProviderPolicy>,
    pub prior_state_fingerprint: String,
    pub created_override: bool,
    pub replaced_override: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderOperationPlan {
    pub schema_version: u32,
    pub operation_id: String,
    pub target: PolicyTarget,
    pub profile: ProfileReference,
    pub provider_reach: ProviderReach,
    pub supported_providers: BTreeSet<ProviderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<StateRevision>,
    pub expected_policy_fingerprint: String,
    pub targets: Vec<ProfileProviderTarget>,
    pub coverage: ProviderReachCoverage,
    pub desired_policy: ScopePolicy,
    pub inverse_evidence: Vec<ProfileProviderInverseEvidence>,
    pub activation: EffectActivation,
    pub no_op: bool,
    pub plan_fingerprint: String,
}

impl ProfileProviderOperationPlan {
    pub fn verify(&self) -> Result<(), ProfileProviderOperationError> {
        if self.schema_version != PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION {
            return Err(ProfileProviderOperationError::InvalidPlan);
        }
        let actual = plan_fingerprint(self)?;
        if actual == self.plan_fingerprint
            && self.operation_id == format!("profile-provider-{actual}")
        {
            Ok(())
        } else {
            Err(ProfileProviderOperationError::PlanFingerprintMismatch)
        }
    }

    #[must_use]
    pub fn selected_provider(&self) -> Option<ProviderId> {
        self.provider_reach.provider()
    }

    #[must_use]
    pub fn selected_provider_provenance(&self) -> Option<SelectedProviderProvenance> {
        self.provider_reach.provenance()
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
        session_id: &str,
    ) -> Result<ApprovalExpectation, ProfileProviderOperationError> {
        let mut expectation = profile_transition_plan(self, context, session_id)?
            .approval_expectation(CONTROL_APPROVAL_ISSUER, PROFILE_PROVIDER_APPROVAL_AUDIENCE);
        expectation.effect_graph_digest = self.plan_fingerprint.clone();
        expectation.resources.push(ApprovalResourceBinding {
            resource_id: policy_resource_id(&self.target)
                .map_err(|_| ProfileProviderOperationError::InvalidPlan)?,
            pre_state_fingerprint: self
                .expected_revision
                .as_ref()
                .map(|revision| approval_binding_digest(&revision.fingerprint)),
        });
        Ok(expectation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileProviderOperationStatus {
    Applied,
    NoOp,
    Blocked,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderOperationResult {
    pub status: ProfileProviderOperationStatus,
    pub operation_id: String,
    pub target: PolicyTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<StateRevision>,
    pub policy: ScopePolicy,
    pub inverse_evidence: Vec<ProfileProviderInverseEvidence>,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderHandoff {
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileProviderOperationRecord {
    schema_version: u32,
    plan: ProfileProviderOperationPlan,
    plan_fingerprint: String,
    writes_started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_lifecycle: Option<ProviderReachLifecycle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_result: Option<ProfileProviderOperationResult>,
}

impl ProfileProviderOperationRecord {
    fn planned(plan: &ProfileProviderOperationPlan) -> Self {
        Self {
            schema_version: PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
            plan: plan.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
            writes_started: false,
            terminal_lifecycle: None,
            terminal_result: None,
        }
    }

    fn verify(
        &self,
        plan: &ProfileProviderOperationPlan,
    ) -> Result<(), ProfileProviderOperationError> {
        self.verify_shape()?;
        self.plan.verify()?;
        if self.plan != *plan
            || self.plan_fingerprint != plan.plan_fingerprint
            || self
                .terminal_result
                .as_ref()
                .is_some_and(|result| !profile_result_matches_plan(result, plan))
        {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile family payload does not match reviewed operation".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_shape(&self) -> Result<(), ProfileProviderOperationError> {
        if self.schema_version != PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION
            || self.terminal_result.is_some()
                != matches!(
                    self.terminal_lifecycle,
                    Some(ProviderReachLifecycle::Applied | ProviderReachLifecycle::NoOp)
                )
        {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile family payload shape is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProfileProviderOperationError {
    Approval(ApprovalError),
    Journal(JournalError),
    TransitionPlan(TransitionPlanError),
    State(StateError),
    InvalidPlan,
    PlanFingerprintMismatch,
    InvalidProfileRevision(String),
    UnsupportedProvider {
        provider: ProviderId,
    },
    NoSupportedProviders,
    StalePreState {
        expected: Option<StateRevision>,
        actual: Option<StateRevision>,
    },
    Store(PolicyStoreError),
    OwnerGenerationOverflow,
    Serialization(String),
    SessionAuthorityRequired,
    ReachAware(String),
    RecoveryRequired {
        operation_id: String,
        reason: String,
        inverse_evidence: Vec<ProfileProviderInverseEvidence>,
    },
}

impl From<ApprovalError> for ProfileProviderOperationError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<JournalError> for ProfileProviderOperationError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<TransitionPlanError> for ProfileProviderOperationError {
    fn from(error: TransitionPlanError) -> Self {
        Self::TransitionPlan(error)
    }
}

impl From<StateError> for ProfileProviderOperationError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<PolicyStoreError> for ProfileProviderOperationError {
    fn from(error: PolicyStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for ProfileProviderOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::InvalidPlan => formatter.write_str("profile provider operation plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("profile provider operation plan fingerprint mismatched")
            }
            Self::InvalidProfileRevision(message) => {
                write!(formatter, "invalid profile revision: {message}")
            }
            Self::UnsupportedProvider { provider } => {
                write!(
                    formatter,
                    "profile does not declare provider {}",
                    provider.as_str()
                )
            }
            Self::NoSupportedProviders => {
                formatter.write_str("profile declares no supported providers")
            }
            Self::StalePreState { expected, actual } => write!(
                formatter,
                "profile provider operation pre-state is stale (expected {expected:?}, actual {actual:?})"
            ),
            Self::Store(error) => error.fmt(formatter),
            Self::OwnerGenerationOverflow => {
                formatter.write_str("profile provider operation owner generation overflow")
            }
            Self::Serialization(message) => write!(
                formatter,
                "profile provider serialization failed: {message}"
            ),
            Self::SessionAuthorityRequired => {
                formatter.write_str("profile provider operation requires a session authority key")
            }
            Self::ReachAware(message) => {
                write!(
                    formatter,
                    "profile provider reach-aware envelope is invalid: {message}"
                )
            }
            Self::RecoveryRequired {
                operation_id,
                reason,
                ..
            } => write!(
                formatter,
                "profile provider operation {operation_id} requires recovery: {reason}"
            ),
        }
    }
}

impl std::error::Error for ProfileProviderOperationError {}

#[derive(Debug, Clone)]
pub struct ProfileProviderOperationController {
    policies: PolicyStore,
    session_authority_key: Option<SessionAuthorityKey>,
}

impl ProfileProviderOperationController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            policies: PolicyStore::new(app_state_root),
            session_authority_key: None,
        }
    }

    #[must_use]
    pub fn with_policy_store(policies: PolicyStore) -> Self {
        Self {
            policies,
            session_authority_key: None,
        }
    }

    #[must_use]
    pub fn with_session_authority_key(
        mut self,
        session_authority_key: SessionAuthorityKey,
    ) -> Self {
        self.session_authority_key = Some(session_authority_key);
        self
    }

    pub fn plan(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        self.plan_with_gateway_selection(target, revision, provider_reach, None, None)
    }

    pub fn plan_with_gateway(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
        gateway: GatewaySelection,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        self.plan_with_gateway_selection(target, revision, provider_reach, Some(gateway), None)
    }

    /// Plan with provider presence derived from trusted discovery inventory.
    ///
    /// The existing [`Self::plan`] and [`Self::plan_with_gateway`] entry points
    /// remain compatible for callers that do not have discovery data; their
    /// target facts intentionally serialize as absent. CLI, TUI, and MCP
    /// adapters should use this method whenever they have a fresh discovery
    /// result so reviewers can distinguish an absent provider from a present
    /// provider that merely lacks an override.
    pub fn plan_with_gateway_and_discovery(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
        gateway: GatewaySelection,
        discovery: &DiscoveryOutput,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        let present_providers = profile_provider_presence_from_discovery(discovery);
        self.plan_with_gateway_selection(
            target,
            revision,
            provider_reach,
            Some(gateway),
            Some(&present_providers),
        )
    }

    /// Persist an authenticated, reviewed profile-provider operation without
    /// mutating provider policy. The later CLI/TUI apply must consume this
    /// exact payload instead of deriving a fresh plan from ambient state.
    pub fn seal_handoff(
        &self,
        plan: &ProfileProviderOperationPlan,
        durable: &ProfileProviderReachAwareApplyContext,
    ) -> Result<ProfileProviderHandoff, ProfileProviderOperationError> {
        plan.verify()?;
        let authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(ProfileProviderOperationError::SessionAuthorityRequired)?;
        let expectation =
            plan.approval_expectation(&durable.approval_context, &durable.principal.session_id)?;
        self.verify_reach_aware_context(plan, &expectation, durable, authority_key)?;
        let transition = profile_transition_plan(
            plan,
            &durable.approval_context,
            &durable.principal.session_id,
        )?;
        let (payload_path, payload_store) =
            profile_payload_store(self.policies.app_state_root(), &plan.operation_id);
        let lock_path = payload_path.with_file_name(".profile-provider-operation-domain");
        let _execution_lock = StateResourceLock::acquire(&lock_path)?;
        let (payload, _) = load_or_create_profile_payload(&payload_store, plan)?;
        payload.verify(plan)?;

        let family = ReachAwareOperationFamily::Profile;
        let selected_provider = plan.provider_reach.provider().map(|provider| {
            SelectedProviderAuthority::new(
                provider,
                plan.provider_reach
                    .provenance()
                    .unwrap_or(SelectedProviderProvenance::ExplicitInput),
            )
        });
        let expected_lifecycle = if plan.no_op {
            ProviderReachLifecycle::NoOp
        } else {
            ProviderReachLifecycle::Applied
        };
        let builder = ReachAwareControlOperationEnvelope::builder()
            .family(family, PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION)
            .operation(
                plan.operation_id.clone(),
                transition.kind.as_str(),
                plan.plan_fingerprint.clone(),
            )
            .context(ControlResolvedContext {
                repository_key: transition.context.repository_key.clone(),
                workspace_key: transition.context.workspace_key.clone(),
                session_id: transition.context.session_id.clone(),
                profile_digest: transition.context.profile_digest.clone(),
            })
            .reach(
                durable.principal.connection_boundary,
                plan.provider_reach,
                selected_provider,
                plan.coverage.clone(),
            )
            .lifecycle(expected_lifecycle, expected_lifecycle, plan.activation)
            .trusted_roots(durable.roots.clone())
            .authority(
                durable.principal.clone(),
                durable.audience.clone(),
                durable.issued_at_unix,
                durable.expires_at_unix,
            )
            .payload_reference(ReachAwarePayloadReference {
                family,
                schema_version: PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
                reference: profile_payload_reference(&plan.operation_id),
                payload_digest: plan.plan_fingerprint.clone(),
            })
            .prior_state(
                plan.targets
                    .iter()
                    .map(|target| ReachAwarePriorState {
                        target_id: format!("profile:{}", target.provider.as_str()),
                        fingerprint: target.pre_state_fingerprint.clone(),
                    })
                    .collect(),
            );
        let store = TransitionJournalStore::new(self.policies.app_state_root());
        let handle = store.create_or_attach_reach_aware(
            &transition,
            operation_owner(&plan.operation_id)?,
            builder,
            authority_key,
        )?;
        verify_attached_profile_envelope(&handle, plan, durable)?;
        Ok(ProfileProviderHandoff {
            operation_id: plan.operation_id.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
            expires_at_unix: durable.expires_at_unix,
        })
    }

    pub fn load_handoff(
        &self,
        operation_id: &str,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        let (_, store) = profile_payload_store(self.policies.app_state_root(), operation_id);
        let snapshot = store
            .load::<ProfileProviderOperationRecord>()?
            .ok_or_else(|| {
                ProfileProviderOperationError::ReachAware(
                    "profile provider handoff not found".to_string(),
                )
            })?;
        let record = snapshot.value;
        record.verify(&record.plan)?;
        if record.plan.operation_id != operation_id {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile provider handoff operation id does not match payload".to_string(),
            ));
        }
        Ok(record.plan)
    }

    /// Plan with an already-derived trusted provider inventory.
    ///
    /// This lower-level form is useful to headless callers that have already
    /// validated a discovery result and to fixture tests. The set must come
    /// from trusted discovery/provider inventory, not caller metadata.
    pub fn plan_with_provider_presence(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
        present_providers: &BTreeSet<ProviderId>,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        self.plan_with_gateway_selection(
            target,
            revision,
            provider_reach,
            None,
            Some(present_providers),
        )
    }

    fn plan_with_gateway_selection(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
        gateway: Option<GatewaySelection>,
        present_providers: Option<&BTreeSet<ProviderId>>,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        revision.verify_digest().map_err(|error| {
            ProfileProviderOperationError::InvalidProfileRevision(error.to_string())
        })?;
        let supported_providers = effective_supported_providers(revision);
        if supported_providers.is_empty() {
            return Err(ProfileProviderOperationError::NoSupportedProviders);
        }
        let target_providers = match provider_reach {
            ProviderReach::All => supported_providers.iter().copied().collect::<Vec<_>>(),
            ProviderReach::Selected { provider, .. } => {
                if !supported_providers.contains(&provider) {
                    return Err(ProfileProviderOperationError::UnsupportedProvider { provider });
                }
                vec![provider]
            }
        };
        let snapshot = self.policies.load(target)?;
        let current_policy = snapshot
            .as_ref()
            .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
        let expected_revision = snapshot.as_ref().map(|snapshot| snapshot.revision.clone());
        let expected_policy_fingerprint = serialized_fingerprint(&current_policy)?;
        let profile = ProfileReference::from(revision);
        let desired_selection = ProfileSelection::Profile {
            reference: profile.clone(),
        };
        let mut desired_policy = current_policy.clone();
        let mut targets = Vec::with_capacity(target_providers.len());
        let mut inverse_evidence = Vec::with_capacity(target_providers.len());
        let mut coverage_entries = Vec::with_capacity(target_providers.len());
        for provider in target_providers {
            let prior_provider_policy = current_policy.providers.get(&provider).cloned();
            let mut desired_provider_policy = prior_provider_policy.clone().unwrap_or_default();
            if let Some(gateway) = gateway {
                desired_provider_policy.gateway = gateway;
            }
            let classification = match prior_provider_policy.as_ref() {
                None => ProfileProviderTargetClassification::Create,
                Some(policy)
                    if policy.profile == desired_selection
                        && gateway.is_none_or(|gateway| policy.gateway == gateway) =>
                {
                    ProfileProviderTargetClassification::AlreadyMatches
                }
                Some(_) => ProfileProviderTargetClassification::Replace,
            };
            desired_provider_policy.profile = desired_selection.clone();
            desired_policy
                .providers
                .insert(provider, desired_provider_policy.clone());
            let pre_state_fingerprint = serialized_fingerprint(&prior_provider_policy)?;
            let post_state_fingerprint =
                serialized_fingerprint(&Some(desired_provider_policy.clone()))?;
            let target_facts = present_providers.map(|present_providers| {
                let local_presence = if present_providers.contains(&provider) {
                    ProfileProviderLocalPresence::Present
                } else {
                    ProfileProviderLocalPresence::Absent
                };
                let generic_profile_inherited_before = prior_provider_policy
                    .as_ref()
                    .is_none_or(|policy| policy.profile.is_inherit());
                let generic_policy_effect = match classification {
                    ProfileProviderTargetClassification::Create => {
                        ProfileProviderGenericPolicyEffect::CreateOverride
                    }
                    ProfileProviderTargetClassification::Replace => {
                        ProfileProviderGenericPolicyEffect::ReplaceOverride
                    }
                    ProfileProviderTargetClassification::AlreadyMatches => {
                        ProfileProviderGenericPolicyEffect::AlreadyProviderSpecific
                    }
                };
                (
                    local_presence,
                    generic_profile_inherited_before,
                    generic_policy_effect,
                    matches!(local_presence, ProfileProviderLocalPresence::Absent),
                )
            });
            targets.push(ProfileProviderTarget {
                provider,
                prior_provider_policy: prior_provider_policy.clone(),
                desired_provider_policy,
                classification,
                local_presence: target_facts.map(|facts| facts.0),
                generic_profile_inherited_before: target_facts.map(|facts| facts.1),
                generic_policy_effect: target_facts.map(|facts| facts.2),
                future_activation: target_facts.map(|facts| facts.3),
                activation: EffectActivation::NextSessionOnly,
                pre_state_fingerprint: pre_state_fingerprint.clone(),
                post_state_fingerprint,
            });
            inverse_evidence.push(ProfileProviderInverseEvidence {
                provider,
                prior_provider_policy: prior_provider_policy.clone(),
                prior_state_fingerprint: pre_state_fingerprint,
                created_override: matches!(
                    classification,
                    ProfileProviderTargetClassification::Create
                ),
                replaced_override: matches!(
                    classification,
                    ProfileProviderTargetClassification::Replace
                ),
            });
            coverage_entries.push(ProviderCoverageEntry::included(
                provider,
                format!("profile:{}", revision.profile_id),
            ));
        }
        let no_op = current_policy == desired_policy;
        let activation = EffectActivation::NextSessionOnly;
        let mut plan = ProfileProviderOperationPlan {
            schema_version: PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
            operation_id: String::new(),
            target: target.clone(),
            profile,
            provider_reach,
            supported_providers,
            expected_revision,
            expected_policy_fingerprint,
            targets,
            coverage: ProviderReachCoverage::new(coverage_entries),
            desired_policy,
            inverse_evidence,
            activation,
            no_op,
            plan_fingerprint: String::new(),
        };
        plan.plan_fingerprint = plan_fingerprint(&plan)?;
        plan.operation_id = format!("profile-provider-{}", plan.plan_fingerprint);
        Ok(plan)
    }

    pub fn apply(
        &self,
        plan: &ProfileProviderOperationPlan,
        actor_id: &str,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError> {
        self.apply_with_verifier(plan, actor_id, |_| Ok(()))
    }

    pub fn apply_with_reach_aware(
        &self,
        plan: &ProfileProviderOperationPlan,
        authorization: ControlAuthorization,
        durable: ProfileProviderReachAwareApplyContext,
        actor_id: &str,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError> {
        plan.verify()?;
        let authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(ProfileProviderOperationError::SessionAuthorityRequired)?;
        let expectation =
            plan.approval_expectation(&durable.approval_context, &durable.principal.session_id)?;
        authorization.assert_matches(&expectation)?;
        self.verify_reach_aware_context(plan, &expectation, &durable, authority_key)?;
        let transition = profile_transition_plan(
            plan,
            &durable.approval_context,
            &durable.principal.session_id,
        )?;
        let (payload_path, payload_store) =
            profile_payload_store(self.policies.app_state_root(), &plan.operation_id);
        let (mut payload, mut payload_revision) =
            load_or_create_profile_payload(&payload_store, plan)?;
        let lock_path = payload_path.with_file_name(".profile-provider-operation-domain");
        let _execution_lock = StateResourceLock::acquire(&lock_path)?;
        if let Some(snapshot) = payload_store.load::<ProfileProviderOperationRecord>()? {
            snapshot.value.verify(plan)?;
            payload = snapshot.value;
            payload_revision = snapshot.revision;
        }
        let store = TransitionJournalStore::new(self.policies.app_state_root());
        let owner = operation_owner(&plan.operation_id)?;
        let family = ReachAwareOperationFamily::Profile;
        let selected_provider = plan.provider_reach.provider().map(|provider| {
            SelectedProviderAuthority::new(
                provider,
                plan.provider_reach
                    .provenance()
                    .unwrap_or(SelectedProviderProvenance::ExplicitInput),
            )
        });
        let expected_lifecycle = if plan.no_op {
            ProviderReachLifecycle::NoOp
        } else {
            ProviderReachLifecycle::Applied
        };
        let builder = ReachAwareControlOperationEnvelope::builder()
            .family(family, PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION)
            .operation(
                plan.operation_id.clone(),
                transition.kind.as_str(),
                plan.plan_fingerprint.clone(),
            )
            .context(ControlResolvedContext {
                repository_key: transition.context.repository_key.clone(),
                workspace_key: transition.context.workspace_key.clone(),
                session_id: transition.context.session_id.clone(),
                profile_digest: transition.context.profile_digest.clone(),
            })
            .reach(
                durable.principal.connection_boundary,
                plan.provider_reach,
                selected_provider,
                plan.coverage.clone(),
            )
            .lifecycle(expected_lifecycle, expected_lifecycle, plan.activation)
            .trusted_roots(durable.roots.clone())
            .authority(
                durable.principal.clone(),
                durable.audience.clone(),
                durable.issued_at_unix,
                durable.expires_at_unix,
            )
            .payload_reference(ReachAwarePayloadReference {
                family,
                schema_version: PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
                reference: profile_payload_reference(&plan.operation_id),
                payload_digest: plan.plan_fingerprint.clone(),
            })
            .prior_state(
                plan.targets
                    .iter()
                    .map(|target| ReachAwarePriorState {
                        target_id: format!("profile:{}", target.provider.as_str()),
                        fingerprint: target.pre_state_fingerprint.clone(),
                    })
                    .collect(),
            );
        let mut handle =
            store.create_or_attach_reach_aware(&transition, owner, builder, authority_key)?;
        verify_attached_profile_envelope(&handle, plan, &durable)?;
        if let Some(result) = payload.terminal_result.clone() {
            let lifecycle = payload.terminal_lifecycle.ok_or_else(|| {
                ProfileProviderOperationError::ReachAware(
                    "profile payload is missing terminal lifecycle".to_string(),
                )
            })?;
            finalize_profile_journal(
                &store,
                &mut handle,
                plan,
                lifecycle,
                payload.writes_started,
                authority_key,
            )?;
            return Ok(result);
        }
        if handle.journal.lifecycle.is_terminal() {
            return self.cached_terminal_result(plan, &handle, &payload);
        }
        if handle.journal.lifecycle != TransitionLifecycle::Applying {
            handle
                .journal
                .record(TransitionLifecycle::Applying, "reach-aware-applying", None)?;
            store.save(&mut handle)?;
        }
        if payload.writes_started {
            if let Some(result) = self.reconcile_committed_profile(plan)? {
                payload.terminal_lifecycle = Some(ProviderReachLifecycle::Applied);
                payload.terminal_result = Some(result.clone());
                save_profile_payload(
                    &payload_store,
                    &mut payload_revision,
                    &payload,
                    &plan.operation_id,
                )?;
                finalize_profile_journal(
                    &store,
                    &mut handle,
                    plan,
                    ProviderReachLifecycle::Applied,
                    true,
                    authority_key,
                )?;
                return Ok(result);
            }
            payload.terminal_lifecycle = Some(ProviderReachLifecycle::RecoveryRequired);
            save_profile_payload(
                &payload_store,
                &mut payload_revision,
                &payload,
                &plan.operation_id,
            )?;
            finalize_profile_journal(
                &store,
                &mut handle,
                plan,
                ProviderReachLifecycle::RecoveryRequired,
                true,
                authority_key,
            )?;
            return Err(ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason: "profile write started without a verifiable committed result".to_string(),
                inverse_evidence: plan.inverse_evidence.clone(),
            });
        }
        if !plan.no_op {
            payload.writes_started = true;
            save_profile_payload(
                &payload_store,
                &mut payload_revision,
                &payload,
                &plan.operation_id,
            )?;
        }

        match self.apply(plan, actor_id) {
            Ok(result) => {
                let lifecycle = match result.status {
                    ProfileProviderOperationStatus::Applied => ProviderReachLifecycle::Applied,
                    ProfileProviderOperationStatus::NoOp => ProviderReachLifecycle::NoOp,
                    ProfileProviderOperationStatus::Blocked => ProviderReachLifecycle::Blocked,
                    ProfileProviderOperationStatus::RecoveryRequired => {
                        ProviderReachLifecycle::RecoveryRequired
                    }
                };
                payload.terminal_lifecycle = Some(lifecycle);
                payload.terminal_result = Some(result.clone());
                save_profile_payload(
                    &payload_store,
                    &mut payload_revision,
                    &payload,
                    &plan.operation_id,
                )?;
                finalize_profile_journal(
                    &store,
                    &mut handle,
                    plan,
                    lifecycle,
                    result.status == ProfileProviderOperationStatus::Applied,
                    authority_key,
                )?;
                Ok(result)
            }
            Err(error) => {
                if !plan.no_op
                    && let Some(result) = self.reconcile_committed_profile(plan)?
                {
                    payload.terminal_lifecycle = Some(ProviderReachLifecycle::Applied);
                    payload.terminal_result = Some(result.clone());
                    save_profile_payload(
                        &payload_store,
                        &mut payload_revision,
                        &payload,
                        &plan.operation_id,
                    )?;
                    finalize_profile_journal(
                        &store,
                        &mut handle,
                        plan,
                        ProviderReachLifecycle::Applied,
                        true,
                        authority_key,
                    )?;
                    return Ok(result);
                }
                let lifecycle = if matches!(
                    error,
                    ProfileProviderOperationError::RecoveryRequired { .. }
                ) {
                    ProviderReachLifecycle::RecoveryRequired
                } else {
                    ProviderReachLifecycle::Blocked
                };
                payload.terminal_lifecycle = Some(lifecycle);
                save_profile_payload(
                    &payload_store,
                    &mut payload_revision,
                    &payload,
                    &plan.operation_id,
                )?;
                finalize_profile_journal(
                    &store,
                    &mut handle,
                    plan,
                    lifecycle,
                    lifecycle == ProviderReachLifecycle::RecoveryRequired,
                    authority_key,
                )?;
                Err(error)
            }
        }
    }

    fn verify_reach_aware_context(
        &self,
        plan: &ProfileProviderOperationPlan,
        expectation: &ApprovalExpectation,
        durable: &ProfileProviderReachAwareApplyContext,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ProfileProviderOperationError> {
        durable
            .principal
            .verify(authority_key)
            .map_err(|error| ProfileProviderOperationError::ReachAware(error.to_string()))?;
        durable
            .roots
            .verify()
            .map_err(|error| ProfileProviderOperationError::ReachAware(error.to_string()))?;
        if !durable.roots.provider_roots.is_empty() {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile policy operation must not bind provider filesystem roots".to_string(),
            ));
        }
        if durable.roots.app_state_root != canonical_existing_path(self.policies.app_state_root())?
        {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile app-state root does not match policy store".to_string(),
            ));
        }
        let expected_boundary = derived_connection_boundary(plan.provider_reach);
        let expected_scope = profile_reach_scope_digest(expectation, &durable.principal.session_id);
        if durable.audience != PROFILE_PROVIDER_APPROVAL_AUDIENCE
            || durable.issued_at_unix > durable.now_unix
            || durable.expires_at_unix <= durable.now_unix
            || durable.principal.connection_boundary != expected_boundary
            || durable.principal.connection_scope_id != expected_scope
            || expectation.session_id.as_deref() != Some(&durable.principal.session_id)
        {
            return Err(ProfileProviderOperationError::ReachAware(
                "profile principal does not match reviewed operation".to_string(),
            ));
        }
        Ok(())
    }

    fn cached_terminal_result(
        &self,
        plan: &ProfileProviderOperationPlan,
        handle: &JournalHandle,
        payload: &ProfileProviderOperationRecord,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError> {
        let envelope = handle.journal.reach_aware.as_ref().ok_or_else(|| {
            ProfileProviderOperationError::ReachAware(
                "missing profile reach-aware envelope".to_string(),
            )
        })?;
        match envelope.lifecycle {
            ProviderReachLifecycle::Applied | ProviderReachLifecycle::NoOp => payload
                .terminal_result
                .clone()
                .or(self.reconcile_committed_profile(plan)?)
                .ok_or_else(|| ProfileProviderOperationError::RecoveryRequired {
                    operation_id: plan.operation_id.clone(),
                    reason: "terminal profile result is unavailable".to_string(),
                    inverse_evidence: plan.inverse_evidence.clone(),
                }),
            ProviderReachLifecycle::RecoveryRequired => {
                Err(ProfileProviderOperationError::RecoveryRequired {
                    operation_id: plan.operation_id.clone(),
                    reason: "profile operation journal requires recovery".to_string(),
                    inverse_evidence: plan.inverse_evidence.clone(),
                })
            }
            _ => Err(ProfileProviderOperationError::ReachAware(
                "profile operation journal is terminal without an applied result".to_string(),
            )),
        }
    }

    fn reconcile_committed_profile(
        &self,
        plan: &ProfileProviderOperationPlan,
    ) -> Result<Option<ProfileProviderOperationResult>, ProfileProviderOperationError> {
        let Some(snapshot) = self.policies.load(&plan.target)? else {
            return Ok(None);
        };
        if snapshot.policy != plan.desired_policy {
            return Ok(None);
        }
        Ok(Some(ProfileProviderOperationResult {
            status: if plan.no_op {
                ProfileProviderOperationStatus::NoOp
            } else {
                ProfileProviderOperationStatus::Applied
            },
            operation_id: plan.operation_id.clone(),
            target: plan.target.clone(),
            revision: Some(snapshot.revision),
            policy: snapshot.policy,
            inverse_evidence: plan.inverse_evidence.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
        }))
    }

    pub fn apply_with_verifier<F>(
        &self,
        plan: &ProfileProviderOperationPlan,
        actor_id: &str,
        verifier: F,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError>
    where
        F: FnOnce(&ScopePolicy) -> Result<(), String>,
    {
        plan.verify()?;
        let snapshot = self.policies.load(&plan.target)?;
        let actual_revision = snapshot.as_ref().map(|snapshot| snapshot.revision.clone());
        if actual_revision != plan.expected_revision {
            return Err(ProfileProviderOperationError::StalePreState {
                expected: plan.expected_revision.clone(),
                actual: actual_revision,
            });
        }
        let current_policy = snapshot
            .as_ref()
            .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
        if serialized_fingerprint(&current_policy)? != plan.expected_policy_fingerprint {
            return Err(ProfileProviderOperationError::StalePreState {
                expected: plan.expected_revision.clone(),
                actual: snapshot.map(|snapshot| snapshot.revision),
            });
        }
        for target in &plan.targets {
            if current_policy.providers.get(&target.provider).cloned()
                != target.prior_provider_policy
            {
                return Err(ProfileProviderOperationError::StalePreState {
                    expected: plan.expected_revision.clone(),
                    actual: snapshot.as_ref().map(|snapshot| snapshot.revision.clone()),
                });
            }
        }
        if plan.no_op {
            let revision = snapshot.map(|snapshot| snapshot.revision).ok_or_else(|| {
                ProfileProviderOperationError::StalePreState {
                    expected: plan.expected_revision.clone(),
                    actual: None,
                }
            })?;
            verifier(&current_policy).map_err(|reason| {
                ProfileProviderOperationError::RecoveryRequired {
                    operation_id: plan.operation_id.clone(),
                    reason,
                    inverse_evidence: plan.inverse_evidence.clone(),
                }
            })?;
            return Ok(ProfileProviderOperationResult {
                status: ProfileProviderOperationStatus::NoOp,
                operation_id: plan.operation_id.clone(),
                target: plan.target.clone(),
                revision: Some(revision),
                policy: current_policy,
                inverse_evidence: plan.inverse_evidence.clone(),
                plan_fingerprint: plan.plan_fingerprint.clone(),
            });
        }
        let generation = snapshot.as_ref().map_or(Ok(1), |snapshot| {
            snapshot
                .owner
                .generation
                .checked_add(1)
                .ok_or(ProfileProviderOperationError::OwnerGenerationOverflow)
        })?;
        let owner = OwnerGeneration::new(actor_id, generation)
            .map_err(|_| ProfileProviderOperationError::OwnerGenerationOverflow)?;
        let revision = match self.policies.compare_and_swap_scope_policy(
            &plan.target,
            &plan.desired_policy,
            plan.expected_revision.as_ref(),
            owner,
        ) {
            Ok(revision) => revision,
            Err(error) => return self.reconcile_save_error(plan, error),
        };
        let committed = self.policies.load(&plan.target).map_err(|error| {
            ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason: error.to_string(),
                inverse_evidence: plan.inverse_evidence.clone(),
            }
        })?;
        let Some(committed) = committed else {
            return Err(ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason: "policy state disappeared after commit".to_string(),
                inverse_evidence: plan.inverse_evidence.clone(),
            });
        };
        if committed.revision != revision || committed.policy != plan.desired_policy {
            return Err(ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason: "policy state could not be verified after commit".to_string(),
                inverse_evidence: plan.inverse_evidence.clone(),
            });
        }
        verifier(&committed.policy).map_err(|reason| {
            ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason,
                inverse_evidence: plan.inverse_evidence.clone(),
            }
        })?;
        Ok(ProfileProviderOperationResult {
            status: ProfileProviderOperationStatus::Applied,
            operation_id: plan.operation_id.clone(),
            target: plan.target.clone(),
            revision: Some(revision),
            policy: committed.policy,
            inverse_evidence: plan.inverse_evidence.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
        })
    }

    fn reconcile_save_error(
        &self,
        plan: &ProfileProviderOperationPlan,
        error: PolicyStoreError,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError> {
        let Some(candidate) = commit_uncertain_candidate(&error) else {
            if let PolicyStoreError::State(StateError::StaleRevision { expected, actual }) = &error
            {
                return Err(ProfileProviderOperationError::StalePreState {
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
            return Err(error.into());
        };
        let committed = self.policies.load(&plan.target).ok().flatten();
        if committed.as_ref().is_some_and(|snapshot| {
            snapshot.revision == *candidate && snapshot.policy == plan.desired_policy
        }) {
            return Ok(ProfileProviderOperationResult {
                status: ProfileProviderOperationStatus::Applied,
                operation_id: plan.operation_id.clone(),
                target: plan.target.clone(),
                revision: Some(candidate.clone()),
                policy: plan.desired_policy.clone(),
                inverse_evidence: plan.inverse_evidence.clone(),
                plan_fingerprint: plan.plan_fingerprint.clone(),
            });
        }
        Err(ProfileProviderOperationError::RecoveryRequired {
            operation_id: plan.operation_id.clone(),
            reason: "policy commit outcome is unverifiable".to_string(),
            inverse_evidence: plan.inverse_evidence.clone(),
        })
    }

    pub fn restore(
        &self,
        plan: &ProfileProviderOperationPlan,
        applied: &ProfileProviderOperationResult,
        actor_id: &str,
    ) -> Result<StateRevision, ProfileProviderOperationError> {
        if applied.plan_fingerprint != plan.plan_fingerprint {
            return Err(ProfileProviderOperationError::InvalidPlan);
        }
        let snapshot = self.policies.load(&plan.target)?.ok_or_else(|| {
            ProfileProviderOperationError::RecoveryRequired {
                operation_id: plan.operation_id.clone(),
                reason: "cannot restore missing policy state".to_string(),
                inverse_evidence: plan.inverse_evidence.clone(),
            }
        })?;
        if applied.revision.as_ref() != Some(&snapshot.revision) {
            return Err(ProfileProviderOperationError::StalePreState {
                expected: applied.revision.clone(),
                actual: Some(snapshot.revision),
            });
        }
        let mut restored = snapshot.policy;
        for evidence in &applied.inverse_evidence {
            match &evidence.prior_provider_policy {
                Some(policy) => {
                    restored.providers.insert(evidence.provider, policy.clone());
                }
                None => {
                    restored.providers.remove(&evidence.provider);
                }
            }
        }
        let generation = snapshot
            .owner
            .generation
            .checked_add(1)
            .ok_or(ProfileProviderOperationError::OwnerGenerationOverflow)?;
        let owner = OwnerGeneration::new(actor_id, generation)
            .map_err(|_| ProfileProviderOperationError::OwnerGenerationOverflow)?;
        self.policies
            .compare_and_swap_scope_policy(
                &plan.target,
                &restored,
                applied.revision.as_ref(),
                owner,
            )
            .map_err(Into::into)
    }
}

fn profile_transition_plan(
    plan: &ProfileProviderOperationPlan,
    context: &ControlApprovalContext,
    session_id: &str,
) -> Result<TransitionPlan, ProfileProviderOperationError> {
    plan.verify()?;
    let mut provider_views = plan
        .targets
        .iter()
        .map(|target| target.provider)
        .collect::<Vec<_>>();
    provider_views.sort_unstable();
    provider_views.dedup();
    let desired_fingerprint = serialized_fingerprint(&plan.desired_policy)?;
    let target_fingerprint = serialized_fingerprint(&plan.target)?;
    TransitionPlan::new(
        plan.operation_id.clone(),
        TransitionKind::ApplyProfile,
        TransitionContext {
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: Some(session_id.to_string()),
            profile_digest: Some(plan.profile.digest.clone()),
        },
        vec![TransitionEffect {
            effect_id: format!("profile-provider-effect-{}", &plan.plan_fingerprint[..16]),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: format!("profile-provider-policy-{}", &target_fingerprint[..16]),
            target_type: "profile-provider-policy".to_string(),
            summary: "Apply named compiled profile to explicit provider policy targets".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: plan.activation,
            expected_pre_fingerprint: Some(plan.expected_policy_fingerprint.clone()),
            expected_post_fingerprint: (!plan.no_op).then_some(desired_fingerprint),
            provider_views,
        }],
    )
    .map_err(Into::into)
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

pub fn profile_reach_scope_digest(expectation: &ApprovalExpectation, session_id: &str) -> String {
    crate::encode_lower_hex(&Sha256::digest(
        format!(
            "{}\0{}\0{}",
            expectation.repository_key, expectation.workspace_key, session_id
        )
        .as_bytes(),
    ))
}

fn canonical_existing_path(path: &Path) -> Result<String, ProfileProviderOperationError> {
    std::fs::canonicalize(path)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| {
            ProfileProviderOperationError::ReachAware(format!(
                "profile app-state root is unavailable: {error}"
            ))
        })
}

fn operation_owner(operation_id: &str) -> Result<OwnerGeneration, ProfileProviderOperationError> {
    let digest = crate::encode_lower_hex(&Sha256::digest(operation_id.as_bytes()));
    OwnerGeneration::new(format!("profile-provider-{}", &digest[..32]), 1)
        .map_err(|_| ProfileProviderOperationError::OwnerGenerationOverflow)
}

fn profile_payload_store(app_state_root: &Path, operation_id: &str) -> (PathBuf, AtomicJsonStore) {
    let path = app_state_root
        .join("transactions")
        .join("payloads")
        .join("profile")
        .join(format!("{}.json", crate::encode_path_segment(operation_id)));
    let store = AtomicJsonStore::new(path.clone(), PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION);
    (path, store)
}

fn profile_payload_reference(operation_id: &str) -> String {
    format!("profile/{}.json", crate::encode_path_segment(operation_id))
}

fn load_or_create_profile_payload(
    store: &AtomicJsonStore,
    plan: &ProfileProviderOperationPlan,
) -> Result<(ProfileProviderOperationRecord, StateRevision), ProfileProviderOperationError> {
    if let Some(snapshot) = store.load::<ProfileProviderOperationRecord>()? {
        snapshot.value.verify(plan)?;
        return Ok((snapshot.value, snapshot.revision));
    }
    let record = ProfileProviderOperationRecord::planned(plan);
    let owner = payload_owner(&plan.operation_id, 1)?;
    match store.compare_and_swap(None, owner, &record) {
        Ok(revision) => Ok((record, revision)),
        Err(StateError::StaleRevision { .. }) => {
            let snapshot = store
                .load::<ProfileProviderOperationRecord>()?
                .ok_or_else(|| {
                    ProfileProviderOperationError::ReachAware(
                        "profile family payload disappeared during create".to_string(),
                    )
                })?;
            snapshot.value.verify(plan)?;
            Ok((snapshot.value, snapshot.revision))
        }
        Err(error) => Err(error.into()),
    }
}

fn save_profile_payload(
    store: &AtomicJsonStore,
    revision: &mut StateRevision,
    record: &ProfileProviderOperationRecord,
    operation_id: &str,
) -> Result<(), ProfileProviderOperationError> {
    record.verify_shape()?;
    let generation = revision
        .sequence
        .checked_add(1)
        .ok_or(ProfileProviderOperationError::OwnerGenerationOverflow)?;
    *revision = store.compare_and_swap(
        Some(revision),
        payload_owner(operation_id, generation)?,
        record,
    )?;
    Ok(())
}

fn payload_owner(
    operation_id: &str,
    generation: u64,
) -> Result<OwnerGeneration, ProfileProviderOperationError> {
    let digest = crate::encode_lower_hex(&Sha256::digest(operation_id.as_bytes()));
    OwnerGeneration::new(format!("profile-payload-{}", &digest[..32]), generation)
        .map_err(|_| ProfileProviderOperationError::OwnerGenerationOverflow)
}

fn profile_result_matches_plan(
    result: &ProfileProviderOperationResult,
    plan: &ProfileProviderOperationPlan,
) -> bool {
    result.operation_id == plan.operation_id
        && result.target == plan.target
        && result.policy == plan.desired_policy
        && result.inverse_evidence == plan.inverse_evidence
        && result.plan_fingerprint == plan.plan_fingerprint
        && matches!(
            (plan.no_op, result.status),
            (true, ProfileProviderOperationStatus::NoOp)
                | (false, ProfileProviderOperationStatus::Applied)
        )
}

fn verify_attached_profile_envelope(
    handle: &JournalHandle,
    plan: &ProfileProviderOperationPlan,
    durable: &ProfileProviderReachAwareApplyContext,
) -> Result<(), ProfileProviderOperationError> {
    let envelope = handle.journal.reach_aware.as_ref().ok_or_else(|| {
        ProfileProviderOperationError::ReachAware(
            "missing profile reach-aware envelope".to_string(),
        )
    })?;
    if envelope.family != ReachAwareOperationFamily::Profile
        || envelope.family_schema_version != PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION
        || envelope.plan_fingerprint != plan.plan_fingerprint
        || envelope.provider_reach != plan.provider_reach
        || envelope.provider_coverage != plan.coverage
        || envelope.roots != durable.roots
        || envelope.principal != durable.principal
        || envelope.audience != durable.audience
        || envelope.issued_at_unix != durable.issued_at_unix
        || envelope.expires_at_unix != durable.expires_at_unix
    {
        return Err(ProfileProviderOperationError::ReachAware(
            "profile reach-aware journal does not match reviewed operation".to_string(),
        ));
    }
    Ok(())
}

fn finalize_profile_journal(
    store: &TransitionJournalStore,
    handle: &mut JournalHandle,
    plan: &ProfileProviderOperationPlan,
    lifecycle: ProviderReachLifecycle,
    writes_started: bool,
    authority_key: &SessionAuthorityKey,
) -> Result<(), ProfileProviderOperationError> {
    if handle.journal.lifecycle.is_terminal() {
        let envelope = handle.journal.reach_aware.as_ref().ok_or_else(|| {
            ProfileProviderOperationError::ReachAware(
                "missing profile reach-aware envelope".to_string(),
            )
        })?;
        if envelope.lifecycle == lifecycle {
            return Ok(());
        }
        return Err(ProfileProviderOperationError::ReachAware(
            "terminal profile journal lifecycle does not match result".to_string(),
        ));
    }
    {
        let envelope = handle.journal.reach_aware.as_mut().ok_or_else(|| {
            ProfileProviderOperationError::ReachAware(
                "missing profile reach-aware envelope".to_string(),
            )
        })?;
        envelope.lifecycle = lifecycle;
        envelope.recovery = Some(ReachAwareRecoveryEvidence {
            writes_started,
            recovery_reference: writes_started
                .then(|| format!("profiles/operations/{}", plan.operation_id)),
            affected_resources: if writes_started {
                plan.targets
                    .iter()
                    .map(|target| format!("profile:{}", target.provider.as_str()))
                    .collect()
            } else {
                Vec::new()
            },
        });
        envelope.envelope_fingerprint = envelope
            .fingerprint()
            .map_err(|error| ProfileProviderOperationError::ReachAware(error.to_string()))?;
        envelope
            .seal(authority_key)
            .map_err(|error| ProfileProviderOperationError::ReachAware(error.to_string()))?;
    }
    let journal_lifecycle = match lifecycle {
        ProviderReachLifecycle::RecoveryRequired => TransitionLifecycle::NeedsRepair,
        ProviderReachLifecycle::Blocked | ProviderReachLifecycle::NoTargetsInProviderReach => {
            TransitionLifecycle::RolledBack
        }
        ProviderReachLifecycle::Applied
        | ProviderReachLifecycle::Partial
        | ProviderReachLifecycle::NoOp => TransitionLifecycle::Committed,
    };
    let terminal_code = format!("provider-reach-{}", lifecycle.as_str());
    handle.journal.terminal_code = Some(terminal_code.clone());
    handle
        .journal
        .record(journal_lifecycle, terminal_code, None)?;
    store.save(handle)?;
    Ok(())
}

fn effective_supported_providers(revision: &CompiledProfileRevision) -> BTreeSet<ProviderId> {
    if !revision.supported_providers().is_empty() {
        revision.supported_providers().clone()
    } else {
        revision
            .members
            .iter()
            .flat_map(|member| member.providers.iter().copied())
            .collect()
    }
}

/// Return providers represented by the trusted discovery inventory.
///
/// Presence is based on provider-qualified discovery items, not on persisted
/// profile overrides and never on caller-supplied provider metadata.
#[must_use]
pub fn profile_provider_presence_from_discovery(
    discovery: &DiscoveryOutput,
) -> BTreeSet<ProviderId> {
    discovery.items.iter().map(|item| item.provider).collect()
}

fn serialized_fingerprint<T: Serialize>(
    value: &T,
) -> Result<String, ProfileProviderOperationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ProfileProviderOperationError::Serialization(error.to_string()))?;
    Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanFingerprintBody<'a> {
    schema_version: u32,
    operation_id: &'a str,
    target: &'a PolicyTarget,
    profile: &'a ProfileReference,
    provider_reach: ProviderReach,
    supported_providers: &'a BTreeSet<ProviderId>,
    expected_revision: Option<&'a StateRevision>,
    expected_policy_fingerprint: &'a str,
    targets: &'a [ProfileProviderTarget],
    coverage: &'a ProviderReachCoverage,
    desired_policy: &'a ScopePolicy,
    inverse_evidence: &'a [ProfileProviderInverseEvidence],
    activation: EffectActivation,
    no_op: bool,
}

fn plan_fingerprint(
    plan: &ProfileProviderOperationPlan,
) -> Result<String, ProfileProviderOperationError> {
    let mut targets = plan.targets.clone();
    targets.sort_by_key(|target| target.provider);
    let mut inverse_evidence = plan.inverse_evidence.clone();
    inverse_evidence.sort_by_key(|evidence| evidence.provider);
    let body = PlanFingerprintBody {
        schema_version: plan.schema_version,
        operation_id: "",
        target: &plan.target,
        profile: &plan.profile,
        provider_reach: plan.provider_reach,
        supported_providers: &plan.supported_providers,
        expected_revision: plan.expected_revision.as_ref(),
        expected_policy_fingerprint: &plan.expected_policy_fingerprint,
        targets: &targets,
        coverage: &plan.coverage,
        desired_policy: &plan.desired_policy,
        inverse_evidence: &inverse_evidence,
        activation: plan.activation,
        no_op: plan.no_op,
    };
    serialized_fingerprint(&body)
}

fn commit_uncertain_candidate(error: &PolicyStoreError) -> Option<&StateRevision> {
    match error {
        PolicyStoreError::State(StateError::CommitUncertain { candidate, .. }) => Some(candidate),
        _ => None,
    }
}
