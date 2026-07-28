//! Explicit provider-target operations for named compiled profiles.
//!
//! Generic profile policy changes continue to use [`super::PolicyChangePlan`].
//! This module is intentionally separate: a named compiled profile writes only
//! provider-specific overrides and commits the complete scope policy in one
//! compare-and-swap.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    provider_reach::{
        ProviderCoverageEntry, ProviderReach, ProviderReachCoverage, SelectedProviderProvenance,
    },
    providers::ProviderId,
    state::atomic_json::{OwnerGeneration, StateError, StateRevision},
    transitions::EffectActivation,
};

use super::{
    CompiledProfileRevision, PolicyStore, PolicyStoreError, PolicyTarget, ProfileReference,
    ProfileSelection, ProviderPolicy, ScopePolicy,
};

pub const PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION: u32 = 2;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProviderTarget {
    pub provider: ProviderId,
    pub prior_provider_policy: Option<ProviderPolicy>,
    pub desired_provider_policy: ProviderPolicy,
    pub classification: ProfileProviderTargetClassification,
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
        if actual == self.plan_fingerprint {
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

#[derive(Debug)]
pub enum ProfileProviderOperationError {
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
    RecoveryRequired {
        operation_id: String,
        reason: String,
        inverse_evidence: Vec<ProfileProviderInverseEvidence>,
    },
}

impl From<PolicyStoreError> for ProfileProviderOperationError {
    fn from(error: PolicyStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for ProfileProviderOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
}

impl ProfileProviderOperationController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            policies: PolicyStore::new(app_state_root),
        }
    }

    #[must_use]
    pub fn with_policy_store(policies: PolicyStore) -> Self {
        Self { policies }
    }

    pub fn plan(
        &self,
        target: &PolicyTarget,
        revision: &CompiledProfileRevision,
        provider_reach: ProviderReach,
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
            let classification = match prior_provider_policy.as_ref() {
                None => ProfileProviderTargetClassification::Create,
                Some(policy) if policy.profile == desired_selection => {
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
            targets.push(ProfileProviderTarget {
                provider,
                prior_provider_policy: prior_provider_policy.clone(),
                desired_provider_policy,
                classification,
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
