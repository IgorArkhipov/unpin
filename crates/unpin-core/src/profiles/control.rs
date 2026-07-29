use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
        ControlOperationKind, approval_binding_digest,
    },
    catalog::CapabilityId,
    control_operation::{
        DurableControlError, DurableControlJournal, DurableControlStart, DurableControlTerminal,
        DurableControlTerminalStatus,
    },
    profiles::{
        CapabilityLockState, GatewaySelection, PolicyResolutionError, PolicySnapshot, PolicyStore,
        PolicyStoreError, PolicyTarget, ProfileProviderOperationController,
        ProfileProviderOperationError, ProfileProviderOperationPlan,
        ProfileProviderOperationResult, ProfileRevisionSet, ProfileSelection, ProfileStore,
        ProfileStoreError, ProviderPolicy, ResolutionPolicies, ScopePolicy,
        resolve_effective_policy,
    },
    provider_reach::ProviderReach,
    providers::ProviderId,
    sessions::{SessionAuthorityKey, SessionManager},
    state::atomic_json::{OwnerGeneration, StateError, StateRevision},
    transitions::{
        EffectActivation, EffectAuthority, TransitionConflict, TransitionConflictChecker,
        TransitionContext, TransitionEffect, TransitionEffectKind, TransitionKind, TransitionPlan,
        TransitionPlanError,
    },
};

pub const POLICY_CHANGE_PLAN_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityLockChange {
    pub capability_id: CapabilityId,
    /// `None` clears the global lock for this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<CapabilityLockState>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewaySelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_lock: Option<CapabilityLockChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyChangePlan {
    pub schema_version: u32,
    pub target: PolicyTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<StateRevision>,
    pub change: PolicyChange,
    pub resulting_policy: ScopePolicy,
    pub no_op: bool,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

impl PolicyChangePlan {
    pub fn verify(&self) -> Result<(), PolicyControlError> {
        if self.schema_version != POLICY_CHANGE_PLAN_SCHEMA_VERSION {
            return Err(PolicyControlError::InvalidPlan);
        }
        let actual = plan_fingerprint(
            &self.target,
            self.provider,
            self.expected_revision.as_ref(),
            &self.change,
            &self.resulting_policy,
            self.no_op,
            self.activation,
        )?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(PolicyControlError::PlanFingerprintMismatch)
        }
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, PolicyControlError> {
        self.verify()?;
        let profile_digest = match self.change.profile.as_ref() {
            Some(ProfileSelection::Profile { reference }) => Some(reference.digest.clone()),
            _ => None,
        };
        let capability_lock_only = self.change.is_capability_lock_only();
        Ok(ApprovalExpectation {
            issuer: CONTROL_APPROVAL_ISSUER.to_string(),
            audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
            operation_id: format!(
                "{}-{}",
                if capability_lock_only {
                    "capability-lock-policy"
                } else {
                    "profile-policy"
                },
                self.plan_fingerprint
            ),
            operation_kind: if capability_lock_only {
                ControlOperationKind::CapabilityPolicy
            } else {
                ControlOperationKind::ProfilePolicy
            }
            .as_str()
            .to_string(),
            effect_graph_digest: self.plan_fingerprint.clone(),
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: None,
            profile_digest,
            resources: vec![ApprovalResourceBinding {
                resource_id: policy_change_resource_id(&self.target, self.provider, &self.change)?,
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
pub enum PolicyApplyStatus {
    Applied,
    NoOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyApplyResult {
    pub status: PolicyApplyStatus,
    pub target: PolicyTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<StateRevision>,
    pub policy: ScopePolicy,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct ProfilePolicyController {
    policies: PolicyStore,
    profiles: ProfileStore,
    session_manager: Option<SessionManager>,
    journal: DurableControlJournal,
}

impl ProfilePolicyController {
    #[must_use]
    pub fn new(app_state_root: impl Into<std::path::PathBuf>) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            policies: PolicyStore::new(&app_state_root),
            profiles: ProfileStore::new(&app_state_root),
            session_manager: None,
            journal: DurableControlJournal::new(app_state_root),
        }
    }

    #[must_use]
    pub fn with_session_authority_key(
        app_state_root: impl Into<std::path::PathBuf>,
        session_authority_key: SessionAuthorityKey,
    ) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            policies: PolicyStore::new(&app_state_root),
            profiles: ProfileStore::new(&app_state_root),
            session_manager: Some(SessionManager::with_authority_key(
                &app_state_root,
                session_authority_key,
            )),
            journal: DurableControlJournal::new(app_state_root),
        }
    }

    pub fn plan(
        &self,
        target: PolicyTarget,
        provider: Option<ProviderId>,
        change: PolicyChange,
    ) -> Result<PolicyChangePlan, PolicyControlError> {
        self.plan_with_revisions(target, provider, change, &[])
    }

    pub fn plan_with_revisions(
        &self,
        target: PolicyTarget,
        provider: Option<ProviderId>,
        change: PolicyChange,
        additional_revisions: &[crate::profiles::CompiledProfileRevision],
    ) -> Result<PolicyChangePlan, PolicyControlError> {
        if change.profile.is_none() && change.gateway.is_none() && change.capability_lock.is_none()
        {
            return Err(PolicyControlError::EmptyChange);
        }
        if change.capability_lock.is_some() {
            if !matches!(target, PolicyTarget::Global) {
                return Err(PolicyControlError::CapabilityLocksRequireGlobalTarget);
            }
            if provider.is_none() {
                return Err(PolicyControlError::CapabilityLocksRequireProvider);
            }
            if change.profile.is_some() || change.gateway.is_some() {
                return Err(PolicyControlError::MixedCapabilityLockChange);
            }
        }
        let current = self.policies.load(&target)?;
        let current_policy = current
            .as_ref()
            .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
        let mut resulting_policy = current_policy.clone();
        apply_change(&mut resulting_policy, provider, &change);
        self.validate_profile_selection(
            &target,
            provider,
            &resulting_policy,
            additional_revisions,
        )?;
        let expected_revision = current.as_ref().map(|snapshot| snapshot.revision.clone());
        let no_op = current_policy == resulting_policy;
        let activation = EffectActivation::NextSessionOnly;
        let plan_fingerprint = plan_fingerprint(
            &target,
            provider,
            expected_revision.as_ref(),
            &change,
            &resulting_policy,
            no_op,
            activation,
        )?;
        Ok(PolicyChangePlan {
            schema_version: POLICY_CHANGE_PLAN_SCHEMA_VERSION,
            target,
            provider,
            expected_revision,
            change,
            resulting_policy,
            no_op,
            activation,
            plan_fingerprint,
        })
    }

    /// Plan an explicit provider-target operation for a named compiled profile.
    /// This is deliberately separate from [`Self::plan`], whose optional
    /// provider remains the legacy generic-policy contract.
    pub fn plan_provider_operation(
        &self,
        target: &PolicyTarget,
        revision: &crate::profiles::CompiledProfileRevision,
        provider_reach: ProviderReach,
    ) -> Result<ProfileProviderOperationPlan, ProfileProviderOperationError> {
        ProfileProviderOperationController::with_policy_store(self.policies.clone()).plan(
            target,
            revision,
            provider_reach,
        )
    }

    pub fn apply_provider_operation(
        &self,
        plan: &ProfileProviderOperationPlan,
        actor_id: &str,
    ) -> Result<ProfileProviderOperationResult, ProfileProviderOperationError> {
        ProfileProviderOperationController::with_policy_store(self.policies.clone())
            .apply(plan, actor_id)
    }

    pub fn restore_provider_operation(
        &self,
        plan: &ProfileProviderOperationPlan,
        applied: &ProfileProviderOperationResult,
        actor_id: &str,
    ) -> Result<StateRevision, ProfileProviderOperationError> {
        ProfileProviderOperationController::with_policy_store(self.policies.clone())
            .restore(plan, applied, actor_id)
    }

    pub fn apply(
        &self,
        reviewed_plan: &PolicyChangePlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        actor_id: &str,
    ) -> Result<PolicyApplyResult, PolicyControlError> {
        self.apply_with(
            reviewed_plan,
            authorization,
            context,
            actor_id,
            Self::apply_current,
        )
    }

    fn apply_with<F>(
        &self,
        reviewed_plan: &PolicyChangePlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        actor_id: &str,
        apply_reviewed: F,
    ) -> Result<PolicyApplyResult, PolicyControlError>
    where
        F: FnOnce(&Self, &PolicyChangePlan, &str) -> Result<PolicyApplyResult, PolicyControlError>,
    {
        let expectation = reviewed_plan.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        let transition = reviewed_plan.transition_plan(&expectation)?;
        let session_manager = self
            .session_manager
            .as_ref()
            .ok_or(PolicyControlError::SessionAuthorityRequired)?;
        let _session_conflict_guard = session_manager.acquire(&transition)?;
        let journal = match self.journal.begin(&transition, &authorization, actor_id)? {
            DurableControlStart::Apply(journal) => journal,
            DurableControlStart::Cached(terminal) => {
                return self.cached_apply_result(reviewed_plan, &terminal);
            }
        };
        if journal.is_resumed() {
            let snapshot = self.policies.load(&reviewed_plan.target)?;
            let current_policy = snapshot
                .as_ref()
                .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
            if current_policy == reviewed_plan.resulting_policy {
                let status = if reviewed_plan.no_op {
                    DurableControlTerminalStatus::NoOp
                } else {
                    DurableControlTerminalStatus::Applied
                };
                let result = PolicyApplyResult {
                    status: if reviewed_plan.no_op {
                        PolicyApplyStatus::NoOp
                    } else {
                        PolicyApplyStatus::Applied
                    },
                    target: reviewed_plan.target.clone(),
                    provider: reviewed_plan.provider,
                    revision: snapshot.map(|snapshot| snapshot.revision),
                    policy: current_policy,
                    activation: reviewed_plan.activation,
                    plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
                };
                journal.commit_with_terminal_status(status)?;
                return Ok(result);
            }
            let pre_state_matches =
                match (snapshot.as_ref(), reviewed_plan.expected_revision.as_ref()) {
                    (Some(snapshot), Some(expected)) => &snapshot.revision == expected,
                    (None, None) => true,
                    _ => false,
                };
            if !pre_state_matches {
                journal.needs_repair("control-resume-state-diverged")?;
                return Err(PolicyControlError::Durable(
                    DurableControlError::RecoveryRequired(expectation.operation_id),
                ));
            }
        }
        let current = match self.plan(
            reviewed_plan.target.clone(),
            reviewed_plan.provider,
            reviewed_plan.change.clone(),
        ) {
            Ok(current) => current,
            Err(error) => {
                journal.abort("control-plan-invalid")?;
                return Err(error);
            }
        };
        if current.plan_fingerprint != reviewed_plan.plan_fingerprint {
            journal.abort("control-plan-drift")?;
            return Err(PolicyControlError::PlanFingerprintMismatch);
        }
        match apply_reviewed(self, &current, actor_id) {
            Ok(result) => {
                let status = match result.status {
                    PolicyApplyStatus::Applied => DurableControlTerminalStatus::Applied,
                    PolicyApplyStatus::NoOp => DurableControlTerminalStatus::NoOp,
                };
                journal.commit_with_terminal_status(status)?;
                Ok(result)
            }
            Err(error) => {
                if let Some(candidate) = commit_uncertain_candidate(&error) {
                    let candidate = candidate.clone();
                    if self
                        .policies
                        .load(&reviewed_plan.target)
                        .is_ok_and(|snapshot| {
                            snapshot.is_some_and(|snapshot| snapshot.revision == candidate)
                        })
                    {
                        journal
                            .commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
                        return Ok(PolicyApplyResult {
                            status: PolicyApplyStatus::Applied,
                            target: reviewed_plan.target.clone(),
                            provider: reviewed_plan.provider,
                            revision: Some(candidate),
                            policy: reviewed_plan.resulting_policy.clone(),
                            activation: reviewed_plan.activation,
                            plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
                        });
                    }
                    journal.needs_repair("control-apply-commit-uncertain")?;
                    return Err(PolicyControlError::Durable(
                        DurableControlError::RecoveryRequired(expectation.operation_id),
                    ));
                }
                journal.abort("control-apply-aborted")?;
                Err(error)
            }
        }
    }

    fn cached_apply_result(
        &self,
        reviewed_plan: &PolicyChangePlan,
        terminal: &DurableControlTerminal,
    ) -> Result<PolicyApplyResult, PolicyControlError> {
        let revision = match terminal.status {
            DurableControlTerminalStatus::NoOp if reviewed_plan.no_op => {
                let snapshot = self.policies.load(&reviewed_plan.target)?;
                let current_policy = snapshot
                    .as_ref()
                    .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy.clone());
                if current_policy != reviewed_plan.resulting_policy {
                    return Err(PolicyControlError::Durable(
                        DurableControlError::RecoveryRequired(terminal.operation_id.clone()),
                    ));
                }
                snapshot.map(|snapshot| snapshot.revision)
            }
            DurableControlTerminalStatus::Applied if !reviewed_plan.no_op => {
                let snapshot = self.policies.load(&reviewed_plan.target)?.ok_or_else(|| {
                    PolicyControlError::Durable(DurableControlError::RecoveryRequired(
                        terminal.operation_id.clone(),
                    ))
                })?;
                if snapshot.policy != reviewed_plan.resulting_policy {
                    return Err(PolicyControlError::Durable(
                        DurableControlError::RecoveryRequired(terminal.operation_id.clone()),
                    ));
                }
                Some(snapshot.revision)
            }
            _ => {
                return Err(PolicyControlError::Durable(
                    DurableControlError::RecoveryRequired(terminal.operation_id.clone()),
                ));
            }
        };
        Ok(PolicyApplyResult {
            status: match terminal.status {
                DurableControlTerminalStatus::Applied => PolicyApplyStatus::Applied,
                DurableControlTerminalStatus::NoOp => PolicyApplyStatus::NoOp,
            },
            target: reviewed_plan.target.clone(),
            provider: reviewed_plan.provider,
            revision,
            policy: reviewed_plan.resulting_policy.clone(),
            activation: reviewed_plan.activation,
            plan_fingerprint: reviewed_plan.plan_fingerprint.clone(),
        })
    }

    pub(crate) fn apply_reviewed(
        &self,
        reviewed_plan: &PolicyChangePlan,
        actor_id: &str,
    ) -> Result<PolicyApplyResult, PolicyControlError> {
        reviewed_plan.verify()?;
        let current = self.plan(
            reviewed_plan.target.clone(),
            reviewed_plan.provider,
            reviewed_plan.change.clone(),
        )?;
        if current.plan_fingerprint != reviewed_plan.plan_fingerprint {
            return Err(PolicyControlError::PlanFingerprintMismatch);
        }
        self.apply_current(&current, actor_id)
    }

    fn apply_current(
        &self,
        current: &PolicyChangePlan,
        actor_id: &str,
    ) -> Result<PolicyApplyResult, PolicyControlError> {
        if current.no_op {
            return Ok(PolicyApplyResult {
                status: PolicyApplyStatus::NoOp,
                target: current.target.clone(),
                provider: current.provider,
                revision: current.expected_revision.clone(),
                policy: current.resulting_policy.clone(),
                activation: current.activation,
                plan_fingerprint: current.plan_fingerprint.clone(),
            });
        }
        let snapshot = self.policies.load(&current.target)?;
        let generation = next_generation(snapshot.as_ref())?;
        let revision = self.policies.save(
            &current.target,
            &current.resulting_policy,
            current.expected_revision.as_ref(),
            OwnerGeneration::new(actor_id, generation)?,
        )?;
        Ok(PolicyApplyResult {
            status: PolicyApplyStatus::Applied,
            target: current.target.clone(),
            provider: current.provider,
            revision: Some(revision),
            policy: current.resulting_policy.clone(),
            activation: current.activation,
            plan_fingerprint: current.plan_fingerprint.clone(),
        })
    }

    fn validate_profile_selection(
        &self,
        target: &PolicyTarget,
        provider: Option<ProviderId>,
        policy: &ScopePolicy,
        additional_revisions: &[crate::profiles::CompiledProfileRevision],
    ) -> Result<(), PolicyControlError> {
        let mut revisions = ProfileRevisionSet::default();
        for revision in additional_revisions {
            revisions.insert(revision.clone())?;
        }
        for selection in profile_selections(policy) {
            if let ProfileSelection::Profile { reference } = selection
                && revisions.get(&reference.digest).is_none()
            {
                let revision =
                    self.profiles
                        .load_revision(&reference.digest)?
                        .ok_or_else(|| PolicyControlError::MissingProfileRevision {
                            digest: reference.digest.clone(),
                        })?;
                revisions.insert(revision)?;
            }
        }
        let policies = policies_for_target(target, policy.clone());
        let providers = provider.map_or_else(|| ProviderId::ALL.to_vec(), |value| vec![value]);
        for provider in providers {
            resolve_effective_policy(provider, &policies, &revisions)?;
        }
        Ok(())
    }
}

fn commit_uncertain_candidate(error: &PolicyControlError) -> Option<&StateRevision> {
    match error {
        PolicyControlError::Store(PolicyStoreError::State(StateError::CommitUncertain {
            candidate,
            ..
        }))
        | PolicyControlError::State(StateError::CommitUncertain { candidate, .. }) => {
            Some(candidate)
        }
        _ => None,
    }
}

impl PolicyChangePlan {
    fn transition_plan(
        &self,
        expectation: &ApprovalExpectation,
    ) -> Result<TransitionPlan, PolicyControlError> {
        let mut provider_views = self
            .provider
            .map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]);
        provider_views.sort();
        let capability_lock_only = self.change.is_capability_lock_only();
        TransitionPlan::new(
            expectation.operation_id.clone(),
            if capability_lock_only {
                TransitionKind::ApplyCapabilityPolicy
            } else {
                TransitionKind::ApplyProfile
            },
            TransitionContext {
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: None,
                profile_digest: expectation.profile_digest.clone(),
            },
            vec![TransitionEffect {
                effect_id: if capability_lock_only {
                    "capability-lock-policy-effect"
                } else {
                    "profile-policy-effect"
                }
                .to_string(),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: policy_change_resource_id(&self.target, self.provider, &self.change)?,
                target_type: if capability_lock_only {
                    "unpin-capability-lock-policy"
                } else {
                    "unpin-policy"
                }
                .to_string(),
                summary: if capability_lock_only {
                    "Apply reviewed capability lock policy for future sessions"
                } else {
                    "Apply reviewed profile policy for future sessions"
                }
                .to_string(),
                authority: EffectAuthority::UserManaged,
                activation: self.activation,
                expected_pre_fingerprint: self
                    .expected_revision
                    .as_ref()
                    .map(|revision| approval_binding_digest(&revision.fingerprint)),
                expected_post_fingerprint: Some(serialized_digest(&self.resulting_policy)?),
                provider_views,
            }],
        )
        .map_err(PolicyControlError::TransitionPlan)
    }
}

fn apply_change(policy: &mut ScopePolicy, provider: Option<ProviderId>, change: &PolicyChange) {
    match provider {
        Some(provider) => {
            let target = policy.providers.entry(provider).or_default();
            if let Some(profile) = &change.profile {
                target.profile = profile.clone();
            }
            if let Some(gateway) = change.gateway {
                target.gateway = gateway;
            }
            if let Some(lock) = &change.capability_lock {
                match lock.state {
                    Some(state) => {
                        target
                            .capability_locks
                            .insert(lock.capability_id.clone(), state);
                    }
                    None => {
                        target.capability_locks.remove(&lock.capability_id);
                    }
                }
            }
            if target == &ProviderPolicy::default() {
                policy.providers.remove(&provider);
            }
        }
        None => {
            if let Some(profile) = &change.profile {
                policy.profile = profile.clone();
            }
            if let Some(gateway) = change.gateway {
                policy.gateway = gateway;
            }
        }
    }
}

impl PolicyChange {
    #[must_use]
    fn is_capability_lock_only(&self) -> bool {
        self.capability_lock.is_some() && self.profile.is_none() && self.gateway.is_none()
    }
}

fn profile_selections(policy: &ScopePolicy) -> impl Iterator<Item = &ProfileSelection> {
    std::iter::once(&policy.profile)
        .chain(policy.providers.values().map(|provider| &provider.profile))
}

fn policies_for_target(target: &PolicyTarget, policy: ScopePolicy) -> ResolutionPolicies {
    match target {
        PolicyTarget::Global => ResolutionPolicies {
            global: policy,
            ..ResolutionPolicies::default()
        },
        PolicyTarget::Repository { .. } => ResolutionPolicies {
            repository: Some(policy),
            ..ResolutionPolicies::default()
        },
        PolicyTarget::Workspace { .. } => ResolutionPolicies {
            workspace: Some(policy),
            ..ResolutionPolicies::default()
        },
    }
}

fn next_generation(snapshot: Option<&PolicySnapshot>) -> Result<u64, PolicyControlError> {
    snapshot.map_or(Ok(1), |snapshot| {
        snapshot
            .owner
            .generation
            .checked_add(1)
            .ok_or(PolicyControlError::OwnerGenerationOverflow)
    })
}

fn plan_fingerprint(
    target: &PolicyTarget,
    provider: Option<ProviderId>,
    expected_revision: Option<&StateRevision>,
    change: &PolicyChange,
    resulting_policy: &ScopePolicy,
    no_op: bool,
    activation: EffectActivation,
) -> Result<String, PolicyControlError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        target: &'a PolicyTarget,
        provider: Option<ProviderId>,
        expected_revision: Option<&'a StateRevision>,
        change: &'a PolicyChange,
        resulting_policy: &'a ScopePolicy,
        no_op: bool,
        activation: EffectActivation,
    }
    serialized_digest(&FingerprintBody {
        schema_version: POLICY_CHANGE_PLAN_SCHEMA_VERSION,
        target,
        provider,
        expected_revision,
        change,
        resulting_policy,
        no_op,
        activation,
    })
}

pub fn policy_resource_id(target: &PolicyTarget) -> Result<String, PolicyControlError> {
    Ok(format!(
        "profile-policy-{}",
        &serialized_digest(target)?[..16]
    ))
}

pub fn capability_lock_resource_id(provider: ProviderId) -> String {
    format!("capability-lock-policy-{}", provider.as_str())
}

fn policy_change_resource_id(
    target: &PolicyTarget,
    provider: Option<ProviderId>,
    change: &PolicyChange,
) -> Result<String, PolicyControlError> {
    if change.is_capability_lock_only() {
        Ok(capability_lock_resource_id(provider.ok_or(
            PolicyControlError::CapabilityLocksRequireProvider,
        )?))
    } else {
        policy_resource_id(target)
    }
}

fn serialized_digest(value: &impl Serialize) -> Result<String, PolicyControlError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PolicyControlError::Serialization(error.to_string()))?;
    Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
}

#[derive(Debug)]
pub enum PolicyControlError {
    Approval(ApprovalError),
    Store(PolicyStoreError),
    ProfileStore(ProfileStoreError),
    Resolution(PolicyResolutionError),
    State(crate::state::atomic_json::StateError),
    Durable(DurableControlError),
    TransitionPlan(TransitionPlanError),
    TransitionConflict(TransitionConflict),
    SessionAuthorityRequired,
    EmptyChange,
    CapabilityLocksRequireGlobalTarget,
    CapabilityLocksRequireProvider,
    MixedCapabilityLockChange,
    InvalidPlan,
    PlanFingerprintMismatch,
    MissingProfileRevision { digest: String },
    OwnerGenerationOverflow,
    Serialization(String),
}

impl From<ApprovalError> for PolicyControlError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<PolicyStoreError> for PolicyControlError {
    fn from(error: PolicyStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ProfileStoreError> for PolicyControlError {
    fn from(error: ProfileStoreError) -> Self {
        Self::ProfileStore(error)
    }
}

impl From<PolicyResolutionError> for PolicyControlError {
    fn from(error: PolicyResolutionError) -> Self {
        Self::Resolution(error)
    }
}

impl From<crate::state::atomic_json::StateError> for PolicyControlError {
    fn from(error: crate::state::atomic_json::StateError) -> Self {
        Self::State(error)
    }
}

impl From<DurableControlError> for PolicyControlError {
    fn from(error: DurableControlError) -> Self {
        Self::Durable(error)
    }
}

impl From<TransitionConflict> for PolicyControlError {
    fn from(error: TransitionConflict) -> Self {
        Self::TransitionConflict(error)
    }
}

impl fmt::Display for PolicyControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::ProfileStore(error) => error.fmt(formatter),
            Self::Resolution(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::Durable(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::TransitionConflict(error) => {
                write!(formatter, "policy apply blocked by {}", error.code())
            }
            Self::SessionAuthorityRequired => {
                formatter.write_str("session authority key is required to check policy conflicts")
            }
            Self::EmptyChange => formatter.write_str("policy change is empty"),
            Self::CapabilityLocksRequireGlobalTarget => {
                formatter.write_str("capability locks require the global policy target")
            }
            Self::CapabilityLocksRequireProvider => {
                formatter.write_str("capability locks require a provider")
            }
            Self::MixedCapabilityLockChange => formatter.write_str(
                "capability lock changes cannot be combined with profile or gateway changes",
            ),
            Self::InvalidPlan => formatter.write_str("policy change plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed policy plan no longer matches current state")
            }
            Self::MissingProfileRevision { digest } => {
                write!(formatter, "compiled profile revision is missing: {digest}")
            }
            Self::OwnerGenerationOverflow => {
                formatter.write_str("policy owner generation overflow")
            }
            Self::Serialization(message) => {
                write!(formatter, "policy plan serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for PolicyControlError {}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        approval::{
            ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims,
            ApprovalVerifier, authorize_control,
        },
        transitions::{TransitionJournalStore, TransitionLifecycle},
    };

    fn controller() -> (TempDir, PathBuf, ProfilePolicyController) {
        let temp = TempDir::new().expect("temporary app state");
        let root = std::fs::canonicalize(temp.path()).expect("physical app-state root");
        let controller = ProfilePolicyController::with_session_authority_key(
            &root,
            SessionAuthorityKey::new([0x53; 32]),
        );
        (temp, root, controller)
    }

    fn control_context() -> ControlApprovalContext {
        ControlApprovalContext::new("repository", "workspace").expect("control approval context")
    }

    fn authorization(
        app_state_root: &Path,
        expectation: &ApprovalExpectation,
        marker: &str,
    ) -> ControlAuthorization {
        let key = ApprovalKey::new([0x71; 32]);
        let issuer = ApprovalIssuer::new(
            key.clone(),
            expectation.issuer.clone(),
            expectation.audience.clone(),
        )
        .expect("approval issuer");
        let receipt = issuer
            .issue(ApprovalReceiptClaims {
                version: 1,
                receipt_id: format!("receipt-{marker}"),
                nonce: format!("nonce-{marker}"),
                issuer: String::new(),
                audience: String::new(),
                operation_id: expectation.operation_id.clone(),
                operation_kind: expectation.operation_kind.clone(),
                effect_graph_digest: expectation.effect_graph_digest.clone(),
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
                resources: expectation.resources.clone(),
                issued_at_unix: 1_000,
                expires_at_unix: 1_060,
            })
            .expect("approval receipt");
        authorize_control(
            app_state_root,
            &receipt,
            &ApprovalVerifier::new(key),
            expectation,
            1_000,
            OwnerGeneration::new("control-approval-test", 1).expect("approval owner"),
        )
        .expect("control authorization")
    }

    fn injected_commit_uncertain(candidate: StateRevision) -> PolicyControlError {
        PolicyControlError::Store(PolicyStoreError::State(StateError::CommitUncertain {
            path: PathBuf::from("injected-policy-state.json"),
            candidate,
            message: "injected durability uncertainty".to_owned(),
        }))
    }

    fn apply_with_commit_uncertain<F>(
        controller: &ProfilePolicyController,
        app_state_root: &Path,
        plan: &PolicyChangePlan,
        context: &ControlApprovalContext,
        marker: &str,
        mutate_live_state: F,
    ) -> Result<PolicyApplyResult, PolicyControlError>
    where
        F: FnOnce(&ProfilePolicyController, &PolicyChangePlan, &str, &StateRevision),
    {
        let expectation = plan
            .approval_expectation(context)
            .expect("approval expectation");
        controller.apply_with(
            plan,
            authorization(app_state_root, &expectation, marker),
            context,
            "policy-control-test",
            |controller, current_plan, actor_id| {
                let applied = controller.apply_current(current_plan, actor_id)?;
                let candidate = applied.revision.expect("applied revision");
                mutate_live_state(controller, current_plan, actor_id, &candidate);
                Err(injected_commit_uncertain(candidate))
            },
        )
    }

    #[test]
    fn interrupted_apply_after_policy_write_resumes_as_committed() {
        let (_temp, root, controller) = controller();
        let context = control_context();
        let target = PolicyTarget::repository("repository").expect("policy target");
        let plan = controller
            .plan(
                target.clone(),
                None,
                PolicyChange {
                    profile: None,
                    gateway: Some(GatewaySelection::Gateway),
                    capability_lock: None,
                },
            )
            .expect("policy plan");
        let expectation = plan
            .approval_expectation(&context)
            .expect("approval expectation");
        let transition = plan.transition_plan(&expectation).expect("transition plan");
        let journal = match controller
            .journal
            .begin(
                &transition,
                &authorization(&root, &expectation, "interrupted-policy"),
                "policy-control-test",
            )
            .expect("begin durable operation")
        {
            DurableControlStart::Apply(journal) => journal,
            DurableControlStart::Cached(_) => panic!("new operation cannot be cached"),
        };
        let written = controller
            .apply_current(&plan, "policy-control-test")
            .expect("write policy before interruption");
        drop(journal);

        let resumed = controller
            .apply(
                &plan,
                authorization(&root, &expectation, "interrupted-policy"),
                &context,
                "policy-control-other-surface",
            )
            .expect("resume interrupted policy apply");

        assert_eq!(resumed, written);
        let journal = TransitionJournalStore::new(&root)
            .list()
            .expect("transition journals")
            .into_iter()
            .find(|journal| journal.operation_id == expectation.operation_id)
            .expect("policy transition journal");
        assert_eq!(journal.lifecycle, TransitionLifecycle::Committed);
    }

    #[test]
    fn commit_uncertain_with_live_create_or_update_candidate_commits_and_replays_as_noop() {
        for seed_update in [false, true] {
            let (_temp, root, controller) = controller();
            let context = control_context();
            let target = PolicyTarget::repository("repository").expect("policy target");
            if seed_update {
                let initial = ScopePolicy {
                    gateway: GatewaySelection::Native,
                    ..ScopePolicy::default()
                };
                controller
                    .policies
                    .save(
                        &target,
                        &initial,
                        None,
                        OwnerGeneration::new("seed", 1).expect("seed owner"),
                    )
                    .expect("seed policy");
            }
            let change = PolicyChange {
                profile: None,
                gateway: Some(GatewaySelection::Gateway),
                capability_lock: None,
            };
            let plan = controller
                .plan(target.clone(), None, change.clone())
                .expect("policy plan");
            assert_eq!(plan.expected_revision.is_some(), seed_update);
            let expectation = plan
                .approval_expectation(&context)
                .expect("approval expectation");

            let applied = apply_with_commit_uncertain(
                &controller,
                &root,
                &plan,
                &context,
                if seed_update {
                    "uncertain-update"
                } else {
                    "uncertain-create"
                },
                |_controller, _plan, _actor_id, _candidate| {},
            )
            .expect("live candidate reconciles as committed");
            assert_eq!(applied.status, PolicyApplyStatus::Applied);
            assert_eq!(
                controller
                    .policies
                    .load(&target)
                    .expect("load policy")
                    .expect("live policy")
                    .revision,
                applied.revision.expect("applied revision")
            );

            let journal = TransitionJournalStore::new(&root)
                .list()
                .expect("transition journals")
                .into_iter()
                .find(|journal| journal.operation_id == expectation.operation_id)
                .expect("policy transition journal");
            assert_eq!(journal.lifecycle, TransitionLifecycle::Committed);
            assert!(
                journal
                    .audit
                    .iter()
                    .all(|event| event.lifecycle != TransitionLifecycle::RolledBack)
            );

            let replay = controller.plan(target, None, change).expect("replay plan");
            assert!(replay.no_op);
            let replay_expectation = replay
                .approval_expectation(&context)
                .expect("replay expectation");
            assert_eq!(
                controller
                    .apply(
                        &replay,
                        authorization(&root, &replay_expectation, "uncertain-replay"),
                        &context,
                        "policy-control-test",
                    )
                    .expect("replay apply")
                    .status,
                PolicyApplyStatus::NoOp
            );
        }
    }

    #[derive(Clone, Copy)]
    enum AmbiguousLiveState {
        Removed,
        Diverged,
    }

    #[test]
    fn commit_uncertain_with_removed_or_diverged_candidate_requires_recovery() {
        for live_state in [AmbiguousLiveState::Removed, AmbiguousLiveState::Diverged] {
            let (_temp, root, controller) = controller();
            let context = control_context();
            let target = PolicyTarget::repository("repository").expect("policy target");
            let plan = controller
                .plan(
                    target.clone(),
                    None,
                    PolicyChange {
                        profile: None,
                        gateway: Some(GatewaySelection::Gateway),
                        capability_lock: None,
                    },
                )
                .expect("policy plan");
            let expectation = plan
                .approval_expectation(&context)
                .expect("approval expectation");

            let result = apply_with_commit_uncertain(
                &controller,
                &root,
                &plan,
                &context,
                match live_state {
                    AmbiguousLiveState::Removed => "uncertain-removed",
                    AmbiguousLiveState::Diverged => "uncertain-diverged",
                },
                |controller, reviewed_plan, actor_id, candidate| match live_state {
                    AmbiguousLiveState::Removed => controller
                        .policies
                        .restore_checkpoint(
                            &reviewed_plan.target,
                            None,
                            candidate,
                            OwnerGeneration::new(actor_id, 2).expect("restore owner"),
                        )
                        .expect("remove live candidate"),
                    AmbiguousLiveState::Diverged => {
                        let snapshot = controller
                            .policies
                            .load(&reviewed_plan.target)
                            .expect("load candidate")
                            .expect("candidate policy");
                        let divergent = ScopePolicy {
                            gateway: GatewaySelection::Native,
                            ..ScopePolicy::default()
                        };
                        controller
                            .policies
                            .save(
                                &reviewed_plan.target,
                                &divergent,
                                Some(candidate),
                                OwnerGeneration::new(actor_id, snapshot.owner.generation + 1)
                                    .expect("divergent owner"),
                            )
                            .expect("diverge live candidate");
                    }
                },
            );
            assert!(matches!(
                result,
                Err(PolicyControlError::Durable(
                    DurableControlError::RecoveryRequired(ref operation_id)
                )) if operation_id == &expectation.operation_id
            ));

            let journal = TransitionJournalStore::new(&root)
                .list()
                .expect("transition journals")
                .into_iter()
                .find(|journal| journal.operation_id == expectation.operation_id)
                .expect("policy transition journal");
            assert_eq!(journal.lifecycle, TransitionLifecycle::NeedsRepair);
            assert_eq!(
                journal.terminal_code.as_deref(),
                Some("control-apply-commit-uncertain")
            );
            assert!(
                journal
                    .audit
                    .iter()
                    .all(|event| event.lifecycle != TransitionLifecycle::RolledBack)
            );
        }
    }
}
