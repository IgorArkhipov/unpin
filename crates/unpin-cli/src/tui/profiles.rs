use std::path::Path;

use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    catalog::Catalog,
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        ReachAwarePrincipal, ReachAwareRootBinding,
    },
    discovery::DiscoveryOutput,
    profiles::{
        CapabilityLockEnforcement, CapabilityLockSnapshot, CompiledProfileRevision,
        GatewaySelection, PROFILE_PROVIDER_APPROVAL_AUDIENCE, PolicyTarget, ProfileDefinitionEntry,
        ProfileProviderOperationController, ProfileProviderOperationError,
        ProfileProviderOperationPlan, ProfileProviderOperationStatus,
        ProfileProviderReachAwareApplyContext, ProfileStore, ResolutionPolicies,
        capability_lock_enforcement, compile_profile, profile_reach_scope_digest,
        resolve_effective_gateway,
    },
    provider_reach::{ConnectionBoundary, ProviderReach, SelectedProviderProvenance},
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::OwnerGeneration,
};

use crate::{credentials, unix_now};

use super::WorkflowPhase;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProfileBackend {
    Native,
    Gateway,
}

impl ProfileBackend {
    fn cycle(self) -> Self {
        match self {
            Self::Native => Self::Gateway,
            Self::Gateway => Self::Native,
        }
    }

    fn selection(self) -> GatewaySelection {
        match self {
            Self::Native => GatewaySelection::Native,
            Self::Gateway => GatewaySelection::Gateway,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProfilePolicyScope {
    Global,
    Repository,
    Workspace,
}

impl ProfilePolicyScope {
    fn cycle(self) -> Self {
        match self {
            Self::Workspace => Self::Global,
            Self::Global => Self::Repository,
            Self::Repository => Self::Workspace,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Repository => "repository",
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone)]
struct ReviewedProfilePlan {
    compiled: CompiledProfileRevision,
    plan: ProfileProviderOperationPlan,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct ProfileWorkflow {
    repository_key: String,
    workspace_key: String,
    profiles: Vec<ProfileDefinitionEntry>,
    selected: usize,
    backend: ProfileBackend,
    scope: ProfilePolicyScope,
    provider: Option<ProviderId>,
    reviewed: Option<ReviewedProfilePlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
    capability_locks: Vec<CapabilityLockEnforcement>,
    capability_lock_digests: Vec<(ProviderId, String)>,
}

impl ProfileWorkflow {
    pub(super) fn new(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        profiles: Vec<ProfileDefinitionEntry>,
    ) -> Self {
        Self {
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            profiles,
            selected: 0,
            backend: ProfileBackend::Native,
            scope: ProfilePolicyScope::Workspace,
            provider: None,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
            capability_locks: Vec::new(),
            capability_lock_digests: Vec::new(),
        }
    }

    pub(super) fn new_with_policy(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        profiles: Vec<ProfileDefinitionEntry>,
        policies: &ResolutionPolicies,
        discovery: &DiscoveryOutput,
    ) -> Self {
        let mut workflow = Self::new(repository_key, workspace_key, profiles);
        let catalog = discovery.to_catalog().unwrap_or_default();
        for (provider, provider_policy) in &policies.global.providers {
            if provider_policy.capability_locks.is_empty() {
                continue;
            }
            let snapshot = CapabilityLockSnapshot::compile(
                *provider,
                provider_policy.capability_locks.clone(),
            )
            .expect("typed capability locks serialize deterministically");
            let (gateway, _) = resolve_effective_gateway(*provider, policies);
            workflow
                .capability_locks
                .extend(capability_lock_enforcement(&snapshot, &catalog, gateway));
            workflow
                .capability_lock_digests
                .push((*provider, snapshot.digest));
        }
        workflow
    }

    pub(super) fn empty() -> Self {
        Self::new("unavailable", "unavailable", Vec::new())
    }

    pub(super) fn len(&self) -> usize {
        self.profiles.len()
    }

    pub(super) fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    pub(super) fn backend(&self) -> ProfileBackend {
        self.backend
    }

    pub(super) fn scope(&self) -> ProfilePolicyScope {
        self.scope
    }

    pub(super) fn provider(&self) -> Option<ProviderId> {
        self.provider
    }

    pub(super) fn select_next(&mut self) {
        if !self.profiles.is_empty() {
            self.selected = (self.selected + 1) % self.profiles.len();
            self.reset_review();
        }
    }

    pub(super) fn select_previous(&mut self) {
        if !self.profiles.is_empty() {
            self.selected = if self.selected == 0 {
                self.profiles.len() - 1
            } else {
                self.selected - 1
            };
            self.reset_review();
        }
    }

    pub(super) fn cycle_backend(&mut self) {
        self.backend = self.backend.cycle();
        self.reset_review();
    }

    pub(super) fn cycle_scope(&mut self) {
        self.scope = self.scope.cycle();
        self.reset_review();
    }

    pub(super) fn cycle_provider(&mut self) {
        self.provider = match self.provider {
            None => ProviderId::ALL.first().copied(),
            Some(current) => ProviderId::ALL
                .iter()
                .position(|provider| *provider == current)
                .and_then(|index| ProviderId::ALL.get(index + 1).copied()),
        };
        self.reset_review();
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| {
                format!(
                    "{} {} ({:?}) members={}",
                    if index == self.selected { ">" } else { " " },
                    profile.definition.display_name,
                    profile.scope,
                    profile.definition.members.len()
                        + profile
                            .definition
                            .provider_members
                            .values()
                            .map(Vec::len)
                            .sum::<usize>()
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![format!(
            "Profiles: {} | backend={} | scope={} | provider={} | phase={}",
            self.profiles.len(),
            self.backend().label(),
            self.scope().label(),
            self.provider().map_or("generic", ProviderId::as_str),
            self.phase().label()
        )];
        if let Some(profile) = self.profiles.get(self.selected) {
            details.push(format!("selected: {}", profile.definition.id));
            details.push(format!("scope: {:?}", profile.scope));
        } else {
            details.push("selected: none".to_string());
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.plan.plan_fingerprint));
            details.push(format!("activation: {:?}", reviewed.plan.activation));
            details.push(format!("reach: {:?}", reviewed.plan.provider_reach));
            for coverage in &reviewed.plan.coverage.entries {
                details.push(format!(
                    "coverage: {} target={} included={} reason={}",
                    coverage.provider.as_str(),
                    coverage.target_id,
                    coverage.included,
                    coverage.reason.map_or("none", |reason| reason.as_str()),
                ));
            }
            for target in &reviewed.plan.targets {
                details.push(format!(
                    "target: {} classification={} activation={:?}",
                    target.provider.as_str(),
                    target.classification.as_str(),
                    target.activation,
                ));
            }
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
        for (provider, digest) in &self.capability_lock_digests {
            details.push(format!(
                "global locks: {} revision={} activation=next-session-only",
                provider.as_str(),
                digest
            ));
        }
        for lock in self.capability_locks.iter().filter(|lock| {
            self.provider
                .is_none_or(|provider| provider == lock.provider)
        }) {
            details.push(format!(
                "lock: {} {} {:?} source=global enforcement={:?} action=`unpin profile lock`",
                lock.provider.as_str(),
                lock.capability_id,
                lock.state,
                lock.enforcement
            ));
        }
        details
    }

    pub(super) fn plan(
        &mut self,
        discovery: &DiscoveryOutput,
        app_state_root: &Path,
        context: &ControlApprovalContext,
    ) -> Result<&ControlOperationEnvelope, String> {
        let entry = self
            .profiles
            .get(self.selected)
            .ok_or_else(|| "no profile selected".to_string())?;
        let catalog = Catalog::from_discovery(discovery).map_err(|error| error.to_string())?;
        let compiled = compile_profile(&entry.definition, &catalog, entry.scope)
            .map_err(|error| error.to_string())?;
        let target = match self.scope {
            ProfilePolicyScope::Global => PolicyTarget::Global,
            ProfilePolicyScope::Repository => {
                PolicyTarget::repository(&self.repository_key).map_err(|error| error.to_string())?
            }
            ProfilePolicyScope::Workspace => {
                PolicyTarget::workspace(&self.repository_key, &self.workspace_key)
                    .map_err(|error| error.to_string())?
            }
        };
        let provider_reach = self.provider.map_or(ProviderReach::All, |provider| {
            ProviderReach::selected(provider, SelectedProviderProvenance::TuiControl)
        });
        let plan = ProfileProviderOperationController::new(app_state_root)
            .plan_with_gateway(&target, &compiled, provider_reach, self.backend.selection())
            .map_err(|error| error.to_string())?;
        let expectation = plan
            .approval_expectation(context, &plan.operation_id)
            .map_err(|error| error.to_string())?;
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            plan.activation,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Review profile, backend, scope, and fingerprint before apply."
                    .to_string(),
            }),
            false,
            plan.coverage
                .included()
                .map(|coverage| coverage.provider)
                .collect(),
            json!({
                "profile": compiled,
                "plan": plan,
                "policyScope": self.scope.label(),
                "providerReach": provider_reach,
                "providerCoverage": plan.coverage,
            }),
        );
        self.reviewed = Some(ReviewedProfilePlan {
            compiled,
            plan,
            envelope,
        });
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        fixture_mode: bool,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("profile plan must be confirmed before apply".to_string());
        }
        unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [app_state_root, project_root],
        )?;
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "profile plan is missing".to_string())?;
        let expectation = reviewed
            .plan
            .approval_expectation(context, &reviewed.plan.operation_id)
            .map_err(|error| error.to_string())?;
        let authorization = credentials::authorize_reviewed_control_decision(
            fixture_mode,
            app_state_root,
            &expectation,
            &reviewed.plan.plan_fingerprint,
            Some(&reviewed.plan.plan_fingerprint),
            "unpin-tui-profile-approval",
            unix_now(),
        )?;
        let roots = ReachAwareRootBinding::from_provider_paths(
            app_state_root,
            Vec::new(),
            "unpin-tui-profile-provider",
        )
        .map_err(|error| error.to_string())?;
        let principal = ReachAwarePrincipal::sign(
            reviewed.plan.operation_id.clone(),
            profile_reach_scope_digest(&expectation, &reviewed.plan.operation_id),
            ConnectionBoundary::All,
            authority_key,
        )
        .map_err(|error| error.to_string())?;
        let now_unix = unix_now();
        let durable = ProfileProviderReachAwareApplyContext {
            approval_context: context.clone(),
            roots,
            principal,
            audience: PROFILE_PROVIDER_APPROVAL_AUDIENCE.to_string(),
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 3600,
            now_unix,
        };
        ProfileStore::new(app_state_root)
            .materialize_revision(
                &reviewed.compiled,
                OwnerGeneration::new("unpin-tui-profile-provider", 1)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        let result = match ProfileProviderOperationController::new(app_state_root)
            .with_session_authority_key(authority_key.clone())
            .apply_with_reach_aware(
                &reviewed.plan,
                authorization,
                durable,
                "unpin-tui-profile-provider",
            ) {
            Ok(result) => result,
            Err(error) => {
                if matches!(
                    &error,
                    ProfileProviderOperationError::RecoveryRequired { .. }
                ) {
                    self.phase = WorkflowPhase::RecoveryRequired;
                }
                return Err(error.to_string());
            }
        };
        let (phase, lifecycle) = match result.status {
            ProfileProviderOperationStatus::Applied => {
                (WorkflowPhase::Applied, ControlOperationLifecycle::Applied)
            }
            ProfileProviderOperationStatus::NoOp => {
                (WorkflowPhase::Applied, ControlOperationLifecycle::NoOp)
            }
            ProfileProviderOperationStatus::Blocked => {
                (WorkflowPhase::Blocked, ControlOperationLifecycle::Blocked)
            }
            ProfileProviderOperationStatus::RecoveryRequired => (
                WorkflowPhase::RecoveryRequired,
                ControlOperationLifecycle::RecoveryRequired,
            ),
        };
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &expectation,
            &reviewed.plan.plan_fingerprint,
            reviewed.plan.activation,
            lifecycle,
            None,
            false,
            reviewed
                .plan
                .coverage
                .included()
                .map(|coverage| coverage.provider)
                .collect(),
            json!({
                "profile": reviewed.compiled,
                "result": result,
                "policyScope": self.scope.label(),
                "providerReach": reviewed.plan.provider_reach,
                "providerCoverage": reviewed.plan.coverage,
            }),
        ));
        self.phase = phase;
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
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
    use std::collections::BTreeMap;
    use unpin_core::{
        catalog::CapabilityId,
        profiles::{
            CapabilityLockState, PROFILE_DEFINITION_VERSION, PolicyStore, ProfileDefinition,
            ProfileSourceScope, ProviderPolicy, ScopePolicy,
        },
    };

    fn workflow() -> ProfileWorkflow {
        workflow_with_source(ProfileSourceScope::Workspace)
    }

    fn authority_key() -> SessionAuthorityKey {
        SessionAuthorityKey::new([0x53; 32])
    }

    #[test]
    fn profile_details_report_global_lock_revision_source_enforcement_and_action() {
        let capability_id = CapabilityId::new("skill.review").unwrap();
        let global = ScopePolicy {
            providers: BTreeMap::from([(
                ProviderId::Codex,
                ProviderPolicy {
                    capability_locks: BTreeMap::from([(
                        capability_id,
                        CapabilityLockState::HardDisabled,
                    )]),
                    ..ProviderPolicy::default()
                },
            )]),
            ..ScopePolicy::default()
        };
        let workflow = ProfileWorkflow::new_with_policy(
            "repo",
            "worktree",
            Vec::new(),
            &ResolutionPolicies {
                global,
                ..ResolutionPolicies::default()
            },
            &DiscoveryOutput::default(),
        );
        let details = workflow.details().join("\n");
        assert!(details.contains("global locks: codex revision="));
        assert!(details.contains("source=global"));
        assert!(details.contains("enforcement=Unsupported"));
        assert!(details.contains("action=`unpin profile lock`"));
    }

    fn workflow_with_source(source_scope: ProfileSourceScope) -> ProfileWorkflow {
        ProfileWorkflow::new(
            "repo",
            "worktree",
            vec![ProfileDefinitionEntry {
                scope: source_scope,
                definition: ProfileDefinition {
                    version: PROFILE_DEFINITION_VERSION,
                    id: "review".to_string(),
                    display_name: "Review".to_string(),
                    description: None,
                    members: Vec::new(),
                    provider_members: BTreeMap::new(),
                    supported_providers: std::collections::BTreeSet::from([
                        ProviderId::Claude,
                        ProviderId::Codex,
                    ]),
                },
                revision: None,
            }],
        )
    }

    #[test]
    fn profile_workflow_plans_real_policy_and_requires_confirmation() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let mut workflow = workflow();
        let envelope = workflow
            .plan(
                &DiscoveryOutput {
                    items: Vec::new(),
                    warnings: Vec::new(),
                },
                &root,
                &context,
            )
            .unwrap();

        assert_eq!(
            envelope.lifecycle,
            ControlOperationLifecycle::AwaitingHumanAction
        );
        assert_eq!(envelope.details["providerReach"], "all");
        assert_eq!(
            envelope.details["providerCoverage"]["entries"]
                .as_array()
                .expect("profile coverage")
                .len(),
            2
        );
        assert_eq!(workflow.phase(), WorkflowPhase::Planned);
        assert!(workflow.confirm());
        assert_eq!(workflow.phase(), WorkflowPhase::Confirmed);
        let result = workflow
            .apply(&root, &root, &context, &authority_key(), true)
            .expect("fixture profile apply");
        assert_eq!(result.lifecycle, ControlOperationLifecycle::Applied);
        assert_eq!(workflow.phase(), WorkflowPhase::Applied);
    }

    #[test]
    fn changing_backend_invalidates_reviewed_plan() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let mut workflow = workflow();
        workflow
            .plan(
                &DiscoveryOutput {
                    items: Vec::new(),
                    warnings: Vec::new(),
                },
                &root,
                &context,
            )
            .unwrap();
        workflow.cycle_backend();

        assert_eq!(workflow.backend(), ProfileBackend::Gateway);
        assert_eq!(workflow.phase(), WorkflowPhase::Browsing);
        assert!(!workflow.confirm());
    }

    #[test]
    fn scope_and_provider_changes_invalidate_confirmed_plan() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let discovery = DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
        };
        let mut workflow = workflow();
        workflow.plan(&discovery, &root, &context).unwrap();
        assert!(workflow.confirm());

        workflow.cycle_scope();
        assert_eq!(workflow.scope(), ProfilePolicyScope::Global);
        assert_eq!(workflow.phase(), WorkflowPhase::Browsing);
        assert!(!workflow.confirm());

        workflow.cycle_scope();
        workflow.cycle_scope();
        assert_eq!(workflow.scope(), ProfilePolicyScope::Workspace);
        workflow.plan(&discovery, &root, &context).unwrap();
        assert!(workflow.confirm());
        workflow.cycle_provider();
        assert_eq!(workflow.provider(), ProviderId::ALL.first().copied());
        assert_eq!(workflow.phase(), WorkflowPhase::Browsing);
        assert!(!workflow.confirm());
    }

    #[test]
    fn global_provider_apply_writes_only_selected_policy_target() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let context = ControlApprovalContext::new("repo", "worktree").unwrap();
        let discovery = DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
        };
        let mut workflow = workflow_with_source(ProfileSourceScope::Global);
        workflow.cycle_scope();
        workflow.cycle_provider();
        let provider = workflow.provider().expect("selected provider");
        let planned = workflow.plan(&discovery, &root, &context).unwrap();
        assert_eq!(planned.details["policyScope"], "global");
        assert_eq!(planned.provider_coverage, vec![provider]);
        assert!(workflow.confirm());
        let applied = workflow
            .apply(&root, &root, &context, &authority_key(), true)
            .unwrap();
        assert_eq!(applied.lifecycle, ControlOperationLifecycle::Applied);

        let store = PolicyStore::new(&root);
        let global = store
            .load(&PolicyTarget::Global)
            .unwrap()
            .expect("global policy");
        assert!(global.policy.profile.is_inherit());
        assert!(matches!(
            global.policy.providers[&provider].profile,
            unpin_core::profiles::ProfileSelection::Profile { .. }
        ));
        let workspace = PolicyTarget::workspace("repo", "worktree").unwrap();
        assert!(store.load(&workspace).unwrap().is_none());
    }

    #[test]
    fn profile_recovery_required_phase_survives_later_error_recording() {
        let mut workflow = workflow();
        workflow.phase = WorkflowPhase::RecoveryRequired;

        workflow.record_error("cached policy state diverged".to_string());

        assert_eq!(workflow.phase(), WorkflowPhase::RecoveryRequired);
        assert_eq!(
            workflow.last_error.as_deref(),
            Some("cached policy state diverged")
        );
    }
}
