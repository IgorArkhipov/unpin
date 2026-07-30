use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{ApprovalExpectation, ControlApprovalContext},
    discovery::{DiscoveryCategory, DiscoveryItem, ProviderId, discover_all},
    encode_lower_hex,
    groups::resolver::index_discovery,
    groups::{
        GroupDefinitionView, GroupDiscoveryIndex, GroupMemberIdentity, GroupRef, GroupResolveError,
        GroupResolver, GroupRevision, GroupScope, GroupSessionError, MAX_GROUP_MEMBERS,
        secure_random_identifier,
    },
    mutation::{
        CONTROL_PLANE_PROTECTED_REASON, NativeToggleController, NativeTogglePlan,
        is_control_plane_protected_disable,
    },
    provider_reach::{
        IncludedTargetOutcome, ProviderCoverageEntry, ProviderReach, ProviderReachCoverage,
        ProviderReachError, ProviderReachLifecycle, ProviderReachRequest, classify_lifecycle,
    },
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionKind, TransitionPlan, TransitionPlanError,
    },
};

pub const GROUP_PLAN_SCHEMA_VERSION: u32 = 2;
pub const GROUP_APPROVAL_ISSUER: &str = "unpin-cli-inventory-group-v1";
pub const GROUP_APPROVAL_AUDIENCE: &str = "unpin-core-inventory-group-apply-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupTargetState {
    Enable,
    Disable,
}

impl GroupTargetState {
    #[must_use]
    pub const fn enabled(self) -> bool {
        matches!(self, Self::Enable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupPlanMode {
    PreviewOnly,
    TuiDirect,
    McpHandoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupPlanDisposition {
    Preview,
    Actionable,
    NoOp,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupMemberPlanOutcome {
    Changed,
    AlreadyCorrect,
    Blocked,
    Missing,
    OutOfProviderReach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberPlan {
    pub identity: GroupMemberIdentity,
    pub current_enabled: Option<bool>,
    pub requested_enabled: bool,
    pub outcome: GroupMemberPlanOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_plan_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_operation_id: Option<String>,
    #[serde(default)]
    pub affected_resources: Vec<String>,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub(crate) native_plan: Option<NativeTogglePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupResourcePlan {
    pub resource_id: String,
    pub target_type: String,
    pub member_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved_members: Vec<GroupPreservedMemberProof>,
    pub expected_pre_fingerprint: String,
    pub expected_post_fingerprint: String,
    pub provider_views: Vec<ProviderId>,
    pub activation: EffectActivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupPreservedMemberProof {
    pub member_index: usize,
    pub source_fingerprint: String,
    pub current_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupExecutionCohort {
    pub cohort_id: String,
    pub member_indices: Vec<usize>,
    pub resource_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupTogglePlan {
    pub schema_version: u32,
    pub response_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub disposition: GroupPlanDisposition,
    pub mode: GroupPlanMode,
    pub qualified_name: String,
    pub scope: GroupScope,
    pub group_revision: GroupRevision,
    pub target: GroupTargetState,
    pub max_members: usize,
    pub total_members: usize,
    pub provider_reach: ProviderReach,
    pub provider_coverage: ProviderReachCoverage,
    pub lifecycle: ProviderReachLifecycle,
    pub definition_view: GroupDefinitionView,
    pub members: Vec<GroupMemberPlan>,
    pub resources: Vec<GroupResourcePlan>,
    pub cohorts: Vec<GroupExecutionCohort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition: Option<TransitionPlan>,
    pub plan_fingerprint: String,
}

impl GroupTogglePlan {
    pub fn verify(&self) -> Result<(), GroupPlanError> {
        self.verify_structure()?;
        let calculated_fingerprint = calculate_group_fingerprint(self)?;
        self.verify_fingerprint(&calculated_fingerprint)
    }

    fn verify_with_fingerprint(&self, calculated_fingerprint: &str) -> Result<(), GroupPlanError> {
        self.verify_structure()?;
        self.verify_fingerprint(calculated_fingerprint)
    }

    fn verify_structure(&self) -> Result<(), GroupPlanError> {
        let reference =
            GroupRef::parse(&self.qualified_name).map_err(|_| GroupPlanError::InvalidPlan)?;
        if self.schema_version != GROUP_PLAN_SCHEMA_VERSION
            || self.total_members != self.members.len()
            || self.total_members == 0
            || self.total_members > self.max_members
            || self.max_members > MAX_GROUP_MEMBERS
            || reference.scope != Some(self.scope)
            || self.definition_view.qualified_name != self.qualified_name
            || self.definition_view.scope != self.scope
            || self.definition_view.revision != self.group_revision
            || self.provider_coverage.entries().iter().any(|entry| {
                entry.included != self.provider_reach.allows(entry.provider)
                    || (!entry.included
                        && entry.reason
                            != Some(crate::provider_reach::ProviderReachReason::OutOfProviderReach))
            })
            || self.provider_coverage.entries
                != ProviderReachCoverage::new(
                    self.members
                        .iter()
                        .map(|member| {
                            if self.provider_reach.allows(member.identity.provider) {
                                ProviderCoverageEntry::included(
                                    member.identity.provider,
                                    member.identity.id.clone(),
                                )
                            } else {
                                ProviderCoverageEntry::excluded(
                                    member.identity.provider,
                                    member.identity.id.clone(),
                                )
                            }
                        })
                        .collect(),
                )
                .entries
            || self.lifecycle != planned_reach_lifecycle(self)
            || self.disposition != expected_group_disposition(self)
            || self
                .cohorts
                .iter()
                .any(|cohort| !valid_cohort_id(&cohort.cohort_id))
        {
            return Err(GroupPlanError::InvalidPlan);
        }
        match self.disposition {
            GroupPlanDisposition::Actionable => {
                let transition = self
                    .transition
                    .as_ref()
                    .ok_or(GroupPlanError::InvalidPlan)?;
                if self.operation_id.as_deref() != Some(&transition.operation_id)
                    || transition.kind != TransitionKind::InventoryGroupApply
                {
                    return Err(GroupPlanError::InvalidPlan);
                }
                transition.verify()?;
            }
            GroupPlanDisposition::Preview
            | GroupPlanDisposition::NoOp
            | GroupPlanDisposition::Blocked => {
                if self.operation_id.is_some() || self.transition.is_some() {
                    return Err(GroupPlanError::InvalidPlan);
                }
            }
        }
        if self.members.iter().any(|member| match member.outcome {
            GroupMemberPlanOutcome::Changed => {
                !member
                    .item_plan_fingerprint
                    .as_deref()
                    .is_some_and(|value| value.len() == 64 && crate::is_lower_hex_digest(value))
                    || !member
                        .child_operation_id
                        .as_deref()
                        .is_some_and(valid_child_operation_id)
            }
            GroupMemberPlanOutcome::AlreadyCorrect
            | GroupMemberPlanOutcome::Blocked
            | GroupMemberPlanOutcome::Missing
            | GroupMemberPlanOutcome::OutOfProviderReach => {
                member.item_plan_fingerprint.is_some() || member.child_operation_id.is_some()
            }
        }) {
            return Err(GroupPlanError::InvalidPlan);
        }
        Ok(())
    }

    fn verify_fingerprint(&self, calculated_fingerprint: &str) -> Result<(), GroupPlanError> {
        if calculated_fingerprint != self.plan_fingerprint {
            return Err(GroupPlanError::FingerprintMismatch);
        }
        Ok(())
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, GroupPlanError> {
        self.verify()?;
        self.approval_expectation_verified(context)
    }

    pub(crate) fn approval_expectation_verified(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, GroupPlanError> {
        if self.disposition != GroupPlanDisposition::Actionable {
            return Err(GroupPlanError::NotActionable);
        }
        let transition = self
            .transition
            .as_ref()
            .ok_or(GroupPlanError::InvalidPlan)?;
        if transition.context.repository_key != context.repository_key()
            || transition.context.workspace_key != context.workspace_key()
        {
            return Err(GroupPlanError::ContextMismatch);
        }
        let mut expectation =
            transition.approval_expectation(GROUP_APPROVAL_ISSUER, GROUP_APPROVAL_AUDIENCE);
        expectation.effect_graph_digest = self.plan_fingerprint.clone();
        Ok(expectation)
    }

    #[must_use]
    pub fn actionable_member_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.outcome == GroupMemberPlanOutcome::Changed)
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct GroupPlanner {
    resolver: GroupResolver,
    #[cfg(test)]
    discovery_override: Option<crate::discovery::DiscoveryOutput>,
}

impl GroupPlanner {
    #[must_use]
    pub fn new(resolver: GroupResolver) -> Self {
        Self {
            resolver,
            #[cfg(test)]
            discovery_override: None,
        }
    }

    #[cfg(test)]
    fn with_discovery_override(mut self, discovery: crate::discovery::DiscoveryOutput) -> Self {
        self.discovery_override = Some(discovery);
        self
    }

    pub fn plan(
        &self,
        reference: &GroupRef,
        target: GroupTargetState,
        max_members: usize,
        mode: GroupPlanMode,
    ) -> Result<GroupTogglePlan, GroupPlanError> {
        self.plan_with_reach(reference, target, max_members, mode, ProviderReach::All)
    }

    /// Plan a group against an already validated provider reach.
    pub fn plan_with_reach(
        &self,
        reference: &GroupRef,
        target: GroupTargetState,
        max_members: usize,
        mode: GroupPlanMode,
        provider_reach: ProviderReach,
    ) -> Result<GroupTogglePlan, GroupPlanError> {
        self.plan_with_operation_id(reference, target, max_members, mode, provider_reach, None)
    }

    /// Validate provider authority before discovery, then plan the group.
    pub fn plan_with_provider_reach_request(
        &self,
        reference: &GroupRef,
        target: GroupTargetState,
        max_members: usize,
        mode: GroupPlanMode,
        request: ProviderReachRequest,
    ) -> Result<GroupTogglePlan, GroupPlanError> {
        let preflight = request
            .validate_before_discovery()
            .map_err(GroupPlanError::ProviderReach)?;
        let provider_reach = preflight
            .reconcile_exact_target(None)
            .map_err(GroupPlanError::ProviderReach)?
            .reach;
        self.plan_with_reach(reference, target, max_members, mode, provider_reach)
    }

    pub(crate) fn revalidate(
        &self,
        reviewed: &GroupTogglePlan,
    ) -> Result<GroupTogglePlan, GroupPlanError> {
        let mut plan = self.plan_with_operation_id(
            &GroupRef::qualified(
                reviewed.scope,
                reviewed
                    .qualified_name
                    .split_once(':')
                    .map_or(reviewed.qualified_name.as_str(), |(_, name)| name),
            )?,
            reviewed.target,
            reviewed.max_members,
            reviewed.mode,
            reviewed.provider_reach,
            reviewed.operation_id.clone(),
        )?;
        plan.response_id.clone_from(&reviewed.response_id);
        let calculated_fingerprint = calculate_group_fingerprint(&plan)?;
        plan.plan_fingerprint.clone_from(&calculated_fingerprint);
        plan.verify_with_fingerprint(&calculated_fingerprint)?;
        Ok(plan)
    }

    #[must_use]
    pub fn resolver(&self) -> &GroupResolver {
        &self.resolver
    }

    fn plan_with_operation_id(
        &self,
        reference: &GroupRef,
        target: GroupTargetState,
        max_members: usize,
        mode: GroupPlanMode,
        provider_reach: ProviderReach,
        fixed_operation_id: Option<String>,
    ) -> Result<GroupTogglePlan, GroupPlanError> {
        if max_members == 0 || max_members > MAX_GROUP_MEMBERS {
            return Err(GroupPlanError::InvalidMaximum {
                actual: max_members,
                maximum: MAX_GROUP_MEMBERS,
            });
        }
        #[cfg(test)]
        let discovery = match self.discovery_override.as_ref() {
            Some(discovery) => discovery.clone(),
            None => discover_all(self.resolver.context().discovery_roots())
                .map_err(GroupPlanError::Discovery)?,
        };
        #[cfg(not(test))]
        let discovery = discover_all(self.resolver.context().discovery_roots())
            .map_err(GroupPlanError::Discovery)?;
        let record = self.resolver.resolve_definition(reference)?;
        let index = index_discovery(&discovery);
        let view = self.resolver.inspect_record(&record, &index);
        if !view.context_compatible {
            return Err(GroupPlanError::ContextMismatch);
        }
        if view.members.len() > max_members {
            return Err(GroupPlanError::MaximumExceeded {
                actual: view.members.len(),
                maximum: max_members,
            });
        }
        let selected = record
            .definition
            .members
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let source_views = index_source_views(&discovery.items);
        let approval_context = ControlApprovalContext::new(
            self.resolver.context().repository_key(),
            self.resolver.context().workspace_key(),
        )
        .map_err(|error| GroupPlanError::Approval(error.to_string()))?;
        let native = NativeToggleController::new(self.resolver.context().app_state_root());
        let planning_journals = native.planning_journals();
        let requested_enabled = target.enabled();
        let provider_coverage = ProviderReachCoverage::new(
            record
                .definition
                .members
                .iter()
                .map(|identity| {
                    if provider_reach.allows(identity.provider) {
                        ProviderCoverageEntry::included(identity.provider, identity.id.clone())
                    } else {
                        ProviderCoverageEntry::excluded(identity.provider, identity.id.clone())
                    }
                })
                .collect(),
        );
        let mut members = Vec::with_capacity(record.definition.members.len());
        for identity in &record.definition.members {
            if !provider_reach.allows(identity.provider) {
                members.push(GroupMemberPlan {
                    identity: identity.clone(),
                    current_enabled: None,
                    requested_enabled,
                    outcome: GroupMemberPlanOutcome::OutOfProviderReach,
                    reason: Some("out-of-provider-reach".to_string()),
                    item_plan_fingerprint: None,
                    child_operation_id: None,
                    affected_resources: Vec::new(),
                    native_plan: None,
                });
                continue;
            }
            let matches = index.get(identity).map(Vec::as_slice).unwrap_or_default();
            let mut member = match matches {
                [] => blocked_member(
                    identity.clone(),
                    requested_enabled,
                    GroupMemberPlanOutcome::Missing,
                    "missing",
                ),
                [item] if item.enabled == requested_enabled => GroupMemberPlan {
                    identity: identity.clone(),
                    current_enabled: Some(item.enabled),
                    requested_enabled,
                    outcome: GroupMemberPlanOutcome::AlreadyCorrect,
                    reason: None,
                    item_plan_fingerprint: None,
                    child_operation_id: None,
                    affected_resources: Vec::new(),
                    native_plan: None,
                },
                [item] if is_control_plane_protected_disable(item, requested_enabled) => {
                    blocked_member_with_state(
                        identity.clone(),
                        Some(item.enabled),
                        requested_enabled,
                        CONTROL_PLANE_PROTECTED_REASON,
                    )
                }
                [item] => match planning_journals
                    .as_ref()
                    .map_err(ToString::to_string)
                    .and_then(|journals| {
                        native
                            .plan_with_journals((*item).clone(), &approval_context, journals)
                            .map_err(|error| error.public_reason_code().to_string())
                    }) {
                    Ok(plan) => {
                        let item_plan_fingerprint = Some(plan.plan_fingerprint.clone());
                        let child_operation_id = Some(plan.transition.operation_id.clone());
                        GroupMemberPlan {
                            identity: identity.clone(),
                            current_enabled: Some(item.enabled),
                            requested_enabled,
                            outcome: GroupMemberPlanOutcome::Changed,
                            reason: None,
                            item_plan_fingerprint,
                            child_operation_id,
                            affected_resources: Vec::new(),
                            native_plan: Some(plan),
                        }
                    }
                    Err(reason) => blocked_member_with_state(
                        identity.clone(),
                        Some(item.enabled),
                        requested_enabled,
                        &reason,
                    ),
                },
                _ => blocked_member(
                    identity.clone(),
                    requested_enabled,
                    GroupMemberPlanOutcome::Blocked,
                    "ambiguous",
                ),
            };
            if member.outcome == GroupMemberPlanOutcome::Changed
                && shared_source_has_unlisted_view(matches[0], &selected, &source_views)
            {
                member.outcome = GroupMemberPlanOutcome::Blocked;
                member.reason = Some("non-member-fan-out".to_string());
                member.item_plan_fingerprint = None;
                member.child_operation_id = None;
                member.native_plan = None;
            }
            if member.outcome == GroupMemberPlanOutcome::Changed
                && shared_source_crosses_provider_reach(matches[0], &provider_reach, &source_views)
            {
                member.outcome = GroupMemberPlanOutcome::Blocked;
                member.reason = Some("shared-source-crosses-provider-reach".to_string());
                member.item_plan_fingerprint = None;
                member.child_operation_id = None;
                member.native_plan = None;
            }
            members.push(member);
        }

        let resources = reconcile_shared_resource_members(&mut members, &index)?;
        let cohorts = build_cohorts(&members, &resources);
        let actionable = members
            .iter()
            .any(|member| member.outcome == GroupMemberPlanOutcome::Changed);
        let exceptional = members.iter().any(|member| {
            matches!(
                member.outcome,
                GroupMemberPlanOutcome::Blocked | GroupMemberPlanOutcome::Missing
            )
        });
        let included_count = members
            .iter()
            .filter(|member| member.outcome != GroupMemberPlanOutcome::OutOfProviderReach)
            .count();
        let reach_exclusions = provider_coverage
            .excluded()
            .any(ProviderCoverageEntry::is_reach_exclusion);
        let disposition =
            if (!actionable && exceptional) || (included_count == 0 && reach_exclusions) {
                GroupPlanDisposition::Blocked
            } else if !actionable && !reach_exclusions {
                GroupPlanDisposition::NoOp
            } else if mode == GroupPlanMode::PreviewOnly {
                GroupPlanDisposition::Preview
            } else {
                // A selected-provider subset with no writes still needs a durable
                // handoff so the excluded members are reported as `partial` rather
                // than being mistaken for an ordinary no-op.
                GroupPlanDisposition::Actionable
            };
        let response_id = secure_random_identifier("group-response", 16)
            .map_err(|error| GroupPlanError::IdentifierGeneration(error.to_string()))?;
        let operation_id = if disposition == GroupPlanDisposition::Actionable {
            Some(
                fixed_operation_id
                    .unwrap_or(secure_random_identifier("inventory-group", 24).map_err(
                        |error| GroupPlanError::IdentifierGeneration(error.to_string()),
                    )?),
            )
        } else {
            None
        };
        let transition = operation_id
            .as_ref()
            .map(|operation_id| {
                build_parent_transition(
                    operation_id,
                    &resources,
                    self.resolver.context().repository_key(),
                    self.resolver.context().workspace_key(),
                )
            })
            .transpose()?;
        let mut plan = GroupTogglePlan {
            schema_version: GROUP_PLAN_SCHEMA_VERSION,
            response_id,
            operation_id,
            disposition,
            mode,
            qualified_name: record.qualified_name,
            scope: record.scope,
            group_revision: record.revision,
            target,
            max_members,
            total_members: members.len(),
            provider_reach,
            provider_coverage: provider_coverage.clone(),
            lifecycle: planned_reach_lifecycle_parts(&members, &provider_coverage),
            definition_view: view,
            members,
            resources,
            cohorts,
            transition,
            plan_fingerprint: String::new(),
        };
        let calculated_fingerprint = calculate_group_fingerprint(&plan)?;
        plan.plan_fingerprint.clone_from(&calculated_fingerprint);
        plan.verify_with_fingerprint(&calculated_fingerprint)?;
        Ok(plan)
    }
}

fn blocked_member(
    identity: GroupMemberIdentity,
    requested_enabled: bool,
    outcome: GroupMemberPlanOutcome,
    reason: &str,
) -> GroupMemberPlan {
    blocked_member_with_state(identity, None, requested_enabled, reason).with_outcome(outcome)
}

fn blocked_member_with_state(
    identity: GroupMemberIdentity,
    current_enabled: Option<bool>,
    requested_enabled: bool,
    reason: &str,
) -> GroupMemberPlan {
    GroupMemberPlan {
        identity,
        current_enabled,
        requested_enabled,
        outcome: GroupMemberPlanOutcome::Blocked,
        reason: Some(reason.to_string()),
        item_plan_fingerprint: None,
        child_operation_id: None,
        affected_resources: Vec::new(),
        native_plan: None,
    }
}

fn valid_child_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
}

fn valid_cohort_id(value: &str) -> bool {
    value.strip_prefix("group-cohort-").is_some_and(|suffix| {
        suffix.len() == 24
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

impl GroupMemberPlan {
    fn with_outcome(mut self, outcome: GroupMemberPlanOutcome) -> Self {
        self.outcome = outcome;
        self
    }
}

pub(crate) fn index_source_views(
    inventory: &[DiscoveryItem],
) -> BTreeMap<String, BTreeSet<GroupMemberIdentity>> {
    let mut index = BTreeMap::new();
    for item in inventory {
        if let Ok(identity) = GroupMemberIdentity::try_from(item) {
            index
                .entry(item.source_path.clone())
                .or_insert_with(BTreeSet::new)
                .insert(identity);
        }
    }
    index
}

pub(crate) fn shared_source_has_unlisted_view(
    item: &DiscoveryItem,
    selected: &BTreeSet<GroupMemberIdentity>,
    source_views: &BTreeMap<String, BTreeSet<GroupMemberIdentity>>,
) -> bool {
    item.is_shared_skill_source()
        && !item.uses_codex_skill_config_state()
        && source_views
            .get(item.source_path.as_str())
            .is_some_and(|views| views.iter().any(|identity| !selected.contains(identity)))
}

pub(crate) fn shared_source_crosses_provider_reach(
    item: &DiscoveryItem,
    provider_reach: &ProviderReach,
    source_views: &BTreeMap<String, BTreeSet<GroupMemberIdentity>>,
) -> bool {
    item.is_shared_skill_source()
        && !item.uses_codex_skill_config_state()
        && source_views
            .get(item.source_path.as_str())
            .is_some_and(|views| {
                views
                    .iter()
                    .any(|identity| !provider_reach.allows(identity.provider))
            })
}

fn planned_reach_lifecycle(plan: &GroupTogglePlan) -> ProviderReachLifecycle {
    planned_reach_lifecycle_parts(&plan.members, &plan.provider_coverage)
}

fn expected_group_disposition(plan: &GroupTogglePlan) -> GroupPlanDisposition {
    let has_blocker = plan.members.iter().any(|member| {
        matches!(
            member.outcome,
            GroupMemberPlanOutcome::Blocked | GroupMemberPlanOutcome::Missing
        )
    });
    let actionable = plan
        .members
        .iter()
        .any(|member| member.outcome == GroupMemberPlanOutcome::Changed);
    let included_count = plan
        .members
        .iter()
        .filter(|member| member.outcome != GroupMemberPlanOutcome::OutOfProviderReach)
        .count();
    let has_reach_exclusions = plan
        .provider_coverage
        .excluded()
        .any(ProviderCoverageEntry::is_reach_exclusion);
    if (!actionable && has_blocker) || (included_count == 0 && has_reach_exclusions) {
        GroupPlanDisposition::Blocked
    } else if !actionable && !has_reach_exclusions {
        GroupPlanDisposition::NoOp
    } else if plan.mode == GroupPlanMode::PreviewOnly {
        GroupPlanDisposition::Preview
    } else {
        GroupPlanDisposition::Actionable
    }
}

fn planned_reach_lifecycle_parts(
    members: &[GroupMemberPlan],
    coverage: &ProviderReachCoverage,
) -> ProviderReachLifecycle {
    let actionable = members
        .iter()
        .any(|member| member.outcome == GroupMemberPlanOutcome::Changed);
    let exceptional = members.iter().any(|member| {
        matches!(
            member.outcome,
            GroupMemberPlanOutcome::Blocked | GroupMemberPlanOutcome::Missing
        )
    });
    if actionable && exceptional {
        return ProviderReachLifecycle::Partial;
    }
    let included_outcomes = members
        .iter()
        .filter_map(|member| match member.outcome {
            GroupMemberPlanOutcome::Changed => Some(IncludedTargetOutcome::Applied),
            GroupMemberPlanOutcome::AlreadyCorrect => Some(IncludedTargetOutcome::NoOp),
            GroupMemberPlanOutcome::Blocked | GroupMemberPlanOutcome::Missing => {
                Some(IncludedTargetOutcome::Blocked)
            }
            GroupMemberPlanOutcome::OutOfProviderReach => None,
        })
        .collect();
    classify_lifecycle(&crate::provider_reach::LifecycleEvidence {
        included_outcomes,
        coverage: coverage.clone(),
        writes_started: false,
    })
}

const BLOCKED_MEMBER_SHARED_RESOURCE_REASON: &str = "blocked-member-shared-resource";

#[derive(Debug)]
struct SharedResourceAssociation {
    resource_id: String,
    member_index: usize,
    provider: ProviderId,
    proof: GroupPreservedMemberProof,
}

fn reconcile_shared_resource_members(
    members: &mut [GroupMemberPlan],
    index: &GroupDiscoveryIndex<'_>,
) -> Result<Vec<GroupResourcePlan>, GroupPlanError> {
    loop {
        let mut resources = build_resources(members)?;
        let (associations, unsafe_resources) =
            classify_blocked_shared_resources(members, &resources, index);
        if unsafe_resources.is_empty() {
            attach_preserved_members(members, &mut resources, associations);
            refresh_resource_fingerprints(&mut resources, members)?;
            return Ok(resources);
        }

        let blocked_component_members = connected_actionable_members(&resources, &unsafe_resources);
        if blocked_component_members.is_empty() {
            return Err(GroupPlanError::InvalidPlan);
        }
        for member_index in blocked_component_members {
            let member = &mut members[member_index];
            member.outcome = GroupMemberPlanOutcome::Blocked;
            member.reason = Some(BLOCKED_MEMBER_SHARED_RESOURCE_REASON.to_string());
            member.item_plan_fingerprint = None;
            member.child_operation_id = None;
            member.affected_resources.clear();
            member.native_plan = None;
        }
    }
}

fn classify_blocked_shared_resources(
    members: &[GroupMemberPlan],
    resources: &[GroupResourcePlan],
    index: &GroupDiscoveryIndex<'_>,
) -> (Vec<SharedResourceAssociation>, BTreeSet<String>) {
    let mut associations = BTreeMap::new();
    let mut unsafe_resources = BTreeSet::new();
    for (blocked_index, blocked_member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.outcome == GroupMemberPlanOutcome::Blocked)
    {
        let matches = index
            .get(&blocked_member.identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for resource in resources {
            for actionable_index in &resource.member_indices {
                let Some(native) = members[*actionable_index].native_plan.as_ref() else {
                    continue;
                };
                for target in native.preview.affected_targets.iter().filter(|target| {
                    group_resource_id(&target.target_type, &target.path) == resource.resource_id
                }) {
                    let sharing = matches
                        .iter()
                        .copied()
                        .filter(|item| item_shares_mutation_target(item, target))
                        .collect::<Vec<_>>();
                    if sharing.is_empty() {
                        continue;
                    }
                    let safe_item = (matches.len() == 1 && sharing.len() == 1)
                        .then_some(sharing[0])
                        .filter(|blocked_item| {
                            composition_preserves_blocked_member(
                                blocked_member,
                                blocked_item,
                                &native.preview.selection,
                                target,
                            )
                        });
                    let Some(blocked_item) = safe_item else {
                        unsafe_resources.insert(resource.resource_id.clone());
                        continue;
                    };
                    associations.insert(
                        (resource.resource_id.clone(), blocked_index),
                        SharedResourceAssociation {
                            resource_id: resource.resource_id.clone(),
                            member_index: blocked_index,
                            provider: blocked_item.provider,
                            proof: GroupPreservedMemberProof {
                                member_index: blocked_index,
                                source_fingerprint: blocked_item
                                    .source_fingerprint
                                    .clone()
                                    .expect("composition proof requires a source fingerprint"),
                                current_enabled: blocked_item.enabled,
                            },
                        },
                    );
                }
            }
        }
    }
    associations.retain(|(resource_id, _), _| !unsafe_resources.contains(resource_id));
    (associations.into_values().collect(), unsafe_resources)
}

fn item_shares_mutation_target(
    item: &DiscoveryItem,
    target: &crate::mutation::MutationTarget,
) -> bool {
    item.state_path == target.path || item.source_path == target.path
}

fn composition_preserves_blocked_member(
    blocked_member: &GroupMemberPlan,
    blocked_item: &DiscoveryItem,
    actionable_item: &DiscoveryItem,
    target: &crate::mutation::MutationTarget,
) -> bool {
    blocked_member.reason.as_deref() == Some(CONTROL_PLANE_PROTECTED_REASON)
        && blocked_item.source_fingerprint.is_some()
        && blocked_item.provider == ProviderId::Codex
        && blocked_item.category == DiscoveryCategory::ConfiguredMcp
        && actionable_item.uses_codex_skill_config_state()
        && target.target_type == "statePath"
        && actionable_item.state_path == target.path
        && blocked_item.state_path == target.path
}

fn connected_actionable_members(
    resources: &[GroupResourcePlan],
    unsafe_resources: &BTreeSet<String>,
) -> BTreeSet<usize> {
    let mut connected = resources
        .iter()
        .filter(|resource| unsafe_resources.contains(&resource.resource_id))
        .flat_map(|resource| resource.member_indices.iter().copied())
        .collect::<BTreeSet<_>>();
    loop {
        let before = connected.len();
        for resource in resources {
            if resource
                .member_indices
                .iter()
                .any(|member_index| connected.contains(member_index))
            {
                connected.extend(resource.member_indices.iter().copied());
            }
        }
        if connected.len() == before {
            return connected;
        }
    }
}

fn attach_preserved_members(
    members: &mut [GroupMemberPlan],
    resources: &mut [GroupResourcePlan],
    associations: Vec<SharedResourceAssociation>,
) {
    for association in associations {
        let resource = resources
            .iter_mut()
            .find(|resource| resource.resource_id == association.resource_id)
            .expect("association references a planned resource");
        resource.member_indices.push(association.member_index);
        resource.member_indices.sort_unstable();
        resource.member_indices.dedup();
        resource.provider_views.push(association.provider);
        resource.provider_views.sort_unstable();
        resource.provider_views.dedup();
        resource.preserved_members.push(association.proof);
        resource
            .preserved_members
            .sort_by_key(|proof| proof.member_index);
        resource
            .preserved_members
            .dedup_by_key(|proof| proof.member_index);
        members[association.member_index]
            .affected_resources
            .push(resource.resource_id.clone());
        members[association.member_index].affected_resources.sort();
        members[association.member_index].affected_resources.dedup();
    }
}

fn refresh_resource_fingerprints(
    resources: &mut [GroupResourcePlan],
    members: &[GroupMemberPlan],
) -> Result<(), GroupPlanError> {
    for resource in resources {
        if resource.preserved_members.is_empty() {
            continue;
        }
        let mut plans = resource
            .member_indices
            .iter()
            .filter_map(|member_index| {
                members[*member_index]
                    .native_plan
                    .as_ref()
                    .map(|native| native.plan_fingerprint.clone())
            })
            .collect::<Vec<_>>();
        plans.sort();
        let encoded = serde_json::to_vec(&(plans, &resource.preserved_members))
            .map_err(|error| GroupPlanError::Serialization(error.to_string()))?;
        resource.expected_pre_fingerprint = encode_lower_hex(&Sha256::digest(
            [b"group-resource-pre-v1\0".as_slice(), encoded.as_slice()].concat(),
        ));
        resource.expected_post_fingerprint = encode_lower_hex(&Sha256::digest(
            [b"group-resource-post-v1\0".as_slice(), encoded.as_slice()].concat(),
        ));
    }
    Ok(())
}

fn build_resources(
    members: &mut [GroupMemberPlan],
) -> Result<Vec<GroupResourcePlan>, GroupPlanError> {
    #[derive(Default)]
    struct ResourceAccumulator {
        target_type: String,
        member_indices: BTreeSet<usize>,
        providers: BTreeSet<ProviderId>,
        plans: Vec<String>,
        activation: Option<EffectActivation>,
    }
    let mut resources = BTreeMap::<String, ResourceAccumulator>::new();
    for member in members.iter_mut() {
        member.affected_resources.clear();
    }
    for (member_index, member) in members.iter_mut().enumerate() {
        let Some(native) = member.native_plan.as_ref() else {
            continue;
        };
        let mut member_resources = Vec::new();
        for target in &native.preview.affected_targets {
            let resource_id = group_resource_id(&target.target_type, &target.path);
            member_resources.push(resource_id.clone());
            let entry = resources.entry(resource_id).or_default();
            entry.target_type.clone_from(&target.target_type);
            entry.member_indices.insert(member_index);
            entry.providers.insert(member.identity.provider);
            entry.plans.push(native.plan_fingerprint.clone());
            for effect in &native.transition.effects {
                entry.activation = Some(max_activation(entry.activation, effect.activation));
            }
        }
        member_resources.sort();
        member_resources.dedup();
        member.affected_resources = member_resources;
    }
    resources
        .into_iter()
        .map(|(resource_id, mut entry)| {
            entry.plans.sort();
            let encoded = serde_json::to_vec(&entry.plans)
                .map_err(|error| GroupPlanError::Serialization(error.to_string()))?;
            let expected_pre_fingerprint = encode_lower_hex(&Sha256::digest(
                [b"group-resource-pre-v1\0".as_slice(), encoded.as_slice()].concat(),
            ));
            let expected_post_fingerprint = encode_lower_hex(&Sha256::digest(
                [b"group-resource-post-v1\0".as_slice(), encoded.as_slice()].concat(),
            ));
            Ok(GroupResourcePlan {
                resource_id,
                target_type: entry.target_type,
                member_indices: entry.member_indices.into_iter().collect(),
                preserved_members: Vec::new(),
                expected_pre_fingerprint,
                expected_post_fingerprint,
                provider_views: entry.providers.into_iter().collect(),
                activation: entry
                    .activation
                    .unwrap_or(EffectActivation::RestartRequired),
            })
        })
        .collect()
}

fn group_resource_id(target_type: &str, path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-group-resource-v1\0");
    hasher.update(target_type.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    format!(
        "group-resource-{}",
        &encode_lower_hex(&hasher.finalize())[..32]
    )
}

fn max_activation(current: Option<EffectActivation>, next: EffectActivation) -> EffectActivation {
    current.map_or(next, |current| current.max(next))
}

fn build_cohorts(
    members: &[GroupMemberPlan],
    resources: &[GroupResourcePlan],
) -> Vec<GroupExecutionCohort> {
    let actionable = members
        .iter()
        .enumerate()
        .filter_map(|(index, member)| {
            (member.outcome == GroupMemberPlanOutcome::Changed).then_some(index)
        })
        .collect::<BTreeSet<_>>();
    let mut remaining = actionable.clone();
    let mut cohorts = Vec::new();
    while let Some(start) = remaining.iter().next().copied() {
        let mut queue = VecDeque::from([start]);
        let mut component_members = BTreeSet::new();
        let mut component_resources = BTreeSet::new();
        while let Some(member_index) = queue.pop_front() {
            if !component_members.insert(member_index) {
                continue;
            }
            remaining.remove(&member_index);
            for resource in resources
                .iter()
                .filter(|resource| resource.member_indices.contains(&member_index))
            {
                if component_resources.insert(resource.resource_id.clone()) {
                    for adjacent in &resource.member_indices {
                        if !component_members.contains(adjacent) {
                            queue.push_back(*adjacent);
                        }
                    }
                }
            }
        }
        let resource_ids = component_resources.into_iter().collect::<Vec<_>>();
        let digest = encode_lower_hex(&Sha256::digest(
            serde_json::to_vec(&(component_members.clone(), &resource_ids))
                .expect("cohort components serialize"),
        ));
        cohorts.push(GroupExecutionCohort {
            cohort_id: format!("group-cohort-{}", &digest[..24]),
            member_indices: component_members.into_iter().collect(),
            resource_ids,
        });
    }
    cohorts.sort_by(|left, right| left.cohort_id.cmp(&right.cohort_id));
    cohorts
}

fn build_parent_transition(
    operation_id: &str,
    resources: &[GroupResourcePlan],
    repository_key: &str,
    workspace_key: &str,
) -> Result<TransitionPlan, TransitionPlanError> {
    let effects = if resources.is_empty() {
        // TransitionPlan requires at least one effect. For an actionable
        // selected-provider plan whose included members are already correct,
        // retain a deterministic terminal selection effect so the reviewed
        // partial outcome has a durable operation/journal without inventing a
        // provider write target.
        let pre_fingerprint = encode_lower_hex(&Sha256::digest(
            format!("inventory-group-terminal-pre\0{operation_id}").as_bytes(),
        ));
        let post_fingerprint = encode_lower_hex(&Sha256::digest(
            format!("inventory-group-terminal-post\0{operation_id}").as_bytes(),
        ));
        let resource_digest = encode_lower_hex(&Sha256::digest(
            format!("inventory-group-terminal-resource\0{operation_id}").as_bytes(),
        ));
        vec![TransitionEffect {
            effect_id: "inventory-group-selection-effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: format!("inventory-group-selection-{}", &resource_digest[..24]),
            target_type: "inventory-group-selection".to_string(),
            summary: "Record one reviewed inventory group selection".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some(pre_fingerprint),
            expected_post_fingerprint: Some(post_fingerprint),
            provider_views: Vec::new(),
        }]
    } else {
        resources
            .iter()
            .map(|resource| TransitionEffect {
                effect_id: resource.resource_id.replace("resource", "effect"),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: resource.resource_id.clone(),
                target_type: resource.target_type.clone(),
                summary: "Apply reviewed inventory group resource cohort".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: resource.activation,
                expected_pre_fingerprint: Some(resource.expected_pre_fingerprint.clone()),
                expected_post_fingerprint: Some(resource.expected_post_fingerprint.clone()),
                provider_views: resource.provider_views.clone(),
            })
            .collect()
    };
    TransitionPlan::new(
        operation_id,
        TransitionKind::InventoryGroupApply,
        TransitionContext {
            repository_key: repository_key.to_string(),
            workspace_key: workspace_key.to_string(),
            session_id: None,
            profile_digest: None,
        },
        effects,
    )
}

fn calculate_group_fingerprint(plan: &GroupTogglePlan) -> Result<String, GroupPlanError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        response_id: &'a str,
        operation_id: &'a Option<String>,
        disposition: GroupPlanDisposition,
        mode: GroupPlanMode,
        qualified_name: &'a str,
        scope: GroupScope,
        group_revision: &'a GroupRevision,
        target: GroupTargetState,
        max_members: usize,
        total_members: usize,
        provider_reach: ProviderReach,
        provider_coverage: &'a ProviderReachCoverage,
        lifecycle: ProviderReachLifecycle,
        definition_view: &'a GroupDefinitionView,
        members: &'a [GroupMemberPlan],
        resources: &'a [GroupResourcePlan],
        cohorts: &'a [GroupExecutionCohort],
        transition: &'a Option<TransitionPlan>,
    }
    let bytes = serde_json::to_vec(&FingerprintBody {
        schema_version: plan.schema_version,
        response_id: &plan.response_id,
        operation_id: &plan.operation_id,
        disposition: plan.disposition,
        mode: plan.mode,
        qualified_name: &plan.qualified_name,
        scope: plan.scope,
        group_revision: &plan.group_revision,
        target: plan.target,
        max_members: plan.max_members,
        total_members: plan.total_members,
        provider_reach: plan.provider_reach,
        provider_coverage: &plan.provider_coverage,
        lifecycle: plan.lifecycle,
        definition_view: &plan.definition_view,
        members: &plan.members,
        resources: &plan.resources,
        cohorts: &plan.cohorts,
        transition: &plan.transition,
    })
    .map_err(|error| GroupPlanError::Serialization(error.to_string()))?;
    Ok(encode_lower_hex(&Sha256::digest(bytes)))
}

#[derive(Debug)]
pub enum GroupPlanError {
    Resolve(GroupResolveError),
    Discovery(crate::discovery::DiscoveryError),
    ProviderReach(ProviderReachError),
    Transition(TransitionPlanError),
    Validation(crate::groups::GroupValidationError),
    Approval(String),
    InvalidMaximum { actual: usize, maximum: usize },
    MaximumExceeded { actual: usize, maximum: usize },
    ContextMismatch,
    NotActionable,
    InvalidPlan,
    FingerprintMismatch,
    Serialization(String),
    IdentifierGeneration(String),
}

impl From<GroupSessionError> for GroupPlanError {
    fn from(error: GroupSessionError) -> Self {
        Self::IdentifierGeneration(error.to_string())
    }
}

impl From<GroupResolveError> for GroupPlanError {
    fn from(error: GroupResolveError) -> Self {
        Self::Resolve(error)
    }
}

impl From<ProviderReachError> for GroupPlanError {
    fn from(error: ProviderReachError) -> Self {
        Self::ProviderReach(error)
    }
}

impl From<TransitionPlanError> for GroupPlanError {
    fn from(error: TransitionPlanError) -> Self {
        Self::Transition(error)
    }
}

impl From<crate::groups::GroupValidationError> for GroupPlanError {
    fn from(error: crate::groups::GroupValidationError) -> Self {
        Self::Validation(error)
    }
}

impl fmt::Display for GroupPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(error) => error.fmt(formatter),
            Self::Discovery(error) => write!(formatter, "group discovery failed: {error}"),
            Self::ProviderReach(error) => error.fmt(formatter),
            Self::Transition(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::Approval(error) => write!(formatter, "group approval context failed: {error}"),
            Self::InvalidMaximum { actual, maximum } => {
                write!(
                    formatter,
                    "invalid maxMembers {actual}; maximum is {maximum}"
                )
            }
            Self::MaximumExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "group has {actual} members; maxMembers is {maximum}"
                )
            }
            Self::ContextMismatch => {
                formatter.write_str("group is outside the trusted access context")
            }
            Self::NotActionable => formatter.write_str("group plan is not actionable"),
            Self::InvalidPlan => formatter.write_str("group plan is invalid"),
            Self::FingerprintMismatch => formatter.write_str("group plan fingerprint mismatch"),
            Self::Serialization(error) => write!(formatter, "group plan JSON failed: {error}"),
            Self::IdentifierGeneration(error) => {
                write!(formatter, "group operation id generation failed: {error}")
            }
        }
    }
}

impl std::error::Error for GroupPlanError {}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        config::{UnpinConfig, UnpinConfigPaths},
        discovery::{
            DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryMutability, DiscoveryOutput,
            DiscoveryRoots,
        },
        groups::{GroupAccessContext, GroupDefinitionV1, PersonalGroupStore, RepositoryGroupStore},
        state::atomic_json::OwnerGeneration,
    };

    fn context(root: &TempDir) -> GroupAccessContext {
        let workspace = root.path().join("workspace");
        let app_state = root.path().join("state");
        fs::create_dir_all(workspace.join(".git")).expect("workspace");
        fs::create_dir_all(&app_state).expect("app state");
        let config = UnpinConfig {
            version: 1,
            app_state_root: app_state,
            cursor_root: root.path().join("cursor"),
            project_root: workspace,
            config_paths: UnpinConfigPaths {
                user_config_path: root.path().join("user.json"),
                project_config_path: root.path().join("project.json"),
            },
        };
        let roots =
            DiscoveryRoots::fixture_root(root.path()).with_app_state_root(&config.app_state_root);
        GroupAccessContext::from_config(&config, &roots, None, None).expect("group context")
    }

    fn identity(id: &str, kind: DiscoveryKind, category: DiscoveryCategory) -> GroupMemberIdentity {
        GroupMemberIdentity::new(
            ProviderId::Codex,
            kind,
            category,
            DiscoveryLayer::Global,
            id,
        )
        .expect("member identity")
    }

    fn item(identity: &GroupMemberIdentity, display_name: &str) -> DiscoveryItem {
        DiscoveryItem {
            provider: identity.provider,
            kind: identity.kind,
            category: identity.category,
            layer: identity.layer,
            id: identity.id.clone(),
            display_name: display_name.to_string(),
            enabled: true,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: "/fixture/source".to_string(),
            state_path: "/fixture/state".to_string(),
            source_fingerprint: Some("fixture".to_string()),
            hook: None,
        }
    }

    #[test]
    fn planner_blocks_missing_ambiguous_and_protected_members_and_enforces_maximum() {
        let root = TempDir::new().expect("tempdir");
        let context = context(&root);
        let personal = PersonalGroupStore::new(context.clone());
        let repository = RepositoryGroupStore::new(context.clone());
        let missing = identity(
            "codex:global:skill:missing",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let ambiguous = identity(
            "codex:global:skill:ambiguous",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let protected = identity(
            "codex:global:mcp:unpin",
            DiscoveryKind::Mcp,
            DiscoveryCategory::ConfiguredMcp,
        );
        for (generation, (name, members)) in [
            ("missing", vec![missing.clone()]),
            ("ambiguous", vec![ambiguous.clone()]),
            ("protected", vec![protected.clone()]),
            ("maximum", vec![missing.clone(), ambiguous.clone()]),
        ]
        .into_iter()
        .enumerate()
        {
            personal
                .create(
                    &GroupDefinitionV1::new(name, members).expect("definition"),
                    OwnerGeneration::new("group-planner-test", generation as u64 + 1)
                        .expect("owner"),
                )
                .expect("create group");
        }
        let planner = GroupPlanner::new(GroupResolver::new(context, personal, repository));

        let missing_plan = planner
            .clone()
            .with_discovery_override(DiscoveryOutput::default())
            .plan(
                &GroupRef::qualified(GroupScope::Personal, "missing").expect("reference"),
                GroupTargetState::Disable,
                4,
                GroupPlanMode::TuiDirect,
            )
            .expect("missing plan");
        assert_eq!(missing_plan.disposition, GroupPlanDisposition::Blocked);
        assert_eq!(
            missing_plan.members[0].outcome,
            GroupMemberPlanOutcome::Missing
        );
        assert_eq!(missing_plan.members[0].reason.as_deref(), Some("missing"));
        assert!(missing_plan.members[0].item_plan_fingerprint.is_none());
        assert!(missing_plan.members[0].child_operation_id.is_none());

        let ambiguous_item = item(&ambiguous, "ambiguous");
        let ambiguous_plan = planner
            .clone()
            .with_discovery_override(DiscoveryOutput {
                items: vec![ambiguous_item.clone(), ambiguous_item],
                warnings: Vec::new(),
            })
            .plan(
                &GroupRef::qualified(GroupScope::Personal, "ambiguous").expect("reference"),
                GroupTargetState::Disable,
                4,
                GroupPlanMode::TuiDirect,
            )
            .expect("ambiguous plan");
        assert_eq!(ambiguous_plan.disposition, GroupPlanDisposition::Blocked);
        assert_eq!(
            ambiguous_plan.members[0].outcome,
            GroupMemberPlanOutcome::Blocked
        );
        assert_eq!(
            ambiguous_plan.members[0].reason.as_deref(),
            Some("ambiguous")
        );

        let protected_plan = planner
            .clone()
            .with_discovery_override(DiscoveryOutput {
                items: vec![item(&protected, "unpin")],
                warnings: Vec::new(),
            })
            .plan(
                &GroupRef::qualified(GroupScope::Personal, "protected").expect("reference"),
                GroupTargetState::Disable,
                4,
                GroupPlanMode::TuiDirect,
            )
            .expect("protected plan");
        assert_eq!(protected_plan.disposition, GroupPlanDisposition::Blocked);
        assert_eq!(
            protected_plan.members[0].reason.as_deref(),
            Some(CONTROL_PLANE_PROTECTED_REASON)
        );

        let maximum_error = planner
            .with_discovery_override(DiscoveryOutput::default())
            .plan(
                &GroupRef::qualified(GroupScope::Personal, "maximum").expect("reference"),
                GroupTargetState::Disable,
                1,
                GroupPlanMode::TuiDirect,
            )
            .expect_err("maximum must be enforced");
        assert!(matches!(
            maximum_error,
            GroupPlanError::MaximumExceeded {
                actual: 2,
                maximum: 1
            }
        ));
    }

    #[test]
    fn shared_source_guard_detects_unlisted_inventory_view() {
        let listed = identity(
            "codex:global:skill:listed",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let unlisted = identity(
            "codex:global:skill:unlisted",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let mut listed_item = item(&listed, "listed");
        listed_item.provider = ProviderId::Claude;
        let mut unlisted_item = item(&unlisted, "unlisted");
        unlisted_item.provider = ProviderId::Claude;
        unlisted_item
            .source_path
            .clone_from(&listed_item.source_path);
        let inventory = vec![listed_item.clone(), unlisted_item];
        let source_views = index_source_views(&inventory);

        assert!(shared_source_has_unlisted_view(
            &listed_item,
            &BTreeSet::from(
                [GroupMemberIdentity::try_from(&listed_item).expect("listed identity")]
            ),
            &source_views,
        ));

        listed_item.provider = ProviderId::Codex;
        listed_item.id = "codex:global:skill:listed".to_string();
        listed_item.source_path = "/fixture/.agents/skills/listed/SKILL.md".to_string();
        listed_item.state_path = "/fixture/.codex/config.toml".to_string();
        let mut other_provider_item = listed_item.clone();
        other_provider_item.provider = ProviderId::Cursor;
        other_provider_item.id = "cursor:global:skill:@compat/agents/listed".to_string();
        let inventory = vec![listed_item.clone(), other_provider_item];
        let source_views = index_source_views(&inventory);

        assert!(!shared_source_has_unlisted_view(
            &listed_item,
            &BTreeSet::from([GroupMemberIdentity::try_from(&listed_item).expect("Codex identity")]),
            &source_views,
        ));
    }

    #[test]
    fn selected_provider_plans_subset_and_binds_reach_coverage() {
        let root = TempDir::new().expect("tempdir");
        let context = context(&root);
        let personal = PersonalGroupStore::new(context.clone());
        let repository = RepositoryGroupStore::new(context.clone());
        let codex = identity(
            "codex:global:skill:codex-only",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let zed = GroupMemberIdentity::new(
            ProviderId::Zed,
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Global,
            "zed:global:skill:zed-only",
        )
        .expect("zed identity");
        personal
            .create(
                &GroupDefinitionV1::new("mixed", vec![codex.clone(), zed.clone()])
                    .expect("definition"),
                OwnerGeneration::new("group-planner-test", 1).expect("owner"),
            )
            .expect("create group");
        let mut codex_item = item(&codex, "codex");
        codex_item.enabled = false;
        codex_item.source_path = "/fixture/.agents/skills/codex-only/SKILL.md".to_string();
        let mut zed_item = item(&zed, "zed");
        zed_item.provider = ProviderId::Zed;
        zed_item.source_path = "/fixture/.agents/skills/zed-only/SKILL.md".to_string();
        let planner = GroupPlanner::new(GroupResolver::new(context, personal, repository))
            .with_discovery_override(DiscoveryOutput {
                items: vec![codex_item, zed_item],
                warnings: Vec::new(),
            });

        let plan = planner
            .plan_with_reach(
                &GroupRef::qualified(GroupScope::Personal, "mixed").expect("reference"),
                GroupTargetState::Disable,
                4,
                GroupPlanMode::TuiDirect,
                ProviderReach::selected(
                    ProviderId::Codex,
                    crate::provider_reach::SelectedProviderProvenance::ExplicitInput,
                ),
            )
            .expect("selected-provider plan");
        assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
        assert_eq!(plan.members.len(), 2);
        assert_eq!(plan.total_members, 2);
        assert_eq!(
            plan.members[0].outcome,
            GroupMemberPlanOutcome::AlreadyCorrect
        );
        assert_eq!(
            plan.members[1].outcome,
            GroupMemberPlanOutcome::OutOfProviderReach
        );
        assert_eq!(plan.members[1].current_enabled, None);
        assert_eq!(
            plan.members[1].reason.as_deref(),
            Some("out-of-provider-reach")
        );
        assert_eq!(plan.provider_coverage.entries().len(), 2);
        assert_eq!(plan.provider_coverage.excluded().count(), 1);
        assert_eq!(plan.lifecycle, ProviderReachLifecycle::Partial);
        plan.verify().expect("reach-bound plan verifies");
    }

    #[test]
    fn all_members_outside_selected_provider_are_blocked_without_native_planning() {
        let root = TempDir::new().expect("tempdir");
        let context = context(&root);
        let personal = PersonalGroupStore::new(context.clone());
        let repository = RepositoryGroupStore::new(context.clone());
        let zed = GroupMemberIdentity::new(
            ProviderId::Zed,
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Global,
            "zed:global:skill:zed-only",
        )
        .expect("zed identity");
        personal
            .create(
                &GroupDefinitionV1::new("zed-only", vec![zed.clone()]).expect("definition"),
                OwnerGeneration::new("group-planner-test", 1).expect("owner"),
            )
            .expect("create group");
        let planner = GroupPlanner::new(GroupResolver::new(context, personal, repository))
            .with_discovery_override(DiscoveryOutput::default());
        let plan = planner
            .plan_with_reach(
                &GroupRef::qualified(GroupScope::Personal, "zed-only").expect("reference"),
                GroupTargetState::Disable,
                4,
                GroupPlanMode::TuiDirect,
                ProviderReach::selected(
                    ProviderId::Codex,
                    crate::provider_reach::SelectedProviderProvenance::ExplicitInput,
                ),
            )
            .expect("all-excluded plan");
        assert_eq!(plan.disposition, GroupPlanDisposition::Blocked);
        assert_eq!(
            plan.lifecycle,
            ProviderReachLifecycle::NoTargetsInProviderReach
        );
        assert_eq!(
            plan.members[0].outcome,
            GroupMemberPlanOutcome::OutOfProviderReach
        );
        assert!(plan.members[0].native_plan.is_none());
        plan.verify().expect("all-excluded plan verifies");
    }

    #[test]
    fn shared_source_crossing_excluded_provider_is_blocked() {
        let listed = identity(
            "codex:global:skill:listed",
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
        );
        let mut listed_item = item(&listed, "listed");
        listed_item.source_path = "/fixture/.agents/skills/shared/SKILL.md".to_string();
        let mut excluded = listed_item.clone();
        excluded.provider = ProviderId::Zed;
        excluded.id = "zed:global:skill:shared".to_string();
        let source_views = index_source_views(&[listed_item.clone(), excluded]);
        assert!(shared_source_crosses_provider_reach(
            &listed_item,
            &ProviderReach::selected(
                ProviderId::Codex,
                crate::provider_reach::SelectedProviderProvenance::ExplicitInput,
            ),
            &source_views,
        ));
    }
}
