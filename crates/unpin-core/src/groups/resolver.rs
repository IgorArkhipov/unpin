use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    discovery::{
        DiscoveryError, DiscoveryItem, DiscoveryMutability, DiscoveryOutput, ProviderId,
        discover_all,
    },
    groups::{
        GroupAccessContext, GroupMemberIdentity, GroupRecord, GroupRef, GroupRevision, GroupScope,
        GroupStoreError, PersonalGroupStore, RepositoryGroupStore,
    },
    mutation::{CONTROL_PLANE_PROTECTED_REASON, TogglePlanRequest, ToggleStatus, plan_toggle},
};

pub(crate) type GroupDiscoveryIndex<'a> = BTreeMap<GroupMemberIdentity, Vec<&'a DiscoveryItem>>;

pub fn validate_new_group_members(
    context: &GroupAccessContext,
    definition: &crate::groups::GroupDefinitionV1,
    retained: &BTreeSet<GroupMemberIdentity>,
) -> Result<(), GroupMemberValidationError> {
    let discovery =
        discover_all(context.discovery_roots()).map_err(GroupMemberValidationError::Discovery)?;
    let index = index_discovery(&discovery);
    for identity in &definition.members {
        if retained.contains(identity) {
            continue;
        }
        let matches = index.get(identity).map(Vec::as_slice).unwrap_or_default();
        let [item] = matches else {
            return Err(GroupMemberValidationError::NotUniquelyDiscoverable(
                identity.clone(),
            ));
        };
        let (eligible, reason) = toggle_eligibility(context, item);
        if !eligible {
            return Err(GroupMemberValidationError::NotIndividuallyToggleable {
                identity: identity.clone(),
                reason: reason.unwrap_or(GroupMemberReason::Unsupported),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct GroupResolver {
    context: GroupAccessContext,
    personal: PersonalGroupStore,
    repository: RepositoryGroupStore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupListWarning {
    pub scope: GroupScope,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct GroupListing {
    pub records: Vec<GroupRecord>,
    pub views: Vec<GroupDefinitionView>,
    pub warnings: Vec<GroupListWarning>,
}

pub(crate) struct GroupMemberObservation {
    pub state: GroupState,
    pub fresh: bool,
}

struct ResolvedGroupMembers {
    members: Vec<GroupMemberView>,
    counts: GroupStateCounts,
    providers: BTreeSet<ProviderId>,
    state: GroupState,
}

impl GroupResolver {
    #[must_use]
    pub fn new(
        context: GroupAccessContext,
        personal: PersonalGroupStore,
        repository: RepositoryGroupStore,
    ) -> Self {
        Self {
            context,
            personal,
            repository,
        }
    }

    pub fn list_definitions(&self) -> Result<Vec<GroupRecord>, GroupResolveError> {
        let mut records = self.personal.list()?;
        records.extend(self.repository.list()?);
        records.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
        Ok(records)
    }

    pub fn list_views(
        &self,
        discovery: &DiscoveryOutput,
    ) -> Result<Vec<GroupDefinitionView>, GroupResolveError> {
        self.list_records_and_views(discovery)
            .map(|(_, views)| views)
    }

    pub fn list_views_with_warnings(
        &self,
        discovery: &DiscoveryOutput,
    ) -> Result<(Vec<GroupDefinitionView>, Vec<GroupListWarning>), GroupResolveError> {
        self.list_records_and_views_with_warnings(discovery)
            .map(|listing| (listing.views, listing.warnings))
    }

    pub fn list_records_and_views(
        &self,
        discovery: &DiscoveryOutput,
    ) -> Result<(Vec<GroupRecord>, Vec<GroupDefinitionView>), GroupResolveError> {
        let index = index_discovery(discovery);
        self.list_definitions().map(|records| {
            let mut eligibility = BTreeMap::new();
            let views = records
                .iter()
                .map(|record| {
                    mark_view_stale_for_warnings(
                        self.inspect_record_with_cache(record, &index, &mut eligibility),
                        discovery,
                    )
                })
                .collect();
            (records, views)
        })
    }

    pub fn list_records_and_views_with_warnings(
        &self,
        discovery: &DiscoveryOutput,
    ) -> Result<GroupListing, GroupResolveError> {
        let index = index_discovery(discovery);
        let mut records = self.personal.list()?;
        let mut warnings = Vec::new();
        match self.repository.list() {
            Ok(repository) => records.extend(repository),
            Err(error) => warnings.push(GroupListWarning {
                scope: GroupScope::Repository,
                code: "repository-groups-unavailable".to_string(),
                message: error.to_string(),
            }),
        }
        records.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
        let mut eligibility = BTreeMap::new();
        let views = records
            .iter()
            .map(|record| {
                mark_view_stale_for_warnings(
                    self.inspect_record_with_cache(record, &index, &mut eligibility),
                    discovery,
                )
            })
            .collect();
        Ok(GroupListing {
            records,
            views,
            warnings,
        })
    }

    pub fn resolve_definition(
        &self,
        reference: &GroupRef,
    ) -> Result<GroupRecord, GroupResolveError> {
        if let Some(scope) = reference.scope {
            return self
                .load_scope(scope, &reference.name)?
                .ok_or_else(|| GroupResolveError::NotFound(reference.name.clone()));
        }
        let mut matches = Vec::new();
        if let Some(record) = self.personal.load(&reference.name).map_err(|source| {
            GroupResolveError::ScopeUnavailable {
                scope: GroupScope::Personal,
                source,
            }
        })? {
            matches.push(record);
        }
        if let Some(record) = self.repository.load(&reference.name).map_err(|source| {
            GroupResolveError::ScopeUnavailable {
                scope: GroupScope::Repository,
                source,
            }
        })? {
            matches.push(record);
        }
        match matches.len() {
            0 => Err(GroupResolveError::NotFound(reference.name.clone())),
            1 => Ok(matches.remove(0)),
            _ => Err(GroupResolveError::Ambiguous {
                name: reference.name.clone(),
                candidates: matches
                    .into_iter()
                    .map(|record| record.qualified_name)
                    .collect(),
            }),
        }
    }

    pub fn inspect(
        &self,
        reference: &GroupRef,
        discovery: &DiscoveryOutput,
    ) -> Result<GroupDefinitionView, GroupResolveError> {
        let record = self.resolve_definition(reference)?;
        let index = index_discovery(discovery);
        Ok(mark_view_stale_for_warnings(
            self.inspect_record(&record, &index),
            discovery,
        ))
    }

    pub(crate) fn inspect_record(
        &self,
        record: &GroupRecord,
        index: &GroupDiscoveryIndex<'_>,
    ) -> GroupDefinitionView {
        self.inspect_record_with_cache(record, index, &mut BTreeMap::new())
    }

    pub(crate) fn observe_members(
        &self,
        identities: &[GroupMemberIdentity],
        discovery: &DiscoveryOutput,
    ) -> GroupMemberObservation {
        if identities
            .iter()
            .any(|identity| !self.context.admits_layer(identity))
        {
            return GroupMemberObservation {
                state: GroupState::Mixed,
                fresh: false,
            };
        }
        let index = index_discovery(discovery);
        let resolved = self.resolve_members(identities, &index, &mut BTreeMap::new());
        let fresh = !identities.iter().any(|identity| {
            discovery
                .warnings
                .iter()
                .any(|warning| warning.provider == identity.provider)
        });
        GroupMemberObservation {
            state: if fresh {
                resolved.state
            } else {
                GroupState::Mixed
            },
            fresh,
        }
    }

    fn inspect_record_with_cache(
        &self,
        record: &GroupRecord,
        index: &GroupDiscoveryIndex<'_>,
        eligibility: &mut BTreeMap<GroupMemberIdentity, (bool, Option<GroupMemberReason>)>,
    ) -> GroupDefinitionView {
        if !self.context.is_binding_compatible(&record.binding)
            || record
                .definition
                .members
                .iter()
                .any(|member| !self.context.admits_layer(member))
        {
            return GroupDefinitionView::redacted(record);
        }

        let resolved = self.resolve_members(&record.definition.members, index, eligibility);
        GroupDefinitionView {
            qualified_name: record.qualified_name.clone(),
            scope: record.scope,
            revision: record.revision.clone(),
            context_compatible: true,
            members: resolved.members,
            provider_coverage: resolved.providers,
            counts: resolved.counts,
            state: Some(resolved.state),
            fresh: Some(true),
            reason: None,
        }
    }

    fn resolve_members(
        &self,
        identities: &[GroupMemberIdentity],
        index: &GroupDiscoveryIndex<'_>,
        eligibility: &mut BTreeMap<GroupMemberIdentity, (bool, Option<GroupMemberReason>)>,
    ) -> ResolvedGroupMembers {
        let mut members = Vec::with_capacity(identities.len());
        let mut counts = GroupStateCounts::default();
        let mut providers = BTreeSet::new();
        let mut observed_states = Vec::with_capacity(identities.len());
        for identity in identities {
            providers.insert(identity.provider);
            let matches = index.get(identity).map(Vec::as_slice).unwrap_or_default();
            let member = match matches {
                [] => {
                    counts.missing += 1;
                    observed_states.push(None);
                    GroupMemberView {
                        identity: identity.clone(),
                        enabled: None,
                        eligible: false,
                        reason: Some(GroupMemberReason::Missing),
                        display_name: None,
                    }
                }
                [item] => {
                    if item.enabled {
                        counts.enabled += 1;
                    } else {
                        counts.disabled += 1;
                    }
                    let (eligible, reason) = *eligibility
                        .entry(identity.clone())
                        .or_insert_with(|| toggle_eligibility(&self.context, item));
                    if !eligible {
                        counts.blocked += 1;
                    }
                    observed_states.push(Some(item.enabled));
                    GroupMemberView {
                        identity: identity.clone(),
                        enabled: Some(item.enabled),
                        eligible,
                        reason,
                        display_name: Some(item.display_name.clone()),
                    }
                }
                _ => {
                    counts.ambiguous += 1;
                    observed_states.push(None);
                    GroupMemberView {
                        identity: identity.clone(),
                        enabled: None,
                        eligible: false,
                        reason: Some(GroupMemberReason::Ambiguous),
                        display_name: None,
                    }
                }
            };
            members.push(member);
        }
        ResolvedGroupMembers {
            members,
            counts,
            providers,
            state: derive_group_state(&observed_states),
        }
    }

    fn load_scope(
        &self,
        scope: GroupScope,
        name: &str,
    ) -> Result<Option<GroupRecord>, GroupResolveError> {
        let result = match scope {
            GroupScope::Personal => self.personal.load(name),
            GroupScope::Repository => self.repository.load(name),
        };
        result.map_err(|source| GroupResolveError::ScopeUnavailable { scope, source })
    }

    #[must_use]
    pub fn context(&self) -> &GroupAccessContext {
        &self.context
    }

    #[must_use]
    pub fn personal_store(&self) -> &PersonalGroupStore {
        &self.personal
    }

    #[must_use]
    pub fn repository_store(&self) -> &RepositoryGroupStore {
        &self.repository
    }
}

pub(crate) fn index_discovery(discovery: &DiscoveryOutput) -> GroupDiscoveryIndex<'_> {
    let mut index = BTreeMap::new();
    for item in &discovery.items {
        if let Ok(identity) = GroupMemberIdentity::try_from(item) {
            index.entry(identity).or_insert_with(Vec::new).push(item);
        }
    }
    index
}

impl TryFrom<&DiscoveryItem> for GroupMemberIdentity {
    type Error = crate::groups::GroupValidationError;

    fn try_from(item: &DiscoveryItem) -> Result<Self, Self::Error> {
        Self::new(
            item.provider,
            item.kind,
            item.category,
            item.layer,
            item.id.clone(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupState {
    On,
    Off,
    Mixed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupStateCounts {
    pub enabled: usize,
    pub disabled: usize,
    pub blocked: usize,
    pub missing: usize,
    pub ambiguous: usize,
    pub stale: usize,
}

impl GroupStateCounts {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupMemberReason {
    Missing,
    Ambiguous,
    ReadOnly,
    Unsupported,
    Protected,
    ContextScopeConflict,
    ObservationStale,
}

impl GroupMemberReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Ambiguous => "ambiguous",
            Self::ReadOnly => "read-only",
            Self::Unsupported => "unsupported",
            Self::Protected => "protected",
            Self::ContextScopeConflict => "context-scope-conflict",
            Self::ObservationStale => "observation-stale",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberView {
    pub identity: GroupMemberIdentity,
    pub enabled: Option<bool>,
    pub eligible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<GroupMemberReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupDefinitionView {
    pub qualified_name: String,
    pub scope: GroupScope,
    pub revision: GroupRevision,
    pub context_compatible: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<GroupMemberView>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub provider_coverage: BTreeSet<ProviderId>,
    #[serde(default, skip_serializing_if = "GroupStateCounts::is_empty")]
    pub counts: GroupStateCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<GroupState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<GroupMemberReason>,
}

impl GroupDefinitionView {
    #[must_use]
    pub fn observed_state(&self) -> GroupState {
        self.state.unwrap_or(GroupState::Mixed)
    }

    #[must_use]
    pub fn observation_is_fresh(&self) -> bool {
        self.fresh.unwrap_or(false)
    }

    fn redacted(record: &GroupRecord) -> Self {
        Self {
            qualified_name: record.qualified_name.clone(),
            scope: record.scope,
            revision: record.revision.clone(),
            context_compatible: false,
            members: Vec::new(),
            provider_coverage: BTreeSet::new(),
            counts: GroupStateCounts::default(),
            state: None,
            fresh: None,
            reason: Some(GroupMemberReason::ContextScopeConflict),
        }
    }
}

fn derive_group_state(states: &[Option<bool>]) -> GroupState {
    if states.iter().all(|state| *state == Some(true)) {
        GroupState::On
    } else if states.iter().all(|state| *state == Some(false)) {
        GroupState::Off
    } else {
        GroupState::Mixed
    }
}

fn mark_view_stale_for_warnings(
    mut view: GroupDefinitionView,
    discovery: &DiscoveryOutput,
) -> GroupDefinitionView {
    if !view.context_compatible {
        return view;
    }
    let stale_providers = discovery
        .warnings
        .iter()
        .map(|warning| warning.provider)
        .collect::<BTreeSet<_>>();
    if stale_providers.is_empty()
        || !view
            .members
            .iter()
            .any(|member| stale_providers.contains(&member.identity.provider))
    {
        return view;
    }
    for member in &mut view.members {
        if stale_providers.contains(&member.identity.provider) && member.enabled.is_some() {
            view.counts.stale += 1;
            if member.reason.is_none() {
                member.reason = Some(GroupMemberReason::ObservationStale);
            }
        }
    }
    view.state = Some(GroupState::Mixed);
    view.fresh = Some(false);
    view
}

fn toggle_eligibility(
    context: &GroupAccessContext,
    item: &DiscoveryItem,
) -> (bool, Option<GroupMemberReason>) {
    if !context.admits_layer(
        &GroupMemberIdentity::try_from(item).expect("discovered item identity is bounded"),
    ) {
        return (false, Some(GroupMemberReason::ContextScopeConflict));
    }
    match item.mutability {
        DiscoveryMutability::ReadOnly => return (false, Some(GroupMemberReason::ReadOnly)),
        DiscoveryMutability::Unsupported => {
            return (false, Some(GroupMemberReason::Unsupported));
        }
        DiscoveryMutability::ReadWrite => {}
    }
    let plan = plan_toggle(TogglePlanRequest {
        app_state_root: context.app_state_root().to_path_buf(),
        item: item.clone(),
    });
    if plan.status == ToggleStatus::DryRun {
        return (true, None);
    }
    let reason = plan.reason.unwrap_or_default();
    if reason == CONTROL_PLANE_PROTECTED_REASON {
        (false, Some(GroupMemberReason::Protected))
    } else {
        (false, Some(GroupMemberReason::Unsupported))
    }
}

#[derive(Debug)]
pub enum GroupResolveError {
    Store(GroupStoreError),
    ScopeUnavailable {
        scope: GroupScope,
        source: GroupStoreError,
    },
    NotFound(String),
    Ambiguous {
        name: String,
        candidates: Vec<String>,
    },
}

impl GroupResolveError {
    #[must_use]
    pub fn candidates(&self) -> &[String] {
        match self {
            Self::Ambiguous { candidates, .. } => candidates,
            _ => &[],
        }
    }
}

impl From<GroupStoreError> for GroupResolveError {
    fn from(error: GroupStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for GroupResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::ScopeUnavailable { scope, .. } => write!(
                formatter,
                "{} inventory group scope is unavailable; retry with an explicit qualified reference such as personal:<name> or repository:<name>",
                scope.as_str()
            ),
            Self::NotFound(name) => write!(formatter, "inventory group was not found: {name}"),
            Self::Ambiguous { name, candidates } => {
                write!(
                    formatter,
                    "inventory group {name:?} is ambiguous; use one of: {}",
                    candidates.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for GroupResolveError {}

#[derive(Debug)]
pub enum GroupMemberValidationError {
    Discovery(DiscoveryError),
    NotUniquelyDiscoverable(GroupMemberIdentity),
    NotIndividuallyToggleable {
        identity: GroupMemberIdentity,
        reason: GroupMemberReason,
    },
}

impl fmt::Display for GroupMemberValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(error) => write!(formatter, "group member discovery failed: {error}"),
            Self::NotUniquelyDiscoverable(identity) => write!(
                formatter,
                "new group member is not uniquely discoverable: {}",
                identity.canonical_key()
            ),
            Self::NotIndividuallyToggleable { identity, reason } => write!(
                formatter,
                "new group member is not individually toggleable: {} ({})",
                identity.canonical_key(),
                reason.as_str()
            ),
        }
    }
}

impl std::error::Error for GroupMemberValidationError {}
