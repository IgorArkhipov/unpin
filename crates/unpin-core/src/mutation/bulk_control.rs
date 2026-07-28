//! Reach-aware bulk native-toggle planning.
//!
//! The MCP surface deliberately serializes this controller's typed result, but
//! does not own selector validation, reach filtering, or reviewed-plan
//! fingerprinting.  Keeping those decisions here makes the CLI/TUI handoff
//! path use the same target set and safety checks later on.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    discovery::{DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryOutput},
    groups::{GroupMemberIdentity, index_source_views, shared_source_has_unlisted_view},
    mutation::{
        TogglePlanRequest, ToggleResult, ToggleStatus, is_control_plane_protected_disable,
        plan_toggle,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, IncludedTargetOutcome, LifecycleEvidence,
        ProviderCoverageEntry, ProviderReach, ProviderReachCoverage, ProviderReachError,
        ProviderReachInput, ProviderReachLifecycle, ProviderReachRequest, ProviderReachResolution,
        SelectedProviderAuthority, classify_lifecycle, filter_derived_targets,
    },
    providers::ProviderId,
};

pub const BULK_TOGGLE_PLAN_SCHEMA_VERSION: u32 = 2;

/// A normalized selector for the existing discovery inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<DiscoveryKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<DiscoveryCategory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<DiscoveryLayer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl BulkToggleSelector {
    /// Normalize ordering and reject duplicate values before discovery.
    pub fn normalize(mut self) -> Result<Self, BulkTogglePlanError> {
        normalize_enum_values(&mut self.providers, "providers")?;
        normalize_enum_values(&mut self.kinds, "kinds")?;
        normalize_enum_values(&mut self.categories, "categories")?;
        normalize_enum_values(&mut self.layers, "layers")?;
        normalize_strings(&mut self.ids, "ids")?;
        if !self.has_non_provider_criterion() {
            return Err(BulkTogglePlanError::SelectorRequiresNonProviderCriterion);
        }
        Ok(self)
    }

    #[must_use]
    pub fn has_non_provider_criterion(&self) -> bool {
        !self.kinds.is_empty()
            || !self.categories.is_empty()
            || !self.layers.is_empty()
            || !self.ids.is_empty()
            || self.enabled.is_some()
    }

    #[must_use]
    pub fn matches(&self, item: &DiscoveryItem) -> bool {
        (self.providers.is_empty() || self.providers.contains(&item.provider))
            && (self.kinds.is_empty() || self.kinds.contains(&item.kind))
            && (self.categories.is_empty() || self.categories.contains(&item.category))
            && (self.layers.is_empty() || self.layers.contains(&item.layer))
            && (self.ids.is_empty() || self.ids.iter().any(|id| id == &item.id))
            && self.enabled.is_none_or(|enabled| enabled == item.enabled)
    }
}

fn normalize_enum_values<T>(values: &mut Vec<T>, field: &str) -> Result<(), BulkTogglePlanError>
where
    T: Ord,
{
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(BulkTogglePlanError::DuplicateSelectorValue(
            field.to_string(),
        ));
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>, field: &str) -> Result<(), BulkTogglePlanError> {
    if values
        .iter()
        .any(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(BulkTogglePlanError::MalformedSelectorValue(
            field.to_string(),
        ));
    }
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(BulkTogglePlanError::DuplicateSelectorValue(
            field.to_string(),
        ));
    }
    Ok(())
}

/// Inputs accepted by all bulk operation adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkToggleRequest {
    pub selector: BulkToggleSelector,
    pub target_enabled: bool,
    pub allow_empty_selection: bool,
    pub acknowledge_whole_inventory: bool,
    pub boundary: ConnectionBoundary,
    pub reach: ProviderReachInput,
    pub authority_candidates: Vec<SelectedProviderAuthority>,
}

impl BulkToggleRequest {
    #[must_use]
    pub fn new(selector: BulkToggleSelector, target_enabled: bool) -> Self {
        Self {
            selector,
            target_enabled,
            allow_empty_selection: false,
            acknowledge_whole_inventory: false,
            boundary: ConnectionBoundary::All,
            reach: ProviderReachInput::Omitted,
            authority_candidates: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_reach(mut self, boundary: ConnectionBoundary, reach: ProviderReachInput) -> Self {
        self.boundary = boundary;
        self.reach = reach;
        self
    }

    #[must_use]
    pub fn with_authority(mut self, authority: SelectedProviderAuthority) -> Self {
        self.authority_candidates.push(authority);
        self
    }

    #[must_use]
    pub const fn allow_empty_selection(mut self, allow: bool) -> Self {
        self.allow_empty_selection = allow;
        self
    }

    #[must_use]
    pub const fn acknowledge_whole_inventory(mut self, acknowledge: bool) -> Self {
        self.acknowledge_whole_inventory = acknowledge;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkProviderCount {
    pub provider: ProviderId,
    pub kind: DiscoveryKind,
    pub resolved: usize,
    pub total: usize,
}

impl BulkProviderCount {
    #[must_use]
    pub const fn covers_whole_inventory(&self) -> bool {
        self.total > 1 && self.resolved == self.total
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkInventoryAcknowledgement {
    pub required: bool,
    pub acknowledged: bool,
    pub counts: Vec<BulkProviderCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkItemIdentity {
    pub provider: ProviderId,
    pub kind: DiscoveryKind,
    pub category: DiscoveryCategory,
    pub layer: DiscoveryLayer,
    pub id: String,
}

impl TryFrom<&DiscoveryItem> for BulkItemIdentity {
    type Error = BulkTogglePlanError;

    fn try_from(item: &DiscoveryItem) -> Result<Self, Self::Error> {
        if item.id.is_empty() || item.id.chars().any(char::is_control) {
            return Err(BulkTogglePlanError::MalformedIdentity(item.id.clone()));
        }
        Ok(Self {
            provider: item.provider,
            kind: item.kind,
            category: item.category,
            layer: item.layer,
            id: item.id.clone(),
        })
    }
}

impl BulkItemIdentity {
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.provider.as_str(),
            self.layer.as_str(),
            self.kind.as_str(),
            self.category.as_str(),
            self.id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkBlockedItem {
    pub item: BulkItemIdentity,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleItemPlan {
    pub item: BulkItemIdentity,
    pub result: ToggleResult,
    pub outcome: IncludedTargetOutcome,
    pub operation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BulkTogglePlanStatus {
    Planned,
    NoOp,
    Blocked,
    NoTargetsInProviderReach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkTogglePlan {
    pub schema_version: u32,
    pub status: BulkTogglePlanStatus,
    pub selector: BulkToggleSelector,
    pub target_enabled: bool,
    pub allow_empty_selection: bool,
    pub provider_reach: ProviderReach,
    pub provider_coverage: ProviderReachCoverage,
    pub acknowledgement: BulkInventoryAcknowledgement,
    pub lifecycle: ProviderReachLifecycle,
    pub matched: Vec<DiscoveryItem>,
    pub included: Vec<BulkToggleItemPlan>,
    pub blocked: Vec<BulkBlockedItem>,
    pub plan_fingerprint: String,
}

impl BulkTogglePlan {
    pub fn verify(&self) -> Result<(), BulkTogglePlanError> {
        if self.schema_version != BULK_TOGGLE_PLAN_SCHEMA_VERSION {
            return Err(BulkTogglePlanError::InvalidPlan);
        }
        let expected_status = match self.lifecycle {
            ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => {
                BulkTogglePlanStatus::Planned
            }
            ProviderReachLifecycle::NoOp => BulkTogglePlanStatus::NoOp,
            ProviderReachLifecycle::NoTargetsInProviderReach => {
                BulkTogglePlanStatus::NoTargetsInProviderReach
            }
            ProviderReachLifecycle::Blocked => BulkTogglePlanStatus::Blocked,
            ProviderReachLifecycle::RecoveryRequired => {
                return Err(BulkTogglePlanError::InvalidPlan);
            }
        };
        if self.status != expected_status {
            return Err(BulkTogglePlanError::InvalidPlan);
        }
        let mut seen = BTreeSet::new();
        for item in &self.matched {
            let identity = BulkItemIdentity::try_from(item)?;
            if !seen.insert(identity.key()) {
                return Err(BulkTogglePlanError::DuplicateIdentity(identity.key()));
            }
        }
        let expected = bulk_plan_fingerprint(self)?;
        if expected != self.plan_fingerprint {
            return Err(BulkTogglePlanError::PlanFingerprintMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn included_count(&self) -> usize {
        self.included.len()
    }

    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    #[must_use]
    pub fn write_count(&self) -> usize {
        self.included
            .iter()
            .filter(|item| item.outcome == IncludedTargetOutcome::Applied)
            .count()
    }

    #[must_use]
    pub fn matched_identities(&self) -> Vec<BulkItemIdentity> {
        let mut identities = self
            .matched
            .iter()
            .filter_map(|item| BulkItemIdentity::try_from(item).ok())
            .collect::<Vec<_>>();
        identities.sort_by_key(BulkItemIdentity::key);
        identities
    }

    #[must_use]
    pub fn actionable_identities(&self) -> Vec<BulkItemIdentity> {
        let mut identities = self
            .included
            .iter()
            .map(|item| item.item.clone())
            .collect::<Vec<_>>();
        identities.sort_by_key(BulkItemIdentity::key);
        identities
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkToggleApplyOutcome {
    NoOp,
    Partial,
    Blocked,
    HumanActionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkTogglePlanError {
    SelectorRequiresNonProviderCriterion,
    DuplicateSelectorValue(String),
    MalformedSelectorValue(String),
    MalformedIdentity(String),
    DuplicateIdentity(String),
    PathAlias(String),
    ProviderReach(ProviderReachError),
    WholeInventoryAcknowledgementRequired(Vec<BulkProviderCount>),
    EmptySelection,
    NoTargetsInProviderReach,
    SharedSourceCrossesProviderReach(String),
    InvalidPlan,
    PlanFingerprintMismatch,
    MaxItemsExceeded { actual: usize, maximum: usize },
    Serialization(String),
}

impl fmt::Display for BulkTogglePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectorRequiresNonProviderCriterion => formatter
                .write_str("bulk selector must include at least one non-provider criterion"),
            Self::DuplicateSelectorValue(field) => {
                write!(formatter, "selector.{field} contains duplicate values")
            }
            Self::MalformedSelectorValue(field) => {
                write!(formatter, "selector.{field} contains a malformed value")
            }
            Self::MalformedIdentity(id) => write!(formatter, "malformed item identity: {id}"),
            Self::DuplicateIdentity(id) => write!(formatter, "duplicate item identity: {id}"),
            Self::PathAlias(id) => write!(formatter, "path alias detected for inventory item {id}"),
            Self::ProviderReach(error) => error.fmt(formatter),
            Self::WholeInventoryAcknowledgementRequired(_) => formatter
                .write_str("whole-inventory acknowledgement is required for this bulk selector"),
            Self::EmptySelection => formatter.write_str("empty-selection"),
            Self::NoTargetsInProviderReach => formatter.write_str("no-targets-in-provider-reach"),
            Self::SharedSourceCrossesProviderReach(id) => {
                write!(formatter, "shared-source-crosses-provider-reach: {id}",)
            }
            Self::InvalidPlan => formatter.write_str("bulk toggle plan is invalid"),
            Self::PlanFingerprintMismatch => {
                formatter.write_str("bulk toggle plan fingerprint mismatch")
            }
            Self::MaxItemsExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "bulk toggle plan has {actual} actionable items; maximum is {maximum}"
                )
            }
            Self::Serialization(error) => {
                write!(formatter, "bulk toggle serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for BulkTogglePlanError {}

impl From<ProviderReachError> for BulkTogglePlanError {
    fn from(error: ProviderReachError) -> Self {
        Self::ProviderReach(error)
    }
}

#[derive(Debug, Clone)]
pub struct BulkToggleController {
    app_state_root: PathBuf,
}

impl BulkToggleController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    /// Validate and normalize all request inputs that must fail before
    /// discovery. Operation adapters should call this before reading provider
    /// state; `plan_from_discovery` repeats the same pure preflight.
    pub fn validate_before_discovery(
        request: &BulkToggleRequest,
    ) -> Result<(), BulkTogglePlanError> {
        Self::preflight(request).map(|_| ())
    }

    fn preflight(
        request: &BulkToggleRequest,
    ) -> Result<(BulkToggleSelector, ProviderReachResolution), BulkTogglePlanError> {
        let selector = request.selector.clone().normalize()?;
        let resolution = ProviderReachRequest {
            boundary: request.boundary,
            reach: request.reach,
            target_kind: DerivedTargetKind::Bulk,
            authority_candidates: request.authority_candidates.clone(),
        }
        .validate_before_discovery()?
        .reconcile_exact_target(None)?;
        Ok((selector, resolution))
    }

    /// Plan from an already-derived discovery set. Callers that own discovery
    /// should run `Self::validate_before_discovery` first; this method repeats
    /// the pure validation to keep direct core callers safe.
    pub fn plan_from_discovery(
        &self,
        discovery: DiscoveryOutput,
        request: BulkToggleRequest,
    ) -> Result<BulkTogglePlan, BulkTogglePlanError> {
        let (selector, resolution) = Self::preflight(&request)?;
        self.plan_normalized(discovery, selector, request, resolution)
    }

    pub fn plan(
        &self,
        discovery: DiscoveryOutput,
        request: BulkToggleRequest,
    ) -> Result<BulkTogglePlan, BulkTogglePlanError> {
        self.plan_from_discovery(discovery, request)
    }

    fn plan_normalized(
        &self,
        discovery: DiscoveryOutput,
        selector: BulkToggleSelector,
        request: BulkToggleRequest,
        resolution: ProviderReachResolution,
    ) -> Result<BulkTogglePlan, BulkTogglePlanError> {
        let matched = discovery
            .items
            .iter()
            .filter(|item| selector.matches(item))
            .cloned()
            .collect::<Vec<_>>();
        reject_duplicate_identities(&matched)?;
        reject_path_aliases(&matched)?;

        let counts = inventory_counts(&discovery.items, &matched);
        let acknowledgement = BulkInventoryAcknowledgement {
            required: counts.iter().any(BulkProviderCount::covers_whole_inventory),
            acknowledged: request.acknowledge_whole_inventory,
            counts,
        };
        if acknowledgement.required && !acknowledgement.acknowledged {
            return Err(BulkTogglePlanError::WholeInventoryAcknowledgementRequired(
                acknowledgement.counts,
            ));
        }

        if matched.is_empty() {
            if request.allow_empty_selection {
                return self.finish_plan(
                    selector,
                    request,
                    resolution.reach,
                    matched,
                    Vec::new(),
                    Vec::new(),
                    ProviderReachCoverage::new(Vec::new()),
                    acknowledgement,
                    ProviderReachLifecycle::NoOp,
                    BulkTogglePlanStatus::NoOp,
                );
            }
            return Err(BulkTogglePlanError::EmptySelection);
        }

        let filtered = filter_derived_targets(&resolution.reach, matched.clone());
        if filtered.included.is_empty() {
            return self.finish_plan(
                selector,
                request,
                resolution.reach,
                matched,
                Vec::new(),
                Vec::new(),
                filtered.coverage,
                acknowledgement,
                ProviderReachLifecycle::NoTargetsInProviderReach,
                BulkTogglePlanStatus::NoTargetsInProviderReach,
            );
        }

        let source_views = index_source_views(&discovery.items);
        let selected_identities = filtered
            .included
            .iter()
            .filter_map(|item| GroupMemberIdentity::try_from(item).ok())
            .collect::<BTreeSet<_>>();
        let mut coverage = filtered.coverage.entries.clone();
        let mut included = Vec::new();
        let mut blocked = Vec::new();
        let mut outcomes = Vec::new();
        for item in filtered.included {
            let identity = BulkItemIdentity::try_from(&item)?;
            let mut blocker = None;
            if is_control_plane_protected_disable(&item, request.target_enabled) {
                blocker = Some(crate::mutation::CONTROL_PLANE_PROTECTED_REASON.to_string());
            } else if item.enabled != request.target_enabled
                && shared_source_has_unlisted_view(&item, &selected_identities, &source_views)
            {
                blocker = Some("shared-source-crosses-provider-reach".to_string());
            }

            if let Some(reason_code) = blocker {
                set_coverage_reason(&mut coverage, &identity, &reason_code);
                blocked.push(BulkBlockedItem {
                    item: identity,
                    reason_code,
                });
                outcomes.push(IncludedTargetOutcome::Blocked);
                continue;
            }

            let mut result = if item.enabled == request.target_enabled {
                no_op_toggle_result(item.clone(), request.target_enabled)
            } else {
                plan_toggle(TogglePlanRequest {
                    app_state_root: self.app_state_root.clone(),
                    item: item.clone(),
                })
            };
            result.provider_reach = Some(resolution.reach);
            result.coverage = Some(ProviderReachCoverage::new(vec![
                ProviderCoverageEntry::included(item.provider, item.id.clone()),
            ]));
            if result.status != ToggleStatus::DryRun {
                let reason_code = result
                    .reason
                    .clone()
                    .unwrap_or_else(|| "not-actionable".to_string());
                set_coverage_reason(&mut coverage, &identity, &reason_code);
                blocked.push(BulkBlockedItem {
                    item: identity,
                    reason_code,
                });
                outcomes.push(IncludedTargetOutcome::Blocked);
                continue;
            }

            let outcome = if item.enabled == request.target_enabled {
                IncludedTargetOutcome::NoOp
            } else {
                IncludedTargetOutcome::Applied
            };
            let operation_digest = digest_json(&result)?;
            included.push(BulkToggleItemPlan {
                item: identity,
                result,
                outcome,
                operation_digest,
            });
            outcomes.push(outcome);
        }

        let coverage = ProviderReachCoverage::new(coverage);
        let lifecycle = classify_lifecycle(&LifecycleEvidence::new(
            outcomes,
            coverage.entries.clone(),
            false,
        ));
        let status = match lifecycle {
            ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => {
                BulkTogglePlanStatus::Planned
            }
            ProviderReachLifecycle::NoOp => BulkTogglePlanStatus::NoOp,
            ProviderReachLifecycle::NoTargetsInProviderReach => {
                BulkTogglePlanStatus::NoTargetsInProviderReach
            }
            ProviderReachLifecycle::Blocked | ProviderReachLifecycle::RecoveryRequired => {
                BulkTogglePlanStatus::Blocked
            }
        };
        self.finish_plan(
            selector,
            request,
            resolution.reach,
            matched,
            included,
            blocked,
            coverage,
            acknowledgement,
            lifecycle,
            status,
        )
    }

    fn finish_plan(
        &self,
        selector: BulkToggleSelector,
        request: BulkToggleRequest,
        provider_reach: ProviderReach,
        matched: Vec<DiscoveryItem>,
        included: Vec<BulkToggleItemPlan>,
        blocked: Vec<BulkBlockedItem>,
        provider_coverage: ProviderReachCoverage,
        acknowledgement: BulkInventoryAcknowledgement,
        lifecycle: ProviderReachLifecycle,
        status: BulkTogglePlanStatus,
    ) -> Result<BulkTogglePlan, BulkTogglePlanError> {
        let mut plan = BulkTogglePlan {
            schema_version: BULK_TOGGLE_PLAN_SCHEMA_VERSION,
            status,
            selector,
            target_enabled: request.target_enabled,
            allow_empty_selection: request.allow_empty_selection,
            provider_reach,
            provider_coverage,
            acknowledgement,
            lifecycle,
            matched,
            included,
            blocked,
            plan_fingerprint: String::new(),
        };
        plan.plan_fingerprint = bulk_plan_fingerprint(&plan)?;
        plan.verify()?;
        Ok(plan)
    }

    /// Validate a reviewed handoff against a freshly planned state. This never
    /// performs provider writes; the applying CLI/TUI owns that boundary.
    pub fn validate_apply(
        &self,
        reviewed: &BulkTogglePlan,
        current: &BulkTogglePlan,
        max_items: usize,
    ) -> Result<BulkToggleApplyOutcome, BulkTogglePlanError> {
        reviewed.verify()?;
        current.verify()?;
        if reviewed.plan_fingerprint != current.plan_fingerprint {
            return Err(BulkTogglePlanError::PlanFingerprintMismatch);
        }
        let write_count = current.write_count();
        if write_count > max_items {
            return Err(BulkTogglePlanError::MaxItemsExceeded {
                actual: write_count,
                maximum: max_items,
            });
        }
        match current.lifecycle {
            ProviderReachLifecycle::Blocked | ProviderReachLifecycle::RecoveryRequired => {
                Ok(BulkToggleApplyOutcome::Blocked)
            }
            ProviderReachLifecycle::Partial if current.write_count() == 0 => {
                Ok(BulkToggleApplyOutcome::Partial)
            }
            ProviderReachLifecycle::NoOp | ProviderReachLifecycle::NoTargetsInProviderReach => {
                Ok(BulkToggleApplyOutcome::NoOp)
            }
            ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => {
                Ok(BulkToggleApplyOutcome::HumanActionRequired)
            }
        }
    }
}

fn reject_duplicate_identities(items: &[DiscoveryItem]) -> Result<(), BulkTogglePlanError> {
    let mut identities = BTreeSet::new();
    for item in items {
        let identity = BulkItemIdentity::try_from(item)?;
        if !identities.insert(identity.key()) {
            return Err(BulkTogglePlanError::DuplicateIdentity(identity.key()));
        }
    }
    Ok(())
}

fn reject_path_aliases(items: &[DiscoveryItem]) -> Result<(), BulkTogglePlanError> {
    let mut source_paths = BTreeMap::new();
    let mut state_paths = BTreeMap::new();
    for item in items {
        reject_path_alias(&mut source_paths, &item.source_path, &item.id)?;
        reject_path_alias(&mut state_paths, &item.state_path, &item.id)?;
    }
    Ok(())
}

fn reject_path_alias(
    seen: &mut BTreeMap<PathBuf, String>,
    raw: &str,
    item_id: &str,
) -> Result<(), BulkTogglePlanError> {
    let path = Path::new(raw);
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(BulkTogglePlanError::PathAlias(item_id.to_string()));
    }
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(previous) = seen.insert(key, raw.to_string())
        && previous != raw
    {
        return Err(BulkTogglePlanError::PathAlias(item_id.to_string()));
    }
    Ok(())
}

fn inventory_counts(
    inventory: &[DiscoveryItem],
    matched: &[DiscoveryItem],
) -> Vec<BulkProviderCount> {
    let mut totals = BTreeMap::<(ProviderId, DiscoveryKind), usize>::new();
    let mut resolved = BTreeMap::<(ProviderId, DiscoveryKind), usize>::new();
    for item in inventory {
        *totals.entry((item.provider, item.kind)).or_default() += 1;
    }
    for item in matched {
        *resolved.entry((item.provider, item.kind)).or_default() += 1;
    }
    let mut counts = resolved
        .into_iter()
        .map(|((provider, kind), resolved)| BulkProviderCount {
            provider,
            kind,
            resolved,
            total: totals.get(&(provider, kind)).copied().unwrap_or(resolved),
        })
        .collect::<Vec<_>>();
    counts.sort_by_key(|count| (count.provider, count.kind));
    counts
}

fn set_coverage_reason(
    coverage: &mut [ProviderCoverageEntry],
    identity: &BulkItemIdentity,
    reason_code: &str,
) {
    if let Some(entry) = coverage
        .iter_mut()
        .find(|entry| entry.provider == identity.provider && entry.target_id == identity.id)
    {
        entry.included = false;
        entry.reason = Some(match reason_code {
            "shared-source-crosses-provider-reach" => {
                crate::provider_reach::ProviderReachReason::SharedSourceCrossesProviderReach
            }
            crate::mutation::CONTROL_PLANE_PROTECTED_REASON | "protected" => {
                crate::provider_reach::ProviderReachReason::Protected
            }
            "read-only" => crate::provider_reach::ProviderReachReason::ReadOnly,
            "missing" => crate::provider_reach::ProviderReachReason::Missing,
            _ => crate::provider_reach::ProviderReachReason::Blocked,
        });
    }
}

fn no_op_toggle_result(item: DiscoveryItem, target_enabled: bool) -> ToggleResult {
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: Vec::new(),
        affected_targets: Vec::new(),
        backup_id: None,
        reason: Some("already-in-desired-state".to_string()),
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, BulkTogglePlanError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| BulkTogglePlanError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", hex_digest(&bytes)))
}

fn bulk_plan_fingerprint(plan: &BulkTogglePlan) -> Result<String, BulkTogglePlanError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FingerprintBody<'a> {
        schema_version: u32,
        selector: &'a BulkToggleSelector,
        target_enabled: bool,
        allow_empty_selection: bool,
        provider_reach: ProviderReach,
        provider_coverage: &'a ProviderReachCoverage,
        acknowledgement: &'a BulkInventoryAcknowledgement,
        lifecycle: ProviderReachLifecycle,
        matched_item_digests: Vec<String>,
        included_item_digests: Vec<String>,
        blocked: &'a [BulkBlockedItem],
    }
    let mut matched_item_digests = plan
        .matched
        .iter()
        .map(digest_json)
        .collect::<Result<Vec<_>, _>>()?;
    matched_item_digests.sort();
    let mut included_item_digests = plan
        .included
        .iter()
        .map(digest_json)
        .collect::<Result<Vec<_>, _>>()?;
    included_item_digests.sort();
    let body = FingerprintBody {
        schema_version: plan.schema_version,
        selector: &plan.selector,
        target_enabled: plan.target_enabled,
        allow_empty_selection: plan.allow_empty_selection,
        provider_reach: plan.provider_reach,
        provider_coverage: &plan.provider_coverage,
        acknowledgement: &plan.acknowledgement,
        lifecycle: plan.lifecycle,
        matched_item_digests,
        included_item_digests,
        blocked: &plan.blocked,
    };
    let encoded = serde_json::to_vec(&body)
        .map_err(|error| BulkTogglePlanError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", hex_digest(&encoded)))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
