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
    approval::{
        ApprovalError, ApprovalExpectation, CONTROL_APPROVAL_ISSUER, ControlApprovalContext,
        ControlAuthorization,
    },
    control_operation::{
        ControlResolvedContext, ReachAwareControlOperationEnvelope, ReachAwareOperationFamily,
        ReachAwarePayloadReference, ReachAwarePrincipal, ReachAwarePriorState,
        ReachAwareRecoveryEvidence, ReachAwareRootBinding,
    },
    discovery::{DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryOutput},
    groups::{GroupMemberIdentity, index_source_views, shared_source_has_unlisted_view},
    mutation::{
        BackupAuthenticationKey, NativeToggleControlError, NativeToggleController,
        TogglePlanRequest, ToggleResult, ToggleStatus, is_control_plane_protected_disable,
        plan_toggle,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, IncludedTargetOutcome, LifecycleEvidence,
        ProviderCoverageEntry, ProviderReach, ProviderReachCoverage, ProviderReachError,
        ProviderReachInput, ProviderReachLifecycle, ProviderReachRequest, ProviderReachResolution,
        SelectedProviderAuthority, SelectedProviderProvenance, classify_lifecycle,
        filter_derived_targets,
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

pub const BULK_TOGGLE_PLAN_SCHEMA_VERSION: u32 = 2;
pub const BULK_TOGGLE_APPROVAL_AUDIENCE: &str = "unpin-core-bulk-toggle-apply-v2";

#[derive(Debug, Clone)]
pub struct BulkToggleReachAwareApplyContext {
    pub approval_context: ControlApprovalContext,
    pub roots: ReachAwareRootBinding,
    pub principal: ReachAwarePrincipal,
    pub audience: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub now_unix: i64,
}

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

fn normalize_enum_values<T>(values: &mut [T], field: &str) -> Result<(), BulkTogglePlanError>
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

fn normalize_strings(values: &mut [String], field: &str) -> Result<(), BulkTogglePlanError> {
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
    pub operation_id: String,
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
        if expected != self.plan_fingerprint
            || self.operation_id
                != format!("bulk-toggle-{}", expected.trim_start_matches("sha256:"))
        {
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

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
        session_id: &str,
    ) -> Result<ApprovalExpectation, BulkTogglePlanError> {
        let mut expectation = bulk_transition_plan(self, context, session_id)?
            .approval_expectation(CONTROL_APPROVAL_ISSUER, BULK_TOGGLE_APPROVAL_AUDIENCE);
        // Human approval reviews the complete reach-aware plan, including its
        // selected reach, coverage and exclusions, rather than only the
        // transition effect list.
        expectation.effect_graph_digest = unprefixed_digest(&self.plan_fingerprint)?;
        Ok(expectation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleItemApplyResult {
    pub item: BulkItemIdentity,
    pub status: ToggleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleApplyResult {
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub lifecycle: ProviderReachLifecycle,
    pub provider_reach: ProviderReach,
    pub provider_coverage: ProviderReachCoverage,
    pub items: Vec<BulkToggleItemApplyResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleHandoff {
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkToggleOperationStatus {
    pub plan: BulkTogglePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<BulkToggleApplyResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BulkToggleOperationRecord {
    schema_version: u32,
    plan: BulkTogglePlan,
    writes_started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_lifecycle: Option<ProviderReachLifecycle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_result: Option<BulkToggleApplyResult>,
}

impl BulkToggleOperationRecord {
    fn verify(&self) -> Result<(), BulkTogglePlanError> {
        if self.schema_version != BULK_TOGGLE_PLAN_SCHEMA_VERSION {
            return Err(BulkTogglePlanError::InvalidPlan);
        }
        self.plan.verify()?;
        match (&self.terminal_lifecycle, &self.terminal_result) {
            (None, None) => Ok(()),
            (Some(lifecycle), Some(result))
                if *lifecycle == result.lifecycle
                    && bulk_result_matches_plan(result, &self.plan)
                    && (*lifecycle != ProviderReachLifecycle::RecoveryRequired
                        || self.writes_started) =>
            {
                Ok(())
            }
            _ => Err(BulkTogglePlanError::ReachAware(
                "bulk family payload is internally inconsistent".to_string(),
            )),
        }
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
    Approval(String),
    Journal(String),
    Native(String),
    State(String),
    TransitionPlan(String),
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
    ReachAware(String),
    ReachAwareAuthorityRequired,
}

impl fmt::Display for BulkTogglePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error)
            | Self::Journal(error)
            | Self::Native(error)
            | Self::State(error)
            | Self::TransitionPlan(error) => formatter.write_str(error),
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
            Self::ReachAware(error) => {
                write!(formatter, "bulk reach-aware operation is invalid: {error}")
            }
            Self::ReachAwareAuthorityRequired => {
                formatter.write_str("bulk reach-aware operation requires configured authority")
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

impl From<ApprovalError> for BulkTogglePlanError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error.to_string())
    }
}

impl From<JournalError> for BulkTogglePlanError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error.to_string())
    }
}

impl From<NativeToggleControlError> for BulkTogglePlanError {
    fn from(error: NativeToggleControlError) -> Self {
        Self::Native(error.to_string())
    }
}

impl From<StateError> for BulkTogglePlanError {
    fn from(error: StateError) -> Self {
        Self::State(error.to_string())
    }
}

impl From<TransitionPlanError> for BulkTogglePlanError {
    fn from(error: TransitionPlanError) -> Self {
        Self::TransitionPlan(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct BulkToggleController {
    app_state_root: PathBuf,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    session_authority_key: Option<SessionAuthorityKey>,
    trusted_roots: Option<ReachAwareRootBinding>,
}

impl BulkToggleController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            backup_authentication_key: None,
            session_authority_key: None,
            trusted_roots: None,
        }
    }

    #[must_use]
    pub fn with_reach_aware_authority(
        mut self,
        backup_authentication_key: BackupAuthenticationKey,
        session_authority_key: SessionAuthorityKey,
        trusted_roots: ReachAwareRootBinding,
    ) -> Self {
        self.backup_authentication_key = Some(backup_authentication_key);
        self.session_authority_key = Some(session_authority_key);
        self.trusted_roots = Some(trusted_roots);
        self
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

    #[allow(clippy::too_many_arguments)]
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
            operation_id: String::new(),
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
        plan.operation_id = format!(
            "bulk-toggle-{}",
            plan.plan_fingerprint.trim_start_matches("sha256:")
        );
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

    pub fn seal_handoff(
        &self,
        plan: &BulkTogglePlan,
        durable: &BulkToggleReachAwareApplyContext,
    ) -> Result<BulkToggleHandoff, BulkTogglePlanError> {
        let (payload_path, _) = bulk_payload_store(&self.app_state_root, &plan.operation_id);
        let lock_path = payload_path.with_file_name(".bulk-toggle-operation-domain");
        let _execution_lock = StateResourceLock::acquire(&lock_path)?;
        self.seal_handoff_locked(plan, durable)
    }

    fn seal_handoff_locked(
        &self,
        plan: &BulkTogglePlan,
        durable: &BulkToggleReachAwareApplyContext,
    ) -> Result<BulkToggleHandoff, BulkTogglePlanError> {
        plan.verify()?;
        let authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(BulkTogglePlanError::ReachAwareAuthorityRequired)?;
        self.verify_reach_aware_context(plan, durable, authority_key)?;
        let transition = bulk_transition_plan(
            plan,
            &durable.approval_context,
            &durable.principal.session_id,
        )?;
        let (_, payload_store) = bulk_payload_store(&self.app_state_root, &plan.operation_id);
        let record = BulkToggleOperationRecord {
            schema_version: BULK_TOGGLE_PLAN_SCHEMA_VERSION,
            plan: plan.clone(),
            writes_started: false,
            terminal_lifecycle: None,
            terminal_result: None,
        };
        create_or_verify_bulk_payload(&payload_store, &record)?;
        let store = TransitionJournalStore::new(&self.app_state_root);
        let owner = bulk_operation_owner(&plan.operation_id, "bulk-journal", 1)?;
        let family = ReachAwareOperationFamily::BulkToggle;
        let selected_provider = plan.provider_reach.provider().map(|provider| {
            SelectedProviderAuthority::new(
                provider,
                plan.provider_reach
                    .provenance()
                    .unwrap_or(SelectedProviderProvenance::ExplicitInput),
            )
        });
        let builder = ReachAwareControlOperationEnvelope::builder()
            .family(family, BULK_TOGGLE_PLAN_SCHEMA_VERSION)
            .operation(
                plan.operation_id.clone(),
                transition.kind.as_str(),
                plan.plan_fingerprint.clone(),
            )
            .context(ControlResolvedContext {
                repository_key: transition.context.repository_key.clone(),
                workspace_key: transition.context.workspace_key.clone(),
                session_id: transition.context.session_id.clone(),
                profile_digest: None,
            })
            .reach(
                durable.principal.connection_boundary,
                plan.provider_reach,
                selected_provider,
                plan.provider_coverage.clone(),
            )
            .lifecycle(
                plan.lifecycle,
                plan.lifecycle,
                EffectActivation::RestartRequired,
            )
            .trusted_roots(durable.roots.clone())
            .authority(
                durable.principal.clone(),
                durable.audience.clone(),
                durable.issued_at_unix,
                durable.expires_at_unix,
            )
            .payload_reference(ReachAwarePayloadReference {
                family,
                schema_version: BULK_TOGGLE_PLAN_SCHEMA_VERSION,
                reference: bulk_payload_reference(&plan.operation_id),
                payload_digest: plan.plan_fingerprint.clone(),
            })
            .prior_state(
                plan.included
                    .iter()
                    .map(|item| ReachAwarePriorState {
                        target_id: item.item.key(),
                        fingerprint: item.operation_digest.clone(),
                    })
                    .collect(),
            );
        let handle =
            store.create_or_attach_reach_aware(&transition, owner, builder, authority_key)?;
        verify_bulk_envelope(&handle, plan, durable, authority_key)?;
        Ok(BulkToggleHandoff {
            operation_id: plan.operation_id.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
            expires_at_unix: durable.expires_at_unix,
        })
    }

    pub fn load_handoff(&self, operation_id: &str) -> Result<BulkTogglePlan, BulkTogglePlanError> {
        Ok(self.load_handoff_status(operation_id)?.plan)
    }

    pub fn load_handoff_status(
        &self,
        operation_id: &str,
    ) -> Result<BulkToggleOperationStatus, BulkTogglePlanError> {
        let (_, store) = bulk_payload_store(&self.app_state_root, operation_id);
        let snapshot = store
            .load::<BulkToggleOperationRecord>()?
            .ok_or_else(|| BulkTogglePlanError::ReachAware("bulk handoff not found".to_string()))?;
        snapshot.value.verify()?;
        Ok(BulkToggleOperationStatus {
            plan: snapshot.value.plan,
            terminal_result: snapshot.value.terminal_result,
        })
    }

    pub fn apply_with_reach_aware(
        &self,
        plan: &BulkTogglePlan,
        authorization: ControlAuthorization,
        durable: BulkToggleReachAwareApplyContext,
        fresh_discovery: DiscoveryOutput,
    ) -> Result<BulkToggleApplyResult, BulkTogglePlanError> {
        plan.verify()?;
        let authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(BulkTogglePlanError::ReachAwareAuthorityRequired)?;
        let backup_key = self
            .backup_authentication_key
            .as_ref()
            .ok_or(BulkTogglePlanError::ReachAwareAuthorityRequired)?;
        let expectation =
            plan.approval_expectation(&durable.approval_context, &durable.principal.session_id)?;
        authorization.assert_matches(&expectation)?;

        let (payload_path, payload_store) =
            bulk_payload_store(&self.app_state_root, &plan.operation_id);
        let lock_path = payload_path.with_file_name(".bulk-toggle-operation-domain");
        let _execution_lock = StateResourceLock::acquire(&lock_path)?;
        self.seal_handoff_locked(plan, &durable)?;
        let snapshot = payload_store
            .load::<BulkToggleOperationRecord>()?
            .ok_or_else(|| BulkTogglePlanError::ReachAware("bulk handoff not found".to_string()))?;
        snapshot.value.verify()?;
        if snapshot.value.plan != *plan {
            return Err(BulkTogglePlanError::PlanFingerprintMismatch);
        }
        let mut record = snapshot.value;
        let mut record_revision = snapshot.revision;
        if let Some(result) = record.terminal_result.clone() {
            return Ok(result);
        }

        let current_request = request_from_reviewed(plan, durable.principal.connection_boundary);
        let current = self.plan_from_discovery(fresh_discovery.clone(), current_request)?;
        if current.plan_fingerprint != plan.plan_fingerprint {
            let result = blocked_bulk_result(plan, "bulk plan drifted before apply");
            record.terminal_lifecycle = Some(ProviderReachLifecycle::Blocked);
            record.terminal_result = Some(result.clone());
            save_bulk_payload(
                &payload_store,
                &mut record_revision,
                &record,
                &plan.operation_id,
            )?;
            let mut handle = self.bulk_journal_handle(plan, &durable)?;
            finalize_bulk_journal(
                &TransitionJournalStore::new(&self.app_state_root),
                &mut handle,
                plan,
                ProviderReachLifecycle::Blocked,
                false,
                authority_key,
            )?;
            return Ok(result);
        }

        let mut handle = self.bulk_journal_handle(plan, &durable)?;
        if handle.journal.lifecycle.is_terminal() {
            return record.terminal_result.ok_or_else(|| {
                BulkTogglePlanError::ReachAware(
                    "terminal bulk journal is missing family result".to_string(),
                )
            });
        }
        if handle.journal.lifecycle != TransitionLifecycle::Applying {
            handle
                .journal
                .record(TransitionLifecycle::Applying, "reach-aware-applying", None)?;
            TransitionJournalStore::new(&self.app_state_root).save(&mut handle)?;
        }

        if !matches!(
            plan.lifecycle,
            ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial
        ) {
            let result = BulkToggleApplyResult {
                operation_id: plan.operation_id.clone(),
                plan_fingerprint: plan.plan_fingerprint.clone(),
                lifecycle: plan.lifecycle,
                provider_reach: plan.provider_reach,
                provider_coverage: plan.provider_coverage.clone(),
                items: no_op_bulk_items(plan),
            };
            record.terminal_lifecycle = Some(plan.lifecycle);
            record.terminal_result = Some(result.clone());
            save_bulk_payload(
                &payload_store,
                &mut record_revision,
                &record,
                &plan.operation_id,
            )?;
            finalize_bulk_journal(
                &TransitionJournalStore::new(&self.app_state_root),
                &mut handle,
                plan,
                plan.lifecycle,
                false,
                authority_key,
            )?;
            return Ok(result);
        }

        let native = NativeToggleController::with_session_authority_key(
            &self.app_state_root,
            authority_key.clone(),
        );
        let mut prepared = Vec::new();
        let mut item_results = no_op_bulk_items(plan);
        for item_plan in plan
            .included
            .iter()
            .filter(|item| item.outcome == IncludedTargetOutcome::Applied)
        {
            let item = exact_bulk_item(&fresh_discovery, &item_plan.item)?;
            let native_plan = native.plan_with_reach_for_session(
                item,
                &durable.approval_context,
                durable.principal.connection_boundary,
                provider_reach_input(plan.provider_reach),
                Vec::new(),
                &durable.principal.session_id,
            )?;
            if digest_json(&native_plan.preview)? != item_plan.operation_digest {
                return Err(BulkTogglePlanError::PlanFingerprintMismatch);
            }
            let child_expectation = native_plan.approval_expectation(&durable.approval_context)?;
            let child_authorization = authorization.attenuate_for_bulk_child(
                &expectation,
                &child_expectation,
                &plan.plan_fingerprint,
                &native_plan.plan_fingerprint,
            )?;
            prepared.push((item_plan.item.clone(), native_plan, child_authorization));
        }

        if !prepared.is_empty() {
            record.writes_started = true;
            save_bulk_payload(
                &payload_store,
                &mut record_revision,
                &record,
                &plan.operation_id,
            )?;
        }
        let mut writes_completed = false;
        for (identity, native_plan, child_authorization) in prepared {
            match native.apply_with_reach_aware(
                &native_plan,
                child_authorization,
                &durable.approval_context,
                backup_key.clone(),
                provider_root_binding(&durable.roots, identity.provider)?,
                BULK_TOGGLE_APPROVAL_AUDIENCE,
                durable.issued_at_unix,
                durable.expires_at_unix,
            ) {
                Ok(result) if result.status == ToggleStatus::Applied => {
                    writes_completed = true;
                    item_results.push(BulkToggleItemApplyResult {
                        item: identity,
                        status: result.status,
                        backup_id: result.backup_id,
                        reason: result.reason,
                    });
                }
                Ok(result) => {
                    item_results.push(BulkToggleItemApplyResult {
                        item: identity,
                        status: result.status,
                        backup_id: result.backup_id,
                        reason: result.reason,
                    });
                    let lifecycle = ProviderReachLifecycle::RecoveryRequired;
                    let result = BulkToggleApplyResult {
                        operation_id: plan.operation_id.clone(),
                        plan_fingerprint: plan.plan_fingerprint.clone(),
                        lifecycle,
                        provider_reach: plan.provider_reach,
                        provider_coverage: plan.provider_coverage.clone(),
                        items: item_results,
                    };
                    record.terminal_lifecycle = Some(lifecycle);
                    record.terminal_result = Some(result.clone());
                    save_bulk_payload(
                        &payload_store,
                        &mut record_revision,
                        &record,
                        &plan.operation_id,
                    )?;
                    finalize_bulk_journal(
                        &TransitionJournalStore::new(&self.app_state_root),
                        &mut handle,
                        plan,
                        lifecycle,
                        true,
                        authority_key,
                    )?;
                    return Ok(result);
                }
                Err(error) => {
                    let recovery_required = writes_completed
                        || matches!(error, NativeToggleControlError::RecoveryRequired(_));
                    let lifecycle = if recovery_required {
                        ProviderReachLifecycle::RecoveryRequired
                    } else {
                        ProviderReachLifecycle::Blocked
                    };
                    item_results.push(BulkToggleItemApplyResult {
                        item: identity,
                        status: if recovery_required {
                            ToggleStatus::RecoveryRequired
                        } else {
                            ToggleStatus::Blocked
                        },
                        backup_id: None,
                        reason: Some(error.to_string()),
                    });
                    let result = BulkToggleApplyResult {
                        operation_id: plan.operation_id.clone(),
                        plan_fingerprint: plan.plan_fingerprint.clone(),
                        lifecycle,
                        provider_reach: plan.provider_reach,
                        provider_coverage: plan.provider_coverage.clone(),
                        items: item_results,
                    };
                    record.terminal_lifecycle = Some(lifecycle);
                    record.terminal_result = Some(result.clone());
                    save_bulk_payload(
                        &payload_store,
                        &mut record_revision,
                        &record,
                        &plan.operation_id,
                    )?;
                    finalize_bulk_journal(
                        &TransitionJournalStore::new(&self.app_state_root),
                        &mut handle,
                        plan,
                        lifecycle,
                        record.writes_started,
                        authority_key,
                    )?;
                    return Ok(result);
                }
            }
        }
        item_results.sort_by_key(|item| item.item.key());
        let result = BulkToggleApplyResult {
            operation_id: plan.operation_id.clone(),
            plan_fingerprint: plan.plan_fingerprint.clone(),
            lifecycle: plan.lifecycle,
            provider_reach: plan.provider_reach,
            provider_coverage: plan.provider_coverage.clone(),
            items: item_results,
        };
        record.terminal_lifecycle = Some(plan.lifecycle);
        record.terminal_result = Some(result.clone());
        save_bulk_payload(
            &payload_store,
            &mut record_revision,
            &record,
            &plan.operation_id,
        )?;
        finalize_bulk_journal(
            &TransitionJournalStore::new(&self.app_state_root),
            &mut handle,
            plan,
            plan.lifecycle,
            record.writes_started,
            authority_key,
        )?;
        Ok(result)
    }

    fn verify_reach_aware_context(
        &self,
        plan: &BulkTogglePlan,
        durable: &BulkToggleReachAwareApplyContext,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), BulkTogglePlanError> {
        durable
            .principal
            .verify(authority_key)
            .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
        durable
            .roots
            .verify()
            .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
        let trusted_roots = self
            .trusted_roots
            .as_ref()
            .ok_or(BulkTogglePlanError::ReachAwareAuthorityRequired)?;
        let expectation =
            plan.approval_expectation(&durable.approval_context, &durable.principal.session_id)?;
        if &durable.roots != trusted_roots
            || durable.roots.app_state_root != canonical_existing_path(&self.app_state_root)?
            || durable.audience != BULK_TOGGLE_APPROVAL_AUDIENCE
            || durable.issued_at_unix > durable.now_unix
            || durable.expires_at_unix <= durable.now_unix
            || durable.principal.connection_boundary
                != derived_connection_boundary(plan.provider_reach)
            || durable.principal.connection_scope_id
                != reach_scope_digest(&expectation, &durable.principal.session_id)
        {
            return Err(BulkTogglePlanError::ReachAware(
                "bulk principal or trusted roots do not match reviewed operation".to_string(),
            ));
        }
        let required = plan
            .provider_coverage
            .included()
            .map(|entry| entry.provider)
            .collect::<BTreeSet<_>>();
        let provided = durable
            .roots
            .provider_roots
            .iter()
            .map(|entry| entry.provider)
            .collect::<BTreeSet<_>>();
        if required != provided {
            return Err(BulkTogglePlanError::ReachAware(
                "bulk provider roots do not match included providers".to_string(),
            ));
        }
        Ok(())
    }

    fn bulk_journal_handle(
        &self,
        plan: &BulkTogglePlan,
        durable: &BulkToggleReachAwareApplyContext,
    ) -> Result<JournalHandle, BulkTogglePlanError> {
        let authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(BulkTogglePlanError::ReachAwareAuthorityRequired)?;
        let store = TransitionJournalStore::new(&self.app_state_root);
        let transition = bulk_transition_plan(
            plan,
            &durable.approval_context,
            &durable.principal.session_id,
        )?;
        let owner = bulk_operation_owner(&plan.operation_id, "bulk-journal", 1)?;
        store
            .create_or_attach(&transition, owner)
            .map_err(Into::into)
            .and_then(|handle| {
                handle
                    .journal
                    .reach_aware
                    .as_ref()
                    .ok_or_else(|| {
                        BulkTogglePlanError::ReachAware(
                            "bulk journal is missing reach-aware envelope".to_string(),
                        )
                    })?
                    .verify_authenticated(authority_key)
                    .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
                Ok(handle)
            })
    }
}

fn bulk_transition_plan(
    plan: &BulkTogglePlan,
    context: &ControlApprovalContext,
    session_id: &str,
) -> Result<TransitionPlan, BulkTogglePlanError> {
    plan.verify()?;
    let mut effects = plan
        .included
        .iter()
        .map(|item| {
            let identity_digest =
                crate::encode_lower_hex(&Sha256::digest(item.item.key().as_bytes()));
            let pre_fingerprint = unprefixed_digest(&item.operation_digest)?;
            let post_fingerprint = crate::encode_lower_hex(&Sha256::digest(
                format!(
                    "bulk-toggle-post\0{}\0{}\0{:?}",
                    item.operation_digest, plan.target_enabled, item.outcome
                )
                .as_bytes(),
            ));
            Ok(TransitionEffect {
                effect_id: format!("bulk-toggle-effect-{}", &identity_digest[..24]),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: format!("bulk-toggle-resource-{}", &identity_digest[..24]),
                target_type: "native-provider-state".to_string(),
                summary: "Apply one reviewed bulk native-toggle target".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::RestartRequired,
                expected_pre_fingerprint: Some(pre_fingerprint),
                expected_post_fingerprint: Some(post_fingerprint),
                provider_views: vec![item.item.provider],
            })
        })
        .collect::<Result<Vec<_>, BulkTogglePlanError>>()?;
    if effects.is_empty() {
        let mut provider_views = plan
            .matched
            .iter()
            .map(|item| item.provider)
            .collect::<Vec<_>>();
        provider_views.sort_unstable();
        provider_views.dedup();
        let pre_fingerprint = unprefixed_digest(&plan.plan_fingerprint)?;
        let post_fingerprint = crate::encode_lower_hex(&Sha256::digest(
            format!(
                "bulk-toggle-terminal\0{}\0{}",
                plan.plan_fingerprint,
                plan.lifecycle.as_str()
            )
            .as_bytes(),
        ));
        effects.push(TransitionEffect {
            effect_id: "bulk-toggle-selection-effect".to_string(),
            kind: TransitionEffectKind::ReplaceProviderConfig,
            resource_id: format!("bulk-toggle-selection-{}", &pre_fingerprint[..24]),
            target_type: "native-provider-state".to_string(),
            summary: "Record one reviewed bulk native-toggle selection".to_string(),
            authority: EffectAuthority::UserManaged,
            activation: EffectActivation::RestartRequired,
            expected_pre_fingerprint: Some(pre_fingerprint),
            expected_post_fingerprint: Some(post_fingerprint),
            provider_views,
        });
    }
    TransitionPlan::new(
        plan.operation_id.clone(),
        TransitionKind::BulkToggle,
        TransitionContext {
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            session_id: Some(session_id.to_string()),
            profile_digest: None,
        },
        effects,
    )
    .map_err(Into::into)
}

fn unprefixed_digest(value: &str) -> Result<String, BulkTogglePlanError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if crate::is_lower_hex_digest(digest) {
        Ok(digest.to_string())
    } else {
        Err(BulkTogglePlanError::InvalidPlan)
    }
}

fn bulk_payload_store(app_state_root: &Path, operation_id: &str) -> (PathBuf, AtomicJsonStore) {
    let path = app_state_root
        .join("transactions")
        .join("payloads")
        .join("bulk-toggle")
        .join(format!("{}.json", crate::encode_path_segment(operation_id)));
    let store = AtomicJsonStore::new(path.clone(), BULK_TOGGLE_PLAN_SCHEMA_VERSION);
    (path, store)
}

fn bulk_payload_reference(operation_id: &str) -> String {
    format!(
        "bulk-toggle/{}.json",
        crate::encode_path_segment(operation_id)
    )
}

fn bulk_operation_owner(
    operation_id: &str,
    role: &str,
    generation: u64,
) -> Result<OwnerGeneration, BulkTogglePlanError> {
    let digest = crate::encode_lower_hex(&Sha256::digest(operation_id.as_bytes()));
    OwnerGeneration::new(format!("bulk-{role}-{}", &digest[..32]), generation)
        .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))
}

fn create_or_verify_bulk_payload(
    store: &AtomicJsonStore,
    record: &BulkToggleOperationRecord,
) -> Result<(), BulkTogglePlanError> {
    record.verify()?;
    if let Some(snapshot) = store.load::<BulkToggleOperationRecord>()? {
        snapshot.value.verify()?;
        if snapshot.value.plan == record.plan {
            return Ok(());
        }
        return Err(BulkTogglePlanError::PlanFingerprintMismatch);
    }
    match store.compare_and_swap(
        None,
        bulk_operation_owner(&record.plan.operation_id, "payload", 1)?,
        record,
    ) {
        Ok(_) => Ok(()),
        Err(StateError::StaleRevision { .. }) => {
            let snapshot = store.load::<BulkToggleOperationRecord>()?.ok_or_else(|| {
                BulkTogglePlanError::ReachAware(
                    "bulk family payload disappeared during create".to_string(),
                )
            })?;
            snapshot.value.verify()?;
            if snapshot.value.plan == record.plan {
                Ok(())
            } else {
                Err(BulkTogglePlanError::PlanFingerprintMismatch)
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn save_bulk_payload(
    store: &AtomicJsonStore,
    revision: &mut StateRevision,
    record: &BulkToggleOperationRecord,
    operation_id: &str,
) -> Result<(), BulkTogglePlanError> {
    record.verify()?;
    let generation = revision.sequence.checked_add(1).ok_or_else(|| {
        BulkTogglePlanError::ReachAware("bulk payload generation overflow".to_string())
    })?;
    *revision = store.compare_and_swap(
        Some(revision),
        bulk_operation_owner(operation_id, "payload", generation)?,
        record,
    )?;
    Ok(())
}

fn verify_bulk_envelope(
    handle: &JournalHandle,
    plan: &BulkTogglePlan,
    durable: &BulkToggleReachAwareApplyContext,
    authority_key: &SessionAuthorityKey,
) -> Result<(), BulkTogglePlanError> {
    let envelope = handle.journal.reach_aware.as_ref().ok_or_else(|| {
        BulkTogglePlanError::ReachAware("bulk journal is missing reach-aware envelope".to_string())
    })?;
    envelope
        .verify_authenticated(authority_key)
        .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
    let transition = bulk_transition_plan(
        plan,
        &durable.approval_context,
        &durable.principal.session_id,
    )?;
    let selected_provider = plan.provider_reach.provider().map(|provider| {
        SelectedProviderAuthority::new(
            provider,
            plan.provider_reach
                .provenance()
                .unwrap_or(SelectedProviderProvenance::ExplicitInput),
        )
    });
    let prior_state = plan
        .included
        .iter()
        .map(|item| ReachAwarePriorState {
            target_id: item.item.key(),
            fingerprint: item.operation_digest.clone(),
        })
        .collect::<Vec<_>>();
    let lifecycle_matches = envelope.lifecycle == plan.lifecycle
        || matches!(
            envelope.lifecycle,
            ProviderReachLifecycle::Blocked | ProviderReachLifecycle::RecoveryRequired
        );
    if envelope.family != ReachAwareOperationFamily::BulkToggle
        || envelope.family_schema_version != BULK_TOGGLE_PLAN_SCHEMA_VERSION
        || envelope.operation_id != plan.operation_id
        || envelope.operation_kind != TransitionKind::BulkToggle.as_str()
        || envelope.plan_fingerprint != plan.plan_fingerprint
        || envelope.context.repository_key != transition.context.repository_key
        || envelope.context.workspace_key != transition.context.workspace_key
        || envelope.context.session_id != transition.context.session_id
        || envelope.connection_boundary != durable.principal.connection_boundary
        || envelope.provider_reach != plan.provider_reach
        || envelope.selected_provider != selected_provider
        || envelope.provider_coverage != plan.provider_coverage
        || envelope.expected_lifecycle != plan.lifecycle
        || !lifecycle_matches
        || envelope.activation != EffectActivation::RestartRequired
        || envelope.roots != durable.roots
        || envelope.principal != durable.principal
        || envelope.audience != durable.audience
        || envelope.issued_at_unix != durable.issued_at_unix
        || envelope.expires_at_unix != durable.expires_at_unix
        || envelope.payload_reference
            != (ReachAwarePayloadReference {
                family: ReachAwareOperationFamily::BulkToggle,
                schema_version: BULK_TOGGLE_PLAN_SCHEMA_VERSION,
                reference: bulk_payload_reference(&plan.operation_id),
                payload_digest: plan.plan_fingerprint.clone(),
            })
        || envelope.prior_state != prior_state
        || envelope.transfer_capability.is_some()
    {
        return Err(BulkTogglePlanError::ReachAware(
            "bulk reach-aware journal does not match reviewed operation".to_string(),
        ));
    }
    Ok(())
}

fn finalize_bulk_journal(
    store: &TransitionJournalStore,
    handle: &mut JournalHandle,
    plan: &BulkTogglePlan,
    lifecycle: ProviderReachLifecycle,
    writes_started: bool,
    authority_key: &SessionAuthorityKey,
) -> Result<(), BulkTogglePlanError> {
    if handle.journal.lifecycle.is_terminal() {
        let envelope = handle.journal.reach_aware.as_ref().ok_or_else(|| {
            BulkTogglePlanError::ReachAware(
                "terminal bulk journal is missing reach-aware envelope".to_string(),
            )
        })?;
        envelope
            .verify_authenticated(authority_key)
            .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
        if envelope.lifecycle == lifecycle {
            return Ok(());
        }
        return Err(BulkTogglePlanError::ReachAware(
            "terminal bulk journal lifecycle does not match result".to_string(),
        ));
    }
    {
        let envelope = handle.journal.reach_aware.as_mut().ok_or_else(|| {
            BulkTogglePlanError::ReachAware(
                "bulk journal is missing reach-aware envelope".to_string(),
            )
        })?;
        envelope.lifecycle = lifecycle;
        envelope.recovery = Some(ReachAwareRecoveryEvidence {
            writes_started,
            recovery_reference: writes_started
                .then(|| format!("bulk-toggle/operations/{}", plan.operation_id)),
            affected_resources: if writes_started {
                plan.included
                    .iter()
                    .filter(|item| item.outcome == IncludedTargetOutcome::Applied)
                    .map(|item| item.item.key())
                    .collect()
            } else {
                Vec::new()
            },
        });
        envelope.envelope_fingerprint = envelope
            .fingerprint()
            .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
        envelope
            .seal(authority_key)
            .map_err(|error| BulkTogglePlanError::ReachAware(error.to_string()))?;
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

fn request_from_reviewed(plan: &BulkTogglePlan, boundary: ConnectionBoundary) -> BulkToggleRequest {
    BulkToggleRequest {
        selector: plan.selector.clone(),
        target_enabled: plan.target_enabled,
        allow_empty_selection: plan.allow_empty_selection,
        acknowledge_whole_inventory: plan.acknowledgement.acknowledged,
        boundary,
        reach: provider_reach_input(plan.provider_reach),
        authority_candidates: Vec::new(),
    }
}

fn blocked_bulk_result(plan: &BulkTogglePlan, reason: &str) -> BulkToggleApplyResult {
    let mut items = no_op_bulk_items(plan);
    let existing = items
        .iter()
        .map(|item| item.item.key())
        .collect::<BTreeSet<_>>();
    items.extend(
        plan.included
            .iter()
            .filter(|item| !existing.contains(&item.item.key()))
            .map(|item| BulkToggleItemApplyResult {
                item: item.item.clone(),
                status: ToggleStatus::Blocked,
                backup_id: None,
                reason: Some(reason.to_string()),
            }),
    );
    items.sort_by_key(|item| item.item.key());
    BulkToggleApplyResult {
        operation_id: plan.operation_id.clone(),
        plan_fingerprint: plan.plan_fingerprint.clone(),
        lifecycle: ProviderReachLifecycle::Blocked,
        provider_reach: plan.provider_reach,
        provider_coverage: plan.provider_coverage.clone(),
        items,
    }
}

fn no_op_bulk_items(plan: &BulkTogglePlan) -> Vec<BulkToggleItemApplyResult> {
    let include_unwritten = !matches!(
        plan.lifecycle,
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial
    );
    let mut items = plan
        .included
        .iter()
        .filter(|item| item.outcome == IncludedTargetOutcome::NoOp || include_unwritten)
        .map(|item| BulkToggleItemApplyResult {
            item: item.item.clone(),
            status: if item.outcome == IncludedTargetOutcome::NoOp {
                ToggleStatus::DryRun
            } else {
                ToggleStatus::Blocked
            },
            backup_id: None,
            reason: Some(if item.outcome == IncludedTargetOutcome::NoOp {
                "already-in-desired-state".to_string()
            } else {
                "operation-blocked-before-provider-writes".to_string()
            }),
        })
        .chain(plan.blocked.iter().map(|item| BulkToggleItemApplyResult {
            item: item.item.clone(),
            status: ToggleStatus::Blocked,
            backup_id: None,
            reason: Some(item.reason_code.clone()),
        }))
        .collect::<Vec<_>>();
    items.sort_by_key(|item| item.item.key());
    items
}

fn exact_bulk_item(
    discovery: &DiscoveryOutput,
    identity: &BulkItemIdentity,
) -> Result<DiscoveryItem, BulkTogglePlanError> {
    let mut matches = discovery.items.iter().filter(|item| {
        item.provider == identity.provider
            && item.kind == identity.kind
            && item.category == identity.category
            && item.layer == identity.layer
            && item.id == identity.id
    });
    let item = matches.next().ok_or_else(|| {
        BulkTogglePlanError::ReachAware(format!(
            "bulk item disappeared before apply: {}",
            identity.key()
        ))
    })?;
    if matches.next().is_some() {
        return Err(BulkTogglePlanError::DuplicateIdentity(identity.key()));
    }
    Ok(item.clone())
}

const fn provider_reach_input(provider_reach: ProviderReach) -> ProviderReachInput {
    match provider_reach {
        ProviderReach::All => ProviderReachInput::All,
        ProviderReach::Selected {
            provider,
            provenance,
        } => ProviderReachInput::Selected {
            provider,
            provenance,
        },
    }
}

fn provider_root_binding(
    roots: &ReachAwareRootBinding,
    provider: ProviderId,
) -> Result<ReachAwareRootBinding, BulkTogglePlanError> {
    let provider_root = roots
        .provider_roots
        .iter()
        .find(|root| root.provider == provider)
        .cloned()
        .ok_or_else(|| {
            BulkTogglePlanError::ReachAware(format!(
                "trusted root is missing for provider {}",
                provider.as_str()
            ))
        })?;
    Ok(ReachAwareRootBinding {
        app_state_root: roots.app_state_root.clone(),
        provider_roots: vec![provider_root],
        provenance: roots.provenance.clone(),
    })
}

fn canonical_existing_path(path: &Path) -> Result<String, BulkTogglePlanError> {
    std::fs::canonicalize(path)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| {
            BulkTogglePlanError::ReachAware(format!("bulk app-state root is unavailable: {error}"))
        })
}

const fn derived_connection_boundary(provider_reach: ProviderReach) -> ConnectionBoundary {
    match provider_reach {
        ProviderReach::Selected {
            provider,
            provenance: SelectedProviderProvenance::PinnedMcpBoundary,
        } => ConnectionBoundary::Pinned(provider),
        ProviderReach::All | ProviderReach::Selected { .. } => ConnectionBoundary::All,
    }
}

/// Stable scope identifier used to bind a reach-aware handoff to its
/// repository/workspace/session authority tuple.
pub fn reach_scope_digest(expectation: &ApprovalExpectation, session_id: &str) -> String {
    crate::encode_lower_hex(&Sha256::digest(
        format!(
            "{}\0{}\0{}",
            expectation.repository_key, expectation.workspace_key, session_id
        )
        .as_bytes(),
    ))
}

fn bulk_result_matches_plan(result: &BulkToggleApplyResult, plan: &BulkTogglePlan) -> bool {
    if result.operation_id != plan.operation_id
        || result.plan_fingerprint != plan.plan_fingerprint
        || result.provider_reach != plan.provider_reach
        || result.provider_coverage != plan.provider_coverage
    {
        return false;
    }
    let matched = plan
        .matched_identities()
        .into_iter()
        .map(|item| item.key())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    result
        .items
        .iter()
        .all(|item| matched.contains(&item.item.key()) && seen.insert(item.item.key()))
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
