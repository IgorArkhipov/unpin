//! Shared provider authority, reach filtering, and lifecycle classification.
//!
//! This module deliberately operates on targets that have already been derived by
//! an operation-specific planner.  It never discovers, clones, or synthesizes a
//! target for a provider that was not present in the derived set.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    control_operation::{ControlOperationEnvelope, ControlOperationLifecycle},
    discovery::DiscoveryItem,
    groups::GroupMemberIdentity,
    providers::ProviderId,
};

/// Schema version for reach-aware operation projections and fingerprint material.
pub const PROVIDER_REACH_SCHEMA_VERSION: u32 = 2;

/// The connection boundary is an authorization boundary, not an operation reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionBoundary {
    All,
    Pinned(ProviderId),
}

impl ConnectionBoundary {
    #[allow(non_upper_case_globals)]
    pub const AllProviders: Self = Self::All;

    #[must_use]
    pub const fn pinned(provider: ProviderId) -> Self {
        Self::Pinned(provider)
    }

    #[must_use]
    pub const fn provider(self) -> Option<ProviderId> {
        match self {
            Self::All => None,
            Self::Pinned(provider) => Some(provider),
        }
    }

    #[must_use]
    pub fn allows(self, provider: ProviderId) -> bool {
        match self {
            Self::All => true,
            Self::Pinned(allowed) => allowed == provider,
        }
    }
}

/// The source that established selected-provider authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectedProviderProvenance {
    ExplicitInput,
    TuiControl,
    PinnedMcpBoundary,
    ExactIndividualTarget,
}

impl SelectedProviderProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitInput => "explicit-input",
            Self::TuiControl => "tui-control",
            Self::PinnedMcpBoundary => "pinned-mcp-boundary",
            Self::ExactIndividualTarget => "exact-individual-target",
        }
    }
}

/// A provider authority candidate established by an operation boundary or
/// explicit operation input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedProviderAuthority {
    pub provider: ProviderId,
    pub provenance: SelectedProviderProvenance,
}

impl SelectedProviderAuthority {
    #[must_use]
    pub const fn new(provider: ProviderId, provenance: SelectedProviderProvenance) -> Self {
        Self {
            provider,
            provenance,
        }
    }
}

/// The reach requested by an operation before target derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderReachInput {
    Omitted,
    All,
    Selected {
        provider: ProviderId,
        provenance: SelectedProviderProvenance,
    },
}

impl ProviderReachInput {
    #[allow(non_upper_case_globals)]
    pub const AllProviders: Self = Self::All;

    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    #[must_use]
    pub const fn selected(provider: ProviderId, provenance: SelectedProviderProvenance) -> Self {
        Self::Selected {
            provider,
            provenance,
        }
    }

    #[must_use]
    pub const fn omitted() -> Self {
        Self::Omitted
    }
}

/// Operation-specific derivation kind.  Exact-target reconciliation applies
/// only to `Individual`; providers observed in other kinds are coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivedTargetKind {
    Individual,
    Group,
    Bulk,
    Profile,
}

/// Canonical provider reach used by a reviewed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderReach {
    All,
    Selected {
        provider: ProviderId,
        provenance: SelectedProviderProvenance,
    },
}

impl ProviderReach {
    #[allow(non_upper_case_globals)]
    pub const AllProviders: Self = Self::All;

    #[must_use]
    pub const fn all() -> Self {
        Self::All
    }

    #[must_use]
    pub const fn selected(provider: ProviderId, provenance: SelectedProviderProvenance) -> Self {
        Self::Selected {
            provider,
            provenance,
        }
    }

    #[must_use]
    pub const fn provider(self) -> Option<ProviderId> {
        match self {
            Self::All => None,
            Self::Selected { provider, .. } => Some(provider),
        }
    }

    #[must_use]
    pub const fn provenance(self) -> Option<SelectedProviderProvenance> {
        match self {
            Self::All => None,
            Self::Selected { provenance, .. } => Some(provenance),
        }
    }

    #[must_use]
    pub fn allows(self, provider: ProviderId) -> bool {
        match self {
            Self::All => true,
            Self::Selected {
                provider: selected, ..
            } => selected == provider,
        }
    }
}

/// Input to the two-phase authority resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReachRequest {
    pub boundary: ConnectionBoundary,
    pub reach: ProviderReachInput,
    pub target_kind: DerivedTargetKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_candidates: Vec<SelectedProviderAuthority>,
}

impl ProviderReachRequest {
    #[must_use]
    pub fn new(
        boundary: ConnectionBoundary,
        reach: ProviderReachInput,
        target_kind: DerivedTargetKind,
    ) -> Self {
        Self {
            boundary,
            reach,
            target_kind,
            authority_candidates: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_authority(mut self, authority: SelectedProviderAuthority) -> Self {
        self.authority_candidates.push(authority);
        self
    }

    /// Validate all authority that is available before provider discovery.
    pub fn validate_before_discovery(self) -> Result<ProviderReachPreflight, ProviderReachError> {
        let mut candidates = self.authority_candidates;
        if let ProviderReachInput::Selected {
            provider,
            provenance,
        } = self.reach
        {
            candidates.push(SelectedProviderAuthority::new(provider, provenance));
        }

        let pinned_provider = self.boundary.provider();
        if matches!(self.reach, ProviderReachInput::All) {
            if let Some(provider) = pinned_provider {
                return Err(ProviderReachError::BoundaryWidening { provider });
            }
        }

        let mut authority: Option<SelectedProviderAuthority> = None;
        for candidate in candidates {
            if let Some(boundary_provider) = pinned_provider
                && candidate.provider != boundary_provider
            {
                return Err(ProviderReachError::BoundaryConflict {
                    boundary: boundary_provider,
                    requested: candidate.provider,
                });
            }
            if let Some(existing) = authority
                && existing.provider != candidate.provider
            {
                return Err(ProviderReachError::ConflictingAuthority {
                    first: existing.provider,
                    second: candidate.provider,
                });
            }
            authority = Some(match authority {
                None => candidate,
                Some(existing) => existing.min(candidate),
            });
        }

        let authority = pinned_provider.map_or(authority, |provider| {
            Some(SelectedProviderAuthority::new(
                provider,
                SelectedProviderProvenance::PinnedMcpBoundary,
            ))
        });

        let resolved_reach = match self.reach {
            ProviderReachInput::All => Some(ProviderReach::All),
            ProviderReachInput::Selected {
                provider,
                provenance,
            } => Some(ProviderReach::selected(
                provider,
                pinned_provider.map_or(provenance, |_| {
                    SelectedProviderProvenance::PinnedMcpBoundary
                }),
            )),
            ProviderReachInput::Omitted => authority
                .map(|authority| ProviderReach::selected(authority.provider, authority.provenance)),
        };

        if resolved_reach.is_none() && self.target_kind != DerivedTargetKind::Individual {
            return Err(ProviderReachError::MissingSelectedProvider);
        }

        Ok(ProviderReachPreflight {
            boundary: self.boundary,
            target_kind: self.target_kind,
            reach: resolved_reach,
            authority,
        })
    }
}

/// Validated boundary state held until operation-specific target derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReachPreflight {
    pub boundary: ConnectionBoundary,
    pub target_kind: DerivedTargetKind,
    pub reach: Option<ProviderReach>,
    pub authority: Option<SelectedProviderAuthority>,
}

impl ProviderReachPreflight {
    /// Reconcile an exact target's provider after derivation.  Group, bulk, and
    /// profile providers are intentionally ignored here and remain coverage.
    pub fn reconcile_exact_target(
        self,
        exact_provider: Option<ProviderId>,
    ) -> Result<ProviderReachResolution, ProviderReachError> {
        if self.target_kind != DerivedTargetKind::Individual {
            return Ok(ProviderReachResolution {
                reach: self
                    .reach
                    .expect("non-individual reach was validated before discovery"),
                selected_provider: self.authority,
            });
        }

        let Some(target_provider) = exact_provider else {
            return Err(ProviderReachError::MissingExactTargetProvider);
        };
        if !self.boundary.allows(target_provider) {
            return Err(ProviderReachError::BoundaryConflict {
                boundary: self
                    .boundary
                    .provider()
                    .expect("a disallowed target implies a pinned boundary"),
                requested: target_provider,
            });
        }

        if let Some(authority) = self.authority
            && authority.provider != target_provider
        {
            return Err(ProviderReachError::ExactTargetConflict {
                selected: authority.provider,
                target: target_provider,
            });
        }

        let reach = self.reach.unwrap_or_else(|| {
            ProviderReach::selected(
                target_provider,
                SelectedProviderProvenance::ExactIndividualTarget,
            )
        });
        let selected_provider = self.authority.or_else(|| {
            (reach.provider() == Some(target_provider)).then(|| {
                SelectedProviderAuthority::new(
                    target_provider,
                    reach
                        .provenance()
                        .unwrap_or(SelectedProviderProvenance::ExactIndividualTarget),
                )
            })
        });
        Ok(ProviderReachResolution {
            reach,
            selected_provider,
        })
    }
}

/// Fully resolved operation reach and its selected-provider authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderReachResolution {
    pub reach: ProviderReach,
    pub selected_provider: Option<SelectedProviderAuthority>,
}

impl ProviderReachResolution {
    #[must_use]
    pub const fn reach(&self) -> &ProviderReach {
        &self.reach
    }
}

/// Errors raised before a reviewed plan can be produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "code", content = "details")]
pub enum ProviderReachError {
    BoundaryWidening {
        provider: ProviderId,
    },
    BoundaryConflict {
        boundary: ProviderId,
        requested: ProviderId,
    },
    ConflictingAuthority {
        first: ProviderId,
        second: ProviderId,
    },
    MissingSelectedProvider,
    MissingExactTargetProvider,
    ExactTargetConflict {
        selected: ProviderId,
        target: ProviderId,
    },
}

impl fmt::Display for ProviderReachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryWidening { provider } => write!(
                formatter,
                "all-provider reach would widen pinned connection boundary {}",
                provider.as_str()
            ),
            Self::BoundaryConflict {
                boundary,
                requested,
            } => write!(
                formatter,
                "provider {} conflicts with pinned connection boundary {}",
                requested.as_str(),
                boundary.as_str()
            ),
            Self::ConflictingAuthority { first, second } => write!(
                formatter,
                "selected-provider authority conflicts: {} versus {}",
                first.as_str(),
                second.as_str()
            ),
            Self::MissingSelectedProvider => {
                formatter.write_str("selected provider is required when provider reach is omitted")
            }
            Self::MissingExactTargetProvider => {
                formatter.write_str("exact individual target has no provider identity")
            }
            Self::ExactTargetConflict { selected, target } => write!(
                formatter,
                "selected provider {} conflicts with exact target provider {}",
                selected.as_str(),
                target.as_str()
            ),
        }
    }
}

impl std::error::Error for ProviderReachError {}

/// A provider-qualified target that can be used directly with the reach filter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReachTarget {
    pub provider: ProviderId,
    pub target_id: String,
}

impl ProviderReachTarget {
    #[must_use]
    pub fn new(provider: ProviderId, target_id: impl Into<String>) -> Self {
        Self {
            provider,
            target_id: target_id.into(),
        }
    }
}

/// Provider-qualified target adapter used by operation-specific planners.
pub trait ProviderQualified {
    fn provider_id(&self) -> ProviderId;
    fn target_id(&self) -> &str;
}

impl ProviderQualified for ProviderReachTarget {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn target_id(&self) -> &str {
        &self.target_id
    }
}

impl ProviderQualified for DiscoveryItem {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn target_id(&self) -> &str {
        &self.id
    }
}

impl ProviderQualified for GroupMemberIdentity {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn target_id(&self) -> &str {
        &self.id
    }
}

/// Closed reason vocabulary for target coverage and exclusions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderReachReason {
    OutOfProviderReach,
    Missing,
    ReadOnly,
    Blocked,
    Protected,
    NonMemberFanOut,
    SharedSourceCrossesProviderReach,
}

impl ProviderReachReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutOfProviderReach => "out-of-provider-reach",
            Self::Missing => "missing",
            Self::ReadOnly => "read-only",
            Self::Blocked => "blocked",
            Self::Protected => "protected",
            Self::NonMemberFanOut => "non-member-fan-out",
            Self::SharedSourceCrossesProviderReach => "shared-source-crosses-provider-reach",
        }
    }
}

/// One canonical provider-qualified coverage record.  `included` preserves the
/// full derived set in the reviewed plan; an excluded record always carries a
/// closed reason code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCoverageEntry {
    pub provider: ProviderId,
    pub target_id: String,
    pub included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ProviderReachReason>,
}

impl ProviderCoverageEntry {
    #[must_use]
    pub fn included(provider: ProviderId, target_id: impl Into<String>) -> Self {
        Self {
            provider,
            target_id: target_id.into(),
            included: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn excluded(provider: ProviderId, target_id: impl Into<String>) -> Self {
        Self {
            provider,
            target_id: target_id.into(),
            included: false,
            reason: Some(ProviderReachReason::OutOfProviderReach),
        }
    }

    #[must_use]
    pub const fn is_excluded(&self) -> bool {
        !self.included
    }

    #[must_use]
    pub const fn is_reach_exclusion(&self) -> bool {
        self.is_excluded() && matches!(self.reason, Some(ProviderReachReason::OutOfProviderReach))
    }
}

/// Coverage collection with deterministic ordering for plans and fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReachCoverage {
    pub entries: Vec<ProviderCoverageEntry>,
}

impl ProviderReachCoverage {
    #[must_use]
    pub fn new(mut entries: Vec<ProviderCoverageEntry>) -> Self {
        entries.sort();
        entries.dedup();
        Self { entries }
    }

    #[must_use]
    pub fn entries(&self) -> &[ProviderCoverageEntry] {
        &self.entries
    }

    #[must_use]
    pub fn included(&self) -> impl Iterator<Item = &ProviderCoverageEntry> {
        self.entries.iter().filter(|entry| entry.included)
    }

    #[must_use]
    pub fn excluded(&self) -> impl Iterator<Item = &ProviderCoverageEntry> {
        self.entries.iter().filter(|entry| entry.is_excluded())
    }
}

impl From<Vec<ProviderCoverageEntry>> for ProviderReachCoverage {
    fn from(entries: Vec<ProviderCoverageEntry>) -> Self {
        Self::new(entries)
    }
}

/// Filter result retaining included target values and complete provider coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredProviderTargets<T> {
    pub included: Vec<T>,
    pub excluded: Vec<ProviderCoverageEntry>,
    pub coverage: ProviderReachCoverage,
}

impl<T> FilteredProviderTargets<T> {
    #[must_use]
    pub fn no_targets_in_reach(&self) -> bool {
        self.included.is_empty() && !self.excluded.is_empty()
    }
}

/// Filter an already-derived target set.  This function does not call discovery
/// and does not create counterpart targets.
pub fn filter_derived_targets<T, I>(reach: &ProviderReach, targets: I) -> FilteredProviderTargets<T>
where
    T: ProviderQualified,
    I: IntoIterator<Item = T>,
{
    let mut included = Vec::new();
    let mut coverage = Vec::new();
    for target in targets {
        let provider = target.provider_id();
        let target_id = target.target_id().to_string();
        if reach.allows(provider) {
            coverage.push(ProviderCoverageEntry::included(provider, target_id));
            included.push(target);
        } else {
            coverage.push(ProviderCoverageEntry::excluded(provider, target_id));
        }
    }
    let coverage = ProviderReachCoverage::new(coverage);
    let excluded = coverage.excluded().cloned().collect();
    FilteredProviderTargets {
        included,
        excluded,
        coverage,
    }
}

/// Outcome of one included target after preflight/apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncludedTargetOutcome {
    Applied,
    NoOp,
    Blocked,
    Failed,
}

/// Evidence consumed by canonical lifecycle classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvidence {
    pub included_outcomes: Vec<IncludedTargetOutcome>,
    pub coverage: ProviderReachCoverage,
    pub writes_started: bool,
}

impl LifecycleEvidence {
    #[must_use]
    pub fn new(
        included_outcomes: Vec<IncludedTargetOutcome>,
        coverage: Vec<ProviderCoverageEntry>,
        writes_started: bool,
    ) -> Self {
        Self {
            included_outcomes,
            coverage: ProviderReachCoverage::new(coverage),
            writes_started,
        }
    }

    #[must_use]
    pub fn from_filter<T>(
        filter: &FilteredProviderTargets<T>,
        included_outcomes: Vec<IncludedTargetOutcome>,
        writes_started: bool,
    ) -> Self {
        Self {
            included_outcomes,
            coverage: filter.coverage.clone(),
            writes_started,
        }
    }
}

/// Canonical terminal lifecycle classification for reach-aware operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderReachLifecycle {
    Applied,
    Partial,
    NoOp,
    NoTargetsInProviderReach,
    Blocked,
    RecoveryRequired,
}

impl ProviderReachLifecycle {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Partial => "partial",
            Self::NoOp => "no-op",
            Self::NoTargetsInProviderReach => "no-targets-in-provider-reach",
            Self::Blocked => "blocked",
            Self::RecoveryRequired => "recovery-required",
        }
    }
}

/// Classify all included work and provider-reach exclusions in one place.
#[must_use]
pub fn classify_lifecycle(evidence: &LifecycleEvidence) -> ProviderReachLifecycle {
    let has_exclusions = evidence
        .coverage
        .excluded()
        .any(ProviderCoverageEntry::is_reach_exclusion);
    let has_nonreach_exclusions = evidence
        .coverage
        .excluded()
        .any(|entry| !entry.is_reach_exclusion());
    let has_blocker = evidence.included_outcomes.iter().any(|outcome| {
        matches!(
            outcome,
            IncludedTargetOutcome::Blocked | IncludedTargetOutcome::Failed
        )
    });

    if has_blocker {
        return if evidence.writes_started {
            ProviderReachLifecycle::RecoveryRequired
        } else {
            ProviderReachLifecycle::Blocked
        };
    }
    if has_nonreach_exclusions {
        return if evidence.writes_started {
            ProviderReachLifecycle::RecoveryRequired
        } else {
            ProviderReachLifecycle::Blocked
        };
    }
    if evidence.included_outcomes.is_empty() {
        return if has_exclusions {
            ProviderReachLifecycle::NoTargetsInProviderReach
        } else {
            ProviderReachLifecycle::Blocked
        };
    }
    if has_exclusions {
        return ProviderReachLifecycle::Partial;
    }
    if evidence
        .included_outcomes
        .iter()
        .all(|outcome| *outcome == IncludedTargetOutcome::NoOp)
    {
        ProviderReachLifecycle::NoOp
    } else {
        ProviderReachLifecycle::Applied
    }
}

/// Canonical material bound into reach-aware plan fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderReachFingerprintMaterial {
    pub schema_version: u32,
    pub provider_reach: ProviderReach,
    pub coverage: ProviderReachCoverage,
}

#[must_use]
pub fn provider_reach_fingerprint_material(
    reach: &ProviderReach,
    coverage: &[ProviderCoverageEntry],
) -> ProviderReachFingerprintMaterial {
    ProviderReachFingerprintMaterial {
        schema_version: PROVIDER_REACH_SCHEMA_VERSION,
        provider_reach: *reach,
        coverage: ProviderReachCoverage::new(coverage.to_vec()),
    }
}

#[must_use]
pub fn provider_reach_fingerprint(
    reach: &ProviderReach,
    coverage: &[ProviderCoverageEntry],
) -> String {
    let material = provider_reach_fingerprint_material(reach, coverage);
    let encoded = serde_json::to_vec(&material).expect("reach fingerprint material serializes");
    let digest = Sha256::digest(encoded);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Reach-aware schema-v2 projection layered around the unchanged schema-v1
/// control-operation envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderReachOperationProjection {
    pub schema_version: u32,
    pub operation: ControlOperationEnvelope,
    pub provider_reach: ProviderReach,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<ProviderId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider_provenance: Option<SelectedProviderProvenance>,
    pub coverage: ProviderReachCoverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<ProviderReachLifecycle>,
    pub reach_fingerprint: String,
}

impl ProviderReachOperationProjection {
    #[must_use]
    pub fn from_envelope<C>(
        operation: &ControlOperationEnvelope,
        provider_reach: ProviderReach,
        coverage: C,
    ) -> Self
    where
        C: Into<ProviderReachCoverage>,
    {
        let coverage = coverage.into();
        let has_reach_exclusions = coverage
            .excluded()
            .any(ProviderCoverageEntry::is_reach_exclusion);
        let has_nonreach_exclusions = coverage.excluded().any(|entry| !entry.is_reach_exclusion());
        let lifecycle = match operation.lifecycle {
            ControlOperationLifecycle::Applied | ControlOperationLifecycle::NoOp
                if has_nonreach_exclusions =>
            {
                Some(ProviderReachLifecycle::Blocked)
            }
            ControlOperationLifecycle::Applied | ControlOperationLifecycle::NoOp
                if has_reach_exclusions =>
            {
                Some(ProviderReachLifecycle::Partial)
            }
            ControlOperationLifecycle::Applied => Some(ProviderReachLifecycle::Applied),
            ControlOperationLifecycle::NoOp => Some(ProviderReachLifecycle::NoOp),
            ControlOperationLifecycle::Blocked => Some(ProviderReachLifecycle::Blocked),
            ControlOperationLifecycle::RecoveryRequired => {
                Some(ProviderReachLifecycle::RecoveryRequired)
            }
            ControlOperationLifecycle::Planned | ControlOperationLifecycle::AwaitingHumanAction => {
                None
            }
        };
        Self::new(operation.clone(), provider_reach, coverage, lifecycle)
    }

    #[must_use]
    pub fn new(
        operation: ControlOperationEnvelope,
        provider_reach: ProviderReach,
        coverage: ProviderReachCoverage,
        lifecycle: Option<ProviderReachLifecycle>,
    ) -> Self {
        let coverage = ProviderReachCoverage::new(coverage.entries);
        let selected_provider = provider_reach.provider();
        let selected_provider_provenance = provider_reach.provenance();
        let reach_fingerprint = provider_reach_fingerprint(&provider_reach, &coverage.entries);
        Self {
            schema_version: PROVIDER_REACH_SCHEMA_VERSION,
            operation,
            provider_reach,
            selected_provider,
            selected_provider_provenance,
            coverage,
            lifecycle,
            reach_fingerprint,
        }
    }
}
