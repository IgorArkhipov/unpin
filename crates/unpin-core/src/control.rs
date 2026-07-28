use std::{collections::BTreeMap, fmt, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    bridges::{
        BridgeError, BridgeInstaller, BridgeStatus, HookBridgeAdapter, HookCoverageStatus,
        hook_bridge_descriptor,
    },
    catalog::{CapabilityKind, Catalog},
    control_operation::{
        ReachAwareControlOperationEnvelope, ReachAwareEnvelopeError, ReachAwareOperationFamily,
        ReachAwarePrincipal, ReachAwareRecoveryEvidence, ReachAwareTransferCapability,
    },
    discovery::DiscoveryOutput,
    profiles::{PolicyStore, ProfileDefinitionEntry, ProfileStore, ResolutionPolicies},
    provider_reach::{
        ConnectionBoundary, ProviderReach, ProviderReachCoverage, ProviderReachLifecycle,
        SelectedProviderAuthority,
    },
    providers::ProviderId,
    sessions::{
        CoverageLevel, GatewayModeManager, GatewayModeState, GatewayModeTarget, IsolationLevel,
        LeaseLifecycle, LiveExposureStatus, SessionAuthorityKey, SessionManager,
    },
    state::workspace::{WorkspaceIdentity, resolve_workspace_identity},
    transitions::{JournalEvent, TransitionJournal},
};

pub const CONTROL_STATUS_SCHEMA_VERSION: u32 = 1;
pub const REACH_AWARE_STATUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlStatus {
    pub schema_version: u32,
    pub repository_key: String,
    pub workspace_key: String,
    pub catalog: CatalogControlSummary,
    pub profiles: Vec<ProfileDefinitionEntry>,
    pub policies: ResolutionPolicies,
    pub gateways: Vec<GatewayControlStatus>,
    pub sessions: Vec<SessionControlStatus>,
    pub operations: Vec<ControlOperationStatus>,
    pub hooks: Vec<HookControlCoverage>,
}

impl ControlStatus {
    #[must_use]
    pub fn persistent_metadata(&self) -> PersistentControlMetadata {
        PersistentControlMetadata {
            schema_version: CONTROL_STATUS_SCHEMA_VERSION,
            catalog: self.catalog.clone(),
            profiles: self.profiles.clone(),
            policies: self.policies.clone(),
            hooks: self.hooks.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogControlSummary {
    pub total: usize,
    pub active: usize,
    pub by_kind: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayControlStatus {
    pub provider: ProviderId,
    pub target: GatewayModeTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<GatewayModeState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionControlStatus {
    pub session_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub profile_digest: Option<String>,
    pub desired_exposure_revision: String,
    pub observed_exposure_revision: String,
    pub live_status: LiveExposureStatus,
    pub isolation: IsolationLevel,
    pub coverage: CoverageLevel,
    pub lifecycle: LeaseLifecycle,
    pub in_flight_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlOperationStatus {
    pub operation_id: String,
    pub operation_kind: String,
    pub lifecycle: crate::transitions::TransitionLifecycle,
    pub effect_graph_digest: String,
    pub authorization_recorded: bool,
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_code: Option<String>,
    pub recovery_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach_aware: Option<ReachAwareOperationStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareOperationStatus {
    pub schema_version: u32,
    pub operation_id: String,
    pub operation_kind: String,
    pub family: ReachAwareOperationFamily,
    pub lifecycle: ProviderReachLifecycle,
    pub expected_lifecycle: ProviderReachLifecycle,
    pub provider_reach: ProviderReach,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<SelectedProviderAuthority>,
    pub provider_coverage: ProviderReachCoverage,
    pub excluded_provider_counts: BTreeMap<ProviderId, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<ReachAwareRecoveryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_code: Option<String>,
    pub audit: Vec<JournalEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachAwareStatusAuthorization {
    pub principal: ReachAwarePrincipal,
    pub audience: String,
    pub capability_scope_digest: String,
    pub now_unix: i64,
    pub transfer_capability: Option<ReachAwareTransferCapability>,
}

impl ReachAwareStatusAuthorization {
    #[must_use]
    pub fn new(
        principal: ReachAwarePrincipal,
        audience: impl Into<String>,
        capability_scope_digest: impl Into<String>,
        now_unix: i64,
        transfer_capability: Option<ReachAwareTransferCapability>,
    ) -> Self {
        Self {
            principal,
            audience: audience.into(),
            capability_scope_digest: capability_scope_digest.into(),
            now_unix,
            transfer_capability,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReachAwareStatusFilter {
    pub operation_id: Option<String>,
    pub family: Option<ReachAwareOperationFamily>,
    pub lifecycle: Option<ProviderReachLifecycle>,
    pub provider: Option<ProviderId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookControlCoverage {
    pub provider: ProviderId,
    pub adapter: HookBridgeAdapter,
    pub built_in_tools: HookCoverageStatus,
    pub gateway_mcp_tools: HookCoverageStatus,
    pub native_events: Vec<String>,
    pub managed_asset: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_bridge_installations: Vec<BridgeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistentControlMetadata {
    pub schema_version: u32,
    pub catalog: CatalogControlSummary,
    pub profiles: Vec<ProfileDefinitionEntry>,
    pub policies: ResolutionPolicies,
    pub hooks: Vec<HookControlCoverage>,
}

pub fn build_control_status(
    discovery: &DiscoveryOutput,
    app_state_root: &Path,
    project_root: &Path,
    session_authority_key: &SessionAuthorityKey,
) -> Result<ControlStatus, ControlStatusError> {
    let identity = resolve_workspace_identity(project_root)?;
    let persistent = build_persistent_control_metadata_with_identity(
        discovery,
        app_state_root,
        project_root,
        Some(&identity),
    )?;
    let sessions =
        SessionManager::with_authority_key(app_state_root, session_authority_key.clone());
    let modes = GatewayModeManager::new(app_state_root, sessions.clone());
    let gateways = ProviderId::ALL
        .into_iter()
        .map(|provider| {
            let target = GatewayModeTarget::workspace_provider(
                &identity.repository_key,
                &identity.workspace_key,
                provider,
            )?;
            let mode = modes.load(&target)?.map(|snapshot| snapshot.mode);
            Ok(GatewayControlStatus {
                provider,
                target,
                mode,
            })
        })
        .collect::<Result<Vec<_>, crate::sessions::LeaseError>>()?;
    let sessions = sessions
        .list()?
        .into_iter()
        .filter(|snapshot| {
            snapshot.lease.repository_key == identity.repository_key
                && snapshot.lease.workspace_key == identity.workspace_key
        })
        .map(|snapshot| SessionControlStatus {
            session_id: snapshot.lease.session_id,
            provider: snapshot.lease.provider,
            repository_key: snapshot.lease.repository_key,
            workspace_key: snapshot.lease.workspace_key,
            profile_digest: snapshot
                .lease
                .desired_exposure
                .profile
                .digest()
                .map(str::to_string),
            desired_exposure_revision: snapshot.lease.desired_exposure.revision,
            observed_exposure_revision: snapshot.lease.observed_exposure.revision,
            live_status: snapshot.lease.live_status,
            isolation: snapshot.lease.isolation,
            coverage: snapshot.lease.coverage,
            lifecycle: snapshot.lease.lifecycle,
            in_flight_calls: snapshot.lease.in_flight_calls,
        })
        .collect();
    let operations = crate::transitions::TransitionJournalStore::new(app_state_root)
        .list()?
        .into_iter()
        .filter(|journal| {
            journal.repository_key == identity.repository_key
                && journal.workspace_key == identity.workspace_key
        })
        .map(|journal| {
            let recovery_required = matches!(
                journal.lifecycle,
                crate::transitions::TransitionLifecycle::Applying
                    | crate::transitions::TransitionLifecycle::Cancelling
                    | crate::transitions::TransitionLifecycle::RollingBack
                    | crate::transitions::TransitionLifecycle::Recovering
                    | crate::transitions::TransitionLifecycle::NeedsRepair
            );
            ControlOperationStatus {
                operation_id: journal.operation_id,
                operation_kind: journal.operation_kind,
                lifecycle: journal.lifecycle,
                effect_graph_digest: journal.effect_graph_digest,
                authorization_recorded: journal.authorization_decision_digest.is_some(),
                resources: journal
                    .effects
                    .into_iter()
                    .map(|effect| effect.resource_id)
                    .collect(),
                terminal_code: journal.terminal_code,
                recovery_required,
                reach_aware: None,
            }
        })
        .collect();
    Ok(ControlStatus {
        schema_version: CONTROL_STATUS_SCHEMA_VERSION,
        repository_key: identity.repository_key,
        workspace_key: identity.workspace_key,
        catalog: persistent.catalog,
        profiles: persistent.profiles,
        policies: persistent.policies,
        gateways,
        sessions,
        operations,
        hooks: persistent.hooks,
    })
}

/// Project one reach-aware journal record for an authenticated connection.
/// The principal is always verified from the signed session record; caller
/// metadata is not accepted as an authorization input.
pub fn project_reach_aware_operation_status(
    journal: &TransitionJournal,
    authorization: &ReachAwareStatusAuthorization,
    authority_key: &SessionAuthorityKey,
) -> Result<ReachAwareOperationStatus, ControlStatusError> {
    let envelope = journal.reach_aware.as_ref().ok_or_else(|| {
        ControlStatusError::ReachAwareAuthorization("operation is schema-v1".into())
    })?;
    let connection_boundary =
        authorize_reach_aware_status(journal, envelope, authorization, authority_key)?;
    let mut entries = Vec::new();
    let mut excluded_provider_counts = BTreeMap::new();
    for entry in envelope.provider_coverage.entries() {
        if connection_boundary.allows(entry.provider) {
            entries.push(entry.clone());
        } else {
            *excluded_provider_counts.entry(entry.provider).or_default() += 1;
        }
    }
    let selected_provider = envelope
        .selected_provider
        .filter(|selected| connection_boundary.allows(selected.provider));
    Ok(ReachAwareOperationStatus {
        schema_version: REACH_AWARE_STATUS_SCHEMA_VERSION,
        operation_id: envelope.operation_id.clone(),
        operation_kind: envelope.operation_kind.clone(),
        family: envelope.family,
        lifecycle: envelope.lifecycle,
        expected_lifecycle: envelope.expected_lifecycle,
        provider_reach: envelope.provider_reach,
        selected_provider,
        provider_coverage: ProviderReachCoverage::new(entries),
        excluded_provider_counts,
        recovery: envelope.recovery.clone(),
        terminal_code: journal.terminal_code.clone(),
        audit: journal.audit.clone(),
    })
}

/// Project authorized reach-aware records with stable operation/family/
/// lifecycle/provider filters. Authorization and redaction occur before
/// filtering so raw provider-qualified coverage cannot become a side channel.
pub fn project_reach_aware_operations(
    journals: &[TransitionJournal],
    filter: &ReachAwareStatusFilter,
    authorization: &ReachAwareStatusAuthorization,
    authority_key: &SessionAuthorityKey,
) -> Result<Vec<ReachAwareOperationStatus>, ControlStatusError> {
    let mut projections = Vec::new();
    for journal in journals {
        if journal.reach_aware.is_none() {
            continue;
        }
        let projection =
            match project_reach_aware_operation_status(journal, authorization, authority_key) {
                Ok(projection) => projection,
                Err(ControlStatusError::ReachAwareAuthorization(_)) => continue,
                Err(error) => return Err(error),
            };
        let matches = filter
            .operation_id
            .as_deref()
            .is_none_or(|operation_id| projection.operation_id == operation_id)
            && filter
                .family
                .is_none_or(|family| projection.family == family)
            && filter
                .lifecycle
                .is_none_or(|lifecycle| projection.lifecycle == lifecycle)
            && filter.provider.is_none_or(|provider| {
                projection
                    .provider_coverage
                    .entries()
                    .iter()
                    .any(|entry| entry.provider == provider)
                    || projection.excluded_provider_counts.contains_key(&provider)
            });
        if matches {
            projections.push(projection);
        }
    }
    projections.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(projections)
}

fn authorize_reach_aware_status(
    journal: &TransitionJournal,
    envelope: &ReachAwareControlOperationEnvelope,
    authorization: &ReachAwareStatusAuthorization,
    authority_key: &SessionAuthorityKey,
) -> Result<ConnectionBoundary, ControlStatusError> {
    envelope
        .verify_authenticated(authority_key)
        .map_err(|error| ControlStatusError::ReachAwareRecord(error.to_string()))?;
    authorization
        .principal
        .verify(authority_key)
        .map_err(ControlStatusError::from)?;
    if authorization.audience != envelope.audience {
        return Err(ControlStatusError::ReachAwareAuthorization(
            "status audience is not authorized".into(),
        ));
    }
    let connection_boundary = authorization.principal.connection_boundary;
    if let ConnectionBoundary::Pinned(provider) = connection_boundary
        && (!envelope.connection_boundary.allows(provider)
            || envelope
                .provider_reach
                .provider()
                .is_some_and(|selected| selected != provider)
            || !envelope
                .provider_coverage
                .entries()
                .iter()
                .any(|entry| entry.provider == provider))
    {
        return Err(ControlStatusError::ReachAwareAuthorization(
            "status connection boundary is not authorized".into(),
        ));
    }
    if authorization.principal == envelope.principal {
        return Ok(connection_boundary);
    }
    let bound_capability = envelope.transfer_capability.as_ref().ok_or_else(|| {
        ControlStatusError::ReachAwareAuthorization("transfer capability is unavailable".into())
    })?;
    if bound_capability.scope_digest != authorization.capability_scope_digest {
        return Err(ControlStatusError::ReachAwareAuthorization(
            "transfer capability scope is not authorized".into(),
        ));
    }
    if bound_capability.connection_boundary != connection_boundary {
        return Err(ControlStatusError::ReachAwareAuthorization(
            "transfer capability connection boundary is not authorized".into(),
        ));
    }
    if let Some(consumption) = journal
        .consumed_transfer_capabilities
        .get(&bound_capability.capability_id)
    {
        if consumption.principal_session_id != authorization.principal.session_id
            || consumption.principal_scope_id != authorization.principal.connection_scope_id
            || consumption.connection_boundary != connection_boundary
        {
            return Err(ControlStatusError::ReachAwareAuthorization(
                "transferred principal is not authorized".into(),
            ));
        }
        consumption
            .verify_for(bound_capability, &authorization.principal, authority_key)
            .map_err(|error| ControlStatusError::ReachAwareRecord(error.to_string()))?;
        return Ok(connection_boundary);
    }
    let capability = authorization.transfer_capability.as_ref().ok_or_else(|| {
        ControlStatusError::ReachAwareAuthorization("transfer capability is required".into())
    })?;
    if bound_capability != capability {
        return Err(ControlStatusError::ReachAwareAuthorization(
            "transfer capability is unavailable".into(),
        ));
    }
    capability
        .validate_for(
            &envelope.operation_id,
            &envelope.audience,
            &authorization.capability_scope_digest,
            &authorization.principal,
            authorization.now_unix,
            authority_key,
        )
        .map_err(ControlStatusError::from)?;
    Ok(connection_boundary)
}

pub fn build_persistent_control_metadata(
    discovery: &DiscoveryOutput,
    app_state_root: &Path,
    project_root: &Path,
) -> Result<PersistentControlMetadata, ControlStatusError> {
    let identity = resolve_workspace_identity(project_root).ok();
    build_persistent_control_metadata_with_identity(
        discovery,
        app_state_root,
        project_root,
        identity.as_ref(),
    )
}

fn build_persistent_control_metadata_with_identity(
    discovery: &DiscoveryOutput,
    app_state_root: &Path,
    project_root: &Path,
    identity: Option<&WorkspaceIdentity>,
) -> Result<PersistentControlMetadata, ControlStatusError> {
    let catalog = Catalog::from_discovery(discovery)?;
    let state_root = canonical_state_root(app_state_root);
    let store = ProfileStore::new(&state_root);
    let mut profiles = store.list_global_definitions()?;
    profiles.extend(ProfileStore::list_workspace_definitions(project_root)?);
    profiles.sort_by(|left, right| {
        (left.definition.id.as_str(), left.scope).cmp(&(right.definition.id.as_str(), right.scope))
    });
    let policy_store = PolicyStore::new(&state_root);
    let policies = match identity {
        Some(identity) => policy_store.load_resolution_policies(
            &identity.repository_key,
            &identity.workspace_key,
            None,
        )?,
        None => ResolutionPolicies {
            global: policy_store
                .load(&crate::profiles::PolicyTarget::Global)?
                .map_or_else(crate::profiles::ScopePolicy::default, |snapshot| {
                    snapshot.policy
                }),
            ..ResolutionPolicies::default()
        },
    };
    Ok(PersistentControlMetadata {
        schema_version: CONTROL_STATUS_SCHEMA_VERSION,
        catalog: catalog_summary(&catalog),
        profiles,
        policies,
        hooks: hook_coverage(&state_root)?,
    })
}

fn canonical_state_root(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        path.parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
            .and_then(|parent| path.file_name().map(|name| parent.join(name)))
            .unwrap_or_else(|| path.to_path_buf())
    })
}

fn catalog_summary(catalog: &Catalog) -> CatalogControlSummary {
    let mut summary = CatalogControlSummary::default();
    for record in catalog.records.values() {
        summary.total += 1;
        summary.active += usize::from(record.lifecycle.active);
        *summary
            .by_kind
            .entry(capability_kind_key(record.kind).to_string())
            .or_default() += 1;
    }
    summary
}

fn hook_coverage(app_state_root: &Path) -> Result<Vec<HookControlCoverage>, BridgeError> {
    let installer = BridgeInstaller::new(app_state_root);
    ProviderId::ALL
        .into_iter()
        .map(|provider| {
            let descriptor = hook_bridge_descriptor(provider);
            Ok(HookControlCoverage {
                provider,
                adapter: descriptor.adapter,
                built_in_tools: descriptor.built_in_tools,
                gateway_mcp_tools: descriptor.gateway_mcp_tools,
                native_events: descriptor
                    .native_events
                    .iter()
                    .map(|event| (*event).to_string())
                    .collect(),
                managed_asset: descriptor.has_managed_asset(),
                managed_bridge_installations: if descriptor.has_managed_asset() {
                    installer.list_statuses(provider)?
                } else {
                    Vec::new()
                },
            })
        })
        .collect()
}

const fn capability_kind_key(kind: CapabilityKind) -> &'static str {
    kind.as_str()
}

#[derive(Debug)]
pub enum ControlStatusError {
    Workspace(crate::state::workspace::WorkspaceIdentityError),
    Catalog(crate::catalog::CatalogModelError),
    Profile(crate::profiles::ProfileStoreError),
    Policy(crate::profiles::PolicyStoreError),
    Session(crate::sessions::LeaseError),
    Journal(crate::transitions::JournalError),
    Bridge(BridgeError),
    ReachAwareAuthorization(String),
    ReachAwareRecord(String),
}

impl From<crate::state::workspace::WorkspaceIdentityError> for ControlStatusError {
    fn from(error: crate::state::workspace::WorkspaceIdentityError) -> Self {
        Self::Workspace(error)
    }
}

impl From<crate::catalog::CatalogModelError> for ControlStatusError {
    fn from(error: crate::catalog::CatalogModelError) -> Self {
        Self::Catalog(error)
    }
}

impl From<crate::profiles::ProfileStoreError> for ControlStatusError {
    fn from(error: crate::profiles::ProfileStoreError) -> Self {
        Self::Profile(error)
    }
}

impl From<crate::profiles::PolicyStoreError> for ControlStatusError {
    fn from(error: crate::profiles::PolicyStoreError) -> Self {
        Self::Policy(error)
    }
}

impl From<crate::sessions::LeaseError> for ControlStatusError {
    fn from(error: crate::sessions::LeaseError) -> Self {
        Self::Session(error)
    }
}

impl From<crate::transitions::JournalError> for ControlStatusError {
    fn from(error: crate::transitions::JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<BridgeError> for ControlStatusError {
    fn from(error: BridgeError) -> Self {
        Self::Bridge(error)
    }
}

impl From<ReachAwareEnvelopeError> for ControlStatusError {
    fn from(error: ReachAwareEnvelopeError) -> Self {
        Self::ReachAwareAuthorization(error.to_string())
    }
}

impl fmt::Display for ControlStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Catalog(error) => error.fmt(formatter),
            Self::Profile(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Session(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::Bridge(error) => error.fmt(formatter),
            Self::ReachAwareAuthorization(message) => formatter.write_str(message),
            Self::ReachAwareRecord(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ControlStatusError {}
