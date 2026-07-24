use std::{collections::BTreeMap, fmt, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    bridges::{
        BridgeError, BridgeInstaller, BridgeStatus, HookBridgeAdapter, HookCoverageStatus,
        hook_bridge_descriptor,
    },
    catalog::{CapabilityKind, Catalog},
    discovery::DiscoveryOutput,
    profiles::{PolicyStore, ProfileDefinitionEntry, ProfileStore, ResolutionPolicies},
    providers::ProviderId,
    sessions::{
        CoverageLevel, GatewayModeManager, GatewayModeState, GatewayModeTarget, IsolationLevel,
        LeaseLifecycle, LiveExposureStatus, SessionAuthorityKey, SessionManager,
    },
    state::workspace::{WorkspaceIdentity, resolve_workspace_identity},
};

pub const CONTROL_STATUS_SCHEMA_VERSION: u32 = 1;

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
        }
    }
}

impl std::error::Error for ControlStatusError {}
