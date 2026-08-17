use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::agent_plugins::{
    AgentPluginAccess, AgentPluginComponentDisposition, AgentPluginComponentKind,
    AgentPluginInstance, AgentPluginState, AgentPluginSummary,
};
use crate::capabilities::{validate_capability_matrix, validate_provider_fixtures};
use crate::catalog::{Catalog, CatalogRecord, adoption::plan_discovered_adoption};
use crate::control::{
    ControlStatus, ReachAwareStatusAuthorization, attach_reach_aware_status_for_operation,
    build_control_status,
};
use crate::control_operation::{
    ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
    ControlResolvedContext, ReachAwarePrincipal, ReachAwareRootBinding, ReachAwareRootScope,
};
use crate::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryOutput,
    DiscoveryRoots, ProviderId, discover_all,
};
use crate::groups::{
    GroupAccessContext, GroupApplyResult, GroupApprovalArtifactStore, GroupController,
    GroupOperationAuthorizationLink, GroupOperationStore, GroupPlanDisposition, GroupPlanError,
    GroupPlanMode, GroupPlanner, GroupRef, GroupResolveError, GroupResolver, GroupTargetState,
    GroupTogglePlan, McpGroupSessionLeaseStore, PersonalGroupStore, RepositoryGroupStore,
    current_unix_seconds, index_discovery, issue_group_approval_challenge,
    list_group_operation_inspections, verify_group_approval_challenge,
};
use crate::hooks::HookTrustStore;
use crate::mutation::{
    BULK_TOGGLE_APPROVAL_AUDIENCE, BackupAuthenticationKey, BackupSummary, BulkToggleController,
    BulkTogglePlan, BulkTogglePlanError, BulkTogglePlanStatus, BulkToggleReachAwareApplyContext,
    BulkToggleRequest, BulkToggleSelector, CONTROL_PLANE_PROTECTED_REASON, NativeToggleController,
    RestoreController, is_control_plane_protected_disable, load_backup_summaries_authenticated,
};
use crate::profiles::{
    CapabilityLockChange, CapabilityLockSnapshot, CapabilityLockState, CompiledProfileRevision,
    GatewaySelection, PROFILE_PROVIDER_APPROVAL_AUDIENCE, PolicyChange,
    PolicyMaintenanceController, PolicyStore, PolicyTarget, ProfileDefinition,
    ProfilePolicyController, ProfileProviderOperationController,
    ProfileProviderReachAwareApplyContext, ProfileReference, ProfileSelection, ProfileSourceScope,
    ProfileStore, UnmanagedPolicyStatus, capability_lock_enforcement, compile_profile,
    profile_reach_scope_digest, propose_profile, resolve_effective_gateway,
};
use crate::provider_reach::{
    ConnectionBoundary, DerivedTargetKind, ProviderReachInput, ProviderReachLifecycle,
    ProviderReachRequest, SelectedProviderAuthority, SelectedProviderProvenance,
};
use crate::sessions::{
    GatewayModeAction, GatewayModeController, GatewayModeTarget, GatewayWorkflowController,
    PinnedExposure, PinnedProfile, SessionAuthorityKey, SessionEndController, WorkflowProposalV1,
    WorkflowReloadLimitation,
};
use crate::snapshots::build_inventory_summary;
use crate::state::workspace::resolve_workspace_identity;
use crate::workflows::{
    CompiledWorkflowRevision, WorkflowDefinitionEntry, WorkflowStore, compile_workflow,
    rank_workflow_definitions,
};
use crate::{
    approval::{
        ApprovalExpectation, ApprovalKey, ApprovalVerifier, CONTROL_APPROVAL_AUDIENCE,
        ControlApprovalContext, approval_binding_digest, authorize_control,
    },
    transitions::{EffectActivation, TransitionContext, TransitionJournalStore, TransitionPlan},
};

mod agent_plugins;
mod control;
mod doctor;
mod groups;
mod inventory;
mod schema;
mod selectors;
mod toggle;
mod workflows;
use agent_plugins::*;
use control::*;
use doctor::*;
use groups::*;
use inventory::*;
use schema::*;
use selectors::*;
use toggle::*;
use workflows::*;

// Keep the public MCP contract in one Unpin-owned namespace.
pub const UNPIN_MCP_TOOL_NAMES: &[&str] = &[
    "unpin_get_inventory_summary",
    "unpin_list_items",
    "unpin_list_agent_plugins",
    "unpin_inspect_agent_plugin",
    "unpin_plan_agent_plugin_toggle",
    "unpin_list_inventory_groups",
    "unpin_get_inventory_group",
    "unpin_plan_inventory_group",
    "unpin_plan_toggle_item",
    "unpin_apply_toggle_item",
    "unpin_plan_toggle_items",
    "unpin_apply_toggle_items",
    "unpin_list_backups",
    "unpin_restore_backup",
    "unpin_run_doctor",
    "unpin_get_control_status",
    "unpin_get_policy_maintenance_status",
    "unpin_list_catalog",
    "unpin_list_hooks",
    "unpin_plan_catalog_adoption",
    "unpin_apply_catalog_adoption",
    "unpin_plan_hook_trust",
    "unpin_apply_hook_trust",
    "unpin_propose_session_profile",
    "unpin_validate_profile",
    "unpin_list_workflows",
    "unpin_validate_workflow",
    "unpin_propose_session_workflow",
    "unpin_plan_workflow_session_launch",
    "unpin_plan_profile_policy",
    "unpin_apply_profile_policy",
    "unpin_plan_profile_provider",
    "unpin_apply_profile_provider",
    "unpin_get_capability_locks",
    "unpin_plan_capability_lock",
    "unpin_apply_capability_lock",
    "unpin_plan_gateway_mode",
    "unpin_apply_gateway_mode",
    "unpin_get_gateway_status",
    "unpin_plan_session_end",
    "unpin_apply_session_end",
    "unpin_plan_session_launch",
];
pub const UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME: &str = "unpin_apply_inventory_group";

pub(super) const MODERN_MCP_PROTOCOL_VERSION: &str = "2026-07-28";
pub(super) const LEGACY_MCP_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub(super) const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &[
    MODERN_MCP_PROTOCOL_VERSION,
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];
pub(super) const LATEST_LEGACY_MCP_PROTOCOL_VERSION: &str = LEGACY_MCP_PROTOCOL_VERSIONS[0];
pub(super) const MCP_PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
pub(super) const MCP_CLIENT_CAPABILITIES_META_KEY: &str =
    "io.modelcontextprotocol/clientCapabilities";
pub(super) const MCP_SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";
pub(super) const MCP_TOOLS_LIST_TTL_MS: u64 = 0;
pub(super) const ADOPTION_APPROVAL_ISSUER: &str = "unpin-cli-human";
pub(super) const ADOPTION_APPROVAL_AUDIENCE: &str = "unpin-core-transition";
pub(super) const HOOK_TRUST_APPROVAL_ISSUER: &str = "unpin-cli-human";
pub(super) const HOOK_TRUST_APPROVAL_AUDIENCE: &str = "unpin-core-hook-trust";
pub(super) const MAX_MCP_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const UNPIN_CONTROL_CONTRACT_VERSION: u32 = 2;
pub(super) const DEFAULT_MCP_DISCOVERY_CACHE_TTL: Duration = Duration::from_millis(250);
pub(super) const MCP_HANDOFF_TTL_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpCredentialStatus {
    Ready,
    Missing,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCredentialReadiness {
    pub status: McpCredentialStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl McpCredentialReadiness {
    #[must_use]
    pub fn ready(key_id: Option<String>) -> Self {
        Self {
            status: McpCredentialStatus::Ready,
            key_id,
        }
    }

    #[must_use]
    pub const fn missing() -> Self {
        Self {
            status: McpCredentialStatus::Missing,
            key_id: None,
        }
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            status: McpCredentialStatus::Unavailable,
            key_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuthenticationReadiness {
    pub backup_authentication: McpCredentialReadiness,
    pub approval_signing: McpCredentialReadiness,
    pub cursor_dashboard: McpCredentialReadiness,
}

#[derive(Debug, Clone)]
pub struct McpContext {
    pub discovery_roots: DiscoveryRoots,
    pub fixture_root: Option<PathBuf>,
    pub package_root: PathBuf,
    pub app_state_root: PathBuf,
    pub project_root: PathBuf,
    pub backup_authentication_key: Option<BackupAuthenticationKey>,
    pub session_authority_key: Option<SessionAuthorityKey>,
    pub authentication: McpAuthenticationReadiness,
    pub provider_scope: McpProviderScope,
    pub discovery_cache: McpDiscoveryCache,
    pub approved_group_apply: Option<McpApprovedGroupApplyContext>,
}

#[derive(Debug, Clone)]
pub struct McpApprovedGroupApplyContext {
    pub session: crate::groups::McpGroupSessionIdentity,
    pub approval_key: ApprovalKey,
}

#[derive(Debug, Clone)]
pub struct McpDiscoveryCache {
    ttl: Duration,
    state: Arc<Mutex<DiscoveryCacheState>>,
}

impl Default for McpDiscoveryCache {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_MCP_DISCOVERY_CACHE_TTL)
    }
}

impl McpDiscoveryCache {
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Arc::new(Mutex::new(DiscoveryCacheState::default())),
        }
    }

    pub fn invalidate(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state.entry = None;
    }

    pub fn get_or_discover(&self, roots: &DiscoveryRoots) -> Result<Arc<DiscoveryOutput>, String> {
        self.get_or_update(|| discover_all(roots).map_err(|error| error.to_string()))
    }

    pub fn refresh(&self, roots: &DiscoveryRoots) -> Result<Arc<DiscoveryOutput>, String> {
        self.refresh_with(|| discover_all(roots).map_err(|error| error.to_string()))
    }

    pub(super) fn get_or_update(
        &self,
        load: impl FnOnce() -> Result<DiscoveryOutput, String>,
    ) -> Result<Arc<DiscoveryOutput>, String> {
        let now = Instant::now();
        let generation = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = state.entry.as_ref()
                && now.saturating_duration_since(cached.refreshed_at) < self.ttl
            {
                return Ok(cached.discovery.clone());
            }
            state.generation
        };

        let discovery = Arc::new(load()?);
        let refreshed_at = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != generation {
            return Ok(discovery);
        }
        if let Some(cached) = state.entry.as_ref()
            && refreshed_at.saturating_duration_since(cached.refreshed_at) < self.ttl
        {
            return Ok(cached.discovery.clone());
        }
        state.entry = Some(CachedDiscovery {
            refreshed_at,
            discovery: discovery.clone(),
        });
        Ok(discovery)
    }

    pub(super) fn refresh_with(
        &self,
        load: impl FnOnce() -> Result<DiscoveryOutput, String>,
    ) -> Result<Arc<DiscoveryOutput>, String> {
        let generation = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        let discovery = Arc::new(load()?);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation == generation {
            state.entry = Some(CachedDiscovery {
                refreshed_at: Instant::now(),
                discovery: discovery.clone(),
            });
        }
        Ok(discovery)
    }
}

#[derive(Debug, Default)]
pub(super) struct DiscoveryCacheState {
    generation: u64,
    entry: Option<CachedDiscovery>,
}

#[derive(Debug, Clone)]
pub(super) struct CachedDiscovery {
    refreshed_at: Instant,
    discovery: Arc<DiscoveryOutput>,
}

#[cfg(test)]
mod discovery_cache_tests {
    use std::cell::Cell;

    use crate::discovery::DiscoveryWarning;

    use super::*;

    #[test]
    fn reuses_successful_discovery_until_invalidated() {
        let cache = McpDiscoveryCache::with_ttl(Duration::from_secs(60));
        let loads = Cell::new(0);
        let first = cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .unwrap();
        let second = cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Err("cached result should be reused".to_string())
            })
            .unwrap();
        assert_eq!(first, second);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(loads.get(), 1);

        cache.invalidate();
        cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .unwrap();
        assert_eq!(loads.get(), 2);
    }

    #[test]
    fn zero_ttl_refreshes_and_failures_are_not_cached() {
        let cache = McpDiscoveryCache::with_ttl(Duration::ZERO);
        let loads = Cell::new(0);
        assert_eq!(
            cache.get_or_update(|| {
                loads.set(loads.get() + 1);
                Err("transient discovery failure".to_string())
            }),
            Err("transient discovery failure".to_string())
        );
        cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .unwrap();
        cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .unwrap();
        assert_eq!(loads.get(), 3);
    }

    #[test]
    fn explicit_refresh_replaces_a_live_cached_entry() {
        let cache = McpDiscoveryCache::with_ttl(Duration::from_secs(60));
        let loads = Cell::new(0);
        cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .unwrap();

        let refreshed = DiscoveryOutput {
            warnings: vec![DiscoveryWarning {
                provider: ProviderId::Codex,
                layer: None,
                code: "refreshed".to_string(),
                message: "refreshed".to_string(),
            }],
            ..DiscoveryOutput::default()
        };
        cache
            .refresh_with(|| {
                loads.set(loads.get() + 1);
                Ok(refreshed.clone())
            })
            .unwrap();
        let cached = cache
            .get_or_update(|| Err("refreshed entry should be reused".to_string()))
            .unwrap();

        assert_eq!(*cached, refreshed);
        assert_eq!(loads.get(), 2);
    }

    #[test]
    fn discovery_load_runs_without_holding_the_cache_mutex() {
        let cache = McpDiscoveryCache::with_ttl(Duration::from_secs(60));
        let invalidating_cache = cache.clone();
        cache
            .get_or_update(|| {
                invalidating_cache.invalidate();
                Ok(DiscoveryOutput::default())
            })
            .expect("discovery can invalidate without deadlocking");

        let loads = Cell::new(0);
        cache
            .get_or_update(|| {
                loads.set(loads.get() + 1);
                Ok(DiscoveryOutput::default())
            })
            .expect("invalidation during discovery leaves no stale cache entry");
        assert_eq!(loads.get(), 1);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum McpProviderScope {
    #[default]
    All,
    Provider(ProviderId),
}

impl McpProviderScope {
    #[must_use]
    pub const fn provider(self) -> Option<ProviderId> {
        match self {
            Self::All => None,
            Self::Provider(provider) => Some(provider),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Provider(provider) => provider.as_str(),
        }
    }

    pub(super) fn allows(self, provider: ProviderId) -> bool {
        self.provider().is_none_or(|allowed| allowed == provider)
    }

    pub(super) fn require_allowed(self, provider: ProviderId) -> Result<ProviderId, String> {
        if self.allows(provider) {
            Ok(provider)
        } else {
            Err(format!(
                "provider {} is outside MCP provider scope {}",
                provider.as_str(),
                self.as_str()
            ))
        }
    }

    pub(super) fn require_allowed_optional(
        self,
        provider: Option<ProviderId>,
    ) -> Result<(), String> {
        match (self.provider(), provider) {
            (None, _) => Ok(()),
            (Some(_), Some(provider)) => self.require_allowed(provider).map(|_| ()),
            (Some(allowed), None) => Err(format!(
                "target is not associated with MCP provider scope {}",
                allowed.as_str()
            )),
        }
    }

    pub(super) fn require_allowed_all(self, providers: &[ProviderId]) -> Result<(), String> {
        for provider in providers {
            self.require_allowed(*provider)?;
        }
        Ok(())
    }

    pub(super) fn validate_arguments(self, arguments: &Value) -> Result<(), String> {
        let Some(allowed) = self.provider() else {
            return Ok(());
        };
        if let Some(provider) = arguments.get("provider") {
            let provider = provider
                .as_str()
                .ok_or_else(|| "provider must be a string".to_string())
                .and_then(parse_provider_id)?;
            self.require_allowed(provider)?;
        }
        for providers in [
            arguments.get("providers"),
            arguments
                .get("selector")
                .and_then(|selector| selector.get("providers")),
        ]
        .into_iter()
        .flatten()
        {
            let providers = providers
                .as_array()
                .ok_or_else(|| "providers must be an array".to_string())?;
            for provider in providers {
                let provider = provider
                    .as_str()
                    .ok_or_else(|| "providers must contain strings".to_string())
                    .and_then(parse_provider_id)?;
                if provider != allowed {
                    return self.require_allowed(provider).map(|_| ());
                }
            }
        }
        Ok(())
    }

    pub(super) fn filter_discovery(self, mut discovery: DiscoveryOutput) -> DiscoveryOutput {
        if let Some(provider) = self.provider() {
            discovery.items.retain(|item| item.provider == provider);
            discovery
                .warnings
                .retain(|warning| warning.provider == provider);
        }
        discovery
    }

    pub(super) fn filter_control_status(self, control: &mut ControlStatus) {
        let Some(provider) = self.provider() else {
            return;
        };
        for policy in [
            Some(&mut control.policies.global),
            control.policies.repository.as_mut(),
            control.policies.workspace.as_mut(),
            control.policies.session.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            policy
                .providers
                .retain(|candidate, _| *candidate == provider);
        }
        control
            .gateways
            .retain(|gateway| gateway.provider == provider);
        control
            .sessions
            .retain(|session| session.provider == provider);
        control.hooks.retain(|hook| hook.provider == provider);
    }
}

pub fn handle_mcp_request(context: &McpContext, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return error_response(id, -32600, "missing method");
    };
    let modern = method == "server/discover" || request_declares_modern_protocol_version(request);

    if modern && let Some(error) = modern_request_error(id.clone(), request) {
        return error;
    }

    match method {
        "initialize" if modern => error_response(id, -32601, "unsupported method: initialize"),
        "initialize" => result_response(
            id,
            json!({
                "protocolVersion": negotiated_protocol_version(request),
                "serverInfo": server_info(),
                "capabilities": server_capabilities(context)
            }),
        ),
        "notifications/initialized" if modern => {
            error_response(id, -32601, "unsupported method: notifications/initialized")
        }
        "notifications/initialized" => result_response(id, json!({})),
        "server/discover" => modern_result_response(id, server_discovery(context)),
        "tools/list" => request_result_response(id, tools_list_result(context, modern), modern),
        "tools/call" => match handle_tool_call(context, request) {
            Ok(result) => request_result_response(id, result, modern),
            Err(message) => error_response(id, -32000, message),
        },
        _ => error_response(id, -32601, format!("unsupported method: {method}")),
    }
}

pub(super) fn negotiated_protocol_version(request: &Value) -> &'static str {
    let requested = request
        .get("params")
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str);

    LEGACY_MCP_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|supported| Some(*supported) == requested)
        .unwrap_or(LATEST_LEGACY_MCP_PROTOCOL_VERSION)
}

pub(super) fn request_declares_modern_protocol_version(request: &Value) -> bool {
    request
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|metadata| metadata.get(MCP_PROTOCOL_VERSION_META_KEY))
        .is_some()
}

pub(super) fn modern_request_error(id: Value, request: &Value) -> Option<Value> {
    let Some(metadata) = request.get("params").and_then(|params| params.get("_meta")) else {
        return Some(error_response(id, -32602, "missing MCP protocol metadata"));
    };
    let Some(protocol_version) = metadata
        .get(MCP_PROTOCOL_VERSION_META_KEY)
        .and_then(Value::as_str)
    else {
        return Some(error_response(
            id,
            -32602,
            "missing MCP protocol version metadata",
        ));
    };
    if protocol_version != MODERN_MCP_PROTOCOL_VERSION {
        return Some(unsupported_protocol_version_response(id, protocol_version));
    }
    if !metadata
        .get(MCP_CLIENT_CAPABILITIES_META_KEY)
        .is_some_and(Value::is_object)
    {
        return Some(error_response(
            id,
            -32602,
            "missing MCP client capabilities metadata",
        ));
    }
    None
}

pub(super) fn unsupported_protocol_version_response(id: Value, requested: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32022,
            "message": "Unsupported protocol version",
            "data": {
                "supported": SUPPORTED_MCP_PROTOCOL_VERSIONS,
                "requested": requested
            }
        }
    })
}

pub(super) fn server_info() -> Value {
    json!({
        "name": "unpin",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

pub(super) fn server_capabilities(context: &McpContext) -> Value {
    let mut control = json!({
        "version": UNPIN_CONTROL_CONTRACT_VERSION,
        "mutation": "human-handoff-only",
        "providerScope": context.provider_scope.as_str()
    });
    if context.approved_group_apply.is_some() {
        control["conditionalGroupApply"] = json!("approved-group-apply-v1");
        control["unattendedWritesEnabled"] = json!(false);
        control["conditionalProviderWritesEnabled"] = json!(true);
        control["challengeStoreWrites"] = json!(false);
        control["sessionLeaseWrites"] = json!(true);
        control["approvalArtifactRequired"] = json!(true);
        control["canMintApproval"] = json!(false);
        control["requiresPersistentSession"] = json!(true);
    }
    json!({
        "tools": {},
        "experimental": {
            "unpinControl": control
        }
    })
}

pub(super) fn server_discovery(context: &McpContext) -> Value {
    json!({
        "protocolVersions": SUPPORTED_MCP_PROTOCOL_VERSIONS,
        "serverInfo": server_info(),
        "capabilities": server_capabilities(context)
    })
}

pub(super) fn tools_list_result(context: &McpContext, modern: bool) -> Value {
    let mut result = json!({ "tools": tool_descriptors(context) });
    if modern {
        result["ttlMs"] = json!(MCP_TOOLS_LIST_TTL_MS);
        result["cacheScope"] = json!("private");
    }
    result
}

pub(super) fn request_result_response(id: Value, result: Value, modern: bool) -> Value {
    if modern {
        modern_result_response(id, result)
    } else {
        result_response(id, result)
    }
}

pub(super) fn modern_result_response(id: Value, mut result: Value) -> Value {
    let result_object = result
        .as_object_mut()
        .expect("all Unpin MCP success results are objects");
    result_object.insert("resultType".to_string(), json!("complete"));
    result_object.insert(
        "_meta".to_string(),
        json!({ MCP_SERVER_INFO_META_KEY: server_info() }),
    );
    result_response(id, result)
}

pub fn handle_stdio_request_once(
    context: &McpContext,
    input: impl Read,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut reader = BufReader::new(input);
    let body = read_message_body(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing MCP message"))?;
    let Some(response) = handle_stdio_message(context, &body) else {
        return Ok(Vec::new());
    };
    let response_body = serde_json::to_string(&response)?;

    Ok(encode_message(&response_body))
}

pub fn handle_stdio_requests(
    context: &McpContext,
    input: impl Read,
    mut output: impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut reader = BufReader::new(input);

    while let Some(body) = read_message_body(&mut reader)? {
        let Some(response) = handle_stdio_message(context, &body) else {
            continue;
        };
        let response_body = serde_json::to_string(&response)?;
        output.write_all(&encode_message(&response_body))?;
        output.flush()?;
    }

    Ok(())
}

pub(super) fn handle_stdio_message(context: &McpContext, body: &[u8]) -> Option<Value> {
    let request = match serde_json::from_slice::<Value>(body) {
        Ok(request) => request,
        Err(_) => return Some(error_response(Value::Null, -32700, "parse error")),
    };

    handle_mcp_response(context, &request)
}

pub(super) fn handle_mcp_response(context: &McpContext, request: &Value) -> Option<Value> {
    request.get("id")?;

    Some(handle_mcp_request(context, request))
}

pub(super) fn read_message_body(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, io::Error> {
    let mut body = Vec::new();
    let bytes_read = reader
        .take((MAX_MCP_MESSAGE_BYTES + 2) as u64)
        .read_until(b'\n', &mut body)?;
    if bytes_read == 0 {
        return Ok(None);
    }

    if body.last() == Some(&b'\n') {
        body.pop();
        if body.last() == Some(&b'\r') {
            body.pop();
        }
    }
    if body.len() > MAX_MCP_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MCP message exceeds {MAX_MCP_MESSAGE_BYTES}-byte limit"),
        ));
    }
    Ok(Some(body))
}

pub(super) fn handle_tool_call(context: &McpContext, request: &Value) -> Result<Value, String> {
    let params = request
        .get("params")
        .ok_or_else(|| "tools/call params are required".to_string())?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "tools/call params.name is required".to_string())?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    context.provider_scope.validate_arguments(&arguments)?;

    match name {
        "unpin_get_inventory_summary" => {
            structured_result(get_inventory_summary(context, &arguments)?)
        }
        "unpin_list_items" => structured_result(list_items(context, &arguments)?),
        "unpin_list_agent_plugins" => structured_result(list_agent_plugins(context, &arguments)?),
        "unpin_inspect_agent_plugin" => {
            structured_result(inspect_agent_plugin(context, &arguments)?)
        }
        "unpin_plan_agent_plugin_toggle" => {
            structured_result(plan_agent_plugin_toggle(context, &arguments))
        }
        "unpin_list_inventory_groups" => {
            structured_result(list_inventory_groups(context, &arguments)?)
        }
        "unpin_get_inventory_group" => structured_result(get_inventory_group(context, &arguments)?),
        "unpin_plan_inventory_group" => {
            structured_result(plan_inventory_group(context, &arguments)?)
        }
        "unpin_apply_inventory_group" if context.approved_group_apply.is_some() => {
            structured_result(apply_inventory_group(context, &arguments)?)
        }
        "unpin_run_doctor" => structured_result(run_doctor_structured(context)),
        "unpin_plan_toggle_item" => structured_result(plan_single_toggle(context, &arguments)),
        "unpin_apply_toggle_item" => structured_result(apply_single_toggle(context, &arguments)),
        "unpin_plan_toggle_items" => structured_result(plan_bulk_toggle_items(context, &arguments)),
        "unpin_apply_toggle_items" => {
            structured_result(apply_bulk_toggle_items(context, &arguments))
        }
        "unpin_list_backups" => structured_result(list_backups(context, &arguments)),
        "unpin_restore_backup" => structured_result(restore_backup_tool(context, &arguments)),
        "unpin_get_control_status" => structured_result(get_control_status(context, &arguments)?),
        "unpin_get_policy_maintenance_status" => {
            structured_result(get_policy_maintenance_status(context, &arguments)?)
        }
        "unpin_list_catalog" => structured_result(list_catalog(context, &arguments)?),
        "unpin_list_hooks" => structured_result(list_hooks(context, &arguments)?),
        "unpin_plan_catalog_adoption" => {
            structured_result(plan_catalog_adoption(context, &arguments)?)
        }
        "unpin_apply_catalog_adoption" => {
            structured_result(apply_catalog_adoption(context, &arguments)?)
        }
        "unpin_plan_hook_trust" => structured_result(plan_hook_trust(context, &arguments)?),
        "unpin_apply_hook_trust" => structured_result(apply_hook_trust(context, &arguments)?),
        "unpin_propose_session_profile" => {
            structured_result(propose_session_profile(context, &arguments)?)
        }
        "unpin_validate_profile" => structured_result(validate_profile(context, &arguments)?),
        "unpin_list_workflows" => structured_result(list_workflows(context, &arguments)?),
        "unpin_validate_workflow" => structured_result(validate_workflow(context, &arguments)?),
        "unpin_propose_session_workflow" => {
            structured_result(propose_session_workflow(context, &arguments)?)
        }
        "unpin_plan_workflow_session_launch" => {
            structured_result(plan_workflow_session_launch(context, &arguments)?)
        }
        "unpin_plan_profile_policy" => structured_result(plan_profile_policy(context, &arguments)?),
        "unpin_apply_profile_policy" => {
            structured_result(apply_profile_policy(context, &arguments)?)
        }
        "unpin_plan_profile_provider" => {
            structured_result(plan_profile_provider(context, &arguments)?)
        }
        "unpin_apply_profile_provider" => {
            structured_result(apply_profile_provider(context, &arguments)?)
        }
        "unpin_get_capability_locks" => {
            structured_result(get_capability_locks(context, &arguments)?)
        }
        "unpin_plan_capability_lock" => {
            structured_result(plan_capability_lock(context, &arguments)?)
        }
        "unpin_apply_capability_lock" => {
            structured_result(apply_capability_lock(context, &arguments)?)
        }
        "unpin_plan_gateway_mode" => structured_result(plan_gateway_mode(context, &arguments)?),
        "unpin_apply_gateway_mode" => structured_result(apply_gateway_mode(context, &arguments)?),
        "unpin_get_gateway_status" => structured_result(get_gateway_status(context, &arguments)?),
        "unpin_plan_session_end" => structured_result(plan_session_end(context, &arguments)?),
        "unpin_apply_session_end" => structured_result(apply_session_end(context, &arguments)?),
        "unpin_plan_session_launch" => structured_result(plan_session_launch(context, &arguments)?),
        _ => Err(format!("unknown tool: {name}")),
    }
}

pub(super) fn discover_scoped(context: &McpContext) -> Result<DiscoveryOutput, String> {
    context
        .discovery_cache
        .refresh(&context.discovery_roots)
        .map(|discovery| {
            context
                .provider_scope
                .filter_discovery((*discovery).clone())
        })
}

pub(super) fn discover_scoped_cached(context: &McpContext) -> Result<DiscoveryOutput, String> {
    context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)
        .map(|discovery| {
            context
                .provider_scope
                .filter_discovery((*discovery).clone())
        })
}

pub(super) fn optional_provider(
    context: &McpContext,
    arguments: &Value,
) -> Result<Option<ProviderId>, String> {
    let requested = arguments
        .get("provider")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "provider must be a string".to_string())
                .and_then(parse_provider_id)
        })
        .transpose()?;
    match (context.provider_scope.provider(), requested) {
        (Some(provider), None) => Ok(Some(provider)),
        (_, Some(provider)) => context.provider_scope.require_allowed(provider).map(Some),
        (None, None) => Ok(None),
    }
}

pub(super) fn required_provider(
    context: &McpContext,
    arguments: &Value,
) -> Result<ProviderId, String> {
    optional_provider(context, arguments)?
        .ok_or_else(|| "missing required field: provider".to_string())
}

pub(super) fn optional_string<'a>(
    arguments: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, String> {
    arguments
        .get(field)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{field} must be a non-empty string"))
        })
        .transpose()
}

pub(super) fn parse_provider_id(value: &str) -> Result<ProviderId, String> {
    ProviderId::ALL
        .into_iter()
        .find(|provider| provider.as_str() == value)
        .ok_or_else(|| format!("unsupported provider: {value}"))
}

pub(super) fn require_plan_fingerprint(arguments: &Value, expected: &str) -> Result<(), String> {
    if arguments.get("planFingerprint").and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err("plan fingerprint does not match current reviewed plan".to_string())
    }
}

pub(super) fn control_operation(
    expectation: &crate::approval::ApprovalExpectation,
    plan_fingerprint: &str,
    activation: EffectActivation,
    lifecycle: ControlOperationLifecycle,
    provider: Option<ProviderId>,
    details: Value,
) -> ControlOperationEnvelope {
    control_operation_with_provider_coverage(
        expectation,
        plan_fingerprint,
        activation,
        lifecycle,
        provider.map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
        details,
    )
}

pub(super) fn control_operation_with_provider_coverage(
    expectation: &crate::approval::ApprovalExpectation,
    plan_fingerprint: &str,
    activation: EffectActivation,
    lifecycle: ControlOperationLifecycle,
    provider_coverage: Vec<ProviderId>,
    details: Value,
) -> ControlOperationEnvelope {
    let human_action = matches!(
        lifecycle,
        ControlOperationLifecycle::Planned | ControlOperationLifecycle::AwaitingHumanAction
    )
    .then(|| ControlHumanAction {
        code: "confirm-and-apply".to_string(),
        guidance: "Review and apply this fingerprint in Unpin CLI or TUI".to_string(),
    });
    ControlOperationEnvelope::from_expectation(
        expectation,
        plan_fingerprint,
        activation,
        lifecycle,
        human_action,
        true,
        provider_coverage,
        details,
    )
}

pub(super) fn human_action_required(operation: ControlOperationEnvelope) -> Value {
    json!({
        "status": "human-action-required",
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
        "planFingerprint": operation.plan_fingerprint.clone(),
        "operation": operation,
        "continuation": "Review and apply this plan in Unpin CLI. MCP cannot mint or substitute human approval; read control status after completion.",
    })
}

pub(super) fn legacy_bulk_human_action_required(
    operation_kind: &str,
    plan_fingerprint: &str,
) -> Value {
    json!({
        "status": "human-action-required",
        "contractVariant": "legacy-bulk-handoff",
        "legacyBulkHandoff": true,
        "operationReference": format!("{operation_kind}:{plan_fingerprint}"),
        "operationKind": operation_kind,
        "planFingerprint": plan_fingerprint,
        "continuation": "Review matching items and apply them in Unpin CLI or TUI. This predecessor bulk handoff is not one durable control operation and does not use ControlOperationEnvelope v2.",
    })
}

pub(super) fn reach_aware_bulk_human_action_required(
    plan: &BulkTogglePlan,
    plan_fingerprint: &str,
    operation_v2: Value,
) -> Value {
    let mut response = legacy_bulk_human_action_required("toggle-items", plan_fingerprint);
    response["schemaVersion"] = json!(crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION);
    response["operationId"] = json!(plan.operation_id);
    response["providerReach"] = json!(plan.provider_reach);
    response["providerCoverage"] = json!(plan.provider_coverage);
    response["lifecycle"] = json!(plan.lifecycle);
    response["expectedLifecycle"] = json!(match plan.lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => "applied",
        ProviderReachLifecycle::NoOp => "no-op",
        ProviderReachLifecycle::NoTargetsInProviderReach => "no-targets-in-provider-reach",
        ProviderReachLifecycle::Blocked => "blocked",
        ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    });
    response["targets"] = json!(
        plan.included
            .iter()
            .map(|entry| &entry.item)
            .collect::<Vec<_>>()
    );
    response["reachExclusions"] = json!(plan.provider_coverage.excluded().collect::<Vec<_>>());
    response["operationV2"] = json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "family": "bulk-toggle",
        "operationId": plan.operation_id,
        "operationKind": "bulk-toggle",
        "planFingerprint": plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.provider_coverage,
        "lifecycle": "awaiting-human-action",
        "expectedLifecycle": plan.lifecycle,
        "activation": "live",
        "humanAction": {
            "code": "confirm-and-apply",
            "guidance": "Review and apply this fingerprint in Unpin CLI or TUI."
        }
    });
    if let Some(object) = response.as_object_mut() {
        object.remove("contractVariant");
        object.remove("legacyBulkHandoff");
    }
    response["handoff"] = json!({
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "expiresAtUnix": operation_v2.get("expiresAtUnix").cloned().unwrap_or(Value::Null),
    });
    response["operationV2"] = operation_v2;
    response
}

pub(super) fn legacy_plan_fingerprint(operation_kind: &str, plan: &Value) -> String {
    bulk_plan_fingerprint(json!({
        "schemaVersion": 1,
        "operationKind": operation_kind,
        "plan": plan,
    }))
}

pub(super) fn require_empty_object(arguments: &Value) -> Result<(), String> {
    match arguments.as_object() {
        Some(arguments) if arguments.is_empty() => Ok(()),
        Some(_) => Err("this tool does not accept arguments".to_string()),
        None => Err("arguments must be an object".to_string()),
    }
}

pub(super) fn require_only_fields(
    arguments: &Value,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("unsupported {label} field: {field}"));
    }
    Ok(())
}

pub(super) fn required_string<'a>(arguments: &'a Value, field: &str) -> Result<&'a str, String> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required field: {field}"))
}

pub(super) fn blocked_value(reason: impl Into<String>) -> Value {
    json!({
        "status": "blocked",
        "reason": reason.into(),
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
    })
}

pub(super) fn capability_matrix_issues(fixture_root: Option<&PathBuf>) -> Vec<Value> {
    let Some(fixture_root) = fixture_root else {
        return Vec::new();
    };

    validate_capability_matrix(fixture_root)
        .issues
        .into_iter()
        .map(|message| json!({ "message": message }))
        .collect()
}

pub(super) fn provider_fixture_issues(fixture_root: Option<&PathBuf>) -> Vec<Value> {
    let Some(fixture_root) = fixture_root else {
        return Vec::new();
    };

    validate_provider_fixtures(fixture_root)
        .issues
        .into_iter()
        .map(|issue| {
            json!({
                "providerId": issue.provider_id,
                "relativePath": issue.relative_path,
                "message": issue.message
            })
        })
        .collect()
}

pub(super) fn provider_health_rows(
    scope: McpProviderScope,
    issue_status: &str,
    issues: Vec<Value>,
) -> Vec<Value> {
    ProviderId::ALL
        .into_iter()
        .filter(|provider| scope.allows(*provider))
        .map(ProviderId::as_str)
        .map(|provider| {
            let provider_issues = issues
                .iter()
                .filter(|issue| issue.get("provider").and_then(Value::as_str) == Some(provider))
                .cloned()
                .collect::<Vec<_>>();
            let status = if provider_issues.is_empty() {
                "ok"
            } else {
                issue_status
            };

            json!({
                "provider": provider,
                "status": status,
                "issues": provider_issues
            })
        })
        .collect()
}

pub(super) fn fixture_provider_issues(issues: &[Value]) -> Vec<Value> {
    issues
        .iter()
        .filter_map(|issue| {
            let provider = issue.get("providerId").and_then(Value::as_str)?;
            Some(json!({
                "provider": provider,
                "code": "fixture-validation",
                "relativePath": issue["relativePath"],
                "message": issue["message"]
            }))
        })
        .collect()
}

pub(super) fn capability_matrix_provider_issues(issues: &[Value]) -> Vec<Value> {
    issues
        .iter()
        .flat_map(|issue| {
            let message = issue
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("capability matrix issue");
            let providers = provider_ids_from_message(message);
            providers.into_iter().map(move |provider| {
                json!({
                    "provider": provider,
                    "code": "capability-matrix",
                    "message": message
                })
            })
        })
        .collect()
}

pub(super) fn discovery_warning_provider_issue(
    warning: &crate::discovery::DiscoveryWarning,
) -> Value {
    let mut issue = json!({
        "provider": warning.provider.as_str(),
        "code": warning.code,
        "message": warning.message
    });
    if let Some(layer) = warning.layer
        && let Some(object) = issue.as_object_mut()
    {
        object.insert("layer".to_string(), json!(layer.as_str()));
    }
    issue
}

pub(super) fn discovery_error_provider_issues(
    scope: McpProviderScope,
    message: &str,
) -> Vec<Value> {
    ProviderId::ALL
        .into_iter()
        .filter(|provider| scope.allows(*provider))
        .map(ProviderId::as_str)
        .map(|provider| {
            json!({
                "provider": provider,
                "code": "discovery-error",
                "message": message
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{McpProviderScope, ProviderId, redact_group_operation_inspections};

    #[test]
    fn provider_scope_rejects_cross_provider_restore_coverage() {
        let error = McpProviderScope::Provider(ProviderId::Codex)
            .require_allowed_all(&[ProviderId::Codex, ProviderId::Zed])
            .expect_err("pinned Codex MCP must not authorize a Zed restore");
        assert_eq!(error, "provider zed is outside MCP provider scope codex");
    }

    #[test]
    fn pinned_group_operation_status_redacts_cross_provider_evidence() {
        let mut value = json!({
            "groupOperations": [{
                "evidenceAvailable": true,
                "cohortBackupIndexes": [{
                    "memberIdentities": [
                        {"provider": "claude", "id": "claude-member"},
                        {"provider": "codex", "id": "codex-member"}
                    ],
                    "resourceIds": ["claude-resource", "codex-resource"],
                    "backupIds": ["claude-backup", "codex-backup"],
                    "coverage": [
                        {
                            "backupId": "claude-backup",
                            "memberIdentities": [{"provider": "claude", "id": "claude-member"}],
                            "resourceIds": ["claude-resource"]
                        },
                        {
                            "backupId": "codex-backup",
                            "memberIdentities": [{"provider": "codex", "id": "codex-member"}],
                            "resourceIds": ["codex-resource"]
                        }
                    ]
                }],
                "operation": {
                    "providerCoverage": {"entries": [
                        {"provider": "claude", "included": true, "targetId": "claude-target"},
                        {"provider": "codex", "included": true, "targetId": "codex-target"}
                    ]},
                    "terminalResult": {
                        "providerCoverage": {"entries": [
                            {"provider": "claude", "included": true, "targetId": "claude-target"},
                            {"provider": "codex", "included": true, "targetId": "codex-target"}
                        ]},
                        "members": [
                            {
                                "identity": {"provider": "claude", "id": "claude-member"},
                                "backupId": "claude-backup"
                            },
                            {
                                "identity": {"provider": "codex", "id": "codex-member"},
                                "backupId": "codex-backup"
                            }
                        ],
                        "backupIds": ["claude-backup", "codex-backup"]
                    }
                }
            }]
        });

        redact_group_operation_inspections(&mut value, Some(ProviderId::Codex));

        let inspection = &value["groupOperations"][0];
        assert_eq!(inspection["evidenceAvailable"], false);
        assert_eq!(inspection["cohortBackupIndexes"], json!([]));
        assert_eq!(
            inspection["operation"]["providerCoverage"]["entries"],
            json!([{"provider": "codex", "included": true, "targetId": "codex-target"}])
        );
        assert_eq!(
            inspection["operation"]["terminalResult"]["providerCoverage"]["entries"],
            json!([{"provider": "codex", "included": true, "targetId": "codex-target"}])
        );
        assert_eq!(
            inspection["operation"]["terminalResult"]["backupIds"],
            json!(["codex-backup"])
        );
        assert_eq!(
            inspection["operation"]["terminalResult"]["members"],
            json!([{
                "identity": {"provider": "codex", "id": "codex-member"},
                "backupId": "codex-backup"
            }])
        );
        let encoded = inspection.to_string();
        for secret in [
            "claude-member",
            "claude-resource",
            "claude-backup",
            "claude-target",
        ] {
            assert!(!encoded.contains(secret), "pinned status exposed {secret}");
        }
    }
}

pub(super) fn result_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

pub(super) fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

pub(super) fn encode_message(body: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(body.len() + 1);
    encoded.extend_from_slice(body.as_bytes());
    encoded.push(b'\n');
    encoded
}
