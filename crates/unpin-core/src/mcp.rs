use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::capabilities::{validate_capability_matrix, validate_provider_fixtures};
use crate::catalog::{Catalog, CatalogRecord, adoption::plan_discovered_adoption};
use crate::control::{
    ControlStatus, ReachAwareStatusAuthorization, attach_reach_aware_status_for_operation,
    build_control_status,
};
use crate::control_operation::{
    ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
    ControlResolvedContext, ReachAwarePrincipal, ReachAwareRootBinding,
};
use crate::discovery::{
    DiscoveryItem, DiscoveryKind, DiscoveryOutput, DiscoveryRoots, ProviderId, discover_all,
};
use crate::groups::{
    GroupAccessContext, GroupApplyResult, GroupApprovalArtifactStore, GroupController,
    GroupOperationAuthorizationLink, GroupOperationStore, GroupPlanDisposition, GroupPlanError,
    GroupPlanMode, GroupPlanner, GroupRef, GroupResolveError, GroupResolver, GroupTargetState,
    GroupTogglePlan, McpGroupSessionLeaseStore, PersonalGroupStore, RepositoryGroupStore,
    current_unix_seconds, index_discovery, issue_group_approval_challenge,
    verify_group_approval_challenge,
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
    ProfileStore, capability_lock_enforcement, compile_profile, profile_reach_scope_digest,
    propose_profile, resolve_effective_gateway,
};
use crate::provider_reach::{
    ConnectionBoundary, DerivedTargetKind, ProviderReachInput, ProviderReachLifecycle,
    ProviderReachRequest, SelectedProviderAuthority, SelectedProviderProvenance,
};
use crate::sessions::{
    GatewayModeAction, GatewayModeController, GatewayModeTarget, GatewayWorkflowController,
    PinnedExposure, PinnedProfile, SessionAuthorityKey, SessionEndController,
};
use crate::snapshots::build_inventory_summary;
use crate::state::workspace::resolve_workspace_identity;
use crate::{
    approval::{
        ApprovalExpectation, ApprovalKey, ApprovalVerifier, CONTROL_APPROVAL_AUDIENCE,
        ControlApprovalContext, approval_binding_digest, authorize_control,
    },
    transitions::{EffectActivation, TransitionContext, TransitionJournalStore, TransitionPlan},
};

// Keep the public MCP contract in one Unpin-owned namespace.
pub const UNPIN_MCP_TOOL_NAMES: &[&str] = &[
    "unpin_get_inventory_summary",
    "unpin_list_items",
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

const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const LATEST_MCP_PROTOCOL_VERSION: &str = SUPPORTED_MCP_PROTOCOL_VERSIONS[0];
const ADOPTION_APPROVAL_ISSUER: &str = "unpin-cli-human";
const ADOPTION_APPROVAL_AUDIENCE: &str = "unpin-core-transition";
const HOOK_TRUST_APPROVAL_ISSUER: &str = "unpin-cli-human";
const HOOK_TRUST_APPROVAL_AUDIENCE: &str = "unpin-core-hook-trust";
const MAX_MCP_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const UNPIN_CONTROL_CONTRACT_VERSION: u32 = 2;
const DEFAULT_MCP_DISCOVERY_CACHE_TTL: Duration = Duration::from_millis(250);
const MCP_HANDOFF_TTL_SECONDS: i64 = 60 * 60;

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

    fn get_or_discover(&self, roots: &DiscoveryRoots) -> Result<DiscoveryOutput, String> {
        self.get_or_update(|| discover_all(roots).map_err(|error| error.to_string()))
    }

    fn refresh(&self, roots: &DiscoveryRoots) -> Result<DiscoveryOutput, String> {
        self.refresh_with(|| discover_all(roots).map_err(|error| error.to_string()))
    }

    fn get_or_update(
        &self,
        load: impl FnOnce() -> Result<DiscoveryOutput, String>,
    ) -> Result<DiscoveryOutput, String> {
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

        let discovery = load()?;
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

    fn refresh_with(
        &self,
        load: impl FnOnce() -> Result<DiscoveryOutput, String>,
    ) -> Result<DiscoveryOutput, String> {
        let generation = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        let discovery = load()?;
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
struct DiscoveryCacheState {
    generation: u64,
    entry: Option<CachedDiscovery>,
}

#[derive(Debug, Clone)]
struct CachedDiscovery {
    refreshed_at: Instant,
    discovery: DiscoveryOutput,
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

        assert_eq!(cached, refreshed);
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

    fn allows(self, provider: ProviderId) -> bool {
        self.provider().is_none_or(|allowed| allowed == provider)
    }

    fn require_allowed(self, provider: ProviderId) -> Result<ProviderId, String> {
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

    fn require_allowed_optional(self, provider: Option<ProviderId>) -> Result<(), String> {
        match (self.provider(), provider) {
            (None, _) => Ok(()),
            (Some(_), Some(provider)) => self.require_allowed(provider).map(|_| ()),
            (Some(allowed), None) => Err(format!(
                "target is not associated with MCP provider scope {}",
                allowed.as_str()
            )),
        }
    }

    fn validate_arguments(self, arguments: &Value) -> Result<(), String> {
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

    fn filter_discovery(self, mut discovery: DiscoveryOutput) -> DiscoveryOutput {
        if let Some(provider) = self.provider() {
            discovery.items.retain(|item| item.provider == provider);
            discovery
                .warnings
                .retain(|warning| warning.provider == provider);
        }
        discovery
    }

    fn filter_control_status(self, control: &mut ControlStatus) {
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

    match method {
        "initialize" => {
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
            result_response(
                id,
                json!({
                    "protocolVersion": negotiated_protocol_version(request),
                    "serverInfo": {
                        "name": "unpin",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "capabilities": {
                        "tools": {},
                        "experimental": {
                            "unpinControl": control
                        }
                    }
                }),
            )
        }
        "notifications/initialized" => result_response(id, json!({})),
        "tools/list" => result_response(id, json!({ "tools": tool_descriptors(context) })),
        "tools/call" => match handle_tool_call(context, request) {
            Ok(result) => result_response(id, result),
            Err(message) => error_response(id, -32000, message),
        },
        _ => error_response(id, -32601, format!("unsupported method: {method}")),
    }
}

fn negotiated_protocol_version(request: &Value) -> &'static str {
    let requested = request
        .get("params")
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str);

    SUPPORTED_MCP_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|supported| Some(*supported) == requested)
        .unwrap_or(LATEST_MCP_PROTOCOL_VERSION)
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

fn handle_stdio_message(context: &McpContext, body: &[u8]) -> Option<Value> {
    let request = match serde_json::from_slice::<Value>(body) {
        Ok(request) => request,
        Err(_) => return Some(error_response(Value::Null, -32700, "parse error")),
    };

    handle_mcp_response(context, &request)
}

fn handle_mcp_response(context: &McpContext, request: &Value) -> Option<Value> {
    request.get("id")?;

    Some(handle_mcp_request(context, request))
}

fn read_message_body(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, io::Error> {
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

fn handle_tool_call(context: &McpContext, request: &Value) -> Result<Value, String> {
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

fn propose_session_profile(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["prompt", "provider"],
        "profile proposal arguments",
    )?;
    let prompt = required_string(arguments, "prompt")?;
    let provider = optional_provider(context, arguments)?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let store = ProfileStore::new(&context.app_state_root);
    let mut profiles = store
        .list_global_definitions()
        .map_err(|error| error.to_string())?;
    profiles.extend(
        ProfileStore::list_workspace_definitions(&context.project_root)
            .map_err(|error| error.to_string())?,
    );
    let proposal = propose_profile(
        prompt,
        &identity.repository_key,
        &identity.workspace_key,
        provider,
        profiles,
    )
    .map_err(|error| error.to_string())?;
    Ok(json!({
        "status": if proposal.recommended.is_some() { "proposed" } else { "selection-required" },
        "proposal": proposal,
        "humanAction": {
            "code": "confirm-session-profile",
            "guidance": "Ask the user to choose the proposed profile, then use the explicit session launch handoff. This tool never changes exposure.",
        },
    }))
}

fn list_inventory_groups(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &[], "inventory group list arguments")?;
    let resolver = group_resolver(context)?;
    let discovery = discover_inventory_groups(context)?;
    let (groups, mut warnings) = resolver
        .list_views_with_warnings(&discovery)
        .map_err(|error| public_group_resolve_error(&error))?;
    for warning in &mut warnings {
        warning.message = "inventory group scope is unavailable".to_string();
    }
    let groups = groups
        .iter()
        .map(|view| public_group_view_value(view, context.provider_scope.provider()))
        .collect::<Vec<_>>();
    Ok(json!({
        "status": "ok",
        "groups": groups,
        "count": groups.len(),
        "warnings": warnings,
    }))
}

fn get_inventory_group(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &["group"], "inventory group get arguments")?;
    let reference =
        GroupRef::parse(required_string(arguments, "group")?).map_err(|error| error.to_string())?;
    let resolver = group_resolver(context)?;
    let discovery = discover_inventory_groups(context)?;
    let view = match resolver.inspect(&reference, &discovery) {
        Ok(view) => view,
        Err(GroupResolveError::Ambiguous { candidates, .. }) => {
            return Ok(ambiguous_group_value(&candidates));
        }
        Err(error) => return Err(public_group_resolve_error(&error)),
    };
    let public_view = public_group_view_value(&view, context.provider_scope.provider());
    Ok(json!({
        "status": if view.context_compatible { "ok" } else { "context-mismatch" },
        "group": public_view,
    }))
}

fn plan_inventory_group(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["group", "targetEnabled", "maxMembers", "providerReach"],
        "inventory group plan arguments",
    )?;
    let reference =
        GroupRef::parse(required_string(arguments, "group")?).map_err(|error| error.to_string())?;
    let target = if arguments
        .get("targetEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| "missing required field: targetEnabled".to_string())?
    {
        GroupTargetState::Enable
    } else {
        GroupTargetState::Disable
    };
    let max_members = arguments
        .get("maxMembers")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "maxMembers must be a positive integer".to_string())?;
    let actionable = context.approved_group_apply.is_some()
        && context.backup_authentication_key.is_some()
        && context.session_authority_key.is_some();
    let mode = if actionable {
        GroupPlanMode::McpHandoff
    } else {
        GroupPlanMode::PreviewOnly
    };
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let reach = parse_bulk_provider_reach(
        arguments.get("providerReach"),
        context.provider_scope.provider(),
    )?;
    let reach_request = ProviderReachRequest::new(boundary, reach, DerivedTargetKind::Group);
    // This validation is deliberately before group discovery and provider
    // planning. An all-provider MCP connection must state its reach explicitly.
    reach_request
        .clone()
        .validate_before_discovery()
        .map_err(|error| error.to_string())?;
    let planner = GroupPlanner::new(group_resolver(context)?);
    let plan = match planner.plan_with_provider_reach_request(
        &reference,
        target,
        max_members,
        mode,
        reach_request,
    ) {
        Ok(plan) => plan,
        Err(GroupPlanError::Resolve(GroupResolveError::Ambiguous { candidates, .. })) => {
            return Ok(ambiguous_group_value(&candidates));
        }
        Err(error) => return Err(public_group_plan_error(&error)),
    };
    let (status, approval, guidance) = match plan.disposition {
        GroupPlanDisposition::Preview => (
            "preview",
            "unavailable",
            Some(
                "Start persistent MCP with approved group apply enabled to request an authorizable plan.",
            ),
        ),
        GroupPlanDisposition::NoOp => ("no-op", "not-required", None),
        GroupPlanDisposition::Blocked => ("blocked", "not-required", None),
        GroupPlanDisposition::Actionable => (
            "actionable",
            "required",
            Some(
                "Review this complete plan in `unpin group approve`, then call unpin_apply_inventory_group with the exact operation, fingerprint, challenge, and one-time artifact.",
            ),
        ),
    };
    let public_plan = public_group_plan_value(&plan, context.provider_scope.provider());
    let mut response = json!({
        "status": status,
        "approval": approval,
        "plan": public_plan,
        "humanAction": guidance.map(|guidance| json!({
            "code": if actionable { "approve-for-mcp-apply" } else { "approved-group-mode-required" },
            "guidance": guidance,
        })),
    });
    if plan.disposition == GroupPlanDisposition::Actionable {
        let approved = context
            .approved_group_apply
            .as_ref()
            .ok_or_else(|| "approved-group MCP session is unavailable".to_string())?;
        let session_key = context
            .session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority credential is unavailable".to_string())?;
        let now_unix = current_unix_seconds()
            .map_err(|_| "inventory group approval is unavailable".to_string())?;
        let lease_expires_at = McpGroupSessionLeaseStore::new(&context.app_state_root)
            .verify(&approved.session, session_key, now_unix)
            .map_err(|_| "inventory group approval is unavailable".to_string())?;
        let challenge = issue_group_approval_challenge(
            plan.clone(),
            approved.session.clone(),
            lease_expires_at,
            session_key,
            now_unix,
        )
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
        response["challenge"] = json!(challenge);
        response["operationId"] = json!(plan.operation_id);
        response["planFingerprint"] = json!(plan.plan_fingerprint);
    }
    Ok(response)
}

fn apply_inventory_group(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &[
            "operationId",
            "planFingerprint",
            "challenge",
            "approvalArtifact",
        ],
        "inventory group apply arguments",
    )?;
    let approved = context
        .approved_group_apply
        .as_ref()
        .ok_or_else(|| "approved-group MCP apply is unavailable".to_string())?;
    let backup_key = context
        .backup_authentication_key
        .as_ref()
        .ok_or_else(|| "backup authentication credential is unavailable".to_string())?;
    let session_key = context
        .session_authority_key
        .as_ref()
        .ok_or_else(|| "session authority credential is unavailable".to_string())?;
    let operation_id = required_string(arguments, "operationId")?;
    let plan_fingerprint = required_string(arguments, "planFingerprint")?;
    let challenge = required_string(arguments, "challenge")?;
    let artifact_id = required_string(arguments, "approvalArtifact")?;
    let now_unix = current_unix_seconds()
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let lease_expires_at = McpGroupSessionLeaseStore::new(&context.app_state_root)
        .verify(&approved.session, session_key, now_unix)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let claims = verify_group_approval_challenge(
        challenge,
        &approved.session,
        lease_expires_at,
        session_key,
        now_unix,
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    if claims.plan.operation_id.as_deref() != Some(operation_id)
        || claims.plan.plan_fingerprint != plan_fingerprint
    {
        return Ok(blocked_value("inventory group approval binding mismatch"));
    }
    let resolver = group_resolver(context)?;
    let planner = GroupPlanner::new(resolver);
    let approval_context = ControlApprovalContext::new(
        planner.resolver().context().repository_key(),
        planner.resolver().context().workspace_key(),
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let expectation = claims
        .plan
        .approval_expectation(&approval_context)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let artifact_store = GroupApprovalArtifactStore::new(&context.app_state_root);
    let (receipt, consumed_decision_digest, consume_artifact) = match artifact_store.load_ready(
        artifact_id,
        operation_id,
        plan_fingerprint,
        challenge,
        &approved.session,
        session_key,
        now_unix,
    ) {
        Ok(artifact) => (artifact.receipt, None, true),
        Err(_) => {
            let consumed = artifact_store
                .load_consumed(
                    artifact_id,
                    operation_id,
                    plan_fingerprint,
                    challenge,
                    &approved.session,
                    session_key,
                    now_unix,
                )
                .map_err(|_| "inventory group approval artifact is unavailable".to_string())?;
            (consumed.receipt, Some(consumed.decision_digest), false)
        }
    };
    let verifier = ApprovalVerifier::new(approved.approval_key.clone());
    let verified = verifier
        .verify(&receipt, &expectation, now_unix)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let decision_digest = verified.decision_digest().to_string();
    if consumed_decision_digest
        .as_deref()
        .is_some_and(|consumed| consumed != decision_digest)
    {
        return Err("inventory group approval artifact is unavailable".to_string());
    }
    let mut fixture_write_paths = vec![context.app_state_root.clone()];
    let existing_operation =
        GroupOperationStore::new(context.app_state_root.clone(), backup_key.clone())
            .load(operation_id)
            .map_err(|_| "inventory group operation evidence is unavailable".to_string())?
            .map(|snapshot| snapshot.value);
    let status_only = existing_operation.as_ref().is_some_and(|operation| {
        operation.provider_writes_started || operation.terminal_result.is_some()
    });
    if existing_operation.is_some() {
        let discovery = discover_inventory_groups(context)?;
        let discovery_index = index_discovery(&discovery);
        for member in &claims.plan.members {
            if member.outcome != crate::groups::GroupMemberPlanOutcome::Changed {
                continue;
            }
            let matches = discovery_index
                .get(&member.identity)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let item = match matches {
                [] => {
                    return Ok(blocked_value(
                        "inventory group member disappeared before apply",
                    ));
                }
                [item] => *item,
                _ => {
                    return Ok(blocked_value(
                        "inventory group member became ambiguous before apply",
                    ));
                }
            };
            fixture_write_paths.extend(
                [item.source_path.as_str(), item.state_path.as_str()]
                    .into_iter()
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from),
            );
        }
    } else {
        let revalidated = planner
            .revalidate(&claims.plan)
            .map_err(|error| public_group_plan_error(&error))?;
        if revalidated.plan_fingerprint != claims.plan.plan_fingerprint {
            return Ok(blocked_value(
                "inventory group plan no longer matches current state",
            ));
        }
        for member in &revalidated.members {
            if member.outcome != crate::groups::GroupMemberPlanOutcome::Changed {
                continue;
            }
            let native = member.native_plan.as_ref().ok_or_else(|| {
                "actionable inventory group member has no sealed native plan".to_string()
            })?;
            fixture_write_paths.extend(
                native
                    .preview
                    .affected_targets
                    .iter()
                    .map(|target| PathBuf::from(&target.path)),
            );
        }
    }
    crate::fixture::require_fixture_write_sandbox(
        context.fixture_root.is_some(),
        fixture_write_paths.iter().map(PathBuf::as_path),
    )
    .map_err(|_| "inventory group apply is outside the fixture write sandbox".to_string())?;
    let controller = GroupController::new(planner, backup_key.clone(), session_key.clone());
    if !status_only {
        controller
            .seal_authorizing_operation(
                &claims.plan,
                &decision_digest,
                GroupOperationAuthorizationLink {
                    artifact_digest: approval_binding_digest(artifact_id),
                    nonce_digest: approval_binding_digest(&receipt.claims.nonce),
                    session_id: approved.session.session_id.clone(),
                    session_generation: approved.session.generation,
                },
            )
            .map_err(|_| "inventory group operation evidence is unavailable".to_string())?;
    }
    let authorization = authorize_control(
        &context.app_state_root,
        &receipt,
        &verifier,
        &expectation,
        now_unix,
        crate::state::atomic_json::OwnerGeneration::new(
            format!("mcp-group-apply:{}", approved.session.session_id),
            approved.session.generation,
        )
        .map_err(|_| "inventory group approval is unavailable".to_string())?,
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    if consume_artifact {
        artifact_store
            .consume(
                artifact_id,
                operation_id,
                plan_fingerprint,
                challenge,
                &approved.session,
                authorization.decision_digest(),
                session_key,
                now_unix,
            )
            .map_err(|_| "inventory group approval artifact is unavailable".to_string())?;
    }
    if status_only {
        context.discovery_cache.invalidate();
        return match controller.status_without_reauthorization(&claims.plan) {
            Ok(result) => group_apply_response(&claims.plan, &expectation, &result),
            Err(_) => Ok(group_recovery_required_response(operation_id)),
        };
    }
    let result = match controller.apply(&claims.plan, authorization) {
        Ok(result) => result,
        Err(_) => {
            context.discovery_cache.invalidate();
            if controller
                .operation(operation_id)
                .ok()
                .flatten()
                .is_some_and(|operation| {
                    operation.provider_writes_started || operation.terminal_result.is_some()
                })
            {
                return Ok(group_recovery_required_response(operation_id));
            }
            return Ok(json!({
                "status": "failed",
                "operationId": operation_id,
                "error": {
                    "code": "group-apply-failed",
                    "message": "inventory group apply failed",
                },
            }));
        }
    };
    context.discovery_cache.invalidate();
    group_apply_response(&claims.plan, &expectation, &result)
}

fn group_recovery_required_response(operation_id: &str) -> Value {
    json!({
        "status": "recovery-required",
        "operationId": operation_id,
        "error": {
            "code": "group-recovery-required",
            "message": "inventory group provider writes may have started; inspect the durable operation and backup evidence",
        },
        "guidance": "Run `unpin group operation-show <operationId> --json` before any further apply.",
    })
}

fn group_apply_response(
    plan: &GroupTogglePlan,
    expectation: &ApprovalExpectation,
    result: &GroupApplyResult,
) -> Result<Value, String> {
    let activation = plan
        .resources
        .iter()
        .fold(EffectActivation::Live, |activation, resource| {
            activation.max(resource.activation)
        });
    let providers = plan
        .provider_coverage
        .entries()
        .iter()
        .map(|entry| entry.provider)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let operation = result
        .control_operation_envelope(expectation, activation, providers)
        .map_err(|_| "inventory group operation result is unavailable".to_string())?;
    let status = match result.provider_reach_lifecycle {
        crate::provider_reach::ProviderReachLifecycle::Applied => match result.lifecycle {
            crate::groups::GroupOperationLifecycle::Completed => "applied",
            crate::groups::GroupOperationLifecycle::Partial
            | crate::groups::GroupOperationLifecycle::Failed => "blocked",
            crate::groups::GroupOperationLifecycle::RecoveryRequired => "recovery-required",
            crate::groups::GroupOperationLifecycle::InProgress => {
                return Err("inventory group operation result is unavailable".to_string());
            }
        },
        crate::provider_reach::ProviderReachLifecycle::Partial => "partial",
        crate::provider_reach::ProviderReachLifecycle::NoOp => "no-op",
        crate::provider_reach::ProviderReachLifecycle::NoTargetsInProviderReach => {
            "no-targets-in-provider-reach"
        }
        crate::provider_reach::ProviderReachLifecycle::Blocked => "blocked",
        crate::provider_reach::ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    };
    let mut operation = serde_json::to_value(operation)
        .map_err(|_| "inventory group operation result is unavailable".to_string())?;
    if let Some(allowed) = plan.provider_reach.provider()
        && let Some(result_value) = operation
            .get_mut("details")
            .and_then(|details| details.get_mut("result"))
    {
        *result_value = public_group_result_value(result, Some(allowed));
    }
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": result.operation_id,
        "planFingerprint": result.plan_fingerprint,
        "providerReach": result.provider_reach,
        "providerCoverage": result.provider_coverage,
        "lifecycle": result.provider_reach_lifecycle,
        "operation": operation,
        "operationV2": {
            "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
            "family": "group-toggle",
            "operationId": result.operation_id,
            "operationKind": "inventory-group-apply",
            "planFingerprint": result.plan_fingerprint,
            "providerReach": result.provider_reach,
            "providerCoverage": result.provider_coverage,
            "lifecycle": status,
            "expectedLifecycle": result.provider_reach_lifecycle,
            "activation": activation,
            "humanAction": null
        }
    }))
}

fn public_group_plan_value(plan: &GroupTogglePlan, allowed: Option<ProviderId>) -> Value {
    let mut value = serde_json::to_value(plan).expect("group plan serializes");
    redact_group_projection(&mut value, allowed);
    value
}

fn public_group_result_value(result: &GroupApplyResult, allowed: Option<ProviderId>) -> Value {
    let mut value = serde_json::to_value(result).expect("group result serializes");
    redact_group_projection(&mut value, allowed);
    value
}

fn public_group_view_value(
    view: &crate::groups::GroupDefinitionView,
    allowed: Option<ProviderId>,
) -> Value {
    let mut value = serde_json::to_value(view).expect("group view serializes");
    if let Some(allowed) = allowed {
        redact_group_view_projection(&mut value, allowed);
    }
    value
}

fn redact_group_projection(value: &mut Value, allowed: Option<ProviderId>) {
    let Some(allowed) = allowed else {
        return;
    };
    let allowed_value = serde_json::to_value(allowed).expect("provider serializes");
    for key in ["members", "groupMembers"] {
        if let Some(members) = value.get_mut(key).and_then(Value::as_array_mut) {
            members.retain(|member| {
                member
                    .get("identity")
                    .and_then(|identity| identity.get("provider"))
                    .is_some_and(|provider| provider == &allowed_value)
            });
        }
    }
    if let Some(definition_view) = value.get_mut("definitionView") {
        redact_group_view_projection(definition_view, allowed);
    }
    let mut excluded_counts = BTreeMap::<String, usize>::new();
    if let Some(entries) = value
        .get_mut("providerCoverage")
        .and_then(|coverage| coverage.get_mut("entries"))
        .and_then(Value::as_array_mut)
    {
        entries.retain(|entry| {
            let included = entry
                .get("included")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if included {
                return true;
            }
            if let Some(provider) = entry.get("provider").and_then(Value::as_str) {
                *excluded_counts.entry(provider.to_string()).or_default() += 1;
            }
            false
        });
    }
    if !excluded_counts.is_empty() {
        value["reachExclusions"] = json!({
            "providers": excluded_counts
                .iter()
                .map(|(provider, count)| json!({"provider": provider, "count": count}))
                .collect::<Vec<_>>(),
            "count": excluded_counts.values().sum::<usize>(),
            "reason": "out-of-provider-reach",
        });
    }
}

fn redact_group_view_projection(value: &mut Value, allowed: ProviderId) {
    if value.get("contextCompatible").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let allowed_value = serde_json::to_value(allowed).expect("provider serializes");
    let mut excluded_counts = BTreeMap::<String, usize>::new();
    if let Some(members) = value.get_mut("members").and_then(Value::as_array_mut) {
        members.retain(|member| {
            let provider = member
                .get("identity")
                .and_then(|identity| identity.get("provider"));
            let retained = provider == Some(&allowed_value);
            if !retained && let Some(provider) = provider.and_then(Value::as_str) {
                *excluded_counts.entry(provider.to_string()).or_default() += 1;
            }
            retained
        });
    }
    if let Some(providers) = value
        .get_mut("providerCoverage")
        .and_then(Value::as_array_mut)
    {
        providers.retain(|provider| provider == &allowed_value);
    }

    let Some(members) = value.get("members").and_then(Value::as_array) else {
        return;
    };
    if members.is_empty() {
        for field in ["counts", "state", "fresh"] {
            value
                .as_object_mut()
                .expect("group view is an object")
                .remove(field);
        }
    } else {
        let mut enabled = 0_u64;
        let mut disabled = 0_u64;
        let mut blocked = 0_u64;
        let mut missing = 0_u64;
        let mut ambiguous = 0_u64;
        let mut stale = 0_u64;
        let mut observed = Vec::with_capacity(members.len());
        for member in members {
            let state = member.get("enabled").and_then(Value::as_bool);
            observed.push(state);
            match state {
                Some(true) => enabled += 1,
                Some(false) => disabled += 1,
                None => match member.get("reason").and_then(Value::as_str) {
                    Some("missing") => missing += 1,
                    Some("ambiguous") => ambiguous += 1,
                    _ => {}
                },
            }
            if state.is_some() && member.get("eligible").and_then(Value::as_bool) == Some(false) {
                blocked += 1;
            }
            if member.get("reason").and_then(Value::as_str) == Some("observation-stale") {
                stale += 1;
            }
        }
        value["counts"] = json!({
            "enabled": enabled,
            "disabled": disabled,
            "blocked": blocked,
            "missing": missing,
            "ambiguous": ambiguous,
            "stale": stale,
        });
        value["state"] = if observed.iter().all(|state| *state == Some(true)) {
            json!("on")
        } else if observed.iter().all(|state| *state == Some(false)) {
            json!("off")
        } else {
            json!("mixed")
        };
        value["fresh"] = json!(stale == 0);
    }
    if !excluded_counts.is_empty() {
        value["reachExclusions"] = json!({
            "providers": excluded_counts
                .iter()
                .map(|(provider, count)| json!({"provider": provider, "count": count}))
                .collect::<Vec<_>>(),
            "count": excluded_counts.values().sum::<usize>(),
            "reason": "out-of-provider-reach",
        });
    }
}

fn group_resolver(context: &McpContext) -> Result<GroupResolver, String> {
    let access = GroupAccessContext::from_runtime(
        &context.app_state_root,
        &context.project_root,
        &context.discovery_roots,
        context.provider_scope.provider(),
        None,
    )
    .map_err(|_| "inventory group context is unavailable".to_string())?;
    Ok(GroupResolver::new(
        access.clone(),
        PersonalGroupStore::new(access.clone()),
        RepositoryGroupStore::new(access),
    ))
}

fn discover_inventory_groups(context: &McpContext) -> Result<DiscoveryOutput, String> {
    discover_scoped(context).map_err(|_| "inventory group discovery is unavailable".to_string())
}

fn public_group_resolve_error(error: &GroupResolveError) -> String {
    match error {
        GroupResolveError::Store(_) | GroupResolveError::ScopeUnavailable { .. } => {
            "inventory group storage is unavailable".to_string()
        }
        GroupResolveError::NotFound(_) | GroupResolveError::Ambiguous { .. } => error.to_string(),
    }
}

fn ambiguous_group_value(candidates: &[String]) -> Value {
    json!({
        "status": "ambiguous",
        "error": {
            "code": "group-reference-ambiguous",
            "message": "inventory group reference is ambiguous",
            "candidates": candidates,
        },
    })
}

fn public_group_plan_error(error: &GroupPlanError) -> String {
    match error {
        GroupPlanError::Resolve(error) => public_group_resolve_error(error),
        GroupPlanError::ProviderReach(error) => error.to_string(),
        GroupPlanError::InvalidMaximum { .. }
        | GroupPlanError::MaximumExceeded { .. }
        | GroupPlanError::ContextMismatch
        | GroupPlanError::NotActionable
        | GroupPlanError::InvalidPlan
        | GroupPlanError::FingerprintMismatch => error.to_string(),
        GroupPlanError::Discovery(_)
        | GroupPlanError::Transition(_)
        | GroupPlanError::Validation(_)
        | GroupPlanError::Approval(_)
        | GroupPlanError::Serialization(_)
        | GroupPlanError::IdentifierGeneration(_) => {
            "inventory group planning is unavailable".to_string()
        }
    }
}

fn validate_profile(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["profileId", "definition", "sourceScope"],
        "profile validation arguments",
    )?;
    let stored_id = optional_string(arguments, "profileId")?;
    let inline = arguments.get("definition");
    let (definition, source_scope) = match (stored_id, inline) {
        (Some(profile_id), None) => load_stored_profile(context, profile_id)?,
        (None, Some(definition)) => {
            let definition = serde_json::from_value::<ProfileDefinition>(definition.clone())
                .map_err(|error| format!("profile definition is invalid: {error}"))?;
            let source_scope =
                parse_profile_source_scope(required_string(arguments, "sourceScope")?)?;
            (definition, source_scope)
        }
        _ => {
            return Err(
                "provide exactly one of profileId or definition; inline definitions require sourceScope"
                    .to_string(),
            );
        }
    };
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let revision =
        compile_profile(&definition, &catalog, source_scope).map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "valid",
        "sourceScope": profile_source_scope_name(source_scope),
        "revision": revision,
        "materialized": false,
    }))
}

fn structured_result(value: Value) -> Result<Value, String> {
    let text = serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": value
    }))
}

fn get_inventory_summary(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    validate_selector(arguments)?;
    let discovery = discover_scoped_cached(context)?;
    let discovery = filter_summary_discovery(discovery, arguments);

    Ok(json!({
        "status": "ok",
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
        "providerScope": context.provider_scope.as_str(),
        "projectRoot": context.project_root.to_string_lossy().into_owned(),
        "writeSafety": {
            "backupAuthentication": context.authentication.backup_authentication.status,
            "backupAuthenticationDetails": &context.authentication.backup_authentication,
            "approvalSigning": &context.authentication.approval_signing,
            "cursorDashboard": &context.authentication.cursor_dashboard,
            "humanApproval": "cli-or-tui-required",
            "writesEnabled": false
        },
        "inventory": {
            "providers": provider_summaries(&discovery, arguments, context.provider_scope)
        },
        "warnings": discovery.warnings
    }))
}

fn list_items(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let discovery = discover_scoped_cached(context)?;
    let selector = arguments.get("selector").unwrap_or(&Value::Null);
    validate_selector(selector)?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0);
    let mut items = discovery
        .items
        .into_iter()
        .filter(|item| selector_matches(item, selector))
        .collect::<Vec<_>>();
    let total_matched = items.len();
    if let Some(limit) = limit {
        items.truncate(limit);
    }

    Ok(json!({
        "status": "ok",
        "selector": selector,
        "totalMatched": total_matched,
        "items": items,
        "warnings": discovery.warnings
    }))
}

fn get_policy_maintenance_status(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["repositoryKey", "workspaceKey", "candidateCurrent"],
        "policy maintenance status arguments",
    )?;
    let repository_key = optional_string(arguments, "repositoryKey")?;
    let workspace_key = optional_string(arguments, "workspaceKey")?;
    let candidate_current = match arguments.get("candidateCurrent") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "candidateCurrent must be a boolean".to_string())?,
        None => false,
    };
    let target = match (repository_key, workspace_key) {
        (Some(repository_key), Some(workspace_key)) => {
            PolicyTarget::workspace(repository_key, workspace_key)
                .map_err(|error| error.to_string())?
        }
        (None, None) => {
            let identity = resolve_workspace_identity(&context.project_root)
                .map_err(|error| error.to_string())?;
            PolicyTarget::workspace(identity.repository_key, identity.workspace_key)
                .map_err(|error| error.to_string())?
        }
        _ => {
            return Err("repositoryKey and workspaceKey must be supplied together".to_string());
        }
    };
    let Some(authentication_key) = context.backup_authentication_key.clone() else {
        return Ok(json!({
            "status": "blocked",
            "reason": "backup-authentication-key-missing",
            "target": target,
            "humanAction": {
                "code": "initialize-backup-authentication",
                "guidance": "Run `unpin auth backup init`, restart the MCP session, then retry."
            }
        }));
    };
    let controller = PolicyMaintenanceController::new(
        &context.app_state_root,
        &context.project_root,
        authentication_key,
    );
    let candidate = candidate_current.then_some(context.project_root.as_path());
    let status = match controller.status(&target, candidate) {
        Ok(status) => status,
        Err(error) => {
            return Ok(json!({
                "status": "blocked",
                "reason": "policy-maintenance-verification-failed",
                "message": error.to_string(),
                "target": target,
                "humanAction": {
                    "code": "inspect-policy-maintenance",
                    "guidance": "Run `unpin profile policy status --json` with the recorded workspace keys. MCP policy mutation remains disabled."
                }
            }));
        }
    };
    let Some(status) = status else {
        return Ok(json!({
            "status": "unmanaged",
            "target": target,
            "humanAction": {
                "code": "review-policy-migration",
                "guidance": "Run `unpin profile policy migrate --json`, review the plan, then apply it through the CLI with exact confirmation."
            }
        }));
    };
    let human_action = status.allowed_actions.first().map(|action| {
        let PolicyTarget::Workspace {
            repository_key,
            workspace_key,
        } = &status.target
        else {
            unreachable!("maintenance records are workspace-scoped");
        };
        let guidance = match action.as_str() {
            "reattach" => format!(
                "Run `unpin profile policy reattach --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            "discard" => format!(
                "Run `unpin profile policy discard --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            "cleanup" => format!(
                "Run `unpin profile policy cleanup --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            _ => "Inspect the authenticated policy status in the CLI.".to_string(),
        };
        json!({
            "code": format!("review-policy-{action}"),
            "guidance": guidance
        })
    });
    Ok(json!({
        "status": "managed",
        "maintenance": status,
        "humanAction": human_action,
        "mutationsAvailable": false
    }))
}

fn get_control_status(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &["operationId"], "control status arguments")?;
    let operation_id = optional_string(arguments, "operationId")?;
    let discovery = discover_scoped_cached(context)?;
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let mut control = build_control_status(
        &discovery,
        &app_state_root,
        &context.project_root,
        context
            .session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    context.provider_scope.filter_control_status(&mut control);
    if let Some(operation_id) = operation_id {
        control
            .operations
            .retain(|operation| operation.operation_id == operation_id);
        let journals = TransitionJournalStore::new(&app_state_root)
            .list()
            .map_err(|error| error.to_string())?;
        if let Some(authorization) =
            reach_aware_status_authorization(context, operation_id, &journals)?
        {
            attach_reach_aware_status_for_operation(
                &mut control,
                &journals,
                Some(operation_id),
                &authorization,
                context
                    .session_authority_key
                    .as_ref()
                    .ok_or_else(|| "session authority key is unavailable".to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        control.operations.retain(|operation| {
            operation.operation_id == operation_id && operation.reach_aware.is_some()
        });
    }
    Ok(json!({
        "status": "ok",
        "control": control,
        "warnings": discovery.warnings
    }))
}

/// A regular MCP connection has no caller-supplied session identity.  Reuse
/// only the authenticated principal sealed in the journal and require its
/// connection boundary to equal this MCP context's configured boundary.  The
/// journal's signature, not caller metadata, establishes the identity; missing
/// or mismatched records remain non-disclosing v1 status rather than becoming
/// a journal lookup oracle.
fn reach_aware_status_authorization(
    context: &McpContext,
    operation_id: &str,
    journals: &[crate::transitions::TransitionJournal],
) -> Result<Option<ReachAwareStatusAuthorization>, String> {
    let Some(session_key) = context.session_authority_key.as_ref() else {
        return Ok(None);
    };
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let matching = journals
        .iter()
        .filter(|journal| journal.operation_id == operation_id)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err("reach-aware status authorization is unavailable".to_string());
    }
    let Some(journal) = matching.into_iter().next() else {
        return Ok(None);
    };
    let Some(envelope) = journal.reach_aware.as_ref() else {
        return Ok(None);
    };
    envelope
        .verify_authenticated(session_key)
        .map_err(|_| "reach-aware status authorization is unavailable".to_string())?;
    let configured_boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let capability_scope_digest = envelope
        .transfer_capability
        .as_ref()
        .map_or_else(String::new, |capability| capability.scope_digest.clone());
    let authorization = ReachAwareStatusAuthorization::new(
        envelope.principal.clone(),
        envelope.audience.clone(),
        capability_scope_digest,
        now_unix,
        None,
    );
    match (configured_boundary, envelope.connection_boundary) {
        (ConnectionBoundary::All, ConnectionBoundary::All)
        | (ConnectionBoundary::Pinned(_), ConnectionBoundary::Pinned(_))
            if configured_boundary == envelope.connection_boundary =>
        {
            Ok(Some(authorization))
        }
        (ConnectionBoundary::Pinned(provider), ConnectionBoundary::All) => Ok(Some(
            authorization.with_requested_boundary(ConnectionBoundary::Pinned(provider)),
        )),
        _ => Ok(None),
    }
}

fn list_catalog(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_empty_object(arguments)?;
    let discovery = discover_scoped_cached(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "ok",
        "capabilities": catalog.records.values().collect::<Vec<_>>(),
        "warnings": discovery.warnings,
    }))
}

fn list_hooks(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let provider = optional_provider(context, arguments)?;
    let profile_digest = optional_string(arguments, "profileDigest")?;
    let discovery = discover_scoped_cached(context)?;
    let warnings = discovery.warnings;
    let trust = HookTrustStore::new(&context.app_state_root);
    let hooks = discovery
        .items
        .into_iter()
        .filter(|item| {
            item.kind == DiscoveryKind::Hook && provider.is_none_or(|value| item.provider == value)
        })
        .map(|item| {
            let stored_trust_decision = stored_hook_trust_decision(&trust, &item, profile_digest)?;
            Ok(json!({
                "provider": item.provider,
                "id": item.id,
                "displayName": item.display_name,
                "layer": item.layer,
                "enabled": item.enabled,
                "mutability": item.mutability,
                "handler": item.hook,
                "storedTrustDecision": stored_trust_decision,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "status": "ok",
        "hooks": hooks,
        "warnings": warnings
    }))
}

fn stored_hook_trust_decision(
    trust: &HookTrustStore,
    item: &DiscoveryItem,
    profile_digest: Option<&str>,
) -> Result<bool, String> {
    let Some(profile_digest) = profile_digest else {
        return Ok(false);
    };
    let metadata = item
        .hook
        .as_ref()
        .ok_or_else(|| "hook metadata is missing".to_string())?;
    let record = trust
        .load_for(item.provider, &item.id, metadata, profile_digest)
        .map_err(|error| error.to_string())?;
    Ok(record.is_some_and(|record| {
        record.provider == item.provider
            && record.handler_id == item.id
            && record.handler_fingerprint == metadata.fingerprint
            && record.invocation_fingerprint == metadata.invocation_fingerprint
            && record.profile_digest == profile_digest
    }))
}

fn plan_catalog_adoption(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, capability, transition) = catalog_adoption_plan(context, arguments)?;
    let expectation =
        transition.approval_expectation(ADOPTION_APPROVAL_ISSUER, ADOPTION_APPROVAL_AUDIENCE);
    let operation = control_operation(
        &expectation,
        &transition.effect_graph_digest,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(item.provider),
        json!({
            "item": item,
            "capability": capability,
            "transition": transition,
        }),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "item": item,
        "capability": capability,
        "transition": transition,
        "planFingerprint": transition.effect_graph_digest,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

fn apply_catalog_adoption(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, capability, transition) = catalog_adoption_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &transition.effect_graph_digest)?;
    let expectation =
        transition.approval_expectation(ADOPTION_APPROVAL_ISSUER, ADOPTION_APPROVAL_AUDIENCE);
    Ok(human_action_required(control_operation(
        &expectation,
        &transition.effect_graph_digest,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(item.provider),
        json!({
            "item": item,
            "capability": capability,
            "transition": transition,
        }),
    )))
}

fn catalog_adoption_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(DiscoveryItem, CatalogRecord, TransitionPlan), String> {
    let provider = required_provider(context, arguments)?;
    let item_id = required_string(arguments, "id")?;
    let provider_root = PathBuf::from(required_string(arguments, "providerRoot")?);
    let discovery = discover_scoped(context)?;
    let item = discovery
        .items
        .iter()
        .find(|item| item.provider == provider && item.id == item_id)
        .cloned()
        .ok_or_else(|| "provider item not found".to_string())?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let capability = catalog
        .find_provider_view(provider, item_id)
        .cloned()
        .ok_or_else(|| "catalog capability not found".to_string())?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let operation_id = format!(
        "adopt-{}-{}",
        provider.as_str(),
        capability.fingerprint.chars().take(24).collect::<String>()
    );
    let planned = plan_discovered_adoption(
        &item,
        &capability,
        operation_id,
        provider_root,
        &context.app_state_root,
        TransitionContext {
            repository_key: identity.repository_key,
            workspace_key: identity.workspace_key,
            session_id: None,
            profile_digest: None,
        },
        EffectActivation::NextSessionOnly,
    )
    .map_err(|error| error.to_string())?;
    Ok((item, capability, planned.transition))
}

fn plan_hook_trust(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, expectation, fingerprint) = hook_trust_plan(context, arguments)?;
    let operation = control_operation(
        &expectation,
        &fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(item.provider),
        json!({"hook": item, "expectation": expectation}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "hook": item,
        "expectation": expectation,
        "planFingerprint": fingerprint,
        "activation": "next-session-only",
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

fn apply_hook_trust(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, expectation, fingerprint) = hook_trust_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &fingerprint)?;
    Ok(human_action_required(control_operation(
        &expectation,
        &fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(item.provider),
        json!({"hook": item, "expectation": expectation}),
    )))
}

fn hook_trust_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(DiscoveryItem, ApprovalExpectation, String), String> {
    let provider = required_provider(context, arguments)?;
    let item_id = required_string(arguments, "id")?;
    let profile_digest = required_string(arguments, "profileDigest")?;
    let session_id = optional_string(arguments, "sessionId")?.unwrap_or("profile-policy");
    let discovery = discover_scoped(context)?;
    let item = discovery
        .items
        .iter()
        .find(|item| {
            item.provider == provider && item.kind == DiscoveryKind::Hook && item.id == item_id
        })
        .cloned()
        .ok_or_else(|| "hook not found".to_string())?;
    require_hook_profile_membership(context, &discovery, &item, profile_digest)?;
    let metadata = item
        .hook
        .as_ref()
        .ok_or_else(|| "hook metadata is missing".to_string())?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let expectation = metadata
        .trust_approval_expectation(
            provider,
            item_id,
            profile_digest,
            HOOK_TRUST_APPROVAL_ISSUER,
            HOOK_TRUST_APPROVAL_AUDIENCE,
            &identity.repository_key,
            &identity.workspace_key,
            session_id,
        )
        .map_err(|error| error.to_string())?;
    let fingerprint = expectation.effect_graph_digest.clone();
    Ok((item, expectation, fingerprint))
}

fn require_hook_profile_membership(
    context: &McpContext,
    discovery: &DiscoveryOutput,
    hook: &DiscoveryItem,
    profile_digest: &str,
) -> Result<(), String> {
    let revision = ProfileStore::new(&context.app_state_root)
        .load_revision(profile_digest)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "compiled profile revision is missing".to_string())?;
    let catalog = Catalog::from_discovery(discovery).map_err(|error| error.to_string())?;
    let capability = catalog
        .find_provider_view(hook.provider, &hook.id)
        .ok_or_else(|| "hook capability is missing from catalog".to_string())?;
    if revision.selects(&capability.id, hook.provider) {
        Ok(())
    } else {
        Err("hook is not selected by compiled profile".to_string())
    }
}

fn plan_profile_provider(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (revision, plan) = profile_provider_plan(context, arguments)?;
    let operation_v2 = seal_profile_provider_handoff(context, &plan)?;
    let status = if plan.no_op { "no-op" } else { "planned" };
    let expected_lifecycle = if plan.no_op {
        ProviderReachLifecycle::NoOp
    } else {
        ProviderReachLifecycle::Applied
    };
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.coverage,
        "activation": plan.activation,
        "expectedLifecycle": expected_lifecycle,
        "targets": plan.targets,
        "operation": profile_provider_operation_value(
            context,
            &revision,
            &plan,
            status,
            expected_lifecycle,
        )?,
        "operationV2": operation_v2,
        "handoff": {
            "operationId": plan.operation_id,
            "planFingerprint": plan.plan_fingerprint,
        },
        "profile": revision,
        "plan": plan,
        "humanApprovalRequired": !plan.no_op,
        "continuation": if plan.no_op {
            "No provider policy change is required; retain this operation id for status inspection."
        } else {
            "Review provider reach, provenance, coverage, target classifications, and fingerprint, then call unpin_apply_profile_provider."
        },
    }))
}

fn apply_profile_provider(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let operation_id = required_string(arguments, "operationId")?;
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let controller = ProfileProviderOperationController::new(&app_state_root)
        .with_session_authority_key(session_key);
    let plan = controller.load_handoff(operation_id).map_err(|error| {
        format!("operation id does not match sealed profile provider handoff: {error}")
    })?;
    if let Some(profile_id) = arguments.get("profileId").and_then(Value::as_str)
        && profile_id != plan.profile.profile_id
    {
        return Err("profile id does not match sealed profile provider operation".to_string());
    }
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let revision = compile_stored_profile(context, &plan.profile.profile_id)?;
    let operation_v2 = sealed_profile_provider_operation(&app_state_root, &plan.operation_id)?;
    let lifecycle = if plan.no_op {
        ProviderReachLifecycle::NoOp
    } else {
        ProviderReachLifecycle::Applied
    };
    let status = if plan.no_op {
        "no-op"
    } else {
        "human-action-required"
    };
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.coverage,
        "activation": plan.activation,
        "expectedLifecycle": lifecycle,
        "targets": plan.targets,
        "operation": profile_provider_operation_value(
            context,
            &revision,
            &plan,
            if plan.no_op {
                "no-op"
            } else {
                "awaiting-human-action"
            },
            lifecycle,
        )?,
        "operationV2": operation_v2,
        "handoff": {
            "operationId": plan.operation_id,
            "planFingerprint": plan.plan_fingerprint,
        },
        "profile": revision,
        "plan": plan,
        "continuation": if plan.no_op {
            "No provider policy change is required."
        } else {
            "MCP cannot mint human approval; review and apply this exact fingerprint in Unpin CLI or TUI, then read control status."
        },
    }))
}

fn seal_profile_provider_handoff(
    context: &McpContext,
    plan: &crate::profiles::ProfileProviderOperationPlan,
) -> Result<Value, String> {
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let approval_context = control_approval_context(context)?;
    let session_id = plan.operation_id.clone();
    let expectation = plan
        .approval_expectation(&approval_context, &session_id)
        .map_err(|error| error.to_string())?;
    let connection_boundary = match plan.provider_reach {
        crate::provider_reach::ProviderReach::All => ConnectionBoundary::All,
        crate::provider_reach::ProviderReach::Selected { provider, .. } => {
            ConnectionBoundary::Pinned(provider)
        }
    };
    let principal = ReachAwarePrincipal::sign(
        session_id,
        profile_reach_scope_digest(&expectation, &plan.operation_id),
        connection_boundary,
        &session_key,
    )
    .map_err(|error| error.to_string())?;
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let expires_at_unix = now_unix
        .checked_add(MCP_HANDOFF_TTL_SECONDS)
        .ok_or_else(|| "MCP handoff expiry overflowed".to_string())?;
    let roots = ReachAwareRootBinding::from_provider_paths(
        &app_state_root,
        Vec::new(),
        "mcp-profile-provider",
    )
    .map_err(|error| error.to_string())?;
    let durable = ProfileProviderReachAwareApplyContext {
        approval_context,
        roots,
        principal,
        audience: PROFILE_PROVIDER_APPROVAL_AUDIENCE.to_string(),
        issued_at_unix: now_unix,
        expires_at_unix,
        now_unix,
    };
    let controller = ProfileProviderOperationController::new(&app_state_root)
        .with_session_authority_key(session_key);
    let handoff = controller
        .seal_handoff(plan, &durable)
        .map_err(|error| error.to_string())?;
    if handoff.operation_id != plan.operation_id
        || handoff.plan_fingerprint != plan.plan_fingerprint
    {
        return Err("sealed profile provider handoff does not match reviewed plan".to_string());
    }
    sealed_profile_provider_operation(&app_state_root, &plan.operation_id)
}

fn sealed_profile_provider_operation(
    app_state_root: &Path,
    operation_id: &str,
) -> Result<Value, String> {
    let matching = TransitionJournalStore::new(app_state_root)
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|journal| journal.operation_id == operation_id)
        .collect::<Vec<_>>();
    let [journal] = matching.as_slice() else {
        return Err("sealed profile provider handoff journal is unavailable".to_string());
    };
    let envelope = journal.reach_aware.as_ref().ok_or_else(|| {
        "sealed profile provider handoff is missing operation schema v2".to_string()
    })?;
    serde_json::to_value(envelope).map_err(|error| error.to_string())
}

fn profile_provider_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<
    (
        CompiledProfileRevision,
        crate::profiles::ProfileProviderOperationPlan,
    ),
    String,
> {
    require_only_fields(
        arguments,
        &[
            "profileId",
            "mode",
            "scope",
            "provider",
            "providerReach",
            "operationId",
            "confirm",
            "planFingerprint",
        ],
        "profile provider operation arguments",
    )?;
    let profile_id = required_string(arguments, "profileId")?;
    let revision = compile_stored_profile(context, profile_id)?;
    let requested_provider = optional_provider(context, arguments)?;
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let mut reach_request = ProviderReachRequest::new(
        boundary,
        parse_bulk_provider_reach(
            arguments.get("providerReach"),
            context.provider_scope.provider(),
        )?,
        DerivedTargetKind::Profile,
    );
    if let Some(provider) = requested_provider {
        reach_request = reach_request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    let provider_reach = reach_request
        .validate_before_discovery()
        .and_then(|preflight| preflight.reconcile_exact_target(None))
        .map_err(|error| error.to_string())?
        .reach;
    let (_, target) = control_targets(context, arguments, provider_reach.provider())?;
    let gateway = match required_string(arguments, "mode")? {
        "native" => GatewaySelection::Native,
        "gateway" => GatewaySelection::Gateway,
        _ => return Err("mode must be native or gateway".to_string()),
    };
    let discovery = context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)?;
    let plan = ProfileProviderOperationController::new(&context.app_state_root)
        .plan_with_gateway_and_discovery(&target, &revision, provider_reach, gateway, &discovery)
        .map_err(|error| error.to_string())?;
    Ok((revision, plan))
}

fn profile_provider_operation_value(
    context: &McpContext,
    revision: &CompiledProfileRevision,
    plan: &crate::profiles::ProfileProviderOperationPlan,
    lifecycle: &str,
    expected_lifecycle: ProviderReachLifecycle,
) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let selected_provider = plan.provider_reach.provider().map(|provider| {
        json!(SelectedProviderAuthority::new(
            provider,
            plan.provider_reach
                .provenance()
                .unwrap_or(SelectedProviderProvenance::ExplicitInput),
        ))
    });
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "family": "profile",
        "familySchemaVersion": crate::profiles::PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
        "operationId": plan.operation_id,
        "operationKind": "apply-profile",
        "planFingerprint": plan.plan_fingerprint,
        "context": {
            "repositoryKey": approval_context.repository_key(),
            "workspaceKey": approval_context.workspace_key(),
            "profileDigest": plan.profile.digest
        },
        "connectionBoundary": boundary,
        "providerReach": plan.provider_reach,
        "selectedProvider": selected_provider,
        "providerCoverage": plan.coverage,
        "expectedLifecycle": expected_lifecycle,
        "lifecycle": lifecycle,
        "activation": plan.activation,
        "humanAction": (lifecycle == "planned" || lifecycle == "awaiting-human-action").then(|| json!({
            "code": "confirm-and-apply",
            "guidance": "Review and apply this fingerprint in Unpin CLI or TUI."
        })),
        "retryable": true,
        "details": {
            "profile": revision,
            "targets": plan.targets,
            "inverseEvidence": plan.inverse_evidence,
        }
    }))
}

fn plan_profile_policy(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (revision, plan) = profile_policy_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        optional_provider(context, arguments)?,
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "profile": revision,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

fn apply_profile_policy(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (_, plan) = profile_policy_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        optional_provider(context, arguments)?,
        json!({"plan": plan}),
    )))
}

fn profile_policy_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(CompiledProfileRevision, crate::profiles::PolicyChangePlan), String> {
    let profile_id = required_string(arguments, "profileId")?;
    let revision = compile_stored_profile(context, profile_id)?;
    let provider = optional_provider(context, arguments)?;
    let (_, policy_target) = control_targets(context, arguments, provider)?;
    let gateway = match required_string(arguments, "mode")? {
        "native" => GatewaySelection::Native,
        "gateway" => GatewaySelection::Gateway,
        _ => return Err("mode must be native or gateway".to_string()),
    };
    let plan = ProfilePolicyController::new(&context.app_state_root)
        .plan_with_revisions(
            policy_target,
            provider,
            PolicyChange {
                profile: Some(ProfileSelection::Profile {
                    reference: ProfileReference::from(&revision),
                }),
                gateway: Some(gateway),
                capability_lock: None,
            },
            std::slice::from_ref(&revision),
        )
        .map_err(|error| error.to_string())?;
    Ok((revision, plan))
}

fn get_capability_locks(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &["provider"], "capability lock status arguments")?;
    let requested_provider = optional_provider(context, arguments)?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let policies = PolicyStore::new(&context.app_state_root)
        .load_resolution_policies(&identity.repository_key, &identity.workspace_key, None)
        .map_err(|error| error.to_string())?;
    let discovery = discover_scoped_cached(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let providers = requested_provider.map_or_else(
        || {
            policies
                .global
                .providers
                .iter()
                .filter_map(|(provider, policy)| {
                    (!policy.capability_locks.is_empty()).then_some(*provider)
                })
                .collect::<Vec<_>>()
        },
        |provider| vec![provider],
    );
    let locks = providers
        .into_iter()
        .map(|provider| {
            let provider_policy = policies.global.providers.get(&provider);
            let snapshot = CapabilityLockSnapshot::compile(
                provider,
                provider_policy
                    .map(|policy| policy.capability_locks.clone())
                    .unwrap_or_default(),
            )
            .map_err(|error| error.to_string())?;
            let (gateway, gateway_source) = resolve_effective_gateway(provider, &policies);
            Ok(json!({
                "provider": provider,
                "source": "global",
                "activation": "next-session-only",
                "activeSessionsUnaffected": true,
                "repositoryKey": identity.repository_key,
                "workspaceKey": identity.workspace_key,
                "gateway": gateway,
                "gatewaySource": gateway_source,
                "digest": snapshot.digest,
                "entries": snapshot.entries,
                "enforcement": capability_lock_enforcement(&snapshot, &catalog, gateway),
                "action": "unpin profile lock",
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "status": "ok",
        "locks": locks,
        "warnings": discovery.warnings
    }))
}

fn plan_capability_lock(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = capability_lock_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let provider = required_provider(context, arguments)?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        Some(provider),
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI profile lock to review and apply this fingerprint, then read capability lock status.",
    }))
}

fn apply_capability_lock(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = capability_lock_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(required_provider(context, arguments)?),
        json!({"plan": plan}),
    )))
}

fn capability_lock_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<crate::profiles::PolicyChangePlan, String> {
    let provider = required_provider(context, arguments)?;
    let capability_id =
        crate::catalog::CapabilityId::new(required_string(arguments, "capabilityId")?)
            .map_err(|error| error.to_string())?;
    let state = match required_string(arguments, "state")? {
        "hard-enabled" => Some(CapabilityLockState::HardEnabled),
        "hard-disabled" => Some(CapabilityLockState::HardDisabled),
        "clear" => None,
        _ => return Err("state must be hard-enabled, hard-disabled, or clear".to_string()),
    };
    ProfilePolicyController::new(&context.app_state_root)
        .plan(
            PolicyTarget::Global,
            Some(provider),
            PolicyChange {
                capability_lock: Some(CapabilityLockChange {
                    capability_id,
                    state,
                }),
                ..PolicyChange::default()
            },
        )
        .map_err(|error| error.to_string())
}

fn compile_stored_profile(
    context: &McpContext,
    profile_id: &str,
) -> Result<CompiledProfileRevision, String> {
    let (definition, source_scope) = load_stored_profile(context, profile_id)?;
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    compile_profile(&definition, &catalog, source_scope).map_err(|error| error.to_string())
}

fn load_stored_profile(
    context: &McpContext,
    profile_id: &str,
) -> Result<(ProfileDefinition, ProfileSourceScope), String> {
    if let Some(entry) = ProfileStore::load_workspace_definition(&context.project_root, profile_id)
        .map_err(|error| error.to_string())?
    {
        return Ok((entry.definition, entry.scope));
    }
    let snapshot = ProfileStore::new(&context.app_state_root)
        .load_global_definition(profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "profile not found".to_string())?;
    Ok((snapshot.value, ProfileSourceScope::Global))
}

fn plan_gateway_mode(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = gateway_workflow_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.mode.activation,
        if plan.mode.blocked_reason.is_some() {
            ControlOperationLifecycle::Blocked
        } else {
            ControlOperationLifecycle::Planned
        },
        optional_provider(context, arguments)?,
        json!({
            "plan": plan,
            "nativeMcpReferences": "not-managed",
        }),
    );
    Ok(json!({
        "status": if plan.mode.blocked_reason.is_some() { "blocked" } else { "planned" },
        "operation": operation,
        "plan": plan,
        "nativeMcpReferences": "not-managed",
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

fn get_gateway_status(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["scope", "provider"],
        "gateway status arguments",
    )?;
    let provider = optional_provider(context, arguments)?;
    let (mode_target, policy_target) = control_targets(context, arguments, provider)?;
    let mode = GatewayModeController::new(&context.app_state_root)
        .status(&mode_target)
        .map_err(|error| error.to_string())?;
    let policy = PolicyStore::new(&context.app_state_root)
        .load(&policy_target)
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "ok",
        "target": mode_target,
        "mode": mode,
        "policy": policy.map(|snapshot| snapshot.policy),
        "provider": provider,
        "runtime": {
            "nativeMcpReferences": "not-managed",
            "liveProviderAttachment": "blocked-until-provider-overlay-is-verified",
        },
    }))
}

fn apply_gateway_mode(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = gateway_workflow_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.mode.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        optional_provider(context, arguments)?,
        json!({
            "plan": plan,
            "nativeMcpReferences": "not-managed",
        }),
    )))
}

fn gateway_workflow_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<crate::sessions::GatewayWorkflowPlan, String> {
    let provider = optional_provider(context, arguments)?;
    let (mode_target, policy_target) = control_targets(context, arguments, provider)?;
    let action = match required_string(arguments, "action")? {
        "install" => GatewayModeAction::Install,
        "on" => GatewayModeAction::Activate,
        "off" => GatewayModeAction::Off,
        "detach" => GatewayModeAction::Detach,
        _ => return Err("action must be install, on, off, or detach".to_string()),
    };
    GatewayWorkflowController::with_authority_keys(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
        context
            .backup_authentication_key
            .clone()
            .ok_or_else(|| "backup authentication key is unavailable".to_string())?,
    )
    .plan(
        mode_target,
        policy_target,
        provider,
        action,
        arguments
            .get("force")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .map_err(|error| error.to_string())
}

fn plan_session_end(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let plan = SessionEndController::with_authority_key(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    )
    .plan(required_string(arguments, "sessionId")?, &approval_context)
    .map_err(|error| error.to_string())?;
    context
        .provider_scope
        .require_allowed_optional(plan.provider)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        plan.provider,
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

fn apply_session_end(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let controller = SessionEndController::with_authority_key(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    );
    let plan = controller
        .plan(required_string(arguments, "sessionId")?, &approval_context)
        .map_err(|error| error.to_string())?;
    context
        .provider_scope
        .require_allowed_optional(plan.provider)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        plan.provider,
        json!({"plan": plan}),
    )))
}

fn plan_session_launch(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["provider", "exposureRevision", "profile"],
        "session launch arguments",
    )?;
    let provider = required_provider(context, arguments)?;
    let profile = session_launch_profile(context, arguments)?;
    let capability_locks = CapabilityLockSnapshot::compile(
        provider,
        PolicyStore::new(&context.app_state_root)
            .load(&PolicyTarget::Global)
            .map_err(|error| error.to_string())?
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&provider))
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|error| error.to_string())?;
    let exposure = PinnedExposure {
        revision: required_string(arguments, "exposureRevision")?.to_string(),
        profile,
        capability_locks: Some(Box::new(capability_locks)),
    };
    exposure.validate().map_err(|error| error.to_string())?;
    let workspace =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;

    let mut cli_arguments = vec![
        "session".to_string(),
        "launch".to_string(),
        "--project-root".to_string(),
        mcp_cli_path(&workspace.canonical_root, "project root")?,
    ];
    if let Some(fixture_root) = &context.fixture_root {
        cli_arguments.extend([
            "--fixture-root".to_string(),
            mcp_cli_path(fixture_root, "fixture root")?,
        ]);
    }
    cli_arguments.extend([
        "--app-state-root".to_string(),
        mcp_cli_path(&context.app_state_root, "app state root")?,
        "--provider".to_string(),
        provider.as_str().to_string(),
        "--exposure-revision".to_string(),
        exposure.revision.clone(),
        "--capability-lock-revision".to_string(),
        exposure
            .capability_locks
            .as_ref()
            .expect("session launch always pins capability locks")
            .digest
            .clone(),
    ]);
    match &exposure.profile {
        PinnedProfile::Native => cli_arguments.push("--native".to_string()),
        PinnedProfile::None => {}
        PinnedProfile::Profile {
            profile_id,
            profile_digest,
            origin_scope,
            definition_digest,
        } => {
            cli_arguments.extend([
                "--profile-id".to_string(),
                profile_id.clone(),
                "--profile-digest".to_string(),
                profile_digest.clone(),
                "--definition-digest".to_string(),
                definition_digest.clone(),
                "--profile-origin".to_string(),
                profile_source_scope_name(*origin_scope).to_string(),
            ]);
        }
    }
    cli_arguments.extend(["--json".to_string(), "--".to_string()]);
    let profile_handoff = match &exposure.profile {
        PinnedProfile::Native => json!({"type": "native"}),
        PinnedProfile::None => json!({"type": "none"}),
        PinnedProfile::Profile {
            profile_id,
            profile_digest,
            origin_scope,
            definition_digest,
        } => json!({
            "type": "profile",
            "profileId": profile_id,
            "profileDigest": profile_digest,
            "originScope": origin_scope,
            "definitionDigest": definition_digest,
        }),
    };

    Ok(json!({
        "status": "human-action-required",
        "humanAction": {
            "code": "run-session-launch",
            "guidance": "Append the provider harness command after the final -- argument, review the argv array, then run it in a trusted terminal.",
        },
        "handoff": {
            "version": 1,
            "kind": "unpin-cli-session-launch",
            "provider": provider,
            "workspace": {
                "projectRoot": workspace.canonical_root,
                "repositoryKey": workspace.repository_key,
                "workspaceKey": workspace.workspace_key,
                "workspaceRevision": workspace.diagnostics.head,
            },
            "exposure": {
                "revision": exposure.revision,
                "profile": profile_handoff,
                "capabilityLocks": exposure.capability_locks,
            },
            "cli": {
                "executable": "unpin",
                "arguments": cli_arguments,
                "appendChildCommandAfterSeparator": true,
            },
        },
        "constraints": {
            "commandAccepted": false,
            "processSpawned": false,
            "stateWritten": false,
            "approvalMinted": false,
            "authorityExposed": false,
        },
    }))
}

fn session_launch_profile(
    context: &McpContext,
    arguments: &Value,
) -> Result<PinnedProfile, String> {
    let profile = arguments
        .get("profile")
        .ok_or_else(|| "missing required field: profile".to_string())?;
    let profile_type = required_string(profile, "type")?;
    match profile_type {
        "native" => {
            require_only_fields(profile, &["type"], "session launch profile")?;
            Ok(PinnedProfile::Native)
        }
        "none" => {
            require_only_fields(profile, &["type"], "session launch profile")?;
            Ok(PinnedProfile::None)
        }
        "profile" => {
            require_only_fields(
                profile,
                &["type", "profileId", "profileDigest", "definitionDigest"],
                "session launch profile",
            )?;
            let profile_id = required_string(profile, "profileId")?;
            let requested_profile_digest = required_string(profile, "profileDigest")?;
            let requested_definition_digest = required_string(profile, "definitionDigest")?;
            let revision = compile_stored_profile(context, profile_id)?;
            if revision.digest != requested_profile_digest
                || revision.origin.definition_digest != requested_definition_digest
            {
                return Err(
                    "session launch profile revision does not match stored definition".to_string(),
                );
            }
            Ok(PinnedProfile::Profile {
                profile_id: revision.profile_id,
                profile_digest: revision.digest,
                origin_scope: revision.origin.scope,
                definition_digest: revision.origin.definition_digest,
            })
        }
        _ => Err("profile.type must be native, none, or profile".to_string()),
    }
}

const fn profile_source_scope_name(scope: ProfileSourceScope) -> &'static str {
    match scope {
        ProfileSourceScope::Global => "global",
        ProfileSourceScope::Repository => "repository",
        ProfileSourceScope::Workspace => "workspace",
        ProfileSourceScope::Session => "session",
    }
}

fn parse_profile_source_scope(value: &str) -> Result<ProfileSourceScope, String> {
    match value {
        "global" => Ok(ProfileSourceScope::Global),
        "repository" => Ok(ProfileSourceScope::Repository),
        "workspace" => Ok(ProfileSourceScope::Workspace),
        "session" => Ok(ProfileSourceScope::Session),
        _ => Err("sourceScope must be global, repository, workspace, or session".to_string()),
    }
}

fn mcp_cli_path(path: &Path, label: &str) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{label} cannot be represented in MCP JSON"))
}

fn control_approval_context(context: &McpContext) -> Result<ControlApprovalContext, String> {
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    ControlApprovalContext::new(identity.repository_key, identity.workspace_key)
        .map_err(|error| error.to_string())
}

fn control_targets(
    context: &McpContext,
    arguments: &Value,
    provider: Option<ProviderId>,
) -> Result<(GatewayModeTarget, PolicyTarget), String> {
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    match arguments
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("workspace")
    {
        "global" => Ok((
            provider.map_or_else(
                GatewayModeTarget::global,
                GatewayModeTarget::global_provider,
            ),
            PolicyTarget::Global,
        )),
        "repository" => Ok((
            match provider {
                Some(provider) => {
                    GatewayModeTarget::repository_provider(&identity.repository_key, provider)
                }
                None => GatewayModeTarget::repository(&identity.repository_key),
            }
            .map_err(|error| error.to_string())?,
            PolicyTarget::repository(&identity.repository_key)
                .map_err(|error| error.to_string())?,
        )),
        "workspace" => Ok((
            match provider {
                Some(provider) => GatewayModeTarget::workspace_provider(
                    &identity.repository_key,
                    &identity.workspace_key,
                    provider,
                ),
                None => {
                    GatewayModeTarget::workspace(&identity.repository_key, &identity.workspace_key)
                }
            }
            .map_err(|error| error.to_string())?,
            PolicyTarget::workspace(&identity.repository_key, &identity.workspace_key)
                .map_err(|error| error.to_string())?,
        )),
        _ => Err("scope must be global, repository, or workspace".to_string()),
    }
}

fn discover_scoped(context: &McpContext) -> Result<DiscoveryOutput, String> {
    context
        .discovery_cache
        .refresh(&context.discovery_roots)
        .map(|discovery| context.provider_scope.filter_discovery(discovery))
}

fn discover_scoped_cached(context: &McpContext) -> Result<DiscoveryOutput, String> {
    context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)
        .map(|discovery| context.provider_scope.filter_discovery(discovery))
}

fn optional_provider(
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

fn required_provider(context: &McpContext, arguments: &Value) -> Result<ProviderId, String> {
    optional_provider(context, arguments)?
        .ok_or_else(|| "missing required field: provider".to_string())
}

fn optional_string<'a>(arguments: &'a Value, field: &str) -> Result<Option<&'a str>, String> {
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

fn parse_provider_id(value: &str) -> Result<ProviderId, String> {
    ProviderId::ALL
        .into_iter()
        .find(|provider| provider.as_str() == value)
        .ok_or_else(|| format!("unsupported provider: {value}"))
}

fn require_plan_fingerprint(arguments: &Value, expected: &str) -> Result<(), String> {
    if arguments.get("planFingerprint").and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err("plan fingerprint does not match current reviewed plan".to_string())
    }
}

fn control_operation(
    expectation: &crate::approval::ApprovalExpectation,
    plan_fingerprint: &str,
    activation: EffectActivation,
    lifecycle: ControlOperationLifecycle,
    provider: Option<ProviderId>,
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
        provider.map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
        details,
    )
}

fn human_action_required(operation: ControlOperationEnvelope) -> Value {
    json!({
        "status": "human-action-required",
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
        "planFingerprint": operation.plan_fingerprint.clone(),
        "operation": operation,
        "continuation": "Review and apply this plan in Unpin CLI. MCP cannot mint or substitute human approval; read control status after completion.",
    })
}

fn legacy_bulk_human_action_required(operation_kind: &str, plan_fingerprint: &str) -> Value {
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

fn reach_aware_bulk_human_action_required(
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

fn legacy_plan_fingerprint(operation_kind: &str, plan: &Value) -> String {
    bulk_plan_fingerprint(json!({
        "schemaVersion": 1,
        "operationKind": operation_kind,
        "plan": plan,
    }))
}

fn require_empty_object(arguments: &Value) -> Result<(), String> {
    match arguments.as_object() {
        Some(arguments) if arguments.is_empty() => Ok(()),
        Some(_) => Err("this tool does not accept arguments".to_string()),
        None => Err("arguments must be an object".to_string()),
    }
}

fn require_only_fields(arguments: &Value, allowed: &[&str], label: &str) -> Result<(), String> {
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

fn run_doctor_structured(context: &McpContext) -> Value {
    let matrix_issues = capability_matrix_issues(context.fixture_root.as_ref())
        .into_iter()
        .filter(|issue| capability_matrix_issue_in_scope(context.provider_scope, issue))
        .collect::<Vec<_>>();
    if !matrix_issues.is_empty() {
        let provider_issues = capability_matrix_provider_issues(&matrix_issues);
        return json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(context.provider_scope, "error", provider_issues),
            "capabilityMatrixIssues": matrix_issues,
            "fixtureIssues": [],
            "warnings": []
        });
    }

    let fixture_issues = provider_fixture_issues(context.fixture_root.as_ref())
        .into_iter()
        .filter(|issue| provider_issue_in_scope(context.provider_scope, issue, "providerId"))
        .collect::<Vec<_>>();
    if !fixture_issues.is_empty() {
        let provider_issues = fixture_provider_issues(&fixture_issues);
        return json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(context.provider_scope, "error", provider_issues),
            "fixtureIssues": fixture_issues,
            "warnings": []
        });
    }

    match discover_scoped_cached(context) {
        Ok(discovery) => {
            let provider_issues = discovery
                .warnings
                .iter()
                .map(discovery_warning_provider_issue)
                .collect::<Vec<_>>();
            json!({
                "status": if provider_issues.is_empty() { "ok" } else { "warning" },
                "packageRoot": context.package_root,
                "fixturesRoot": context.fixture_root,
                "providers": provider_health_rows(context.provider_scope, "warning", provider_issues),
                "itemsDiscovered": discovery.items.len(),
                "warnings": discovery.warnings
            })
        }
        Err(error) => json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(
                context.provider_scope,
                "error",
                discovery_error_provider_issues(context.provider_scope, &error.to_string())
            ),
            "itemsDiscovered": 0,
            "warnings": [],
            "reason": error.to_string()
        }),
    }
}

fn individual_reach_inputs(
    context: &McpContext,
    arguments: &Value,
) -> Result<
    (
        ConnectionBoundary,
        ProviderReachInput,
        Vec<crate::provider_reach::SelectedProviderAuthority>,
    ),
    String,
> {
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let reach = parse_bulk_provider_reach(
        arguments.get("providerReach"),
        context.provider_scope.provider(),
    )?;
    let mut authority_candidates = Vec::new();
    if let Some(provider) = arguments.get("provider") {
        let provider = provider
            .as_str()
            .ok_or_else(|| "provider must be a string".to_string())
            .and_then(parse_provider_id)?;
        authority_candidates.push(crate::provider_reach::SelectedProviderAuthority::new(
            provider,
            crate::provider_reach::SelectedProviderProvenance::ExplicitInput,
        ));
    }
    Ok((boundary, reach, authority_candidates))
}

fn plan_single_toggle(context: &McpContext, arguments: &Value) -> Value {
    let Some(target_enabled) = arguments.get("targetEnabled").and_then(Value::as_bool) else {
        return blocked_value("missing required field: targetEnabled");
    };
    let (boundary, reach, authority_candidates) = match individual_reach_inputs(context, arguments)
    {
        Ok(inputs) => inputs,
        Err(reason) => return blocked_value(reason),
    };
    let reach_request = ProviderReachRequest {
        boundary,
        reach,
        target_kind: DerivedTargetKind::Individual,
        authority_candidates: authority_candidates.clone(),
    };
    if let Err(error) = reach_request.clone().validate_before_discovery() {
        return blocked_value(error.to_string());
    }
    let item = match selected_item(context, arguments) {
        Ok(item) => item,
        Err(reason) => return blocked_value(reason),
    };
    if is_control_plane_protected_disable(&item, target_enabled) {
        return blocked_toggle_value(item, target_enabled, CONTROL_PLANE_PROTECTED_REASON);
    }

    if item.enabled == target_enabled {
        let resolved = match reach_request
            .validate_before_discovery()
            .and_then(|preflight| preflight.reconcile_exact_target(Some(item.provider)))
        {
            Ok(resolved) => resolved,
            Err(error) => return blocked_value(error.to_string()),
        };
        let mut plan = json!({
            "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
            "status": "planned",
            "selection": item.clone(),
            "targetEnabled": target_enabled,
            "providerReach": resolved.reach,
            "coverage": {
                "entries": [{
                    "provider": resolved.reach.provider().unwrap_or(item.provider),
                    "targetId": item.id.clone(),
                    "included": true
                }]
            },
            "applyMode": "re-resolve-on-apply",
            "operations": [],
            "affectedTargets": [],
            "affectedPaths": [],
            "blocked": null,
            "warnings": []
        });
        plan["providerCoverage"] = plan["coverage"].clone();
        plan["planFingerprint"] = json!(legacy_plan_fingerprint("toggle-item", &plan));
        let approval_context = match control_approval_context(context) {
            Ok(context) => context,
            Err(error) => return blocked_value(error),
        };
        let fingerprint = plan["planFingerprint"]
            .as_str()
            .expect("single toggle no-op plan includes fingerprint")
            .to_owned();
        let operation = ControlOperationEnvelope::new(
            format!("native-toggle-no-op-{fingerprint}"),
            "native-toggle",
            fingerprint.clone(),
            ControlResolvedContext {
                repository_key: approval_context.repository_key().to_string(),
                workspace_key: approval_context.workspace_key().to_string(),
                session_id: None,
                profile_digest: None,
            },
            ControlOperationLifecycle::NoOp,
            EffectActivation::Live,
            None,
            false,
            vec![item.provider],
            json!({"plan": plan.clone(), "reason": "already-in-desired-state"}),
        );
        plan["controlContractVersion"] = json!(UNPIN_CONTROL_CONTRACT_VERSION);
        plan["operation"] =
            serde_json::to_value(operation).expect("control operation envelope serializes");
        plan["operationV2"] = json!({
            "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
            "family": "native-toggle",
            "operationId": format!("native-toggle-no-op-{fingerprint}"),
            "operationKind": "native-toggle",
            "planFingerprint": fingerprint,
            "providerReach": resolved.reach,
            "providerCoverage": plan["providerCoverage"].clone(),
            "lifecycle": "no-op",
            "expectedLifecycle": "no-op",
            "activation": "live"
        });
        return plan;
    }

    let approval_context = match control_approval_context(context) {
        Ok(approval_context) => approval_context,
        Err(error) => return blocked_value(error),
    };
    let inventory = match discover_all(&context.discovery_roots) {
        Ok(inventory) => inventory,
        Err(error) => return blocked_value(error.to_string()),
    };
    let controlled = match NativeToggleController::new(&context.app_state_root)
        .plan_with_reach_in_inventory(
            item,
            &inventory.items,
            &approval_context,
            boundary,
            reach,
            authority_candidates,
        ) {
        Ok(controlled) => controlled,
        Err(error) => return blocked_value(error.to_string()),
    };
    let expectation = match controlled.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return blocked_value(error.to_string()),
    };
    let provider = controlled.preview.selection.provider;
    let activation = controlled
        .transition
        .effects
        .first()
        .map_or(EffectActivation::RestartRequired, |effect| {
            effect.activation
        });
    let operation = control_operation(
        &expectation,
        &controlled.plan_fingerprint,
        activation,
        ControlOperationLifecycle::Planned,
        Some(provider),
        json!({"plan": controlled.clone()}),
    );
    let mut plan = plan_summary_value(
        serde_json::to_value(&controlled.preview).expect("toggle result serializes"),
    );
    plan["providerReach"] =
        serde_json::to_value(controlled.provider_reach).expect("provider reach serializes");
    plan["coverage"] =
        serde_json::to_value(&controlled.coverage).expect("provider coverage serializes");
    plan["schemaVersion"] = json!(crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION);
    plan["providerCoverage"] = plan["coverage"].clone();
    plan["planFingerprint"] = json!(controlled.plan_fingerprint);
    plan["controlContractVersion"] = json!(UNPIN_CONTROL_CONTRACT_VERSION);
    plan["operation"] =
        serde_json::to_value(operation).expect("control operation envelope serializes");
    plan["operationV2"] = json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "family": "native-toggle",
        "operationId": controlled.transition.operation_id,
        "operationKind": "native-toggle",
        "planFingerprint": controlled.plan_fingerprint,
        "providerReach": controlled.provider_reach,
        "providerCoverage": controlled.coverage,
        "lifecycle": "planned",
        "expectedLifecycle": "applied",
        "activation": activation
    });
    plan["continuation"] =
        json!("Review this plan, then call unpin_apply_toggle_item with its planFingerprint.");
    plan
}

fn apply_single_toggle(context: &McpContext, arguments: &Value) -> Value {
    let plan = plan_single_toggle(context, arguments);
    if plan["status"] == "blocked" {
        return plan;
    }
    let fingerprint = plan["planFingerprint"]
        .as_str()
        .expect("single toggle plan includes fingerprint");
    if let Err(error) = require_plan_fingerprint(arguments, fingerprint) {
        return blocked_value(error);
    }
    if plan["operations"].as_array().is_some_and(Vec::is_empty) {
        let mut no_op = plan;
        no_op["status"] = json!("no-op");
        return no_op;
    }
    let item = match selected_item(context, arguments) {
        Ok(item) => item,
        Err(reason) => return blocked_value(reason),
    };
    let (boundary, reach, authority_candidates) = match individual_reach_inputs(context, arguments)
    {
        Ok(inputs) => inputs,
        Err(reason) => return blocked_value(reason),
    };
    let approval_context = match control_approval_context(context) {
        Ok(context) => context,
        Err(error) => return blocked_value(error),
    };
    let inventory = match discover_all(&context.discovery_roots) {
        Ok(inventory) => inventory,
        Err(error) => return blocked_value(error.to_string()),
    };
    let controlled = match NativeToggleController::new(&context.app_state_root)
        .plan_with_reach_in_inventory(
            item,
            &inventory.items,
            &approval_context,
            boundary,
            reach,
            authority_candidates,
        ) {
        Ok(controlled) => controlled,
        Err(error) => return blocked_value(error.to_string()),
    };
    if controlled.plan_fingerprint != fingerprint {
        return blocked_value("plan fingerprint does not match current reviewed plan");
    }
    let operation_v2 = match seal_native_toggle_handoff(context, &controlled, &approval_context) {
        Ok(operation) => operation,
        Err(error) => return blocked_value(error),
    };
    let expectation = match controlled.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return blocked_value(error.to_string()),
    };
    let provider = controlled.preview.selection.provider;
    let activation = controlled
        .transition
        .effects
        .first()
        .map_or(EffectActivation::RestartRequired, |effect| {
            effect.activation
        });
    let operation_id = controlled.transition.operation_id.clone();
    let provider_reach = controlled.provider_reach;
    let provider_coverage = controlled.coverage.clone();
    let mut response = human_action_required(control_operation(
        &expectation,
        fingerprint,
        activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(provider),
        json!({"plan": controlled}),
    ));
    response["schemaVersion"] = json!(crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION);
    response["operationId"] = json!(operation_id.clone());
    response["providerReach"] = json!(provider_reach);
    response["providerCoverage"] = json!(provider_coverage.clone());
    response["coverage"] = json!(provider_coverage.clone());
    response["operationV2"] = json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "family": "native-toggle",
        "operationId": operation_id,
        "operationKind": "native-toggle",
        "planFingerprint": fingerprint,
        "providerReach": provider_reach,
        "providerCoverage": provider_coverage,
        "lifecycle": "awaiting-human-action",
        "expectedLifecycle": "applied",
        "activation": activation,
        "humanAction": {
            "code": "confirm-and-apply",
            "guidance": "Review and apply this fingerprint in Unpin CLI or TUI."
        }
    });
    response["operationV2"] = operation_v2;
    response["handoff"] = json!({
        "operationId": response["operationId"].clone(),
        "planFingerprint": response["planFingerprint"].clone(),
        "expiresAtUnix": response["operationV2"]["expiresAtUnix"].clone(),
    });
    response["operationKind"] = json!("toggle-item");
    response["operationReference"] = json!(format!("toggle-item:{fingerprint}"));
    response
}

fn seal_native_toggle_handoff(
    context: &McpContext,
    plan: &crate::mutation::NativeTogglePlan,
    approval_context: &ControlApprovalContext,
) -> Result<Value, String> {
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let providers = plan
        .coverage
        .included()
        .map(|entry| entry.provider)
        .collect::<BTreeSet<_>>();
    let provider_roots = providers
        .into_iter()
        .map(|provider| {
            (
                provider,
                mcp_provider_root(&context.discovery_roots, provider),
                "mcp-discovery-root".to_string(),
            )
        })
        .collect();
    let roots = ReachAwareRootBinding::from_provider_paths(
        &app_state_root,
        provider_roots,
        "mcp-native-toggle",
    )
    .map_err(|error| error.to_string())?;
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let expires_at_unix = now_unix
        .checked_add(MCP_HANDOFF_TTL_SECONDS)
        .ok_or_else(|| "MCP handoff expiry overflowed".to_string())?;
    let controller =
        NativeToggleController::with_session_authority_key(&app_state_root, session_key);
    let handoff = controller
        .seal_handoff(
            plan,
            approval_context,
            roots,
            CONTROL_APPROVAL_AUDIENCE,
            now_unix,
            expires_at_unix,
        )
        .map_err(|error| error.to_string())?;
    if handoff.operation_id != plan.transition.operation_id
        || handoff.plan_fingerprint != plan.plan_fingerprint
    {
        return Err("sealed native toggle handoff does not match reviewed plan".to_string());
    }
    let matching = TransitionJournalStore::new(&app_state_root)
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|journal| journal.operation_id == plan.transition.operation_id)
        .collect::<Vec<_>>();
    let [journal] = matching.as_slice() else {
        return Err("sealed native toggle handoff journal is unavailable".to_string());
    };
    let envelope = journal
        .reach_aware
        .as_ref()
        .ok_or_else(|| "sealed native toggle handoff is missing operation schema v2".to_string())?;
    serde_json::to_value(envelope).map_err(|error| error.to_string())
}

fn plan_bulk_toggle_items(context: &McpContext, arguments: &Value) -> Value {
    match build_bulk_plan(context, arguments) {
        Ok((plan, warnings)) => bulk_plan_value(&plan, warnings),
        Err(error) => bulk_plan_error_value(error),
    }
}

fn apply_bulk_toggle_items(context: &McpContext, arguments: &Value) -> Value {
    let Some(provided_fingerprint) = arguments.get("planFingerprint").and_then(Value::as_str)
    else {
        return blocked_value("missing required field: planFingerprint");
    };

    let Some(max_items) = arguments.get("maxItems").and_then(Value::as_u64) else {
        return blocked_value("missing required field: maxItems");
    };

    let (current_plan, warnings) = match build_bulk_plan(context, arguments) {
        Ok(plan) => plan,
        Err(error) => return bulk_plan_error_value(error),
    };
    let current_fingerprint = current_plan.plan_fingerprint.as_str();
    if current_fingerprint != provided_fingerprint {
        return json!({
            "status": "blocked",
            "reasonCode": "plan-fingerprint-mismatch",
            "message": "The reviewed bulk plan no longer matches the current machine state. Re-run the plan step before applying.",
            "currentPlanFingerprint": current_fingerprint,
            "planFingerprint": provided_fingerprint
        });
    }

    let actionable_count = current_plan.write_count();
    if actionable_count as u64 > max_items {
        return json!({
            "status": "blocked",
            "reason": "max-items-exceeded",
            "reasonCode": "max-items-exceeded",
            "message": "The reviewed bulk plan exceeds the requested maxItems guard.",
            "maxItems": max_items,
            "actionableCount": actionable_count,
            "planFingerprint": current_fingerprint
        });
    }

    if current_plan.status == BulkTogglePlanStatus::Blocked || actionable_count == 0 {
        let mut response = bulk_plan_value(&current_plan, warnings);
        if current_plan.lifecycle == ProviderReachLifecycle::Partial {
            response["status"] = json!(ProviderReachLifecycle::Partial.as_str());
        }
        return response;
    }

    match seal_bulk_toggle_handoff(context, &current_plan) {
        Ok(operation_v2) => {
            reach_aware_bulk_human_action_required(&current_plan, current_fingerprint, operation_v2)
        }
        Err(error) => blocked_value(error),
    }
}

fn seal_bulk_toggle_handoff(context: &McpContext, plan: &BulkTogglePlan) -> Result<Value, String> {
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let backup_key = context
        .backup_authentication_key
        .clone()
        .ok_or_else(|| "backup authentication key is unavailable".to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let approval_context = control_approval_context(context)?;
    let session_id = plan.operation_id.clone();
    let expectation = plan
        .approval_expectation(&approval_context, &session_id)
        .map_err(|error| error.to_string())?;
    let scope_digest = crate::mutation::reach_scope_digest(&expectation, &session_id);
    let connection_boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let roots = bulk_mcp_root_binding(context, plan)?;
    let principal =
        ReachAwarePrincipal::sign(session_id, scope_digest, connection_boundary, &session_key)
            .map_err(|error| error.to_string())?;
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let expires_at_unix = now_unix
        .checked_add(MCP_HANDOFF_TTL_SECONDS)
        .ok_or_else(|| "MCP handoff expiry overflowed".to_string())?;
    let durable = BulkToggleReachAwareApplyContext {
        approval_context,
        roots: roots.clone(),
        principal,
        audience: BULK_TOGGLE_APPROVAL_AUDIENCE.to_string(),
        issued_at_unix: now_unix,
        expires_at_unix,
        now_unix,
    };
    let controller = BulkToggleController::new(&app_state_root).with_reach_aware_authority(
        backup_key,
        session_key,
        roots,
    );
    let handoff = controller
        .seal_handoff(plan, &durable)
        .map_err(|error| error.to_string())?;
    if handoff.operation_id != plan.operation_id
        || handoff.plan_fingerprint != plan.plan_fingerprint
    {
        return Err("sealed bulk handoff does not match reviewed plan".to_string());
    }
    let matching = TransitionJournalStore::new(&app_state_root)
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|journal| journal.operation_id == plan.operation_id)
        .collect::<Vec<_>>();
    let [journal] = matching.as_slice() else {
        return Err("sealed bulk handoff journal is unavailable".to_string());
    };
    let envelope = journal
        .reach_aware
        .as_ref()
        .ok_or_else(|| "sealed bulk handoff is missing operation schema v2".to_string())?;
    serde_json::to_value(envelope).map_err(|error| error.to_string())
}

fn bulk_mcp_root_binding(
    context: &McpContext,
    plan: &BulkTogglePlan,
) -> Result<ReachAwareRootBinding, String> {
    let providers = plan
        .provider_coverage
        .included()
        .map(|entry| entry.provider)
        .collect::<BTreeSet<_>>();
    let provider_roots = providers
        .into_iter()
        .map(|provider| {
            (
                provider,
                mcp_provider_root(&context.discovery_roots, provider),
                "mcp-discovery-root".to_string(),
            )
        })
        .collect();
    ReachAwareRootBinding::from_provider_paths(
        &context.app_state_root,
        provider_roots,
        "mcp-bulk-toggle",
    )
    .map_err(|error| error.to_string())
}

fn mcp_provider_root(roots: &DiscoveryRoots, provider: ProviderId) -> PathBuf {
    match provider {
        ProviderId::Claude => roots.claude_global.clone(),
        ProviderId::Codex => roots.codex_global.clone(),
        ProviderId::Cursor => roots.cursor_config.clone(),
        ProviderId::Pi => roots.pi_global.clone(),
        ProviderId::OpenCode => roots.opencode_global.clone(),
        ProviderId::Zed => roots.zed_global.clone(),
    }
}

#[derive(Debug)]
enum BulkBuildError {
    Message(String),
    Core(BulkTogglePlanError),
}

fn build_bulk_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(BulkTogglePlan, Vec<Value>), BulkBuildError> {
    let target_enabled = arguments
        .get("targetEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            BulkBuildError::Message("missing required field: targetEnabled".to_string())
        })?;
    let selector_value = arguments
        .get("selector")
        .ok_or_else(|| BulkBuildError::Message("selector is required".to_string()))?;
    validate_selector(selector_value).map_err(BulkBuildError::Message)?;
    let selector = serde_json::from_value::<BulkToggleSelector>(selector_value.clone())
        .map_err(|error| BulkBuildError::Message(format!("invalid selector: {error}")))?;
    let reach = parse_bulk_provider_reach(
        arguments.get("providerReach"),
        context.provider_scope.provider(),
    )
    .map_err(BulkBuildError::Message)?;
    let allow_empty_selection = match arguments.get("allowEmptySelection") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            BulkBuildError::Message("allowEmptySelection must be a boolean".to_string())
        })?,
    };
    let acknowledge_whole_inventory = match arguments.get("acknowledgeWholeInventory") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            BulkBuildError::Message("acknowledgeWholeInventory must be a boolean".to_string())
        })?,
    };

    let boundary = match context.provider_scope.provider() {
        Some(provider) => ConnectionBoundary::Pinned(provider),
        None => ConnectionBoundary::All,
    };
    let request = BulkToggleRequest::new(selector, target_enabled)
        .with_reach(boundary, reach)
        .allow_empty_selection(allow_empty_selection)
        .acknowledge_whole_inventory(acknowledge_whole_inventory);
    BulkToggleController::validate_before_discovery(&request).map_err(BulkBuildError::Core)?;

    let discovery = discover_scoped(context).map_err(BulkBuildError::Message)?;
    let warnings = discovery
        .warnings
        .iter()
        .map(|warning| serde_json::to_value(warning).expect("discovery warning serializes"))
        .collect::<Vec<_>>();
    let plan = BulkToggleController::new(&context.app_state_root)
        .plan_from_discovery(discovery, request)
        .map_err(BulkBuildError::Core)?;
    Ok((plan, warnings))
}

fn parse_bulk_provider_reach(
    value: Option<&Value>,
    pinned_provider: Option<ProviderId>,
) -> Result<ProviderReachInput, String> {
    let Some(value) = value else {
        return Ok(ProviderReachInput::Omitted);
    };
    if let Some(mode) = value.as_str() {
        return match mode {
            "all" | "all-providers" => Ok(ProviderReachInput::All),
            "omitted" => Ok(ProviderReachInput::Omitted),
            _ => {
                Err("providerReach must be all, omitted, or a selected provider object".to_string())
            }
        };
    }
    let object = value
        .as_object()
        .ok_or_else(|| "providerReach must be a string or object".to_string())?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| "providerReach.mode is required".to_string())?;
    match mode {
        "all" | "all-providers" => {
            if object.keys().any(|key| key != "mode") {
                return Err("providerReach has unsupported fields".to_string());
            }
            Ok(ProviderReachInput::All)
        }
        "selected" | "selected-provider" => {
            let provider = match object.get("provider") {
                Some(value) => value
                    .as_str()
                    .ok_or_else(|| "providerReach.provider must be a string".to_string())
                    .and_then(parse_provider_id)?,
                None => pinned_provider.ok_or_else(|| {
                    "providerReach.provider is required on an all-provider connection".to_string()
                })?,
            };
            let provenance = if object.contains_key("provider") {
                crate::provider_reach::SelectedProviderProvenance::ExplicitInput
            } else {
                crate::provider_reach::SelectedProviderProvenance::PinnedMcpBoundary
            };
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "mode" | "provider"))
            {
                return Err("providerReach has unsupported fields".to_string());
            }
            Ok(ProviderReachInput::selected(provider, provenance))
        }
        _ => Err("providerReach.mode must be all or selected".to_string()),
    }
}

fn bulk_plan_value(plan: &BulkTogglePlan, warnings: Vec<Value>) -> Value {
    let matched = plan
        .matched
        .iter()
        .map(|item| serde_json::to_value(item).expect("bulk item serializes"))
        .collect::<Vec<_>>();
    let mut matched_items = plan
        .matched_identities()
        .into_iter()
        .map(|identity| serde_json::to_value(identity).expect("bulk identity serializes"))
        .collect::<Vec<_>>();
    sort_item_identity_values(&mut matched_items);

    let mut per_item_plans = plan
        .included
        .iter()
        .map(|entry| {
            let mut value = plan_summary_value(
                serde_json::to_value(&entry.result).expect("toggle result serializes"),
            );
            if entry.outcome == crate::provider_reach::IncludedTargetOutcome::NoOp {
                value["status"] = json!("no-op");
                value["reason"] = json!("already-in-desired-state");
                value["reasonCode"] = json!("already-in-desired-state");
            }
            value
        })
        .collect::<Vec<_>>();
    sort_per_item_plan_values(&mut per_item_plans);
    let mut actionable = plan
        .included
        .iter()
        .filter(|entry| entry.outcome == crate::provider_reach::IncludedTargetOutcome::Applied)
        .map(|entry| {
            plan_summary_value(
                serde_json::to_value(&entry.result).expect("toggle result serializes"),
            )
        })
        .collect::<Vec<_>>();
    sort_per_item_plan_values(&mut actionable);
    let mut actionable_items = actionable
        .iter()
        .map(|entry| item_identity_from_value(&entry["selection"]))
        .collect::<Vec<_>>();
    sort_item_identity_values(&mut actionable_items);
    let mut no_op_plans = per_item_plans
        .iter()
        .filter(|entry| entry["status"] == "no-op")
        .cloned()
        .collect::<Vec<_>>();
    sort_per_item_plan_values(&mut no_op_plans);
    let mut no_op_items = no_op_plans
        .iter()
        .map(|entry| item_identity_from_value(&entry["selection"]))
        .collect::<Vec<_>>();
    sort_item_identity_values(&mut no_op_items);
    let per_item_operation_digests = plan
        .included
        .iter()
        .map(|entry| json!({"selection": serde_json::to_value(&entry.item).expect("identity"), "digest": entry.operation_digest}))
        .collect::<Vec<_>>();
    let mut blocked = plan
        .blocked
        .iter()
        .map(|entry| {
            json!({
                "item": entry.item,
                "reason": entry.reason_code,
            })
        })
        .collect::<Vec<_>>();
    sort_blocked_item_values(&mut blocked);
    let mut blocked_items = plan
        .blocked
        .iter()
        .map(|entry| {
            json!({
                "item": entry.item,
                "reasonCode": entry.reason_code,
                "message": blocked_reason_message(&entry.reason_code),
            })
        })
        .collect::<Vec<_>>();
    sort_blocked_item_values(&mut blocked_items);
    let status = match plan.status {
        BulkTogglePlanStatus::Planned => "planned",
        BulkTogglePlanStatus::NoOp => "no-op",
        BulkTogglePlanStatus::Blocked => "blocked",
        BulkTogglePlanStatus::NoTargetsInProviderReach => "no-targets-in-provider-reach",
    };
    let mut response = json!({
        "schemaVersion": plan.schema_version,
        "operationId": plan.operation_id,
        "status": status,
        "selector": plan.selector,
        "targetEnabled": plan.target_enabled,
        "allowEmptySelection": plan.allow_empty_selection,
        "providerReach": plan.provider_reach,
        "coverage": plan.provider_coverage,
        "providerCoverage": plan.provider_coverage,
        "acknowledgement": plan.acknowledgement,
        "lifecycle": plan.lifecycle,
        "applyMode": "fingerprint-required",
        "planFingerprint": plan.plan_fingerprint,
        "matchedCount": matched_items.len(),
        "includedCount": per_item_plans.len(),
        "actionableCount": actionable_items.len(),
        "noOpCount": no_op_items.len(),
        "blockedCount": blocked_items.len(),
        "matchedItems": matched_items,
        "actionableItems": actionable_items,
        "noOpItems": no_op_items,
        "blockedItems": blocked_items,
        "perItemPlans": per_item_plans,
        "noOpPlans": no_op_plans,
        "perItemOperationDigests": per_item_operation_digests,
        "warnings": warnings,
        "matched": matched,
        "actionable": actionable,
        "blocked": blocked,
    });
    if matches!(plan.status, BulkTogglePlanStatus::NoOp) && plan.matched.is_empty() {
        response["reason"] = json!("empty-selection");
        response["reasonCode"] = json!("empty-selection");
        response["message"] = json!(blocked_reason_message("empty-selection"));
    }
    response
}

fn bulk_plan_error_value(error: BulkBuildError) -> Value {
    match error {
        BulkBuildError::Message(message) => blocked_value(message),
        BulkBuildError::Core(BulkTogglePlanError::WholeInventoryAcknowledgementRequired(
            counts,
        )) => {
            json!({
                "status": "blocked",
                "reason": "whole-inventory-acknowledgement-required",
                "reasonCode": "whole-inventory-acknowledgement-required",
                "message": "The selector covers an entire multi-item inventory; acknowledge the complete inventory before planning.",
                "resolvedCounts": counts,
                "acknowledgementRequired": true,
            })
        }
        BulkBuildError::Core(error) => {
            let (reason_code, message) = match &error {
                BulkTogglePlanError::SelectorRequiresNonProviderCriterion => (
                    "selector-requires-non-provider-criterion",
                    error.to_string(),
                ),
                BulkTogglePlanError::EmptySelection => ("empty-selection", error.to_string()),
                BulkTogglePlanError::NoTargetsInProviderReach => {
                    ("no-targets-in-provider-reach", error.to_string())
                }
                _ => ("bulk-plan-invalid", error.to_string()),
            };
            json!({
                "status": "blocked",
                "reason": reason_code,
                "reasonCode": reason_code,
                "message": message,
                "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
            })
        }
    }
}

fn item_identity_from_value(item: &Value) -> Value {
    json!({
        "provider": item["provider"],
        "kind": item["kind"],
        "id": item["id"],
        "layer": item["layer"]
    })
}

fn blocked_reason_message(reason_code: &str) -> String {
    match reason_code {
        "already-in-desired-state" => "Item is already in the requested state.".to_string(),
        CONTROL_PLANE_PROTECTED_REASON => {
            "This configured MCP entry appears to be the Unpin control plane and cannot be disabled through MCP tools.".to_string()
        }
        "empty-selection" => "The selector did not match any items.".to_string(),
        "max-items-exceeded" => {
            "The reviewed bulk plan exceeds the requested maxItems guard.".to_string()
        }
        "plan-fingerprint-mismatch" => {
            "The reviewed bulk plan no longer matches the current machine state. Re-run the plan step before applying.".to_string()
        }
        other => format!("Item is blocked: {other}"),
    }
}

fn sort_item_identity_values(items: &mut [Value]) {
    items.sort_by_key(item_identity_key);
}

fn sort_blocked_item_values(items: &mut [Value]) {
    items.sort_by_key(|entry| item_identity_key(&entry["item"]));
}

fn sort_per_item_plan_values(items: &mut [Value]) {
    items.sort_by_key(|entry| item_identity_key(&entry["selection"]));
}

fn item_identity_key(item: &Value) -> (String, String, String, String) {
    (
        item.get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        item.get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        item.get("layer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        item.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    )
}

fn plan_summary_value(result: Value) -> Value {
    let affected_targets = target_summary_values(&result["affectedTargets"]);
    let affected_paths = path_values_from_targets(&affected_targets);
    let warnings = toggle_warning_values(&result);

    if result["status"] == "blocked" {
        let reason = result["reason"].as_str().unwrap_or("blocked").to_string();
        return json!({
            "status": "blocked",
            "selection": result["selection"],
            "targetEnabled": result["targetEnabled"],
            "applyMode": "re-resolve-on-apply",
            "operations": operation_summary_values(&result["operations"]),
            "affectedTargets": affected_targets,
            "affectedPaths": affected_paths,
            "reason": reason,
            "blocked": blocked_reason_value(&reason),
            "warnings": warnings
        });
    }

    json!({
        "status": "planned",
        "selection": result["selection"],
        "targetEnabled": result["targetEnabled"],
        "applyMode": "re-resolve-on-apply",
        "operations": operation_summary_values(&result["operations"]),
        "affectedTargets": affected_targets,
        "affectedPaths": affected_paths,
        "blocked": null,
        "warnings": warnings
    })
}

fn toggle_warning_values(result: &Value) -> Value {
    let changed_or_planned = matches!(
        result.get("status").and_then(Value::as_str),
        Some("dry-run" | "applied")
    );
    let provider = result["selection"]["provider"].as_str();
    let category = result["selection"]["category"].as_str();
    let restart_message = match (provider, category) {
        (Some("codex"), Some("skill")) => Some("Restart Codex to load the skill state change."),
        (Some("codex"), Some("plugin-config")) => {
            Some("Restart Codex to load the plugin state change.")
        }
        (Some("cursor"), Some("plugin-manifest")) => {
            Some("Restart Cursor or reload its window to load the local plugin state change.")
        }
        _ => None,
    };
    if changed_or_planned && let Some(message) = restart_message {
        json!([{
            "code": "restart-required",
            "message": message
        }])
    } else {
        json!([])
    }
}

fn operation_summary_values(operations: &Value) -> Value {
    Value::Array(
        operations
            .as_array()
            .into_iter()
            .flatten()
            .map(operation_summary_value)
            .collect(),
    )
}

fn operation_summary_value(operation: &Value) -> Value {
    if let Some(operation_type) = operation.get("type").and_then(Value::as_str) {
        return operation_with_contract_aliases(operation.clone(), operation_type);
    }

    match operation.get("operationType").and_then(Value::as_str) {
        Some("renamePath") => {
            let (Some(from_path), Some(to_path)) = (
                operation.get("fromPath").and_then(Value::as_str),
                operation.get("toPath").and_then(Value::as_str),
            ) else {
                return operation.clone();
            };

            json!({
                "type": "renamePath",
                "op": "renamePath",
                "from": from_path,
                "to": to_path,
                "fromPath": from_path,
                "toPath": to_path
            })
        }
        Some("replaceJsonValue") => {
            let (Some(path), Some(json_path), Some(value)) = (
                operation.get("path").and_then(Value::as_str),
                operation.get("jsonPath").and_then(Value::as_array),
                operation.get("value"),
            ) else {
                return operation.clone();
            };

            json!({
                "type": "replaceJsonValue",
                "op": "replaceJsonValue",
                "path": path,
                "jsonPath": json_path,
                "pointer": json_pointer_from_path(json_path),
                "value": value
            })
        }
        Some("replaceFile") => {
            let Some(path) = operation
                .get("path")
                .or_else(|| operation.get("fromPath"))
                .and_then(Value::as_str)
            else {
                return operation.clone();
            };

            json!({
                "type": "replaceFile",
                "op": "replaceFile",
                "path": path
            })
        }
        Some("replaceSqliteItemTableValue") => {
            let (Some(path), Some(value)) = (
                operation.get("path").and_then(Value::as_str),
                operation.get("value"),
            ) else {
                return operation.clone();
            };

            json!({
                "type": "replaceSqliteItemTableValue",
                "op": "replaceSqliteItemTableValue",
                "path": path,
                "value": value
            })
        }
        _ => operation.clone(),
    }
}

fn operation_with_contract_aliases(mut operation: Value, operation_type: &str) -> Value {
    let Some(object) = operation.as_object_mut() else {
        return operation;
    };

    object
        .entry("op".to_string())
        .or_insert_with(|| json!(operation_type));

    match operation_type {
        "renamePath" => {
            if let Some(from_path) = object.get("fromPath").cloned() {
                object.entry("from".to_string()).or_insert(from_path);
            }
            if let Some(to_path) = object.get("toPath").cloned() {
                object.entry("to".to_string()).or_insert(to_path);
            }
        }
        "replaceJsonValue" => {
            if let Some(json_path) = object.get("jsonPath").and_then(Value::as_array) {
                let pointer = json_pointer_from_path(json_path);
                object
                    .entry("pointer".to_string())
                    .or_insert_with(|| json!(pointer));
            }
        }
        _ => {}
    }

    operation
}

fn json_pointer_from_path(path: &[Value]) -> String {
    if path.is_empty() {
        return String::new();
    }

    let mut pointer = String::new();
    for segment in path {
        pointer.push('/');
        let rendered = segment
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| segment.to_string());
        pointer.push_str(&rendered.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}

fn target_summary_values(targets: &Value) -> Value {
    Value::Array(
        targets
            .as_array()
            .into_iter()
            .flatten()
            .map(target_summary_value)
            .collect(),
    )
}

fn target_summary_value(target: &Value) -> Value {
    if target.get("type").is_some() {
        return target.clone();
    }

    let Some(path) = target.get("path").and_then(Value::as_str) else {
        return target.clone();
    };
    let Some(target_type) = target.get("targetType").and_then(Value::as_str) else {
        return json!({ "type": "path", "path": path });
    };

    if target_type == "sqlite-item" {
        json!({ "type": target_type, "targetType": target_type, "path": path })
    } else {
        json!({ "type": "path", "path": path })
    }
}

fn path_values_from_targets(targets: &Value) -> Vec<String> {
    targets
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target.get("path").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn blocked_reason_value(reason_code: &str) -> Value {
    json!({
        "reasonCode": reason_code,
        "message": blocked_reason_message(reason_code)
    })
}

fn blocked_toggle_value(item: DiscoveryItem, target_enabled: bool, reason_code: &str) -> Value {
    json!({
        "status": "blocked",
        "selection": item,
        "targetEnabled": target_enabled,
        "applyMode": "re-resolve-on-apply",
        "operations": [],
        "affectedTargets": [],
        "affectedPaths": [],
        "reason": reason_code,
        "reasonCode": reason_code,
        "message": blocked_reason_message(reason_code),
        "blocked": blocked_reason_value(reason_code),
        "warnings": []
    })
}

fn list_backups(context: &McpContext, arguments: &Value) -> Value {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0);
    let mut backups = load_backup_summaries_authenticated(
        &context.app_state_root,
        context.backup_authentication_key.as_ref(),
    )
    .into_iter()
    .filter(|summary| {
        context.provider_scope.provider().is_none_or(|provider| {
            summary.providers.len() == 1
                && summary.providers.first().map(String::as_str) == Some(provider.as_str())
        })
    })
    .map(backup_summary_value)
    .collect::<Vec<_>>();
    let total_backups = backups.len();
    if let Some(limit) = limit {
        backups.truncate(limit);
    }

    json!({
        "status": "ok",
        "totalBackups": total_backups,
        "backups": backups
    })
}

fn backup_summary_value(summary: BackupSummary) -> Value {
    json!({
        "backupId": summary.backup_id,
        "createdAt": summary.created_at,
        "itemCount": summary.item_count,
        "providers": summary.providers,
        "layers": summary.layers,
        "paths": summary.paths,
        "restorable": summary.restorable,
        "authentication": summary.authentication,
        "selection": summary.selection,
        "targetEnabled": summary.target_enabled
    })
}

fn restore_backup_tool(context: &McpContext, arguments: &Value) -> Value {
    let Some(backup_id) = arguments.get("backupId").and_then(Value::as_str) else {
        return json!({
            "status": "failed",
            "reason": "missing required field: backupId"
        });
    };

    let approval_context = match control_approval_context(context) {
        Ok(context) => context,
        Err(error) => return blocked_value(error),
    };
    let plan = match RestoreController::new(&context.app_state_root).plan(
        backup_id,
        &approval_context,
        context.backup_authentication_key.as_ref(),
    ) {
        Ok(plan) => plan,
        Err(error) => return blocked_value(error.to_string()),
    };
    if let Err(error) = context
        .provider_scope
        .require_allowed_optional(Some(plan.provider))
    {
        return blocked_value(error);
    }
    let fingerprint = plan.plan_fingerprint.clone();
    if arguments.get("planFingerprint").is_some()
        && let Err(error) = require_plan_fingerprint(arguments, &fingerprint)
    {
        return blocked_value(error);
    }
    let expectation = match plan.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return blocked_value(error.to_string()),
    };
    let reviewed = arguments.get("planFingerprint").is_some();
    let lifecycle = if reviewed {
        ControlOperationLifecycle::AwaitingHumanAction
    } else {
        ControlOperationLifecycle::Planned
    };
    let operation = control_operation(
        &expectation,
        &fingerprint,
        plan.activation,
        lifecycle,
        Some(plan.provider),
        json!({"plan": plan.clone()}),
    );
    let mut response = if reviewed {
        human_action_required(operation)
    } else {
        json!({
            "status": "planned",
            "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
            "planFingerprint": fingerprint,
            "operation": operation,
            "continuation": "Review this plan, then call unpin_restore_backup again with its planFingerprint."
        })
    };
    response["operationKind"] = json!("restore-backup");
    response["operationReference"] = json!(format!("restore-backup:{fingerprint}"));
    response["plan"] = serde_json::to_value(plan).expect("restore plan serializes");
    response
}

fn selected_item(context: &McpContext, arguments: &Value) -> Result<DiscoveryItem, String> {
    let provider = optional_provider(context, arguments)?;
    let kind = required_string(arguments, "kind")?;
    let layer = required_string(arguments, "layer")?;
    let id = required_string(arguments, "id")?;
    let discovery = discover_scoped(context)?;
    let matches = discovery
        .items
        .into_iter()
        .filter(|item| {
            provider.is_none_or(|provider| item.provider == provider)
                && item.kind.as_str() == kind
                && item.layer.as_str() == layer
                && item.id == id
        })
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Err(format!("unknown selection for {id}")),
        1 => Ok(matches.into_iter().next().expect("one match exists")),
        _ => Err(format!("ambiguous selection for {id}")),
    }
}

fn required_string<'a>(arguments: &'a Value, field: &str) -> Result<&'a str, String> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required field: {field}"))
}

fn blocked_value(reason: impl Into<String>) -> Value {
    json!({
        "status": "blocked",
        "reason": reason.into(),
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
    })
}

fn capability_matrix_issues(fixture_root: Option<&PathBuf>) -> Vec<Value> {
    let Some(fixture_root) = fixture_root else {
        return Vec::new();
    };

    validate_capability_matrix(fixture_root)
        .issues
        .into_iter()
        .map(|message| json!({ "message": message }))
        .collect()
}

fn provider_fixture_issues(fixture_root: Option<&PathBuf>) -> Vec<Value> {
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

fn provider_health_rows(
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

fn fixture_provider_issues(issues: &[Value]) -> Vec<Value> {
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

fn capability_matrix_provider_issues(issues: &[Value]) -> Vec<Value> {
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

fn discovery_warning_provider_issue(warning: &crate::discovery::DiscoveryWarning) -> Value {
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

fn discovery_error_provider_issues(scope: McpProviderScope, message: &str) -> Vec<Value> {
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

fn provider_issue_in_scope(scope: McpProviderScope, issue: &Value, field: &str) -> bool {
    scope
        .provider()
        .is_none_or(|provider| issue.get(field).and_then(Value::as_str) == Some(provider.as_str()))
}

fn capability_matrix_issue_in_scope(scope: McpProviderScope, issue: &Value) -> bool {
    scope.provider().is_none_or(|provider| {
        issue
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| provider_ids_from_message(message).contains(&provider.as_str()))
    })
}

fn provider_ids_from_message(message: &str) -> Vec<&'static str> {
    let providers = ProviderId::ALL
        .into_iter()
        .map(ProviderId::as_str)
        .filter(|provider| message.contains(provider))
        .collect::<Vec<_>>();

    if providers.is_empty() {
        ProviderId::ALL.map(ProviderId::as_str).to_vec()
    } else {
        providers
    }
}

fn provider_summaries(
    discovery: &DiscoveryOutput,
    arguments: &Value,
    scope: McpProviderScope,
) -> Vec<Value> {
    let mut summaries = build_inventory_summary(discovery)
        .providers
        .into_iter()
        .map(|summary| serde_json::to_value(summary).expect("provider summary serializes"))
        .collect::<Vec<_>>();
    summaries.retain(|summary| {
        summary
            .get("provider")
            .and_then(Value::as_str)
            .is_some_and(|provider| {
                parse_provider_id(provider).is_ok_and(|provider| scope.allows(provider))
                    && selector_array_matches(arguments, "providers", provider)
            })
    });
    summaries
}

fn filter_summary_discovery(mut discovery: DiscoveryOutput, arguments: &Value) -> DiscoveryOutput {
    discovery.items.retain(|item| {
        selector_array_matches(arguments, "providers", item.provider.as_str())
            && selector_array_matches(arguments, "layers", item.layer.as_str())
    });
    discovery.warnings.retain(|warning| {
        selector_array_matches(arguments, "providers", warning.provider.as_str())
            && warning
                .layer
                .is_none_or(|layer| selector_array_matches(arguments, "layers", layer.as_str()))
    });
    discovery
}

fn selector_matches(item: &DiscoveryItem, selector: &Value) -> bool {
    selector_array_matches(selector, "providers", item.provider.as_str())
        && selector_array_matches(selector, "kinds", item.kind.as_str())
        && selector_array_matches(selector, "categories", item.category.as_str())
        && selector_array_matches(selector, "layers", item.layer.as_str())
        && selector_array_matches(selector, "ids", &item.id)
        && selector
            .get("enabled")
            .and_then(Value::as_bool)
            .is_none_or(|enabled| enabled == item.enabled)
}

fn validate_selector(selector: &Value) -> Result<(), String> {
    if selector.is_null() {
        return Ok(());
    }

    let selector = selector
        .as_object()
        .ok_or_else(|| "selector must be an object".to_string())?;

    for field in ["providers", "kinds", "categories", "layers", "ids"] {
        validate_selector_array_field(selector.get(field), field)?;
    }

    if let Some(enabled) = selector.get("enabled")
        && !enabled.is_boolean()
    {
        return Err("selector.enabled must be a boolean".to_string());
    }

    Ok(())
}

fn validate_selector_array_field(value: Option<&Value>, field: &str) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| format!("selector.{field} must be an array of strings"))?;
    if entries.iter().any(|entry| !entry.is_string()) {
        return Err(format!("selector.{field} must be an array of strings"));
    }

    Ok(())
}

fn selector_array_matches(selector: &Value, field: &str, value: &str) -> bool {
    selector
        .get(field)
        .and_then(Value::as_array)
        .is_none_or(|entries| entries.iter().any(|entry| entry.as_str() == Some(value)))
}

#[allow(dead_code)]
fn canonical_selector(selector: &Value) -> Value {
    let Some(selector_object) = selector.as_object() else {
        return json!({});
    };
    let mut canonical = serde_json::Map::new();

    for field in ["providers", "kinds", "categories", "layers", "ids"] {
        if let Some(values) = selector_object.get(field).and_then(Value::as_array) {
            let mut strings = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            strings.sort();
            canonical.insert(field.to_string(), json!(strings));
        }
    }

    if let Some(enabled) = selector_object.get("enabled").and_then(Value::as_bool) {
        canonical.insert("enabled".to_string(), json!(enabled));
    }

    Value::Object(canonical)
}

fn bulk_plan_fingerprint(payload: Value) -> String {
    let canonical = serde_json::to_vec(&payload).expect("bulk plan payload serializes");
    let digest = Sha256::digest(canonical);
    format!("sha256:{}", hex_bytes(&digest))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}

fn tool_descriptors(context: &McpContext) -> Vec<Value> {
    UNPIN_MCP_TOOL_NAMES
        .iter()
        .copied()
        .chain(
            context
                .approved_group_apply
                .as_ref()
                .map(|_| UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME),
        )
        .map(|name| {
            json!({
                "name": name,
                "title": tool_title(name),
                "description": tool_description(name),
                "inputSchema": tool_input_schema(name, context.provider_scope),
                "annotations": tool_annotations(name)
            })
        })
        .collect()
}

fn tool_title(name: &str) -> &'static str {
    match name {
        "unpin_get_inventory_summary" => "Get Unpin inventory summary",
        "unpin_list_items" => "List Unpin items",
        "unpin_list_inventory_groups" => "List Unpin inventory groups",
        "unpin_get_inventory_group" => "Get one Unpin inventory group",
        "unpin_plan_inventory_group" => "Plan one Unpin inventory group toggle",
        "unpin_apply_inventory_group" => "Apply one approved Unpin inventory group toggle",
        "unpin_plan_toggle_item" => "Plan one Unpin item toggle",
        "unpin_apply_toggle_item" => "Request one Unpin item toggle",
        "unpin_plan_toggle_items" => "Plan Unpin item toggles",
        "unpin_apply_toggle_items" => "Request Unpin item toggles",
        "unpin_list_backups" => "List Unpin backups",
        "unpin_restore_backup" => "Request Unpin backup restore",
        "unpin_run_doctor" => "Run Unpin doctor",
        "unpin_get_control_status" => "Get Unpin control status",
        "unpin_get_policy_maintenance_status" => "Get Unpin workspace policy maintenance status",
        "unpin_list_catalog" => "List Unpin catalog",
        "unpin_list_hooks" => "List Unpin hooks",
        "unpin_plan_catalog_adoption" => "Plan Unpin catalog adoption",
        "unpin_apply_catalog_adoption" => "Request Unpin catalog adoption",
        "unpin_plan_hook_trust" => "Plan Unpin hook trust",
        "unpin_apply_hook_trust" => "Request Unpin hook trust",
        "unpin_propose_session_profile" => "Propose Unpin session profile",
        "unpin_validate_profile" => "Validate Unpin profile",
        "unpin_plan_profile_policy" => "Plan Unpin profile policy",
        "unpin_apply_profile_policy" => "Request Unpin profile policy apply",
        "unpin_plan_profile_provider" => "Plan Unpin provider profile operation",
        "unpin_apply_profile_provider" => "Request Unpin provider profile apply",
        "unpin_get_capability_locks" => "Get Unpin capability locks",
        "unpin_plan_capability_lock" => "Plan Unpin capability lock",
        "unpin_apply_capability_lock" => "Request Unpin capability lock apply",
        "unpin_plan_gateway_mode" => "Plan Unpin gateway mode",
        "unpin_apply_gateway_mode" => "Request Unpin gateway mode apply",
        "unpin_get_gateway_status" => "Get Unpin gateway status",
        "unpin_plan_session_end" => "Plan Unpin session end",
        "unpin_apply_session_end" => "Request Unpin session end",
        "unpin_plan_session_launch" => "Plan isolated Unpin session launch",
        _ => "Unpin tool",
    }
}

fn tool_description(name: &str) -> &'static str {
    match name {
        "unpin_get_inventory_summary" => {
            "Return structured provider inventory counts and discovery warnings."
        }
        "unpin_list_items" => {
            "List discovered Unpin provider items with optional selector filters."
        }
        "unpin_list_inventory_groups" => {
            "List visible named inventory groups and their current derived state without writing."
        }
        "unpin_get_inventory_group" => {
            "Inspect one qualified inventory group with fresh member state without writing."
        }
        "unpin_plan_inventory_group" => {
            "Plan enabling or disabling one exact inventory group without writing."
        }
        "unpin_apply_inventory_group" => {
            "Apply only the exact inventory group plan authorized by an external one-time human approval artifact."
        }
        "unpin_plan_toggle_item" => {
            "Plan a reversible toggle for one selected provider item without writing."
        }
        "unpin_apply_toggle_item" => {
            "Validate one exact toggle plan and return a human-action handoff without writing."
        }
        "unpin_plan_toggle_items" => {
            "Plan a bulk selector toggle and return a stable review fingerprint."
        }
        "unpin_apply_toggle_items" => {
            "Validate a reviewed bulk toggle plan and return a human-action handoff without writing."
        }
        "unpin_list_backups" => "List recent Unpin mutation backups from local app state.",
        "unpin_restore_backup" => {
            "Validate one backup restore request and return a human-action handoff without writing."
        }
        "unpin_run_doctor" => "Return structured fixture and provider discovery health output.",
        "unpin_get_control_status" => {
            "Return redacted catalog, profiles, policies, gateway, sessions, and hook coverage state."
        }
        "unpin_get_policy_maintenance_status" => {
            "Return authenticated workspace-policy binding and orphan classification with exact CLI handoffs; never mutate policy state."
        }
        "unpin_list_catalog" => {
            "List normalized catalog capabilities and provider contribution fan-out."
        }
        "unpin_list_hooks" => {
            "List granular hook metadata and optional profile-bound stored trust status without executable bodies or trust receipts."
        }
        "unpin_plan_catalog_adoption" => {
            "Plan copying one adoptable native skill or agent into Unpin catalog storage without writing."
        }
        "unpin_apply_catalog_adoption" => {
            "Validate an exact catalog adoption fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_hook_trust" => {
            "Plan profile-bound trust for one discovered hook without storing a receipt."
        }
        "unpin_apply_hook_trust" => {
            "Validate an exact hook-trust fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_propose_session_profile" => {
            "Rank locally stored profiles from metadata, return only a prompt digest, and require explicit user confirmation before session launch."
        }
        "unpin_validate_profile" => {
            "Validate one stored or inline typed profile against current catalog without materializing state."
        }
        "unpin_plan_profile_policy" => {
            "Compile one stored profile and plan its next-session native/gateway policy selection without writing."
        }
        "unpin_apply_profile_policy" => {
            "Validate an exact profile policy fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_profile_provider" => {
            "Plan a named compiled profile for the explicitly reviewed provider reach without writing."
        }
        "unpin_apply_profile_provider" => {
            "Validate an exact provider-profile reach fingerprint and return a schema-v2 CLI human-approval handoff without writing."
        }
        "unpin_get_capability_locks" => {
            "Return global provider capability lock revisions and conservative enforcement evidence without writing."
        }
        "unpin_plan_capability_lock" => {
            "Plan one global provider hard-enabled, hard-disabled, or cleared capability lock without writing."
        }
        "unpin_apply_capability_lock" => {
            "Validate an exact capability lock fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_gateway_mode" => {
            "Plan combined gateway lifecycle and profile policy changes without writing."
        }
        "unpin_apply_gateway_mode" => {
            "Validate an exact gateway workflow fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_get_gateway_status" => {
            "Return gateway mode and policy state for global, repository, or workspace scope without writing."
        }
        "unpin_plan_session_end" => {
            "Plan fencing one session while preserving process-owned cleanup state."
        }
        "unpin_apply_session_end" => {
            "Validate an exact session-end fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_session_launch" => {
            "Validate immutable session exposure identifiers and return an argv-safe CLI launch handoff without accepting a child command, spawning a process, writing state, minting approval, or exposing session authority."
        }
        _ => "Unpin MCP tool.",
    }
}

fn tool_input_schema(name: &str, provider_scope: McpProviderScope) -> Value {
    let provider_ids = provider_scope.provider().map_or_else(
        || ProviderId::ALL.map(ProviderId::as_str).to_vec(),
        |provider| vec![provider.as_str()],
    );
    let mut schema = match name {
        "unpin_get_inventory_summary" => json!({
            "type": "object",
            "properties": {
                "providers": { "type": "array", "items": string_enum(&provider_ids) },
                "layers": { "type": "array", "items": string_enum(&["global", "project"]) }
            }
        }),
        "unpin_list_items" => json!({
            "type": "object",
            "properties": {
                "selector": selector_schema(&provider_ids),
                "limit": { "type": "integer", "minimum": 1 }
            }
        }),
        "unpin_list_inventory_groups" => json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_get_inventory_group" => json!({
            "type": "object",
            "required": ["group"],
            "properties": {
                "group": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_inventory_group" => json!({
            "type": "object",
            "required": ["group", "targetEnabled", "maxMembers", "providerReach"],
            "properties": {
                "group": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                "maxMembers": { "type": "integer", "minimum": 1, "maximum": 256 },
                "providerReach": {
                    "oneOf": [
                        { "type": "string", "enum": ["all", "all-providers", "omitted"] },
                        {
                            "type": "object",
                            "required": ["mode", "provider"],
                            "properties": {
                                "mode": { "type": "string", "enum": ["selected", "selected-provider"] },
                                "provider": non_empty_string_schema(),
                                "provenance": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    ]
                }
            },
            "additionalProperties": false
        }),
        "unpin_apply_inventory_group" => json!({
            "type": "object",
            "required": [
                "operationId",
                "planFingerprint",
                "challenge",
                "approvalArtifact"
            ],
            "properties": {
                "operationId": non_empty_string_schema(),
                "planFingerprint": non_empty_string_schema(),
                "challenge": non_empty_string_schema(),
                "approvalArtifact": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_toggle_item" => json!({
            "type": "object",
            "required": ["kind", "layer", "id", "targetEnabled"],
            "properties": {
                "provider": string_enum(&provider_ids),
                "kind": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]),
                "layer": string_enum(&["global", "project"]),
                "id": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" }
            }
        }),
        "unpin_apply_toggle_item" => json!({
            "type": "object",
            "required": ["kind", "layer", "id", "targetEnabled", "planFingerprint"],
            "properties": {
                "provider": string_enum(&provider_ids),
                "kind": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]),
                "layer": string_enum(&["global", "project"]),
                "id": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "requireConfirmation": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "planFingerprint": non_empty_string_schema()
            }
        }),
        "unpin_plan_toggle_items" => json!({
            "type": "object",
            "required": ["targetEnabled"],
            "properties": {
                "selector": selector_schema(&provider_ids),
                "targetEnabled": { "type": "boolean" },
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" },
                "planFingerprint": { "type": "string" },
                "maxItems": { "type": "integer", "minimum": 0 },
                "allowEmptySelection": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "acknowledgeWholeInventory": { "type": "boolean" }
            }
        }),
        "unpin_apply_toggle_items" => json!({
            "type": "object",
            "required": ["targetEnabled", "planFingerprint", "maxItems"],
            "properties": {
                "selector": selector_schema(&provider_ids),
                "targetEnabled": { "type": "boolean" },
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" },
                "planFingerprint": { "type": "string" },
                "maxItems": { "type": "integer", "minimum": 0 },
                "allowEmptySelection": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "acknowledgeWholeInventory": { "type": "boolean" }
            }
        }),
        "unpin_restore_backup" => json!({
            "type": "object",
            "required": ["backupId"],
            "properties": {
                "backupId": non_empty_string_schema(),
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "planFingerprint": non_empty_string_schema()
            }
        }),
        "unpin_list_backups" => json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "minimum": 1 }
            }
        }),
        "unpin_get_control_status" => json!({
            "type": "object",
            "properties": {
                "operationId": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_get_policy_maintenance_status" => json!({
            "type": "object",
            "properties": {
                "repositoryKey": non_empty_string_schema(),
                "workspaceKey": non_empty_string_schema(),
                "candidateCurrent": { "type": "boolean" }
            },
            "dependentRequired": {
                "repositoryKey": ["workspaceKey"],
                "workspaceKey": ["repositoryKey"]
            },
            "additionalProperties": false
        }),
        "unpin_list_catalog" => json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_list_hooks" => json!({
            "type": "object",
            "properties": {
                "provider": string_enum(&provider_ids),
                "profileDigest": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_propose_session_profile" => json!({
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": { "type": "string", "minLength": 1, "maxLength": 16384 },
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_validate_profile" => json!({
            "type": "object",
            "properties": {
                "profileId": non_empty_string_schema(),
                "definition": { "type": "object" },
                "sourceScope": string_enum(&["global", "repository", "workspace", "session"])
            },
            "oneOf": [
                { "required": ["profileId"] },
                { "required": ["definition", "sourceScope"] }
            ],
            "additionalProperties": false
        }),
        "unpin_plan_catalog_adoption" => control_catalog_adoption_schema(&provider_ids, false),
        "unpin_apply_catalog_adoption" => control_catalog_adoption_schema(&provider_ids, true),
        "unpin_plan_hook_trust" => control_hook_trust_schema(&provider_ids, false),
        "unpin_apply_hook_trust" => control_hook_trust_schema(&provider_ids, true),
        "unpin_plan_profile_policy" => control_profile_schema(&provider_ids, false),
        "unpin_apply_profile_policy" => control_profile_schema(&provider_ids, true),
        "unpin_plan_profile_provider" => control_profile_provider_schema(&provider_ids, false),
        "unpin_apply_profile_provider" => control_profile_provider_schema(&provider_ids, true),
        "unpin_get_capability_locks" => json!({
            "type": "object",
            "properties": {
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_plan_capability_lock" => control_capability_lock_schema(&provider_ids, false),
        "unpin_apply_capability_lock" => control_capability_lock_schema(&provider_ids, true),
        "unpin_plan_gateway_mode" => control_gateway_schema(&provider_ids, false),
        "unpin_apply_gateway_mode" => control_gateway_schema(&provider_ids, true),
        "unpin_get_gateway_status" => json!({
            "type": "object",
            "properties": {
                "scope": string_enum(&["global", "repository", "workspace"]),
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_plan_session_end" => control_session_end_schema(false),
        "unpin_apply_session_end" => control_session_end_schema(true),
        "unpin_plan_session_launch" => control_session_launch_schema(&provider_ids),
        _ => json!({
            "type": "object",
            "properties": {}
        }),
    };
    if provider_scope.provider().is_some() {
        remove_provider_requirement(&mut schema);
    }
    schema
}

fn remove_provider_requirement(schema: &mut Value) {
    match schema {
        Value::Array(values) => {
            for value in values {
                remove_provider_requirement(value);
            }
        }
        Value::Object(object) => {
            if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
                required.retain(|field| field.as_str() != Some("provider"));
            }
            for value in object.values_mut() {
                remove_provider_requirement(value);
            }
        }
        _ => {}
    }
}

fn control_catalog_adoption_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("id"), json!("providerRoot")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "id": non_empty_string_schema(),
            "providerRoot": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_hook_trust_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("id"), json!("profileDigest")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "id": non_empty_string_schema(),
            "profileDigest": non_empty_string_schema(),
            "sessionId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_profile_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("profileId"), json!("mode")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "profileId": non_empty_string_schema(),
            "mode": string_enum(&["native", "gateway"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_profile_provider_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("profileId"), json!("mode"), json!("providerReach")];
    if apply {
        required.push(json!("operationId"));
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "profileId": non_empty_string_schema(),
            "mode": string_enum(&["native", "gateway"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "providerReach": {
                "oneOf": [
                    { "type": "string", "enum": ["all", "all-providers", "omitted"] },
                    {
                        "type": "object",
                        "required": ["mode", "provider"],
                        "properties": {
                            "mode": { "type": "string", "enum": ["selected", "selected-provider"] },
                            "provider": string_enum(provider_ids),
                            "provenance": { "type": "string" }
                        },
                        "additionalProperties": false
                    }
                ]
            },
            "operationId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_capability_lock_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("capabilityId"), json!("state")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "capabilityId": non_empty_string_schema(),
            "state": string_enum(&["hard-enabled", "hard-disabled", "clear"]),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_gateway_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("action")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "action": string_enum(&["install", "on", "off", "detach"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "force": { "type": "boolean" },
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_session_end_schema(apply: bool) -> Value {
    let mut required = vec![json!("sessionId")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "sessionId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

fn control_session_launch_schema(provider_ids: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": ["provider", "exposureRevision", "profile"],
        "properties": {
            "provider": string_enum(provider_ids),
            "exposureRevision": non_empty_string_schema(),
            "profile": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": string_enum(&["native"])
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": string_enum(&["none"])
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["type", "profileId", "profileDigest", "definitionDigest"],
                        "properties": {
                            "type": string_enum(&["profile"]),
                            "profileId": non_empty_string_schema(),
                            "profileDigest": non_empty_string_schema(),
                            "definitionDigest": non_empty_string_schema()
                        },
                        "additionalProperties": false
                    }
                ]
            }
        },
        "additionalProperties": false
    })
}

fn tool_annotations(name: &str) -> Value {
    match name {
        "unpin_apply_inventory_group" => json!({
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false
        }),
        "unpin_get_inventory_summary"
        | "unpin_list_items"
        | "unpin_list_inventory_groups"
        | "unpin_get_inventory_group"
        | "unpin_plan_inventory_group"
        | "unpin_plan_toggle_item"
        | "unpin_plan_toggle_items"
        | "unpin_apply_toggle_item"
        | "unpin_apply_toggle_items"
        | "unpin_list_backups"
        | "unpin_restore_backup"
        | "unpin_run_doctor"
        | "unpin_get_control_status"
        | "unpin_get_policy_maintenance_status"
        | "unpin_list_catalog"
        | "unpin_list_hooks"
        | "unpin_plan_catalog_adoption"
        | "unpin_apply_catalog_adoption"
        | "unpin_plan_hook_trust"
        | "unpin_apply_hook_trust"
        | "unpin_propose_session_profile"
        | "unpin_validate_profile"
        | "unpin_plan_profile_policy"
        | "unpin_apply_profile_policy"
        | "unpin_plan_profile_provider"
        | "unpin_apply_profile_provider"
        | "unpin_get_capability_locks"
        | "unpin_plan_capability_lock"
        | "unpin_apply_capability_lock"
        | "unpin_plan_gateway_mode"
        | "unpin_apply_gateway_mode"
        | "unpin_get_gateway_status"
        | "unpin_plan_session_end"
        | "unpin_apply_session_end"
        | "unpin_plan_session_launch" => json!({
            "readOnlyHint": true
        }),
        _ => json!({}),
    }
}

fn selector_schema(provider_ids: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {
            "providers": { "type": "array", "items": string_enum(provider_ids) },
            "kinds": { "type": "array", "items": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]) },
            "categories": { "type": "array", "items": string_enum(&[
                "skill",
                "configured-mcp",
                "tool",
                "agent",
                "hook",
                "provider-setting",
                "plugin-config",
                "plugin-manifest"
            ]) },
            "layers": { "type": "array", "items": string_enum(&["global", "project"]) },
            "enabled": { "type": "boolean" },
            "ids": { "type": "array", "items": non_empty_string_schema() }
        }
    })
}

fn string_enum(values: &[&str]) -> Value {
    json!({
        "type": "string",
        "enum": values
    })
}

fn provider_reach_input_schema(provider_ids: &[&str], selected_provider_required: bool) -> Value {
    let mut selected_required = vec![json!("mode")];
    if selected_provider_required {
        selected_required.push(json!("provider"));
    }
    json!({
        "oneOf": [
            {
                "type": "string",
                "enum": ["all", "all-providers", "omitted"]
            },
            {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["all", "all-providers"]
                    }
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": selected_required,
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["selected", "selected-provider"]
                    },
                    "provider": {
                        "type": "string",
                        "enum": provider_ids
                    }
                },
                "additionalProperties": false
            }
        ]
    })
}

fn non_empty_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1
    })
}

fn result_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

fn encode_message(body: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(body.len() + 1);
    encoded.extend_from_slice(body.as_bytes());
    encoded.push(b'\n');
    encoded
}
