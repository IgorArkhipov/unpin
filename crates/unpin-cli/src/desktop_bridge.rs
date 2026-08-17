use std::{
    collections::VecDeque,
    ffi::OsString,
    io::{self, BufRead, Write},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "macos")]
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

pub(super) use crate::{
    commands::{ProviderReachArg, toggle::durable_context},
    credentials,
    group_store::ScopedGroupStore,
    parse_provider_id, session_process,
};
pub(super) use serde_json::{Value, json};
pub(super) use std::collections::{BTreeMap, BTreeSet};
pub(super) use unpin_core::{
    agent_plugins::{AgentPluginComponentDisposition, AgentPluginInstance, AgentPluginSummary},
    approval::ControlApprovalContext,
    catalog::Catalog,
    config::UnpinConfig,
    control::build_control_status,
    control_operation::ReachAwareOperationFamily,
    discovery::{DiscoveryItem, DiscoveryOutput, DiscoveryRoots},
    groups::{
        GROUP_DEFINITION_OWNER_ID, GroupAccessContext, GroupController, GroupDefinitionV1,
        GroupMemberIdentity, GroupPlanDisposition, GroupPlanMode, GroupPlanner, GroupRef,
        GroupResolver, GroupRevision, GroupScope, GroupTargetState, GroupTogglePlan,
        MAX_GROUP_MEMBERS, PersonalGroupStore, RepositoryGroupStore,
        list_group_operation_inspections, list_group_operation_inspections_with_backup_index,
        validate_new_group_members,
    },
    mcp::McpDiscoveryCache,
    mutation::{
        AuthenticatedBackupIndex, BackupAuthenticationKey, BulkToggleApplyResult,
        BulkToggleController, BulkTogglePlan, BulkTogglePlanError, BulkToggleRequest,
        RestoreControlPlan, RestoreController, RestoreResult, ToggleStatus,
        load_backup_index_authenticated,
    },
    profiles::{
        CapabilityLockSnapshot, PolicyStore, PolicyTarget, ProfileSourceScope, ProfileStore,
        compile_profile,
    },
    provider_reach::{
        ConnectionBoundary, IncludedTargetOutcome, ProviderReach, ProviderReachLifecycle,
        SelectedProviderAuthority, SelectedProviderProvenance,
    },
    providers::ProviderId,
    sessions::{
        LeaseSnapshot, PinnedExposure, PinnedProfile, SessionAuthorityKey, SessionManager,
        WorkflowJournal, WorkflowOperationRecord, WorkflowProposalV1, WorkflowReloadLimitation,
        WorkflowTransitionRequest,
    },
    state::atomic_json::OwnerGeneration,
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowDefinition, WorkflowModeDefinition, WorkflowStore,
        compile_workflow,
    },
};

pub(crate) const PROTOCOL_VERSION: u64 = 2;
pub(super) const MAX_FRAME_BYTES: usize = 1_048_576;
pub(super) const MAX_REQUEST_ID_BYTES: usize = 128;
pub(super) const MAX_SEEN_REQUEST_IDS: usize = 4_096;
pub(super) const MAX_BRIDGE_IDENTIFIER_BYTES: usize = 256;
pub(super) const MAX_REVIEWED_CONTROL_PLANS: usize = 32;
pub(super) const MAX_REVIEWED_DEFINITION_PLANS: usize = 32;
pub(super) const REVIEWED_PLAN_TTL_SECONDS: i64 = 15 * 60;
pub(super) const METHOD_HANDSHAKE: &str = "handshake";
pub(super) const METHOD_WORKFLOW_COMPOSE: &str = "workflow.compose";
pub(super) const METHOD_WORKFLOW_VALIDATE: &str = "workflow.validate";
pub(super) const METHOD_WORKFLOW_PROPOSE: &str = "workflow.propose";
pub(super) const METHOD_WORKFLOW_LAUNCH: &str = "workflow.launch";
pub(super) const METHOD_WORKFLOW_TRANSITION: &str = "workflow.transition";
pub(super) const METHOD_WORKFLOW_OBSERVE: &str = "workflow.observe";
pub(super) const METHOD_WORKFLOW_CANCEL: &str = "workflow.cancel-transition";
pub(super) const METHOD_WORKFLOW_STATUS: &str = "workflow.status";
pub(super) const METHOD_WORKFLOW_RECOVERY: &str = "workflow.recovery";
pub(super) const METHOD_SNAPSHOT: &str = "snapshot";
pub(super) const METHOD_GROUP_PLAN: &str = "group.plan";
pub(super) const METHOD_GROUP_APPROVE: &str = "group.approve";
pub(super) const METHOD_GROUP_APPLY: &str = "group.apply";
pub(super) const METHOD_GROUP_DISCARD: &str = "group.discard";
pub(super) const METHOD_AGENT_PLUGIN_INSPECT: &str = "agentPlugins.inspect";
pub(super) const METHOD_AGENT_PLUGIN_PLAN: &str = "agentPlugins.plan";
pub(super) const METHOD_AGENT_PLUGIN_APPROVE: &str = "agentPlugins.approve";
pub(super) const METHOD_AGENT_PLUGIN_APPLY: &str = "agentPlugins.apply";
pub(super) const METHOD_AGENT_PLUGIN_DISCARD: &str = "agentPlugins.discard";
pub(super) const METHOD_GROUP_DEFINITION_PLAN: &str = "group.definition.plan";
pub(super) const METHOD_GROUP_DEFINITION_APPLY: &str = "group.definition.apply";
pub(super) const METHOD_GROUP_DEFINITION_DISCARD: &str = "group.definition.discard";
pub(super) const METHOD_GROUP_DEFINITION_HISTORY: &str = "group.definition.history";
pub(super) const METHOD_RECOVERY_SNAPSHOT: &str = "recovery.snapshot";
pub(super) const METHOD_RESTORE_PLAN: &str = "restore.plan";
pub(super) const METHOD_RESTORE_APPROVE: &str = "restore.approve";
pub(super) const METHOD_RESTORE_APPLY: &str = "restore.apply";
pub(super) const METHOD_RESTORE_DISCARD: &str = "restore.discard";
pub(super) const METHOD_SHUTDOWN: &str = "shutdown";
pub(super) const BRIDGE_CAPABILITIES: &[&str] = &[
    METHOD_SNAPSHOT,
    METHOD_GROUP_PLAN,
    METHOD_GROUP_APPROVE,
    METHOD_GROUP_APPLY,
    METHOD_GROUP_DISCARD,
    METHOD_AGENT_PLUGIN_INSPECT,
    METHOD_AGENT_PLUGIN_PLAN,
    METHOD_AGENT_PLUGIN_APPROVE,
    METHOD_AGENT_PLUGIN_APPLY,
    METHOD_AGENT_PLUGIN_DISCARD,
    METHOD_GROUP_DEFINITION_PLAN,
    METHOD_GROUP_DEFINITION_APPLY,
    METHOD_GROUP_DEFINITION_DISCARD,
    METHOD_GROUP_DEFINITION_HISTORY,
    METHOD_RECOVERY_SNAPSHOT,
    METHOD_RESTORE_PLAN,
    METHOD_RESTORE_APPROVE,
    METHOD_RESTORE_APPLY,
    METHOD_RESTORE_DISCARD,
    METHOD_WORKFLOW_COMPOSE,
    METHOD_WORKFLOW_VALIDATE,
    METHOD_WORKFLOW_PROPOSE,
    METHOD_WORKFLOW_LAUNCH,
    METHOD_WORKFLOW_TRANSITION,
    METHOD_WORKFLOW_OBSERVE,
    METHOD_WORKFLOW_CANCEL,
    METHOD_WORKFLOW_STATUS,
    METHOD_WORKFLOW_RECOVERY,
];

mod agent_plugins;
mod groups;
mod restore;
mod snapshot;
mod workflow;
use agent_plugins::*;
use groups::*;
use restore::*;
use snapshot::*;
use workflow::*;

pub(crate) struct DesktopBridgeContext {
    config: UnpinConfig,
    discovery_roots: DiscoveryRoots,
    fixture_mode: bool,
    discovery_cache: McpDiscoveryCache,
}

impl DesktopBridgeContext {
    #[must_use]
    pub(crate) fn new(
        config: UnpinConfig,
        discovery_roots: DiscoveryRoots,
        fixture_mode: bool,
    ) -> Self {
        Self {
            config,
            discovery_roots,
            fixture_mode,
            discovery_cache: McpDiscoveryCache::with_ttl(Duration::from_secs(60)),
        }
    }
}

pub(super) fn cached_discovery(
    context: &DesktopBridgeContext,
) -> Result<DiscoveryOutput, &'static str> {
    cached_discovery_arc(context).map(|discovery| (*discovery).clone())
}

pub(super) fn fresh_discovery(
    context: &DesktopBridgeContext,
) -> Result<DiscoveryOutput, &'static str> {
    fresh_discovery_arc(context).map(|discovery| (*discovery).clone())
}

fn cached_discovery_arc(
    context: &DesktopBridgeContext,
) -> Result<std::sync::Arc<DiscoveryOutput>, &'static str> {
    context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)
        .map_err(|_| "discovery-unavailable")
}

fn fresh_discovery_arc(
    context: &DesktopBridgeContext,
) -> Result<std::sync::Arc<DiscoveryOutput>, &'static str> {
    context
        .discovery_cache
        .refresh(&context.discovery_roots)
        .map_err(|_| "discovery-unavailable")
}

pub(super) fn invalidate_discovery(context: &DesktopBridgeContext) {
    context.discovery_cache.invalidate();
}

pub(super) fn invalidate_after_discovery_change<T, E>(
    context: &DesktopBridgeContext,
    result: Result<T, E>,
) -> Result<T, E> {
    invalidate_discovery(context);
    result
}

pub(crate) fn run(context: DesktopBridgeContext) -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(context, stdin.lock(), stdout.lock())
}

pub(super) fn run_with_io(
    context: DesktopBridgeContext,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<(), String> {
    let mut state = DesktopBridgeState::new(context);
    let mut seen_request_ids = RecentRequestIds::default();
    let mut frame = Vec::with_capacity(4096);
    while let Some(frame_status) =
        read_frame(&mut input, &mut frame).map_err(|error| error.to_string())?
    {
        if frame_status == FrameStatus::Oversized {
            write_response(&mut output, &error_response(None, "frame-too-large"))?;
            continue;
        }
        let response = match parse_request(&frame) {
            Ok(request) => match record_request_id(&mut seen_request_ids, &request.id) {
                Ok(()) => handle_request(&mut state, request),
                Err(code) => error_response(Some(&request.id), code),
            },
            Err(error) => error_response(error.id.as_deref(), error.code),
        };
        write_response(&mut output, &response)?;
        if response
            .get("result")
            .and_then(|result| result.get("shutdown"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            break;
        }
    }
    Ok(())
}

pub(super) struct Request {
    id: String,
    method: String,
    params: Value,
    auth: Option<BridgeRequestAuth>,
}

#[derive(Clone, Debug)]
pub(super) struct BridgeRequestAuth {
    parent_pid: u32,
    parent_start_marker: String,
    child_pid: u32,
    child_start_marker: String,
    project_root: String,
    app_state_root: String,
    process_generation: String,
    sequence: u64,
    operation_id: String,
    fingerprint: String,
    auth_tag: String,
}

impl BridgeRequestAuth {
    pub(super) fn from_value(value: &Value) -> Result<Self, ()> {
        let object = value.as_object().ok_or(())?;
        if object.len() != 11
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "parentPid"
                        | "parentStartMarker"
                        | "childPid"
                        | "childStartMarker"
                        | "projectRoot"
                        | "appStateRoot"
                        | "processGeneration"
                        | "sequence"
                        | "operationId"
                        | "fingerprint"
                        | "authTag"
                )
            })
        {
            return Err(());
        }
        let string = |key: &str| {
            object
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(())
        };
        Ok(Self {
            parent_pid: u32::try_from(object.get("parentPid").and_then(Value::as_u64).ok_or(())?)
                .map_err(|_| ())?,
            parent_start_marker: string("parentStartMarker")?,
            child_pid: u32::try_from(object.get("childPid").and_then(Value::as_u64).ok_or(())?)
                .map_err(|_| ())?,
            child_start_marker: string("childStartMarker")?,
            project_root: string("projectRoot")?,
            app_state_root: string("appStateRoot")?,
            process_generation: string("processGeneration")?,
            sequence: object.get("sequence").and_then(Value::as_u64).ok_or(())?,
            operation_id: string("operationId")?,
            fingerprint: string("fingerprint")?,
            auth_tag: string("authTag")?,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct BridgeBinding {
    session_secret: String,
    parent_pid: u32,
    parent_start_marker: String,
    child_pid: u32,
    child_start_marker: String,
    project_root: String,
    app_state_root: String,
    process_generation: String,
}

#[derive(Clone, Debug)]
pub(super) struct WorkflowModeDraft {
    name: String,
    profile_id: String,
}

#[derive(Clone, Debug)]
pub(super) struct WorkflowDraft {
    workflow_id: String,
    display_name: String,
    description: Option<String>,
    provider: String,
    baseline_profile_id: String,
    entry_mode: String,
    modes: Vec<WorkflowModeDraft>,
    workflow_revision: String,
}

#[derive(Clone, Debug)]
pub(super) struct ReviewedWorkflowLaunch {
    proposal: WorkflowProposalV1,
    workflow_id: String,
    proposal_fingerprint: String,
    reviewed_at_unix: i64,
}

pub(super) struct DesktopBridgeState {
    context: DesktopBridgeContext,
    binding: Option<BridgeBinding>,
    next_authenticated_sequence: u64,
    reviewed_groups: BTreeMap<String, ReviewedGroupPlan>,
    reviewed_agent_plugins: BTreeMap<String, ReviewedAgentPluginPlan>,
    reviewed_restores: BTreeMap<String, ReviewedRestorePlan>,
    reviewed_definitions: BTreeMap<String, ReviewedDefinitionChange>,
    workflows: BTreeMap<String, WorkflowDraft>,
    reviewed_workflow_launches: BTreeMap<String, ReviewedWorkflowLaunch>,
    workflow_session_id: Option<String>,
    next_definition_plan_id: u64,
}

impl DesktopBridgeState {
    pub(super) fn new(context: DesktopBridgeContext) -> Self {
        Self {
            context,
            binding: None,
            next_authenticated_sequence: 0,
            reviewed_groups: Default::default(),
            reviewed_agent_plugins: Default::default(),
            reviewed_restores: Default::default(),
            reviewed_definitions: Default::default(),
            workflows: Default::default(),
            reviewed_workflow_launches: Default::default(),
            workflow_session_id: None,
            next_definition_plan_id: 0,
        }
    }
}

pub(super) struct ReviewedGroupPlan {
    plan: GroupTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

pub(super) struct ReviewedAgentPluginPlan {
    package: AgentPluginSummary,
    plan: BulkTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

pub(super) struct ReviewedRestorePlan {
    plan: RestoreControlPlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

#[derive(Clone)]
pub(super) struct ReviewedDefinitionChange {
    action: DefinitionChangeAction,
    plan_fingerprint: String,
    reviewed_at_unix: i64,
}

#[derive(Default)]
pub(super) struct RecentRequestIds {
    order: VecDeque<String>,
    values: BTreeSet<String>,
}

#[derive(Clone)]
pub(super) enum DefinitionChangeAction {
    Create {
        scope: GroupScope,
        definition: GroupDefinitionV1,
    },
    Replace {
        scope: GroupScope,
        qualified_name: String,
        definition: GroupDefinitionV1,
        expected_revision: GroupRevision,
    },
    Rename {
        scope: GroupScope,
        qualified_name: String,
        new_name: String,
        expected_revision: GroupRevision,
    },
    Delete {
        scope: GroupScope,
        qualified_name: String,
        expected_revision: GroupRevision,
    },
    Restore {
        scope: GroupScope,
        history_id: String,
        expected_revision: Option<GroupRevision>,
    },
}

impl DefinitionChangeAction {
    pub(super) const fn kind(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Replace { .. } => "replace",
            Self::Rename { .. } => "rename",
            Self::Delete { .. } => "delete",
            Self::Restore { .. } => "restore",
        }
    }

    pub(super) const fn scope(&self) -> GroupScope {
        match self {
            Self::Create { scope, .. }
            | Self::Replace { scope, .. }
            | Self::Rename { scope, .. }
            | Self::Delete { scope, .. }
            | Self::Restore { scope, .. } => *scope,
        }
    }
}

pub(super) struct RequestError {
    id: Option<String>,
    code: &'static str,
}

pub(super) fn parse_request(frame: &[u8]) -> Result<Request, RequestError> {
    let value = serde_json::from_slice::<Value>(frame).map_err(|_| RequestError {
        id: None,
        code: "malformed-request",
    })?;
    let object = value.as_object().ok_or(RequestError {
        id: None,
        code: "malformed-request",
    })?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "version" | "id" | "method" | "params" | "auth"
        )
    }) {
        return Err(RequestError {
            id: object
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            code: "unknown-request-field",
        });
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(RequestError {
            id: None,
            code: "missing-request-id",
        })?
        .to_string();
    if !valid_request_id(&id) {
        return Err(RequestError {
            id: Some(id),
            code: "invalid-request-id",
        });
    }
    if object.get("version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
        return Err(RequestError {
            id: Some(id),
            code: "unsupported-protocol-version",
        });
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty() && method.len() <= 128)
        .ok_or(RequestError {
            id: Some(id.clone()),
            code: "invalid-method",
        })?
        .to_string();
    if object
        .get("params")
        .is_some_and(|params| !params.is_object())
    {
        return Err(RequestError {
            id: Some(id),
            code: "invalid-params",
        });
    }
    Ok(Request {
        id,
        method,
        params: object.get("params").cloned().unwrap_or_else(|| json!({})),
        auth: object
            .get("auth")
            .map(BridgeRequestAuth::from_value)
            .transpose()
            .map_err(|_| RequestError {
                id: object
                    .get("id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                code: "invalid-bridge-auth",
            })?,
    })
}

pub(super) fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_ID_BYTES && !value.chars().any(char::is_control)
}

pub(super) fn record_request_id(
    seen_request_ids: &mut RecentRequestIds,
    id: &str,
) -> Result<(), &'static str> {
    if seen_request_ids.values.contains(id) {
        return Err("duplicate-request-id");
    }
    if seen_request_ids.order.len() == MAX_SEEN_REQUEST_IDS
        && let Some(expired) = seen_request_ids.order.pop_front()
    {
        seen_request_ids.values.remove(&expired);
    }
    seen_request_ids.order.push_back(id.to_string());
    seen_request_ids.values.insert(id.to_string());
    Ok(())
}

pub(super) fn has_reviewed_plan_capacity<T>(
    plans: &BTreeMap<String, T>,
    operation_id: &str,
) -> bool {
    plans.contains_key(operation_id) || plans.len() < MAX_REVIEWED_CONTROL_PLANS
}

pub(super) fn reviewed_plan_is_expired(reviewed_at_unix: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(reviewed_at_unix) > REVIEWED_PLAN_TTL_SECONDS
}

pub(super) fn prune_expired_reviewed_plans(state: &mut DesktopBridgeState) {
    let now_unix = unix_now();
    state
        .reviewed_groups
        .retain(|_, review| !reviewed_plan_is_expired(review.reviewed_at_unix, now_unix));
    state
        .reviewed_agent_plugins
        .retain(|_, review| !reviewed_plan_is_expired(review.reviewed_at_unix, now_unix));
    state
        .reviewed_restores
        .retain(|_, review| !reviewed_plan_is_expired(review.reviewed_at_unix, now_unix));
    state
        .reviewed_definitions
        .retain(|_, review| !reviewed_plan_is_expired(review.reviewed_at_unix, now_unix));
    state
        .reviewed_workflow_launches
        .retain(|_, review| !reviewed_plan_is_expired(review.reviewed_at_unix, now_unix));
}

pub(super) fn handle_handshake(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "sessionSecret",
            "parentPid",
            "parentStartMarker",
            "childPid",
            "processGeneration",
            "projectRoot",
            "appStateRoot",
        ],
    )?;
    if state.binding.is_some() {
        return Err("bridge-handshake-already-complete");
    }
    let session_secret = required_string(params, "sessionSecret")?;
    if session_secret.len() != 64 || !session_secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid-bridge-session-secret");
    }
    let parent_pid = params
        .get("parentPid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or("invalid-bridge-parent")?;
    let child_pid = params
        .get("childPid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or("invalid-bridge-child")?;
    let parent_start_marker = bounded_bridge_string(params, "parentStartMarker")?;
    let process_generation = bounded_bridge_string(params, "processGeneration")?;
    let project_root = bounded_bridge_string(params, "projectRoot")?;
    let app_state_root = bounded_bridge_string(params, "appStateRoot")?;
    let expected_project_root = state.context.config.project_root.to_string_lossy();
    let expected_app_state_root = state.context.config.app_state_root.to_string_lossy();
    if project_root != expected_project_root || app_state_root != expected_app_state_root {
        return Err("bridge-root-mismatch");
    }
    require_fixture_bridge_sandbox(&state.context)?;
    if child_pid != std::process::id() || parent_pid != current_parent_process_id() {
        return Err("bridge-process-mismatch");
    }
    if !state.context.fixture_mode {
        verify_signed_desktop_parent(parent_pid)?;
    }
    let child_start_marker = unpin_core::sha256_digest(
        format!(
            "unpin.desktop.bridge.child.v1\0{session_secret}\0{child_pid}\0{}",
            unix_now()
        )
        .as_bytes(),
    );
    let binding = BridgeBinding {
        session_secret: session_secret.to_ascii_lowercase(),
        parent_pid,
        parent_start_marker: parent_start_marker.to_string(),
        child_pid,
        child_start_marker: child_start_marker.clone(),
        project_root: project_root.to_string(),
        app_state_root: app_state_root.to_string(),
        process_generation: process_generation.to_string(),
    };
    state.binding = Some(binding.clone());
    state.next_authenticated_sequence = 0;
    Ok(handshake_response_for_binding(&binding))
}

pub(super) fn bounded_bridge_string<'a>(
    params: &'a Value,
    key: &str,
) -> Result<&'a str, &'static str> {
    let value = required_string(params, key)?;
    if value.is_empty()
        || value.len() > MAX_BRIDGE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("invalid-bridge-binding");
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
pub(super) fn verify_signed_desktop_parent(parent_pid: u32) -> Result<(), &'static str> {
    pub(super) const DESKTOP_SIGNING_IDENTITY: &str = "dev.unpin.workbench";
    pub(super) const CS_VALID: u32 = 0x0000_0001;
    pub(super) const CS_ADHOC: u32 = 0x0000_0002;
    pub(super) const CS_OPS_STATUS: c_uint = 0;
    pub(super) const CS_OPS_IDENTITY: c_uint = 11;
    pub(super) const CS_OPS_TEAMID: c_uint = 14;

    unsafe extern "C" {
        pub(super) fn csops(
            pid: c_int,
            ops: c_uint,
            useraddr: *mut c_void,
            usersize: usize,
        ) -> c_int;
    }

    pub(super) fn signing_value(pid: u32, operation: c_uint) -> Result<String, &'static str> {
        let pid = c_int::try_from(pid).map_err(|_| "bridge-signing-identity-unavailable")?;
        let mut value = [0_u8; 256];
        // SAFETY: `value` is writable for the duration of this kernel call.
        let result = unsafe {
            csops(
                pid,
                operation,
                value.as_mut_ptr().cast::<c_void>(),
                value.len(),
            )
        };
        if result != 0 || !value.contains(&0) {
            return Err("bridge-signing-identity-unavailable");
        }
        // SAFETY: successful csops identity values are NUL-terminated.
        let value = unsafe { CStr::from_ptr(value.as_ptr().cast::<c_char>()) };
        value
            .to_str()
            .map(str::to_string)
            .map_err(|_| "bridge-signing-identity-unavailable")
    }

    pub(super) fn signing_status(pid: u32) -> Result<u32, &'static str> {
        let pid = c_int::try_from(pid).map_err(|_| "bridge-signing-identity-unavailable")?;
        let mut status = 0_u32;
        // SAFETY: `status` is a valid writable u32 for this kernel call.
        let result = unsafe {
            csops(
                pid,
                CS_OPS_STATUS,
                (&raw mut status).cast::<c_void>(),
                size_of::<u32>(),
            )
        };
        (result == 0)
            .then_some(status)
            .ok_or("bridge-signing-identity-unavailable")
    }

    let child_pid = std::process::id();
    let parent_status = signing_status(parent_pid)?;
    let child_status = signing_status(child_pid)?;
    if parent_status & CS_VALID == 0
        || child_status & CS_VALID == 0
        || parent_status & CS_ADHOC != 0
        || child_status & CS_ADHOC != 0
        || signing_value(parent_pid, CS_OPS_IDENTITY)? != DESKTOP_SIGNING_IDENTITY
    {
        return Err("bridge-signing-identity-mismatch");
    }
    let parent_team = signing_value(parent_pid, CS_OPS_TEAMID)?;
    let child_team = signing_value(child_pid, CS_OPS_TEAMID)?;
    if parent_team.is_empty() || parent_team != child_team {
        return Err("bridge-signing-identity-mismatch");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn verify_signed_desktop_parent(_parent_pid: u32) -> Result<(), &'static str> {
    Err("bridge-signing-identity-unavailable")
}

pub(super) fn current_parent_process_id() -> u32 {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            pub(super) fn getppid() -> i32;
        }
        // SAFETY: getppid is a side-effect-free libc query on supported Unix
        // hosts and has no pointers or ownership requirements.
        unsafe { getppid() }.try_into().unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub(super) fn authenticate_request(
    state: &mut DesktopBridgeState,
    request: &Request,
) -> Result<(), &'static str> {
    let Some(binding) = state.binding.as_ref() else {
        return Err("bridge-handshake-required");
    };
    let Some(auth) = request.auth.as_ref() else {
        return Err("bridge-auth-required");
    };
    if auth.parent_pid != binding.parent_pid
        || auth.parent_start_marker != binding.parent_start_marker
        || auth.child_pid != binding.child_pid
        || auth.child_start_marker != binding.child_start_marker
        || auth.project_root != binding.project_root
        || auth.app_state_root != binding.app_state_root
        || auth.process_generation != binding.process_generation
    {
        return Err("bridge-binding-mismatch");
    }
    let expected_sequence = state
        .next_authenticated_sequence
        .checked_add(1)
        .ok_or("bridge-sequence-overflow")?;
    if auth.sequence != expected_sequence {
        return Err("bridge-sequence-mismatch");
    }
    if auth.operation_id.is_empty()
        || auth.operation_id.len() > MAX_BRIDGE_IDENTIFIER_BYTES
        || auth.fingerprint.len() != 64
        || !auth
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || auth.auth_tag.len() != 64
        || !auth.auth_tag.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid-bridge-request-auth");
    }
    let expected_tag = bridge_request_tag(&binding.session_secret, request, auth);
    if !constant_time_text_equal(&expected_tag, &auth.auth_tag) {
        return Err("bridge-authentication-failed");
    }
    state.next_authenticated_sequence = expected_sequence;
    Ok(())
}

pub(super) fn bridge_request_tag(
    secret: &str,
    request: &Request,
    auth: &BridgeRequestAuth,
) -> String {
    let operation_id = &auth.operation_id;
    let fingerprint = &auth.fingerprint;
    let params_digest = canonical_params_digest(&request.params);
    let material = format!(
        "unpin.desktop.bridge.request.v1\0{secret}\0{}\0{}\0{}\0{operation_id}\0{fingerprint}\0{params_digest}",
        auth.sequence, request.id, request.method,
    );
    unpin_core::sha256_digest(material.as_bytes())
}

pub(super) fn canonical_params_digest(params: &Value) -> String {
    pub(super) fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.clone(), canonicalize(value)))
                        .collect(),
                )
            }
            Value::Array(array) => Value::Array(array.iter().map(canonicalize).collect()),
            value => value.clone(),
        }
    }

    let canonical = canonicalize(params);
    let encoded = serde_json::to_vec(&canonical).expect("bridge params are JSON");
    unpin_core::sha256_digest(&encoded)
}

pub(super) fn constant_time_text_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(super) fn handle_request(state: &mut DesktopBridgeState, request: Request) -> Value {
    prune_expired_reviewed_plans(state);
    let result = if request.method == METHOD_HANDSHAKE {
        handle_handshake(state, &request.params)
    } else if let Err(code) = authenticate_request(state, &request) {
        Err(code)
    } else {
        match request.method.as_str() {
            METHOD_SNAPSHOT => snapshot_response(&state.context),
            METHOD_GROUP_PLAN => plan_group(state, &request.params),
            METHOD_GROUP_APPROVE => approve_group(state, &request.params),
            METHOD_GROUP_APPLY => apply_group(state, &request.params),
            METHOD_GROUP_DISCARD => discard_group(state, &request.params),
            METHOD_AGENT_PLUGIN_INSPECT => inspect_agent_plugin(state, &request.params),
            METHOD_AGENT_PLUGIN_PLAN => plan_agent_plugin(state, &request.params),
            METHOD_AGENT_PLUGIN_APPROVE => approve_agent_plugin(state, &request.params),
            METHOD_AGENT_PLUGIN_APPLY => apply_agent_plugin(state, &request.params),
            METHOD_AGENT_PLUGIN_DISCARD => discard_agent_plugin(state, &request.params),
            METHOD_GROUP_DEFINITION_PLAN => plan_definition_change(state, &request.params),
            METHOD_GROUP_DEFINITION_APPLY => apply_definition_change(state, &request.params),
            METHOD_GROUP_DEFINITION_DISCARD => discard_definition_change(state, &request.params),
            METHOD_GROUP_DEFINITION_HISTORY => definition_history(&state.context, &request.params),
            METHOD_RECOVERY_SNAPSHOT => recovery_snapshot_response(&state.context),
            METHOD_RESTORE_PLAN => plan_restore(state, &request.params),
            METHOD_RESTORE_APPROVE => approve_restore(state, &request.params),
            METHOD_RESTORE_APPLY => apply_restore(state, &request.params),
            METHOD_RESTORE_DISCARD => discard_restore(state, &request.params),
            METHOD_WORKFLOW_COMPOSE => compose_workflow(state, &request.params),
            METHOD_WORKFLOW_VALIDATE => validate_workflow(state, &request.params),
            METHOD_WORKFLOW_PROPOSE => propose_workflow(state, &request.params),
            METHOD_WORKFLOW_LAUNCH => launch_workflow(state, &request.params),
            METHOD_WORKFLOW_TRANSITION => transition_workflow(state, &request.params),
            METHOD_WORKFLOW_OBSERVE => observe_workflow(state, &request.params),
            METHOD_WORKFLOW_CANCEL => cancel_workflow_transition(state, &request.params),
            METHOD_WORKFLOW_STATUS => workflow_status(state),
            METHOD_WORKFLOW_RECOVERY => workflow_recovery(state),
            METHOD_SHUTDOWN => Ok(json!({"shutdown": true})),
            _ => Err("unknown-method"),
        }
    };
    match result {
        Ok(result) => json!({
            "version": PROTOCOL_VERSION,
            "id": request.id,
            "result": result,
        }),
        Err(code) => error_response(Some(&request.id), code),
    }
}

pub(super) fn require_only_params(params: &Value, allowed: &[&str]) -> Result<(), &'static str> {
    let object = params.as_object().ok_or("invalid-params")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unknown-parameter");
    }
    Ok(())
}

pub(super) fn required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1_024)
        .ok_or("invalid-params")
}

pub(super) fn optional_bounded_string<'a>(
    params: &'a Value,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 1_024)
            .map(Some)
            .ok_or("invalid-params"),
    }
}

pub(super) fn group_access_context(
    context: &DesktopBridgeContext,
) -> Result<GroupAccessContext, &'static str> {
    GroupAccessContext::from_config(&context.config, &context.discovery_roots, None, None)
        .map_err(|_| "group-context-unavailable")
}

pub(super) fn group_planner(context: &DesktopBridgeContext) -> Result<GroupPlanner, &'static str> {
    Ok(GroupPlanner::new(group_resolver(context)?))
}

pub(super) fn group_resolver(
    context: &DesktopBridgeContext,
) -> Result<GroupResolver, &'static str> {
    let group_context = group_access_context(context)?;
    Ok(GroupResolver::new(
        group_context.clone(),
        PersonalGroupStore::new(group_context.clone()),
        RepositoryGroupStore::new(group_context),
    ))
}

pub(super) fn group_controller(
    context: &DesktopBridgeContext,
) -> Result<GroupController, &'static str> {
    let backup_key = backup_authentication_key(context)?;
    let session_key = session_authority_key(context)?;
    controller_with_keys(context, backup_key, session_key)
}

pub(super) fn controller_with_keys(
    context: &DesktopBridgeContext,
    backup_key: BackupAuthenticationKey,
    session_key: SessionAuthorityKey,
) -> Result<GroupController, &'static str> {
    Ok(GroupController::new(
        group_planner(context)?,
        backup_key,
        session_key,
    ))
}

pub(super) fn approval_context(
    context: &DesktopBridgeContext,
) -> Result<ControlApprovalContext, &'static str> {
    let group_context = group_access_context(context)?;
    control_approval_context(&group_context)
}

pub(super) fn control_approval_context(
    group_context: &GroupAccessContext,
) -> Result<ControlApprovalContext, &'static str> {
    ControlApprovalContext::new(
        group_context.repository_key(),
        group_context.workspace_key(),
    )
    .map_err(|_| "approval-context-unavailable")
}

pub(super) fn backup_authentication_key(
    context: &DesktopBridgeContext,
) -> Result<BackupAuthenticationKey, &'static str> {
    credentials::resolve_backup_authentication_key(
        context.fixture_mode,
        &context.config.app_state_root,
    )
    .map_err(|_| "backup-authentication-unavailable")?
    .ok_or("backup-authentication-unavailable")
}

pub(super) fn session_authority_key(
    context: &DesktopBridgeContext,
) -> Result<SessionAuthorityKey, &'static str> {
    credentials::resolve_session_authority_key(context.fixture_mode, &context.config.app_state_root)
        .map_err(|_| "session-authority-unavailable")?
        .ok_or("session-authority-unavailable")
}

pub(super) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

pub(super) fn error_response(id: Option<&str>, code: &str) -> Value {
    json!({
        "version": PROTOCOL_VERSION,
        "id": id,
        "error": {"code": code},
    })
}

pub(super) fn write_response(output: &mut impl Write, response: &Value) -> Result<(), String> {
    let encoded = serde_json::to_vec(response).map_err(|_| "response-serialization-failed")?;
    if encoded.len() > MAX_FRAME_BYTES {
        let fallback = serde_json::to_vec(&error_response(
            response.get("id").and_then(Value::as_str),
            "response-too-large",
        ))
        .map_err(|_| "response-serialization-failed")?;
        output
            .write_all(&fallback)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush())
            .map_err(|error| error.to_string())
    } else {
        output
            .write_all(&encoded)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameStatus {
    Complete,
    Oversized,
}

pub(super) fn read_frame(
    input: &mut impl BufRead,
    frame: &mut Vec<u8>,
) -> io::Result<Option<FrameStatus>> {
    frame.clear();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok((!frame.is_empty()).then_some(FrameStatus::Complete));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if frame.len().saturating_add(take) > MAX_FRAME_BYTES {
            input.consume(take);
            if newline.is_none() {
                discard_to_newline(input)?;
            }
            return Ok(Some(FrameStatus::Oversized));
        }
        frame.extend_from_slice(&available[..take]);
        input.consume(take);
        if newline.is_some() {
            if frame.last() == Some(&b'\n') {
                frame.pop();
            }
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(FrameStatus::Complete));
        }
    }
}

pub(super) fn discard_to_newline(input: &mut impl BufRead) -> io::Result<()> {
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(index) = available.iter().position(|byte| *byte == b'\n') {
            input.consume(index + 1);
            return Ok(());
        }
        let length = available.len();
        input.consume(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge_test_context(root: &std::path::Path) -> DesktopBridgeContext {
        let config = UnpinConfig {
            version: 1,
            app_state_root: root.join("state"),
            cursor_root: root.join("cursor"),
            project_root: root.join("project"),
            config_paths: unpin_core::config::UnpinConfigPaths {
                user_config_path: root.join("user-config.json"),
                project_config_path: root.join("project-config.json"),
            },
        };
        DesktopBridgeContext::new(config, DiscoveryRoots::fixture_root(root), true)
    }

    #[test]
    fn failed_discovery_change_invalidates_cached_discovery() {
        let temporary = tempfile::tempdir().expect("temporary bridge root");
        let context = bridge_test_context(temporary.path());
        let cached = cached_discovery_arc(&context).expect("initial discovery");

        let result = invalidate_after_discovery_change(&context, Err::<(), _>("apply-failed"));

        assert_eq!(result, Err("apply-failed"));
        let refreshed = cached_discovery_arc(&context).expect("refreshed discovery");
        assert!(!std::sync::Arc::ptr_eq(&cached, &refreshed));
    }

    fn agent_plugin_fixture_context(root: &std::path::Path) -> DesktopBridgeContext {
        let source_fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CLI crate has a workspace crates parent")
            .join("unpin-core")
            .join("tests")
            .join("fixtures");
        let fixture_root = root.join("fixtures");
        copy_test_directory(&source_fixture_root, &fixture_root);
        let app_state_root = root.join("state");
        let project_root = root.join("project");
        std::fs::create_dir_all(&app_state_root).expect("temporary bridge app state");
        std::fs::create_dir_all(project_root.join(".git")).expect("temporary bridge project");
        let config = UnpinConfig {
            version: 1,
            app_state_root,
            cursor_root: root.join("cursor"),
            project_root,
            config_paths: unpin_core::config::UnpinConfigPaths {
                user_config_path: root.join("user-config.json"),
                project_config_path: root.join("project-config.json"),
            },
        };
        DesktopBridgeContext::new(config, DiscoveryRoots::fixture_root(fixture_root), true)
    }

    fn copy_test_directory(source: &std::path::Path, destination: &std::path::Path) {
        std::fs::create_dir_all(destination).expect("create fixture destination");
        for entry in std::fs::read_dir(source).expect("read fixture source") {
            let entry = entry.expect("read fixture entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if source_path.is_dir() {
                copy_test_directory(&source_path, &destination_path);
            } else {
                std::fs::copy(&source_path, &destination_path).expect("copy fixture file");
            }
        }
    }

    #[test]
    fn fixture_handshake_rejects_roots_outside_private_temporary_storage() {
        let temporary = tempfile::tempdir().expect("temporary fixture root");
        let mut context = bridge_test_context(temporary.path());
        context.config.project_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let app_state_root = context.config.app_state_root.clone();
        let mut state = bridge_state(context);
        let encoded = test_handshake_request("handshake", &state.context);
        let handshake = parse_request(&encoded)
            .unwrap_or_else(|error| panic!("test handshake request failed: {}", error.code));

        assert_eq!(
            handle_request(&mut state, handshake)["error"]["code"],
            "fixture-write-sandbox-blocked"
        );
        assert!(!app_state_root.exists());
        assert!(state.binding.is_none());
    }

    fn bridge_state(context: DesktopBridgeContext) -> DesktopBridgeState {
        DesktopBridgeState {
            context,
            binding: None,
            next_authenticated_sequence: 0,
            reviewed_groups: Default::default(),
            reviewed_agent_plugins: Default::default(),
            reviewed_restores: Default::default(),
            reviewed_definitions: Default::default(),
            workflows: Default::default(),
            reviewed_workflow_launches: Default::default(),
            workflow_session_id: None,
            next_definition_plan_id: 0,
        }
    }

    #[test]
    fn read_only_discovery_cache_reuses_snapshot_until_refresh() {
        let fixture_root = tempfile::tempdir().expect("fixture root");
        let context = agent_plugin_fixture_context(fixture_root.path());
        let first = cached_discovery_arc(&context).expect("first cached discovery");
        let second = cached_discovery_arc(&context).expect("second cached discovery");
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        let refreshed = fresh_discovery_arc(&context).expect("fresh discovery");
        assert!(!std::sync::Arc::ptr_eq(&first, &refreshed));
        let after_refresh = cached_discovery_arc(&context).expect("cached after refresh");
        assert!(std::sync::Arc::ptr_eq(&refreshed, &after_refresh));
        invalidate_discovery(&context);
        let after_invalidate = cached_discovery_arc(&context).expect("cached after invalidate");
        assert!(!std::sync::Arc::ptr_eq(&refreshed, &after_invalidate));
    }

    fn create_test_workflow_session(context: &DesktopBridgeContext, suffix: &str) {
        let authority_key = SessionAuthorityKey::new(
            unpin_core::fixture::fixture_credential_key(
                &context.config.app_state_root,
                unpin_core::fixture::FixtureCredentialPurpose::SessionAuthority,
            )
            .expect("fixture session authority"),
        );
        let manager =
            SessionManager::with_authority_key(&context.config.app_state_root, authority_key);
        let identity = context
            .config
            .workspace_identity()
            .expect("workspace identity");
        let now = unix_now();
        let request = unpin_core::sessions::BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: identity.repository_key,
            workspace_key: identity.workspace_key,
            workspace_revision: identity.diagnostics.head,
            exposure: PinnedExposure {
                revision: "a".repeat(64),
                profile: PinnedProfile::None,
                capability_locks: None,
            },
            process: unpin_core::sessions::ProcessEvidence {
                pid: std::process::id(),
                start_marker: format!("desktop-test-{suffix}"),
            },
            connection_scope_id: format!("desktop-test-scope-{suffix}"),
            isolation: unpin_core::sessions::IsolationLevel::Strict,
            coverage: unpin_core::sessions::CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::from([format!("desktop-test-resource-{suffix}")]),
            lease_expires_at_unix: now + 3_600,
        };
        let authority = manager
            .prepare_bootstrap(request.clone(), now)
            .expect("prepare workflow session");
        let claimed = manager
            .claim_bootstrap(
                &authority,
                &unpin_core::sessions::ConnectionClaim {
                    connection_owner_id: format!("desktop-test-owner-{suffix}"),
                    provider: request.provider,
                    repository_key: request.repository_key,
                    workspace_key: request.workspace_key,
                    process: request.process,
                    connection_scope_id: request.connection_scope_id,
                },
                now + 1,
            )
            .expect("claim workflow session");
        let digest = "b".repeat(64);
        manager
            .pin_workflow(
                &claimed.handle,
                &claimed.lease.revision,
                unpin_core::sessions::PinnedWorkflowEnvelope {
                    workflow_id: format!("delivery-{suffix}"),
                    workflow_revision: "c".repeat(64),
                    baseline_profile_id: "baseline".to_string(),
                    baseline_profile_digest: "d".repeat(64),
                    profile_revisions: BTreeMap::from([("planning".to_string(), digest.clone())]),
                    active_mode: "planning".to_string(),
                    active_effective_profile_digest: digest.clone(),
                    maximum_envelope_digest: "e".repeat(64),
                    capability_lock_digest: "f".repeat(64),
                    catalog_revision: "1".repeat(64),
                    proposal_id: format!("proposal-{suffix}"),
                    proposal_fingerprint: "2".repeat(64),
                    state_sequence: 1,
                    sealed_generation: 1,
                },
                PinnedExposure {
                    revision: digest.clone(),
                    profile: PinnedProfile::Profile {
                        profile_id: format!("delivery-{suffix}.planning"),
                        profile_digest: digest,
                        origin_scope: ProfileSourceScope::Session,
                        definition_digest: "c".repeat(64),
                    },
                    capability_locks: None,
                },
                now + 2,
            )
            .expect("pin workflow");
    }

    #[test]
    fn workflow_status_reports_observed_active_mode_while_transition_is_pending() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let root = std::fs::canonicalize(temporary.path()).expect("canonical temporary root");
        let context = bridge_test_context(&root);
        std::fs::create_dir_all(&context.config.project_root).expect("temporary workflow project");
        let authority_key = SessionAuthorityKey::new(
            unpin_core::fixture::fixture_credential_key(
                &context.config.app_state_root,
                unpin_core::fixture::FixtureCredentialPurpose::SessionAuthority,
            )
            .expect("fixture session authority"),
        );
        let manager =
            SessionManager::with_authority_key(&context.config.app_state_root, authority_key);
        create_test_workflow_session(&context, "pending-status");
        let current = manager
            .list()
            .expect("list workflow sessions")
            .into_iter()
            .next()
            .expect("workflow session");
        let mut staged = current;
        staged
            .lease
            .workflow
            .as_mut()
            .expect("pinned workflow")
            .active_mode = "implementation".to_string();
        staged.lease.desired_exposure.revision = "3".repeat(64);
        staged.lease.admission_open = false;

        let status = workflow_status_value(Some(&staged));
        assert_eq!(status["activeMode"], "planning");
        assert_eq!(status["observedMode"], "planning");
        assert_eq!(status["desiredMode"], "implementation");
    }

    fn encoded_request(id: &str, method: &str, params: Option<Value>) -> Vec<u8> {
        let mut request = serde_json::Map::new();
        request.insert("version".to_string(), json!(PROTOCOL_VERSION));
        request.insert("id".to_string(), json!(id));
        request.insert("method".to_string(), json!(method));
        if let Some(params) = params {
            request.insert("params".to_string(), params);
        }
        serde_json::to_vec(&Value::Object(request)).expect("encode bridge request")
    }

    fn test_handshake_request(id: &str, context: &DesktopBridgeContext) -> Vec<u8> {
        encoded_request(
            id,
            METHOD_HANDSHAKE,
            Some(json!({
                "sessionSecret": "11".repeat(32),
                "parentPid": current_parent_process_id(),
                "parentStartMarker": "test-parent",
                "childPid": std::process::id(),
                "processGeneration": "test-generation",
                "projectRoot": context.config.project_root,
                "appStateRoot": context.config.app_state_root,
            })),
        )
    }

    fn parsed_request(id: &str, method: &str, params: Value) -> Request {
        parse_request(&encoded_request(id, method, Some(params)))
            .unwrap_or_else(|error| panic!("test bridge request failed: {}", error.code))
    }

    fn authenticate_test_request(state: &DesktopBridgeState, request: &mut Request, sequence: u64) {
        let binding = state.binding.as_ref().expect("test bridge binding");
        let operation_id = request
            .params
            .get("operationId")
            .or_else(|| request.params.get("proposalId"))
            .and_then(Value::as_str)
            .unwrap_or(&request.id)
            .to_string();
        let fallback_fingerprint =
            unpin_core::sha256_digest(&serde_json::to_vec(&request.params).expect("test params"));
        let fingerprint = request
            .params
            .get("planFingerprint")
            .or_else(|| request.params.get("proposalFingerprint"))
            .or_else(|| request.params.get("operationFingerprint"))
            .and_then(Value::as_str)
            .unwrap_or(&fallback_fingerprint)
            .to_string();
        let mut auth = BridgeRequestAuth {
            parent_pid: binding.parent_pid,
            parent_start_marker: binding.parent_start_marker.clone(),
            child_pid: binding.child_pid,
            child_start_marker: binding.child_start_marker.clone(),
            project_root: binding.project_root.clone(),
            app_state_root: binding.app_state_root.clone(),
            process_generation: binding.process_generation.clone(),
            sequence,
            operation_id,
            fingerprint,
            auth_tag: String::new(),
        };
        auth.auth_tag = bridge_request_tag(&binding.session_secret, request, &auth);
        request.auth = Some(auth);
    }

    fn complete_test_handshake(state: &mut DesktopBridgeState) {
        let encoded = test_handshake_request("handshake", &state.context);
        let handshake = parse_request(&encoded)
            .unwrap_or_else(|error| panic!("test handshake request failed: {}", error.code));
        let response = handle_request(state, handshake);
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn authenticated_requests_require_binding_and_monotonic_sequence() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let context = agent_plugin_fixture_context(temporary.path());
        let mut state = bridge_state(context);

        let pre_handshake = parsed_request("snapshot-pre", METHOD_SNAPSHOT, json!({}));
        assert_eq!(
            handle_request(&mut state, pre_handshake)["error"]["code"],
            "bridge-handshake-required"
        );

        complete_test_handshake(&mut state);
        let unauthenticated = parsed_request("snapshot-no-auth", METHOD_SNAPSHOT, json!({}));
        assert_eq!(
            handle_request(&mut state, unauthenticated)["error"]["code"],
            "bridge-auth-required"
        );

        let mut first = parsed_request("snapshot-1", METHOD_SNAPSHOT, json!({}));
        authenticate_test_request(&state, &mut first, 1);
        assert!(handle_request(&mut state, first).get("result").is_some());

        let mut replay = parsed_request("snapshot-replay", METHOD_SNAPSHOT, json!({}));
        authenticate_test_request(&state, &mut replay, 1);
        assert_eq!(
            handle_request(&mut state, replay)["error"]["code"],
            "bridge-sequence-mismatch"
        );

        let mut skipped = parsed_request("snapshot-skipped", METHOD_SNAPSHOT, json!({}));
        authenticate_test_request(&state, &mut skipped, 3);
        assert_eq!(
            handle_request(&mut state, skipped)["error"]["code"],
            "bridge-sequence-mismatch"
        );

        let mut second = parsed_request("snapshot-2", METHOD_SNAPSHOT, json!({}));
        authenticate_test_request(&state, &mut second, 2);
        assert!(handle_request(&mut state, second).get("result").is_some());
    }

    #[test]
    fn authenticated_requests_bind_canonical_parameters() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let context = agent_plugin_fixture_context(temporary.path());
        let mut state = bridge_state(context);
        complete_test_handshake(&mut state);

        let mut request = parsed_request(
            "snapshot-tamper",
            METHOD_SNAPSHOT,
            json!({"nested": {"before": true}}),
        );
        authenticate_test_request(&state, &mut request, 1);
        request.params["nested"]["before"] = json!(false);
        assert_eq!(
            handle_request(&mut state, request)["error"]["code"],
            "bridge-authentication-failed"
        );
    }

    #[test]
    fn reconnect_requires_explicit_selection_for_multiple_matching_workflow_sessions() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let root =
            std::fs::canonicalize(temporary.path()).expect("canonical temporary bridge state");
        let context = agent_plugin_fixture_context(&root);
        create_test_workflow_session(&context, "one");
        create_test_workflow_session(&context, "two");
        let mut state = bridge_state(context);
        complete_test_handshake(&mut state);
        let mut request = parsed_request("workflow-status", METHOD_WORKFLOW_STATUS, json!({}));
        authenticate_test_request(&state, &mut request, 1);

        assert_eq!(
            handle_request(&mut state, request)["error"]["code"],
            "workflow-session-selection-required"
        );
        assert!(state.workflow_session_id.is_none());
    }

    #[test]
    fn authenticated_requests_reject_each_process_binding_mismatch() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let context = agent_plugin_fixture_context(temporary.path());
        let mut state = bridge_state(context);
        complete_test_handshake(&mut state);

        for field in [
            "parentPid",
            "parentStartMarker",
            "childPid",
            "childStartMarker",
            "projectRoot",
            "appStateRoot",
            "processGeneration",
        ] {
            let mut request =
                parsed_request(&format!("binding-{field}"), METHOD_SNAPSHOT, json!({}));
            authenticate_test_request(&state, &mut request, 1);
            let auth = request.auth.as_mut().expect("test auth");
            match field {
                "parentPid" => auth.parent_pid = auth.parent_pid.saturating_add(1),
                "parentStartMarker" => auth.parent_start_marker.push_str("-other"),
                "childPid" => auth.child_pid = auth.child_pid.saturating_add(1),
                "childStartMarker" => auth.child_start_marker.push_str("-other"),
                "projectRoot" => auth.project_root.push_str("-other"),
                "appStateRoot" => auth.app_state_root.push_str("-other"),
                "processGeneration" => auth.process_generation.push_str("-other"),
                _ => unreachable!(),
            }
            assert_eq!(
                handle_request(&mut state, request)["error"]["code"],
                "bridge-binding-mismatch",
                "binding field {field} must be authenticated"
            );
        }
    }

    #[test]
    fn authenticated_workflow_requests_compose_validate_and_propose() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let root =
            std::fs::canonicalize(temporary.path()).expect("canonical temporary bridge state");
        let context = agent_plugin_fixture_context(&root);
        unpin_core::profiles::ProfileStore::new(&context.config.app_state_root)
            .save_global_definition(
                &unpin_core::profiles::ProfileDefinition {
                    version: unpin_core::profiles::PROFILE_DEFINITION_VERSION,
                    id: "baseline".to_string(),
                    display_name: "Baseline".to_string(),
                    description: None,
                    members: Vec::new(),
                    provider_members: Default::default(),
                    supported_providers: Default::default(),
                },
                None,
                OwnerGeneration::new("desktop-workflow-test", 1).expect("profile owner"),
            )
            .expect("global baseline profile");
        let mut state = bridge_state(context);
        complete_test_handshake(&mut state);

        let mut compose = parsed_request(
            "workflow-compose",
            METHOD_WORKFLOW_COMPOSE,
            json!({
                "workflowId": "delivery",
                "displayName": "Delivery",
                "description": "Plan and implement",
                "provider": "codex",
                "baselineProfileId": "baseline",
                "entryMode": "planning",
                "modes": [{"name": "planning", "profileId": "baseline"}],
            }),
        );
        authenticate_test_request(&state, &mut compose, 1);
        let composed = handle_request(&mut state, compose);
        let workflow_revision = composed["result"]["workflowRevision"]
            .as_str()
            .expect("workflow revision")
            .to_string();

        let mut validate = parsed_request(
            "workflow-validate",
            METHOD_WORKFLOW_VALIDATE,
            json!({
                "workflowId": "delivery",
                "provider": "codex",
                "workflowRevision": workflow_revision,
            }),
        );
        authenticate_test_request(&state, &mut validate, 2);
        let validated = handle_request(&mut state, validate);
        assert_eq!(
            validated["result"]["status"], "valid",
            "workflow validation response: {validated}"
        );
        assert_eq!(validated["result"]["provider"], "codex");

        let private_prompt = "Implement the private customer task";
        let mut propose = parsed_request(
            "workflow-propose",
            METHOD_WORKFLOW_PROPOSE,
            json!({"prompt": private_prompt, "provider": "codex"}),
        );
        authenticate_test_request(&state, &mut propose, 3);
        let proposed = handle_request(&mut state, propose);
        assert_eq!(proposed["result"]["status"], "proposed");
        assert_eq!(proposed["result"]["proposal"]["workflowId"], "delivery");
        assert!(proposed["result"]["proposal"]["promptDigest"].is_string());
        assert!(
            !serde_json::to_string(&proposed)
                .expect("proposal response")
                .contains(private_prompt)
        );
    }

    #[test]
    fn parser_rejects_malformed_contracts_with_stable_codes() {
        let too_long_id = "i".repeat(MAX_REQUEST_ID_BYTES + 1);
        let too_long_method = "m".repeat(129);
        let cases = vec![
            ("malformed-json", b"{".to_vec(), None, "malformed-request"),
            (
                "unknown-field",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "unknown-field",
                    "method": METHOD_HANDSHAKE,
                    "extra": true,
                }))
                .expect("unknown field request"),
                Some("unknown-field"),
                "unknown-request-field",
            ),
            (
                "missing-id",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "method": METHOD_HANDSHAKE,
                }))
                .expect("missing id request"),
                None,
                "missing-request-id",
            ),
            (
                "empty-id",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "",
                    "method": METHOD_HANDSHAKE,
                }))
                .expect("empty id request"),
                Some(""),
                "invalid-request-id",
            ),
            (
                "control-id",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "bad\nrequest",
                    "method": METHOD_HANDSHAKE,
                }))
                .expect("control id request"),
                Some("bad\nrequest"),
                "invalid-request-id",
            ),
            (
                "too-long-id",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": too_long_id.clone(),
                    "method": METHOD_HANDSHAKE,
                }))
                .expect("long id request"),
                Some(too_long_id.as_str()),
                "invalid-request-id",
            ),
            (
                "unsupported-version",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION + 1,
                    "id": "unsupported-version",
                    "method": METHOD_HANDSHAKE,
                }))
                .expect("unsupported version request"),
                Some("unsupported-version"),
                "unsupported-protocol-version",
            ),
            (
                "missing-method",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "missing-method",
                }))
                .expect("missing method request"),
                Some("missing-method"),
                "invalid-method",
            ),
            (
                "empty-method",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "empty-method",
                    "method": "",
                }))
                .expect("empty method request"),
                Some("empty-method"),
                "invalid-method",
            ),
            (
                "too-long-method",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "too-long-method",
                    "method": too_long_method,
                }))
                .expect("long method request"),
                Some("too-long-method"),
                "invalid-method",
            ),
            (
                "invalid-params",
                serde_json::to_vec(&json!({
                    "version": PROTOCOL_VERSION,
                    "id": "invalid-params",
                    "method": METHOD_HANDSHAKE,
                    "params": [],
                }))
                .expect("invalid params request"),
                Some("invalid-params"),
                "invalid-params",
            ),
        ];

        for (name, frame, expected_id, expected_code) in cases {
            let error = match parse_request(&frame) {
                Ok(_) => panic!("{name} should be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.id.as_deref(), expected_id, "{name} id");
            assert_eq!(error.code, expected_code, "{name} code");
        }
    }

    #[test]
    fn stdio_contract_errors_recover_on_the_following_valid_request() {
        let cases = vec![
            (
                "malformed-json",
                vec![b"{".to_vec()],
                None,
                "malformed-request",
                0,
            ),
            (
                "unknown-field",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "id": "unknown-field",
                        "method": METHOD_HANDSHAKE,
                        "extra": true,
                    }))
                    .expect("unknown field request"),
                ],
                Some("unknown-field"),
                "unknown-request-field",
                0,
            ),
            (
                "missing-id",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "method": METHOD_HANDSHAKE,
                    }))
                    .expect("missing id request"),
                ],
                None,
                "missing-request-id",
                0,
            ),
            (
                "invalid-id",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "id": "",
                        "method": METHOD_HANDSHAKE,
                    }))
                    .expect("invalid id request"),
                ],
                Some(""),
                "invalid-request-id",
                0,
            ),
            (
                "unsupported-version",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION + 1,
                        "id": "unsupported-version",
                        "method": METHOD_HANDSHAKE,
                    }))
                    .expect("unsupported version request"),
                ],
                Some("unsupported-version"),
                "unsupported-protocol-version",
                0,
            ),
            (
                "missing-method",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "id": "missing-method",
                    }))
                    .expect("missing method request"),
                ],
                Some("missing-method"),
                "invalid-method",
                0,
            ),
            (
                "invalid-method",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "id": "invalid-method",
                        "method": "",
                    }))
                    .expect("invalid method request"),
                ],
                Some("invalid-method"),
                "invalid-method",
                0,
            ),
            (
                "bridge-handshake-required",
                vec![encoded_request("unknown-method", "unknown.method", None)],
                Some("unknown-method"),
                "bridge-handshake-required",
                0,
            ),
            (
                "invalid-params",
                vec![
                    serde_json::to_vec(&json!({
                        "version": PROTOCOL_VERSION,
                        "id": "invalid-params",
                        "method": METHOD_HANDSHAKE,
                        "params": [],
                    }))
                    .expect("invalid params request"),
                ],
                Some("invalid-params"),
                "invalid-params",
                0,
            ),
            (
                "duplicate-id",
                vec![
                    encoded_request("duplicate-id", METHOD_HANDSHAKE, None),
                    encoded_request("duplicate-id", METHOD_HANDSHAKE, None),
                ],
                Some("duplicate-id"),
                "duplicate-request-id",
                1,
            ),
        ];

        for (name, prefix, expected_id, expected_code, error_index) in cases {
            let temporary = tempfile::tempdir().expect("temporary bridge state");
            let mut input = Vec::new();
            for frame in prefix {
                input.extend_from_slice(&frame);
                input.push(b'\n');
            }
            let context = bridge_test_context(temporary.path());
            let recovery = test_handshake_request("recovery", &context);
            input.extend_from_slice(&recovery);
            input.push(b'\n');
            input.extend_from_slice(&encoded_request("shutdown", METHOD_SHUTDOWN, None));
            input.push(b'\n');
            let mut output = Vec::new();
            run_with_io(context, input.as_slice(), &mut output).expect(name);
            let output = String::from_utf8(output).expect("bridge UTF-8 responses");
            let responses = output
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).expect("bridge response JSON"))
                .collect::<Vec<_>>();
            assert_eq!(
                responses[error_index]["id"].as_str(),
                expected_id,
                "{name} error id"
            );
            assert_eq!(
                responses[error_index]["error"]["code"], expected_code,
                "{name} error code"
            );
            let recovery_index = error_index + 1;
            assert_eq!(
                responses[recovery_index]["id"], "recovery",
                "{name} recovery id"
            );
            assert_eq!(
                responses[recovery_index]["result"]["protocolVersion"], PROTOCOL_VERSION,
                "{name} recovery result"
            );
            assert_eq!(
                responses.last().expect("shutdown response")["id"],
                "shutdown"
            );
        }
    }

    #[test]
    fn request_ids_are_bounded_without_hiding_duplicates() {
        let mut seen = RecentRequestIds::default();
        record_request_id(&mut seen, "already-seen").expect("first request id");
        assert_eq!(
            record_request_id(&mut seen, "already-seen"),
            Err("duplicate-request-id")
        );
        for index in 1..MAX_SEEN_REQUEST_IDS {
            record_request_id(&mut seen, &format!("request-{index}"))
                .expect("request id within limit");
        }
        record_request_id(&mut seen, "one-too-many")
            .expect("oldest request id is evicted from the replay window");
        assert_eq!(
            record_request_id(&mut seen, "request-1"),
            Err("duplicate-request-id")
        );
        record_request_id(&mut seen, "already-seen")
            .expect("evicted request ids can be reused after the replay window");
    }

    #[test]
    fn reviewed_control_plans_allow_replacing_existing_operations_at_capacity() {
        let mut plans = BTreeMap::new();
        for index in 0..MAX_REVIEWED_CONTROL_PLANS {
            plans.insert(format!("operation-{index}"), ());
        }
        assert!(has_reviewed_plan_capacity(&plans, "operation-0"));
        assert!(!has_reviewed_plan_capacity(&plans, "new-operation"));
    }

    #[test]
    fn expired_reviewed_plans_are_not_current() {
        assert!(!reviewed_plan_is_expired(
            100,
            100 + REVIEWED_PLAN_TTL_SECONDS
        ));
        assert!(reviewed_plan_is_expired(
            100,
            101 + REVIEWED_PLAN_TTL_SECONDS
        ));
    }

    #[test]
    fn agent_plugin_capabilities_and_snapshot_are_additive_and_path_free() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let context = agent_plugin_fixture_context(temporary.path());

        let handshake = handshake_response();
        for capability in [
            METHOD_AGENT_PLUGIN_INSPECT,
            METHOD_AGENT_PLUGIN_PLAN,
            METHOD_AGENT_PLUGIN_APPROVE,
            METHOD_AGENT_PLUGIN_APPLY,
            METHOD_AGENT_PLUGIN_DISCARD,
        ] {
            assert!(
                handshake["capabilities"]
                    .as_array()
                    .expect("bridge capabilities")
                    .contains(&json!(capability)),
                "missing capability {capability}",
            );
        }

        let snapshot = snapshot_response(&context).expect("package snapshot");
        assert_eq!(snapshot["agentPluginInventoryComplete"], true);
        let packages = snapshot["agentPlugins"]
            .as_array()
            .expect("agent plugin package collection");
        assert!(!packages.is_empty(), "checked-in fixtures project packages");
        let encoded = serde_json::to_string(&packages).expect("package JSON");
        for forbidden in [
            "sourcePath",
            "statePath",
            "packageRoot",
            "package_root",
            "rawManifest",
            "sourceFingerprint",
            "description",
            "Review and context tools for agent workbenches.",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "snapshot leaked forbidden field {forbidden}: {encoded}",
            );
        }
        assert!(!encoded.contains(&temporary.path().to_string_lossy().into_owned()));

        let logical_id = packages[0]["logicalId"]
            .as_str()
            .expect("logical package id");
        let state = DesktopBridgeState::new(context);
        let inspected = inspect_agent_plugin(&state, &json!({"logicalId": logical_id}))
            .expect("agent plugin inspection");
        assert_eq!(inspected["package"]["logicalId"], logical_id);
    }

    #[test]
    fn agent_plugin_plan_redacts_bulk_internals_and_discard_invalidates_review() {
        let temporary = tempfile::tempdir().expect("temporary bridge state");
        let context = agent_plugin_fixture_context(temporary.path());
        let discovery = fresh_discovery(&context).expect("fresh discovery");
        let package = discovery
            .agent_plugins()
            .into_iter()
            .find(|package| package.name == "connector-kit")
            .expect("fixture connector package");
        let logical_id = package.logical_id.clone();
        let mut state = bridge_state(context);

        let planned = plan_agent_plugin(
            &mut state,
            &json!({
                "logicalId": logical_id.clone(),
                "target": "off",
                "reach": "selected",
                "selectedProvider": "codex",
            }),
        )
        .expect("selected-provider package plan");
        let plan = &planned["plan"];
        assert_eq!(plan["logicalId"], package.logical_id);
        assert_eq!(plan["name"], package.name);
        assert_eq!(plan["target"], "off");
        assert_eq!(plan["access"], "actionable");
        assert_eq!(plan["providerReach"]["selected"]["provider"], "codex");
        assert!(plan["review"]["included"].is_array());
        assert!(plan["review"]["noOp"].is_array());
        assert!(plan["review"]["blocked"].is_array());
        assert!(plan["review"]["reachExcluded"].is_array());
        assert!(plan["review"]["componentDiagnostics"].is_array());
        assert!(plan["counts"]["reachExcluded"].as_u64().unwrap_or_default() > 0);

        let encoded = serde_json::to_string(plan).expect("plan JSON");
        for forbidden in [
            "matched",
            "selector",
            "sourcePath",
            "statePath",
            "packageRoot",
            "sourceFingerprint",
            "operationDigest",
            "affectedResources",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "plan leaked bulk/provider internals {forbidden}: {encoded}",
            );
        }

        let operation_id = plan["operationId"].as_str().expect("operation id");
        let fingerprint = plan["planFingerprint"].as_str().expect("plan fingerprint");
        discard_agent_plugin(
            &mut state,
            &json!({
                "operationId": operation_id,
                "planFingerprint": fingerprint,
            }),
        )
        .expect("discard reviewed package plan");
        assert_eq!(
            discard_agent_plugin(
                &mut state,
                &json!({
                    "operationId": operation_id,
                    "planFingerprint": fingerprint,
                }),
            ),
            Err("agent-plugin-plan-unavailable"),
        );

        let all_planned = plan_agent_plugin(
            &mut state,
            &json!({
                "logicalId": logical_id,
                "target": "off",
                "reach": "all",
            }),
        )
        .expect("all-provider package plan");
        let all_plan = &all_planned["plan"];
        assert_eq!(all_plan["providerReach"], "all");
        assert_eq!(all_plan["counts"]["reachExcluded"], 0);
        assert!(
            all_plan["review"]["reachExcluded"]
                .as_array()
                .expect("all-provider reach exclusions")
                .is_empty()
        );
    }

    #[test]
    fn fixture_group_apply_requires_a_temporary_workspace() {
        let temporary = tempfile::tempdir().expect("temporary fixture root");
        let app_state_root = temporary.path().join("state");
        let workspace_root = temporary.path().join("workspace");
        let discovery_roots = DiscoveryRoots::fixture_root(temporary.path());
        assert!(
            require_fixture_group_write_sandbox(
                true,
                &app_state_root,
                &workspace_root,
                &discovery_roots,
            )
            .is_ok()
        );
        assert_eq!(
            require_fixture_group_write_sandbox(
                true,
                &app_state_root,
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
                &discovery_roots,
            ),
            Err("fixture-write-sandbox-blocked")
        );
    }

    #[test]
    fn fixture_group_apply_rejects_external_provider_roots() {
        let temporary = tempfile::tempdir().expect("temporary fixture root");
        let app_state_root = temporary.path().join("state");
        let workspace_root = temporary.path().join("workspace");
        let mut discovery_roots = DiscoveryRoots::fixture_root(temporary.path());
        discovery_roots.codex_global = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            require_fixture_group_write_sandbox(
                true,
                &app_state_root,
                &workspace_root,
                &discovery_roots,
            ),
            Err("fixture-write-sandbox-blocked")
        );
    }
}
