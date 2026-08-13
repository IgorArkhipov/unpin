use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsString,
    io::{self, BufRead, Write},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use unpin_core::{
    agent_plugins::{AgentPluginComponentDisposition, AgentPluginInstance, AgentPluginSummary},
    approval::ControlApprovalContext,
    catalog::Catalog,
    config::UnpinConfig,
    control::build_control_status,
    control_operation::ReachAwareOperationFamily,
    discovery::{DiscoveryItem, DiscoveryRoots, discover_all},
    groups::{
        GROUP_DEFINITION_OWNER_ID, GroupAccessContext, GroupController, GroupDefinitionV1,
        GroupMemberIdentity, GroupPlanDisposition, GroupPlanMode, GroupPlanner, GroupRef,
        GroupResolver, GroupRevision, GroupScope, GroupTargetState, GroupTogglePlan,
        MAX_GROUP_MEMBERS, PersonalGroupStore, RepositoryGroupStore,
        list_group_operation_inspections, list_group_operation_inspections_with_backup_index,
        validate_new_group_members,
    },
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
        WorkflowProposalV1, WorkflowReloadLimitation, WorkflowTransitionRequest,
    },
    state::atomic_json::OwnerGeneration,
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowDefinition, WorkflowModeDefinition, WorkflowStore,
        compile_workflow,
    },
};

use crate::{
    commands::{ProviderReachArg, toggle::durable_context},
    credentials,
    group_store::ScopedGroupStore,
    parse_provider_id, session_process,
};

pub(crate) const PROTOCOL_VERSION: u64 = 2;
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_SEEN_REQUEST_IDS: usize = 4_096;
const MAX_BRIDGE_IDENTIFIER_BYTES: usize = 256;
const MAX_REVIEWED_CONTROL_PLANS: usize = 32;
const MAX_REVIEWED_DEFINITION_PLANS: usize = 32;
const REVIEWED_PLAN_TTL_SECONDS: i64 = 15 * 60;
const METHOD_HANDSHAKE: &str = "handshake";
const METHOD_WORKFLOW_COMPOSE: &str = "workflow.compose";
const METHOD_WORKFLOW_VALIDATE: &str = "workflow.validate";
const METHOD_WORKFLOW_PROPOSE: &str = "workflow.propose";
const METHOD_WORKFLOW_LAUNCH: &str = "workflow.launch";
const METHOD_WORKFLOW_TRANSITION: &str = "workflow.transition";
const METHOD_WORKFLOW_OBSERVE: &str = "workflow.observe";
const METHOD_WORKFLOW_CANCEL: &str = "workflow.cancel-transition";
const METHOD_WORKFLOW_STATUS: &str = "workflow.status";
const METHOD_WORKFLOW_RECOVERY: &str = "workflow.recovery";
const METHOD_WORKFLOW_RECOVER: &str = "workflow.recover";
const METHOD_SNAPSHOT: &str = "snapshot";
const METHOD_GROUP_PLAN: &str = "group.plan";
const METHOD_GROUP_APPROVE: &str = "group.approve";
const METHOD_GROUP_APPLY: &str = "group.apply";
const METHOD_GROUP_DISCARD: &str = "group.discard";
const METHOD_AGENT_PLUGIN_INSPECT: &str = "agentPlugins.inspect";
const METHOD_AGENT_PLUGIN_PLAN: &str = "agentPlugins.plan";
const METHOD_AGENT_PLUGIN_APPROVE: &str = "agentPlugins.approve";
const METHOD_AGENT_PLUGIN_APPLY: &str = "agentPlugins.apply";
const METHOD_AGENT_PLUGIN_DISCARD: &str = "agentPlugins.discard";
const METHOD_GROUP_DEFINITION_PLAN: &str = "group.definition.plan";
const METHOD_GROUP_DEFINITION_APPLY: &str = "group.definition.apply";
const METHOD_GROUP_DEFINITION_DISCARD: &str = "group.definition.discard";
const METHOD_GROUP_DEFINITION_HISTORY: &str = "group.definition.history";
const METHOD_RECOVERY_SNAPSHOT: &str = "recovery.snapshot";
const METHOD_RESTORE_PLAN: &str = "restore.plan";
const METHOD_RESTORE_APPROVE: &str = "restore.approve";
const METHOD_RESTORE_APPLY: &str = "restore.apply";
const METHOD_RESTORE_DISCARD: &str = "restore.discard";
const METHOD_SHUTDOWN: &str = "shutdown";
const BRIDGE_CAPABILITIES: &[&str] = &[
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
    METHOD_WORKFLOW_RECOVER,
];

pub(crate) struct DesktopBridgeContext {
    config: UnpinConfig,
    discovery_roots: DiscoveryRoots,
    fixture_mode: bool,
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
        }
    }
}

pub(crate) fn run(context: DesktopBridgeContext) -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(context, stdin.lock(), stdout.lock())
}

fn run_with_io(
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

struct Request {
    id: String,
    method: String,
    params: Value,
    auth: Option<BridgeRequestAuth>,
}

#[derive(Clone, Debug)]
struct BridgeRequestAuth {
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
    fn from_value(value: &Value) -> Result<Self, ()> {
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
struct BridgeBinding {
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
struct WorkflowModeDraft {
    name: String,
    profile_id: String,
}

#[derive(Clone, Debug)]
struct WorkflowDraft {
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
struct ReviewedWorkflowLaunch {
    proposal: WorkflowProposalV1,
    workflow_id: String,
    proposal_fingerprint: String,
    reviewed_at_unix: i64,
}

struct DesktopBridgeState {
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
    fn new(context: DesktopBridgeContext) -> Self {
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

struct ReviewedGroupPlan {
    plan: GroupTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

struct ReviewedAgentPluginPlan {
    package: AgentPluginSummary,
    plan: BulkTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

struct ReviewedRestorePlan {
    plan: RestoreControlPlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
    reviewed_at_unix: i64,
}

#[derive(Clone)]
struct ReviewedDefinitionChange {
    action: DefinitionChangeAction,
    plan_fingerprint: String,
    reviewed_at_unix: i64,
}

#[derive(Default)]
struct RecentRequestIds {
    order: VecDeque<String>,
    values: BTreeSet<String>,
}

#[derive(Clone)]
enum DefinitionChangeAction {
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
    const fn kind(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Replace { .. } => "replace",
            Self::Rename { .. } => "rename",
            Self::Delete { .. } => "delete",
            Self::Restore { .. } => "restore",
        }
    }

    const fn scope(&self) -> GroupScope {
        match self {
            Self::Create { scope, .. }
            | Self::Replace { scope, .. }
            | Self::Rename { scope, .. }
            | Self::Delete { scope, .. }
            | Self::Restore { scope, .. } => *scope,
        }
    }
}

struct RequestError {
    id: Option<String>,
    code: &'static str,
}

fn parse_request(frame: &[u8]) -> Result<Request, RequestError> {
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

fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_ID_BYTES && !value.chars().any(char::is_control)
}

fn record_request_id(
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

fn has_reviewed_plan_capacity<T>(plans: &BTreeMap<String, T>, operation_id: &str) -> bool {
    plans.contains_key(operation_id) || plans.len() < MAX_REVIEWED_CONTROL_PLANS
}

fn reviewed_plan_is_expired(reviewed_at_unix: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(reviewed_at_unix) > REVIEWED_PLAN_TTL_SECONDS
}

fn prune_expired_reviewed_plans(state: &mut DesktopBridgeState) {
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

fn handle_handshake(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
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
    if child_pid != std::process::id() || parent_pid != current_parent_process_id() {
        return Err("bridge-process-mismatch");
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

fn bounded_bridge_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    let value = required_string(params, key)?;
    if value.is_empty()
        || value.len() > MAX_BRIDGE_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("invalid-bridge-binding");
    }
    Ok(value)
}

fn current_parent_process_id() -> u32 {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn getppid() -> i32;
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

fn authenticate_request(
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

fn bridge_request_tag(secret: &str, request: &Request, auth: &BridgeRequestAuth) -> String {
    let operation_id = &auth.operation_id;
    let fingerprint = &auth.fingerprint;
    let material = format!(
        "unpin.desktop.bridge.request.v1\0{secret}\0{}\0{}\0{}\0{operation_id}\0{fingerprint}",
        auth.sequence, request.id, request.method,
    );
    unpin_core::sha256_digest(material.as_bytes())
}

fn constant_time_text_equal(left: &str, right: &str) -> bool {
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

fn handle_request(state: &mut DesktopBridgeState, request: Request) -> Value {
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
            METHOD_WORKFLOW_RECOVERY => workflow_recovery(state, false),
            METHOD_WORKFLOW_RECOVER => workflow_recovery(state, true),
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

fn compose_workflow(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "workflowId",
            "displayName",
            "description",
            "provider",
            "baselineProfileId",
            "entryMode",
            "modes",
        ],
    )?;
    let provider = required_string(params, "provider")?;
    parse_provider_id(provider).ok_or("invalid-workflow-provider")?;
    let modes = params
        .get("modes")
        .and_then(Value::as_array)
        .ok_or("invalid-workflow-modes")?
        .iter()
        .map(|mode| {
            require_only_params(mode, &["name", "profileId"])?;
            Ok::<WorkflowModeDraft, &'static str>(WorkflowModeDraft {
                name: required_string(mode, "name")?.to_string(),
                profile_id: required_string(mode, "profileId")?.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let definition = WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: required_string(params, "workflowId")?.to_string(),
        display_name: required_string(params, "displayName")?.to_string(),
        description: optional_bounded_string(params, "description")?.map(str::to_string),
        baseline_profile_id: required_string(params, "baselineProfileId")?.to_string(),
        entry_mode: required_string(params, "entryMode")?.to_string(),
        modes: modes
            .iter()
            .map(|mode| WorkflowModeDefinition::new(&mode.name, &mode.profile_id))
            .collect(),
    };
    definition
        .validate()
        .map_err(|_| "invalid-workflow-definition")?;
    let workflow_revision = definition
        .definition_digest()
        .map_err(|_| "invalid-workflow-definition")?;
    let draft = WorkflowDraft {
        workflow_id: definition.id,
        display_name: definition.display_name,
        description: definition.description,
        provider: provider.to_string(),
        baseline_profile_id: definition.baseline_profile_id,
        entry_mode: definition.entry_mode,
        modes,
        workflow_revision,
    };
    state
        .workflows
        .insert(draft.workflow_id.clone(), draft.clone());
    Ok(json!({
        "status": "composed",
        "workflowRevision": draft.workflow_revision,
        "workflow": workflow_draft_value(&draft),
        "errors": [],
    }))
}

fn validate_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["workflowId", "provider", "workflowRevision"])?;
    let workflow_id = required_string(params, "workflowId")?;
    let provider = parse_provider_id(required_string(params, "provider")?)
        .ok_or("invalid-workflow-provider")?;
    let draft = state
        .workflows
        .get(workflow_id)
        .cloned()
        .ok_or("workflow-draft-unavailable")?;
    if optional_bounded_string(params, "workflowRevision")?
        .is_some_and(|revision| revision != draft.workflow_revision)
    {
        return Err("workflow-revision-mismatch");
    }
    let (definition, revision) = compile_workflow_draft(&state.context, &draft, provider)?;
    Ok(json!({
        "status": "valid",
        "valid": true,
        "workflow": workflow_draft_value(&draft),
        "workflowRevision": revision.digest,
        "provider": provider,
        "capabilityCount": revision.maximum_envelope.authored_member_count,
        "reloadLimitation": WorkflowReloadLimitation::LiveRefreshExpected,
        "errors": [],
        "definitionDigest": definition.definition_digest().map_err(|_| "workflow-validation-failed")?,
    }))
}

fn propose_workflow(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["prompt", "workflowId", "provider"])?;
    let prompt = required_string(params, "prompt")?;
    let workflow_id = optional_bounded_string(params, "workflowId")?;
    let provider = optional_bounded_string(params, "provider")?
        .and_then(parse_provider_id)
        .ok_or("workflow-provider-required")?;
    let draft = match workflow_id {
        Some(workflow_id) => state
            .workflows
            .get(workflow_id)
            .cloned()
            .ok_or("workflow-draft-unavailable")?,
        None => state
            .workflows
            .values()
            .find(|draft| draft.provider == provider.as_str())
            .cloned()
            .ok_or("workflow-selection-required")?,
    };
    let (_, revision) = compile_workflow_draft(&state.context, &draft, provider)?;
    let identity = state
        .context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let discovery =
        discover_all(&state.context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    let catalog_revision = desktop_catalog_digest(&catalog);
    let proposal = WorkflowProposalV1::new(
        draft.workflow_id.clone(),
        draft.entry_mode.clone(),
        provider,
        identity.repository_key,
        identity.workspace_key,
        catalog_revision,
        revision.digest,
        prompt,
        revision.maximum_envelope.authored_member_count,
        true,
        WorkflowReloadLimitation::LiveRefreshExpected,
    )
    .map_err(|_| "workflow-proposal-invalid")?;
    state.reviewed_workflow_launches.insert(
        proposal.proposal_id.clone(),
        ReviewedWorkflowLaunch {
            workflow_id: draft.workflow_id.clone(),
            proposal_fingerprint: proposal.proposal_fingerprint.clone(),
            proposal: proposal.clone(),
            reviewed_at_unix: unix_now(),
        },
    );
    Ok(json!({
        "status": "proposed",
        "proposal": proposal,
        "candidates": [{
            "workflowId": draft.workflow_id,
            "displayName": draft.display_name,
            "scope": "desktop-draft",
            "score": 1,
            "entryMode": draft.entry_mode,
        }],
        "confirmationRequired": true,
        "nextAction": "confirm-workflow-session",
    }))
}

fn launch_workflow(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &["proposalId", "proposalFingerprint", "hostCommand"],
    )?;
    let proposal_id = required_string(params, "proposalId")?;
    let proposal_fingerprint = required_string(params, "proposalFingerprint")?;
    let reviewed = state
        .reviewed_workflow_launches
        .get(proposal_id)
        .cloned()
        .ok_or("workflow-proposal-unavailable")?;
    if reviewed.proposal_fingerprint != proposal_fingerprint {
        return Err("workflow-proposal-fingerprint-mismatch");
    }
    if state.workflow_session_id.is_some() {
        return Err("workflow-session-already-active");
    }
    let host_command = workflow_host_command(params)?;
    let draft = state
        .workflows
        .get(&reviewed.workflow_id)
        .cloned()
        .ok_or("workflow-draft-unavailable")?;
    let (definition, revision) =
        compile_workflow_draft(&state.context, &draft, reviewed.proposal.provider)?;
    validate_reviewed_workflow(&reviewed.proposal, &definition, &revision, &state.context)?;
    WorkflowStore::new(&state.context.config.app_state_root)
        .materialize_revision(
            &revision,
            OwnerGeneration::new(
                format!("desktop-workflow-{}", reviewed.proposal.proposal_id),
                1,
            )
            .map_err(|_| "workflow-revision-unavailable")?,
        )
        .map_err(|_| "workflow-revision-unavailable")?;
    let policy = PolicyStore::new(&state.context.config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|_| "workflow-policy-unavailable")?;
    let locks = CapabilityLockSnapshot::compile(
        reviewed.proposal.provider,
        policy
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&reviewed.proposal.provider))
            .map(|provider| provider.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|_| "workflow-policy-invalid")?;
    let entry = revision
        .effective_profiles
        .get(&revision.entry_mode)
        .ok_or("workflow-entry-profile-missing")?;
    let authority_key = credentials::resolve_session_authority_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-session-authority-unavailable")?
    .ok_or("workflow-session-authority-unavailable")?;
    let backup_authentication_key = credentials::resolve_backup_authentication_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-backup-authority-unavailable")?
    .ok_or("workflow-backup-authority-unavailable")?;
    let identity = state
        .context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let request = session_process::SessionLaunchRequest {
        app_state_root: state.context.config.app_state_root.clone(),
        discovery_roots: state.context.discovery_roots.clone(),
        repository_key: identity.repository_key,
        workspace_key: identity.workspace_key,
        workspace_revision: identity.diagnostics.head,
        provider: reviewed.proposal.provider,
        exposure: PinnedExposure {
            revision: entry.digest.clone(),
            profile: PinnedProfile::Profile {
                profile_id: entry.profile_id.clone(),
                profile_digest: entry.digest.clone(),
                origin_scope: ProfileSourceScope::Session,
                definition_digest: revision.digest.clone(),
            },
            capability_locks: Some(Box::new(locks)),
        },
        workflow: Some(session_process::WorkflowLaunchRequest {
            workflow_id: reviewed.proposal.workflow_id.clone(),
            workflow_revision: reviewed.proposal.workflow_revision.clone(),
            entry_mode: reviewed.proposal.entry_mode.clone(),
            catalog_revision: reviewed.proposal.catalog_revision.clone(),
            proposal_id: reviewed.proposal.proposal_id.clone(),
            proposal_fingerprint: reviewed.proposal.proposal_fingerprint.clone(),
            prompt_digest: reviewed.proposal.prompt_digest.clone(),
            capability_count: reviewed.proposal.capability_count,
        }),
        bridge_socket: None,
        command: host_command,
        authority_key,
        backup_authentication_key,
        fixture_mode: state.context.fixture_mode,
    };
    let (established_sender, established_receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("unpin-desktop-workflow-session".to_string())
        .spawn(move || {
            match session_process::launch_with_established_callback(request, |established| {
                let _ = established_sender.send(Ok(established));
            }) {
                Ok(_) => {}
                Err(error) => {
                    let _ = established_sender.send(Err(error.to_string()));
                }
            }
        })
        .map_err(|_| "workflow-launch-failed")?;
    let established = established_receiver
        .recv_timeout(Duration::from_secs(15))
        .map_err(|_| "workflow-launch-unconfirmed")?
        .map_err(|_| "workflow-launch-failed")?;
    state.workflow_session_id = Some(established.session_id.clone());
    state.reviewed_workflow_launches.remove(proposal_id);
    let session = current_workflow_session(state)?;
    Ok(json!({
        "status": "launched",
        "sessionId": established.session_id,
        "session": workflow_session_value(&session),
        "nextAction": "inspect-workflow-status",
    }))
}

fn transition_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "operationId",
            "operationFingerprint",
            "sourceStateSequence",
            "targetMode",
            "requestedAtUnix",
        ],
    )?;
    let session_id = workflow_session_id(state)?;
    let target_mode = required_string(params, "targetMode")?;
    let session = current_workflow_session(state)?;
    let workflow = session
        .lease
        .workflow
        .as_deref()
        .ok_or("workflow-session-unavailable")?;
    if !workflow.profile_revisions.contains_key(target_mode) {
        return Err("workflow-expansion-requires-review");
    }
    let source_state_sequence = params
        .get("sourceStateSequence")
        .and_then(Value::as_u64)
        .ok_or("invalid-workflow-transition")?;
    let requested_at_unix = params
        .get("requestedAtUnix")
        .and_then(Value::as_i64)
        .ok_or("invalid-workflow-transition")?;
    let result = session_process::call_gateway_control(
        &state.context.config.app_state_root,
        &session_id,
        "unpin_workflow_enter_mode",
        json!(WorkflowTransitionRequest {
            operation_id: required_string(params, "operationId")?.to_string(),
            operation_fingerprint: required_string(params, "operationFingerprint")?.to_string(),
            source_state_sequence,
            target_mode: target_mode.to_string(),
            requested_at_unix,
        }),
    )
    .map_err(|_| "workflow-transition-blocked")?;
    let session = current_workflow_session(state)?;
    Ok(json!({
        "result": result.get("result").cloned().unwrap_or(result),
        "session": workflow_session_value(&session),
        "status": workflow_status_value(Some(&session)),
    }))
}

fn observe_workflow(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &[])?;
    let session = current_workflow_session(state)?;
    Ok(json!({
        "session": workflow_session_value(&session),
        "status": workflow_status_value(Some(&session)),
    }))
}

fn cancel_workflow_transition(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId"])?;
    let operation_id = required_string(params, "operationId")?;
    let session_id = workflow_session_id(state)?;
    let _ = session_process::call_gateway_control(
        &state.context.config.app_state_root,
        &session_id,
        "unpin_workflow_cancel_transition",
        json!({"operationId": operation_id}),
    )
    .map_err(|_| "workflow-cancel-blocked")?;
    let session = current_workflow_session(state)?;
    Ok(json!({
        "status": "cancelled",
        "operationId": operation_id,
        "session": workflow_session_value(&session),
    }))
}

fn workflow_status(state: &mut DesktopBridgeState) -> Result<Value, &'static str> {
    let session = state
        .workflow_session_id
        .as_deref()
        .map(|_| current_workflow_session(state))
        .transpose()?;
    Ok(json!({
        "status": workflow_status_value(session.as_ref()),
        "session": session.as_ref().map(workflow_session_value),
        "operations": [],
        "recoveryRequired": session.as_ref().is_some_and(workflow_recovery_required),
    }))
}

fn workflow_recovery(state: &mut DesktopBridgeState, recover: bool) -> Result<Value, &'static str> {
    let session = state
        .workflow_session_id
        .as_deref()
        .map(|_| current_workflow_session(state))
        .transpose()?;
    let recovery_required = session.as_ref().is_some_and(workflow_recovery_required);
    if recover && recovery_required {
        return Err("workflow-owner-recovery-required");
    }
    Ok(json!({
        "status": if recovery_required { "recovery-required" } else { "ready" },
        "recoveryRequired": recovery_required,
        "operations": [],
        "session": session.as_ref().map(workflow_session_value),
        "message": if recovery_required { "End and relaunch the routed child session after inspecting status." } else { "No workflow recovery is required." },
    }))
}

fn workflow_host_command(params: &Value) -> Result<Vec<OsString>, &'static str> {
    let command = params
        .get("hostCommand")
        .and_then(Value::as_array)
        .ok_or("workflow-host-command-required")?;
    if command.is_empty() || command.len() > 128 {
        return Err("workflow-host-command-required");
    }
    command
        .iter()
        .map(|part| {
            part.as_str()
                .filter(|part| !part.is_empty() && part.len() <= 16 * 1024)
                .map(OsString::from)
                .ok_or("invalid-workflow-host-command")
        })
        .collect()
}

fn validate_reviewed_workflow(
    proposal: &WorkflowProposalV1,
    definition: &WorkflowDefinition,
    revision: &unpin_core::workflows::CompiledWorkflowRevision,
    context: &DesktopBridgeContext,
) -> Result<(), &'static str> {
    let identity = context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let discovery = discover_all(&context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    if definition.id != proposal.workflow_id
        || definition.entry_mode != proposal.entry_mode
        || revision.provider != proposal.provider
        || identity.repository_key != proposal.repository_key
        || identity.workspace_key != proposal.workspace_key
        || desktop_catalog_digest(&catalog) != proposal.catalog_revision
        || revision.digest != proposal.workflow_revision
        || revision.maximum_envelope.authored_member_count != proposal.capability_count
        || !proposal.gateway_required
    {
        return Err("workflow-proposal-stale");
    }
    Ok(())
}

fn workflow_session_id(state: &DesktopBridgeState) -> Result<String, &'static str> {
    state
        .workflow_session_id
        .clone()
        .ok_or("workflow-session-unavailable")
}

fn current_workflow_session(state: &DesktopBridgeState) -> Result<LeaseSnapshot, &'static str> {
    let session_id = workflow_session_id(state)?;
    let authority_key = credentials::resolve_session_authority_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-session-authority-unavailable")?
    .ok_or("workflow-session-authority-unavailable")?;
    SessionManager::with_authority_key(&state.context.config.app_state_root, authority_key)
        .list()
        .map_err(|_| "workflow-session-unavailable")?
        .into_iter()
        .find(|snapshot| snapshot.lease.session_id == session_id)
        .ok_or("workflow-session-unavailable")
}

fn workflow_recovery_required(session: &LeaseSnapshot) -> bool {
    session.lease.desired_exposure != session.lease.observed_exposure
        && matches!(
            session.lease.live_status,
            unpin_core::sessions::LiveExposureStatus::ReloadRequired
                | unpin_core::sessions::LiveExposureStatus::NextSessionOnly
                | unpin_core::sessions::LiveExposureStatus::Unknown
        )
}

fn compile_workflow_draft(
    context: &DesktopBridgeContext,
    draft: &WorkflowDraft,
    provider: ProviderId,
) -> Result<
    (
        WorkflowDefinition,
        unpin_core::workflows::CompiledWorkflowRevision,
    ),
    &'static str,
> {
    let definition = WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: draft.workflow_id.clone(),
        display_name: draft.display_name.clone(),
        description: draft.description.clone(),
        baseline_profile_id: draft.baseline_profile_id.clone(),
        entry_mode: draft.entry_mode.clone(),
        modes: draft
            .modes
            .iter()
            .map(|mode| WorkflowModeDefinition::new(&mode.name, &mode.profile_id))
            .collect(),
    };
    definition
        .validate()
        .map_err(|_| "workflow-validation-failed")?;
    let discovery = discover_all(&context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    let profile_store = ProfileStore::new(&context.config.app_state_root);
    let profile_ids = std::iter::once(definition.baseline_profile_id.clone())
        .chain(definition.modes.iter().map(|mode| mode.profile_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut profiles = BTreeMap::new();
    for profile_id in profile_ids {
        let entry =
            ProfileStore::load_workspace_definition(&context.config.project_root, &profile_id)
                .map_err(|_| "workflow-profile-unavailable")?
                .or_else(|| {
                    profile_store
                        .load_global_definition(&profile_id)
                        .ok()
                        .flatten()
                        .map(|snapshot| unpin_core::profiles::ProfileDefinitionEntry {
                            scope: ProfileSourceScope::Global,
                            definition: snapshot.value,
                            revision: Some(snapshot.revision),
                        })
                })
                .ok_or("workflow-profile-unavailable")?;
        profiles.insert(
            profile_id,
            compile_profile(&entry.definition, &catalog, entry.scope)
                .map_err(|_| "workflow-profile-invalid")?,
        );
    }
    let policy = PolicyStore::new(&context.config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|_| "workflow-policy-unavailable")?;
    let locks = CapabilityLockSnapshot::compile(
        provider,
        policy
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&provider))
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|_| "workflow-policy-invalid")?;
    let revision = compile_workflow(
        &definition,
        &profiles,
        &catalog,
        &locks,
        provider,
        ProfileSourceScope::Workspace,
    )
    .map_err(|_| "workflow-validation-failed")?;
    Ok((definition, revision))
}

fn desktop_catalog_digest(catalog: &Catalog) -> String {
    unpin_core::sha256_digest(&serde_json::to_vec(catalog).expect("catalog serialization"))
}

fn workflow_draft_value(draft: &WorkflowDraft) -> Value {
    json!({
        "workflowId": draft.workflow_id,
        "displayName": draft.display_name,
        "description": draft.description,
        "provider": draft.provider,
        "baselineProfileId": draft.baseline_profile_id,
        "entryMode": draft.entry_mode,
        "modes": draft.modes.iter().map(|mode| json!({
            "name": mode.name,
            "profileId": mode.profile_id,
        })).collect::<Vec<_>>(),
        "workflowRevision": draft.workflow_revision,
    })
}

fn workflow_session_value(session: &LeaseSnapshot) -> Value {
    let workflow = session.lease.workflow.as_deref();
    json!({
        "sessionId": session.lease.session_id,
        "workflowId": workflow.map(|workflow| workflow.workflow_id.as_str()),
        "proposalId": workflow.map(|workflow| workflow.proposal_id.as_str()),
        "activeMode": workflow.map(|workflow| workflow.active_mode.as_str()),
        "observedMode": observed_workflow_mode(session),
        "desiredExposureRevision": session.lease.desired_exposure.revision,
        "observedExposureRevision": session.lease.observed_exposure.revision,
        "stateSequence": session.revision.sequence,
        "liveStatus": session.lease.live_status,
        "admissionOpen": session.lease.admission_open,
        "operationHistory": [],
    })
}

fn workflow_status_value(session: Option<&LeaseSnapshot>) -> Value {
    session.map_or_else(
        || {
            json!({
                "activeMode": null,
                "desiredMode": null,
                "observedMode": null,
                "stateSequence": null,
                "liveStatus": "no-session",
                "admissionOpen": false,
                "recoveryRequired": false,
            })
        },
        |session| {
            let workflow = session.lease.workflow.as_deref();
            json!({
                "sessionId": session.lease.session_id,
                "workflowId": workflow.map(|workflow| workflow.workflow_id.as_str()),
                "activeMode": workflow.map(|workflow| workflow.active_mode.as_str()),
                "desiredMode": workflow.map(|workflow| workflow.active_mode.as_str()),
                "observedMode": observed_workflow_mode(session),
                "stateSequence": session.revision.sequence,
                "liveStatus": session.lease.live_status,
                "admissionOpen": session.lease.admission_open,
                "recoveryRequired": workflow_recovery_required(session),
            })
        },
    )
}

fn observed_workflow_mode(session: &LeaseSnapshot) -> Option<&str> {
    let workflow = session.lease.workflow.as_deref()?;
    workflow
        .profile_revisions
        .iter()
        .find_map(|(mode, revision)| {
            (revision == &session.lease.observed_exposure.revision).then_some(mode.as_str())
        })
}

fn handshake_response() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "binaryVersion": env!("CARGO_PKG_VERSION"),
        "capabilities": BRIDGE_CAPABILITIES,
    })
}

fn handshake_response_for_binding(binding: &BridgeBinding) -> Value {
    let mut response = handshake_response();
    response["binding"] = json!({
        "parentPid": binding.parent_pid,
        "parentStartMarker": binding.parent_start_marker,
        "childPid": binding.child_pid,
        "childStartMarker": binding.child_start_marker,
        "projectRoot": binding.project_root,
        "appStateRoot": binding.app_state_root,
        "processGeneration": binding.process_generation,
    });
    response
}

fn plan_group(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["qualifiedName", "target"])?;
    let qualified_name = required_string(params, "qualifiedName")?;
    let target = match required_string(params, "target")? {
        "enable" => GroupTargetState::Enable,
        "disable" => GroupTargetState::Disable,
        _ => return Err("invalid-group-target"),
    };
    let reference = GroupRef::parse(qualified_name).map_err(|_| "invalid-group-reference")?;
    let planner = group_planner(&state.context)?;
    let plan = planner
        .plan_with_reach(
            &reference,
            target,
            MAX_GROUP_MEMBERS,
            GroupPlanMode::LocalInteractive,
            ProviderReach::All,
        )
        .map_err(|_| "group-plan-unavailable")?;
    if let Some(operation_id) = plan.operation_id.clone() {
        if !has_reviewed_plan_capacity(&state.reviewed_groups, &operation_id) {
            return Err("group-plan-limit-reached");
        }
        state.reviewed_groups.insert(
            operation_id,
            ReviewedGroupPlan {
                plan: plan.clone(),
                authorization: None,
                reviewed_at_unix: unix_now(),
            },
        );
    }
    Ok(json!({"plan": plan}))
}

fn approve_group(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_groups
        .get_mut(operation_id)
        .ok_or("group-plan-unavailable")?;
    if reviewed.plan.disposition != GroupPlanDisposition::Actionable
        || reviewed.plan.plan_fingerprint != plan_fingerprint
    {
        return Err("plan-fingerprint-mismatch");
    }
    let approval_context = approval_context(&state.context)?;
    let expectation = reviewed
        .plan
        .approval_expectation(&approval_context)
        .map_err(|_| "group-plan-unavailable")?;
    let authorization = credentials::authorize_desktop_control_decision(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
        &expectation,
        &reviewed.plan.plan_fingerprint,
        Some(plan_fingerprint),
        "unpin-desktop-local-approval",
        unix_now(),
    )
    .map_err(|_| "desktop-approval-blocked")?;
    reviewed.authorization = Some(authorization);
    Ok(json!({
        "operationId": operation_id,
        "planFingerprint": plan_fingerprint,
        "approval": "current",
    }))
}

fn apply_group(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let controller = group_controller(&state.context)?;
    let reviewed = state
        .reviewed_groups
        .get_mut(operation_id)
        .ok_or("group-plan-unavailable")?;
    if reviewed.plan.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    let authorization = reviewed
        .authorization
        .take()
        .ok_or("desktop-approval-required")?;
    let plan = reviewed.plan.clone();
    require_group_write_sandbox(&state.context)?;
    let result = controller
        .apply(&plan, authorization)
        .map_err(|_| "group-apply-blocked")?;
    state.reviewed_groups.remove(operation_id);
    Ok(json!({"result": result}))
}

fn discard_group(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_groups
        .get(operation_id)
        .ok_or("group-plan-unavailable")?;
    if reviewed.plan.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    state.reviewed_groups.remove(operation_id);
    Ok(json!({"discarded": true}))
}

fn inspect_agent_plugin(state: &DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["logicalId"])?;
    let logical_id = required_string(params, "logicalId")?;
    let discovery =
        discover_all(&state.context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let package = discovery
        .agent_plugins()
        .into_iter()
        .find(|package| package.logical_id == logical_id)
        .ok_or("agent-plugin-not-found")?;
    Ok(json!({"package": redacted_agent_plugin_summary(&package)}))
}

fn plan_agent_plugin(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &["logicalId", "target", "reach", "selectedProvider"],
    )?;
    let logical_id = required_string(params, "logicalId")?;
    let target_enabled = match required_string(params, "target")? {
        "on" | "enable" => true,
        "off" | "disable" => false,
        _ => return Err("invalid-agent-plugin-target"),
    };
    let discovery =
        discover_all(&state.context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let package = discovery
        .agent_plugins()
        .into_iter()
        .find(|package| package.logical_id == logical_id)
        .ok_or("agent-plugin-not-found")?;
    let mut request =
        BulkToggleRequest::for_agent_plugin_summary(&discovery, &package, target_enabled)
            .map_err(agent_plugin_plan_error_code)?;
    let selected_provider = params
        .get("selectedProvider")
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 1_024)
                .ok_or("invalid-params")
                .and_then(|value| parse_provider_id(value).ok_or("invalid-selected-provider"))
        })
        .transpose()?;
    let reach = match required_string(params, "reach")? {
        "all" if selected_provider.is_none() => ProviderReachArg::All,
        "all" => return Err("provider-conflicts-with-all-reach"),
        "selected" => ProviderReachArg::Selected,
        _ => return Err("invalid-agent-plugin-reach"),
    };
    let reach_input = reach
        .input(selected_provider)
        .map_err(|_| "selected-provider-required")?;
    request = request.with_reach(ConnectionBoundary::All, reach_input);
    if let Some(provider) = selected_provider {
        request = request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    BulkToggleController::validate_before_discovery(&request)
        .map_err(agent_plugin_plan_error_code)?;
    let plan = BulkToggleController::new(&state.context.config.app_state_root)
        .plan_agent_plugin_from_discovery(discovery, request, &package)
        .map_err(agent_plugin_plan_error_code)?;
    if !has_reviewed_plan_capacity(&state.reviewed_agent_plugins, &plan.operation_id) {
        return Err("agent-plugin-plan-limit-reached");
    }
    let response = redacted_agent_plugin_plan(&package, &plan);
    state.reviewed_agent_plugins.insert(
        plan.operation_id.clone(),
        ReviewedAgentPluginPlan {
            package,
            plan,
            authorization: None,
            reviewed_at_unix: unix_now(),
        },
    );
    Ok(json!({"plan": response}))
}

fn approve_agent_plugin(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let plan = {
        let reviewed = state
            .reviewed_agent_plugins
            .get(operation_id)
            .ok_or("agent-plugin-plan-unavailable")?;
        if reviewed.plan.plan_fingerprint != plan_fingerprint {
            return Err("plan-fingerprint-mismatch");
        }
        reviewed.plan.clone()
    };
    if !matches!(
        plan.lifecycle,
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial
    ) || plan.write_count() == 0
    {
        return Err("agent-plugin-plan-not-actionable");
    }
    let (_, durable) = durable_context(
        &state.context.config.app_state_root,
        &state.context.discovery_roots,
        &state.context.config,
        &plan,
        state.context.fixture_mode,
    )
    .map_err(|_| "agent-plugin-approval-unavailable")?;
    let expectation = plan
        .approval_expectation(&durable.approval_context, &durable.principal.session_id)
        .map_err(|_| "agent-plugin-approval-unavailable")?;
    let digest = unprefixed_plan_fingerprint(plan_fingerprint);
    let authorization = credentials::authorize_desktop_control_decision(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
        &expectation,
        digest,
        Some(digest),
        "unpin-desktop-agent-plugin-approval",
        unix_now(),
    )
    .map_err(|_| "desktop-approval-blocked")?;
    state
        .reviewed_agent_plugins
        .get_mut(operation_id)
        .ok_or("agent-plugin-plan-unavailable")?
        .authorization = Some(authorization);
    Ok(json!({
        "operationId": operation_id,
        "planFingerprint": plan_fingerprint,
        "approval": "current",
    }))
}

fn apply_agent_plugin(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let (logical_id, package, plan) = {
        let reviewed = state
            .reviewed_agent_plugins
            .get(operation_id)
            .ok_or("agent-plugin-plan-unavailable")?;
        if reviewed.plan.plan_fingerprint != plan_fingerprint {
            return Err("plan-fingerprint-mismatch");
        }
        if reviewed.authorization.is_none() {
            return Err("desktop-approval-required");
        }
        (
            reviewed.package.logical_id.clone(),
            reviewed.package.clone(),
            reviewed.plan.clone(),
        )
    };
    let fresh_discovery =
        discover_all(&state.context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let (controller, durable) = durable_context(
        &state.context.config.app_state_root,
        &state.context.discovery_roots,
        &state.context.config,
        &plan,
        state.context.fixture_mode,
    )
    .map_err(|_| "agent-plugin-apply-blocked")?;
    require_group_write_sandbox(&state.context)?;
    let authorization = state
        .reviewed_agent_plugins
        .get_mut(operation_id)
        .ok_or("agent-plugin-plan-unavailable")?
        .authorization
        .take()
        .ok_or("desktop-approval-required")?;
    let result = controller
        .apply_with_reach_aware(&plan, authorization, durable, fresh_discovery)
        .map_err(|_| "agent-plugin-recovery-required")?;
    state.reviewed_agent_plugins.remove(operation_id);
    let refreshed = discover_all(&state.context.discovery_roots)
        .ok()
        .and_then(|discovery| {
            discovery
                .agent_plugins()
                .into_iter()
                .find(|candidate| candidate.logical_id == logical_id)
        });
    Ok(json!({
        "result": redacted_agent_plugin_apply(refreshed.as_ref().unwrap_or(&package), &result),
        "refreshStatus": if refreshed.is_some() { "complete" } else { "unavailable" },
    }))
}

fn discard_agent_plugin(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_agent_plugins
        .get(operation_id)
        .ok_or("agent-plugin-plan-unavailable")?;
    if reviewed.plan.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    state.reviewed_agent_plugins.remove(operation_id);
    Ok(json!({"discarded": true}))
}

fn agent_plugin_plan_error_code(error: BulkTogglePlanError) -> &'static str {
    match error {
        BulkTogglePlanError::AgentPluginNotFound => "agent-plugin-not-found",
        BulkTogglePlanError::AgentPluginHasNoActivationAnchors => {
            "agent-plugin-no-activation-anchors"
        }
        BulkTogglePlanError::AgentPluginInventoryIncomplete => "agent-plugin-inventory-incomplete",
        BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors => {
            "agent-plugin-diagnostics-only-writable-activation"
        }
        BulkTogglePlanError::AgentPluginHasNoActionableActivationAnchors => {
            "agent-plugin-no-actionable-activation"
        }
        BulkTogglePlanError::SelectionContextFingerprintMismatch => {
            "agent-plugin-projection-changed"
        }
        BulkTogglePlanError::PlanFingerprintMismatch => "plan-fingerprint-mismatch",
        BulkTogglePlanError::NoTargetsInProviderReach => "no-targets-in-provider-reach",
        _ => "agent-plugin-plan-unavailable",
    }
}

fn unprefixed_plan_fingerprint(fingerprint: &str) -> &str {
    fingerprint.strip_prefix("sha256:").unwrap_or(fingerprint)
}

fn plan_definition_change(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "action",
            "scope",
            "qualifiedName",
            "name",
            "newName",
            "members",
            "expectedRevision",
            "historyId",
        ],
    )?;
    if state.reviewed_definitions.len() >= MAX_REVIEWED_DEFINITION_PLANS {
        return Err("group-definition-plan-limit-reached");
    }
    let (action, plan_fingerprint) = definition_change_from_params(&state.context, params)?;
    let operation_id = next_definition_operation_id(state)?;
    let plan = redacted_definition_plan(&action, &plan_fingerprint);
    state.reviewed_definitions.insert(
        operation_id.clone(),
        ReviewedDefinitionChange {
            action,
            plan_fingerprint,
            reviewed_at_unix: unix_now(),
        },
    );
    Ok(json!({"operationId": operation_id, "plan": plan}))
}

fn apply_definition_change(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_definitions
        .get(operation_id)
        .ok_or("group-definition-plan-unavailable")?;
    if reviewed.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    let action = reviewed.action.clone();
    require_group_write_sandbox(&state.context)?;
    let result = apply_reviewed_definition_change(&state.context, &action)?;
    state.reviewed_definitions.remove(operation_id);
    Ok(result)
}

fn discard_definition_change(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_definitions
        .get(operation_id)
        .ok_or("group-definition-plan-unavailable")?;
    if reviewed.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    state.reviewed_definitions.remove(operation_id);
    Ok(json!({"discarded": true}))
}

fn definition_history(
    context: &DesktopBridgeContext,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["scope"])?;
    let scope = required_group_scope(params, "scope")?;
    let history = definition_store(context, scope)?
        .history()
        .map_err(|_| "group-definition-history-unavailable")?;
    Ok(json!({
        "history": history.iter().map(redacted_definition_history).collect::<Vec<_>>(),
    }))
}

fn definition_change_from_params(
    context: &DesktopBridgeContext,
    params: &Value,
) -> Result<(DefinitionChangeAction, String), &'static str> {
    match required_string(params, "action")? {
        "create" => {
            let scope = required_group_scope(params, "scope")?;
            let definition = definition_from_params(params, "name")?;
            validate_definition_members(context, &definition, BTreeSet::new())?;
            let plan_fingerprint = definition_revision(context, scope, &definition)?;
            Ok((
                DefinitionChangeAction::Create { scope, definition },
                plan_fingerprint,
            ))
        }
        "replace" => {
            let existing = resolved_group_record(context, params)?;
            let definition = definition_from_params(params, "name")?;
            let retained = existing.definition.members.iter().cloned().collect();
            validate_definition_members(context, &definition, retained)?;
            let expected_revision = required_group_revision(params, "expectedRevision")?;
            let plan_fingerprint = definition_revision(context, existing.scope, &definition)?;
            Ok((
                DefinitionChangeAction::Replace {
                    scope: existing.scope,
                    qualified_name: existing.qualified_name,
                    definition,
                    expected_revision,
                },
                plan_fingerprint,
            ))
        }
        "rename" => {
            let existing = resolved_group_record(context, params)?;
            let new_name = required_string(params, "newName")?.to_string();
            let expected_revision = required_group_revision(params, "expectedRevision")?;
            let mut renamed = existing.definition.clone();
            renamed.name = new_name.clone();
            renamed
                .canonicalize_and_validate()
                .map_err(|_| "group-definition-invalid")?;
            let plan_fingerprint = definition_revision(context, existing.scope, &renamed)?;
            Ok((
                DefinitionChangeAction::Rename {
                    scope: existing.scope,
                    qualified_name: existing.qualified_name,
                    new_name,
                    expected_revision,
                },
                plan_fingerprint,
            ))
        }
        "delete" => {
            let existing = resolved_group_record(context, params)?;
            let expected_revision = required_group_revision(params, "expectedRevision")?;
            Ok((
                DefinitionChangeAction::Delete {
                    scope: existing.scope,
                    qualified_name: existing.qualified_name,
                    expected_revision,
                },
                existing.revision.to_string(),
            ))
        }
        "restore" => {
            let scope = required_group_scope(params, "scope")?;
            let history_id = required_string(params, "historyId")?.to_string();
            let expected_revision = optional_group_revision(params, "expectedRevision")?;
            let history = definition_store(context, scope)?
                .history()
                .map_err(|_| "group-definition-history-unavailable")?
                .into_iter()
                .find(|record| record.history_id == history_id)
                .ok_or("group-definition-history-unavailable")?;
            let definition = history
                .definition_before
                .ok_or("group-definition-restore-blocked")?;
            let plan_fingerprint = definition_revision(context, scope, &definition)?;
            Ok((
                DefinitionChangeAction::Restore {
                    scope,
                    history_id,
                    expected_revision,
                },
                plan_fingerprint,
            ))
        }
        _ => Err("invalid-group-definition-action"),
    }
}

fn definition_from_params(
    params: &Value,
    name_key: &str,
) -> Result<GroupDefinitionV1, &'static str> {
    let name = required_string(params, name_key)?;
    let members = params
        .get("members")
        .cloned()
        .ok_or("invalid-params")
        .and_then(|members| {
            serde_json::from_value::<Vec<GroupMemberIdentity>>(members)
                .map_err(|_| "invalid-group-members")
        })?;
    GroupDefinitionV1::new(name, members).map_err(|_| "group-definition-invalid")
}

fn resolved_group_record(
    context: &DesktopBridgeContext,
    params: &Value,
) -> Result<unpin_core::groups::GroupRecord, &'static str> {
    let reference = GroupRef::parse(required_string(params, "qualifiedName")?)
        .map_err(|_| "invalid-group-reference")?;
    if reference.scope.is_none() {
        return Err("invalid-group-reference");
    }
    group_resolver(context)?
        .resolve_definition(&reference)
        .map_err(|_| "group-definition-unavailable")
}

fn required_group_scope(params: &Value, key: &str) -> Result<GroupScope, &'static str> {
    required_string(params, key)?
        .parse()
        .map_err(|_| "invalid-group-scope")
}

fn required_group_revision(params: &Value, key: &str) -> Result<GroupRevision, &'static str> {
    GroupRevision::parse(required_string(params, key)?).map_err(|_| "invalid-group-revision")
}

fn optional_group_revision(
    params: &Value,
    key: &str,
) -> Result<Option<GroupRevision>, &'static str> {
    params
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 1_024)
                .ok_or("invalid-params")
                .and_then(|value| GroupRevision::parse(value).map_err(|_| "invalid-group-revision"))
        })
        .transpose()
}

fn validate_definition_members(
    context: &DesktopBridgeContext,
    definition: &GroupDefinitionV1,
    retained: BTreeSet<GroupMemberIdentity>,
) -> Result<(), &'static str> {
    let group_context = group_access_context(context)?;
    validate_new_group_members(&group_context, definition, &retained)
        .map_err(|_| "group-definition-members-blocked")
}

fn definition_revision(
    context: &DesktopBridgeContext,
    scope: GroupScope,
    definition: &GroupDefinitionV1,
) -> Result<String, &'static str> {
    let group_context = group_access_context(context)?;
    let binding = match scope {
        GroupScope::Personal => group_context.binding_for_personal(definition),
        GroupScope::Repository => group_context.binding_for_repository(definition),
    };
    definition
        .revision(&binding)
        .map(|revision| revision.to_string())
        .map_err(|_| "group-definition-invalid")
}

fn next_definition_operation_id(state: &mut DesktopBridgeState) -> Result<String, &'static str> {
    state.next_definition_plan_id = state
        .next_definition_plan_id
        .checked_add(1)
        .ok_or("group-definition-session-exhausted")?;
    Ok(format!("definition-{}", state.next_definition_plan_id))
}

fn require_group_write_sandbox(context: &DesktopBridgeContext) -> Result<(), &'static str> {
    let group_context = group_access_context(context)?;
    require_fixture_group_write_sandbox(
        context.fixture_mode,
        group_context.app_state_root(),
        group_context.workspace_root(),
        &context.discovery_roots,
    )
}

fn require_fixture_group_write_sandbox(
    fixture_mode: bool,
    app_state_root: &std::path::Path,
    workspace_root: &std::path::Path,
    discovery_roots: &DiscoveryRoots,
) -> Result<(), &'static str> {
    let mut roots = vec![
        app_state_root,
        workspace_root,
        &discovery_roots.claude_global,
        &discovery_roots.claude_user_state,
        &discovery_roots.claude_project,
        &discovery_roots.codex_global,
        &discovery_roots.codex_admin,
        &discovery_roots.codex_project,
        &discovery_roots.cursor_global,
        &discovery_roots.cursor_config,
        &discovery_roots.cursor_project,
        &discovery_roots.pi_global,
        &discovery_roots.pi_project,
        &discovery_roots.opencode_global,
        &discovery_roots.opencode_project,
        &discovery_roots.shared_global,
        &discovery_roots.shared_project,
        &discovery_roots.zed_global,
        &discovery_roots.zed_project,
    ];
    if let Some(app_state_root) = discovery_roots.app_state_root.as_deref() {
        roots.push(app_state_root);
    }
    unpin_core::fixture::require_fixture_write_sandbox(fixture_mode, roots)
        .map_err(|_| "fixture-write-sandbox-blocked")
}

fn definition_store(
    context: &DesktopBridgeContext,
    scope: GroupScope,
) -> Result<ScopedGroupStore, &'static str> {
    let group_context = group_access_context(context)?;
    let authentication_key = backup_authentication_key(context)?;
    Ok(match scope {
        GroupScope::Personal => ScopedGroupStore::Personal(
            PersonalGroupStore::new(group_context)
                .with_history_authentication_key(authentication_key),
        ),
        GroupScope::Repository => ScopedGroupStore::Repository(
            RepositoryGroupStore::new(group_context)
                .with_history_authentication_key(authentication_key),
        ),
    })
}

fn definition_owner() -> OwnerGeneration {
    OwnerGeneration::new(GROUP_DEFINITION_OWNER_ID, 1).expect("static owner is valid")
}

fn apply_reviewed_definition_change(
    context: &DesktopBridgeContext,
    action: &DefinitionChangeAction,
) -> Result<Value, &'static str> {
    let store = definition_store(context, action.scope())?;
    match action {
        DefinitionChangeAction::Create { scope, definition } => {
            let record = store
                .create(definition, definition_owner())
                .map_err(|_| "group-definition-apply-blocked")?;
            Ok(redacted_definition_change_result(
                "create", *scope, &record, None,
            ))
        }
        DefinitionChangeAction::Replace {
            scope,
            definition,
            expected_revision,
            ..
        } => {
            let record = store
                .replace(definition, Some(expected_revision), definition_owner())
                .map_err(|_| "group-definition-apply-blocked")?;
            Ok(redacted_definition_change_result(
                "replace", *scope, &record, None,
            ))
        }
        DefinitionChangeAction::Rename {
            scope,
            qualified_name,
            new_name,
            expected_revision,
        } => {
            let old_name = GroupRef::parse(qualified_name)
                .map_err(|_| "group-definition-apply-blocked")?
                .name;
            let record = store
                .rename(&old_name, new_name, expected_revision, definition_owner())
                .map_err(|_| "group-definition-apply-blocked")?;
            Ok(redacted_definition_change_result(
                "rename", *scope, &record, None,
            ))
        }
        DefinitionChangeAction::Delete {
            scope,
            qualified_name,
            expected_revision,
        } => {
            let name = GroupRef::parse(qualified_name)
                .map_err(|_| "group-definition-apply-blocked")?
                .name;
            let history = store
                .delete(&name, expected_revision, definition_owner())
                .map_err(|_| "group-definition-apply-blocked")?;
            Ok(json!({
                "action": "delete",
                "scope": scope,
                "qualifiedName": qualified_name,
                "historyId": history.history_id,
            }))
        }
        DefinitionChangeAction::Restore {
            scope,
            history_id,
            expected_revision,
        } => {
            let record = store
                .restore(history_id, expected_revision.as_ref(), definition_owner())
                .map_err(|_| "group-definition-apply-blocked")?;
            Ok(redacted_definition_change_result(
                "restore",
                *scope,
                &record,
                Some(history_id),
            ))
        }
    }
}

fn redacted_definition_plan(action: &DefinitionChangeAction, plan_fingerprint: &str) -> Value {
    match action {
        DefinitionChangeAction::Create { scope, definition } => json!({
            "action": action.kind(),
            "scope": scope,
            "qualifiedName": format!("{}:{}", scope.as_str(), definition.name),
            "memberCount": definition.members.len(),
            "planFingerprint": plan_fingerprint,
        }),
        DefinitionChangeAction::Replace {
            scope,
            qualified_name,
            definition,
            expected_revision,
        } => json!({
            "action": action.kind(),
            "scope": scope,
            "qualifiedName": qualified_name,
            "memberCount": definition.members.len(),
            "expectedRevision": expected_revision,
            "planFingerprint": plan_fingerprint,
        }),
        DefinitionChangeAction::Rename {
            scope,
            qualified_name,
            new_name,
            expected_revision,
        } => json!({
            "action": action.kind(),
            "scope": scope,
            "qualifiedName": qualified_name,
            "newName": new_name,
            "expectedRevision": expected_revision,
            "planFingerprint": plan_fingerprint,
        }),
        DefinitionChangeAction::Delete {
            scope,
            qualified_name,
            expected_revision,
        } => json!({
            "action": action.kind(),
            "scope": scope,
            "qualifiedName": qualified_name,
            "expectedRevision": expected_revision,
            "planFingerprint": plan_fingerprint,
        }),
        DefinitionChangeAction::Restore {
            scope,
            history_id,
            expected_revision,
        } => json!({
            "action": action.kind(),
            "scope": scope,
            "historyId": history_id,
            "expectedRevision": expected_revision,
            "planFingerprint": plan_fingerprint,
        }),
    }
}

fn redacted_definition_change_result(
    action: &str,
    scope: GroupScope,
    record: &unpin_core::groups::GroupRecord,
    history_id: Option<&str>,
) -> Value {
    json!({
        "action": action,
        "scope": scope,
        "qualifiedName": record.qualified_name,
        "revision": record.revision,
        "historyId": history_id,
    })
}

fn redacted_definition_history(record: &unpin_core::groups::GroupHistoryRecord) -> Value {
    json!({
        "historyId": record.history_id,
        "createdAt": record.created_at,
        "scope": record.scope,
        "change": record.change,
        "nameBefore": record.name_before,
        "nameAfter": record.name_after,
        "revisionBefore": record.revision_before,
        "revisionAfter": record.revision_after,
        "definitionAfterExists": record.definition_after.is_some(),
    })
}

fn plan_restore(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["backupId"])?;
    let backup_id = required_string(params, "backupId")?;
    let group_context = group_access_context(&state.context)?;
    let approval_context = control_approval_context(&group_context)?;
    let app_state_root = group_context.app_state_root().to_path_buf();
    let backup_key = backup_authentication_key(&state.context)?;
    let plan = RestoreController::new(&app_state_root)
        .plan(backup_id, &approval_context, Some(&backup_key))
        .map_err(|_| "restore-plan-unavailable")?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|_| "restore-plan-unavailable")?;
    let operation_id = expectation.operation_id.clone();
    if !has_reviewed_plan_capacity(&state.reviewed_restores, &operation_id) {
        return Err("restore-plan-limit-reached");
    }
    state.reviewed_restores.insert(
        operation_id.clone(),
        ReviewedRestorePlan {
            plan: plan.clone(),
            authorization: None,
            reviewed_at_unix: unix_now(),
        },
    );
    Ok(json!({
        "operationId": operation_id,
        "plan": redacted_restore_plan(&plan),
    }))
}

fn approve_restore(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let plan = {
        let reviewed = state
            .reviewed_restores
            .get(operation_id)
            .ok_or("restore-plan-unavailable")?;
        if reviewed.plan.plan_fingerprint != plan_fingerprint {
            return Err("plan-fingerprint-mismatch");
        }
        reviewed.plan.clone()
    };
    let approval_context = approval_context(&state.context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|_| "restore-plan-unavailable")?;
    let authorization = credentials::authorize_desktop_control_decision(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        Some(plan_fingerprint),
        "unpin-desktop-local-restore-approval",
        unix_now(),
    )
    .map_err(|_| "desktop-approval-blocked")?;
    state
        .reviewed_restores
        .get_mut(operation_id)
        .ok_or("restore-plan-unavailable")?
        .authorization = Some(authorization);
    Ok(json!({
        "operationId": operation_id,
        "planFingerprint": plan_fingerprint,
        "approval": "current",
    }))
}

fn apply_restore(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let plan = {
        let reviewed = state
            .reviewed_restores
            .get(operation_id)
            .ok_or("restore-plan-unavailable")?;
        if reviewed.plan.plan_fingerprint != plan_fingerprint {
            return Err("plan-fingerprint-mismatch");
        }
        reviewed
            .authorization
            .as_ref()
            .ok_or("desktop-approval-required")?;
        reviewed.plan.clone()
    };
    let group_context = group_access_context(&state.context)?;
    let approval_context = control_approval_context(&group_context)?;
    let app_state_root = group_context.app_state_root().to_path_buf();
    let backup_key = backup_authentication_key(&state.context)?;
    let session_key = session_authority_key(&state.context)?;
    let mut fixture_paths = vec![app_state_root.as_path()];
    fixture_paths.extend(
        plan.affected_resources
            .iter()
            .map(|resource| std::path::Path::new(resource.path.as_str())),
    );
    unpin_core::fixture::require_fixture_write_sandbox(state.context.fixture_mode, fixture_paths)
        .map_err(|_| "fixture-write-sandbox-blocked")?;
    let authorization = state
        .reviewed_restores
        .get_mut(operation_id)
        .ok_or("restore-plan-unavailable")?
        .authorization
        .take()
        .ok_or("desktop-approval-required")?;
    let result = RestoreController::with_session_authority_key(&app_state_root, session_key)
        .apply(&plan, authorization, &approval_context, Some(backup_key))
        .map_err(|_| "restore-apply-blocked")?;
    state.reviewed_restores.remove(operation_id);
    Ok(json!({"result": redacted_restore_result(&result)}))
}

fn discard_restore(state: &mut DesktopBridgeState, params: &Value) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId", "planFingerprint"])?;
    let operation_id = required_string(params, "operationId")?;
    let plan_fingerprint = required_string(params, "planFingerprint")?;
    let reviewed = state
        .reviewed_restores
        .get(operation_id)
        .ok_or("restore-plan-unavailable")?;
    if reviewed.plan.plan_fingerprint != plan_fingerprint {
        return Err("plan-fingerprint-mismatch");
    }
    state.reviewed_restores.remove(operation_id);
    Ok(json!({"discarded": true}))
}

fn require_only_params(params: &Value, allowed: &[&str]) -> Result<(), &'static str> {
    let object = params.as_object().ok_or("invalid-params")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unknown-parameter");
    }
    Ok(())
}

fn required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1_024)
        .ok_or("invalid-params")
}

fn optional_bounded_string<'a>(
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

fn group_access_context(
    context: &DesktopBridgeContext,
) -> Result<GroupAccessContext, &'static str> {
    GroupAccessContext::from_config(&context.config, &context.discovery_roots, None, None)
        .map_err(|_| "group-context-unavailable")
}

fn group_planner(context: &DesktopBridgeContext) -> Result<GroupPlanner, &'static str> {
    Ok(GroupPlanner::new(group_resolver(context)?))
}

fn group_resolver(context: &DesktopBridgeContext) -> Result<GroupResolver, &'static str> {
    let group_context = group_access_context(context)?;
    Ok(GroupResolver::new(
        group_context.clone(),
        PersonalGroupStore::new(group_context.clone()),
        RepositoryGroupStore::new(group_context),
    ))
}

fn group_controller(context: &DesktopBridgeContext) -> Result<GroupController, &'static str> {
    let backup_key = backup_authentication_key(context)?;
    let session_key = session_authority_key(context)?;
    controller_with_keys(context, backup_key, session_key)
}

fn controller_with_keys(
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

fn approval_context(
    context: &DesktopBridgeContext,
) -> Result<ControlApprovalContext, &'static str> {
    let group_context = group_access_context(context)?;
    control_approval_context(&group_context)
}

fn control_approval_context(
    group_context: &GroupAccessContext,
) -> Result<ControlApprovalContext, &'static str> {
    ControlApprovalContext::new(
        group_context.repository_key(),
        group_context.workspace_key(),
    )
    .map_err(|_| "approval-context-unavailable")
}

fn backup_authentication_key(
    context: &DesktopBridgeContext,
) -> Result<BackupAuthenticationKey, &'static str> {
    credentials::resolve_backup_authentication_key(
        context.fixture_mode,
        &context.config.app_state_root,
    )
    .map_err(|_| "backup-authentication-unavailable")?
    .ok_or("backup-authentication-unavailable")
}

fn session_authority_key(
    context: &DesktopBridgeContext,
) -> Result<SessionAuthorityKey, &'static str> {
    credentials::resolve_session_authority_key(context.fixture_mode, &context.config.app_state_root)
        .map_err(|_| "session-authority-unavailable")?
        .ok_or("session-authority-unavailable")
}

fn recovery_snapshot_response(context: &DesktopBridgeContext) -> Result<Value, &'static str> {
    let backup_key = backup_authentication_key(context);
    let backup_index = backup_key
        .as_ref()
        .ok()
        .map(|key| load_backup_index_authenticated(&context.config.app_state_root, Some(key)));
    let (backups, backup_status) = match backup_index.as_ref() {
        Some(index) => (
            index
                .summaries()
                .iter()
                .map(redacted_backup_summary)
                .collect::<Vec<_>>(),
            if index.is_complete() {
                "available"
            } else {
                "unavailable"
            },
        ),
        None => (Vec::new(), "unavailable"),
    };
    let (mut operations, control_operation_status) = control_operation_summaries(context);
    let (group_operations, group_operation_status) =
        group_operation_summaries(context, backup_key.as_ref().ok(), backup_index.as_ref());
    operations.extend(group_operations);
    operations.sort_by(|left, right| {
        left["operationId"]
            .as_str()
            .cmp(&right["operationId"].as_str())
    });
    let operation_status =
        if control_operation_status == "available" && group_operation_status == "available" {
            "available"
        } else {
            "unavailable"
        };
    Ok(json!({
        "backups": backups,
        "backupStatus": backup_status,
        "operations": operations,
        "operationStatus": operation_status,
        "groupOperationStatus": group_operation_status,
    }))
}

fn control_operation_summaries(context: &DesktopBridgeContext) -> (Vec<Value>, &'static str) {
    let Ok(session_key) = session_authority_key(context) else {
        return (Vec::new(), "unavailable");
    };
    let Ok(discovery) = discover_all(&context.discovery_roots) else {
        return (Vec::new(), "unavailable");
    };
    let Ok(status) = build_control_status(
        &discovery,
        &context.config.app_state_root,
        &context.config.project_root,
        &session_key,
    ) else {
        return (Vec::new(), "unavailable");
    };
    (
        status
            .operations
            .iter()
            .map(redacted_operation_summary)
            .collect(),
        "available",
    )
}

fn group_operation_summaries(
    context: &DesktopBridgeContext,
    backup_key: Option<&BackupAuthenticationKey>,
    backup_index: Option<&AuthenticatedBackupIndex>,
) -> (Vec<Value>, &'static str) {
    let Some(backup_key) = backup_key else {
        return (Vec::new(), "unavailable");
    };
    let Ok(group_context) = group_access_context(context) else {
        return (Vec::new(), "unavailable");
    };
    let inspections = match backup_index {
        Some(backup_index) => list_group_operation_inspections_with_backup_index(
            group_context.app_state_root(),
            backup_key.clone(),
            group_context.repository_key(),
            group_context.workspace_key(),
            backup_index,
        ),
        None => list_group_operation_inspections(
            group_context.app_state_root(),
            backup_key.clone(),
            group_context.repository_key(),
            group_context.workspace_key(),
        ),
    };
    match inspections {
        Ok(operations) => (
            operations
                .iter()
                .map(redacted_group_operation_summary)
                .collect(),
            "available",
        ),
        Err(
            unpin_core::groups::GroupOperationError::Authentication(_)
            | unpin_core::groups::GroupOperationError::AuthenticationFailed,
        ) => (Vec::new(), "authentication-unavailable"),
        Err(unpin_core::groups::GroupOperationError::ContextMismatch) => {
            (Vec::new(), "context-unavailable")
        }
        Err(unpin_core::groups::GroupOperationError::State(_)) => (Vec::new(), "state-unavailable"),
        Err(unpin_core::groups::GroupOperationError::Io(_)) => (Vec::new(), "storage-unavailable"),
        Err(
            unpin_core::groups::GroupOperationError::InvalidOperationId
            | unpin_core::groups::GroupOperationError::InvalidRecord
            | unpin_core::groups::GroupOperationError::InvalidBackupIndex
            | unpin_core::groups::GroupOperationError::Json(_)
            | unpin_core::groups::GroupOperationError::Clock(_),
        ) => (Vec::new(), "evidence-invalid"),
    }
}

fn redacted_backup_summary(summary: &unpin_core::mutation::BackupSummary) -> Value {
    json!({
        "backupId": summary.backup_id,
        "createdAt": summary.created_at,
        "itemCount": summary.item_count,
        "providers": summary.providers,
        "layers": summary.layers,
        "restorable": summary.restorable,
        "authentication": summary.authentication,
        "targetEnabled": summary.target_enabled,
    })
}

fn redacted_operation_summary(operation: &unpin_core::control::ControlOperationStatus) -> Value {
    json!({
        "operationId": operation.operation_id,
        "operationKind": operation.operation_kind,
        "lifecycle": operation.lifecycle,
        "effectGraphDigest": operation.effect_graph_digest,
        "authorizationRecorded": operation.authorization_recorded,
        "terminalCode": operation.terminal_code,
        "recoveryRequired": operation.recovery_required,
        "resourceCount": operation.resources.len(),
    })
}

fn redacted_group_operation_summary(
    inspection: &unpin_core::groups::GroupOperationInspection,
) -> Value {
    json!({
        "operationId": inspection.operation.operation_id,
        "operationKind": ReachAwareOperationFamily::GroupToggle.as_str(),
        "lifecycle": inspection.operation.lifecycle,
        "qualifiedName": inspection.operation.qualified_name,
        "requestedState": inspection.operation.requested_state,
        "createdAt": inspection.operation.created_at,
        "updatedAt": inspection.operation.updated_at,
        "effectGraphDigest": inspection.operation.plan_fingerprint,
        "authorizationRecorded": true,
        "providerReach": inspection.operation.provider_reach,
        "providerCoverage": inspection.operation.provider_coverage,
        "providerReachLifecycle": inspection.operation.provider_reach_lifecycle,
        "providerWritesStarted": inspection.operation.provider_writes_started,
        "recoveryRequired": inspection.operation.lifecycle
            == unpin_core::groups::GroupOperationLifecycle::RecoveryRequired,
        "resourceCount": inspection
            .cohort_backup_indexes
            .iter()
            .map(|cohort| cohort.resource_ids.len())
            .sum::<usize>(),
        "backupIds": inspection
            .cohort_backup_indexes
            .iter()
            .flat_map(|cohort| cohort.backup_ids.iter())
            .collect::<Vec<_>>(),
        "evidenceAvailable": inspection.evidence_available,
        "finalState": inspection.operation.terminal_result.as_ref().map(|result| result.final_state),
        "observationFresh": inspection.operation.terminal_result.as_ref().map(|result| result.observation_fresh),
        "observationReason": inspection.operation.terminal_result.as_ref().and_then(|result| result.observation_reason.as_ref()),
        "members": inspection.operation.terminal_result.as_ref().map(|result| &result.members),
    })
}

fn redacted_restore_plan(plan: &RestoreControlPlan) -> Value {
    json!({
        "backupId": plan.backup_id,
        "providers": plan.providers,
        "authentication": plan.authentication,
        "affectedResourceIds": plan.affected_resources.iter().map(|resource| &resource.resource_id).collect::<Vec<_>>(),
        "planFingerprint": plan.plan_fingerprint,
    })
}

fn redacted_restore_result(result: &RestoreResult) -> Value {
    json!({
        "status": result.status,
        "backupId": result.backup_id,
        "affectedTargetCount": result.affected_targets.len(),
    })
}

fn snapshot_response(context: &DesktopBridgeContext) -> Result<Value, &'static str> {
    let discovery = discover_all(&context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let agent_plugins = discovery.agent_plugins();
    let resolver = group_resolver(context)?;
    let (groups, group_warnings) = resolver
        .list_views_with_warnings(&discovery)
        .map_err(|_| "group-state-unavailable")?;
    Ok(json!({
        "capturedAtUnix": unix_now(),
        "inventory": discovery.items.iter().map(redacted_item).collect::<Vec<_>>(),
        "warnings": discovery.warnings.iter().map(|warning| json!({
            "provider": warning.provider,
            "layer": warning.layer,
            "code": warning.code,
        })).collect::<Vec<_>>(),
        "agentPluginInventoryComplete": discovery.agent_plugin_inventory_complete(),
        "agentPlugins": agent_plugins.iter().map(redacted_agent_plugin_summary).collect::<Vec<_>>(),
        "groups": groups,
        "groupWarnings": group_warnings.iter().map(|warning| json!({
            "scope": warning.scope,
            "code": warning.code,
        })).collect::<Vec<_>>(),
    }))
}

fn redacted_item(item: &DiscoveryItem) -> Value {
    json!({
        "provider": item.provider,
        "kind": item.kind,
        "category": item.category,
        "layer": item.layer,
        "id": item.id,
        "displayName": item.display_name,
        "enabled": item.enabled,
        "mutability": item.mutability,
    })
}

fn redacted_agent_plugin_summary(package: &AgentPluginSummary) -> Value {
    let providers = package
        .instances
        .iter()
        .map(|instance| instance.provider)
        .collect::<BTreeSet<_>>();
    let component_kinds = package
        .instances
        .iter()
        .flat_map(|instance| instance.components.iter().map(|component| component.kind))
        .collect::<BTreeSet<_>>();
    json!({
        "logicalId": package.logical_id,
        "name": package.name,
        "componentSignature": package.component_signature,
        "projectionFingerprint": package.projection_fingerprint,
        "state": package.state,
        "access": package.access,
        "providers": providers,
        "componentKinds": component_kinds,
        "blockerCount": package.instances.iter().map(|instance| instance.blockers.len()).sum::<usize>(),
        "diagnosticCount": package.instances.iter().map(|instance| instance.diagnostics.len()).sum::<usize>(),
        "instanceCount": package.instances.len(),
        "instances": package.instances.iter().map(redacted_agent_plugin_instance).collect::<Vec<_>>(),
    })
}

fn redacted_agent_plugin_instance(instance: &AgentPluginInstance) -> Value {
    json!({
        "instanceId": instance.instance_id,
        "provider": instance.provider,
        "layer": instance.layer,
        "state": instance.state,
        "access": instance.access,
        "version": instance.manifest.version,
        "components": instance.components.iter().map(|component| json!({
            "kind": component.kind,
            "name": component.name,
            "disposition": component.disposition,
            "reason": component.reason,
        })).collect::<Vec<_>>(),
        "activations": instance.activations.iter().map(|activation| json!({
            "enabled": activation.enabled,
            "mutability": activation.mutability,
        })).collect::<Vec<_>>(),
        "blockers": instance.blockers,
        "diagnostics": instance.diagnostics,
    })
}

fn redacted_agent_plugin_plan(package: &AgentPluginSummary, plan: &BulkTogglePlan) -> Value {
    let mut value = redacted_agent_plugin_summary(package);
    value["operationId"] = json!(plan.operation_id);
    value["planFingerprint"] = json!(plan.plan_fingerprint);
    value["target"] = json!(if plan.target_enabled { "on" } else { "off" });
    value["providerReach"] = json!(plan.provider_reach);
    value["coverage"] = redacted_provider_coverage(&plan.provider_coverage);
    value["lifecycle"] = json!(plan.lifecycle);
    value["counts"] = redacted_agent_plugin_plan_counts(package, plan);
    value["review"] = redacted_agent_plugin_plan_review(package, plan);
    value
}

fn redacted_agent_plugin_plan_counts(package: &AgentPluginSummary, plan: &BulkTogglePlan) -> Value {
    let activations = package
        .instances
        .iter()
        .map(|instance| instance.activations.len())
        .sum::<usize>();
    let components = package
        .instances
        .iter()
        .map(|instance| instance.components.len())
        .sum::<usize>();
    let diagnostics = package
        .instances
        .iter()
        .map(|instance| instance.blockers.len() + instance.diagnostics.len())
        .sum::<usize>();
    json!({
        "instances": package.instances.len(),
        "activations": activations,
        "components": components,
        "diagnostics": diagnostics,
        "included": plan.included_count(),
        "writes": plan.write_count(),
        "noOp": plan.included_count().saturating_sub(plan.write_count()),
        "blocked": plan.blocked_count(),
        "reachExcluded": plan.provider_coverage.reach_excluded_count(),
    })
}

fn redacted_agent_plugin_plan_review(package: &AgentPluginSummary, plan: &BulkTogglePlan) -> Value {
    let included = plan
        .included
        .iter()
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
                "outcome": item.outcome,
            })
        })
        .collect::<Vec<_>>();
    let no_op = plan
        .included
        .iter()
        .filter(|item| item.outcome == IncludedTargetOutcome::NoOp)
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
            })
        })
        .collect::<Vec<_>>();
    let blocked = plan
        .blocked
        .iter()
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
                "reasonCode": item.reason_code,
            })
        })
        .collect::<Vec<_>>();
    let reach_excluded = package
        .instances
        .iter()
        .filter(|instance| !plan.provider_reach.allows(instance.provider))
        .map(|instance| {
            json!({
                "provider": instance.provider,
                "layer": instance.layer,
                "activationCount": instance.activations.len(),
                "reasonCode": "outside-selected-provider-reach",
            })
        })
        .collect::<Vec<_>>();
    let component_diagnostics = package
        .instances
        .iter()
        .flat_map(|instance| {
            let mut rows = instance
                .components
                .iter()
                .filter(|component| {
                    component.disposition != AgentPluginComponentDisposition::Available
                })
                .map(|component| {
                    json!({
                        "provider": instance.provider,
                        "layer": instance.layer,
                        "kind": component.kind,
                        "name": component.name,
                        "disposition": component.disposition,
                        "reason": component.reason,
                    })
                })
                .collect::<Vec<_>>();
            rows.extend(instance.blockers.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "blocked",
                    "reason": reason,
                })
            }));
            rows.extend(instance.diagnostics.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "diagnostic",
                    "reason": reason,
                })
            }));
            rows
        })
        .collect::<Vec<_>>();
    json!({
        "included": included,
        "noOp": no_op,
        "blocked": blocked,
        "reachExcluded": reach_excluded,
        "componentDiagnostics": component_diagnostics,
    })
}

fn redacted_provider_coverage(
    coverage: &unpin_core::provider_reach::ProviderReachCoverage,
) -> Value {
    let mut summaries = BTreeMap::<ProviderId, (usize, usize, BTreeSet<String>)>::new();
    for entry in &coverage.entries {
        let summary = summaries.entry(entry.provider).or_default();
        if entry.included {
            summary.0 += 1;
        } else {
            summary.1 += 1;
        }
        if let Some(reason) = &entry.reason
            && let Ok(Value::String(reason)) = serde_json::to_value(reason)
        {
            summary.2.insert(reason);
        }
    }
    Value::Array(
        summaries
            .into_iter()
            .map(|(provider, (included, excluded, reason_codes))| {
                json!({
                    "provider": provider,
                    "included": included,
                    "excluded": excluded,
                    "reasonCodes": reason_codes,
                })
            })
            .collect(),
    )
}

fn redacted_agent_plugin_apply(
    package: &AgentPluginSummary,
    result: &BulkToggleApplyResult,
) -> Value {
    let mut applied = 0;
    let mut no_op = 0;
    let mut blocked = 0;
    let mut recovery_required = 0;
    let mut backup_count = 0;
    let mut reason_codes = BTreeSet::new();
    for item in &result.items {
        match item.status {
            ToggleStatus::Applied => applied += 1,
            ToggleStatus::DryRun => no_op += 1,
            ToggleStatus::Blocked => blocked += 1,
            ToggleStatus::RecoveryRequired => recovery_required += 1,
        }
        backup_count += usize::from(item.backup_id.is_some());
        if let Some(reason) = &item.reason {
            reason_codes.insert(crate::commands::agent_plugins::safe_reason_code(reason));
        }
    }
    json!({
        "operationId": result.operation_id,
        "planFingerprint": result.plan_fingerprint,
        "lifecycle": result.lifecycle,
        "providerReach": result.provider_reach,
        "coverage": redacted_provider_coverage(&result.provider_coverage),
        "logicalId": package.logical_id,
        "name": package.name,
        "state": package.state,
        "access": package.access,
        "counts": {
            "applied": applied,
            "noOp": no_op,
            "blocked": blocked,
            "recoveryRequired": recovery_required,
            "backupCount": backup_count,
            "reasonCodes": reason_codes,
        },
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn error_response(id: Option<&str>, code: &str) -> Value {
    json!({
        "version": PROTOCOL_VERSION,
        "id": id,
        "error": {"code": code},
    })
}

fn write_response(output: &mut impl Write, response: &Value) -> Result<(), String> {
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
enum FrameStatus {
    Complete,
    Oversized,
}

fn read_frame(input: &mut impl BufRead, frame: &mut Vec<u8>) -> io::Result<Option<FrameStatus>> {
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

fn discard_to_newline(input: &mut impl BufRead) -> io::Result<()> {
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

    fn agent_plugin_fixture_context(root: &std::path::Path) -> DesktopBridgeContext {
        let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CLI crate has a workspace crates parent")
            .join("unpin-core")
            .join("tests")
            .join("fixtures");
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
        let discovery = discover_all(&context.discovery_roots).expect("fresh discovery");
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
