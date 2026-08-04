use std::{
    collections::BTreeSet,
    io::{self, BufRead, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use unpin_core::{
    approval::ControlApprovalContext,
    config::UnpinConfig,
    discovery::{DiscoveryItem, DiscoveryRoots, discover_all},
    groups::{
        GroupAccessContext, GroupController, GroupPlanDisposition, GroupPlanMode, GroupPlanner,
        GroupRef, GroupResolver, GroupTargetState, GroupTogglePlan, MAX_GROUP_MEMBERS,
        PersonalGroupStore, RepositoryGroupStore,
    },
    mutation::BackupAuthenticationKey,
    provider_reach::ProviderReach,
    sessions::SessionAuthorityKey,
};

use crate::credentials;

pub(crate) const PROTOCOL_VERSION: u64 = 1;
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_REQUEST_ID_BYTES: usize = 128;

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
    let mut state = DesktopBridgeState {
        context,
        reviewed_groups: Default::default(),
    };
    let mut seen_request_ids = BTreeSet::new();
    let mut frame = Vec::with_capacity(4096);
    while let Some(frame_status) =
        read_frame(&mut input, &mut frame).map_err(|error| error.to_string())?
    {
        if frame_status == FrameStatus::Oversized {
            write_response(&mut output, &error_response(None, "frame-too-large"))?;
            continue;
        }
        let response = match parse_request(&frame) {
            Ok(request) if !seen_request_ids.insert(request.id.clone()) => {
                error_response(Some(&request.id), "duplicate-request-id")
            }
            Ok(request) => handle_request(&mut state, request),
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
}

struct DesktopBridgeState {
    context: DesktopBridgeContext,
    reviewed_groups: std::collections::BTreeMap<String, ReviewedGroupPlan>,
}

struct ReviewedGroupPlan {
    plan: GroupTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
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
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "version" | "id" | "method" | "params"))
    {
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
    })
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_ID_BYTES && !value.chars().any(char::is_control)
}

fn handle_request(state: &mut DesktopBridgeState, request: Request) -> Value {
    let result = match request.method.as_str() {
        "handshake" => Ok(handshake_response()),
        "snapshot" => snapshot_response(&state.context),
        "group.plan" => plan_group(state, &request.params),
        "group.approve" => approve_group(state, &request.params),
        "group.apply" => apply_group(state, &request.params),
        "shutdown" => Ok(json!({"shutdown": true})),
        _ => Err("unknown-method"),
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

fn handshake_response() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "binaryVersion": env!("CARGO_PKG_VERSION"),
        "capabilities": ["snapshot", "group.plan", "group.approve", "group.apply"],
    })
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
        state.reviewed_groups.insert(
            operation_id,
            ReviewedGroupPlan {
                plan: plan.clone(),
                authorization: None,
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
    let group_context = group_access_context(&state.context)?;
    let approval_context = ControlApprovalContext::new(
        group_context.repository_key(),
        group_context.workspace_key(),
    )
    .map_err(|_| "approval-context-unavailable")?;
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
    let result = controller
        .apply(&plan, authorization)
        .map_err(|_| "group-apply-blocked")?;
    Ok(json!({"result": result}))
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

fn group_access_context(
    context: &DesktopBridgeContext,
) -> Result<GroupAccessContext, &'static str> {
    GroupAccessContext::from_config(&context.config, &context.discovery_roots, None, None)
        .map_err(|_| "group-context-unavailable")
}

fn group_planner(context: &DesktopBridgeContext) -> Result<GroupPlanner, &'static str> {
    let group_context = group_access_context(context)?;
    Ok(GroupPlanner::new(GroupResolver::new(
        group_context.clone(),
        PersonalGroupStore::new(group_context.clone()),
        RepositoryGroupStore::new(group_context),
    )))
}

fn group_controller(context: &DesktopBridgeContext) -> Result<GroupController, &'static str> {
    let backup_key = credentials::resolve_backup_authentication_key(
        context.fixture_mode,
        &context.config.app_state_root,
    )
    .map_err(|_| "backup-authentication-unavailable")?
    .ok_or("backup-authentication-unavailable")?;
    let session_key = credentials::resolve_session_authority_key(
        context.fixture_mode,
        &context.config.app_state_root,
    )
    .map_err(|_| "session-authority-unavailable")?
    .ok_or("session-authority-unavailable")?;
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

fn snapshot_response(context: &DesktopBridgeContext) -> Result<Value, &'static str> {
    let discovery = discover_all(&context.discovery_roots).map_err(|_| "discovery-unavailable")?;
    let group_context =
        GroupAccessContext::from_config(&context.config, &context.discovery_roots, None, None)
            .map_err(|_| "group-context-unavailable")?;
    let resolver = GroupResolver::new(
        group_context.clone(),
        PersonalGroupStore::new(group_context.clone()),
        RepositoryGroupStore::new(group_context),
    );
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
