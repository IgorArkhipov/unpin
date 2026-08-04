use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use unpin_core::{
    approval::ControlApprovalContext,
    config::UnpinConfig,
    control::build_control_status,
    control_operation::ReachAwareOperationFamily,
    discovery::{DiscoveryItem, DiscoveryRoots, discover_all},
    groups::{
        GROUP_DEFINITION_OWNER_ID, GroupAccessContext, GroupController, GroupDefinitionV1,
        GroupMemberIdentity, GroupPlanDisposition, GroupPlanMode, GroupPlanner, GroupRef,
        GroupResolver, GroupRevision, GroupScope, GroupTargetState, GroupTogglePlan,
        MAX_GROUP_MEMBERS, PersonalGroupStore, RepositoryGroupStore,
        list_group_operation_inspections, validate_new_group_members,
    },
    mutation::{
        BackupAuthenticationKey, RestoreControlPlan, RestoreController, RestoreResult,
        load_backup_summaries_authenticated,
    },
    provider_reach::ProviderReach,
    sessions::SessionAuthorityKey,
    state::atomic_json::OwnerGeneration,
};

use crate::{credentials, group_store::ScopedGroupStore};

pub(crate) const PROTOCOL_VERSION: u64 = 2;
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_REVIEWED_DEFINITION_PLANS: usize = 32;
const METHOD_HANDSHAKE: &str = "handshake";
const METHOD_SNAPSHOT: &str = "snapshot";
const METHOD_GROUP_PLAN: &str = "group.plan";
const METHOD_GROUP_APPROVE: &str = "group.approve";
const METHOD_GROUP_APPLY: &str = "group.apply";
const METHOD_GROUP_DEFINITION_PLAN: &str = "group.definition.plan";
const METHOD_GROUP_DEFINITION_APPLY: &str = "group.definition.apply";
const METHOD_GROUP_DEFINITION_HISTORY: &str = "group.definition.history";
const METHOD_RECOVERY_SNAPSHOT: &str = "recovery.snapshot";
const METHOD_RESTORE_PLAN: &str = "restore.plan";
const METHOD_RESTORE_APPROVE: &str = "restore.approve";
const METHOD_RESTORE_APPLY: &str = "restore.apply";
const METHOD_SHUTDOWN: &str = "shutdown";
const BRIDGE_CAPABILITIES: &[&str] = &[
    METHOD_SNAPSHOT,
    METHOD_GROUP_PLAN,
    METHOD_GROUP_APPROVE,
    METHOD_GROUP_APPLY,
    METHOD_GROUP_DEFINITION_PLAN,
    METHOD_GROUP_DEFINITION_APPLY,
    METHOD_GROUP_DEFINITION_HISTORY,
    METHOD_RECOVERY_SNAPSHOT,
    METHOD_RESTORE_PLAN,
    METHOD_RESTORE_APPROVE,
    METHOD_RESTORE_APPLY,
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
    let mut state = DesktopBridgeState {
        context,
        reviewed_groups: Default::default(),
        reviewed_restores: Default::default(),
        reviewed_definitions: Default::default(),
        next_definition_plan_id: 0,
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
    reviewed_groups: BTreeMap<String, ReviewedGroupPlan>,
    reviewed_restores: BTreeMap<String, ReviewedRestorePlan>,
    reviewed_definitions: BTreeMap<String, ReviewedDefinitionChange>,
    next_definition_plan_id: u64,
}

struct ReviewedGroupPlan {
    plan: GroupTogglePlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
}

struct ReviewedRestorePlan {
    plan: RestoreControlPlan,
    authorization: Option<unpin_core::approval::ControlAuthorization>,
}

#[derive(Clone)]
struct ReviewedDefinitionChange {
    action: DefinitionChangeAction,
    plan_fingerprint: String,
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
        METHOD_HANDSHAKE => Ok(handshake_response()),
        METHOD_SNAPSHOT => snapshot_response(&state.context),
        METHOD_GROUP_PLAN => plan_group(state, &request.params),
        METHOD_GROUP_APPROVE => approve_group(state, &request.params),
        METHOD_GROUP_APPLY => apply_group(state, &request.params),
        METHOD_GROUP_DEFINITION_PLAN => plan_definition_change(state, &request.params),
        METHOD_GROUP_DEFINITION_APPLY => apply_definition_change(state, &request.params),
        METHOD_GROUP_DEFINITION_HISTORY => definition_history(&state.context, &request.params),
        METHOD_RECOVERY_SNAPSHOT => recovery_snapshot_response(&state.context),
        METHOD_RESTORE_PLAN => plan_restore(state, &request.params),
        METHOD_RESTORE_APPROVE => approve_restore(state, &request.params),
        METHOD_RESTORE_APPLY => apply_restore(state, &request.params),
        METHOD_SHUTDOWN => Ok(json!({"shutdown": true})),
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
        "capabilities": BRIDGE_CAPABILITIES,
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
    let result = controller
        .apply(&plan, authorization)
        .map_err(|_| "group-apply-blocked")?;
    Ok(json!({"result": result}))
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
    require_definition_write_sandbox(&state.context)?;
    let result = apply_reviewed_definition_change(&state.context, &action)?;
    state.reviewed_definitions.remove(operation_id);
    Ok(result)
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

fn require_definition_write_sandbox(context: &DesktopBridgeContext) -> Result<(), &'static str> {
    let group_context = group_access_context(context)?;
    unpin_core::fixture::require_fixture_write_sandbox(
        context.fixture_mode,
        [
            group_context.app_state_root(),
            group_context.workspace_root(),
        ],
    )
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
    state.reviewed_restores.insert(
        operation_id.clone(),
        ReviewedRestorePlan {
            plan: plan.clone(),
            authorization: None,
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
    let (backups, backup_status) = match backup_key.as_ref() {
        Ok(key) => (
            load_backup_summaries_authenticated(&context.config.app_state_root, Some(key))
                .iter()
                .map(redacted_backup_summary)
                .collect::<Vec<_>>(),
            "available",
        ),
        Err(_) => (Vec::new(), "unavailable"),
    };
    let (mut operations, control_operation_status) = control_operation_summaries(context);
    let (group_operations, group_operation_status) =
        group_operation_summaries(context, backup_key.as_ref().ok());
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
) -> (Vec<Value>, &'static str) {
    let Some(backup_key) = backup_key else {
        return (Vec::new(), "unavailable");
    };
    let Ok(group_context) = group_access_context(context) else {
        return (Vec::new(), "unavailable");
    };
    match list_group_operation_inspections(
        group_context.app_state_root(),
        backup_key.clone(),
        group_context.repository_key(),
        group_context.workspace_key(),
    ) {
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
        "effectGraphDigest": inspection.operation.plan_fingerprint,
        "authorizationRecorded": true,
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
