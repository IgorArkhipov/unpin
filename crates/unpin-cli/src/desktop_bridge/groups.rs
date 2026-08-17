use super::*;

use serde_json::{Value, json};

pub(super) fn plan_group(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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

pub(super) fn approve_group(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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

pub(super) fn apply_group(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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
    let result = invalidate_after_discovery_change(
        &state.context,
        controller
            .apply(&plan, authorization)
            .map_err(|_| "group-apply-blocked"),
    )?;
    state.reviewed_groups.remove(operation_id);
    Ok(json!({"result": result}))
}

pub(super) fn discard_group(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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
pub(super) fn plan_definition_change(
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

pub(super) fn apply_definition_change(
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
    invalidate_discovery(&state.context);
    Ok(result)
}

pub(super) fn discard_definition_change(
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

pub(super) fn definition_history(
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

pub(super) fn definition_change_from_params(
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

pub(super) fn definition_from_params(
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

pub(super) fn resolved_group_record(
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

pub(super) fn required_group_scope(params: &Value, key: &str) -> Result<GroupScope, &'static str> {
    required_string(params, key)?
        .parse()
        .map_err(|_| "invalid-group-scope")
}

pub(super) fn required_group_revision(
    params: &Value,
    key: &str,
) -> Result<GroupRevision, &'static str> {
    GroupRevision::parse(required_string(params, key)?).map_err(|_| "invalid-group-revision")
}

pub(super) fn optional_group_revision(
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

pub(super) fn validate_definition_members(
    context: &DesktopBridgeContext,
    definition: &GroupDefinitionV1,
    retained: BTreeSet<GroupMemberIdentity>,
) -> Result<(), &'static str> {
    let group_context = group_access_context(context)?;
    validate_new_group_members(&group_context, definition, &retained)
        .map_err(|_| "group-definition-members-blocked")
}

pub(super) fn definition_revision(
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

pub(super) fn next_definition_operation_id(
    state: &mut DesktopBridgeState,
) -> Result<String, &'static str> {
    state.next_definition_plan_id = state
        .next_definition_plan_id
        .checked_add(1)
        .ok_or("group-definition-session-exhausted")?;
    Ok(format!("definition-{}", state.next_definition_plan_id))
}

pub(super) fn require_group_write_sandbox(
    context: &DesktopBridgeContext,
) -> Result<(), &'static str> {
    let group_context = group_access_context(context)?;
    require_fixture_group_write_sandbox(
        context.fixture_mode,
        group_context.app_state_root(),
        group_context.workspace_root(),
        &context.discovery_roots,
    )
}

pub(super) fn require_fixture_bridge_sandbox(
    context: &DesktopBridgeContext,
) -> Result<(), &'static str> {
    require_fixture_group_write_sandbox(
        context.fixture_mode,
        &context.config.app_state_root,
        &context.config.project_root,
        &context.discovery_roots,
    )
}

pub(super) fn require_fixture_group_write_sandbox(
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

pub(super) fn definition_store(
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

pub(super) fn definition_owner() -> OwnerGeneration {
    OwnerGeneration::new(GROUP_DEFINITION_OWNER_ID, 1).expect("static owner is valid")
}

pub(super) fn apply_reviewed_definition_change(
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

pub(super) fn redacted_definition_plan(
    action: &DefinitionChangeAction,
    plan_fingerprint: &str,
) -> Value {
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

pub(super) fn redacted_definition_change_result(
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

pub(super) fn redacted_definition_history(
    record: &unpin_core::groups::GroupHistoryRecord,
) -> Value {
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
