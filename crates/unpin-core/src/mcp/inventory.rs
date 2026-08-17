use super::*;

use serde_json::{Value, json};

pub(super) fn get_inventory_summary(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
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

pub(super) fn list_items(context: &McpContext, arguments: &Value) -> Result<Value, String> {
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
pub(super) fn list_backups(context: &McpContext, arguments: &Value) -> Value {
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
            !summary.providers.is_empty()
                && summary
                    .providers
                    .iter()
                    .all(|summary_provider| summary_provider == provider.as_str())
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

pub(super) fn backup_summary_value(summary: BackupSummary) -> Value {
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

pub(super) fn restore_backup_tool(context: &McpContext, arguments: &Value) -> Value {
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
    if let Err(error) = context.provider_scope.require_allowed_all(&plan.providers) {
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
    let operation = control_operation_with_provider_coverage(
        &expectation,
        &fingerprint,
        plan.activation,
        lifecycle,
        plan.providers.clone(),
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

pub(super) fn selected_item(
    context: &McpContext,
    arguments: &Value,
) -> Result<DiscoveryItem, String> {
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
