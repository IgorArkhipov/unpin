use super::*;

use serde_json::{Value, json};

pub(super) fn plan_restore(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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

pub(super) fn approve_restore(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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

pub(super) fn apply_restore(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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
    invalidate_discovery(&state.context);
    Ok(json!({"result": redacted_restore_result(&result)}))
}

pub(super) fn discard_restore(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
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
