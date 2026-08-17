use super::*;

use serde_json::{Value, json};

pub(super) fn inspect_agent_plugin(
    state: &DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["logicalId"])?;
    let logical_id = required_string(params, "logicalId")?;
    let discovery = cached_discovery(&state.context)?;
    let package = discovery
        .agent_plugins()
        .into_iter()
        .find(|package| package.logical_id == logical_id)
        .ok_or("agent-plugin-not-found")?;
    Ok(json!({"package": redacted_agent_plugin_summary(&package)}))
}

pub(super) fn plan_agent_plugin(
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
    let discovery = fresh_discovery(&state.context)?;
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

pub(super) fn approve_agent_plugin(
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

pub(super) fn apply_agent_plugin(
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
    let live_discovery = fresh_discovery(&state.context)?;
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
        .apply_with_reach_aware(&plan, authorization, durable, live_discovery)
        .map_err(|_| "agent-plugin-recovery-required")?;
    state.reviewed_agent_plugins.remove(operation_id);
    let refreshed = fresh_discovery(&state.context).ok().and_then(|discovery| {
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

pub(super) fn discard_agent_plugin(
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

pub(super) fn agent_plugin_plan_error_code(error: BulkTogglePlanError) -> &'static str {
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

pub(super) fn unprefixed_plan_fingerprint(fingerprint: &str) -> &str {
    fingerprint.strip_prefix("sha256:").unwrap_or(fingerprint)
}
