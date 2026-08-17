use super::*;

use serde_json::{Value, json};

pub(super) fn individual_reach_inputs(
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct McpAgentPluginCoverage {
    instance_count: usize,
    actionable_instance_count: usize,
    diagnostics_only_instance_count: usize,
    component_count: usize,
    activation_count: usize,
    providers: Vec<ProviderId>,
    layers: Vec<DiscoveryLayer>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct McpAgentPluginComponentView {
    kind: AgentPluginComponentKind,
    name: String,
    disposition: AgentPluginComponentDisposition,
    providers: Vec<ProviderId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct McpAgentPluginActivationCoverage {
    total: usize,
    enabled: usize,
    disabled: usize,
    writable: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct McpAgentPluginInstanceView {
    provider: ProviderId,
    layer: DiscoveryLayer,
    state: AgentPluginState,
    access: AgentPluginAccess,
    activation_coverage: McpAgentPluginActivationCoverage,
    components: Vec<McpAgentPluginComponentView>,
    blockers: Vec<String>,
    diagnostics: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct McpAgentPluginView {
    logical_id: String,
    name: String,
    component_signature: String,
    projection_fingerprint: String,
    state: AgentPluginState,
    access: AgentPluginAccess,
    coverage: McpAgentPluginCoverage,
    components: Vec<McpAgentPluginComponentView>,
    blocker_count: usize,
    diagnostic_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    instances: Vec<McpAgentPluginInstanceView>,
}

pub(super) fn list_agent_plugins(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_empty_object(arguments)?;
    let discovery = match context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)
    {
        Ok(discovery) => discovery,
        Err(_) => return Ok(agent_plugin_discovery_error_value()),
    };
    let discovery = context
        .provider_scope
        .filter_discovery((*discovery).clone());
    let packages = scoped_agent_plugins(&discovery, context.provider_scope);
    let diagnostic_package_count = packages
        .iter()
        .filter(|package| package.access != AgentPluginAccess::Actionable)
        .count();
    let packages = packages
        .iter()
        .map(|package| mcp_agent_plugin_value(package, false))
        .collect::<Vec<_>>();
    Ok(json!({
        "statusVersion": 1,
        "status": "ok",
        "providerScope": context.provider_scope.as_str(),
        "inventoryComplete": discovery.agent_plugin_inventory_complete(),
        "packageCount": packages.len(),
        "diagnosticPackageCount": diagnostic_package_count,
        "packages": packages,
    }))
}

pub(super) fn inspect_agent_plugin(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["logicalId"],
        "agent plugin inspection arguments",
    )?;
    let logical_id = required_string(arguments, "logicalId")?;
    let discovery = match context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)
    {
        Ok(discovery) => discovery,
        Err(_) => return Ok(agent_plugin_discovery_error_value()),
    };
    let Some(package) = scoped_agent_plugins(&discovery, context.provider_scope)
        .into_iter()
        .find(|package| package.logical_id == logical_id)
    else {
        return Ok(agent_plugin_not_found_value());
    };
    Ok(json!({
        "statusVersion": 1,
        "status": "ok",
        "providerScope": context.provider_scope.as_str(),
        "package": mcp_agent_plugin_value(&package, true),
        "guidance": agent_plugin_guidance(package.access),
    }))
}

pub(super) fn plan_agent_plugin_toggle(context: &McpContext, arguments: &Value) -> Value {
    if let Err(error) = require_only_fields(
        arguments,
        &["logicalId", "targetEnabled", "providerReach"],
        "agent plugin plan arguments",
    ) {
        return invalid_arguments_value(error);
    }
    let logical_id = match required_string(arguments, "logicalId") {
        Ok(logical_id) => logical_id,
        Err(error) => return invalid_arguments_value(error),
    };
    let Some(target_enabled) = arguments.get("targetEnabled").and_then(Value::as_bool) else {
        return invalid_arguments_value("missing required field: targetEnabled".to_string());
    };
    let Some(reach_value) = arguments.get("providerReach") else {
        return invalid_arguments_value("missing required field: providerReach".to_string());
    };
    let reach =
        match parse_bulk_provider_reach(Some(reach_value), context.provider_scope.provider()) {
            Ok(ProviderReachInput::Omitted) => {
                return invalid_arguments_value(
                    "providerReach must explicitly select one provider or all providers"
                        .to_string(),
                );
            }
            Ok(reach) => reach,
            Err(error) => return invalid_arguments_value(error),
        };
    let discovery = match context.discovery_cache.refresh(&context.discovery_roots) {
        Ok(discovery) => discovery,
        Err(_) => return agent_plugin_discovery_error_value(),
    };
    let discovery = context
        .provider_scope
        .filter_discovery((*discovery).clone());
    let Some(package) = scoped_agent_plugins(&discovery, context.provider_scope)
        .into_iter()
        .find(|package| package.logical_id == logical_id)
    else {
        return agent_plugin_not_found_value();
    };

    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let mut request =
        match BulkToggleRequest::for_agent_plugin_summary(&discovery, &package, target_enabled) {
            Ok(request) => request,
            Err(error) => return agent_plugin_plan_error_value(&package, &error),
        };
    request = request.with_reach(boundary, reach);
    if let ProviderReachInput::Selected {
        provider,
        provenance,
    } = reach
    {
        request = request.with_authority(SelectedProviderAuthority::new(provider, provenance));
    }
    if let Err(error) = BulkToggleController::validate_before_discovery(&request) {
        return agent_plugin_plan_error_value(&package, &error);
    }
    let plan = match BulkToggleController::new(&context.app_state_root)
        .plan_agent_plugin_from_discovery(discovery, request, &package)
    {
        Ok(plan) => plan,
        Err(error) => return agent_plugin_plan_error_value(&package, &error),
    };
    agent_plugin_plan_value(context, &package, &plan)
}

pub(super) fn scoped_agent_plugins(
    discovery: &DiscoveryOutput,
    scope: McpProviderScope,
) -> Vec<AgentPluginSummary> {
    discovery
        .agent_plugins()
        .into_iter()
        .filter_map(|mut package| {
            package
                .instances
                .retain(|instance| scope.allows(instance.provider));
            if package.instances.is_empty() {
                return None;
            }
            package.refresh_rollup();
            Some(package)
        })
        .collect()
}

pub(super) fn mcp_agent_plugin_value(
    package: &AgentPluginSummary,
    include_instances: bool,
) -> Value {
    let providers = package
        .instances
        .iter()
        .map(|instance| instance.provider)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let layers = package
        .instances
        .iter()
        .map(|instance| instance.layer)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let blocker_count = package
        .instances
        .iter()
        .map(|instance| instance.blockers.len())
        .sum();
    let diagnostic_count = package
        .instances
        .iter()
        .map(|instance| instance.diagnostics.len())
        .sum();
    let instances = if include_instances {
        package
            .instances
            .iter()
            .map(mcp_agent_plugin_instance)
            .collect()
    } else {
        Vec::new()
    };
    let view = McpAgentPluginView {
        logical_id: package.logical_id.clone(),
        name: package.name.clone(),
        component_signature: package.component_signature.clone(),
        projection_fingerprint: package.projection_fingerprint.clone(),
        state: package.state,
        access: package.access,
        coverage: McpAgentPluginCoverage {
            instance_count: package.instances.len(),
            actionable_instance_count: package
                .instances
                .iter()
                .filter(|instance| instance.access == AgentPluginAccess::Actionable)
                .count(),
            diagnostics_only_instance_count: package
                .instances
                .iter()
                .filter(|instance| instance.access == AgentPluginAccess::DiagnosticsOnly)
                .count(),
            component_count: package
                .instances
                .iter()
                .map(|instance| instance.components.len())
                .sum(),
            activation_count: package
                .instances
                .iter()
                .map(|instance| instance.activations.len())
                .sum(),
            providers,
            layers,
        },
        components: mcp_agent_plugin_components(&package.instances),
        blocker_count,
        diagnostic_count,
        instances,
    };
    serde_json::to_value(view).expect("public agent plugin view serializes")
}

pub(super) fn mcp_agent_plugin_components(
    instances: &[AgentPluginInstance],
) -> Vec<McpAgentPluginComponentView> {
    let mut components = BTreeMap::<
        (
            AgentPluginComponentKind,
            String,
            AgentPluginComponentDisposition,
            Option<String>,
        ),
        BTreeSet<ProviderId>,
    >::new();
    for instance in instances {
        for component in &instance.components {
            components
                .entry((
                    component.kind,
                    component.name.clone(),
                    component.disposition,
                    component.reason.clone(),
                ))
                .or_default()
                .insert(instance.provider);
        }
    }
    components
        .into_iter()
        .map(
            |((kind, name, disposition, reason), providers)| McpAgentPluginComponentView {
                kind,
                name,
                disposition,
                providers: providers.into_iter().collect(),
                reason,
            },
        )
        .collect()
}

pub(super) fn mcp_agent_plugin_instance(
    instance: &AgentPluginInstance,
) -> McpAgentPluginInstanceView {
    let enabled = instance
        .activations
        .iter()
        .filter(|activation| activation.enabled)
        .count();
    let writable = instance
        .activations
        .iter()
        .filter(|activation| {
            activation.mutability == crate::discovery::DiscoveryMutability::ReadWrite
        })
        .count();
    McpAgentPluginInstanceView {
        provider: instance.provider,
        layer: instance.layer,
        state: instance.state,
        access: instance.access,
        activation_coverage: McpAgentPluginActivationCoverage {
            total: instance.activations.len(),
            enabled,
            disabled: instance.activations.len().saturating_sub(enabled),
            writable,
        },
        components: mcp_agent_plugin_components(std::slice::from_ref(instance)),
        blockers: instance.blockers.clone(),
        diagnostics: instance.diagnostics.clone(),
    }
}

pub(super) fn agent_plugin_plan_value(
    context: &McpContext,
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
    let review = agent_plugin_plan_review_value(package, plan);
    let reach_excluded_count = review["reachExcluded"].as_array().map_or(0, Vec::len);
    let activation_count = package
        .instances
        .iter()
        .map(|instance| instance.activations.len())
        .sum::<usize>();
    let diagnostics = package
        .instances
        .iter()
        .map(|instance| instance.blockers.len() + instance.diagnostics.len())
        .sum::<usize>();
    let lifecycle = provider_reach_lifecycle_name(plan.lifecycle);
    let coverage = agent_plugin_plan_coverage_value(package, plan);
    let mut response = json!({
        "statusVersion": 1,
        "status": lifecycle,
        "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "coverage": coverage,
        "targetEnabled": plan.target_enabled,
        "package": mcp_agent_plugin_value(package, false),
        "counts": {
            "instances": package.instances.len(),
            "activations": activation_count,
            "components": package.instances.iter().map(|instance| instance.components.len()).sum::<usize>(),
            "diagnostics": diagnostics,
            "included": plan.included_count(),
            "writes": plan.write_count(),
            "noOp": plan.included_count().saturating_sub(plan.write_count()),
            "blocked": plan.blocked_count(),
            "reachExcluded": reach_excluded_count,
        },
        "review": review,
        "guidance": agent_plugin_lifecycle_guidance(plan.lifecycle),
    });

    if plan.write_count() == 0 {
        response["operation"] = json!({
            "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
            "operationId": plan.operation_id,
            "operationKind": "agent-plugin-toggle",
            "planFingerprint": plan.plan_fingerprint,
            "lifecycle": lifecycle,
            "expectedLifecycle": lifecycle,
            "providerReach": plan.provider_reach,
            "coverage": coverage,
        });
        response["continuation"] = json!({
            "humanActionRequired": false,
            "guidance": agent_plugin_lifecycle_guidance(plan.lifecycle),
        });
        return response;
    }

    let operation_v2 = match seal_bulk_toggle_handoff(context, plan, true) {
        Ok(operation) => operation,
        Err(_) => {
            return json!({
                "status": "blocked",
                "reasonCode": "handoff-unavailable",
                "reason": "A durable package handoff could not be sealed with the current Unpin credentials and workspace binding.",
                "package": mcp_agent_plugin_value(package, false),
            });
        }
    };
    let approval_context = match control_approval_context(context) {
        Ok(context) => context,
        Err(_) => {
            return json!({
                "status": "blocked",
                "reasonCode": "workspace-binding-unavailable",
                "reason": "The current Unpin workspace binding is unavailable for a durable package handoff.",
                "package": mcp_agent_plugin_value(package, false),
            });
        }
    };
    let expires_at_unix = operation_v2
        .get("expiresAtUnix")
        .cloned()
        .unwrap_or(Value::Null);
    let cli_argv = json!([
        "agent-plugins",
        "apply",
        package.logical_id,
        "--operation-id",
        plan.operation_id,
        "--plan-fingerprint",
        plan.plan_fingerprint,
        "--app-state-root",
        context.app_state_root,
        "--adopt-sealed-roots",
        "--confirm"
    ]);
    response["status"] = json!("human-action-required");
    response["operation"] = json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "operationId": plan.operation_id,
        "operationKind": "agent-plugin-toggle",
        "planFingerprint": plan.plan_fingerprint,
        "lifecycle": "awaiting-human-action",
        "expectedLifecycle": lifecycle,
        "activation": "live",
        "providerReach": plan.provider_reach,
        "coverage": coverage,
        "workspaceBinding": {
            "repositoryKey": approval_context.repository_key(),
            "workspaceKey": approval_context.workspace_key(),
        },
        "humanAction": {
            "code": "confirm-and-apply",
                "guidance": "Review package coverage. CLI may adopt the sealed handoff; desktop creates a fresh local review."
        }
    });
    response["handoff"] = json!({
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "expiresAtUnix": expires_at_unix,
    });
    response["continuation"] = json!({
        "humanActionRequired": true,
        "cli": {
            "command": "unpin",
            "argv": cli_argv,
        },
        "desktop": {
            "action": "plan-agent-plugin-toggle",
            "logicalId": package.logical_id,
            "targetEnabled": plan.target_enabled,
            "providerReach": plan.provider_reach,
            "selectedProvider": plan.provider_reach.provider(),
            "handoffAdoption": false,
        },
        "guidance": "MCP cannot apply provider writes. Use the sealed CLI handoff or create a fresh desktop review."
    });
    response
}

pub(super) fn agent_plugin_plan_review_value(
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
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
        .filter(|item| item.outcome == crate::provider_reach::IncludedTargetOutcome::NoOp)
        .map(|item| json!({ "provider": item.item.provider, "layer": item.item.layer }))
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
            let mut diagnostics = instance
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
            diagnostics.extend(instance.blockers.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "blocked",
                    "reason": reason,
                })
            }));
            diagnostics.extend(instance.diagnostics.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "diagnostic",
                    "reason": reason,
                })
            }));
            diagnostics
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

pub(super) fn agent_plugin_plan_coverage_value(
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
    Value::Array(
        package
            .instances
            .iter()
            .map(|instance| {
                let included = plan.provider_reach.allows(instance.provider);
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "included": included,
                    "activationCount": instance.activations.len(),
                    "reasonCode": (!included).then_some("outside-selected-provider-reach"),
                })
            })
            .collect(),
    )
}

pub(super) fn agent_plugin_plan_error_value(
    package: &AgentPluginSummary,
    error: &BulkTogglePlanError,
) -> Value {
    let (reason_code, reason) = match error {
        BulkTogglePlanError::AgentPluginHasNoActivationAnchors => (
            "agent-plugin-no-activation-anchors",
            "The package has no native activation anchors that Unpin can plan.",
        ),
        BulkTogglePlanError::AgentPluginInventoryIncomplete => (
            "agent-plugin-inventory-incomplete",
            "Agent Plugin cache inventory is incomplete. Refresh discovery before planning a package toggle.",
        ),
        BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors => (
            "agent-plugin-diagnostics-only-writable-activation-anchors",
            "The package has diagnostics-only writable native activation anchors and cannot be safely toggled.",
        ),
        BulkTogglePlanError::AgentPluginHasNoActionableActivationAnchors => (
            "agent-plugin-no-actionable-activation-anchors",
            "The package is diagnostics-only and has no safely actionable native activation anchors.",
        ),
        BulkTogglePlanError::NoTargetsInProviderReach => (
            "no-targets-in-provider-reach",
            "The selected provider reach contains no package activation anchors.",
        ),
        BulkTogglePlanError::ProviderReach(_) => (
            "invalid-provider-reach",
            "The requested provider reach is not authorized by this MCP connection.",
        ),
        _ => (
            "agent-plugin-plan-blocked",
            "The package plan could not be created from fresh discovery.",
        ),
    };
    json!({
        "status": "blocked",
        "reasonCode": reason_code,
        "reason": reason,
        "package": mcp_agent_plugin_value(package, false),
        "guidance": agent_plugin_guidance(package.access),
    })
}

pub(super) fn agent_plugin_not_found_value() -> Value {
    json!({
        "status": "blocked",
        "reasonCode": "agent-plugin-not-found",
        "reason": "Agent Plugin package was not found in the current MCP provider scope; refresh the inventory and use its logical id.",
    })
}

pub(super) fn agent_plugin_discovery_error_value() -> Value {
    json!({
        "status": "blocked",
        "reasonCode": "agent-plugin-discovery-failed",
        "reason": "Agent Plugin discovery could not be completed in the current MCP provider scope.",
    })
}

pub(super) fn invalid_arguments_value(reason: String) -> Value {
    json!({
        "status": "blocked",
        "reasonCode": "invalid-arguments",
        "reason": reason,
    })
}

pub(super) const fn agent_plugin_guidance(access: AgentPluginAccess) -> &'static str {
    match access {
        AgentPluginAccess::Actionable => {
            "Package state is derived from native provider activation anchors; review a package plan before applying in Unpin CLI or desktop."
        }
        AgentPluginAccess::DiagnosticsOnly => {
            "Diagnostics-only package: inspect component dispositions and native activation coverage; no apply handoff is available."
        }
        AgentPluginAccess::Unsupported => {
            "Package control is unsupported for this provider and layer; no apply handoff is available."
        }
    }
}

pub(super) const fn agent_plugin_lifecycle_guidance(
    lifecycle: ProviderReachLifecycle,
) -> &'static str {
    match lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => {
            "Review included, no-op, blocked, and reach-excluded package members before human apply."
        }
        ProviderReachLifecycle::NoOp => {
            "All included native activation anchors already match the requested package state."
        }
        ProviderReachLifecycle::NoTargetsInProviderReach => {
            "Choose explicit reach containing an existing native activation anchor and replan."
        }
        ProviderReachLifecycle::Blocked => {
            "No apply handoff is available; resolve package diagnostics and refresh discovery."
        }
        ProviderReachLifecycle::RecoveryRequired => {
            "Do not reapply; inspect the durable operation and recovery evidence."
        }
    }
}

pub(super) const fn provider_reach_lifecycle_name(
    lifecycle: ProviderReachLifecycle,
) -> &'static str {
    match lifecycle {
        ProviderReachLifecycle::Applied => "planned",
        ProviderReachLifecycle::Partial => "partial",
        ProviderReachLifecycle::NoOp => "no-op",
        ProviderReachLifecycle::NoTargetsInProviderReach => "no-targets-in-provider-reach",
        ProviderReachLifecycle::Blocked => "blocked",
        ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    }
}
