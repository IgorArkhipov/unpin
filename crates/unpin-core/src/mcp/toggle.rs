use super::*;

use serde_json::{Value, json};

pub(super) fn plan_single_toggle(context: &McpContext, arguments: &Value) -> Value {
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

pub(super) fn apply_single_toggle(context: &McpContext, arguments: &Value) -> Value {
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

pub(super) fn seal_native_toggle_handoff(
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
                crate::mutation::BULK_TOGGLE_PROVIDER_ROOT_PROVENANCE.to_string(),
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

pub(super) fn plan_bulk_toggle_items(context: &McpContext, arguments: &Value) -> Value {
    match build_bulk_plan(context, arguments) {
        Ok((plan, warnings)) => bulk_plan_value(&plan, warnings),
        Err(error) => bulk_plan_error_value(error),
    }
}

pub(super) fn apply_bulk_toggle_items(context: &McpContext, arguments: &Value) -> Value {
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

    match seal_bulk_toggle_handoff(context, &current_plan, false) {
        Ok(operation_v2) => {
            reach_aware_bulk_human_action_required(&current_plan, current_fingerprint, operation_v2)
        }
        Err(error) => blocked_value(error),
    }
}

pub(super) fn seal_bulk_toggle_handoff(
    context: &McpContext,
    plan: &BulkTogglePlan,
    bind_claude_project_root: bool,
) -> Result<Value, String> {
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
    let roots = bulk_mcp_root_binding(context, plan, bind_claude_project_root)?;
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

pub(super) fn bulk_mcp_root_binding(
    context: &McpContext,
    plan: &BulkTogglePlan,
    bind_claude_project_root: bool,
) -> Result<ReachAwareRootBinding, String> {
    let providers = plan
        .provider_coverage
        .included()
        .map(|entry| entry.provider)
        .collect::<BTreeSet<_>>();
    let mut provider_roots = providers
        .into_iter()
        .map(|provider| {
            (
                provider,
                ReachAwareRootScope::Primary,
                mcp_provider_root(&context.discovery_roots, provider),
                crate::mutation::BULK_TOGGLE_PROVIDER_ROOT_PROVENANCE.to_string(),
            )
        })
        .collect::<Vec<_>>();
    if bind_claude_project_root
        && plan.included.iter().any(|target| {
            target.item.provider == ProviderId::Claude
                && target.item.layer == DiscoveryLayer::Project
        })
        && provider_roots
            .iter()
            .any(|(provider, _, _, _)| *provider == ProviderId::Claude)
    {
        provider_roots.push((
            ProviderId::Claude,
            ReachAwareRootScope::Project,
            context.discovery_roots.claude_project.clone(),
            crate::mutation::BULK_TOGGLE_PROVIDER_ROOT_PROVENANCE.to_string(),
        ));
    }
    ReachAwareRootBinding::from_scoped_provider_paths(
        &context.app_state_root,
        provider_roots,
        crate::mutation::BULK_TOGGLE_ROOT_PROVENANCE,
    )
    .map_err(|error| error.to_string())
}

pub(super) fn mcp_provider_root(roots: &DiscoveryRoots, provider: ProviderId) -> PathBuf {
    roots.provider_global_root(provider).to_path_buf()
}

/// Coarse selector accepted across the public MCP boundary. Exact identities
/// and their selection-context fingerprints are internal capabilities created
/// only by trusted package/group adapters after fresh discovery.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub(super) struct McpBulkToggleSelector {
    providers: Vec<ProviderId>,
    kinds: Vec<DiscoveryKind>,
    categories: Vec<DiscoveryCategory>,
    layers: Vec<DiscoveryLayer>,
    ids: Vec<String>,
    enabled: Option<bool>,
}

impl From<McpBulkToggleSelector> for BulkToggleSelector {
    fn from(selector: McpBulkToggleSelector) -> Self {
        Self {
            providers: selector.providers,
            kinds: selector.kinds,
            categories: selector.categories,
            layers: selector.layers,
            ids: selector.ids,
            enabled: selector.enabled,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub(super) enum BulkBuildError {
    InvalidArguments(String),
    Message(String),
    Core(BulkTogglePlanError),
}

pub(super) fn build_bulk_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(BulkTogglePlan, Vec<Value>), BulkBuildError> {
    require_only_fields(
        arguments,
        &[
            "selector",
            "targetEnabled",
            "requireConfirmation",
            "confirm",
            "planFingerprint",
            "maxItems",
            "allowEmptySelection",
            "providerReach",
            "acknowledgeWholeInventory",
        ],
        "bulk toggle arguments",
    )
    .map_err(BulkBuildError::InvalidArguments)?;
    let target_enabled = arguments
        .get("targetEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            BulkBuildError::InvalidArguments("missing required field: targetEnabled".to_string())
        })?;
    let selector_value = arguments
        .get("selector")
        .ok_or_else(|| BulkBuildError::InvalidArguments("selector is required".to_string()))?;
    validate_selector(selector_value).map_err(BulkBuildError::InvalidArguments)?;
    let selector = serde_json::from_value::<McpBulkToggleSelector>(selector_value.clone())
        .map(BulkToggleSelector::from)
        .map_err(|error| BulkBuildError::InvalidArguments(format!("invalid selector: {error}")))?;
    let reach = parse_bulk_provider_reach(
        arguments.get("providerReach"),
        context.provider_scope.provider(),
    )
    .map_err(BulkBuildError::InvalidArguments)?;
    let allow_empty_selection = match arguments.get("allowEmptySelection") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            BulkBuildError::InvalidArguments("allowEmptySelection must be a boolean".to_string())
        })?,
    };
    let acknowledge_whole_inventory = match arguments.get("acknowledgeWholeInventory") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            BulkBuildError::InvalidArguments(
                "acknowledgeWholeInventory must be a boolean".to_string(),
            )
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

pub(super) fn parse_bulk_provider_reach(
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

pub(super) fn bulk_plan_value(plan: &BulkTogglePlan, warnings: Vec<Value>) -> Value {
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

pub(super) fn bulk_plan_error_value(error: BulkBuildError) -> Value {
    match error {
        BulkBuildError::InvalidArguments(reason) => json!({
            "status": "blocked",
            "reason": reason,
            "reasonCode": "invalid-arguments",
            "message": "The public MCP bulk selector accepts only coarse inventory criteria.",
            "controlContractVersion": UNPIN_CONTROL_CONTRACT_VERSION,
        }),
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

pub(super) fn item_identity_from_value(item: &Value) -> Value {
    json!({
        "provider": item["provider"],
        "kind": item["kind"],
        "id": item["id"],
        "layer": item["layer"]
    })
}

pub(super) fn blocked_reason_message(reason_code: &str) -> String {
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

pub(super) fn sort_item_identity_values(items: &mut [Value]) {
    items.sort_by_key(item_identity_key);
}

pub(super) fn sort_blocked_item_values(items: &mut [Value]) {
    items.sort_by_key(|entry| item_identity_key(&entry["item"]));
}

pub(super) fn sort_per_item_plan_values(items: &mut [Value]) {
    items.sort_by_key(|entry| item_identity_key(&entry["selection"]));
}

pub(super) fn item_identity_key(item: &Value) -> (String, String, String, String) {
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

pub(super) fn plan_summary_value(result: Value) -> Value {
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

pub(super) fn toggle_warning_values(result: &Value) -> Value {
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

pub(super) fn operation_summary_values(operations: &Value) -> Value {
    Value::Array(
        operations
            .as_array()
            .into_iter()
            .flatten()
            .map(operation_summary_value)
            .collect(),
    )
}

pub(super) fn operation_summary_value(operation: &Value) -> Value {
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

pub(super) fn operation_with_contract_aliases(mut operation: Value, operation_type: &str) -> Value {
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

pub(super) fn json_pointer_from_path(path: &[Value]) -> String {
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

pub(super) fn target_summary_values(targets: &Value) -> Value {
    Value::Array(
        targets
            .as_array()
            .into_iter()
            .flatten()
            .map(target_summary_value)
            .collect(),
    )
}

pub(super) fn target_summary_value(target: &Value) -> Value {
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

pub(super) fn path_values_from_targets(targets: &Value) -> Vec<String> {
    targets
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target.get("path").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

pub(super) fn blocked_reason_value(reason_code: &str) -> Value {
    json!({
        "reasonCode": reason_code,
        "message": blocked_reason_message(reason_code)
    })
}

pub(super) fn blocked_toggle_value(
    item: DiscoveryItem,
    target_enabled: bool,
    reason_code: &str,
) -> Value {
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
