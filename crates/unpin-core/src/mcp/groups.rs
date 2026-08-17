use super::*;

use serde_json::{Value, json};

pub(super) fn list_inventory_groups(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(arguments, &[], "inventory group list arguments")?;
    let resolver = group_resolver(context)?;
    let discovery = discover_inventory_groups(context)?;
    let (groups, mut warnings) = resolver
        .list_views_with_warnings(&discovery)
        .map_err(|error| public_group_resolve_error(&error))?;
    for warning in &mut warnings {
        warning.message = "inventory group scope is unavailable".to_string();
    }
    let groups = groups
        .iter()
        .map(|view| public_group_view_value(view, context.provider_scope.provider()))
        .collect::<Vec<_>>();
    Ok(json!({
        "status": "ok",
        "groups": groups,
        "count": groups.len(),
        "warnings": warnings,
    }))
}

pub(super) fn get_inventory_group(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(arguments, &["group"], "inventory group get arguments")?;
    let reference =
        GroupRef::parse(required_string(arguments, "group")?).map_err(|error| error.to_string())?;
    let resolver = group_resolver(context)?;
    let discovery = discover_inventory_groups(context)?;
    let view = match resolver.inspect(&reference, &discovery) {
        Ok(view) => view,
        Err(GroupResolveError::Ambiguous { candidates, .. }) => {
            return Ok(ambiguous_group_value(&candidates));
        }
        Err(error) => return Err(public_group_resolve_error(&error)),
    };
    let public_view = public_group_view_value(&view, context.provider_scope.provider());
    Ok(json!({
        "status": if view.context_compatible { "ok" } else { "context-mismatch" },
        "group": public_view,
    }))
}

pub(super) fn plan_inventory_group(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["group", "targetEnabled", "maxMembers", "providerReach"],
        "inventory group plan arguments",
    )?;
    let reference =
        GroupRef::parse(required_string(arguments, "group")?).map_err(|error| error.to_string())?;
    let target = if arguments
        .get("targetEnabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| "missing required field: targetEnabled".to_string())?
    {
        GroupTargetState::Enable
    } else {
        GroupTargetState::Disable
    };
    let max_members = arguments
        .get("maxMembers")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "maxMembers must be a positive integer".to_string())?;
    let actionable = context.approved_group_apply.is_some()
        && context.backup_authentication_key.is_some()
        && context.session_authority_key.is_some();
    let mode = if actionable {
        GroupPlanMode::McpHandoff
    } else {
        GroupPlanMode::PreviewOnly
    };
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let reach = parse_bulk_provider_reach(
        arguments.get("providerReach"),
        context.provider_scope.provider(),
    )?;
    let reach_request = ProviderReachRequest::new(boundary, reach, DerivedTargetKind::Group);
    // This validation is deliberately before group discovery and provider
    // planning. An all-provider MCP connection must state its reach explicitly.
    reach_request
        .clone()
        .validate_before_discovery()
        .map_err(|error| error.to_string())?;
    let planner = GroupPlanner::new(group_resolver(context)?);
    let plan = match planner.plan_with_provider_reach_request(
        &reference,
        target,
        max_members,
        mode,
        reach_request,
    ) {
        Ok(plan) => plan,
        Err(GroupPlanError::Resolve(GroupResolveError::Ambiguous { candidates, .. })) => {
            return Ok(ambiguous_group_value(&candidates));
        }
        Err(error) => return Err(public_group_plan_error(&error)),
    };
    let (status, approval, guidance) = match plan.disposition {
        GroupPlanDisposition::Preview => (
            "preview",
            "unavailable",
            Some(
                "Start persistent MCP with approved group apply enabled to request an authorizable plan.",
            ),
        ),
        GroupPlanDisposition::NoOp => ("no-op", "not-required", None),
        GroupPlanDisposition::Blocked => ("blocked", "not-required", None),
        GroupPlanDisposition::Actionable => (
            "actionable",
            "required",
            Some(
                "Review this complete plan in `unpin group approve`, then call unpin_apply_inventory_group with the exact operation, fingerprint, challenge, and one-time artifact.",
            ),
        ),
    };
    let public_plan = public_group_plan_value(&plan, context.provider_scope.provider());
    let mut response = json!({
        "status": status,
        "approval": approval,
        "plan": public_plan,
        "humanAction": guidance.map(|guidance| json!({
            "code": if actionable { "approve-for-mcp-apply" } else { "approved-group-mode-required" },
            "guidance": guidance,
        })),
    });
    if plan.disposition == GroupPlanDisposition::Actionable {
        let approved = context
            .approved_group_apply
            .as_ref()
            .ok_or_else(|| "approved-group MCP session is unavailable".to_string())?;
        let session_key = context
            .session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority credential is unavailable".to_string())?;
        let now_unix = current_unix_seconds()
            .map_err(|_| "inventory group approval is unavailable".to_string())?;
        let lease_expires_at = McpGroupSessionLeaseStore::new(&context.app_state_root)
            .verify(&approved.session, session_key, now_unix)
            .map_err(|_| "inventory group approval is unavailable".to_string())?;
        let challenge = issue_group_approval_challenge(
            plan.clone(),
            approved.session.clone(),
            lease_expires_at,
            session_key,
            now_unix,
        )
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
        response["challenge"] = json!(challenge);
        response["operationId"] = json!(plan.operation_id);
        response["planFingerprint"] = json!(plan.plan_fingerprint);
    }
    Ok(response)
}

pub(super) fn apply_inventory_group(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &[
            "operationId",
            "planFingerprint",
            "challenge",
            "approvalArtifact",
        ],
        "inventory group apply arguments",
    )?;
    let approved = context
        .approved_group_apply
        .as_ref()
        .ok_or_else(|| "approved-group MCP apply is unavailable".to_string())?;
    let backup_key = context
        .backup_authentication_key
        .as_ref()
        .ok_or_else(|| "backup authentication credential is unavailable".to_string())?;
    let session_key = context
        .session_authority_key
        .as_ref()
        .ok_or_else(|| "session authority credential is unavailable".to_string())?;
    let operation_id = required_string(arguments, "operationId")?;
    let plan_fingerprint = required_string(arguments, "planFingerprint")?;
    let challenge = required_string(arguments, "challenge")?;
    let artifact_id = required_string(arguments, "approvalArtifact")?;
    let now_unix = current_unix_seconds()
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let lease_expires_at = McpGroupSessionLeaseStore::new(&context.app_state_root)
        .verify(&approved.session, session_key, now_unix)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let claims = verify_group_approval_challenge(
        challenge,
        &approved.session,
        lease_expires_at,
        session_key,
        now_unix,
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    if claims.plan.operation_id.as_deref() != Some(operation_id)
        || claims.plan.plan_fingerprint != plan_fingerprint
    {
        return Ok(blocked_value("inventory group approval binding mismatch"));
    }
    let resolver = group_resolver(context)?;
    let planner = GroupPlanner::new(resolver);
    let approval_context = ControlApprovalContext::new(
        planner.resolver().context().repository_key(),
        planner.resolver().context().workspace_key(),
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let expectation = claims
        .plan
        .approval_expectation(&approval_context)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let artifact_store = GroupApprovalArtifactStore::new(&context.app_state_root);
    let (receipt, consumed_decision_digest, consume_artifact) = match artifact_store.load_ready(
        artifact_id,
        operation_id,
        plan_fingerprint,
        challenge,
        &approved.session,
        session_key,
        now_unix,
    ) {
        Ok(artifact) => (artifact.receipt, None, true),
        Err(_) => {
            let consumed = artifact_store
                .load_consumed(
                    artifact_id,
                    operation_id,
                    plan_fingerprint,
                    challenge,
                    &approved.session,
                    session_key,
                    now_unix,
                )
                .map_err(|_| "inventory group approval artifact is unavailable".to_string())?;
            (consumed.receipt, Some(consumed.decision_digest), false)
        }
    };
    let verifier = ApprovalVerifier::new(approved.approval_key.clone());
    let verified = verifier
        .verify(&receipt, &expectation, now_unix)
        .map_err(|_| "inventory group approval is unavailable".to_string())?;
    let decision_digest = verified.decision_digest().to_string();
    if consumed_decision_digest
        .as_deref()
        .is_some_and(|consumed| consumed != decision_digest)
    {
        return Err("inventory group approval artifact is unavailable".to_string());
    }
    let mut fixture_write_paths = vec![context.app_state_root.clone()];
    let existing_operation =
        GroupOperationStore::new(context.app_state_root.clone(), backup_key.clone())
            .load(operation_id)
            .map_err(|_| "inventory group operation evidence is unavailable".to_string())?
            .map(|snapshot| snapshot.value);
    let status_only = existing_operation.as_ref().is_some_and(|operation| {
        operation.provider_writes_started || operation.terminal_result.is_some()
    });
    if existing_operation.is_some() {
        let discovery = discover_inventory_groups(context)?;
        let discovery_index = index_discovery(&discovery);
        for member in &claims.plan.members {
            if member.outcome != crate::groups::GroupMemberPlanOutcome::Changed {
                continue;
            }
            let matches = discovery_index
                .get(&member.identity)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let item = match matches {
                [] => {
                    return Ok(blocked_value(
                        "inventory group member disappeared before apply",
                    ));
                }
                [item] => *item,
                _ => {
                    return Ok(blocked_value(
                        "inventory group member became ambiguous before apply",
                    ));
                }
            };
            fixture_write_paths.extend(
                [item.source_path.as_str(), item.state_path.as_str()]
                    .into_iter()
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from),
            );
        }
    } else {
        let revalidated = planner
            .revalidate(&claims.plan)
            .map_err(|error| public_group_plan_error(&error))?;
        if revalidated.plan_fingerprint != claims.plan.plan_fingerprint {
            return Ok(blocked_value(
                "inventory group plan no longer matches current state",
            ));
        }
        for member in &revalidated.members {
            if member.outcome != crate::groups::GroupMemberPlanOutcome::Changed {
                continue;
            }
            let native = member.native_plan.as_ref().ok_or_else(|| {
                "actionable inventory group member has no sealed native plan".to_string()
            })?;
            fixture_write_paths.extend(
                native
                    .preview
                    .affected_targets
                    .iter()
                    .map(|target| PathBuf::from(&target.path)),
            );
        }
    }
    crate::fixture::require_fixture_write_sandbox(
        context.fixture_root.is_some(),
        fixture_write_paths.iter().map(PathBuf::as_path),
    )
    .map_err(|_| "inventory group apply is outside the fixture write sandbox".to_string())?;
    let controller = GroupController::new(planner, backup_key.clone(), session_key.clone());
    if !status_only {
        controller
            .seal_authorizing_operation(
                &claims.plan,
                &decision_digest,
                GroupOperationAuthorizationLink {
                    artifact_digest: approval_binding_digest(artifact_id),
                    nonce_digest: approval_binding_digest(&receipt.claims.nonce),
                    session_id: approved.session.session_id.clone(),
                    session_generation: approved.session.generation,
                },
            )
            .map_err(|_| "inventory group operation evidence is unavailable".to_string())?;
    }
    let authorization = authorize_control(
        &context.app_state_root,
        &receipt,
        &verifier,
        &expectation,
        now_unix,
        crate::state::atomic_json::OwnerGeneration::new(
            format!("mcp-group-apply:{}", approved.session.session_id),
            approved.session.generation,
        )
        .map_err(|_| "inventory group approval is unavailable".to_string())?,
    )
    .map_err(|_| "inventory group approval is unavailable".to_string())?;
    if consume_artifact {
        artifact_store
            .consume(
                artifact_id,
                operation_id,
                plan_fingerprint,
                challenge,
                &approved.session,
                authorization.decision_digest(),
                session_key,
                now_unix,
            )
            .map_err(|_| "inventory group approval artifact is unavailable".to_string())?;
    }
    if status_only {
        context.discovery_cache.invalidate();
        return match controller.status_without_reauthorization(&claims.plan) {
            Ok(result) => group_apply_response(&claims.plan, &expectation, &result),
            Err(_) => Ok(group_recovery_required_response(operation_id)),
        };
    }
    let result = match controller.apply(&claims.plan, authorization) {
        Ok(result) => result,
        Err(_) => {
            context.discovery_cache.invalidate();
            if controller
                .operation(operation_id)
                .ok()
                .flatten()
                .is_some_and(|operation| {
                    operation.provider_writes_started || operation.terminal_result.is_some()
                })
            {
                return Ok(group_recovery_required_response(operation_id));
            }
            return Ok(json!({
                "status": "failed",
                "operationId": operation_id,
                "error": {
                    "code": "group-apply-failed",
                    "message": "inventory group apply failed",
                },
            }));
        }
    };
    context.discovery_cache.invalidate();
    group_apply_response(&claims.plan, &expectation, &result)
}

pub(super) fn group_recovery_required_response(operation_id: &str) -> Value {
    json!({
        "status": "recovery-required",
        "operationId": operation_id,
        "error": {
            "code": "group-recovery-required",
            "message": "inventory group provider writes may have started; inspect the durable operation and backup evidence",
        },
        "guidance": "Run `unpin group operation-show <operationId> --json` before any further apply.",
    })
}

pub(super) fn group_apply_response(
    plan: &GroupTogglePlan,
    expectation: &ApprovalExpectation,
    result: &GroupApplyResult,
) -> Result<Value, String> {
    let activation = plan
        .resources
        .iter()
        .fold(EffectActivation::Live, |activation, resource| {
            activation.max(resource.activation)
        });
    let providers = plan
        .provider_coverage
        .entries()
        .iter()
        .map(|entry| entry.provider)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let operation = result
        .control_operation_envelope(expectation, activation, providers)
        .map_err(|_| "inventory group operation result is unavailable".to_string())?;
    let status = match result.provider_reach_lifecycle {
        crate::provider_reach::ProviderReachLifecycle::Applied => match result.lifecycle {
            crate::groups::GroupOperationLifecycle::Completed => "applied",
            crate::groups::GroupOperationLifecycle::Partial
            | crate::groups::GroupOperationLifecycle::Failed => "blocked",
            crate::groups::GroupOperationLifecycle::RecoveryRequired => "recovery-required",
            crate::groups::GroupOperationLifecycle::InProgress => {
                return Err("inventory group operation result is unavailable".to_string());
            }
        },
        crate::provider_reach::ProviderReachLifecycle::Partial => "partial",
        crate::provider_reach::ProviderReachLifecycle::NoOp => "no-op",
        crate::provider_reach::ProviderReachLifecycle::NoTargetsInProviderReach => {
            "no-targets-in-provider-reach"
        }
        crate::provider_reach::ProviderReachLifecycle::Blocked => "blocked",
        crate::provider_reach::ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    };
    let mut operation = serde_json::to_value(operation)
        .map_err(|_| "inventory group operation result is unavailable".to_string())?;
    if let Some(allowed) = plan.provider_reach.provider()
        && let Some(result_value) = operation
            .get_mut("details")
            .and_then(|details| details.get_mut("result"))
    {
        *result_value = public_group_result_value(result, Some(allowed));
    }
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": result.operation_id,
        "planFingerprint": result.plan_fingerprint,
        "providerReach": result.provider_reach,
        "providerCoverage": result.provider_coverage,
        "lifecycle": result.provider_reach_lifecycle,
        "operation": operation,
        "operationV2": {
            "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
            "family": "group-toggle",
            "operationId": result.operation_id,
            "operationKind": "inventory-group-apply",
            "planFingerprint": result.plan_fingerprint,
            "providerReach": result.provider_reach,
            "providerCoverage": result.provider_coverage,
            "lifecycle": status,
            "expectedLifecycle": result.provider_reach_lifecycle,
            "activation": activation,
            "humanAction": null
        }
    }))
}

pub(super) fn public_group_plan_value(
    plan: &GroupTogglePlan,
    allowed: Option<ProviderId>,
) -> Value {
    let mut value = serde_json::to_value(plan).expect("group plan serializes");
    redact_group_projection(&mut value, allowed);
    value
}

pub(super) fn public_group_result_value(
    result: &GroupApplyResult,
    allowed: Option<ProviderId>,
) -> Value {
    let mut value = serde_json::to_value(result).expect("group result serializes");
    redact_group_projection(&mut value, allowed);
    value
}

pub(super) fn public_group_view_value(
    view: &crate::groups::GroupDefinitionView,
    allowed: Option<ProviderId>,
) -> Value {
    let mut value = serde_json::to_value(view).expect("group view serializes");
    if let Some(allowed) = allowed {
        redact_group_view_projection(&mut value, allowed);
    }
    value
}

pub(super) fn redact_group_projection(value: &mut Value, allowed: Option<ProviderId>) {
    let Some(allowed) = allowed else {
        return;
    };
    let allowed_value = serde_json::to_value(allowed).expect("provider serializes");
    for key in ["members", "groupMembers"] {
        if let Some(members) = value.get_mut(key).and_then(Value::as_array_mut) {
            members.retain(|member| {
                member
                    .get("identity")
                    .and_then(|identity| identity.get("provider"))
                    .is_some_and(|provider| provider == &allowed_value)
            });
        }
    }
    if let Some(definition_view) = value.get_mut("definitionView") {
        redact_group_view_projection(definition_view, allowed);
    }
    let mut excluded_counts = BTreeMap::<String, usize>::new();
    if let Some(entries) = value
        .get_mut("providerCoverage")
        .and_then(|coverage| coverage.get_mut("entries"))
        .and_then(Value::as_array_mut)
    {
        entries.retain(|entry| {
            let provider = entry.get("provider");
            let retained = provider == Some(&allowed_value);
            if !retained && let Some(provider) = provider.and_then(Value::as_str) {
                *excluded_counts.entry(provider.to_string()).or_default() += 1;
            }
            retained
        });
    }
    if !excluded_counts.is_empty() {
        value["reachExclusions"] = json!({
            "providers": excluded_counts
                .iter()
                .map(|(provider, count)| json!({"provider": provider, "count": count}))
                .collect::<Vec<_>>(),
            "count": excluded_counts.values().sum::<usize>(),
            "reason": "out-of-provider-reach",
        });
    }
}

pub(super) fn redact_group_operation_inspections(value: &mut Value, allowed: Option<ProviderId>) {
    let Some(allowed) = allowed else {
        return;
    };
    let Some(inspections) = value
        .get_mut("groupOperations")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for inspection in inspections {
        // Cohort indexes contain aggregate resource and backup identifiers.
        // Their resource IDs do not carry an independently verifiable provider
        // attribution, so never expose them through a pinned-provider status
        // read. Likewise, an aggregate evidence bit cannot be recomputed once
        // the other providers are removed.
        if let Some(inspection_object) = inspection.as_object_mut() {
            inspection_object.insert("cohortBackupIndexes".to_string(), Value::Array(Vec::new()));
            inspection_object.insert("evidenceAvailable".to_string(), Value::Bool(false));
        }
        let Some(operation) = inspection.get_mut("operation") else {
            continue;
        };
        redact_group_projection(operation, Some(allowed));
        if let Some(result) = operation.get_mut("terminalResult") {
            redact_group_result_backup_ids(result, allowed);
            redact_group_projection(result, Some(allowed));
        }
    }
}

pub(super) fn redact_group_result_backup_ids(value: &mut Value, allowed: ProviderId) {
    let mut backup_providers = BTreeMap::<String, BTreeSet<String>>::new();
    for member in value
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(backup_id), Some(provider)) = (
            member.get("backupId").and_then(Value::as_str),
            member
                .get("identity")
                .and_then(|identity| identity.get("provider"))
                .and_then(Value::as_str),
        ) else {
            continue;
        };
        backup_providers
            .entry(backup_id.to_owned())
            .or_default()
            .insert(provider.to_owned());
    }
    let allowed_backup_ids = backup_providers
        .into_iter()
        .filter(|(_, providers)| providers.len() == 1 && providers.contains(allowed.as_str()))
        .map(|(backup_id, _)| backup_id)
        .collect::<BTreeSet<_>>();
    if let Some(backup_ids) = value.get_mut("backupIds").and_then(Value::as_array_mut) {
        backup_ids.retain(|backup_id| {
            backup_id
                .as_str()
                .is_some_and(|backup_id| allowed_backup_ids.contains(backup_id))
        });
    }
}

pub(super) fn redact_group_view_projection(value: &mut Value, allowed: ProviderId) {
    if value.get("contextCompatible").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let allowed_value = serde_json::to_value(allowed).expect("provider serializes");
    let mut excluded_counts = BTreeMap::<String, usize>::new();
    if let Some(members) = value.get_mut("members").and_then(Value::as_array_mut) {
        members.retain(|member| {
            let provider = member
                .get("identity")
                .and_then(|identity| identity.get("provider"));
            let retained = provider == Some(&allowed_value);
            if !retained && let Some(provider) = provider.and_then(Value::as_str) {
                *excluded_counts.entry(provider.to_string()).or_default() += 1;
            }
            retained
        });
    }
    if let Some(providers) = value
        .get_mut("providerCoverage")
        .and_then(Value::as_array_mut)
    {
        providers.retain(|provider| provider == &allowed_value);
    }

    let Some(members) = value.get("members").and_then(Value::as_array) else {
        return;
    };
    if members.is_empty() {
        for field in ["counts", "state", "fresh"] {
            value
                .as_object_mut()
                .expect("group view is an object")
                .remove(field);
        }
    } else {
        let mut enabled = 0_u64;
        let mut disabled = 0_u64;
        let mut blocked = 0_u64;
        let mut missing = 0_u64;
        let mut ambiguous = 0_u64;
        let mut stale = 0_u64;
        let mut observed = Vec::with_capacity(members.len());
        for member in members {
            let state = member.get("enabled").and_then(Value::as_bool);
            observed.push(state);
            match state {
                Some(true) => enabled += 1,
                Some(false) => disabled += 1,
                None => match member.get("reason").and_then(Value::as_str) {
                    Some("missing") => missing += 1,
                    Some("ambiguous") => ambiguous += 1,
                    _ => {}
                },
            }
            if state.is_some() && member.get("eligible").and_then(Value::as_bool) == Some(false) {
                blocked += 1;
            }
            if member.get("reason").and_then(Value::as_str) == Some("observation-stale") {
                stale += 1;
            }
        }
        value["counts"] = json!({
            "enabled": enabled,
            "disabled": disabled,
            "blocked": blocked,
            "missing": missing,
            "ambiguous": ambiguous,
            "stale": stale,
        });
        value["state"] = if observed.iter().all(|state| *state == Some(true)) {
            json!("on")
        } else if observed.iter().all(|state| *state == Some(false)) {
            json!("off")
        } else {
            json!("mixed")
        };
        value["fresh"] = json!(stale == 0);
    }
    if !excluded_counts.is_empty() {
        value["reachExclusions"] = json!({
            "providers": excluded_counts
                .iter()
                .map(|(provider, count)| json!({"provider": provider, "count": count}))
                .collect::<Vec<_>>(),
            "count": excluded_counts.values().sum::<usize>(),
            "reason": "out-of-provider-reach",
        });
    }
}

pub(super) fn group_resolver(context: &McpContext) -> Result<GroupResolver, String> {
    let access = GroupAccessContext::from_runtime(
        &context.app_state_root,
        &context.project_root,
        &context.discovery_roots,
        context.provider_scope.provider(),
        None,
    )
    .map_err(|_| "inventory group context is unavailable".to_string())?;
    Ok(GroupResolver::new(
        access.clone(),
        PersonalGroupStore::new(access.clone()),
        RepositoryGroupStore::new(access),
    ))
}

pub(super) fn discover_inventory_groups(context: &McpContext) -> Result<DiscoveryOutput, String> {
    discover_scoped(context).map_err(|_| "inventory group discovery is unavailable".to_string())
}

pub(super) fn public_group_resolve_error(error: &GroupResolveError) -> String {
    match error {
        GroupResolveError::Store(_) | GroupResolveError::ScopeUnavailable { .. } => {
            "inventory group storage is unavailable".to_string()
        }
        GroupResolveError::NotFound(_) | GroupResolveError::Ambiguous { .. } => error.to_string(),
    }
}

pub(super) fn ambiguous_group_value(candidates: &[String]) -> Value {
    json!({
        "status": "ambiguous",
        "error": {
            "code": "group-reference-ambiguous",
            "message": "inventory group reference is ambiguous",
            "candidates": candidates,
        },
    })
}

pub(super) fn public_group_plan_error(error: &GroupPlanError) -> String {
    match error {
        GroupPlanError::Resolve(error) => public_group_resolve_error(error),
        GroupPlanError::ProviderReach(error) => error.to_string(),
        GroupPlanError::InvalidMaximum { .. }
        | GroupPlanError::MaximumExceeded { .. }
        | GroupPlanError::ContextMismatch
        | GroupPlanError::NotActionable
        | GroupPlanError::InvalidPlan
        | GroupPlanError::FingerprintMismatch => error.to_string(),
        GroupPlanError::Discovery(_)
        | GroupPlanError::Transition(_)
        | GroupPlanError::Validation(_)
        | GroupPlanError::Approval(_)
        | GroupPlanError::Serialization(_)
        | GroupPlanError::IdentifierGeneration(_) => {
            "inventory group planning is unavailable".to_string()
        }
    }
}
