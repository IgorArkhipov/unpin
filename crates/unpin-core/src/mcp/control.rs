use super::*;

use serde_json::{Value, json};

pub(super) fn validate_profile(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["profileId", "definition", "sourceScope"],
        "profile validation arguments",
    )?;
    let stored_id = optional_string(arguments, "profileId")?;
    let inline = arguments.get("definition");
    let (definition, source_scope) = match (stored_id, inline) {
        (Some(profile_id), None) => load_stored_profile(context, profile_id)?,
        (None, Some(definition)) => {
            let definition = serde_json::from_value::<ProfileDefinition>(definition.clone())
                .map_err(|error| format!("profile definition is invalid: {error}"))?;
            let source_scope =
                parse_profile_source_scope(required_string(arguments, "sourceScope")?)?;
            (definition, source_scope)
        }
        _ => {
            return Err(
                "provide exactly one of profileId or definition; inline definitions require sourceScope"
                    .to_string(),
            );
        }
    };
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let revision =
        compile_profile(&definition, &catalog, source_scope).map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "valid",
        "sourceScope": profile_source_scope_name(source_scope),
        "revision": revision,
        "materialized": false,
    }))
}

pub(super) fn structured_result(value: Value) -> Result<Value, String> {
    let text = serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?;

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": value
    }))
}
pub(super) fn get_policy_maintenance_status(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["repositoryKey", "workspaceKey", "candidateCurrent"],
        "policy maintenance status arguments",
    )?;
    let repository_key = optional_string(arguments, "repositoryKey")?;
    let workspace_key = optional_string(arguments, "workspaceKey")?;
    let candidate_current = match arguments.get("candidateCurrent") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "candidateCurrent must be a boolean".to_string())?,
        None => false,
    };
    let target = match (repository_key, workspace_key) {
        (Some(repository_key), Some(workspace_key)) => {
            PolicyTarget::workspace(repository_key, workspace_key)
                .map_err(|error| error.to_string())?
        }
        (None, None) => {
            let identity = resolve_workspace_identity(&context.project_root)
                .map_err(|_| "workspace identity is unavailable".to_string())?;
            PolicyTarget::workspace(identity.repository_key, identity.workspace_key)
                .map_err(|_| "workspace identity is invalid".to_string())?
        }
        _ => {
            return Err("repositoryKey and workspaceKey must be supplied together".to_string());
        }
    };
    let Some(authentication_key) = context.backup_authentication_key.clone() else {
        return Ok(json!({
            "status": "blocked",
            "reason": "backup-authentication-key-missing",
            "target": target,
            "humanAction": {
                "code": "initialize-backup-authentication",
                "guidance": "Run `unpin auth backup init`, restart the MCP session, then retry."
            }
        }));
    };
    let controller = PolicyMaintenanceController::new(
        &context.app_state_root,
        &context.project_root,
        authentication_key,
    );
    let candidate = candidate_current.then_some(context.project_root.as_path());
    let status = match controller.status(&target, candidate) {
        Ok(status) => status,
        Err(error) => {
            return Ok(json!({
                "status": "blocked",
                "reason": error.public_code(),
                "message": error.public_message(),
                "target": target,
                "humanAction": {
                    "code": "inspect-policy-maintenance",
                    "guidance": "Run `unpin profile policy status --json` with the recorded workspace keys. MCP policy mutation remains disabled."
                }
            }));
        }
    };
    let Some(status) = status else {
        let unmanaged = match controller.unmanaged_status(&target) {
            Ok(unmanaged) => unmanaged,
            Err(error) => {
                return Ok(json!({
                    "status": "blocked",
                    "reason": error.public_code(),
                    "message": error.public_message(),
                    "target": target,
                    "humanAction": {
                        "code": "inspect-policy-maintenance",
                        "guidance": "Run `unpin profile policy status --json` and inspect local state."
                    }
                }));
            }
        };
        let human_action = match unmanaged {
            UnmanagedPolicyStatus::MigrationAvailable => json!({
                "code": "review-policy-migration",
                "guidance": "Run `unpin profile policy migrate --json`, review the plan, then apply it through the CLI with exact confirmation."
            }),
            UnmanagedPolicyStatus::ExistingPolicy => json!({
                "code": "inspect-existing-policy",
                "guidance": "A workspace policy already exists without a maintenance record; inspect it before choosing an explicit adoption or replacement path."
            }),
            UnmanagedPolicyStatus::MigrationUnavailable => json!({
                "code": "inspect-migration-source",
                "guidance": "No safe fixed-source migration is currently available; inspect the workspace policy source."
            }),
        };
        return Ok(json!({
            "status": "unmanaged",
            "unmanagedState": unmanaged,
            "target": target,
            "humanAction": human_action
        }));
    };
    let human_actions = status.allowed_actions.iter().map(|action| {
        let PolicyTarget::Workspace {
            repository_key,
            workspace_key,
        } = &status.target
        else {
            unreachable!("maintenance records are workspace-scoped");
        };
        let guidance = match action.as_str() {
            "reattach" => format!(
                "Run `unpin profile policy reattach --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            "discard" => format!(
                "Run `unpin profile policy discard --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            "cleanup" => format!(
                "Run `unpin profile policy cleanup --repository-key {repository_key} --workspace-key {workspace_key} --json`, review the plan, then apply it through the CLI."
            ),
            _ => "Inspect the authenticated policy status in the CLI.".to_string(),
        };
        json!({
            "code": format!("review-policy-{action}"),
            "guidance": guidance
        })
    }).collect::<Vec<_>>();
    let human_action = human_actions.first().cloned();
    Ok(json!({
        "status": "managed",
        "maintenance": status,
        "humanAction": human_action,
        "humanActions": human_actions,
        "mutationsAvailable": false
    }))
}

pub(super) fn get_control_status(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &["operationId"], "control status arguments")?;
    let operation_id = optional_string(arguments, "operationId")?;
    let discovery = discover_scoped_cached(context)?;
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let mut control = build_control_status(
        &discovery,
        &app_state_root,
        &context.project_root,
        context
            .session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if let Some(authentication_key) = context.backup_authentication_key.clone() {
        // Group-operation records and cohort indexes are independently
        // authenticated.  A missing or invalid backup key must not turn this
        // status read into an unauthenticated state lookup, so keep the
        // additive projection empty unless the complete authenticated list is
        // available for this exact workspace.
        control.group_operations = list_group_operation_inspections(
            &app_state_root,
            authentication_key,
            &control.repository_key,
            &control.workspace_key,
        )
        .unwrap_or_default();
    }
    context.provider_scope.filter_control_status(&mut control);
    if let Some(operation_id) = operation_id {
        control
            .group_operations
            .retain(|inspection| inspection.operation.operation_id == operation_id);
        control
            .operations
            .retain(|operation| operation.operation_id == operation_id);
        let journals = TransitionJournalStore::new(&app_state_root)
            .list()
            .map_err(|error| error.to_string())?;
        if let Some(authorization) =
            reach_aware_status_authorization(context, operation_id, &journals)?
        {
            attach_reach_aware_status_for_operation(
                &mut control,
                &journals,
                Some(operation_id),
                &authorization,
                context
                    .session_authority_key
                    .as_ref()
                    .ok_or_else(|| "session authority key is unavailable".to_string())?,
            )
            .map_err(|error| error.to_string())?;
        }
        control.operations.retain(|operation| {
            operation.operation_id == operation_id && operation.reach_aware.is_some()
        });
    }
    let mut control_value = serde_json::to_value(&control).map_err(|error| error.to_string())?;
    redact_group_operation_inspections(&mut control_value, context.provider_scope.provider());
    Ok(json!({
        "status": "ok",
        "control": control_value,
        "warnings": discovery.warnings
    }))
}

/// A regular MCP connection has no caller-supplied session identity.  Reuse
/// only the authenticated principal sealed in the journal and require its
/// connection boundary to equal this MCP context's configured boundary.  The
/// journal's signature, not caller metadata, establishes the identity; missing
/// or mismatched records remain non-disclosing v1 status rather than becoming
/// a journal lookup oracle.
pub(super) fn reach_aware_status_authorization(
    context: &McpContext,
    operation_id: &str,
    journals: &[crate::transitions::TransitionJournal],
) -> Result<Option<ReachAwareStatusAuthorization>, String> {
    let Some(session_key) = context.session_authority_key.as_ref() else {
        return Ok(None);
    };
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let matching = journals
        .iter()
        .filter(|journal| journal.operation_id == operation_id)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err("reach-aware status authorization is unavailable".to_string());
    }
    let Some(journal) = matching.into_iter().next() else {
        return Ok(None);
    };
    let Some(envelope) = journal.reach_aware.as_ref() else {
        return Ok(None);
    };
    envelope
        .verify_authenticated(session_key)
        .map_err(|_| "reach-aware status authorization is unavailable".to_string())?;
    let configured_boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let capability_scope_digest = envelope
        .transfer_capability
        .as_ref()
        .map_or_else(String::new, |capability| capability.scope_digest.clone());
    let authorization = ReachAwareStatusAuthorization::new(
        envelope.principal.clone(),
        envelope.audience.clone(),
        capability_scope_digest,
        now_unix,
        None,
    );
    match (configured_boundary, envelope.connection_boundary) {
        (ConnectionBoundary::All, ConnectionBoundary::All)
        | (ConnectionBoundary::Pinned(_), ConnectionBoundary::Pinned(_))
            if configured_boundary == envelope.connection_boundary =>
        {
            Ok(Some(authorization))
        }
        (ConnectionBoundary::Pinned(provider), ConnectionBoundary::All) => Ok(Some(
            authorization.with_requested_boundary(ConnectionBoundary::Pinned(provider)),
        )),
        _ => Ok(None),
    }
}

pub(super) fn list_catalog(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_empty_object(arguments)?;
    let discovery = discover_scoped_cached(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "ok",
        "capabilities": catalog.records.values().collect::<Vec<_>>(),
        "warnings": discovery.warnings,
    }))
}

pub(super) fn list_hooks(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let provider = optional_provider(context, arguments)?;
    let profile_digest = optional_string(arguments, "profileDigest")?;
    let discovery = discover_scoped_cached(context)?;
    let warnings = discovery.warnings;
    let trust = HookTrustStore::new(&context.app_state_root);
    let hooks = discovery
        .items
        .into_iter()
        .filter(|item| {
            item.kind == DiscoveryKind::Hook && provider.is_none_or(|value| item.provider == value)
        })
        .map(|item| {
            let stored_trust_decision = stored_hook_trust_decision(&trust, &item, profile_digest)?;
            Ok(json!({
                "provider": item.provider,
                "id": item.id,
                "displayName": item.display_name,
                "layer": item.layer,
                "enabled": item.enabled,
                "mutability": item.mutability,
                "handler": item.hook,
                "storedTrustDecision": stored_trust_decision,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "status": "ok",
        "hooks": hooks,
        "warnings": warnings
    }))
}

pub(super) fn stored_hook_trust_decision(
    trust: &HookTrustStore,
    item: &DiscoveryItem,
    profile_digest: Option<&str>,
) -> Result<bool, String> {
    let Some(profile_digest) = profile_digest else {
        return Ok(false);
    };
    let metadata = item
        .hook
        .as_ref()
        .ok_or_else(|| "hook metadata is missing".to_string())?;
    let record = trust
        .load_for(item.provider, &item.id, metadata, profile_digest)
        .map_err(|error| error.to_string())?;
    Ok(record.is_some_and(|record| {
        record.provider == item.provider
            && record.handler_id == item.id
            && record.handler_fingerprint == metadata.fingerprint
            && record.invocation_fingerprint == metadata.invocation_fingerprint
            && record.profile_digest == profile_digest
    }))
}

pub(super) fn plan_catalog_adoption(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let (item, capability, transition) = catalog_adoption_plan(context, arguments)?;
    let expectation =
        transition.approval_expectation(ADOPTION_APPROVAL_ISSUER, ADOPTION_APPROVAL_AUDIENCE);
    let operation = control_operation(
        &expectation,
        &transition.effect_graph_digest,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(item.provider),
        json!({
            "item": item,
            "capability": capability,
            "transition": transition,
        }),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "item": item,
        "capability": capability,
        "transition": transition,
        "planFingerprint": transition.effect_graph_digest,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

pub(super) fn apply_catalog_adoption(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let (item, capability, transition) = catalog_adoption_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &transition.effect_graph_digest)?;
    let expectation =
        transition.approval_expectation(ADOPTION_APPROVAL_ISSUER, ADOPTION_APPROVAL_AUDIENCE);
    Ok(human_action_required(control_operation(
        &expectation,
        &transition.effect_graph_digest,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(item.provider),
        json!({
            "item": item,
            "capability": capability,
            "transition": transition,
        }),
    )))
}

pub(super) fn catalog_adoption_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(DiscoveryItem, CatalogRecord, TransitionPlan), String> {
    let provider = required_provider(context, arguments)?;
    let item_id = required_string(arguments, "id")?;
    let provider_root = PathBuf::from(required_string(arguments, "providerRoot")?);
    let discovery = discover_scoped(context)?;
    let item = discovery
        .items
        .iter()
        .find(|item| item.provider == provider && item.id == item_id)
        .cloned()
        .ok_or_else(|| "provider item not found".to_string())?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let capability = catalog
        .find_provider_view(provider, item_id)
        .cloned()
        .ok_or_else(|| "catalog capability not found".to_string())?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let operation_id = format!(
        "adopt-{}-{}",
        provider.as_str(),
        capability.fingerprint.chars().take(24).collect::<String>()
    );
    let planned = plan_discovered_adoption(
        &item,
        &capability,
        operation_id,
        provider_root,
        &context.app_state_root,
        TransitionContext {
            repository_key: identity.repository_key,
            workspace_key: identity.workspace_key,
            session_id: None,
            profile_digest: None,
        },
        EffectActivation::NextSessionOnly,
    )
    .map_err(|error| error.to_string())?;
    Ok((item, capability, planned.transition))
}

pub(super) fn plan_hook_trust(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, expectation, fingerprint) = hook_trust_plan(context, arguments)?;
    let operation = control_operation(
        &expectation,
        &fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(item.provider),
        json!({"hook": item, "expectation": expectation}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "hook": item,
        "expectation": expectation,
        "planFingerprint": fingerprint,
        "activation": "next-session-only",
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

pub(super) fn apply_hook_trust(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let (item, expectation, fingerprint) = hook_trust_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &fingerprint)?;
    Ok(human_action_required(control_operation(
        &expectation,
        &fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(item.provider),
        json!({"hook": item, "expectation": expectation}),
    )))
}

pub(super) fn hook_trust_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(DiscoveryItem, ApprovalExpectation, String), String> {
    let provider = required_provider(context, arguments)?;
    let item_id = required_string(arguments, "id")?;
    let profile_digest = required_string(arguments, "profileDigest")?;
    let session_id = optional_string(arguments, "sessionId")?.unwrap_or("profile-policy");
    let discovery = discover_scoped(context)?;
    let item = discovery
        .items
        .iter()
        .find(|item| {
            item.provider == provider && item.kind == DiscoveryKind::Hook && item.id == item_id
        })
        .cloned()
        .ok_or_else(|| "hook not found".to_string())?;
    require_hook_profile_membership(context, &discovery, &item, profile_digest)?;
    let metadata = item
        .hook
        .as_ref()
        .ok_or_else(|| "hook metadata is missing".to_string())?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let expectation = metadata
        .trust_approval_expectation(
            provider,
            item_id,
            profile_digest,
            HOOK_TRUST_APPROVAL_ISSUER,
            HOOK_TRUST_APPROVAL_AUDIENCE,
            &identity.repository_key,
            &identity.workspace_key,
            session_id,
        )
        .map_err(|error| error.to_string())?;
    let fingerprint = expectation.effect_graph_digest.clone();
    Ok((item, expectation, fingerprint))
}

pub(super) fn require_hook_profile_membership(
    context: &McpContext,
    discovery: &DiscoveryOutput,
    hook: &DiscoveryItem,
    profile_digest: &str,
) -> Result<(), String> {
    let revision = ProfileStore::new(&context.app_state_root)
        .load_revision(profile_digest)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "compiled profile revision is missing".to_string())?;
    let catalog = Catalog::from_discovery(discovery).map_err(|error| error.to_string())?;
    let capability = catalog
        .find_provider_view(hook.provider, &hook.id)
        .ok_or_else(|| "hook capability is missing from catalog".to_string())?;
    if revision.selects(&capability.id, hook.provider) {
        Ok(())
    } else {
        Err("hook is not selected by compiled profile".to_string())
    }
}

pub(super) fn plan_profile_provider(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let (revision, plan) = profile_provider_plan(context, arguments)?;
    let operation_v2 = seal_profile_provider_handoff(context, &plan)?;
    let status = if plan.no_op { "no-op" } else { "planned" };
    let expected_lifecycle = if plan.no_op {
        ProviderReachLifecycle::NoOp
    } else {
        ProviderReachLifecycle::Applied
    };
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.coverage,
        "activation": plan.activation,
        "expectedLifecycle": expected_lifecycle,
        "targets": plan.targets,
        "operation": profile_provider_operation_value(
            context,
            &revision,
            &plan,
            status,
            expected_lifecycle,
        )?,
        "operationV2": operation_v2,
        "handoff": {
            "operationId": plan.operation_id,
            "planFingerprint": plan.plan_fingerprint,
        },
        "profile": revision,
        "plan": plan,
        "humanApprovalRequired": !plan.no_op,
        "continuation": if plan.no_op {
            "No provider policy change is required; retain this operation id for status inspection."
        } else {
            "Review provider reach, provenance, coverage, target classifications, and fingerprint, then call unpin_apply_profile_provider."
        },
    }))
}

pub(super) fn apply_profile_provider(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let operation_id = required_string(arguments, "operationId")?;
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let controller = ProfileProviderOperationController::new(&app_state_root)
        .with_session_authority_key(session_key);
    let plan = controller.load_handoff(operation_id).map_err(|error| {
        format!("operation id does not match sealed profile provider handoff: {error}")
    })?;
    if let Some(profile_id) = arguments.get("profileId").and_then(Value::as_str)
        && profile_id != plan.profile.profile_id
    {
        return Err("profile id does not match sealed profile provider operation".to_string());
    }
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let revision = compile_stored_profile(context, &plan.profile.profile_id)?;
    let operation_v2 = sealed_profile_provider_operation(&app_state_root, &plan.operation_id)?;
    let lifecycle = if plan.no_op {
        ProviderReachLifecycle::NoOp
    } else {
        ProviderReachLifecycle::Applied
    };
    let status = if plan.no_op {
        "no-op"
    } else {
        "human-action-required"
    };
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "status": status,
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.coverage,
        "activation": plan.activation,
        "expectedLifecycle": lifecycle,
        "targets": plan.targets,
        "operation": profile_provider_operation_value(
            context,
            &revision,
            &plan,
            if plan.no_op {
                "no-op"
            } else {
                "awaiting-human-action"
            },
            lifecycle,
        )?,
        "operationV2": operation_v2,
        "handoff": {
            "operationId": plan.operation_id,
            "planFingerprint": plan.plan_fingerprint,
        },
        "profile": revision,
        "plan": plan,
        "continuation": if plan.no_op {
            "No provider policy change is required."
        } else {
            "MCP cannot mint human approval; review and apply this exact fingerprint in Unpin CLI or TUI, then read control status."
        },
    }))
}

pub(super) fn seal_profile_provider_handoff(
    context: &McpContext,
    plan: &crate::profiles::ProfileProviderOperationPlan,
) -> Result<Value, String> {
    let app_state_root =
        std::fs::canonicalize(&context.app_state_root).map_err(|error| error.to_string())?;
    let session_key = context
        .session_authority_key
        .clone()
        .ok_or_else(|| "session authority key is unavailable".to_string())?;
    let approval_context = control_approval_context(context)?;
    let session_id = plan.operation_id.clone();
    let expectation = plan
        .approval_expectation(&approval_context, &session_id)
        .map_err(|error| error.to_string())?;
    let connection_boundary = match plan.provider_reach {
        crate::provider_reach::ProviderReach::All => ConnectionBoundary::All,
        crate::provider_reach::ProviderReach::Selected { provider, .. } => {
            ConnectionBoundary::Pinned(provider)
        }
    };
    let principal = ReachAwarePrincipal::sign(
        session_id,
        profile_reach_scope_digest(&expectation, &plan.operation_id),
        connection_boundary,
        &session_key,
    )
    .map_err(|error| error.to_string())?;
    let now_unix = current_unix_seconds().map_err(|error| error.to_string())?;
    let expires_at_unix = now_unix
        .checked_add(MCP_HANDOFF_TTL_SECONDS)
        .ok_or_else(|| "MCP handoff expiry overflowed".to_string())?;
    let roots = ReachAwareRootBinding::from_provider_paths(
        &app_state_root,
        Vec::new(),
        "mcp-profile-provider",
    )
    .map_err(|error| error.to_string())?;
    let durable = ProfileProviderReachAwareApplyContext {
        approval_context,
        roots,
        principal,
        audience: PROFILE_PROVIDER_APPROVAL_AUDIENCE.to_string(),
        issued_at_unix: now_unix,
        expires_at_unix,
        now_unix,
    };
    let controller = ProfileProviderOperationController::new(&app_state_root)
        .with_session_authority_key(session_key);
    let handoff = controller
        .seal_handoff(plan, &durable)
        .map_err(|error| error.to_string())?;
    if handoff.operation_id != plan.operation_id
        || handoff.plan_fingerprint != plan.plan_fingerprint
    {
        return Err("sealed profile provider handoff does not match reviewed plan".to_string());
    }
    sealed_profile_provider_operation(&app_state_root, &plan.operation_id)
}

pub(super) fn sealed_profile_provider_operation(
    app_state_root: &Path,
    operation_id: &str,
) -> Result<Value, String> {
    let matching = TransitionJournalStore::new(app_state_root)
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|journal| journal.operation_id == operation_id)
        .collect::<Vec<_>>();
    let [journal] = matching.as_slice() else {
        return Err("sealed profile provider handoff journal is unavailable".to_string());
    };
    let envelope = journal.reach_aware.as_ref().ok_or_else(|| {
        "sealed profile provider handoff is missing operation schema v2".to_string()
    })?;
    serde_json::to_value(envelope).map_err(|error| error.to_string())
}

pub(super) fn profile_provider_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<
    (
        CompiledProfileRevision,
        crate::profiles::ProfileProviderOperationPlan,
    ),
    String,
> {
    require_only_fields(
        arguments,
        &[
            "profileId",
            "mode",
            "scope",
            "provider",
            "providerReach",
            "operationId",
            "confirm",
            "planFingerprint",
        ],
        "profile provider operation arguments",
    )?;
    let profile_id = required_string(arguments, "profileId")?;
    let revision = compile_stored_profile(context, profile_id)?;
    let requested_provider = optional_provider(context, arguments)?;
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let mut reach_request = ProviderReachRequest::new(
        boundary,
        parse_bulk_provider_reach(
            arguments.get("providerReach"),
            context.provider_scope.provider(),
        )?,
        DerivedTargetKind::Profile,
    );
    if let Some(provider) = requested_provider {
        reach_request = reach_request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    let provider_reach = reach_request
        .validate_before_discovery()
        .and_then(|preflight| preflight.reconcile_exact_target(None))
        .map_err(|error| error.to_string())?
        .reach;
    let (_, target) = control_targets(context, arguments, provider_reach.provider())?;
    let gateway = match required_string(arguments, "mode")? {
        "native" => GatewaySelection::Native,
        "gateway" => GatewaySelection::Gateway,
        _ => return Err("mode must be native or gateway".to_string()),
    };
    let discovery = context
        .discovery_cache
        .get_or_discover(&context.discovery_roots)?;
    let plan = ProfileProviderOperationController::new(&context.app_state_root)
        .plan_with_gateway_and_discovery(&target, &revision, provider_reach, gateway, &discovery)
        .map_err(|error| error.to_string())?;
    Ok((revision, plan))
}

pub(super) fn profile_provider_operation_value(
    context: &McpContext,
    revision: &CompiledProfileRevision,
    plan: &crate::profiles::ProfileProviderOperationPlan,
    lifecycle: &str,
    expected_lifecycle: ProviderReachLifecycle,
) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let boundary = context
        .provider_scope
        .provider()
        .map_or(ConnectionBoundary::All, ConnectionBoundary::Pinned);
    let selected_provider = plan.provider_reach.provider().map(|provider| {
        json!(SelectedProviderAuthority::new(
            provider,
            plan.provider_reach
                .provenance()
                .unwrap_or(SelectedProviderProvenance::ExplicitInput),
        ))
    });
    Ok(json!({
        "schemaVersion": crate::provider_reach::PROVIDER_REACH_SCHEMA_VERSION,
        "family": "profile",
        "familySchemaVersion": crate::profiles::PROFILE_PROVIDER_OPERATION_SCHEMA_VERSION,
        "operationId": plan.operation_id,
        "operationKind": "apply-profile",
        "planFingerprint": plan.plan_fingerprint,
        "context": {
            "repositoryKey": approval_context.repository_key(),
            "workspaceKey": approval_context.workspace_key(),
            "profileDigest": plan.profile.digest
        },
        "connectionBoundary": boundary,
        "providerReach": plan.provider_reach,
        "selectedProvider": selected_provider,
        "providerCoverage": plan.coverage,
        "expectedLifecycle": expected_lifecycle,
        "lifecycle": lifecycle,
        "activation": plan.activation,
        "humanAction": (lifecycle == "planned" || lifecycle == "awaiting-human-action").then(|| json!({
            "code": "confirm-and-apply",
            "guidance": "Review and apply this fingerprint in Unpin CLI or TUI."
        })),
        "retryable": true,
        "details": {
            "profile": revision,
            "targets": plan.targets,
            "inverseEvidence": plan.inverse_evidence,
        }
    }))
}

pub(super) fn plan_profile_policy(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let (revision, plan) = profile_policy_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        optional_provider(context, arguments)?,
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "profile": revision,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

pub(super) fn apply_profile_policy(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let (_, plan) = profile_policy_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        optional_provider(context, arguments)?,
        json!({"plan": plan}),
    )))
}

pub(super) fn profile_policy_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<(CompiledProfileRevision, crate::profiles::PolicyChangePlan), String> {
    let profile_id = required_string(arguments, "profileId")?;
    let revision = compile_stored_profile(context, profile_id)?;
    let provider = optional_provider(context, arguments)?;
    let (_, policy_target) = control_targets(context, arguments, provider)?;
    let gateway = match required_string(arguments, "mode")? {
        "native" => GatewaySelection::Native,
        "gateway" => GatewaySelection::Gateway,
        _ => return Err("mode must be native or gateway".to_string()),
    };
    let plan = ProfilePolicyController::new(&context.app_state_root)
        .plan_with_revisions(
            policy_target,
            provider,
            PolicyChange {
                profile: Some(ProfileSelection::Profile {
                    reference: ProfileReference::from(&revision),
                }),
                gateway: Some(gateway),
                capability_lock: None,
            },
            std::slice::from_ref(&revision),
        )
        .map_err(|error| error.to_string())?;
    Ok((revision, plan))
}

pub(super) fn get_capability_locks(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(arguments, &["provider"], "capability lock status arguments")?;
    let requested_provider = optional_provider(context, arguments)?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let policies = PolicyStore::new(&context.app_state_root)
        .load_resolution_policies(&identity.repository_key, &identity.workspace_key, None)
        .map_err(|error| error.to_string())?;
    let discovery = discover_scoped_cached(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let providers = requested_provider.map_or_else(
        || {
            policies
                .global
                .providers
                .iter()
                .filter_map(|(provider, policy)| {
                    (!policy.capability_locks.is_empty()).then_some(*provider)
                })
                .collect::<Vec<_>>()
        },
        |provider| vec![provider],
    );
    let locks = providers
        .into_iter()
        .map(|provider| {
            let provider_policy = policies.global.providers.get(&provider);
            let snapshot = CapabilityLockSnapshot::compile(
                provider,
                provider_policy
                    .map(|policy| policy.capability_locks.clone())
                    .unwrap_or_default(),
            )
            .map_err(|error| error.to_string())?;
            let (gateway, gateway_source) = resolve_effective_gateway(provider, &policies);
            Ok(json!({
                "provider": provider,
                "source": "global",
                "activation": "next-session-only",
                "activeSessionsUnaffected": true,
                "repositoryKey": identity.repository_key,
                "workspaceKey": identity.workspace_key,
                "gateway": gateway,
                "gatewaySource": gateway_source,
                "digest": snapshot.digest,
                "entries": snapshot.entries,
                "enforcement": capability_lock_enforcement(&snapshot, &catalog, gateway),
                "action": "unpin profile lock",
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "status": "ok",
        "locks": locks,
        "warnings": discovery.warnings
    }))
}

pub(super) fn plan_capability_lock(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let plan = capability_lock_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let provider = required_provider(context, arguments)?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        Some(provider),
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI profile lock to review and apply this fingerprint, then read capability lock status.",
    }))
}

pub(super) fn apply_capability_lock(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    let plan = capability_lock_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        Some(required_provider(context, arguments)?),
        json!({"plan": plan}),
    )))
}

pub(super) fn capability_lock_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<crate::profiles::PolicyChangePlan, String> {
    let provider = required_provider(context, arguments)?;
    let capability_id =
        crate::catalog::CapabilityId::new(required_string(arguments, "capabilityId")?)
            .map_err(|error| error.to_string())?;
    let state = match required_string(arguments, "state")? {
        "hard-enabled" => Some(CapabilityLockState::HardEnabled),
        "hard-disabled" => Some(CapabilityLockState::HardDisabled),
        "clear" => None,
        _ => return Err("state must be hard-enabled, hard-disabled, or clear".to_string()),
    };
    ProfilePolicyController::new(&context.app_state_root)
        .plan(
            PolicyTarget::Global,
            Some(provider),
            PolicyChange {
                capability_lock: Some(CapabilityLockChange {
                    capability_id,
                    state,
                }),
                ..PolicyChange::default()
            },
        )
        .map_err(|error| error.to_string())
}

pub(super) fn compile_stored_profile(
    context: &McpContext,
    profile_id: &str,
) -> Result<CompiledProfileRevision, String> {
    let (definition, source_scope) = load_stored_profile(context, profile_id)?;
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    compile_profile(&definition, &catalog, source_scope).map_err(|error| error.to_string())
}

pub(super) fn load_stored_profile(
    context: &McpContext,
    profile_id: &str,
) -> Result<(ProfileDefinition, ProfileSourceScope), String> {
    if let Some(entry) = ProfileStore::load_workspace_definition(&context.project_root, profile_id)
        .map_err(|error| error.to_string())?
    {
        return Ok((entry.definition, entry.scope));
    }
    let snapshot = ProfileStore::new(&context.app_state_root)
        .load_global_definition(profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "profile not found".to_string())?;
    Ok((snapshot.value, ProfileSourceScope::Global))
}

pub(super) fn plan_gateway_mode(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = gateway_workflow_plan(context, arguments)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.mode.activation,
        if plan.mode.blocked_reason.is_some() {
            ControlOperationLifecycle::Blocked
        } else {
            ControlOperationLifecycle::Planned
        },
        optional_provider(context, arguments)?,
        json!({
            "plan": plan,
            "nativeMcpReferences": "not-managed",
        }),
    );
    Ok(json!({
        "status": if plan.mode.blocked_reason.is_some() { "blocked" } else { "planned" },
        "operation": operation,
        "plan": plan,
        "nativeMcpReferences": "not-managed",
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

pub(super) fn get_gateway_status(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["scope", "provider"],
        "gateway status arguments",
    )?;
    let provider = optional_provider(context, arguments)?;
    let (mode_target, policy_target) = control_targets(context, arguments, provider)?;
    let mode = GatewayModeController::new(&context.app_state_root)
        .status(&mode_target)
        .map_err(|error| error.to_string())?;
    let policy = PolicyStore::new(&context.app_state_root)
        .load(&policy_target)
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "ok",
        "target": mode_target,
        "mode": mode,
        "policy": policy.map(|snapshot| snapshot.policy),
        "provider": provider,
        "runtime": {
            "nativeMcpReferences": "not-managed",
            "liveProviderAttachment": "blocked-until-provider-overlay-is-verified",
        },
    }))
}

pub(super) fn apply_gateway_mode(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let plan = gateway_workflow_plan(context, arguments)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let approval_context = control_approval_context(context)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.mode.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        optional_provider(context, arguments)?,
        json!({
            "plan": plan,
            "nativeMcpReferences": "not-managed",
        }),
    )))
}

pub(super) fn gateway_workflow_plan(
    context: &McpContext,
    arguments: &Value,
) -> Result<crate::sessions::GatewayWorkflowPlan, String> {
    let provider = optional_provider(context, arguments)?;
    let (mode_target, policy_target) = control_targets(context, arguments, provider)?;
    let action = match required_string(arguments, "action")? {
        "install" => GatewayModeAction::Install,
        "on" => GatewayModeAction::Activate,
        "off" => GatewayModeAction::Off,
        "detach" => GatewayModeAction::Detach,
        _ => return Err("action must be install, on, off, or detach".to_string()),
    };
    GatewayWorkflowController::with_authority_keys(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
        context
            .backup_authentication_key
            .clone()
            .ok_or_else(|| "backup authentication key is unavailable".to_string())?,
    )
    .plan(
        mode_target,
        policy_target,
        provider,
        action,
        arguments
            .get("force")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .map_err(|error| error.to_string())
}

pub(super) fn plan_session_end(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let plan = SessionEndController::with_authority_key(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    )
    .plan(required_string(arguments, "sessionId")?, &approval_context)
    .map_err(|error| error.to_string())?;
    context
        .provider_scope
        .require_allowed_optional(plan.provider)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    let operation = control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::Planned,
        plan.provider,
        json!({"plan": plan}),
    );
    Ok(json!({
        "status": "planned",
        "operation": operation,
        "plan": plan,
        "humanApprovalRequired": true,
        "continuation": "Use Unpin CLI to review and apply this fingerprint, then read control status.",
    }))
}

pub(super) fn apply_session_end(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    let approval_context = control_approval_context(context)?;
    let controller = SessionEndController::with_authority_key(
        &context.app_state_root,
        context
            .session_authority_key
            .clone()
            .ok_or_else(|| "session authority key is unavailable".to_string())?,
    );
    let plan = controller
        .plan(required_string(arguments, "sessionId")?, &approval_context)
        .map_err(|error| error.to_string())?;
    context
        .provider_scope
        .require_allowed_optional(plan.provider)?;
    require_plan_fingerprint(arguments, &plan.plan_fingerprint)?;
    let expectation = plan
        .approval_expectation(&approval_context)
        .map_err(|error| error.to_string())?;
    Ok(human_action_required(control_operation(
        &expectation,
        &plan.plan_fingerprint,
        plan.activation,
        ControlOperationLifecycle::AwaitingHumanAction,
        plan.provider,
        json!({"plan": plan}),
    )))
}

pub(super) fn plan_session_launch(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["provider", "exposureRevision", "profile"],
        "session launch arguments",
    )?;
    let provider = required_provider(context, arguments)?;
    let profile = session_launch_profile(context, arguments)?;
    let capability_locks = CapabilityLockSnapshot::compile(
        provider,
        PolicyStore::new(&context.app_state_root)
            .load(&PolicyTarget::Global)
            .map_err(|error| error.to_string())?
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&provider))
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|error| error.to_string())?;
    let exposure = PinnedExposure {
        revision: required_string(arguments, "exposureRevision")?.to_string(),
        profile,
        capability_locks: Some(Box::new(capability_locks)),
    };
    exposure.validate().map_err(|error| error.to_string())?;
    let workspace =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;

    let mut cli_arguments = vec![
        "session".to_string(),
        "launch".to_string(),
        "--project-root".to_string(),
        mcp_cli_path(&workspace.canonical_root, "project root")?,
    ];
    if let Some(fixture_root) = &context.fixture_root {
        cli_arguments.extend([
            "--fixture-root".to_string(),
            mcp_cli_path(fixture_root, "fixture root")?,
        ]);
    }
    cli_arguments.extend([
        "--app-state-root".to_string(),
        mcp_cli_path(&context.app_state_root, "app state root")?,
        "--provider".to_string(),
        provider.as_str().to_string(),
        "--exposure-revision".to_string(),
        exposure.revision.clone(),
        "--capability-lock-revision".to_string(),
        exposure
            .capability_locks
            .as_ref()
            .expect("session launch always pins capability locks")
            .digest
            .clone(),
    ]);
    match &exposure.profile {
        PinnedProfile::Native => cli_arguments.push("--native".to_string()),
        PinnedProfile::None => {}
        PinnedProfile::Profile {
            profile_id,
            profile_digest,
            origin_scope,
            definition_digest,
        } => {
            cli_arguments.extend([
                "--profile-id".to_string(),
                profile_id.clone(),
                "--profile-digest".to_string(),
                profile_digest.clone(),
                "--definition-digest".to_string(),
                definition_digest.clone(),
                "--profile-origin".to_string(),
                profile_source_scope_name(*origin_scope).to_string(),
            ]);
        }
    }
    cli_arguments.extend(["--json".to_string(), "--".to_string()]);
    let profile_handoff = match &exposure.profile {
        PinnedProfile::Native => json!({"type": "native"}),
        PinnedProfile::None => json!({"type": "none"}),
        PinnedProfile::Profile {
            profile_id,
            profile_digest,
            origin_scope,
            definition_digest,
        } => json!({
            "type": "profile",
            "profileId": profile_id,
            "profileDigest": profile_digest,
            "originScope": origin_scope,
            "definitionDigest": definition_digest,
        }),
    };

    Ok(json!({
        "status": "human-action-required",
        "humanAction": {
            "code": "run-session-launch",
            "guidance": "Append the provider harness command after the final -- argument, review the argv array, then run it in a trusted terminal.",
        },
        "handoff": {
            "version": 1,
            "kind": "unpin-cli-session-launch",
            "provider": provider,
            "workspace": {
                "projectRoot": workspace.canonical_root,
                "repositoryKey": workspace.repository_key,
                "workspaceKey": workspace.workspace_key,
                "workspaceRevision": workspace.diagnostics.head,
            },
            "exposure": {
                "revision": exposure.revision,
                "profile": profile_handoff,
                "capabilityLocks": exposure.capability_locks,
            },
            "cli": {
                "executable": "unpin",
                "arguments": cli_arguments,
                "appendChildCommandAfterSeparator": true,
            },
        },
        "constraints": {
            "commandAccepted": false,
            "processSpawned": false,
            "stateWritten": false,
            "approvalMinted": false,
            "authorityExposed": false,
        },
    }))
}

pub(super) fn session_launch_profile(
    context: &McpContext,
    arguments: &Value,
) -> Result<PinnedProfile, String> {
    let profile = arguments
        .get("profile")
        .ok_or_else(|| "missing required field: profile".to_string())?;
    let profile_type = required_string(profile, "type")?;
    match profile_type {
        "native" => {
            require_only_fields(profile, &["type"], "session launch profile")?;
            Ok(PinnedProfile::Native)
        }
        "none" => {
            require_only_fields(profile, &["type"], "session launch profile")?;
            Ok(PinnedProfile::None)
        }
        "profile" => {
            require_only_fields(
                profile,
                &["type", "profileId", "profileDigest", "definitionDigest"],
                "session launch profile",
            )?;
            let profile_id = required_string(profile, "profileId")?;
            let requested_profile_digest = required_string(profile, "profileDigest")?;
            let requested_definition_digest = required_string(profile, "definitionDigest")?;
            let revision = compile_stored_profile(context, profile_id)?;
            if revision.digest != requested_profile_digest
                || revision.origin.definition_digest != requested_definition_digest
            {
                return Err(
                    "session launch profile revision does not match stored definition".to_string(),
                );
            }
            Ok(PinnedProfile::Profile {
                profile_id: revision.profile_id,
                profile_digest: revision.digest,
                origin_scope: revision.origin.scope,
                definition_digest: revision.origin.definition_digest,
            })
        }
        _ => Err("profile.type must be native, none, or profile".to_string()),
    }
}

pub(super) const fn profile_source_scope_name(scope: ProfileSourceScope) -> &'static str {
    match scope {
        ProfileSourceScope::Global => "global",
        ProfileSourceScope::Repository => "repository",
        ProfileSourceScope::Workspace => "workspace",
        ProfileSourceScope::Session => "session",
    }
}

pub(super) fn parse_profile_source_scope(value: &str) -> Result<ProfileSourceScope, String> {
    match value {
        "global" => Ok(ProfileSourceScope::Global),
        "repository" => Ok(ProfileSourceScope::Repository),
        "workspace" => Ok(ProfileSourceScope::Workspace),
        "session" => Ok(ProfileSourceScope::Session),
        _ => Err("sourceScope must be global, repository, workspace, or session".to_string()),
    }
}

pub(super) fn mcp_cli_path(path: &Path, label: &str) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{label} cannot be represented in MCP JSON"))
}

pub(super) fn control_approval_context(
    context: &McpContext,
) -> Result<ControlApprovalContext, String> {
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    ControlApprovalContext::new(identity.repository_key, identity.workspace_key)
        .map_err(|error| error.to_string())
}

pub(super) fn control_targets(
    context: &McpContext,
    arguments: &Value,
    provider: Option<ProviderId>,
) -> Result<(GatewayModeTarget, PolicyTarget), String> {
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    match arguments
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("workspace")
    {
        "global" => Ok((
            provider.map_or_else(
                GatewayModeTarget::global,
                GatewayModeTarget::global_provider,
            ),
            PolicyTarget::Global,
        )),
        "repository" => Ok((
            match provider {
                Some(provider) => {
                    GatewayModeTarget::repository_provider(&identity.repository_key, provider)
                }
                None => GatewayModeTarget::repository(&identity.repository_key),
            }
            .map_err(|error| error.to_string())?,
            PolicyTarget::repository(&identity.repository_key)
                .map_err(|error| error.to_string())?,
        )),
        "workspace" => Ok((
            match provider {
                Some(provider) => GatewayModeTarget::workspace_provider(
                    &identity.repository_key,
                    &identity.workspace_key,
                    provider,
                ),
                None => {
                    GatewayModeTarget::workspace(&identity.repository_key, &identity.workspace_key)
                }
            }
            .map_err(|error| error.to_string())?,
            PolicyTarget::workspace(&identity.repository_key, &identity.workspace_key)
                .map_err(|error| error.to_string())?,
        )),
        _ => Err("scope must be global, repository, or workspace".to_string()),
    }
}
