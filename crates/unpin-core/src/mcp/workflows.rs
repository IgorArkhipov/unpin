use super::*;

use serde_json::{Value, json};

pub(super) fn propose_session_profile(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["prompt", "provider"],
        "profile proposal arguments",
    )?;
    let prompt = required_string(arguments, "prompt")?;
    let provider = optional_provider(context, arguments)?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let store = ProfileStore::new(&context.app_state_root);
    let mut profiles = store
        .list_global_definitions()
        .map_err(|error| error.to_string())?;
    profiles.extend(
        ProfileStore::list_workspace_definitions(&context.project_root)
            .map_err(|error| error.to_string())?,
    );
    let proposal = propose_profile(
        prompt,
        &identity.repository_key,
        &identity.workspace_key,
        provider,
        profiles,
    )
    .map_err(|error| error.to_string())?;
    Ok(json!({
        "status": if proposal.recommended.is_some() { "proposed" } else { "selection-required" },
        "proposal": proposal,
        "humanAction": {
            "code": "confirm-session-profile",
            "guidance": "Ask the user to choose the proposed profile, then use the explicit session launch handoff. This tool never changes exposure.",
        },
    }))
}

pub(super) fn list_workflows(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(arguments, &[], "workflow list arguments")?;
    let workflows = list_stored_workflows(context)?
        .into_iter()
        .map(|entry| workflow_entry_value(&entry))
        .collect::<Vec<_>>();
    Ok(json!({
        "status": "ok",
        "workflows": workflows,
        "mutatesState": false,
    }))
}

pub(super) fn validate_workflow(context: &McpContext, arguments: &Value) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["workflowId", "provider"],
        "workflow validation arguments",
    )?;
    let entry = load_stored_workflow(context, required_string(arguments, "workflowId")?)?;
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let providers = optional_provider(context, arguments)?
        .map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]);
    let revisions = providers
        .into_iter()
        .map(|provider| {
            compile_stored_workflow(context, &entry, provider, &catalog).map(|revision| {
                json!({
                    "provider": provider,
                    "workflowRevision": revision.digest,
                    "definitionDigest": revision.definition_digest,
                    "entryMode": revision.entry_mode,
                    "capabilityCount": revision.maximum_envelope.authored_member_count,
                    "maximumEnvelopeDigest": revision.maximum_envelope.digest,
                    "capabilityLockDigest": revision.capability_lock_digest,
                    "systemControlToolNames": revision.system_controls.iter().map(|control| control.name()).collect::<Vec<_>>(),
                })
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "status": "valid",
        "workflow": workflow_entry_value(&entry),
        "revisions": revisions,
        "materialized": false,
        "mutatesState": false,
    }))
}

pub(super) fn propose_session_workflow(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["prompt", "provider"],
        "workflow proposal arguments",
    )?;
    let prompt = required_string(arguments, "prompt")?;
    if prompt.len() > 16 * 1024 {
        return Err("prompt exceeds 16384-byte limit".to_string());
    }
    let provider = optional_provider(context, arguments)?;
    let ranked = rank_workflow_definitions(prompt, list_stored_workflows(context)?)
        .map_err(|error| error.to_string())?;
    let candidates = ranked
        .iter()
        .take(20)
        .map(|ranked| {
            json!({
                "workflowId": ranked.entry.definition.id,
                "displayName": ranked.entry.definition.display_name,
                "scope": ranked.entry.scope,
                "score": ranked.score,
                "entryMode": ranked.entry.definition.entry_mode,
            })
        })
        .collect::<Vec<_>>();
    let Some(recommended) = ranked.first() else {
        return Ok(workflow_selection_required(prompt, provider, candidates));
    };
    let Some(provider) = provider else {
        return Ok(workflow_selection_required(prompt, None, candidates));
    };
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let revision = compile_stored_workflow(context, &recommended.entry, provider, &catalog)?;
    let identity =
        resolve_workspace_identity(&context.project_root).map_err(|error| error.to_string())?;
    let catalog_revision =
        crate::sha256_digest(&serde_json::to_vec(&catalog).map_err(|error| error.to_string())?);
    let proposal = WorkflowProposalV1::new(
        recommended.entry.definition.id.clone(),
        recommended.entry.definition.entry_mode.clone(),
        provider,
        identity.repository_key,
        identity.workspace_key,
        catalog_revision,
        revision.digest,
        prompt,
        revision.maximum_envelope.authored_member_count,
        true,
        WorkflowReloadLimitation::LiveRefreshExpected,
    )
    .map_err(|error| error.to_string())?;
    Ok(json!({
        "status": "proposed",
        "proposal": proposal,
        "candidates": candidates,
        "humanAction": {
            "code": "confirm-workflow-session",
            "guidance": "Ask the user to confirm the stored workflow, then request a read-only workflow session launch plan. This tool never materializes or launches a session.",
        },
        "constraints": workflow_read_only_constraints(),
    }))
}

pub(super) fn workflow_selection_required(
    prompt: &str,
    provider: Option<ProviderId>,
    candidates: Vec<Value>,
) -> Value {
    json!({
        "status": "selection-required",
        "proposal": {
            "schemaVersion": 1,
            "promptDigest": crate::sha256_digest(prompt.as_bytes()),
            "provider": provider,
            "candidates": candidates,
            "recommended": null,
            "confirmationRequired": true,
            "mutatesState": false,
        },
        "constraints": workflow_read_only_constraints(),
    })
}

pub(super) fn plan_workflow_session_launch(
    context: &McpContext,
    arguments: &Value,
) -> Result<Value, String> {
    require_only_fields(
        arguments,
        &["workflowId", "provider", "workflowRevision", "promptDigest"],
        "workflow session launch arguments",
    )?;
    let provider = required_provider(context, arguments)?;
    let entry = load_stored_workflow(context, required_string(arguments, "workflowId")?)?;
    let discovery = discover_scoped(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let revision = compile_stored_workflow(context, &entry, provider, &catalog)?;
    if let Some(expected) = optional_string(arguments, "workflowRevision")?
        && expected != revision.digest
    {
        return Err("workflow revision mismatch".to_string());
    }
    let prompt_digest = optional_string(arguments, "promptDigest")?;
    if prompt_digest.is_some_and(|digest| !crate::is_lower_hex_digest(digest)) {
        return Err("promptDigest must be a lowercase SHA-256 digest".to_string());
    }
    Ok(json!({
        "status": "human-action-required",
        "plan": {
            "schemaVersion": 1,
            "workflowId": revision.workflow_id,
            "displayName": revision.display_name,
            "provider": revision.provider,
            "workflowRevision": revision.digest,
            "definitionDigest": revision.definition_digest,
            "entryMode": revision.entry_mode,
            "baselineProfileId": revision.baseline_profile_id,
            "baselineProfileDigest": revision.baseline_profile_digest,
            "maximumEnvelopeDigest": revision.maximum_envelope.digest,
            "capabilityLockDigest": revision.capability_lock_digest,
            "promptDigest": prompt_digest,
        },
        "materializationRequired": true,
        "materialized": false,
        "humanAction": {
            "code": "materialize-and-launch-workflow-session",
            "guidance": "Continue in a trusted Unpin CLI or desktop workflow launch surface. That human surface must materialize the compiled revision before launching the provider session.",
        },
        "handoff": {
            "cli": {
                "required": true,
                "action": "validate-materialize-and-launch-workflow-session",
                "workflowId": entry.definition.id,
                "provider": provider,
            },
            "desktop": {
                "required": true,
                "action": "review-materialize-and-launch-workflow-session",
                "workflowId": entry.definition.id,
                "provider": provider,
            },
        },
        "constraints": workflow_read_only_constraints(),
    }))
}

pub(super) fn workflow_read_only_constraints() -> Value {
    json!({
        "inlineDefinitionAccepted": false,
        "arbitraryPathAccepted": false,
        "processSpawned": false,
        "stateWritten": false,
        "approvalMinted": false,
        "authorityExposed": false,
    })
}

pub(super) fn list_stored_workflows(
    context: &McpContext,
) -> Result<Vec<WorkflowDefinitionEntry>, String> {
    let mut effective = WorkflowStore::new(&context.app_state_root)
        .list_global_definitions()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|entry| (entry.definition.id.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    for entry in WorkflowStore::list_workspace_definitions(&context.project_root)
        .map_err(|error| error.to_string())?
    {
        effective.insert(entry.definition.id.clone(), entry);
    }
    Ok(effective.into_values().collect())
}

pub(super) fn load_stored_workflow(
    context: &McpContext,
    workflow_id: &str,
) -> Result<WorkflowDefinitionEntry, String> {
    if let Some(entry) =
        WorkflowStore::load_workspace_definition(&context.project_root, workflow_id)
            .map_err(|error| error.to_string())?
    {
        return Ok(entry);
    }
    WorkflowStore::new(&context.app_state_root)
        .load_global_definition(workflow_id)
        .map_err(|error| error.to_string())?
        .map(|snapshot| WorkflowDefinitionEntry {
            scope: ProfileSourceScope::Global,
            definition: snapshot.value,
            revision: Some(snapshot.revision),
        })
        .ok_or_else(|| "workflow not found".to_string())
}

pub(super) fn compile_stored_workflow(
    context: &McpContext,
    entry: &WorkflowDefinitionEntry,
    provider: ProviderId,
    catalog: &Catalog,
) -> Result<CompiledWorkflowRevision, String> {
    context.provider_scope.require_allowed(provider)?;
    let profile_ids = std::iter::once(entry.definition.baseline_profile_id.clone())
        .chain(
            entry
                .definition
                .modes
                .iter()
                .map(|mode| mode.profile_id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut profiles = BTreeMap::new();
    for profile_id in profile_ids {
        let (definition, scope) = load_stored_profile(context, &profile_id)?;
        profiles.insert(
            profile_id,
            compile_profile(&definition, catalog, scope).map_err(|error| error.to_string())?,
        );
    }
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
    compile_workflow(
        &entry.definition,
        &profiles,
        catalog,
        &capability_locks,
        provider,
        entry.scope,
    )
    .map_err(|error| error.to_string())
}

pub(super) fn workflow_entry_value(entry: &WorkflowDefinitionEntry) -> Value {
    json!({
        "workflowId": entry.definition.id,
        "displayName": entry.definition.display_name,
        "description": entry.definition.description,
        "scope": entry.scope,
        "baselineProfileId": entry.definition.baseline_profile_id,
        "entryMode": entry.definition.entry_mode,
        "modes": entry.definition.modes,
    })
}
