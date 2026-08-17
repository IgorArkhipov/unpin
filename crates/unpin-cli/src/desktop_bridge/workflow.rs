use super::*;

use serde_json::{Value, json};

pub(super) fn compose_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "workflowId",
            "displayName",
            "description",
            "provider",
            "baselineProfileId",
            "entryMode",
            "modes",
        ],
    )?;
    let provider = required_string(params, "provider")?;
    parse_provider_id(provider).ok_or("invalid-workflow-provider")?;
    let modes = params
        .get("modes")
        .and_then(Value::as_array)
        .ok_or("invalid-workflow-modes")?
        .iter()
        .map(|mode| {
            require_only_params(mode, &["name", "profileId"])?;
            Ok::<WorkflowModeDraft, &'static str>(WorkflowModeDraft {
                name: required_string(mode, "name")?.to_string(),
                profile_id: required_string(mode, "profileId")?.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let definition = WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: required_string(params, "workflowId")?.to_string(),
        display_name: required_string(params, "displayName")?.to_string(),
        description: optional_bounded_string(params, "description")?.map(str::to_string),
        baseline_profile_id: required_string(params, "baselineProfileId")?.to_string(),
        entry_mode: required_string(params, "entryMode")?.to_string(),
        modes: modes
            .iter()
            .map(|mode| WorkflowModeDefinition::new(&mode.name, &mode.profile_id))
            .collect(),
    };
    definition
        .validate()
        .map_err(|_| "invalid-workflow-definition")?;
    let workflow_revision = definition
        .definition_digest()
        .map_err(|_| "invalid-workflow-definition")?;
    let draft = WorkflowDraft {
        workflow_id: definition.id,
        display_name: definition.display_name,
        description: definition.description,
        provider: provider.to_string(),
        baseline_profile_id: definition.baseline_profile_id,
        entry_mode: definition.entry_mode,
        modes,
        workflow_revision,
    };
    state
        .workflows
        .insert(draft.workflow_id.clone(), draft.clone());
    Ok(json!({
        "status": "composed",
        "workflowRevision": draft.workflow_revision,
        "workflow": workflow_draft_value(&draft),
        "errors": [],
    }))
}

pub(super) fn validate_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["workflowId", "provider", "workflowRevision"])?;
    let workflow_id = required_string(params, "workflowId")?;
    let provider = parse_provider_id(required_string(params, "provider")?)
        .ok_or("invalid-workflow-provider")?;
    let draft = state
        .workflows
        .get(workflow_id)
        .cloned()
        .ok_or("workflow-draft-unavailable")?;
    if optional_bounded_string(params, "workflowRevision")?
        .is_some_and(|revision| revision != draft.workflow_revision)
    {
        return Err("workflow-revision-mismatch");
    }
    let (definition, revision) = compile_workflow_draft(&state.context, &draft, provider)?;
    Ok(json!({
        "status": "valid",
        "valid": true,
        "workflow": workflow_draft_value(&draft),
        "workflowRevision": revision.digest,
        "provider": provider,
        "capabilityCount": revision.maximum_envelope.authored_member_count,
        "reloadLimitation": WorkflowReloadLimitation::LiveRefreshExpected,
        "errors": [],
        "definitionDigest": definition.definition_digest().map_err(|_| "workflow-validation-failed")?,
    }))
}

pub(super) fn propose_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["prompt", "workflowId", "provider"])?;
    let prompt = required_string(params, "prompt")?;
    let workflow_id = optional_bounded_string(params, "workflowId")?;
    let provider = optional_bounded_string(params, "provider")?
        .and_then(parse_provider_id)
        .ok_or("workflow-provider-required")?;
    let draft = match workflow_id {
        Some(workflow_id) => state
            .workflows
            .get(workflow_id)
            .cloned()
            .ok_or("workflow-draft-unavailable")?,
        None => state
            .workflows
            .values()
            .find(|draft| draft.provider == provider.as_str())
            .cloned()
            .ok_or("workflow-selection-required")?,
    };
    let (_, revision) = compile_workflow_draft(&state.context, &draft, provider)?;
    let identity = state
        .context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let discovery = cached_discovery(&state.context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    let catalog_revision = desktop_catalog_digest(&catalog);
    let proposal = WorkflowProposalV1::new(
        draft.workflow_id.clone(),
        draft.entry_mode.clone(),
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
    .map_err(|_| "workflow-proposal-invalid")?;
    state.reviewed_workflow_launches.insert(
        proposal.proposal_id.clone(),
        ReviewedWorkflowLaunch {
            workflow_id: draft.workflow_id.clone(),
            proposal_fingerprint: proposal.proposal_fingerprint.clone(),
            proposal: proposal.clone(),
            reviewed_at_unix: unix_now(),
        },
    );
    Ok(json!({
        "status": "proposed",
        "proposal": proposal,
        "candidates": [{
            "workflowId": draft.workflow_id,
            "displayName": draft.display_name,
            "scope": "desktop-draft",
            "score": 1,
            "entryMode": draft.entry_mode,
        }],
        "confirmationRequired": true,
        "nextAction": "confirm-workflow-session",
    }))
}

pub(super) fn launch_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &["proposalId", "proposalFingerprint", "hostCommand"],
    )?;
    let proposal_id = required_string(params, "proposalId")?;
    let proposal_fingerprint = required_string(params, "proposalFingerprint")?;
    let reviewed = state
        .reviewed_workflow_launches
        .get(proposal_id)
        .cloned()
        .ok_or("workflow-proposal-unavailable")?;
    if reviewed.proposal_fingerprint != proposal_fingerprint {
        return Err("workflow-proposal-fingerprint-mismatch");
    }
    if state.workflow_session_id.is_some() {
        return Err("workflow-session-already-active");
    }
    let host_command = workflow_host_command(params)?;
    let draft = state
        .workflows
        .get(&reviewed.workflow_id)
        .cloned()
        .ok_or("workflow-draft-unavailable")?;
    let (definition, revision) =
        compile_workflow_draft(&state.context, &draft, reviewed.proposal.provider)?;
    validate_reviewed_workflow(&reviewed.proposal, &definition, &revision, &state.context)?;
    WorkflowStore::new(&state.context.config.app_state_root)
        .materialize_revision(
            &revision,
            OwnerGeneration::new(
                format!("desktop-workflow-{}", reviewed.proposal.proposal_id),
                1,
            )
            .map_err(|_| "workflow-revision-unavailable")?,
        )
        .map_err(|_| "workflow-revision-unavailable")?;
    let policy = PolicyStore::new(&state.context.config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|_| "workflow-policy-unavailable")?;
    let locks = CapabilityLockSnapshot::compile(
        reviewed.proposal.provider,
        policy
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&reviewed.proposal.provider))
            .map(|provider| provider.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|_| "workflow-policy-invalid")?;
    let entry = revision
        .effective_profiles
        .get(&revision.entry_mode)
        .ok_or("workflow-entry-profile-missing")?;
    let authority_key = credentials::resolve_session_authority_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-session-authority-unavailable")?
    .ok_or("workflow-session-authority-unavailable")?;
    let backup_authentication_key = credentials::resolve_backup_authentication_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-backup-authority-unavailable")?
    .ok_or("workflow-backup-authority-unavailable")?;
    let identity = state
        .context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let request = session_process::SessionLaunchRequest {
        app_state_root: state.context.config.app_state_root.clone(),
        discovery_roots: state.context.discovery_roots.clone(),
        repository_key: identity.repository_key,
        workspace_key: identity.workspace_key,
        workspace_revision: identity.diagnostics.head,
        provider: reviewed.proposal.provider,
        exposure: PinnedExposure {
            revision: entry.digest.clone(),
            profile: PinnedProfile::Profile {
                profile_id: entry.profile_id.clone(),
                profile_digest: entry.digest.clone(),
                origin_scope: ProfileSourceScope::Session,
                definition_digest: revision.digest.clone(),
            },
            capability_locks: Some(Box::new(locks)),
        },
        workflow: Some(session_process::WorkflowLaunchRequest {
            workflow_id: reviewed.proposal.workflow_id.clone(),
            workflow_revision: reviewed.proposal.workflow_revision.clone(),
            entry_mode: reviewed.proposal.entry_mode.clone(),
            catalog_revision: reviewed.proposal.catalog_revision.clone(),
            proposal_id: reviewed.proposal.proposal_id.clone(),
            proposal_fingerprint: reviewed.proposal.proposal_fingerprint.clone(),
            prompt_digest: reviewed.proposal.prompt_digest.clone(),
            capability_count: reviewed.proposal.capability_count,
        }),
        bridge_socket: None,
        command: host_command,
        authority_key,
        backup_authentication_key,
        fixture_mode: state.context.fixture_mode,
    };
    let (established_sender, established_receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("unpin-desktop-workflow-session".to_string())
        .spawn(move || {
            match session_process::launch_with_established_callback(request, |established| {
                let _ = established_sender.send(Ok(established));
            }) {
                Ok(_) => {}
                Err(error) => {
                    let _ = established_sender.send(Err(error.to_string()));
                }
            }
        })
        .map_err(|_| "workflow-launch-failed")?;
    let established = established_receiver
        .recv_timeout(Duration::from_secs(15))
        .map_err(|_| "workflow-launch-unconfirmed")?
        .map_err(|_| "workflow-launch-failed")?;
    state.workflow_session_id = Some(established.session_id.clone());
    state.reviewed_workflow_launches.remove(proposal_id);
    let session = current_workflow_session(state)?;
    let operations = workflow_operations(state, Some(&session))?;
    Ok(json!({
        "status": "launched",
        "sessionId": established.session_id,
        "session": workflow_session_value(&session, &operations),
        "nextAction": "inspect-workflow-status",
    }))
}

pub(super) fn transition_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(
        params,
        &[
            "operationId",
            "operationFingerprint",
            "sourceStateSequence",
            "targetMode",
            "requestedAtUnix",
        ],
    )?;
    let session_id = workflow_session_id(state)?;
    let target_mode = required_string(params, "targetMode")?;
    let session = current_workflow_session(state)?;
    let workflow = session
        .lease
        .workflow
        .as_deref()
        .ok_or("workflow-session-unavailable")?;
    if !workflow.profile_revisions.contains_key(target_mode) {
        return Err("workflow-expansion-requires-review");
    }
    let source_state_sequence = params
        .get("sourceStateSequence")
        .and_then(Value::as_u64)
        .ok_or("invalid-workflow-transition")?;
    let requested_at_unix = params
        .get("requestedAtUnix")
        .and_then(Value::as_i64)
        .ok_or("invalid-workflow-transition")?;
    let result = session_process::call_gateway_control(
        &state.context.config.app_state_root,
        &session_id,
        "unpin_workflow_enter_mode",
        json!(WorkflowTransitionRequest {
            operation_id: required_string(params, "operationId")?.to_string(),
            operation_fingerprint: required_string(params, "operationFingerprint")?.to_string(),
            source_state_sequence,
            target_mode: target_mode.to_string(),
            requested_at_unix,
        }),
    )
    .map_err(|_| "workflow-transition-blocked")?;
    let session = current_workflow_session(state)?;
    let operations = workflow_operations(state, Some(&session))?;
    Ok(json!({
        "result": result.get("result").cloned().unwrap_or(result),
        "session": workflow_session_value(&session, &operations),
        "status": workflow_status_value(Some(&session)),
    }))
}

pub(super) fn observe_workflow(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &[])?;
    let session = current_workflow_session(state)?;
    let operations = workflow_operations(state, Some(&session))?;
    Ok(json!({
        "session": workflow_session_value(&session, &operations),
        "status": workflow_status_value(Some(&session)),
    }))
}

pub(super) fn cancel_workflow_transition(
    state: &mut DesktopBridgeState,
    params: &Value,
) -> Result<Value, &'static str> {
    require_only_params(params, &["operationId"])?;
    let operation_id = required_string(params, "operationId")?;
    let session_id = workflow_session_id(state)?;
    let _ = session_process::call_gateway_control(
        &state.context.config.app_state_root,
        &session_id,
        "unpin_workflow_cancel_transition",
        json!({"operationId": operation_id}),
    )
    .map_err(|_| "workflow-cancel-blocked")?;
    let session = current_workflow_session(state)?;
    let operations = workflow_operations(state, Some(&session))?;
    Ok(json!({
        "status": "cancelled",
        "operationId": operation_id,
        "session": workflow_session_value(&session, &operations),
    }))
}

pub(super) fn workflow_status(state: &mut DesktopBridgeState) -> Result<Value, &'static str> {
    let session = discover_current_workflow_session(state)?;
    if state.workflow_session_id.is_none() {
        state.workflow_session_id = session
            .as_ref()
            .map(|snapshot| snapshot.lease.session_id.clone());
    }
    let operations = workflow_operations(state, session.as_ref())?;
    let recovery_required =
        session.as_ref().is_some_and(workflow_recovery_required) || !operations.is_empty();
    let workflows = state
        .workflows
        .values()
        .map(workflow_draft_value)
        .collect::<Vec<_>>();
    let selected_workflow_id = session
        .as_ref()
        .and_then(|session| session.lease.workflow.as_deref())
        .map(|workflow| workflow.workflow_id.clone())
        .or_else(|| {
            (workflows.len() == 1)
                .then(|| state.workflows.keys().next().cloned())
                .flatten()
        });
    let selected_workflow = selected_workflow_id
        .as_deref()
        .and_then(|workflow_id| state.workflows.get(workflow_id))
        .map(workflow_draft_value);
    Ok(json!({
        "status": workflow_status_value(session.as_ref()),
        "session": session.as_ref().map(|session| workflow_session_value(session, &operations)),
        "workflow": selected_workflow,
        "workflows": workflows,
        "selectedWorkflowId": selected_workflow_id,
        "operations": operations,
        "recoveryRequired": recovery_required,
    }))
}

pub(super) fn workflow_recovery(state: &mut DesktopBridgeState) -> Result<Value, &'static str> {
    let session = discover_current_workflow_session(state)?;
    if state.workflow_session_id.is_none() {
        state.workflow_session_id = session
            .as_ref()
            .map(|snapshot| snapshot.lease.session_id.clone());
    }
    let operations = workflow_operations(state, session.as_ref())?;
    let recovery_required =
        session.as_ref().is_some_and(workflow_recovery_required) || !operations.is_empty();
    Ok(json!({
        "status": if recovery_required { "recovery-required" } else { "ready" },
        "recoveryRequired": recovery_required,
        "operations": operations,
        "session": session.as_ref().map(|session| workflow_session_value(session, &operations)),
        "message": if recovery_required {
            "Inspect the pending transition before choosing cancel or relaunch."
        } else {
            "No workflow recovery is required."
        },
    }))
}

pub(super) fn workflow_host_command(params: &Value) -> Result<Vec<OsString>, &'static str> {
    let command = params
        .get("hostCommand")
        .and_then(Value::as_array)
        .ok_or("workflow-host-command-required")?;
    if command.is_empty() || command.len() > 128 {
        return Err("workflow-host-command-required");
    }
    command
        .iter()
        .map(|part| {
            part.as_str()
                .filter(|part| !part.is_empty() && part.len() <= 16 * 1024)
                .map(OsString::from)
                .ok_or("invalid-workflow-host-command")
        })
        .collect()
}

pub(super) fn validate_reviewed_workflow(
    proposal: &WorkflowProposalV1,
    definition: &WorkflowDefinition,
    revision: &unpin_core::workflows::CompiledWorkflowRevision,
    context: &DesktopBridgeContext,
) -> Result<(), &'static str> {
    let identity = context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let discovery = fresh_discovery(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    if definition.id != proposal.workflow_id
        || definition.entry_mode != proposal.entry_mode
        || revision.provider != proposal.provider
        || identity.repository_key != proposal.repository_key
        || identity.workspace_key != proposal.workspace_key
        || desktop_catalog_digest(&catalog) != proposal.catalog_revision
        || revision.digest != proposal.workflow_revision
        || revision.maximum_envelope.authored_member_count != proposal.capability_count
        || !proposal.gateway_required
    {
        return Err("workflow-proposal-stale");
    }
    Ok(())
}

pub(super) fn workflow_session_id(state: &DesktopBridgeState) -> Result<String, &'static str> {
    state
        .workflow_session_id
        .clone()
        .ok_or("workflow-session-unavailable")
}

pub(super) fn current_workflow_session(
    state: &DesktopBridgeState,
) -> Result<LeaseSnapshot, &'static str> {
    let session_id = workflow_session_id(state)?;
    let authority_key = credentials::resolve_session_authority_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-session-authority-unavailable")?
    .ok_or("workflow-session-authority-unavailable")?;
    SessionManager::with_authority_key(&state.context.config.app_state_root, authority_key)
        .list()
        .map_err(|_| "workflow-session-unavailable")?
        .into_iter()
        .find(|snapshot| snapshot.lease.session_id == session_id)
        .ok_or("workflow-session-unavailable")
}

pub(super) fn discover_current_workflow_session(
    state: &DesktopBridgeState,
) -> Result<Option<LeaseSnapshot>, &'static str> {
    let authority_key = credentials::resolve_session_authority_key(
        state.context.fixture_mode,
        &state.context.config.app_state_root,
    )
    .map_err(|_| "workflow-session-authority-unavailable")?
    .ok_or("workflow-session-authority-unavailable")?;
    let identity = state
        .context
        .config
        .workspace_identity()
        .map_err(|_| "workspace-identity-unavailable")?;
    let sessions =
        SessionManager::with_authority_key(&state.context.config.app_state_root, authority_key)
            .list()
            .map_err(|_| "workflow-session-unavailable")?;
    if let Some(session_id) = state.workflow_session_id.as_deref() {
        return Ok(sessions
            .into_iter()
            .find(|snapshot| snapshot.lease.session_id == session_id));
    }
    let mut matches = sessions.into_iter().filter(|snapshot| {
        snapshot.lease.lifecycle == unpin_core::sessions::LeaseLifecycle::Active
            && snapshot.lease.workflow.is_some()
            && snapshot.lease.repository_key == identity.repository_key
            && snapshot.lease.workspace_key == identity.workspace_key
    });
    let selected = matches.next();
    if matches.next().is_some() {
        return Err("workflow-session-selection-required");
    }
    Ok(selected)
}

pub(super) fn workflow_operations(
    state: &DesktopBridgeState,
    session: Option<&LeaseSnapshot>,
) -> Result<Vec<WorkflowOperationRecord>, &'static str> {
    let Some(session) = session else {
        return Ok(Vec::new());
    };
    WorkflowJournal::new(&state.context.config.app_state_root)
        .nonterminal_records(&session.lease.session_id)
        .map_err(|_| "workflow-operation-history-unavailable")
}

pub(super) fn workflow_recovery_required(session: &LeaseSnapshot) -> bool {
    session.lease.desired_exposure != session.lease.observed_exposure
        && matches!(
            session.lease.live_status,
            unpin_core::sessions::LiveExposureStatus::ReloadRequired
                | unpin_core::sessions::LiveExposureStatus::NextSessionOnly
                | unpin_core::sessions::LiveExposureStatus::Unknown
        )
}

pub(super) fn compile_workflow_draft(
    context: &DesktopBridgeContext,
    draft: &WorkflowDraft,
    provider: ProviderId,
) -> Result<
    (
        WorkflowDefinition,
        unpin_core::workflows::CompiledWorkflowRevision,
    ),
    &'static str,
> {
    let definition = WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: draft.workflow_id.clone(),
        display_name: draft.display_name.clone(),
        description: draft.description.clone(),
        baseline_profile_id: draft.baseline_profile_id.clone(),
        entry_mode: draft.entry_mode.clone(),
        modes: draft
            .modes
            .iter()
            .map(|mode| WorkflowModeDefinition::new(&mode.name, &mode.profile_id))
            .collect(),
    };
    definition
        .validate()
        .map_err(|_| "workflow-validation-failed")?;
    let discovery = fresh_discovery(context)?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|_| "catalog-unavailable")?;
    let profile_store = ProfileStore::new(&context.config.app_state_root);
    let profile_ids = std::iter::once(definition.baseline_profile_id.clone())
        .chain(definition.modes.iter().map(|mode| mode.profile_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut profiles = BTreeMap::new();
    for profile_id in profile_ids {
        let entry =
            ProfileStore::load_workspace_definition(&context.config.project_root, &profile_id)
                .map_err(|_| "workflow-profile-unavailable")?
                .or_else(|| {
                    profile_store
                        .load_global_definition(&profile_id)
                        .ok()
                        .flatten()
                        .map(|snapshot| unpin_core::profiles::ProfileDefinitionEntry {
                            scope: ProfileSourceScope::Global,
                            definition: snapshot.value,
                            revision: Some(snapshot.revision),
                        })
                })
                .ok_or("workflow-profile-unavailable")?;
        profiles.insert(
            profile_id,
            compile_profile(&entry.definition, &catalog, entry.scope)
                .map_err(|_| "workflow-profile-invalid")?,
        );
    }
    let policy = PolicyStore::new(&context.config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|_| "workflow-policy-unavailable")?;
    let locks = CapabilityLockSnapshot::compile(
        provider,
        policy
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&provider))
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|_| "workflow-policy-invalid")?;
    let revision = compile_workflow(
        &definition,
        &profiles,
        &catalog,
        &locks,
        provider,
        ProfileSourceScope::Workspace,
    )
    .map_err(|_| "workflow-validation-failed")?;
    Ok((definition, revision))
}

pub(super) fn desktop_catalog_digest(catalog: &Catalog) -> String {
    unpin_core::sha256_digest(&serde_json::to_vec(catalog).expect("catalog serialization"))
}

pub(super) fn workflow_draft_value(draft: &WorkflowDraft) -> Value {
    json!({
        "workflowId": draft.workflow_id,
        "displayName": draft.display_name,
        "description": draft.description,
        "provider": draft.provider,
        "baselineProfileId": draft.baseline_profile_id,
        "entryMode": draft.entry_mode,
        "modes": draft.modes.iter().map(|mode| json!({
            "name": mode.name,
            "profileId": mode.profile_id,
        })).collect::<Vec<_>>(),
        "workflowRevision": draft.workflow_revision,
    })
}

pub(super) fn workflow_session_value(
    session: &LeaseSnapshot,
    operation_history: &[WorkflowOperationRecord],
) -> Value {
    let workflow = session.lease.workflow.as_deref();
    json!({
        "sessionId": session.lease.session_id,
        "workflowId": workflow.map(|workflow| workflow.workflow_id.as_str()),
        "proposalId": workflow.map(|workflow| workflow.proposal_id.as_str()),
        "activeMode": observed_workflow_mode(session),
        "desiredMode": workflow.map(|workflow| workflow.active_mode.as_str()),
        "observedMode": observed_workflow_mode(session),
        "desiredExposureRevision": session.lease.desired_exposure.revision,
        "observedExposureRevision": session.lease.observed_exposure.revision,
        "stateSequence": session.revision.sequence,
        "liveStatus": session.lease.live_status,
        "admissionOpen": session.lease.admission_open,
        "operationHistory": operation_history,
    })
}

pub(super) fn workflow_status_value(session: Option<&LeaseSnapshot>) -> Value {
    session.map_or_else(
        || {
            json!({
                "activeMode": null,
                "desiredMode": null,
                "observedMode": null,
                "stateSequence": null,
                "liveStatus": "no-session",
                "admissionOpen": false,
                "recoveryRequired": false,
            })
        },
        |session| {
            let workflow = session.lease.workflow.as_deref();
            json!({
                "sessionId": session.lease.session_id,
                "workflowId": workflow.map(|workflow| workflow.workflow_id.as_str()),
                "activeMode": observed_workflow_mode(session),
                "desiredMode": workflow.map(|workflow| workflow.active_mode.as_str()),
                "observedMode": observed_workflow_mode(session),
                "stateSequence": session.revision.sequence,
                "liveStatus": session.lease.live_status,
                "admissionOpen": session.lease.admission_open,
                "recoveryRequired": workflow_recovery_required(session),
            })
        },
    )
}

pub(super) fn observed_workflow_mode(session: &LeaseSnapshot) -> Option<&str> {
    let workflow = session.lease.workflow.as_deref()?;
    workflow
        .profile_revisions
        .iter()
        .find_map(|(mode, revision)| {
            (revision == &session.lease.observed_exposure.revision).then_some(mode.as_str())
        })
}

pub(super) fn handshake_response() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "binaryVersion": env!("CARGO_PKG_VERSION"),
        "capabilities": BRIDGE_CAPABILITIES,
    })
}

pub(super) fn handshake_response_for_binding(binding: &BridgeBinding) -> Value {
    let mut response = handshake_response();
    response["binding"] = json!({
        "parentPid": binding.parent_pid,
        "parentStartMarker": binding.parent_start_marker,
        "childPid": binding.child_pid,
        "childStartMarker": binding.child_start_marker,
        "projectRoot": binding.project_root,
        "appStateRoot": binding.app_state_root,
        "processGeneration": binding.process_generation,
    });
    response
}
