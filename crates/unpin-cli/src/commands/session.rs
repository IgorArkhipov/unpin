use std::{ffi::OsString, path::PathBuf, process::ExitCode};

use clap::Subcommand;
use unpin_core::{
    approval::ControlApprovalContext,
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        DurableControlError,
    },
    profiles::{CapabilityLockSnapshot, PolicyStore, PolicyTarget, ProfileSourceScope},
    sessions::{
        PinnedExposure, PinnedProfile, SessionEndControlError, SessionEndController,
        SessionManager, WorkflowTransitionRequest,
    },
};

use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, session_process, unix_now,
};

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommands {
    /// Launch one child harness with a connection-scoped lease and private overlay.
    Launch {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Provider harness represented by this session.
        #[arg(long)]
        provider: String,
        /// Immutable exposure revision digest.
        #[arg(long)]
        exposure_revision: String,
        /// Reviewed global capability lock revision; fails if policy drifted.
        #[arg(long)]
        capability_lock_revision: Option<String>,
        /// Select native provider behavior instead of an empty profile.
        #[arg(long)]
        native: bool,
        /// Pinned profile id; requires both profile digest fields.
        #[arg(long)]
        profile_id: Option<String>,
        /// Pinned compiled profile revision digest.
        #[arg(long)]
        profile_digest: Option<String>,
        /// Pinned source definition digest.
        #[arg(long)]
        definition_digest: Option<String>,
        /// Pinned profile origin scope; defaults to workspace for compatibility.
        #[arg(long)]
        profile_origin: Option<String>,
        /// Reviewed workflow definition id from `workflow propose`.
        #[arg(long)]
        workflow_id: Option<String>,
        /// Reviewed compiled workflow revision digest.
        #[arg(long)]
        workflow_revision: Option<String>,
        /// Reviewed workflow entry mode.
        #[arg(long)]
        workflow_entry_mode: Option<String>,
        /// Catalog revision bound by the reviewed workflow proposal.
        #[arg(long)]
        workflow_catalog_revision: Option<String>,
        /// Proposal id emitted by `workflow propose`.
        #[arg(long)]
        workflow_proposal_id: Option<String>,
        /// Proposal fingerprint emitted by `workflow propose`.
        #[arg(long)]
        workflow_proposal_fingerprint: Option<String>,
        /// Prompt digest emitted by `workflow propose`.
        #[arg(long)]
        workflow_prompt_digest: Option<String>,
        /// Capability count emitted by `workflow propose`.
        #[arg(long)]
        workflow_capability_count: Option<usize>,
        /// Active Unpin hook bridge control socket.
        #[arg(long)]
        bridge_socket: Option<PathBuf>,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
        /// Child command and arguments, separated with `--`.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// List active established leases; pending bootstrap secrets are never shown.
    List {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Show redacted workflow-aware state for established sessions.
    Status {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Restrict the result to one exact session id.
        #[arg(long)]
        id: Option<String>,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Request an explicit in-envelope workflow mode transition.
    EnterMode {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Exact session id from `session status`.
        #[arg(long)]
        id: String,
        /// Named mode in the pinned workflow envelope.
        #[arg(long, alias = "mode")]
        target_mode: String,
        /// Caller-chosen durable operation id.
        #[arg(long)]
        operation_id: String,
        /// Fingerprint of the reviewed transition request.
        #[arg(long)]
        operation_fingerprint: String,
        /// Expected lease state sequence; defaults to the current authenticated state.
        #[arg(long)]
        source_state_sequence: Option<u64>,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Cancel a staged or reload-pending workflow transition.
    CancelTransition {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Exact session id from `session status`.
        #[arg(long)]
        id: String,
        /// Durable transition operation id.
        #[arg(long)]
        operation_id: String,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Reconcile and explain a session transition recovery state.
    #[command(alias = "recover")]
    Recovery {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Exact session id from `session status`.
        #[arg(long)]
        id: String,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
    /// Fence one active session; owner process retains cleanup responsibility.
    End {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned runtime state root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Exact session id from `session list`.
        #[arg(long)]
        id: String,
        /// Apply reviewed end plan. Omit for dry-run.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
        /// Render machine-readable result.
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(command: SessionCommands) -> ExitCode {
    match command {
        SessionCommands::Launch {
            roots,
            app_state_root,
            provider,
            exposure_revision,
            capability_lock_revision,
            native,
            profile_id,
            profile_digest,
            definition_digest,
            profile_origin,
            workflow_id,
            workflow_revision,
            workflow_entry_mode,
            workflow_catalog_revision,
            workflow_proposal_id,
            workflow_proposal_fingerprint,
            workflow_prompt_digest,
            workflow_capability_count,
            bridge_socket,
            json,
            command,
        } => launch(
            roots,
            app_state_root,
            &provider,
            exposure_revision,
            capability_lock_revision,
            native,
            profile_id,
            profile_digest,
            definition_digest,
            profile_origin,
            workflow_id,
            workflow_revision,
            workflow_entry_mode,
            workflow_catalog_revision,
            workflow_proposal_id,
            workflow_proposal_fingerprint,
            workflow_prompt_digest,
            workflow_capability_count,
            bridge_socket,
            json,
            command,
        ),
        SessionCommands::List {
            roots,
            app_state_root,
            json,
        } => list(roots, app_state_root, json),
        SessionCommands::Status {
            roots,
            app_state_root,
            id,
            json,
        } => session_status(roots, app_state_root, id.as_deref(), json),
        SessionCommands::EnterMode {
            roots,
            app_state_root,
            id,
            target_mode,
            operation_id,
            operation_fingerprint,
            source_state_sequence,
            json,
        } => enter_mode(
            roots,
            app_state_root,
            &id,
            &target_mode,
            &operation_id,
            &operation_fingerprint,
            source_state_sequence,
            json,
        ),
        SessionCommands::CancelTransition {
            roots,
            app_state_root,
            id,
            operation_id,
            json,
        } => cancel_transition(roots, app_state_root, &id, &operation_id, json),
        SessionCommands::Recovery {
            roots,
            app_state_root,
            id,
            json,
        } => recovery(roots, app_state_root, &id, json),
        SessionCommands::End {
            roots,
            app_state_root,
            id,
            apply,
            confirm,
            plan_fingerprint,
            json,
        } => end(
            roots,
            app_state_root,
            &id,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
            json,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn launch(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    provider: &str,
    exposure_revision: String,
    capability_lock_revision: Option<String>,
    native: bool,
    profile_id: Option<String>,
    profile_digest: Option<String>,
    definition_digest: Option<String>,
    profile_origin: Option<String>,
    workflow_id: Option<String>,
    workflow_revision: Option<String>,
    workflow_entry_mode: Option<String>,
    workflow_catalog_revision: Option<String>,
    workflow_proposal_id: Option<String>,
    workflow_proposal_fingerprint: Option<String>,
    workflow_prompt_digest: Option<String>,
    workflow_capability_count: Option<usize>,
    bridge_socket: Option<PathBuf>,
    json: bool,
    command: Vec<OsString>,
) -> ExitCode {
    let fixture_mode = roots.fixture_root.is_some();
    let provider = match parse_provider_id(provider) {
        Some(provider) => provider,
        None => return command_error_exit(json, "failed", "unsupported provider"),
    };
    let profile = match session_profile_selection(
        native,
        profile_id,
        profile_digest,
        definition_digest,
        profile_origin,
    ) {
        Ok(profile) => profile,
        Err(error) => return command_error_exit(json, "failed", error),
    };
    let workflow = match workflow_launch_selection(
        workflow_id,
        workflow_revision,
        workflow_entry_mode,
        workflow_catalog_revision,
        workflow_proposal_id,
        workflow_proposal_fingerprint,
        workflow_prompt_digest,
        workflow_capability_count,
    ) {
        Ok(workflow) => workflow,
        Err(error) => return command_error_exit(json, "failed", error),
    };
    if let Err(error) = session_process::preflight_bridge_socket(bridge_socket.as_deref()) {
        return command_error_exit(json, "failed", &error.to_string());
    }
    let config = match resolve_config(&roots, app_state_root) {
        Ok(config) => config,
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    let workspace = match config.workspace_identity() {
        Ok(workspace) => workspace,
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    let capability_locks = match PolicyStore::new(&config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|error| error.to_string())
        .and_then(|snapshot| {
            CapabilityLockSnapshot::compile(
                provider,
                snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.policy.providers.get(&provider))
                    .map(|policy| policy.capability_locks.clone())
                    .unwrap_or_default(),
            )
            .map_err(|error| error.to_string())
        }) {
        Ok(locks) => locks,
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    if capability_lock_revision
        .as_deref()
        .is_some_and(|revision| revision != capability_locks.digest)
    {
        return command_error_exit(json, "blocked", "capability-lock-revision-mismatch");
    }
    let discovery_roots = match resolve_discovery_roots_with_config(&roots, &config) {
        Ok(roots) => roots.with_app_state_root(&config.app_state_root),
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        fixture_mode,
        [
            config.app_state_root.as_path(),
            config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(json, "blocked", &error);
    }
    let authority_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit(
                    json,
                    "blocked",
                    "session authority key missing; run `unpin auth session init`",
                );
            }
            Err(error) => return command_error_exit(json, "blocked", &error),
        };
    let backup_authentication_key = match credentials::resolve_backup_authentication_key(
        fixture_mode,
        &config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                json,
                "blocked",
                "backup authentication key missing; run `unpin auth backup init`",
            );
        }
        Err(error) => {
            return command_error_exit(
                json,
                "blocked",
                &format!("backup authentication unavailable for protected session: {error}"),
            );
        }
    };
    let result = session_process::launch(session_process::SessionLaunchRequest {
        app_state_root: config.app_state_root,
        discovery_roots,
        repository_key: workspace.repository_key,
        workspace_key: workspace.workspace_key,
        workspace_revision: workspace.diagnostics.head,
        provider,
        exposure: PinnedExposure {
            revision: exposure_revision,
            profile,
            capability_locks: Some(Box::new(capability_locks)),
        },
        workflow,
        bridge_socket,
        command,
        authority_key,
        backup_authentication_key,
        fixture_mode,
    });
    match result {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result.to_json()).expect("session result JSON")
                );
            } else {
                println!(
                    "session {} {} exit={:?} isolation=connection-scoped cleanup={} cleanup_failures={} degradation={}",
                    result.session_id,
                    result.provider.as_str(),
                    result.child_exit_code,
                    result.cleanup_complete(),
                    result.cleanup_failures.join(","),
                    result.degradation.join(",")
                );
            }
            if result.child_exit_code == Some(0) && result.cleanup_complete() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => command_error_exit(json, "failed", &error.to_string()),
    }
}

fn list(roots: DiscoveryRootArgs, app_state_root: Option<PathBuf>, json: bool) -> ExitCode {
    let fixture_mode = roots.fixture_root.is_some();
    let config = match resolve_config(&roots, app_state_root) {
        Ok(config) => config,
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    let authority_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit(
                    json,
                    "blocked",
                    "session authority key missing; run `unpin auth session init`",
                );
            }
            Err(error) => return command_error_exit(json, "blocked", &error),
        };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    match SessionManager::with_authority_key(config.app_state_root, authority_key).list() {
        Ok(leases) => {
            let leases = leases
                .into_iter()
                .filter(|snapshot| {
                    snapshot.lease.repository_key == identity.repository_key
                        && snapshot.lease.workspace_key == identity.workspace_key
                })
                .collect::<Vec<_>>();
            if json {
                let summaries = leases
                    .iter()
                    .map(|snapshot| {
                        serde_json::json!({
                            "sessionId": snapshot.lease.session_id,
                            "provider": snapshot.lease.provider,
                            "repositoryKey": snapshot.lease.repository_key,
                            "workspaceKey": snapshot.lease.workspace_key,
                            "profileDigest": snapshot.lease.desired_exposure.profile.digest(),
                            "desiredExposureRevision": snapshot.lease.desired_exposure.revision,
                            "observedExposureRevision": snapshot.lease.observed_exposure.revision,
                            "liveStatus": snapshot.lease.live_status,
                            "isolation": snapshot.lease.isolation,
                            "coverage": snapshot.lease.coverage,
                            "lifecycle": snapshot.lease.lifecycle,
                            "inFlightCalls": snapshot.lease.in_flight_calls,
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ready",
                        "sessions": summaries,
                    }))
                    .expect("session summaries JSON")
                );
            } else if leases.is_empty() {
                println!("No active sessions.");
            } else {
                for snapshot in leases {
                    println!(
                        "{} {} {} {:?}",
                        snapshot.lease.session_id,
                        snapshot.lease.provider.as_str(),
                        snapshot.lease.workspace_key,
                        snapshot.lease.lifecycle
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => command_error_exit(json, "failed", &error.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn end(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: &str,
    apply: bool,
    confirm: bool,
    plan_fingerprint: Option<&str>,
    json: bool,
) -> ExitCode {
    let fixture_mode = roots.fixture_root.is_some();
    let config = match resolve_config(&roots, app_state_root) {
        Ok(config) => config,
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    let approval_context =
        match ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key) {
            Ok(context) => context,
            Err(error) => return command_error_exit(json, "failed", &error.to_string()),
        };
    if apply
        && let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [
                config.app_state_root.as_path(),
                config.project_root.as_path(),
            ],
        )
    {
        return command_error_exit(json, "blocked", &error);
    }
    let authority_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit(
                    json,
                    "blocked",
                    "session authority key missing; run `unpin auth session init`",
                );
            }
            Err(error) => return command_error_exit(json, "blocked", &error),
        };
    let controller =
        SessionEndController::with_authority_key(&config.app_state_root, authority_key);
    let plan = match controller.plan(id, &approval_context) {
        Ok(plan) => plan,
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    if !apply {
        if json {
            let expectation = plan
                .approval_expectation(&approval_context)
                .expect("validated session end plan has approval expectation");
            let operation = ControlOperationEnvelope::from_expectation(
                &expectation,
                &plan.plan_fingerprint,
                plan.activation,
                ControlOperationLifecycle::Planned,
                Some(ControlHumanAction {
                    code: "confirm-and-apply".to_string(),
                    guidance: "Re-run with --apply --confirm and this plan fingerprint".to_string(),
                }),
                true,
                plan.provider.into_iter().collect(),
                serde_json::json!({"plan": plan}),
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "planned",
                    "operation": operation,
                    "plan": plan,
                    "humanApprovalRequired": true,
                }))
                .expect("session end plan JSON")
            );
        } else {
            println!(
                "planned session end {} fingerprint={} activation=live",
                id, plan.plan_fingerprint
            );
        }
        return ExitCode::SUCCESS;
    }
    if !confirm {
        return command_error_exit(json, "blocked", "confirmation-required");
    }
    if plan_fingerprint != Some(plan.plan_fingerprint.as_str()) {
        return command_error_exit(json, "blocked", "plan-fingerprint-mismatch");
    }
    let expectation = match plan.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(json, "blocked", &error.to_string()),
    };
    let now_unix = unix_now();
    let authorization = match credentials::authorize_reviewed_control_decision(
        fixture_mode,
        &config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        plan_fingerprint,
        "unpin-cli-session-end-approval",
        now_unix,
    ) {
        Ok(authorization) => authorization,
        Err(error) => return command_error_exit(json, "blocked", &error),
    };
    match controller.apply(
        &plan,
        authorization,
        &approval_context,
        "unpin-cli-session-end",
        now_unix,
    ) {
        Ok(result) => {
            if json {
                let lifecycle = match result.status {
                    unpin_core::sessions::SessionEndStatus::NoOp
                    | unpin_core::sessions::SessionEndStatus::AlreadyEnding => {
                        ControlOperationLifecycle::NoOp
                    }
                    unpin_core::sessions::SessionEndStatus::RevocationRequested => {
                        ControlOperationLifecycle::Applied
                    }
                };
                let operation = ControlOperationEnvelope::from_expectation(
                    &expectation,
                    &plan.plan_fingerprint,
                    result.activation,
                    lifecycle,
                    None,
                    false,
                    plan.provider.into_iter().collect(),
                    serde_json::json!({"result": result}),
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "applied",
                        "operation": operation,
                        "result": result,
                    }))
                    .expect("session end result JSON")
                );
            } else {
                println!(
                    "session {} {:?}; owner cleanup pending",
                    result.session_id, result.status
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            command_error_exit(json, session_end_error_status(&error), &error.to_string())
        }
    }
}

fn session_status(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: Option<&str>,
    json: bool,
) -> ExitCode {
    let fixture_mode = roots.fixture_root.is_some();
    let config = match resolve_config(&roots, app_state_root) {
        Ok(config) => config,
        Err(error) => return command_error_exit(json, "failed", &error),
    };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    let authority_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit(json, "blocked", "session authority key missing");
            }
            Err(error) => return command_error_exit(json, "blocked", &error),
        };
    let manager = SessionManager::with_authority_key(&config.app_state_root, authority_key);
    let mut sessions = match manager.list() {
        Ok(sessions) => sessions
            .into_iter()
            .filter(|snapshot| {
                snapshot.lease.repository_key == identity.repository_key
                    && snapshot.lease.workspace_key == identity.workspace_key
                    && id.is_none_or(|id| snapshot.lease.session_id == id)
            })
            .collect::<Vec<_>>(),
        Err(error) => return command_error_exit(json, "failed", &error.to_string()),
    };
    if id.is_some() && sessions.is_empty() {
        return command_error_exit(json, "failed", "session not found");
    }
    sessions.sort_by(|left, right| left.lease.session_id.cmp(&right.lease.session_id));
    let summaries = sessions
        .into_iter()
        .map(|snapshot| {
            let session_id = snapshot.lease.session_id.clone();
            let gateway_status = session_process::call_gateway_control(
                &config.app_state_root,
                &session_id,
                "unpin_workflow_status",
                serde_json::json!({}),
            )
            .ok();
            let gateway_modes = session_process::call_gateway_control(
                &config.app_state_root,
                &session_id,
                "unpin_workflow_modes",
                serde_json::json!({}),
            )
            .ok();
            serde_json::json!({
                "sessionId": session_id,
                "provider": snapshot.lease.provider,
                "repositoryKey": snapshot.lease.repository_key,
                "workspaceKey": snapshot.lease.workspace_key,
                "desiredExposureRevision": snapshot.lease.desired_exposure.revision,
                "observedExposureRevision": snapshot.lease.observed_exposure.revision,
                "liveStatus": snapshot.lease.live_status,
                "lifecycle": snapshot.lease.lifecycle,
                "admissionOpen": snapshot.lease.admission_open,
                "inFlightCalls": snapshot.lease.in_flight_calls,
                "workflow": snapshot.lease.workflow.as_deref().map(|workflow| serde_json::json!({
                    "workflowId": workflow.workflow_id,
                    "workflowRevision": workflow.workflow_revision,
                    "activeMode": workflow.active_mode,
                    "modes": workflow.profile_revisions.keys().collect::<Vec<_>>(),
                    "stateSequence": workflow.state_sequence,
                })),
                "gateway": {
                    "status": gateway_status,
                    "modes": gateway_modes,
                },
            })
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ready",
                "sessions": summaries,
            }))
            .expect("session status JSON")
        );
    } else if summaries.is_empty() {
        println!("No active sessions.");
    } else {
        for summary in summaries {
            println!(
                "{} {} lifecycle={} admission={}",
                summary["sessionId"].as_str().unwrap_or("unknown"),
                summary["provider"].as_str().unwrap_or("unknown"),
                summary["lifecycle"].as_str().unwrap_or("unknown"),
                summary["admissionOpen"].as_bool().unwrap_or(false)
            );
        }
    }
    ExitCode::SUCCESS
}

fn enter_mode(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: &str,
    target_mode: &str,
    operation_id: &str,
    operation_fingerprint: &str,
    source_state_sequence: Option<u64>,
    json: bool,
) -> ExitCode {
    let (config, snapshot) = match authenticated_session(&roots, app_state_root, id) {
        Ok(value) => value,
        Err((status, error)) => return command_error_exit(json, status, &error),
    };
    let source_state_sequence = source_state_sequence.unwrap_or(snapshot.revision.sequence);
    let requested_at_unix = unix_now();
    let result = session_process::call_gateway_control(
        &config.app_state_root,
        id,
        "unpin_workflow_enter_mode",
        serde_json::json!(WorkflowTransitionRequest {
            operation_id: operation_id.to_string(),
            operation_fingerprint: operation_fingerprint.to_string(),
            source_state_sequence,
            target_mode: target_mode.to_string(),
            requested_at_unix,
        }),
    );
    match result {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "applied",
                        "result": result,
                    }))
                    .expect("workflow transition JSON")
                );
            } else {
                println!("session {id} workflow transition requested");
            }
            ExitCode::SUCCESS
        }
        Err(error) => command_error_exit(json, "blocked", &error.to_string()),
    }
}

fn cancel_transition(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: &str,
    operation_id: &str,
    json: bool,
) -> ExitCode {
    let (config, _) = match authenticated_session(&roots, app_state_root, id) {
        Ok(value) => value,
        Err((status, error)) => return command_error_exit(json, status, &error),
    };
    let result = session_process::call_gateway_control(
        &config.app_state_root,
        id,
        "unpin_workflow_cancel_transition",
        serde_json::json!({"operationId": operation_id}),
    );
    match result {
        Ok(result) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "applied",
                        "result": result,
                    }))
                    .expect("workflow cancellation JSON")
                );
            } else {
                println!("session {id} workflow transition cancelled");
            }
            ExitCode::SUCCESS
        }
        Err(error) => command_error_exit(json, "blocked", &error.to_string()),
    }
}

fn recovery(
    roots: DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: &str,
    json: bool,
) -> ExitCode {
    let (config, snapshot) = match authenticated_session(&roots, app_state_root, id) {
        Ok(value) => value,
        Err((status, error)) => return command_error_exit(json, status, &error),
    };
    let status = session_process::call_gateway_control(
        &config.app_state_root,
        id,
        "unpin_workflow_status",
        serde_json::json!({}),
    )
    .ok();
    let modes = session_process::call_gateway_control(
        &config.app_state_root,
        id,
        "unpin_workflow_modes",
        serde_json::json!({}),
    )
    .ok();
    let transition_pending = snapshot.lease.desired_exposure != snapshot.lease.observed_exposure;
    let result = serde_json::json!({
        "status": if transition_pending { "recovery-required" } else { "ready" },
        "sessionId": id,
        "transitionPending": transition_pending,
        "nextAction": if transition_pending { "cancel-transition-or-owner-refresh" } else { "none" },
        "workflowStatus": status,
        "workflowModes": modes,
    });
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("workflow recovery JSON")
        );
    } else {
        println!(
            "session {id} recovery={} next={}",
            result["status"].as_str().unwrap_or("unknown"),
            result["nextAction"].as_str().unwrap_or("unknown")
        );
    }
    ExitCode::SUCCESS
}

fn authenticated_session(
    roots: &DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
    id: &str,
) -> Result<
    (
        unpin_core::config::UnpinConfig,
        unpin_core::sessions::LeaseSnapshot,
    ),
    (&'static str, String),
> {
    let fixture_mode = roots.fixture_root.is_some();
    let config = resolve_config(roots, app_state_root).map_err(|error| ("failed", error))?;
    let identity = config
        .workspace_identity()
        .map_err(|error| ("failed", error.to_string()))?;
    let authority_key =
        credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root)
            .map_err(|error| ("blocked", error))?
            .ok_or(("blocked", "session authority key missing".to_string()))?;
    let manager = SessionManager::with_authority_key(&config.app_state_root, authority_key);
    manager
        .list()
        .map_err(|error| ("failed", error.to_string()))?
        .into_iter()
        .find(|snapshot| {
            snapshot.lease.session_id == id
                && snapshot.lease.repository_key == identity.repository_key
                && snapshot.lease.workspace_key == identity.workspace_key
        })
        .map(|snapshot| (config, snapshot))
        .ok_or(("failed", "session not found".to_string()))
}

fn session_end_error_status(error: &SessionEndControlError) -> &'static str {
    if matches!(
        error,
        SessionEndControlError::Durable(DurableControlError::RecoveryRequired(_))
    ) {
        "recovery-required"
    } else {
        "blocked"
    }
}

fn session_profile_selection(
    native: bool,
    profile_id: Option<String>,
    profile_digest: Option<String>,
    definition_digest: Option<String>,
    profile_origin: Option<String>,
) -> Result<PinnedProfile, &'static str> {
    let supplied = [
        profile_id.is_some(),
        profile_digest.is_some(),
        definition_digest.is_some(),
        profile_origin.is_some(),
    ];
    if native && supplied.iter().any(|supplied| *supplied) {
        return Err("--native cannot be combined with profile fields");
    }
    if native {
        return Ok(PinnedProfile::Native);
    }
    match (
        profile_id,
        profile_digest,
        definition_digest,
        profile_origin,
    ) {
        (None, None, None, None) => Ok(PinnedProfile::None),
        (Some(profile_id), Some(profile_digest), Some(definition_digest), profile_origin) => {
            let origin_scope = match profile_origin.as_deref().unwrap_or("workspace") {
                "global" => ProfileSourceScope::Global,
                "repository" => ProfileSourceScope::Repository,
                "workspace" => ProfileSourceScope::Workspace,
                "session" => ProfileSourceScope::Session,
                _ => {
                    return Err("profile origin must be global, repository, workspace, or session");
                }
            };
            Ok(PinnedProfile::Profile {
                profile_id,
                profile_digest,
                origin_scope,
                definition_digest,
            })
        }
        _ => Err("profile id, profile digest, and definition digest must be supplied together"),
    }
}

#[allow(clippy::too_many_arguments)]
fn workflow_launch_selection(
    workflow_id: Option<String>,
    workflow_revision: Option<String>,
    entry_mode: Option<String>,
    catalog_revision: Option<String>,
    proposal_id: Option<String>,
    proposal_fingerprint: Option<String>,
    prompt_digest: Option<String>,
    capability_count: Option<usize>,
) -> Result<Option<session_process::WorkflowLaunchRequest>, &'static str> {
    let supplied = [
        workflow_id.is_some(),
        workflow_revision.is_some(),
        entry_mode.is_some(),
        catalog_revision.is_some(),
        proposal_id.is_some(),
        proposal_fingerprint.is_some(),
        prompt_digest.is_some(),
        capability_count.is_some(),
    ];
    if supplied.iter().all(|supplied| !*supplied) {
        return Ok(None);
    }
    if supplied.iter().any(|supplied| !*supplied) {
        return Err(
            "workflow launch requires workflow id, revision, entry mode, catalog revision, proposal id/fingerprint, prompt digest, and capability count",
        );
    }
    Ok(Some(session_process::WorkflowLaunchRequest {
        workflow_id: workflow_id.expect("checked workflow id"),
        workflow_revision: workflow_revision.expect("checked workflow revision"),
        entry_mode: entry_mode.expect("checked entry mode"),
        catalog_revision: catalog_revision.expect("checked catalog revision"),
        proposal_id: proposal_id.expect("checked proposal id"),
        proposal_fingerprint: proposal_fingerprint.expect("checked proposal fingerprint"),
        prompt_digest: prompt_digest.expect("checked prompt digest"),
        capability_count: capability_count.expect("checked capability count"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_end_recovery_has_distinct_machine_status() {
        let error = SessionEndControlError::Durable(DurableControlError::RecoveryRequired(
            "session-end-operation".to_string(),
        ));

        assert_eq!(session_end_error_status(&error), "recovery-required");
    }
}
