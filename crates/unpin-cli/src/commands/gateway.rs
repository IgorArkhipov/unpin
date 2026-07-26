use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    bridges::hook_bridge_descriptor,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    profiles::{PolicyStore, PolicyTarget},
    providers::ProviderId,
    sessions::{
        GatewayModeAction, GatewayModeApplyStatus, GatewayModeController, GatewayModeTarget,
        GatewayWorkflowController, GatewayWorkflowError, GatewayWorkflowPlan, SessionAuthorityKey,
    },
};

use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config, unix_now,
};

#[derive(Debug, Subcommand)]
pub(crate) enum GatewayCommands {
    /// Show physical gateway lifecycle, selected policy, and provider hook coverage.
    Status(GatewayTargetOptions),
    /// Install dormant gateway lifecycle state for selected target.
    Install(GatewayChangeOptions),
    /// Open gateway routing for future sessions and select gateway policy.
    On(GatewayChangeOptions),
    /// Select native policy and close gateway admission.
    Off(GatewayChangeOptions),
    /// Select native policy and remove gateway lifecycle state.
    Detach(GatewayChangeOptions),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct GatewayTargetOptions {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    /// Unpin-owned runtime state root.
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Global, repository, or physical workspace target.
    #[arg(long, value_enum, default_value_t = GatewayScopeArg::Workspace)]
    scope: GatewayScopeArg,
    /// Provider-specific target. Omit for all providers in selected scope.
    #[arg(long)]
    provider: Option<String>,
    /// Render machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct GatewayChangeOptions {
    #[command(flatten)]
    target: GatewayTargetOptions,
    /// Drain matching sessions for off/detach.
    #[arg(long)]
    force: bool,
    /// Apply reviewed plan. Omit for dry-run.
    #[arg(long)]
    apply: bool,
    /// Explicit human confirmation required with --apply.
    #[arg(long, requires = "apply")]
    confirm: bool,
    /// Combined fingerprint emitted by matching dry-run.
    #[arg(long, requires = "apply")]
    plan_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum GatewayScopeArg {
    Global,
    Repository,
    Workspace,
}

pub(crate) fn run(command: GatewayCommands) -> ExitCode {
    match command {
        GatewayCommands::Status(options) => status(options),
        GatewayCommands::Install(options) => change(options, GatewayModeAction::Install),
        GatewayCommands::On(options) => change(options, GatewayModeAction::Activate),
        GatewayCommands::Off(options) => change(options, GatewayModeAction::Off),
        GatewayCommands::Detach(options) => change(options, GatewayModeAction::Detach),
    }
}

fn status(options: GatewayTargetOptions) -> ExitCode {
    let fixture_mode = options.roots.fixture_root.is_some();
    let context = match gateway_context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let mode = match context.mode_controller.status(&context.mode_target) {
        Ok(mode) => mode,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let policy = match PolicyStore::new(&context.config.app_state_root).load(&context.policy_target)
    {
        Ok(policy) => policy,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let providers = context
        .provider
        .map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]);
    let coverage = providers
        .into_iter()
        .map(|provider| {
            let descriptor = hook_bridge_descriptor(provider);
            json!({
                "provider": provider,
                "hookAdapter": descriptor.adapter,
                "builtInTools": descriptor.built_in_tools,
                "gatewayMcpTools": descriptor.gateway_mcp_tools,
                "verificationScope": "fixture-contract",
                "nativeHostActivation": "pending-live-verification",
            })
        })
        .collect::<Vec<_>>();
    let routing_intent_active = mode
        .as_ref()
        .is_some_and(|mode| mode.routing == unpin_core::sessions::GatewayRoutingState::Active);
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "target": context.mode_target,
                "mode": mode,
                "policy": policy.map(|snapshot| snapshot.policy),
                "providerCoverage": coverage,
                "runtime": {
                    "gatewayDataPlane": if fixture_mode {
                        "available-for-fixture-session-launch"
                    } else {
                        "implemented-without-live-provider-attachment"
                    },
                    "fixtureHarnessAttachment": if fixture_mode {
                        "verified-contract-runtime-not-observed"
                    } else {
                        "not-applicable"
                    },
                    "liveProviderAttachment": "blocked-until-provider-overlay-is-verified",
                    "routingIntentActive": routing_intent_active,
                    "configuredRoutingIsLive": serde_json::Value::Null,
                    "runtimeObservation": "not-performed",
                    "nativeMcpReferences": "not-managed",
                },
            }))
            .expect("gateway status JSON")
        );
    } else {
        let lifecycle = mode.map_or_else(
            || "detached/off".to_string(),
            |mode| format!("{:?}/{:?}", mode.installation, mode.routing),
        );
        println!("gateway {} {lifecycle}", context.mode_target);
    }
    ExitCode::SUCCESS
}

fn change(options: GatewayChangeOptions, action: GatewayModeAction) -> ExitCode {
    let context = match gateway_context(&options.target) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.target.json, "failed", &error),
    };
    let fixture_mode = options.target.roots.fixture_root.is_some();
    let backup_authentication_key = match credentials::resolve_backup_authentication_key(
        fixture_mode,
        &context.config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                options.target.json,
                "blocked",
                "backup authentication key missing; run `unpin auth backup init`",
            );
        }
        Err(error) => return command_error_exit(options.target.json, "blocked", &error),
    };
    let workflow_controller = GatewayWorkflowController::with_authority_keys(
        &context.config.app_state_root,
        context.session_authority_key.clone(),
        backup_authentication_key,
    );
    let pending_plan = if options.apply {
        match options.plan_fingerprint.as_deref() {
            Some(fingerprint) => match workflow_controller.pending_plan(fingerprint) {
                Ok(plan) => plan,
                Err(error) => {
                    return command_error_exit(
                        options.target.json,
                        "recovery-required",
                        &error.to_string(),
                    );
                }
            },
            None => None,
        }
    } else {
        None
    };
    let plan = match pending_plan {
        Some(plan)
            if plan.mode.target == context.mode_target
                && plan.mode.action == action
                && plan.mode.force == options.force
                && plan.policy.as_ref().is_none_or(|policy| {
                    policy.target == context.policy_target && policy.provider == context.provider
                }) =>
        {
            plan
        }
        Some(_) => {
            return command_error_exit(
                options.target.json,
                "blocked",
                "pending plan does not match requested gateway target",
            );
        }
        None => match workflow_controller.plan(
            context.mode_target.clone(),
            context.policy_target.clone(),
            context.provider,
            action,
            options.force,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return command_error_exit(options.target.json, "blocked", &error.to_string());
            }
        },
    };
    if !options.apply {
        return render_plan(
            options.target.json,
            &plan,
            &context.approval_context,
            context.provider,
        );
    }
    if !options.confirm {
        return command_error_exit(options.target.json, "blocked", "confirmation-required");
    }
    if options.plan_fingerprint.as_deref() != Some(plan.plan_fingerprint.as_str()) {
        return command_error_exit(options.target.json, "blocked", "plan-fingerprint-mismatch");
    }
    if let Some(reason) = &plan.mode.blocked_reason {
        return command_error_exit(options.target.json, "blocked", reason);
    }
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        fixture_mode,
        [
            context.config.app_state_root.as_path(),
            context.config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(options.target.json, "blocked", &error);
    }
    let expectation = match plan.approval_expectation(&context.approval_context) {
        Ok(expectation) => expectation,
        Err(error) => {
            return command_error_exit(options.target.json, "blocked", &error.to_string());
        }
    };
    let now_unix = unix_now();
    let authorization = match credentials::authorize_reviewed_control_decision(
        options.target.roots.fixture_root.is_some(),
        &context.config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        options.plan_fingerprint.as_deref(),
        "unpin-cli-gateway-approval",
        now_unix,
    ) {
        Ok(authorization) => authorization,
        Err(error) => return command_error_exit(options.target.json, "blocked", &error),
    };
    let result = match workflow_controller.apply(
        &plan,
        authorization,
        &context.approval_context,
        "unpin-cli-gateway",
        now_unix,
    ) {
        Ok(result) => result,
        Err(error @ GatewayWorkflowError::RecoveryRequired { .. }) => {
            return command_error_exit(
                options.target.json,
                "recovery-required",
                &error.to_string(),
            );
        }
        Err(error @ GatewayWorkflowError::Draining { .. }) => {
            return command_error_exit(options.target.json, "draining", &error.to_string());
        }
        Err(error) => {
            return command_error_exit(options.target.json, "blocked", &error.to_string());
        }
    };
    if options.target.json {
        let no_op = result.mode.status == GatewayModeApplyStatus::NoOp
            && result.policy.as_ref().is_none_or(|policy| {
                policy.status == unpin_core::profiles::PolicyApplyStatus::NoOp
            })
            && result.native_views.as_ref().is_none_or(|views| {
                views.status == unpin_core::sessions::GatewayNativeViewApplyStatus::NoOp
            });
        let operation = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            result.mode.activation,
            if no_op {
                ControlOperationLifecycle::NoOp
            } else {
                ControlOperationLifecycle::Applied
            },
            None,
            false,
            context
                .provider
                .map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
            json!({
                "mode": result.mode,
                "policy": result.policy,
                "nativeViews": result.native_views,
                "nativeMcpReferences": "not-managed",
            }),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "applied",
                "operation": operation,
                "planFingerprint": result.plan_fingerprint,
                "mode": result.mode,
                "policy": result.policy,
                "nativeViews": result.native_views,
                "nativeMcpReferences": "not-managed",
            }))
            .expect("gateway apply JSON")
        );
    } else {
        println!(
            "gateway {:?} applied; activation={:?} nativeMcpReferences=not-managed",
            action, result.mode.activation
        );
    }
    ExitCode::SUCCESS
}

struct GatewayContext {
    config: unpin_core::config::UnpinConfig,
    provider: Option<ProviderId>,
    mode_target: GatewayModeTarget,
    policy_target: PolicyTarget,
    approval_context: ControlApprovalContext,
    session_authority_key: SessionAuthorityKey,
    mode_controller: GatewayModeController,
}

fn gateway_context(options: &GatewayTargetOptions) -> Result<GatewayContext, String> {
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let authority_key = credentials::resolve_session_authority_key(
        options.roots.fixture_root.is_some(),
        &config.app_state_root,
    )?
    .ok_or_else(|| "session authority key missing; run `unpin auth session init`".to_string())?;
    let provider = options
        .provider
        .as_deref()
        .map(|provider| {
            parse_provider_id(provider).ok_or_else(|| "unsupported provider".to_string())
        })
        .transpose()?;
    let identity = config
        .workspace_identity()
        .map_err(|error| error.to_string())?;
    let approval_context =
        ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key)
            .map_err(|error| error.to_string())?;
    let (mode_target, policy_target) = match options.scope {
        GatewayScopeArg::Global => (
            provider.map_or_else(
                GatewayModeTarget::global,
                GatewayModeTarget::global_provider,
            ),
            PolicyTarget::Global,
        ),
        GatewayScopeArg::Repository => (
            match provider {
                Some(provider) => {
                    GatewayModeTarget::repository_provider(&identity.repository_key, provider)
                }
                None => GatewayModeTarget::repository(&identity.repository_key),
            }
            .map_err(|error| error.to_string())?,
            PolicyTarget::repository(&identity.repository_key)
                .map_err(|error| error.to_string())?,
        ),
        GatewayScopeArg::Workspace => (
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
        ),
    };
    Ok(GatewayContext {
        mode_controller: GatewayModeController::with_authority_key(
            &config.app_state_root,
            authority_key.clone(),
        ),
        session_authority_key: authority_key,
        config,
        provider,
        mode_target,
        policy_target,
        approval_context,
    })
}

fn render_plan(
    json_output: bool,
    plan: &GatewayWorkflowPlan,
    context: &ControlApprovalContext,
    provider: Option<ProviderId>,
) -> ExitCode {
    if json_output {
        let expectation = plan
            .approval_expectation(context)
            .expect("validated gateway plan has approval expectation");
        let blocked = plan.mode.blocked_reason.is_some();
        let operation = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            plan.mode.activation,
            if blocked {
                ControlOperationLifecycle::Blocked
            } else {
                ControlOperationLifecycle::Planned
            },
            (!blocked).then(|| ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Re-run with --apply --confirm and this plan fingerprint".to_string(),
            }),
            true,
            provider.map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
            json!({
                "modePlan": plan.mode,
                "policyPlan": plan.policy,
                "nativeViewPlan": plan.native_views,
                "nativeMcpReferences": "not-managed",
            }),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": if plan.mode.blocked_reason.is_some() { "blocked" } else { "planned" },
                "operation": operation,
                "planFingerprint": plan.plan_fingerprint,
                "modePlan": plan.mode,
                "policyPlan": plan.policy,
                "nativeViewPlan": plan.native_views,
                "nativeMcpReferences": "not-managed",
            }))
            .expect("gateway plan JSON")
        );
    } else {
        println!(
            "gateway {:?} {} fingerprint={}",
            plan.mode.action,
            plan.mode.blocked_reason.as_deref().unwrap_or("planned"),
            plan.plan_fingerprint
        );
    }
    if plan.mode.blocked_reason.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
