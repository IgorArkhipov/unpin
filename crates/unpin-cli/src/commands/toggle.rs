//! Reach-aware bulk native-toggle CLI.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use unpin_core::{
    approval::ControlApprovalContext,
    control_operation::{ReachAwarePrincipal, ReachAwareRootBinding, ReachAwareRootScope},
    discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryRoots, discover_all},
    mutation::{
        BULK_TOGGLE_APPROVAL_AUDIENCE, BulkToggleApplyResult, BulkToggleController, BulkTogglePlan,
        BulkToggleReachAwareApplyContext, BulkToggleRequest, BulkToggleSelector,
    },
    provider_reach::{
        ConnectionBoundary, ProviderReach, ProviderReachLifecycle, SelectedProviderAuthority,
        SelectedProviderProvenance,
    },
    providers::ProviderId,
};

use super::ProviderReachArg;
use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, unix_now,
};

#[derive(Debug, Subcommand)]
pub(crate) enum BulkCommands {
    /// Build a reach-aware bulk plan (and seal a handoff when credentials are available).
    Plan(BulkPlanArgs),
    /// Explicit alias for `bulk plan` intended for MCP-to-CLI handoff.
    Handoff(BulkPlanArgs),
    /// Apply one sealed operation by exact operation id and plan fingerprint.
    Apply(BulkApplyArgs),
    /// Inspect a sealed operation without rediscovering or mutating providers.
    Status(BulkStatusArgs),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct BulkPlanArgs {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Provider selector values (repeat or comma-separate).
    #[arg(long = "provider", value_delimiter = ',')]
    providers: Vec<String>,
    /// Provider authority for selected-provider reach. This is distinct from
    /// the provider selector above.
    #[arg(long)]
    selected_provider: Option<String>,
    #[arg(long = "kind", value_delimiter = ',')]
    kinds: Vec<String>,
    #[arg(long = "category", value_delimiter = ',')]
    categories: Vec<String>,
    #[arg(long = "layer", value_delimiter = ',')]
    layers: Vec<String>,
    #[arg(long = "id", value_delimiter = ',')]
    ids: Vec<String>,
    /// Restrict matching items by their current enabled state.
    #[arg(long)]
    enabled: Option<bool>,
    /// Enable matching items (the default target).
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable matching items.
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
    #[arg(long, value_enum, alias = "provider-reach")]
    reach: Option<ProviderReachArg>,
    #[arg(long)]
    allow_empty_selection: bool,
    #[arg(long)]
    acknowledge_whole_inventory: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct BulkApplyArgs {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    #[arg(long)]
    operation_id: String,
    #[arg(long, alias = "fingerprint")]
    plan_fingerprint: String,
    #[arg(long)]
    confirm: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct BulkStatusArgs {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    json: bool,
}

pub(crate) fn run(command: BulkCommands) -> ExitCode {
    match command {
        BulkCommands::Plan(args) => plan(args, false),
        BulkCommands::Handoff(args) => plan(args, true),
        BulkCommands::Apply(args) => apply(args),
        BulkCommands::Status(args) => status(args),
    }
}

fn plan(args: BulkPlanArgs, require_handoff: bool) -> ExitCode {
    let fixture_mode = args.roots.fixture_root.is_some();
    let config = match resolve_config(&args.roots, args.app_state_root.clone()) {
        Ok(config) => config,
        Err(error) => return command_error_exit(args.json, "failed", &error.to_string()),
    };
    let roots = match resolve_discovery_roots_with_config(&args.roots, &config) {
        Ok(roots) => roots.with_app_state_root(&config.app_state_root),
        Err(error) => return command_error_exit(args.json, "failed", &error),
    };
    let discovery = match discover_all(&roots) {
        Ok(discovery) => discovery,
        Err(error) => return command_error_exit(args.json, "failed", &error.to_string()),
    };
    let selector = match selector_from_args(&args) {
        Ok(selector) => selector,
        Err(error) => return command_error_exit(args.json, "failed", &error),
    };
    let selected_provider = match args.selected_provider.as_deref() {
        Some(value) => match parse_provider_id(value) {
            Some(provider) => Some(provider),
            None => {
                return command_error_exit_code(
                    args.json,
                    "blocked",
                    &format!("invalid selected provider: {value}"),
                    3,
                );
            }
        },
        None => None,
    };
    let reach = match args.reach {
        Some(reach) => match reach.input(selected_provider) {
            Ok(reach) => reach,
            Err(error) => return command_error_exit_code(args.json, "blocked", &error, 3),
        },
        None => unpin_core::provider_reach::ProviderReachInput::Omitted,
    };
    let mut request = BulkToggleRequest::new(selector, !args.disable);
    request = request
        .with_reach(ConnectionBoundary::All, reach)
        .allow_empty_selection(args.allow_empty_selection)
        .acknowledge_whole_inventory(args.acknowledge_whole_inventory);
    if let Some(provider) = selected_provider {
        request = request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    if let Err(error) = BulkToggleController::validate_before_discovery(&request) {
        let status = lifecycle_status_for_plan_error(&error);
        return command_error_exit_code(
            args.json,
            status,
            &error.to_string(),
            lifecycle_status_exit_code(status),
        );
    }
    let controller = BulkToggleController::new(&config.app_state_root);
    let plan = match controller.plan_from_discovery(discovery, request) {
        Ok(plan) => plan,
        Err(error) => {
            let status = lifecycle_status_for_plan_error(&error);
            return command_error_exit_code(
                args.json,
                status,
                &error.to_string(),
                lifecycle_status_exit_code(status),
            );
        }
    };

    let handoff = if require_handoff || fixture_mode {
        match durable_context(&config.app_state_root, &roots, &config, &plan, fixture_mode) {
            Ok((controller, durable)) => match controller.seal_handoff(&plan, &durable) {
                Ok(handoff) => Some(handoff),
                Err(error) if !require_handoff => {
                    if args.json {
                        eprintln!("handoff not sealed: {error}");
                    }
                    None
                }
                Err(error) => {
                    return command_error_exit_code(args.json, "blocked", &error.to_string(), 3);
                }
            },
            Err(error) if !require_handoff => {
                if args.json {
                    eprintln!("handoff not sealed: {error}");
                }
                None
            }
            Err(error) => {
                return command_error_exit_code(args.json, "blocked", &error.to_string(), 3);
            }
        }
    } else {
        None
    };
    render_plan(&plan, handoff.as_ref(), args.json)
}

fn apply(args: BulkApplyArgs) -> ExitCode {
    if !args.confirm {
        return command_error_exit_code(args.json, "blocked", "confirmation-required", 3);
    }
    let fixture_mode = args.roots.fixture_root.is_some();
    let config = match resolve_config(&args.roots, args.app_state_root.clone()) {
        Ok(config) => config,
        Err(error) => return command_error_exit_code(args.json, "failed", &error.to_string(), 3),
    };
    let controller = BulkToggleController::new(&config.app_state_root);
    let plan = match controller.load_handoff(&args.operation_id) {
        Ok(plan) => plan,
        Err(error) => return command_error_exit_code(args.json, "blocked", &error.to_string(), 3),
    };
    if plan.operation_id != args.operation_id || plan.plan_fingerprint != args.plan_fingerprint {
        return command_error_exit_code(args.json, "blocked", "plan-fingerprint-mismatch", 3);
    }
    let roots = match resolve_discovery_roots_with_config(&args.roots, &config) {
        Ok(roots) => roots.with_app_state_root(&config.app_state_root),
        Err(error) => return command_error_exit_code(args.json, "failed", &error, 3),
    };
    match durable_context(&config.app_state_root, &roots, &config, &plan, fixture_mode) {
        Ok((controller, durable)) => {
            let discovery = match discover_all(&roots) {
                Ok(discovery) => discovery,
                Err(error) => {
                    return command_error_exit_code(args.json, "failed", &error.to_string(), 3);
                }
            };
            let expectation = match plan
                .approval_expectation(&durable.approval_context, &durable.principal.session_id)
            {
                Ok(expectation) => expectation,
                Err(error) => {
                    return command_error_exit_code(args.json, "blocked", &error.to_string(), 3);
                }
            };
            let authorization = match credentials::authorize_reviewed_control_decision(
                fixture_mode,
                &config.app_state_root,
                &expectation,
                plan.plan_fingerprint
                    .strip_prefix("sha256:")
                    .unwrap_or(&plan.plan_fingerprint),
                Some(
                    plan.plan_fingerprint
                        .strip_prefix("sha256:")
                        .unwrap_or(&plan.plan_fingerprint),
                ),
                "unpin-cli-bulk-toggle-approval",
                unix_now(),
            ) {
                Ok(authorization) => authorization,
                Err(error) => return command_error_exit_code(args.json, "blocked", &error, 3),
            };
            match controller.apply_with_reach_aware(&plan, authorization, durable, discovery) {
                Ok(result) => render_apply_result(&result, args.json),
                Err(error) => command_error_exit_code(
                    args.json,
                    lifecycle_status_for_plan_error(&error),
                    &error.to_string(),
                    lifecycle_status_exit_code(lifecycle_status_for_plan_error(&error)),
                ),
            }
        }
        Err(error) => command_error_exit_code(args.json, "blocked", &error, 3),
    }
}

fn status(args: BulkStatusArgs) -> ExitCode {
    let fixture_mode = args.roots.fixture_root.is_some();
    let config = match resolve_config(&args.roots, args.app_state_root.clone()) {
        Ok(config) => config,
        Err(error) => return command_error_exit(args.json, "failed", &error.to_string()),
    };
    let session_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit_code(
                    args.json,
                    "blocked",
                    "session authority key missing; run `unpin auth session init`",
                    3,
                );
            }
            Err(error) => return command_error_exit_code(args.json, "blocked", &error, 3),
        };
    let controller =
        BulkToggleController::new(&config.app_state_root).with_session_authority_key(session_key);
    let operation = match controller.load_handoff_status(&args.operation_id) {
        Ok(operation) => operation,
        Err(error) => {
            let status = lifecycle_status_for_plan_error(&error);
            return command_error_exit_code(
                args.json,
                status,
                &error.to_string(),
                lifecycle_status_exit_code(status),
            );
        }
    };
    let lifecycle = operation.lifecycle();
    let plan = operation.plan;
    let terminal_result = operation.terminal_result;
    let provider_reach = terminal_result
        .as_ref()
        .map_or(plan.provider_reach, |result| result.provider_reach);
    let provider_coverage = terminal_result.as_ref().map_or_else(
        || plan.provider_coverage.clone(),
        |result| result.provider_coverage.clone(),
    );
    let value = json!({
        "statusVersion": 2,
        "status": lifecycle_name(lifecycle),
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": provider_reach,
        "providerCoverage": provider_coverage,
        "acknowledgement": plan.acknowledgement,
        "lifecycle": lifecycle,
        "result": terminal_result,
    });
    print_value(value, args.json, "bulk status");
    lifecycle_exit(lifecycle)
}

fn selector_from_args(args: &BulkPlanArgs) -> Result<BulkToggleSelector, String> {
    Ok(BulkToggleSelector {
        exact_identities: Vec::new(),
        providers: args
            .providers
            .iter()
            .map(|value| {
                parse_provider_id(value).ok_or_else(|| format!("invalid provider: {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        kinds: args
            .kinds
            .iter()
            .map(|value| parse_kind(value))
            .collect::<Result<Vec<_>, _>>()?,
        categories: args
            .categories
            .iter()
            .map(|value| parse_category(value))
            .collect::<Result<Vec<_>, _>>()?,
        layers: args
            .layers
            .iter()
            .map(|value| parse_layer(value))
            .collect::<Result<Vec<_>, _>>()?,
        ids: args.ids.clone(),
        enabled: args.enabled,
    })
}

fn parse_kind(value: &str) -> Result<DiscoveryKind, String> {
    [
        DiscoveryKind::Skill,
        DiscoveryKind::Mcp,
        DiscoveryKind::Plugin,
        DiscoveryKind::Agent,
        DiscoveryKind::Hook,
        DiscoveryKind::Setting,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == value)
    .ok_or_else(|| format!("invalid kind: {value}"))
}

fn parse_category(value: &str) -> Result<DiscoveryCategory, String> {
    [
        DiscoveryCategory::Skill,
        DiscoveryCategory::ConfiguredMcp,
        DiscoveryCategory::Tool,
        DiscoveryCategory::Agent,
        DiscoveryCategory::Hook,
        DiscoveryCategory::ProviderSetting,
        DiscoveryCategory::PluginConfig,
        DiscoveryCategory::PluginManifest,
    ]
    .into_iter()
    .find(|category| category.as_str() == value)
    .ok_or_else(|| format!("invalid category: {value}"))
}

fn parse_layer(value: &str) -> Result<DiscoveryLayer, String> {
    [DiscoveryLayer::Global, DiscoveryLayer::Project]
        .into_iter()
        .find(|layer| layer.as_str() == value)
        .ok_or_else(|| format!("invalid layer: {value}"))
}

pub(crate) fn durable_context(
    app_state_root: &Path,
    roots: &DiscoveryRoots,
    config: &unpin_core::config::UnpinConfig,
    plan: &BulkTogglePlan,
    fixture_mode: bool,
) -> Result<(BulkToggleController, BulkToggleReachAwareApplyContext), String> {
    let backup_key = credentials::resolve_backup_authentication_key(fixture_mode, app_state_root)?
        .ok_or_else(|| {
            "backup authentication key missing; run `unpin auth backup init`".to_string()
        })?;
    let session_key = credentials::resolve_session_authority_key(fixture_mode, app_state_root)?
        .ok_or_else(|| {
            "session authority key missing; run `unpin auth session init`".to_string()
        })?;
    let identity = config
        .workspace_identity()
        .map_err(|error| error.to_string())?;
    let approval_context =
        ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key)
            .map_err(|error| error.to_string())?;
    let session_id = plan.operation_id.clone();
    let scope_id = unpin_core::mutation::reach_scope_digest(
        &plan
            .approval_expectation(&approval_context, &session_id)
            .map_err(|error| error.to_string())?,
        &session_id,
    );
    let root_binding = root_binding(app_state_root, roots, plan)?;
    let principal = ReachAwarePrincipal::sign(
        session_id,
        scope_id,
        match plan.provider_reach {
            ProviderReach::Selected {
                provider,
                provenance: SelectedProviderProvenance::PinnedMcpBoundary,
            } => ConnectionBoundary::Pinned(provider),
            _ => ConnectionBoundary::All,
        },
        &session_key,
    )
    .map_err(|error| error.to_string())?;
    let durable = BulkToggleReachAwareApplyContext {
        approval_context,
        roots: root_binding.clone(),
        principal,
        audience: BULK_TOGGLE_APPROVAL_AUDIENCE.to_string(),
        issued_at_unix: unix_now(),
        expires_at_unix: unix_now() + 3600,
        now_unix: unix_now(),
    };
    let controller = BulkToggleController::new(app_state_root.to_path_buf())
        .with_reach_aware_authority(backup_key, session_key, root_binding);
    Ok((controller, durable))
}

fn root_binding(
    app_state_root: &Path,
    roots: &DiscoveryRoots,
    plan: &BulkTogglePlan,
) -> Result<ReachAwareRootBinding, String> {
    let mut providers = BTreeSet::new();
    for entry in plan.provider_coverage.included() {
        providers.insert(entry.provider);
    }
    let mut provider_roots = providers
        .into_iter()
        .map(|provider| {
            (
                provider,
                ReachAwareRootScope::Primary,
                provider_root(roots, provider),
                unpin_core::mutation::BULK_TOGGLE_PROVIDER_ROOT_PROVENANCE.to_string(),
            )
        })
        .collect::<Vec<_>>();
    if plan.included.iter().any(|target| {
        target.item.provider == ProviderId::Claude && target.item.layer == DiscoveryLayer::Project
    }) && provider_roots
        .iter()
        .any(|(provider, _, _, _)| *provider == ProviderId::Claude)
    {
        provider_roots.push((
            ProviderId::Claude,
            ReachAwareRootScope::Project,
            roots.claude_project.clone(),
            unpin_core::mutation::BULK_TOGGLE_PROVIDER_ROOT_PROVENANCE.to_string(),
        ));
    }
    ReachAwareRootBinding::from_scoped_provider_paths(
        app_state_root,
        provider_roots,
        unpin_core::mutation::BULK_TOGGLE_ROOT_PROVENANCE,
    )
    .map_err(|error| error.to_string())
}

fn provider_root(roots: &DiscoveryRoots, provider: ProviderId) -> PathBuf {
    match provider {
        ProviderId::Claude => roots.claude_global.clone(),
        ProviderId::Codex => roots.codex_global.clone(),
        ProviderId::Cursor => roots.cursor_config.clone(),
        ProviderId::Pi => roots.pi_global.clone(),
        ProviderId::OpenCode => roots.opencode_global.clone(),
        ProviderId::Zed => roots.zed_global.clone(),
    }
}

fn render_plan(
    plan: &BulkTogglePlan,
    handoff: Option<&unpin_core::mutation::BulkToggleHandoff>,
    json_output: bool,
) -> ExitCode {
    let mut value = json!({
        "statusVersion": 2,
        "status": lifecycle_name(plan.lifecycle),
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "providerCoverage": plan.provider_coverage,
        "acknowledgement": plan.acknowledgement,
        "lifecycle": plan.lifecycle,
        "selector": plan.selector,
        "matched": plan.matched,
        "included": plan.included,
        "blocked": plan.blocked,
    });
    if let Some(handoff) = handoff {
        value["handoff"] = serde_json::to_value(handoff).unwrap_or(Value::Null);
    }
    print_value(value, json_output, "bulk plan");
    lifecycle_exit(plan.lifecycle)
}

fn render_apply_result(result: &BulkToggleApplyResult, json_output: bool) -> ExitCode {
    print_value(
        json!({
            "statusVersion": 2,
            "status": lifecycle_name(result.lifecycle),
            "operationId": result.operation_id,
            "planFingerprint": result.plan_fingerprint,
            "providerReach": result.provider_reach,
            "providerCoverage": result.provider_coverage,
            "lifecycle": result.lifecycle,
            "items": result.items,
        }),
        json_output,
        "bulk apply",
    );
    lifecycle_exit(result.lifecycle)
}

fn print_value(value: Value, json_output: bool, title: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON output")
        );
    } else {
        println!("{title}: {}", value["status"].as_str().unwrap_or("unknown"));
        if let Some(operation_id) = value["operationId"].as_str() {
            println!("operationId: {operation_id}");
        }
        if let Some(fingerprint) = value["planFingerprint"].as_str() {
            println!("planFingerprint: {fingerprint}");
        }
        println!("providerReach: {}", value["providerReach"]);
    }
}

pub(crate) const fn lifecycle_name(lifecycle: ProviderReachLifecycle) -> &'static str {
    match lifecycle {
        ProviderReachLifecycle::Applied => "applied",
        ProviderReachLifecycle::Partial => "partial",
        ProviderReachLifecycle::NoOp => "no-op",
        ProviderReachLifecycle::NoTargetsInProviderReach => "no-targets-in-provider-reach",
        ProviderReachLifecycle::Blocked => "blocked",
        ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    }
}

pub(crate) fn lifecycle_exit(lifecycle: ProviderReachLifecycle) -> ExitCode {
    ExitCode::from(match lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::NoOp => 0,
        ProviderReachLifecycle::Partial => 2,
        ProviderReachLifecycle::Blocked | ProviderReachLifecycle::NoTargetsInProviderReach => 3,
        ProviderReachLifecycle::RecoveryRequired => 4,
    })
}

fn lifecycle_status_exit_code(status: &str) -> u8 {
    match status {
        "partial" => 2,
        "blocked" | "no-targets" | "no-targets-in-provider-reach" => 3,
        "recovery-required" => 4,
        _ => 1,
    }
}

fn lifecycle_status_for_plan_error(error: &impl std::fmt::Display) -> &'static str {
    let text = error.to_string();
    if text.contains("recovery-required") {
        "recovery-required"
    } else if text.contains("no targets") {
        "no-targets"
    } else {
        "blocked"
    }
}

fn command_error_exit_code(json: bool, status: &str, reason: &str, code: u8) -> ExitCode {
    match crate::render_command_error(json, status, reason) {
        Ok(output) => {
            if json {
                println!("{output}");
            } else {
                eprintln!("{output}");
            }
        }
        Err(error) => eprintln!("{error}"),
    }
    ExitCode::from(code)
}
