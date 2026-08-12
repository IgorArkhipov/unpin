//! Path-free CLI projection and reviewed control for Agent Plugin packages.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use unpin_core::{
    agent_plugins::{
        AgentPluginAccess, AgentPluginComponentDisposition, AgentPluginInstance, AgentPluginSummary,
    },
    config::UnpinConfig,
    control_operation::{ReachAwareProviderRoot, ReachAwareRootBinding, ReachAwareRootScope},
    discovery::{DiscoveryOutput, DiscoveryRoots, ProviderId, discover_all},
    mutation::{
        BulkToggleApplyResult, BulkToggleController, BulkTogglePlan, BulkTogglePlanError,
        BulkToggleRequest, ToggleStatus,
    },
    provider_reach::{
        ConnectionBoundary, IncludedTargetOutcome, ProviderReachLifecycle,
        SelectedProviderAuthority, SelectedProviderProvenance,
    },
    transitions::TransitionJournalStore,
};

use super::{
    ProviderReachArg,
    toggle::{durable_context, lifecycle_exit, lifecycle_name},
};
use crate::{
    DiscoveryRootArgs, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, unix_now,
};

#[derive(Debug, Subcommand)]
pub(crate) enum AgentPluginCommands {
    /// List logical Agent Plugin packages derived from fresh discovery.
    List(AgentPluginListArgs),
    /// Inspect one logical package without exposing provider paths.
    Show(AgentPluginShowArgs),
    /// Build a reviewed package plan without sealing a durable handoff.
    Plan(AgentPluginPlanArgs),
    /// Build a reviewed package plan and seal its durable bulk handoff.
    Handoff(AgentPluginPlanArgs),
    /// Apply one sealed package operation after fresh discovery and confirmation.
    Apply(AgentPluginApplyArgs),
    /// Inspect one sealed package operation and its current projection status.
    Status(AgentPluginStatusArgs),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentPluginListArgs {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentPluginShowArgs {
    /// Stable logical package id emitted by `agent-plugins list`.
    logical_id: String,
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentPluginPlanArgs {
    /// Stable logical package id emitted by `agent-plugins list`.
    logical_id: String,
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Required operation reach. Selected reach also requires --provider.
    #[arg(long, value_enum, alias = "provider-reach")]
    reach: Option<ProviderReachArg>,
    /// Explicit selected-provider authority. Invalid with all-provider reach.
    #[arg(long)]
    provider: Option<String>,
    /// Enable the package's existing native activation anchors (default target).
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable the package's existing native activation anchors.
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentPluginApplyArgs {
    /// Logical package id reviewed by the sealed operation.
    logical_id: String,
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
    /// Adopt provider roots sealed by an MCP handoff without exposing them in the continuation.
    #[arg(long, hide = true)]
    adopt_sealed_roots: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct AgentPluginStatusArgs {
    /// Logical package id reviewed by the sealed operation.
    logical_id: String,
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    json: bool,
}

struct InventoryContext {
    fixture_mode: bool,
    config: UnpinConfig,
    roots: DiscoveryRoots,
    discovery: DiscoveryOutput,
}

pub(crate) fn run(command: AgentPluginCommands) -> ExitCode {
    match command {
        AgentPluginCommands::List(args) => list(args),
        AgentPluginCommands::Show(args) => show(args),
        AgentPluginCommands::Plan(args) => plan(args, false),
        AgentPluginCommands::Handoff(args) => plan(args, true),
        AgentPluginCommands::Apply(args) => apply(args),
        AgentPluginCommands::Status(args) => status(args),
    }
}

fn list(args: AgentPluginListArgs) -> ExitCode {
    let context = match load_inventory(&args.roots, args.app_state_root) {
        Ok(context) => context,
        Err(_) => return inventory_error(args.json),
    };
    let packages = context.discovery.agent_plugins();
    let value = json!({
        "statusVersion": 1,
        "status": "ok",
        "inventoryComplete": context.discovery.agent_plugin_inventory_complete(),
        "packageCount": packages.len(),
        "packages": packages.iter().map(package_summary_value).collect::<Vec<_>>(),
    });
    print_list(value, args.json)
}

fn show(args: AgentPluginShowArgs) -> ExitCode {
    let context = match load_inventory(&args.roots, args.app_state_root) {
        Ok(context) => context,
        Err(_) => return inventory_error(args.json),
    };
    let Some(package) = find_package(&context.discovery, &args.logical_id) else {
        return command_error(
            args.json,
            "blocked",
            "agent-plugin-not-found",
            "Agent Plugin package was not found; refresh the inventory and use its logical id",
            3,
        );
    };
    let value = json!({
        "statusVersion": 1,
        "status": "ok",
        "package": package_detail_value(&package),
        "guidance": package_guidance(&package),
    });
    print_package_value(value, args.json, "agent plugin");
    ExitCode::SUCCESS
}

fn plan(args: AgentPluginPlanArgs, require_handoff: bool) -> ExitCode {
    let context = match load_inventory(&args.roots, args.app_state_root.clone()) {
        Ok(context) => context,
        Err(_) => return inventory_error(args.json),
    };
    let Some(package) = find_package(&context.discovery, &args.logical_id) else {
        return command_error(
            args.json,
            "blocked",
            "agent-plugin-not-found",
            "Agent Plugin package was not found; refresh the inventory and use its logical id",
            3,
        );
    };
    let request = match package_request(&context.discovery, &package, &args) {
        Ok(request) => request,
        Err(error) => return render_plan_error(args.json, &error),
    };
    if let Err(error) = BulkToggleController::validate_before_discovery(&request) {
        return render_plan_error(args.json, &error);
    }
    let controller = BulkToggleController::new(&context.config.app_state_root);
    let reviewed =
        match controller.plan_agent_plugin_from_discovery(context.discovery, request, &package) {
            Ok(plan) => plan,
            Err(error) => return render_plan_error(args.json, &error),
        };
    let handoff = if require_handoff {
        match durable_context(
            &context.config.app_state_root,
            &context.roots,
            &context.config,
            &reviewed,
            context.fixture_mode,
        ) {
            Ok((controller, durable)) => match controller.seal_handoff(&reviewed, &durable) {
                Ok(handoff) => Some(handoff),
                Err(error) => return render_plan_error(args.json, &error),
            },
            Err(error) => return handoff_error(args.json, &error),
        }
    } else {
        None
    };
    let mut value = package_plan_value(&package, &reviewed);
    if let Some(handoff) = handoff {
        value["handoff"] = json!({
            "operationId": handoff.operation_id,
            "planFingerprint": handoff.plan_fingerprint,
            "expiresAtUnix": handoff.expires_at_unix,
        });
    }
    print_package_value(value, args.json, "agent plugin plan");
    lifecycle_exit(reviewed.lifecycle)
}

fn apply(args: AgentPluginApplyArgs) -> ExitCode {
    if !args.confirm {
        return command_error(
            args.json,
            "blocked",
            "confirmation-required",
            "confirmation is required before applying a reviewed package plan",
            3,
        );
    }
    let mut context = match load_inventory(&args.roots, args.app_state_root.clone()) {
        Ok(context) => context,
        Err(_) => return inventory_error(args.json),
    };
    let controller = BulkToggleController::new(&context.config.app_state_root);
    let reviewed = match controller.load_handoff(&args.operation_id) {
        Ok(plan) => plan,
        Err(error) => return render_plan_error(args.json, &error),
    };
    if reviewed.operation_id != args.operation_id
        || reviewed.plan_fingerprint != args.plan_fingerprint
    {
        return command_error(
            args.json,
            "blocked",
            "plan-fingerprint-mismatch",
            "the operation id and reviewed plan fingerprint do not match",
            3,
        );
    }
    if args.adopt_sealed_roots {
        let sealed_roots = match sealed_agent_plugin_roots(
            &context.config.app_state_root,
            &args.operation_id,
            &context.roots,
        ) {
            Ok(roots) => roots,
            Err(_) => {
                return command_error(
                    args.json,
                    "blocked",
                    "sealed-root-binding-unavailable",
                    "the sealed package root binding is unavailable; create a new MCP handoff",
                    3,
                );
            }
        };
        context.discovery = match discover_all(&sealed_roots) {
            Ok(discovery) => discovery,
            Err(_) => return inventory_error(args.json),
        };
        context.roots = sealed_roots;
    }
    let Some(package) = find_package(&context.discovery, &args.logical_id) else {
        return command_error(
            args.json,
            "blocked",
            "package-refresh-required",
            "the reviewed package is no longer present; refresh before applying",
            3,
        );
    };
    let current_request = match BulkToggleRequest::for_agent_plugin_summary(
        &context.discovery,
        &package,
        reviewed.target_enabled,
    ) {
        Ok(request) => request,
        Err(error) => return render_plan_error(args.json, &error),
    };
    if current_request.selector != reviewed.selector
        || current_request.selection_context_fingerprint != reviewed.selection_context_fingerprint
    {
        return command_error(
            args.json,
            "blocked",
            "package-projection-changed",
            "the package projection changed after review; refresh and create a new handoff",
            3,
        );
    }
    let (controller, durable) = match durable_context(
        &context.config.app_state_root,
        &context.roots,
        &context.config,
        &reviewed,
        context.fixture_mode,
    ) {
        Ok(context) => context,
        Err(error) => return handoff_error(args.json, &error),
    };
    let expectation = match reviewed
        .approval_expectation(&durable.approval_context, &durable.principal.session_id)
    {
        Ok(expectation) => expectation,
        Err(error) => return render_plan_error(args.json, &error),
    };
    let digest = reviewed
        .plan_fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(&reviewed.plan_fingerprint);
    let authorization = match credentials::authorize_reviewed_control_decision(
        context.fixture_mode,
        &context.config.app_state_root,
        &expectation,
        digest,
        Some(digest),
        "unpin-cli-agent-plugin-approval",
        unix_now(),
    ) {
        Ok(authorization) => authorization,
        Err(_) => {
            return command_error(
                args.json,
                "blocked",
                "approval-unavailable",
                "reviewed package approval is unavailable; refresh credentials and create a new handoff",
                3,
            );
        }
    };
    let result = match controller.apply_with_reach_aware(
        &reviewed,
        authorization,
        durable,
        context.discovery,
    ) {
        Ok(result) => result,
        Err(error) => return render_plan_error(args.json, &error),
    };
    let refreshed = discover_all(&context.roots)
        .ok()
        .and_then(|discovery| find_package(&discovery, &args.logical_id));
    let mut value = package_apply_value(refreshed.as_ref().unwrap_or(&package), &result);
    value["refreshStatus"] = Value::String(if refreshed.is_some() {
        "complete".to_string()
    } else {
        "failed-run-status".to_string()
    });
    print_package_value(value, args.json, "agent plugin apply");
    lifecycle_exit(result.lifecycle)
}

fn status(args: AgentPluginStatusArgs) -> ExitCode {
    let context = match load_inventory(&args.roots, args.app_state_root.clone()) {
        Ok(context) => context,
        Err(_) => return inventory_error(args.json),
    };
    let session_key = match credentials::resolve_session_authority_key(
        context.fixture_mode,
        &context.config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error(
                args.json,
                "blocked",
                "session-authority-missing",
                "session authority key missing; run `unpin auth session init`",
                3,
            );
        }
        Err(_) => {
            return command_error(
                args.json,
                "blocked",
                "session-authority-unavailable",
                "session authority could not be loaded; reinitialize it before reading package status",
                3,
            );
        }
    };
    let controller = BulkToggleController::new(&context.config.app_state_root)
        .with_session_authority_key(session_key);
    let operation = match controller.load_handoff_status(&args.operation_id) {
        Ok(operation) => operation,
        Err(error) => return render_plan_error(args.json, &error),
    };
    let lifecycle = operation.lifecycle();
    let package = find_package(&context.discovery, &args.logical_id);
    let projection_matches = package.as_ref().is_some_and(|package| {
        operation.plan.selection_context_fingerprint.as_deref()
            == Some(package.projection_fingerprint.as_str())
    });
    let package_value = package.as_ref().map_or_else(
        || json!({ "logicalId": args.logical_id, "current": false }),
        package_summary_value,
    );
    let terminal_counts = operation
        .terminal_result
        .as_ref()
        .map(result_counts_value)
        .unwrap_or(Value::Null);
    let refresh_required = !projection_matches;
    let value = json!({
        "statusVersion": 1,
        "status": lifecycle_name(lifecycle),
        "operationId": operation.plan.operation_id,
        "planFingerprint": operation.plan.plan_fingerprint,
        "providerReach": operation.plan.provider_reach,
        "targetEnabled": operation.plan.target_enabled,
        "package": package_value,
        "projectionMatchesReview": projection_matches,
        "refreshStatus": if refresh_required { "required" } else { "complete" },
        "refreshRequired": refresh_required,
        "replanRequired": !projection_matches,
        "counts": plan_counts_value(package.as_ref(), &operation.plan),
        "review": plan_review_value(package.as_ref(), &operation.plan),
        "resultCounts": terminal_counts,
        "guidance": lifecycle_guidance(lifecycle),
    });
    print_package_value(value, args.json, "agent plugin status");
    lifecycle_exit(lifecycle)
}

fn load_inventory(
    roots: &DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
) -> Result<InventoryContext, String> {
    let fixture_mode = roots.fixture_root.is_some();
    let config = resolve_config(roots, app_state_root).map_err(|error| error.to_string())?;
    let roots = resolve_discovery_roots_with_config(roots, &config)?
        .with_app_state_root(&config.app_state_root);
    let discovery = discover_all(&roots).map_err(|error| error.to_string())?;
    Ok(InventoryContext {
        fixture_mode,
        config,
        roots,
        discovery,
    })
}

fn sealed_agent_plugin_roots(
    app_state_root: &Path,
    operation_id: &str,
    current_roots: &DiscoveryRoots,
) -> Result<DiscoveryRoots, String> {
    let canonical_app_state_root =
        std::fs::canonicalize(app_state_root).map_err(|error| error.to_string())?;
    let journal = TransitionJournalStore::new(&canonical_app_state_root)
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|journal| journal.operation_id == operation_id)
        .ok_or_else(|| "sealed operation journal not found".to_string())?;
    let sealed: ReachAwareRootBinding = journal
        .reach_aware
        .ok_or_else(|| "sealed operation root binding not found".to_string())?
        .roots;
    sealed.verify().map_err(|error| error.to_string())?;

    let sealed_app_state_root =
        std::fs::canonicalize(&sealed.app_state_root).map_err(|error| error.to_string())?;
    if sealed_app_state_root != canonical_app_state_root {
        return Err("sealed operation is bound to a different app-state root".to_string());
    }

    let roots =
        apply_sealed_agent_plugin_provider_roots(current_roots.clone(), sealed.provider_roots)?;
    Ok(roots.with_app_state_root(canonical_app_state_root))
}

fn apply_sealed_agent_plugin_provider_roots(
    mut roots: DiscoveryRoots,
    bindings: impl IntoIterator<Item = ReachAwareProviderRoot>,
) -> Result<DiscoveryRoots, String> {
    for binding in bindings {
        let root = PathBuf::from(binding.root);
        match (binding.provider, binding.scope) {
            (ProviderId::Claude, ReachAwareRootScope::Primary) => roots.claude_global = root,
            (ProviderId::Claude, ReachAwareRootScope::Project) => roots.claude_project = root,
            (ProviderId::Codex, ReachAwareRootScope::Primary) => roots.codex_global = root,
            (ProviderId::Cursor, ReachAwareRootScope::Primary) => roots.cursor_config = root,
            (ProviderId::Pi, ReachAwareRootScope::Primary) => roots.pi_global = root,
            (ProviderId::OpenCode, ReachAwareRootScope::Primary) => roots.opencode_global = root,
            (ProviderId::Zed, ReachAwareRootScope::Primary) => roots.zed_global = root,
            (provider, ReachAwareRootScope::Project) => {
                return Err(format!(
                    "sealed Agent Plugin handoff contains an unsupported project root for {}",
                    provider.as_str()
                ));
            }
        }
    }
    Ok(roots)
}

fn package_request(
    discovery: &DiscoveryOutput,
    package: &AgentPluginSummary,
    args: &AgentPluginPlanArgs,
) -> Result<BulkToggleRequest, PackageRequestError> {
    let target_enabled = args.enable || !args.disable;
    let mut request =
        BulkToggleRequest::for_agent_plugin_summary(discovery, package, target_enabled)?;
    let reach = args.reach.ok_or(PackageRequestError::ReachRequired)?;
    let provider = args
        .provider
        .as_deref()
        .map(|value| parse_provider_id(value).ok_or(PackageRequestError::InvalidProvider))
        .transpose()?;
    if reach == ProviderReachArg::All && provider.is_some() {
        return Err(PackageRequestError::ProviderWithAllReach);
    }
    let input = reach
        .input(provider)
        .map_err(|_| PackageRequestError::Reach)?;
    request = request.with_reach(ConnectionBoundary::All, input);
    if let Some(provider) = provider {
        request = request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    Ok(request)
}

#[derive(Debug)]
enum PackageRequestError {
    Core(BulkTogglePlanError),
    ReachRequired,
    Reach,
    InvalidProvider,
    ProviderWithAllReach,
}

impl From<BulkTogglePlanError> for PackageRequestError {
    fn from(error: BulkTogglePlanError) -> Self {
        Self::Core(error)
    }
}

fn render_plan_error(json: bool, error: &impl AsPlanError) -> ExitCode {
    let (reason_code, reason) = error.safe_plan_error();
    command_error(json, "blocked", reason_code, reason, 3)
}

trait AsPlanError {
    fn safe_plan_error(&self) -> (&'static str, &str);
}

impl AsPlanError for BulkTogglePlanError {
    fn safe_plan_error(&self) -> (&'static str, &str) {
        match self {
            Self::AgentPluginNotFound => (
                "agent-plugin-not-found",
                "Agent Plugin package was not found; refresh the inventory and use its logical id",
            ),
            Self::AgentPluginHasNoActivationAnchors => (
                "no-native-activation-anchors",
                "diagnostics-only package has no existing native activation anchors and cannot be applied",
            ),
            Self::AgentPluginInventoryIncomplete => (
                "agent-plugin-inventory-incomplete",
                "Agent Plugin inventory is incomplete; refresh discovery before planning",
            ),
            Self::AgentPluginHasDiagnosticsOnlyActivationAnchors => (
                "diagnostics-only-writable-activation",
                "A diagnostics-only package instance has writable native activation anchors; fix diagnostics before planning",
            ),
            Self::AgentPluginHasNoActionableActivationAnchors => (
                "diagnostics-only-no-actionable-activation",
                "diagnostics-only package has no safe apply action; fix component diagnostics and refresh before planning",
            ),
            Self::SelectionContextFingerprintMismatch => (
                "package-projection-changed",
                "the package projection changed after review; refresh and create a new handoff",
            ),
            Self::PlanFingerprintMismatch => (
                "plan-fingerprint-mismatch",
                "the reviewed package plan no longer matches fresh discovery",
            ),
            Self::NoTargetsInProviderReach => (
                "no-targets-in-provider-reach",
                "the selected provider reach contains no package activation anchors",
            ),
            _ => (
                "package-plan-blocked",
                "the package plan is blocked; refresh inventory and review package diagnostics",
            ),
        }
    }
}

impl AsPlanError for PackageRequestError {
    fn safe_plan_error(&self) -> (&'static str, &str) {
        match self {
            Self::Core(error) => error.safe_plan_error(),
            Self::ReachRequired => (
                "provider-reach-required",
                "choose explicit package reach with --reach selected --provider <id> or --reach all",
            ),
            Self::Reach => (
                "selected-provider-required",
                "selected package reach requires explicit --provider authority",
            ),
            Self::InvalidProvider => (
                "invalid-selected-provider",
                "selected package reach names an unsupported provider",
            ),
            Self::ProviderWithAllReach => (
                "provider-conflicts-with-all-reach",
                "--provider is only valid with selected package reach",
            ),
        }
    }
}

fn find_package(discovery: &DiscoveryOutput, logical_id: &str) -> Option<AgentPluginSummary> {
    discovery
        .agent_plugins()
        .into_iter()
        .find(|package| package.logical_id == logical_id)
}

fn package_summary_value(package: &AgentPluginSummary) -> Value {
    json!({
        "logicalId": package.logical_id,
        "name": package.name,
        "componentSignature": package.component_signature,
        "projectionFingerprint": package.projection_fingerprint,
        "state": package.state,
        "access": package.access,
        "componentKinds": package.instances.iter()
            .flat_map(|instance| instance.components.iter().map(|component| component.kind))
            .collect::<BTreeSet<_>>(),
        "blockerCount": package.instances.iter().map(|instance| instance.blockers.len()).sum::<usize>(),
        "diagnosticCount": package.instances.iter().map(|instance| instance.diagnostics.len()).sum::<usize>(),
        "instanceCount": package.instances.len(),
        "instances": package.instances.iter().map(instance_summary_value).collect::<Vec<_>>(),
    })
}

fn instance_summary_value(instance: &AgentPluginInstance) -> Value {
    json!({
        "provider": instance.provider,
        "layer": instance.layer,
        "state": instance.state,
        "access": instance.access,
        "componentCount": instance.components.len(),
        "activationCount": instance.activations.len(),
        "blockerCount": instance.blockers.len(),
        "diagnosticCount": instance.diagnostics.len(),
    })
}

fn package_detail_value(package: &AgentPluginSummary) -> Value {
    let mut instances = package
        .instances
        .iter()
        .map(|instance| {
            let mut components = instance
                .components
                .iter()
                .map(|component| {
                    json!({
                        "kind": component.kind,
                        "name": component.name,
                        "disposition": component.disposition,
                        "reason": component.reason,
                    })
                })
                .collect::<Vec<_>>();
            components.sort_by_key(|component| {
                component["kind"].as_str().unwrap_or_default().to_string()
            });
            json!({
                "provider": instance.provider,
                "layer": instance.layer,
                "state": instance.state,
                "access": instance.access,
                "version": instance.manifest.version,
                "components": components,
                "activations": instance.activations.iter().map(|activation| json!({
                    "enabled": activation.enabled,
                    "mutability": activation.mutability,
                })).collect::<Vec<_>>(),
                "blockers": instance.blockers,
                "diagnostics": instance.diagnostics,
            })
        })
        .collect::<Vec<_>>();
    instances.sort_by_key(|instance| {
        (
            instance["provider"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            instance["layer"].as_str().unwrap_or_default().to_string(),
        )
    });
    let mut value = package_summary_value(package);
    value["instances"] = Value::Array(instances);
    value
}

fn package_plan_status(lifecycle: ProviderReachLifecycle) -> &'static str {
    match lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::Partial => "planned",
        ProviderReachLifecycle::NoOp => "no-op",
        ProviderReachLifecycle::NoTargetsInProviderReach => "no-targets-in-provider-reach",
        ProviderReachLifecycle::Blocked => "blocked",
        ProviderReachLifecycle::RecoveryRequired => "recovery-required",
    }
}

fn package_plan_value(package: &AgentPluginSummary, plan: &BulkTogglePlan) -> Value {
    json!({
        "statusVersion": 1,
        "status": package_plan_status(plan.lifecycle),
        "lifecycle": lifecycle_name(plan.lifecycle),
        "operationId": plan.operation_id,
        "planFingerprint": plan.plan_fingerprint,
        "providerReach": plan.provider_reach,
        "targetEnabled": plan.target_enabled,
        "package": package_summary_value(package),
        "counts": plan_counts_value(Some(package), plan),
        "review": plan_review_value(Some(package), plan),
        "guidance": lifecycle_guidance(plan.lifecycle),
    })
}

fn plan_counts_value(package: Option<&AgentPluginSummary>, plan: &BulkTogglePlan) -> Value {
    let (instances, activations, components, diagnostics) =
        package.map_or((0, 0, 0, 0), |package| {
            (
                package.instances.len(),
                package
                    .instances
                    .iter()
                    .map(|instance| instance.activations.len())
                    .sum(),
                package
                    .instances
                    .iter()
                    .map(|instance| instance.components.len())
                    .sum(),
                package
                    .instances
                    .iter()
                    .map(|instance| instance.diagnostics.len() + instance.blockers.len())
                    .sum(),
            )
        });
    json!({
        "instances": instances,
        "activations": activations,
        "components": components,
        "diagnostics": diagnostics,
        "included": plan.included_count(),
        "writes": plan.write_count(),
        "noOp": plan.included_count().saturating_sub(plan.write_count()),
        "blocked": plan.blocked_count(),
        "reachExcluded": plan.provider_coverage.reach_excluded_count(),
    })
}

fn plan_review_value(package: Option<&AgentPluginSummary>, plan: &BulkTogglePlan) -> Value {
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
        .filter(|item| item.outcome == IncludedTargetOutcome::NoOp)
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
    let reach_excluded = package.map_or_else(Vec::new, |package| {
        package
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
            .collect::<Vec<_>>()
    });
    let component_diagnostics = package.map_or_else(Vec::new, |package| {
        package
            .instances
            .iter()
            .flat_map(|instance| {
                let mut rows = instance
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
                rows.extend(instance.blockers.iter().map(|reason| {
                    json!({
                        "provider": instance.provider,
                        "layer": instance.layer,
                        "disposition": "blocked",
                        "reason": reason,
                    })
                }));
                rows.extend(instance.diagnostics.iter().map(|reason| {
                    json!({
                        "provider": instance.provider,
                        "layer": instance.layer,
                        "disposition": "diagnostic",
                        "reason": reason,
                    })
                }));
                rows
            })
            .collect::<Vec<_>>()
    });
    json!({
        "included": included,
        "noOp": no_op,
        "blocked": blocked,
        "reachExcluded": reach_excluded,
        "componentDiagnostics": component_diagnostics,
    })
}

fn package_apply_value(package: &AgentPluginSummary, result: &BulkToggleApplyResult) -> Value {
    json!({
        "statusVersion": 1,
        "status": lifecycle_name(result.lifecycle),
        "operationId": result.operation_id,
        "planFingerprint": result.plan_fingerprint,
        "providerReach": result.provider_reach,
        "package": package_summary_value(package),
        "resultCounts": result_counts_value(result),
        "guidance": lifecycle_guidance(result.lifecycle),
    })
}

fn result_counts_value(result: &BulkToggleApplyResult) -> Value {
    let mut applied = 0;
    let mut no_op = 0;
    let mut blocked = 0;
    let mut recovery_required = 0;
    let mut backup_count = 0;
    let mut reason_codes = BTreeSet::new();
    for item in &result.items {
        match item.status {
            ToggleStatus::Applied => applied += 1,
            ToggleStatus::DryRun => no_op += 1,
            ToggleStatus::Blocked => blocked += 1,
            ToggleStatus::RecoveryRequired => recovery_required += 1,
        }
        backup_count += usize::from(item.backup_id.is_some());
        if let Some(reason) = &item.reason {
            reason_codes.insert(safe_reason_code(reason));
        }
    }
    json!({
        "applied": applied,
        "noOp": no_op,
        "blocked": blocked,
        "recoveryRequired": recovery_required,
        "backupCount": backup_count,
        "reasonCodes": reason_codes,
    })
}

fn package_guidance(package: &AgentPluginSummary) -> &'static str {
    match package.access {
        AgentPluginAccess::Actionable => {
            "Packages are derived logical views; plan changes existing native activation anchors. Groups remain editable user definitions."
        }
        AgentPluginAccess::DiagnosticsOnly => {
            "Diagnostics-only package: inspect component diagnostics and native activation coverage; no apply action is available."
        }
        AgentPluginAccess::Unsupported => {
            "Package control is unsupported for this provider/layer; no apply action is available."
        }
    }
}

fn lifecycle_guidance(lifecycle: ProviderReachLifecycle) -> &'static str {
    match lifecycle {
        ProviderReachLifecycle::Applied => {
            "Refresh package status after apply. Backups and restore remain available through Unpin restore/operations."
        }
        ProviderReachLifecycle::Partial => {
            "Review blocked and included counts before applying; after apply inspect backups and recovery guidance."
        }
        ProviderReachLifecycle::NoOp => {
            "All included native activation anchors already match the requested package state."
        }
        ProviderReachLifecycle::NoTargetsInProviderReach => {
            "Choose reach that includes an existing native activation anchor, then replan from fresh discovery."
        }
        ProviderReachLifecycle::Blocked => {
            "No apply is available. Refresh discovery and resolve package/component diagnostics before replanning."
        }
        ProviderReachLifecycle::RecoveryRequired => {
            "Do not reapply. Inspect operation status and use Unpin restore/operations recovery evidence."
        }
    }
}

fn print_list(value: Value, json_output: bool) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("Agent Plugin list JSON")
        );
    } else {
        println!(
            "Agent Plugins: {} logical package(s)",
            value["packageCount"].as_u64().unwrap_or(0)
        );
        if let Some(packages) = value["packages"].as_array() {
            for package in packages {
                println!(
                    "[{}] {} ({}) instances={} access={}",
                    package["state"].as_str().unwrap_or("unknown"),
                    package["name"].as_str().unwrap_or("unknown"),
                    package["logicalId"].as_str().unwrap_or("unknown"),
                    package["instanceCount"].as_u64().unwrap_or(0),
                    package["access"].as_str().unwrap_or("unknown"),
                );
            }
        }
        if value["packageCount"] == 0 {
            println!("No Agent Plugin packages were derived from fresh discovery.");
        }
    }
    ExitCode::SUCCESS
}

fn print_package_value(value: Value, json_output: bool, title: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("Agent Plugin JSON")
        );
        return;
    }
    println!("{title}: {}", value["status"].as_str().unwrap_or("unknown"));
    if let Some(package) = value.get("package") {
        println!(
            "package: {} ({}) state={} access={}",
            package["name"].as_str().unwrap_or("unknown"),
            package["logicalId"].as_str().unwrap_or("unknown"),
            package["state"].as_str().unwrap_or("unknown"),
            package["access"].as_str().unwrap_or("unknown"),
        );
    }
    if let Some(operation_id) = value["operationId"].as_str() {
        println!("operationId: {operation_id}");
    }
    if let Some(fingerprint) = value["planFingerprint"].as_str() {
        println!("planFingerprint: {fingerprint}");
    }
    if !value["providerReach"].is_null() {
        println!("providerReach: {}", value["providerReach"]);
    }
    if let Some(guidance) = value["guidance"].as_str() {
        println!("guidance: {guidance}");
    }
}

fn inventory_error(json_output: bool) -> ExitCode {
    command_error(
        json_output,
        "failed",
        "discovery-failed",
        "fresh Agent Plugin discovery failed; run `unpin doctor` and retry",
        1,
    )
}

fn handoff_error(json_output: bool, error: &str) -> ExitCode {
    let reason = if error.contains("backup authentication key missing") {
        "backup authentication key missing; run `unpin auth backup init`"
    } else if error.contains("session authority key missing") {
        "session authority key missing; run `unpin auth session init`"
    } else {
        "durable package handoff is unavailable; refresh credentials and discovery before retrying"
    };
    command_error(json_output, "blocked", "handoff-unavailable", reason, 3)
}

fn command_error(
    json_output: bool,
    status: &str,
    reason_code: &str,
    reason: &str,
    code: u8,
) -> ExitCode {
    let value = json!({
        "statusVersion": 1,
        "status": status,
        "reasonCode": reason_code,
        "reason": reason,
    });
    let rendered = if json_output {
        serde_json::to_string_pretty(&value).expect("Agent Plugin error JSON")
    } else {
        format!("agent plugin {status}: {reason_code}: {reason}")
    };
    if json_output {
        println!("{rendered}");
    } else {
        eprintln!("{rendered}");
    }
    ExitCode::from(code)
}

pub(crate) fn safe_reason_code(reason: &str) -> String {
    if !reason.is_empty()
        && reason.len() <= 128
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        reason.to_string()
    } else {
        "redacted-operation-reason".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use unpin_core::{
        control_operation::{ReachAwareProviderRoot, ReachAwareRootScope},
        discovery::{DiscoveryRoots, ProviderId},
    };

    use super::{apply_sealed_agent_plugin_provider_roots, safe_reason_code};

    #[test]
    fn sealed_roots_restore_the_claude_project_root() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let project = tempfile::TempDir::new().expect("custom project root");
        fs::create_dir_all(project.path().join(".claude")).expect("project directory");
        let project_root = fs::canonicalize(project.path()).expect("canonical project root");

        let restored = apply_sealed_agent_plugin_provider_roots(
            DiscoveryRoots::fixture_root(fixture.path()),
            [ReachAwareProviderRoot {
                provider: ProviderId::Claude,
                scope: ReachAwareRootScope::Project,
                root: project_root.to_string_lossy().into_owned(),
                provenance: "test-root".to_string(),
            }],
        )
        .expect("project root is supported");

        assert_eq!(restored.claude_project, project_root);
    }

    #[test]
    fn unsafe_operation_reasons_are_redacted() {
        assert_eq!(safe_reason_code("already-disabled"), "already-disabled");
        assert_eq!(
            safe_reason_code("bulk plan drifted before apply at /private/provider.json"),
            "redacted-operation-reason"
        );
    }
}
