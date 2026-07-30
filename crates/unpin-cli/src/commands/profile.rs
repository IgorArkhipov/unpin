use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    catalog::{CapabilityId, Catalog},
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        DurableControlError, ReachAwarePrincipal, ReachAwareRootBinding,
    },
    discovery::{DiscoveryOutput, discover_all},
    profiles::{
        CapabilityLockChange, CapabilityLockSnapshot, CapabilityLockState, GatewaySelection,
        PROFILE_PROVIDER_APPROVAL_AUDIENCE, PolicyApplyStatus, PolicyChange, PolicyControlError,
        PolicyMaintenanceApproval, PolicyMaintenanceController, PolicyMaintenancePlan, PolicyStore,
        PolicyTarget, ProfileDefinition, ProfileDefinitionEntry, ProfilePolicyController,
        ProfileProviderOperationController, ProfileProviderOperationError,
        ProfileProviderOperationStatus, ProfileProviderReachAwareApplyContext, ProfileReference,
        ProfileSelection, ProfileSourceScope, ProfileStore, ProtectedPolicyChangeError,
        capability_lock_enforcement, compile_profile, profile_reach_scope_digest, propose_profile,
        resolve_effective_gateway,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, ProviderReachRequest, SelectedProviderAuthority,
        SelectedProviderProvenance,
    },
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
    state::workspace::WorkspaceIdentity,
};

use super::ProviderReachArg;
use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, unix_now,
};

#[derive(Debug, Subcommand)]
pub(crate) enum ProfileCommands {
    /// List global and workspace profile definitions.
    List(ProfileRootOptions),
    /// Show one profile definition using workspace-over-global precedence.
    Show {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Profile id.
        id: String,
        /// Definition scope to inspect.
        #[arg(long, value_enum, default_value_t = DefinitionScopeArg::Auto)]
        scope: DefinitionScopeArg,
    },
    /// Compile one profile against current capability catalog without changing state.
    Validate {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Stored profile id. Conflicts with --file.
        #[arg(long, conflicts_with = "file")]
        id: Option<String>,
        /// Standalone profile definition JSON. .env files are rejected.
        #[arg(long, conflicts_with = "id")]
        file: Option<PathBuf>,
        /// Source scope assigned to --file definitions.
        #[arg(long, value_enum, default_value_t = DefinitionScopeArg::Workspace)]
        scope: DefinitionScopeArg,
    },
    /// Propose a metadata-matched session profile without changing exposure.
    Propose {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Prompt text used only for local metadata matching; output contains its digest, not body.
        #[arg(long)]
        prompt: String,
        /// Optional provider context for proposal and later validation.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Select one profile and native/gateway mode for future sessions.
    Apply {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Stored profile id.
        #[arg(long)]
        id: String,
        /// Provider-specific override. Omit for generic scope policy.
        #[arg(long)]
        provider: Option<String>,
        /// Reach-aware provider targeting. Omit to preserve the legacy generic
        /// profile/gateway policy workflow.
        #[arg(long, alias = "provider-reach", value_enum)]
        reach: Option<ProviderReachArg>,
        /// Persistent scope receiving selection.
        #[arg(long, value_enum, default_value_t = PolicyScopeArg::Workspace)]
        scope: PolicyScopeArg,
        /// Native or gateway application backend for future sessions.
        #[arg(long, value_enum)]
        mode: ProfileModeArg,
        /// Apply reviewed plan. Omit for dry-run.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run plan.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
    },
    /// Plan or apply one global provider capability lock.
    Lock {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Provider receiving the global lock.
        #[arg(long)]
        provider: String,
        /// Stable catalog capability id.
        #[arg(long)]
        capability: String,
        /// Hard-enable, hard-disable, or clear this lock.
        #[arg(long, value_enum)]
        state: CapabilityLockStateArg,
        /// Apply reviewed plan. Omit for dry-run.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run plan.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
    },
    /// Show global provider capability locks and enforcement evidence.
    Locks {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Limit output to one provider.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Inspect or explicitly maintain migrated workspace policy state.
    Policy {
        #[command(subcommand)]
        command: ProfilePolicyCommands,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProfilePolicyCommands {
    /// Show authenticated workspace-policy binding and orphan status.
    Status {
        #[command(flatten)]
        options: ProfileRootOptions,
        /// Recorded repository key. Omit with --workspace-key to use the current workspace.
        #[arg(long, requires = "workspace_key")]
        repository_key: Option<String>,
        /// Recorded workspace key. Omit with --repository-key to use the current workspace.
        #[arg(long, requires = "repository_key")]
        workspace_key: Option<String>,
        /// Compare the record with the current checkout as a reattachment candidate.
        #[arg(long)]
        candidate_current: bool,
    },
    /// Plan or apply fixed-source .unpin/policy.json migration.
    Migrate(PolicyMaintenanceMutationOptions),
    /// Plan or apply reattachment to the current physical checkout.
    Reattach {
        #[command(flatten)]
        mutation: PolicyMaintenanceMutationOptions,
        #[arg(long)]
        repository_key: String,
        #[arg(long)]
        workspace_key: String,
    },
    /// Plan or apply explicit orphan discard.
    Discard {
        #[command(flatten)]
        mutation: PolicyMaintenanceMutationOptions,
        #[arg(long)]
        repository_key: String,
        #[arg(long)]
        workspace_key: String,
    },
    /// Plan or apply cleanup of an authenticated inactive tombstone.
    Cleanup {
        #[command(flatten)]
        mutation: PolicyMaintenanceMutationOptions,
        #[arg(long)]
        repository_key: String,
        #[arg(long)]
        workspace_key: String,
    },
    /// Plan or apply exact restore from an authenticated policy backup.
    Restore {
        #[command(flatten)]
        mutation: PolicyMaintenanceMutationOptions,
        #[arg(long)]
        backup_id: String,
    },
}

#[derive(Debug, Clone, Args)]
pub(crate) struct PolicyMaintenanceMutationOptions {
    #[command(flatten)]
    options: ProfileRootOptions,
    /// Apply the reviewed maintenance plan. Omit for dry-run.
    #[arg(long)]
    apply: bool,
    /// Explicit confirmation required with --apply.
    #[arg(long, requires = "apply")]
    confirm: bool,
    /// Fingerprint emitted by the matching dry-run plan.
    #[arg(long, requires = "apply")]
    plan_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct ProfileRootOptions {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    /// Unpin-owned state root containing global profiles and policies.
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Render machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DefinitionScopeArg {
    Auto,
    Global,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PolicyScopeArg {
    Global,
    Repository,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ProfileModeArg {
    Native,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CapabilityLockStateArg {
    HardEnabled,
    HardDisabled,
    Clear,
}

pub(crate) fn run(command: ProfileCommands) -> ExitCode {
    match command {
        ProfileCommands::List(options) => list(options),
        ProfileCommands::Show { options, id, scope } => show(options, &id, scope),
        ProfileCommands::Validate {
            options,
            id,
            file,
            scope,
        } => validate(options, id.as_deref(), file.as_deref(), scope),
        ProfileCommands::Propose {
            options,
            prompt,
            provider,
        } => propose(options, &prompt, provider.as_deref()),
        ProfileCommands::Apply {
            options,
            id,
            provider,
            reach,
            scope,
            mode,
            apply,
            confirm,
            plan_fingerprint,
        } => apply_profile(
            options,
            &id,
            provider.as_deref(),
            reach,
            scope,
            mode,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
        ),
        ProfileCommands::Lock {
            options,
            provider,
            capability,
            state,
            apply,
            confirm,
            plan_fingerprint,
        } => change_capability_lock(
            options,
            &provider,
            &capability,
            state,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
        ),
        ProfileCommands::Locks { options, provider } => {
            list_capability_locks(options, provider.as_deref())
        }
        ProfileCommands::Policy { command } => run_policy_maintenance(command),
    }
}

fn run_policy_maintenance(command: ProfilePolicyCommands) -> ExitCode {
    match command {
        ProfilePolicyCommands::Status {
            options,
            repository_key,
            workspace_key,
            candidate_current,
        } => policy_maintenance_status(
            options,
            repository_key.as_deref(),
            workspace_key.as_deref(),
            candidate_current,
        ),
        ProfilePolicyCommands::Migrate(mutation) => {
            run_policy_maintenance_mutation(mutation, |controller| controller.plan_migration())
        }
        ProfilePolicyCommands::Reattach {
            mutation,
            repository_key,
            workspace_key,
        } => run_workspace_policy_maintenance_mutation(
            mutation,
            &repository_key,
            &workspace_key,
            |controller, target| controller.plan_reattach(target),
        ),
        ProfilePolicyCommands::Discard {
            mutation,
            repository_key,
            workspace_key,
        } => run_workspace_policy_maintenance_mutation(
            mutation,
            &repository_key,
            &workspace_key,
            |controller, target| controller.plan_discard(target),
        ),
        ProfilePolicyCommands::Cleanup {
            mutation,
            repository_key,
            workspace_key,
        } => run_workspace_policy_maintenance_mutation(
            mutation,
            &repository_key,
            &workspace_key,
            |controller, target| controller.plan_cleanup(target),
        ),
        ProfilePolicyCommands::Restore {
            mutation,
            backup_id,
        } => run_policy_maintenance_mutation(mutation, |controller| {
            controller.plan_restore(backup_id)
        }),
    }
}

fn policy_maintenance_status(
    options: ProfileRootOptions,
    repository_key: Option<&str>,
    workspace_key: Option<&str>,
    candidate_current: bool,
) -> ExitCode {
    let (config, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let target = match (repository_key, workspace_key) {
        (Some(repository_key), Some(workspace_key)) => {
            match PolicyTarget::workspace(repository_key, workspace_key) {
                Ok(target) => target,
                Err(error) => {
                    return command_error_exit(options.json, "failed", &error.to_string());
                }
            }
        }
        (None, None) => {
            let identity = match config.workspace_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    return command_error_exit(options.json, "failed", &error.to_string());
                }
            };
            match PolicyTarget::workspace(identity.repository_key, identity.workspace_key) {
                Ok(target) => target,
                Err(error) => {
                    return command_error_exit(options.json, "failed", &error.to_string());
                }
            }
        }
        _ => {
            return command_error_exit(
                options.json,
                "failed",
                "repository-key and workspace-key must be supplied together",
            );
        }
    };
    let controller = match policy_maintenance_controller(&options, &config) {
        Ok(controller) => controller,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let candidate = candidate_current.then_some(config.project_root.as_path());
    let status = match controller.status(&target, candidate) {
        Ok(status) => status,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": if status.is_some() { "managed" } else { "unmanaged" },
                "target": target,
                "maintenance": status,
                "humanAction": if status.is_none() {
                    Some(json!({
                        "code": "review-migration",
                        "guidance": "Run `unpin profile policy migrate` to review the fixed workspace source."
                    }))
                } else {
                    None
                },
            }))
            .expect("policy maintenance status JSON")
        );
    } else if let Some(status) = status {
        println!(
            "workspace policy {} classification={:?} lifecycle={:?} actions={}",
            status.record_id,
            status.classification,
            status.lifecycle,
            if status.allowed_actions.is_empty() {
                "none".to_string()
            } else {
                status.allowed_actions.join(",")
            }
        );
    } else {
        println!("workspace policy is unmanaged; review `unpin profile policy migrate`");
    }
    ExitCode::SUCCESS
}

fn run_workspace_policy_maintenance_mutation(
    mutation: PolicyMaintenanceMutationOptions,
    repository_key: &str,
    workspace_key: &str,
    planner: impl FnOnce(
        &PolicyMaintenanceController,
        PolicyTarget,
    )
        -> Result<PolicyMaintenancePlan, unpin_core::profiles::PolicyMaintenanceError>,
) -> ExitCode {
    let target = match PolicyTarget::workspace(repository_key, workspace_key) {
        Ok(target) => target,
        Err(error) => {
            return command_error_exit(mutation.options.json, "failed", &error.to_string());
        }
    };
    run_policy_maintenance_mutation(mutation, |controller| planner(controller, target))
}

fn run_policy_maintenance_mutation(
    mutation: PolicyMaintenanceMutationOptions,
    planner: impl FnOnce(
        &PolicyMaintenanceController,
    )
        -> Result<PolicyMaintenancePlan, unpin_core::profiles::PolicyMaintenanceError>,
) -> ExitCode {
    let (config, _) = match context(&mutation.options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(mutation.options.json, "failed", &error),
    };
    let controller = match policy_maintenance_controller(&mutation.options, &config) {
        Ok(controller) => controller,
        Err(error) => return command_error_exit(mutation.options.json, "blocked", &error),
    };
    let plan = match planner(&controller) {
        Ok(plan) => plan,
        Err(error) => {
            return command_error_exit(mutation.options.json, "blocked", &error.to_string());
        }
    };
    if !mutation.apply {
        if mutation.options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "planned",
                    "plan": plan,
                    "humanAction": {
                        "code": "confirm-and-apply",
                        "guidance": "Re-run with --apply --confirm and this plan fingerprint."
                    }
                }))
                .expect("policy maintenance plan JSON")
            );
        } else {
            println!(
                "policy maintenance planned operation={} fingerprint={}",
                plan.operation_id, plan.plan_fingerprint
            );
        }
        return ExitCode::SUCCESS;
    }
    if !mutation.confirm {
        return command_error_exit(mutation.options.json, "blocked", "confirmation-required");
    }
    if mutation.plan_fingerprint.as_deref() != Some(plan.plan_fingerprint.as_str()) {
        return command_error_exit(
            mutation.options.json,
            "blocked",
            "plan-fingerprint-mismatch",
        );
    }
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        mutation.options.roots.fixture_root.is_some(),
        [
            config.app_state_root.as_path(),
            config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(mutation.options.json, "blocked", &error);
    }
    let approval = policy_maintenance_approval(&plan.plan_fingerprint);
    let owner = OwnerGeneration::new(format!("unpin-cli-{}", plan.operation_id), 1)
        .expect("derived policy maintenance owner is valid");
    let outcome = match controller.apply(&plan, &approval, owner) {
        Ok(outcome) => outcome,
        Err(error) => {
            return command_error_exit(mutation.options.json, "blocked", &error.to_string());
        }
    };
    if mutation.options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "applied",
                "planFingerprint": plan.plan_fingerprint,
                "outcome": outcome,
            }))
            .expect("policy maintenance outcome JSON")
        );
    } else {
        println!(
            "policy maintenance applied operation={} backup={}",
            outcome.operation_id, outcome.backup_id
        );
    }
    ExitCode::SUCCESS
}

fn policy_maintenance_controller(
    options: &ProfileRootOptions,
    config: &unpin_core::config::UnpinConfig,
) -> Result<PolicyMaintenanceController, String> {
    let fixture_mode = options.roots.fixture_root.is_some();
    let key =
        match credentials::resolve_backup_authentication_key(fixture_mode, &config.app_state_root)?
        {
            Some(key) => key,
            None => {
                return Err(
                    "backup authentication key missing; run `unpin auth backup init`".to_string(),
                );
            }
        };
    Ok(PolicyMaintenanceController::new(
        &config.app_state_root,
        &config.project_root,
        key,
    ))
}

fn policy_maintenance_approval(plan_fingerprint: &str) -> PolicyMaintenanceApproval {
    PolicyMaintenanceApproval {
        confirmed: true,
        plan_fingerprint: plan_fingerprint.to_string(),
        actor_id: "unpin-cli-policy-maintenance".to_string(),
        reviewed_at_unix: u64::try_from(unix_now()).unwrap_or_default(),
        decision_digest: plan_fingerprint.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn change_capability_lock(
    options: ProfileRootOptions,
    provider: &str,
    capability: &str,
    state: CapabilityLockStateArg,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
) -> ExitCode {
    let provider = match parse_provider_id(provider) {
        Some(provider) => provider,
        None => return command_error_exit(options.json, "failed", "unsupported provider"),
    };
    let capability_id = match CapabilityId::new(capability) {
        Ok(capability_id) => capability_id,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let (config, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let change = PolicyChange {
        capability_lock: Some(CapabilityLockChange {
            capability_id,
            state: match state {
                CapabilityLockStateArg::HardEnabled => Some(CapabilityLockState::HardEnabled),
                CapabilityLockStateArg::HardDisabled => Some(CapabilityLockState::HardDisabled),
                CapabilityLockStateArg::Clear => None,
            },
        }),
        ..PolicyChange::default()
    };
    let plan = match ProfilePolicyController::new(&config.app_state_root).plan(
        PolicyTarget::Global,
        Some(provider),
        change,
    ) {
        Ok(plan) => plan,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let approval_context =
        match ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key) {
            Ok(context) => context,
            Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
        };
    let expectation = match plan.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    if !apply {
        if options.json {
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
                vec![provider],
                json!({"plan": plan}),
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "planned",
                    "operation": operation,
                    "plan": plan,
                }))
                .expect("capability lock plan JSON")
            );
        } else {
            println!(
                "planned global {} capability lock activation=next-session-only fingerprint={}",
                provider.as_str(),
                plan.plan_fingerprint
            );
        }
        return ExitCode::SUCCESS;
    }
    if !confirm {
        return command_error_exit(options.json, "blocked", "confirmation-required");
    }
    if reviewed_fingerprint != Some(plan.plan_fingerprint.as_str()) {
        return command_error_exit(options.json, "blocked", "plan-fingerprint-mismatch");
    }
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        options.roots.fixture_root.is_some(),
        [
            config.app_state_root.as_path(),
            config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let session_authority_key = match credentials::resolve_session_authority_key(
        options.roots.fixture_root.is_some(),
        &config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                options.json,
                "blocked",
                "session authority key missing; run `unpin auth session init`",
            );
        }
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let authorization = match credentials::authorize_reviewed_control_decision(
        options.roots.fixture_root.is_some(),
        &config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        reviewed_fingerprint,
        "unpin-cli-capability-lock-approval",
        unix_now(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let maintenance = match policy_maintenance_controller(&options, &config) {
        Ok(controller) => controller,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let maintenance_approval = policy_maintenance_approval(&plan.plan_fingerprint);
    let protected = maintenance.protect_policy_change(
        &plan.target,
        &format!("capability-lock-{}", &plan.plan_fingerprint[..32]),
        &plan.plan_fingerprint,
        &maintenance_approval,
        OwnerGeneration::new(
            format!("unpin-cli-capability-lock-{}", &plan.plan_fingerprint[..16]),
            1,
        )
        .expect("derived capability-lock backup owner is valid"),
        || {
            ProfilePolicyController::with_session_authority_key(
                &config.app_state_root,
                session_authority_key,
            )
            .apply(
                &plan,
                authorization,
                &approval_context,
                "unpin-cli-capability-lock",
            )
        },
    );
    let protected = match protected {
        Ok(protected) => protected,
        Err(ProtectedPolicyChangeError::Apply(error)) => {
            return command_error_exit(
                options.json,
                policy_control_error_status(&error),
                &error.to_string(),
            );
        }
        Err(ProtectedPolicyChangeError::Maintenance(error)) => {
            return command_error_exit(options.json, "recovery-required", &error.to_string());
        }
    };
    let result = protected.result;
    if options.json {
        let operation = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            result.activation,
            if result.status == PolicyApplyStatus::NoOp {
                ControlOperationLifecycle::NoOp
            } else {
                ControlOperationLifecycle::Applied
            },
            None,
            false,
            vec![provider],
            json!({"result": result}),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "applied",
                "operation": operation,
                "result": result,
            }))
            .expect("capability lock apply JSON")
        );
    } else {
        println!(
            "global {} capability lock applied; activation=next-session-only",
            provider.as_str()
        );
    }
    ExitCode::SUCCESS
}

fn list_capability_locks(options: ProfileRootOptions, provider: Option<&str>) -> ExitCode {
    let provider = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => Some(provider),
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => None,
    };
    let (config, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let policies = match PolicyStore::new(&config.app_state_root).load_resolution_policies(
        &identity.repository_key,
        &identity.workspace_key,
        None,
    ) {
        Ok(policies) => policies,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let roots = match resolve_discovery_roots_with_config(&options.roots, &config) {
        Ok(roots) => roots.with_app_state_root(&config.app_state_root),
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let catalog = match discover_all(&roots)
        .map_err(|error| error.to_string())
        .and_then(|discovery| {
            Catalog::from_discovery(&discovery).map_err(|error| error.to_string())
        }) {
        Ok(catalog) => catalog,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let providers = provider.map_or_else(
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
            .expect("typed capability locks serialize deterministically");
            let (gateway, gateway_source) = resolve_effective_gateway(provider, &policies);
            let enforcement = capability_lock_enforcement(&snapshot, &catalog, gateway);
            json!({
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
                "enforcement": enforcement,
                "action": "unpin profile lock",
            })
        })
        .collect::<Vec<_>>();
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "locks": locks}))
                .expect("capability lock status JSON")
        );
    } else if locks.is_empty() {
        println!("No global capability locks.");
    } else {
        for lock in &locks {
            println!(
                "{} global locks={} digest={} activation=next-session-only",
                lock["provider"].as_str().unwrap_or("unknown"),
                lock["entries"].as_object().map_or(0, serde_json::Map::len),
                lock["digest"].as_str().unwrap_or("unknown")
            );
        }
    }
    ExitCode::SUCCESS
}

fn propose(options: ProfileRootOptions, prompt: &str, provider: Option<&str>) -> ExitCode {
    let provider = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => Some(provider),
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => None,
    };
    let (config, store) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let mut profiles = match store.list_global_definitions() {
        Ok(profiles) => profiles,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    match ProfileStore::list_workspace_definitions(&config.project_root) {
        Ok(mut workspace) => profiles.append(&mut workspace),
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    }
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let proposal = match propose_profile(
        prompt,
        &identity.repository_key,
        &identity.workspace_key,
        provider,
        profiles,
    ) {
        Ok(proposal) => proposal,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let status = if proposal.recommended.is_some() {
        "proposed"
    } else {
        "selection-required"
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": status,
                "proposal": proposal,
                "humanAction": {
                    "code": "confirm-session-profile",
                    "guidance": "Choose the proposed profile explicitly when launching a session. This proposal never changes persistent or active exposure.",
                },
            }))
            .expect("profile proposal JSON")
        );
    } else if let Some(recommended) = &proposal.recommended {
        println!(
            "proposed session profile {} ({:?}); confirmation required; fingerprint={}",
            recommended.profile_id, recommended.scope, proposal.proposal_fingerprint
        );
    } else {
        println!(
            "no unique session profile proposal; choose explicitly from {} candidates",
            proposal.candidates.len()
        );
    }
    ExitCode::SUCCESS
}

fn list(options: ProfileRootOptions) -> ExitCode {
    let (config, store) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let mut profiles = match store.list_global_definitions() {
        Ok(profiles) => profiles,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    match ProfileStore::list_workspace_definitions(&config.project_root) {
        Ok(mut workspace) => profiles.append(&mut workspace),
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    }
    profiles.sort_by(|left, right| {
        (left.definition.id.as_str(), left.scope).cmp(&(right.definition.id.as_str(), right.scope))
    });
    render_profiles(options.json, &profiles)
}

fn show(options: ProfileRootOptions, id: &str, scope: DefinitionScopeArg) -> ExitCode {
    let (config, store) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let profile = match load_definition(&store, &config.project_root, id, scope) {
        Ok(Some(profile)) => profile,
        Ok(None) => return command_error_exit(options.json, "failed", "profile not found"),
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "profile": profile}))
                .expect("profile JSON")
        );
    } else {
        println!(
            "{} ({:?})\n  name: {}\n  members: {}",
            profile.definition.id,
            profile.scope,
            profile.definition.display_name,
            profile.definition.members.len()
                + profile
                    .definition
                    .provider_members
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
        );
    }
    ExitCode::SUCCESS
}

fn validate(
    options: ProfileRootOptions,
    id: Option<&str>,
    file: Option<&std::path::Path>,
    scope: DefinitionScopeArg,
) -> ExitCode {
    if id.is_none() == file.is_none() {
        return command_error_exit(
            options.json,
            "failed",
            "provide exactly one of --id or --file",
        );
    }
    let (config, store) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let (definition, source_scope) = if let Some(id) = id {
        match load_definition(&store, &config.project_root, id, scope) {
            Ok(Some(entry)) => (entry.definition, entry.scope),
            Ok(None) => return command_error_exit(options.json, "failed", "profile not found"),
            Err(error) => return command_error_exit(options.json, "failed", &error),
        }
    } else {
        let file = file.expect("file is present after validation");
        if file
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".env"))
        {
            return command_error_exit(options.json, "failed", ".env profile input is forbidden");
        }
        let raw = match std::fs::read_to_string(file) {
            Ok(raw) => raw,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        };
        let definition = match ProfileDefinition::from_json(&raw) {
            Ok(definition) => definition,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        };
        let source_scope = match scope {
            DefinitionScopeArg::Global => ProfileSourceScope::Global,
            DefinitionScopeArg::Auto | DefinitionScopeArg::Workspace => {
                ProfileSourceScope::Workspace
            }
        };
        (definition, source_scope)
    };
    let compiled = match compile_current(&options, &config, &definition, source_scope) {
        Ok(compiled) => compiled,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "valid", "profile": compiled}))
                .expect("compiled profile JSON")
        );
    } else {
        println!(
            "valid profile {} digest={} members={} local-review={}",
            compiled.profile_id,
            compiled.digest,
            compiled.members.len(),
            compiled.requires_local_review
        );
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn apply_profile(
    options: ProfileRootOptions,
    id: &str,
    provider: Option<&str>,
    reach: Option<ProviderReachArg>,
    scope: PolicyScopeArg,
    mode: ProfileModeArg,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
) -> ExitCode {
    let provider = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => Some(provider),
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => None,
    };
    let (config, store) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let entry = match load_definition(&store, &config.project_root, id, DefinitionScopeArg::Auto) {
        Ok(Some(entry)) => entry,
        Ok(None) => return command_error_exit(options.json, "failed", "profile not found"),
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let (compiled, discovery) =
        match compile_current_with_discovery(&options, &config, &entry.definition, entry.scope) {
            Ok(compiled) => compiled,
            Err(error) => return command_error_exit(options.json, "failed", &error),
        };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let target = match scope {
        PolicyScopeArg::Global => PolicyTarget::Global,
        PolicyScopeArg::Repository => match PolicyTarget::repository(&identity.repository_key) {
            Ok(target) => target,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        },
        PolicyScopeArg::Workspace => {
            match PolicyTarget::workspace(&identity.repository_key, &identity.workspace_key) {
                Ok(target) => target,
                Err(error) => {
                    return command_error_exit(options.json, "failed", &error.to_string());
                }
            }
        }
    };
    if let Some(reach) = reach {
        return apply_profile_with_reach(
            &options,
            &config,
            &store,
            &compiled,
            &discovery,
            &identity,
            target,
            provider,
            reach,
            mode,
            apply,
            confirm,
            reviewed_fingerprint,
        );
    }
    let controller = ProfilePolicyController::new(&config.app_state_root);
    let change = PolicyChange {
        profile: Some(ProfileSelection::Profile {
            reference: ProfileReference::from(&compiled),
        }),
        gateway: Some(match mode {
            ProfileModeArg::Native => GatewaySelection::Native,
            ProfileModeArg::Gateway => GatewaySelection::Gateway,
        }),
        capability_lock: None,
    };
    let plan = match controller.plan_with_revisions(
        target,
        provider,
        change,
        std::slice::from_ref(&compiled),
    ) {
        Ok(plan) => plan,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let approval_context =
        match ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key) {
            Ok(context) => context,
            Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
        };
    if !apply {
        return render_profile_plan(options.json, &compiled, &plan, &approval_context, provider);
    }
    if !confirm {
        return command_error_exit(options.json, "blocked", "confirmation-required");
    }
    if reviewed_fingerprint != Some(plan.plan_fingerprint.as_str()) {
        return command_error_exit(options.json, "blocked", "plan-fingerprint-mismatch");
    }
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        options.roots.fixture_root.is_some(),
        [
            config.app_state_root.as_path(),
            config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let session_authority_key = match credentials::resolve_session_authority_key(
        options.roots.fixture_root.is_some(),
        &config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                options.json,
                "blocked",
                "session authority key missing; run `unpin auth session init`",
            );
        }
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let expectation = match plan.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let authorization = match credentials::authorize_reviewed_control_decision(
        options.roots.fixture_root.is_some(),
        &config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        reviewed_fingerprint,
        "unpin-cli-profile-approval",
        unix_now(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    if let Err(error) = store.materialize_revision(
        &compiled,
        OwnerGeneration::new("unpin-cli-profile", 1).expect("static owner is valid"),
    ) {
        return command_error_exit(options.json, "blocked", &error.to_string());
    }
    let maintenance = match policy_maintenance_controller(&options, &config) {
        Ok(controller) => controller,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let maintenance_approval = policy_maintenance_approval(&plan.plan_fingerprint);
    let protected = maintenance.protect_policy_change(
        &plan.target,
        &format!("profile-apply-{}", &plan.plan_fingerprint[..32]),
        &plan.plan_fingerprint,
        &maintenance_approval,
        OwnerGeneration::new(
            format!("unpin-cli-profile-backup-{}", &plan.plan_fingerprint[..16]),
            1,
        )
        .expect("derived profile backup owner is valid"),
        || {
            ProfilePolicyController::with_session_authority_key(
                &config.app_state_root,
                session_authority_key,
            )
            .apply(&plan, authorization, &approval_context, "unpin-cli-profile")
        },
    );
    let protected = match protected {
        Ok(protected) => protected,
        Err(ProtectedPolicyChangeError::Apply(error)) => {
            return command_error_exit(
                options.json,
                policy_control_error_status(&error),
                &error.to_string(),
            );
        }
        Err(ProtectedPolicyChangeError::Maintenance(error)) => {
            return command_error_exit(options.json, "recovery-required", &error.to_string());
        }
    };
    let result = protected.result;
    if options.json {
        let operation = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            result.activation,
            if result.status == PolicyApplyStatus::NoOp {
                ControlOperationLifecycle::NoOp
            } else {
                ControlOperationLifecycle::Applied
            },
            None,
            false,
            provider.map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
            json!({"profile": compiled, "result": result}),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "applied",
                "operation": operation,
                "profile": compiled,
                "result": result,
            }))
            .expect("profile apply JSON")
        );
    } else {
        println!(
            "profile {} selected; activation=next-session-only mode={:?}",
            compiled.profile_id, mode
        );
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn apply_profile_with_reach(
    options: &ProfileRootOptions,
    config: &unpin_core::config::UnpinConfig,
    store: &ProfileStore,
    compiled: &unpin_core::profiles::CompiledProfileRevision,
    discovery: &DiscoveryOutput,
    identity: &WorkspaceIdentity,
    target: PolicyTarget,
    provider: Option<ProviderId>,
    reach: ProviderReachArg,
    mode: ProfileModeArg,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
) -> ExitCode {
    let reach_input = match reach.input(provider) {
        Ok(reach) => reach,
        Err(error) => return crate::command_error_exit_code(options.json, "blocked", &error, 3),
    };
    let mut reach_request = ProviderReachRequest::new(
        ConnectionBoundary::All,
        reach_input,
        DerivedTargetKind::Profile,
    );
    if let Some(provider) = provider {
        reach_request = reach_request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    let provider_reach = match reach_request
        .validate_before_discovery()
        .and_then(|preflight| preflight.reconcile_exact_target(None))
    {
        Ok(resolution) => resolution.reach,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error.to_string(), 3);
        }
    };
    let controller = ProfileProviderOperationController::new(&config.app_state_root);
    let plan = match controller.plan_with_gateway_and_discovery(
        &target,
        compiled,
        provider_reach,
        match mode {
            ProfileModeArg::Native => GatewaySelection::Native,
            ProfileModeArg::Gateway => GatewaySelection::Gateway,
        },
        discovery,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return crate::command_error_exit_code(
                options.json,
                profile_provider_error_status(&error),
                &error.to_string(),
                profile_provider_error_exit(&error),
            );
        }
    };
    if !apply {
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "statusVersion": 2,
                    "status": if plan.no_op { "no-op" } else { "planned" },
                    "operationId": plan.operation_id,
                    "planFingerprint": plan.plan_fingerprint,
                    "providerReach": plan.provider_reach,
                    "providerCoverage": plan.coverage,
                    "activation": plan.activation,
                    "targets": plan.targets,
                    "humanAction": {
                        "code": "confirm-and-apply",
                        "guidance": "Review provider reach, provenance, coverage, target classifications, activation, and fingerprint before apply."
                    },
                    "plan": plan,
                }))
                .expect("reach-aware profile plan JSON")
            );
        } else {
            println!(
                "profile {} reach={:?} targets={} activation={:?} fingerprint={}",
                compiled.profile_id,
                plan.provider_reach,
                plan.targets.len(),
                plan.activation,
                plan.plan_fingerprint
            );
            for target in &plan.targets {
                println!(
                    "  {} classification={} presence={:?} inherited-before={:?} effect={:?} future-activation={:?} activation={:?}",
                    target.provider.as_str(),
                    target.classification.as_str(),
                    target.local_presence,
                    target.generic_profile_inherited_before,
                    target.generic_policy_effect,
                    target.future_activation,
                    target.activation
                );
            }
        }
        return ExitCode::SUCCESS;
    }
    if !confirm {
        return crate::command_error_exit_code(options.json, "blocked", "confirmation-required", 3);
    }
    if reviewed_fingerprint != Some(plan.plan_fingerprint.as_str()) {
        return crate::command_error_exit_code(
            options.json,
            "blocked",
            "plan-fingerprint-mismatch",
            3,
        );
    }
    let fixture_mode = options.roots.fixture_root.is_some();
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        fixture_mode,
        [
            config.app_state_root.as_path(),
            config.project_root.as_path(),
        ],
    ) {
        return crate::command_error_exit_code(options.json, "blocked", &error, 3);
    }
    let session_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return crate::command_error_exit_code(
                    options.json,
                    "blocked",
                    "session authority key missing; run `unpin auth session init`",
                    3,
                );
            }
            Err(error) => {
                return crate::command_error_exit_code(options.json, "blocked", &error, 3);
            }
        };
    let approval_context =
        match ControlApprovalContext::new(&identity.repository_key, &identity.workspace_key) {
            Ok(context) => context,
            Err(error) => {
                return crate::command_error_exit_code(
                    options.json,
                    "blocked",
                    &error.to_string(),
                    3,
                );
            }
        };
    let session_id = plan.operation_id.clone();
    let expectation = match plan.approval_expectation(&approval_context, &session_id) {
        Ok(expectation) => expectation,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error.to_string(), 3);
        }
    };
    let roots = match ReachAwareRootBinding::from_provider_paths(
        &config.app_state_root,
        Vec::new(),
        "unpin-cli-profile-provider",
    ) {
        Ok(roots) => roots,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error.to_string(), 3);
        }
    };
    // The CLI does not accept caller metadata as identity. The reviewed
    // operation id and scope digest are signed with the locally resolved
    // session authority key, yielding an operation-specific trusted principal
    // without minting an ad-hoc lease.
    let principal = match sign_reviewed_profile_principal(&plan, &expectation, &session_key) {
        Ok(principal) => principal,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error, 3);
        }
    };
    let now_unix = unix_now();
    let durable = ProfileProviderReachAwareApplyContext {
        approval_context: approval_context.clone(),
        roots,
        principal,
        audience: PROFILE_PROVIDER_APPROVAL_AUDIENCE.to_string(),
        issued_at_unix: now_unix,
        expires_at_unix: now_unix + 3600,
        now_unix,
    };
    let authorization = match credentials::authorize_reviewed_control_decision(
        fixture_mode,
        &config.app_state_root,
        &expectation,
        &plan.plan_fingerprint,
        reviewed_fingerprint,
        "unpin-cli-profile-provider-approval",
        now_unix,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error, 3);
        }
    };
    if let Err(error) = store.materialize_revision(
        compiled,
        OwnerGeneration::new("unpin-cli-profile-provider", 1).expect("static owner is valid"),
    ) {
        return crate::command_error_exit_code(options.json, "blocked", &error.to_string(), 3);
    }
    let maintenance = match policy_maintenance_controller(options, config) {
        Ok(controller) => controller,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error, 3);
        }
    };
    let maintenance_approval = policy_maintenance_approval(&plan.plan_fingerprint);
    let protected = maintenance.protect_policy_change(
        &plan.target,
        &plan.operation_id,
        &plan.plan_fingerprint,
        &maintenance_approval,
        OwnerGeneration::new(
            format!("unpin-cli-profile-provider-backup-{}", plan.operation_id),
            1,
        )
        .expect("derived profile-provider backup owner is valid"),
        || {
            ProfileProviderOperationController::new(&config.app_state_root)
                .with_session_authority_key(session_key)
                .apply_with_reach_aware(&plan, authorization, durable, "unpin-cli-profile-provider")
        },
    );
    let protected = match protected {
        Ok(protected) => protected,
        Err(ProtectedPolicyChangeError::Apply(error)) => {
            return crate::command_error_exit_code(
                options.json,
                profile_provider_error_status(&error),
                &error.to_string(),
                profile_provider_error_exit(&error),
            );
        }
        Err(ProtectedPolicyChangeError::Maintenance(error)) => {
            return crate::command_error_exit_code(
                options.json,
                "recovery-required",
                &error.to_string(),
                4,
            );
        }
    };
    let result = protected.result;
    let status = match result.status {
        ProfileProviderOperationStatus::Applied => "applied",
        ProfileProviderOperationStatus::NoOp => "no-op",
        ProfileProviderOperationStatus::Blocked => "blocked",
        ProfileProviderOperationStatus::RecoveryRequired => "recovery-required",
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "statusVersion": 2,
                "status": status,
                "operationId": plan.operation_id,
                "planFingerprint": plan.plan_fingerprint,
                "providerReach": plan.provider_reach,
                "providerCoverage": plan.coverage,
                "activation": plan.activation,
                "result": result,
            }))
            .expect("reach-aware profile apply JSON")
        );
    } else {
        println!(
            "profile {} {status}; reach={:?} activation={:?}",
            compiled.profile_id, plan.provider_reach, plan.activation
        );
    }
    ExitCode::from(match result.status {
        ProfileProviderOperationStatus::Applied | ProfileProviderOperationStatus::NoOp => 0,
        ProfileProviderOperationStatus::Blocked => 3,
        ProfileProviderOperationStatus::RecoveryRequired => 4,
    })
}

fn sign_reviewed_profile_principal(
    plan: &unpin_core::profiles::ProfileProviderOperationPlan,
    expectation: &unpin_core::approval::ApprovalExpectation,
    session_key: &unpin_core::sessions::SessionAuthorityKey,
) -> Result<ReachAwarePrincipal, String> {
    // The operation id and scope digest come from the reviewed plan and its
    // approval expectation; no command-line caller metadata is interpreted as
    // identity. The local credential signature is the trusted boundary.
    ReachAwarePrincipal::sign(
        plan.operation_id.clone(),
        profile_reach_scope_digest(expectation, &plan.operation_id),
        ConnectionBoundary::All,
        session_key,
    )
    .map_err(|error| error.to_string())
}

fn profile_provider_error_status(error: &ProfileProviderOperationError) -> &'static str {
    if matches!(
        error,
        ProfileProviderOperationError::RecoveryRequired { .. }
    ) {
        "recovery-required"
    } else {
        "blocked"
    }
}

fn profile_provider_error_exit(error: &ProfileProviderOperationError) -> u8 {
    if matches!(
        error,
        ProfileProviderOperationError::RecoveryRequired { .. }
    ) {
        4
    } else {
        3
    }
}

fn context(
    options: &ProfileRootOptions,
) -> Result<(unpin_core::config::UnpinConfig, ProfileStore), String> {
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let store = ProfileStore::new(&config.app_state_root);
    Ok((config, store))
}

fn load_definition(
    store: &ProfileStore,
    workspace_root: &std::path::Path,
    id: &str,
    scope: DefinitionScopeArg,
) -> Result<Option<ProfileDefinitionEntry>, String> {
    if matches!(
        scope,
        DefinitionScopeArg::Auto | DefinitionScopeArg::Workspace
    ) && let Some(profile) = ProfileStore::load_workspace_definition(workspace_root, id)
        .map_err(|error| error.to_string())?
    {
        return Ok(Some(profile));
    }
    if matches!(scope, DefinitionScopeArg::Auto | DefinitionScopeArg::Global) {
        return store
            .load_global_definition(id)
            .map(|profile| {
                profile.map(|snapshot| ProfileDefinitionEntry {
                    scope: ProfileSourceScope::Global,
                    definition: snapshot.value,
                    revision: Some(snapshot.revision),
                })
            })
            .map_err(|error| error.to_string());
    }
    Ok(None)
}

fn compile_current(
    options: &ProfileRootOptions,
    config: &unpin_core::config::UnpinConfig,
    definition: &ProfileDefinition,
    source_scope: ProfileSourceScope,
) -> Result<unpin_core::profiles::CompiledProfileRevision, String> {
    compile_current_with_discovery(options, config, definition, source_scope)
        .map(|(compiled, _)| compiled)
}

fn compile_current_with_discovery(
    options: &ProfileRootOptions,
    config: &unpin_core::config::UnpinConfig,
    definition: &ProfileDefinition,
    source_scope: ProfileSourceScope,
) -> Result<
    (
        unpin_core::profiles::CompiledProfileRevision,
        DiscoveryOutput,
    ),
    String,
> {
    let roots = resolve_discovery_roots_with_config(&options.roots, config)?
        .with_app_state_root(&config.app_state_root);
    let discovery = discover_all(&roots).map_err(|error| error.to_string())?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    let compiled =
        compile_profile(definition, &catalog, source_scope).map_err(|error| error.to_string())?;
    Ok((compiled, discovery))
}

fn render_profiles(json_output: bool, profiles: &[ProfileDefinitionEntry]) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "profiles": profiles}))
                .expect("profile inventory JSON")
        );
    } else if profiles.is_empty() {
        println!("No profiles.");
    } else {
        for profile in profiles {
            println!(
                "{} {:?} {}",
                profile.definition.id, profile.scope, profile.definition.display_name
            );
        }
    }
    ExitCode::SUCCESS
}

fn render_profile_plan(
    json_output: bool,
    compiled: &unpin_core::profiles::CompiledProfileRevision,
    plan: &unpin_core::profiles::PolicyChangePlan,
    context: &ControlApprovalContext,
    provider: Option<ProviderId>,
) -> ExitCode {
    if json_output {
        let expectation = plan
            .approval_expectation(context)
            .expect("validated profile plan has approval expectation");
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
            provider.map_or_else(|| ProviderId::ALL.to_vec(), |provider| vec![provider]),
            json!({"profile": compiled, "plan": plan}),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "planned",
                "operation": operation,
                "profile": compiled,
                "plan": plan,
            }))
            .expect("profile plan JSON")
        );
    } else {
        println!(
            "planned profile {} activation=next-session-only fingerprint={}",
            compiled.profile_id, plan.plan_fingerprint
        );
    }
    ExitCode::SUCCESS
}

fn policy_control_error_status(error: &PolicyControlError) -> &'static str {
    if matches!(
        error,
        PolicyControlError::Durable(DurableControlError::RecoveryRequired(_))
    ) {
        "recovery-required"
    } else {
        "blocked"
    }
}

#[cfg(test)]
mod recovery_status_tests {
    use super::*;

    #[test]
    fn profile_durable_recovery_has_distinct_machine_status() {
        let error = PolicyControlError::Durable(DurableControlError::RecoveryRequired(
            "profile-operation".to_string(),
        ));

        assert_eq!(policy_control_error_status(&error), "recovery-required");
    }
}

#[cfg(test)]
mod profile_principal_tests {
    use std::collections::BTreeSet;

    use super::*;
    use unpin_core::{
        discovery::DiscoveryOutput,
        profiles::{
            PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileProviderOperationController,
            ProfileSourceScope,
        },
        provider_reach::ProviderReach,
        providers::ProviderId,
        sessions::SessionAuthorityKey,
    };

    #[test]
    fn reviewed_profile_principal_rejects_caller_metadata_tampering() {
        let temp = tempfile::TempDir::new().expect("principal test root");
        let state_root = std::fs::canonicalize(temp.path()).expect("canonical principal root");
        let catalog = Catalog::from_discovery(&DiscoveryOutput::default()).expect("empty catalog");
        let definition = ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: "principal-review".to_string(),
            display_name: "Principal review".to_string(),
            description: None,
            members: Vec::new(),
            provider_members: std::collections::BTreeMap::new(),
            supported_providers: BTreeSet::from([ProviderId::Codex]),
        };
        let compiled =
            compile_profile(&definition, &catalog, ProfileSourceScope::Global).expect("profile");
        let controller = ProfileProviderOperationController::new(&state_root);
        let plan = controller
            .plan(&PolicyTarget::Global, &compiled, ProviderReach::all())
            .expect("provider plan");
        let context = ControlApprovalContext::new("principal-repo", "principal-workspace")
            .expect("approval context");
        let expectation = plan
            .approval_expectation(&context, &plan.operation_id)
            .expect("expectation");
        let key = SessionAuthorityKey::new([0x7a; 32]);
        let principal =
            sign_reviewed_profile_principal(&plan, &expectation, &key).expect("signed principal");
        principal.verify(&key).expect("principal verifies");

        let mut tampered = principal;
        tampered.connection_scope_id = "caller-supplied-scope".to_string();
        assert!(
            tampered.verify(&key).is_err(),
            "caller metadata must not replace the signed scope"
        );
    }
}
