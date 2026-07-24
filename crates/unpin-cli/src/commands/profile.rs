use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    catalog::{CapabilityId, Catalog},
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        DurableControlError,
    },
    discovery::{DiscoveryRoots, discover_all},
    profiles::{
        CapabilityLockChange, CapabilityLockSnapshot, CapabilityLockState, GatewaySelection,
        PolicyApplyStatus, PolicyChange, PolicyControlError, PolicyStore, PolicyTarget,
        ProfileDefinition, ProfileDefinitionEntry, ProfilePolicyController, ProfileReference,
        ProfileSelection, ProfileSourceScope, ProfileStore, capability_lock_enforcement,
        compile_profile, propose_profile, resolve_effective_gateway,
    },
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
};

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
            scope,
            mode,
            apply,
            confirm,
            plan_fingerprint,
        } => apply_profile(
            options,
            &id,
            provider.as_deref(),
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
    let session_authority_key =
        match credentials::resolve_session_authority_key(options.roots.fixture_root.is_some()) {
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
    let result = match ProfilePolicyController::with_session_authority_key(
        &config.app_state_root,
        session_authority_key,
    )
    .apply(
        &plan,
        authorization,
        &approval_context,
        "unpin-cli-capability-lock",
    ) {
        Ok(result) => result,
        Err(error) => {
            return command_error_exit(
                options.json,
                policy_control_error_status(&error),
                &error.to_string(),
            );
        }
    };
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
    let compiled = match compile_current(&options, &config, &entry.definition, entry.scope) {
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
    let session_authority_key =
        match credentials::resolve_session_authority_key(options.roots.fixture_root.is_some()) {
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
    let result = match ProfilePolicyController::with_session_authority_key(
        &config.app_state_root,
        session_authority_key,
    )
    .apply(&plan, authorization, &approval_context, "unpin-cli-profile")
    {
        Ok(result) => result,
        Err(error) => {
            return command_error_exit(
                options.json,
                policy_control_error_status(&error),
                &error.to_string(),
            );
        }
    };
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
    let roots = resolve_discovery_roots_with_config(&options.roots, config)?
        .with_app_state_root(&config.app_state_root);
    compile_from_roots(&roots, definition, source_scope)
}

fn compile_from_roots(
    roots: &DiscoveryRoots,
    definition: &ProfileDefinition,
    source_scope: ProfileSourceScope,
) -> Result<unpin_core::profiles::CompiledProfileRevision, String> {
    let discovery = discover_all(roots).map_err(|error| error.to_string())?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    compile_profile(definition, &catalog, source_scope).map_err(|error| error.to_string())
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
