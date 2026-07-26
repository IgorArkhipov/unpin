use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Subcommand};
use serde_json::json;
use unpin_core::{
    bridges::{BridgeInstaller, hook_bridge_descriptor},
    discovery::{DiscoveryKind, discover_all},
    hooks::HookTrustStore,
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
};

use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, hook_support::require_profile_membership,
    parse_provider_id, resolve_config, resolve_discovery_roots_with_config, unix_now,
};

const APPROVAL_ISSUER: &str = "unpin-cli-human";
const APPROVAL_AUDIENCE: &str = "unpin-core-hook-trust";

#[derive(Debug, Subcommand)]
pub(crate) enum HookCommands {
    /// List individual discovered handlers with optional stored trust receipt state.
    List {
        #[command(flatten)]
        options: HookRootOptions,
        /// Profile digest used to locate matching stored trust receipts.
        #[arg(long)]
        profile_digest: Option<String>,
    },
    /// Show honest built-in and gateway hook coverage for providers.
    Coverage {
        #[command(flatten)]
        options: HookRootOptions,
        /// Provider filter.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Review one executable/network hook for one compiled profile.
    Trust {
        #[command(flatten)]
        options: HookRootOptions,
        /// Provider owning handler.
        #[arg(long)]
        provider: String,
        /// Exact discovered hook handler id.
        #[arg(long)]
        id: String,
        /// Materialized compiled profile digest containing handler capability.
        #[arg(long)]
        profile_digest: String,
        /// Session authorization binding; defaults to future profile policy.
        #[arg(long, default_value = "profile-policy")]
        session_id: String,
        /// Apply signed trust receipt. Omit for dry-run.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
    },
}

#[derive(Debug, Clone, Args)]
pub(crate) struct HookRootOptions {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    /// Unpin-owned state root containing profile revisions and trust receipts.
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Render machine-readable JSON.
    #[arg(long)]
    json: bool,
}

pub(crate) fn run(command: HookCommands) -> ExitCode {
    match command {
        HookCommands::List {
            options,
            profile_digest,
        } => list(options, profile_digest.as_deref()),
        HookCommands::Coverage { options, provider } => coverage(options, provider.as_deref()),
        HookCommands::Trust {
            options,
            provider,
            id,
            profile_digest,
            session_id,
            apply,
            confirm,
            plan_fingerprint,
        } => trust(
            options,
            &provider,
            &id,
            &profile_digest,
            &session_id,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
        ),
    }
}

fn list(options: HookRootOptions, profile_digest: Option<&str>) -> ExitCode {
    let context = match hook_context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let trust = HookTrustStore::new(&context.config.app_state_root);
    let hooks = context
        .discovery
        .items
        .into_iter()
        .filter(|item| item.kind == DiscoveryKind::Hook)
        .map(|item| {
            let stored_decision = profile_digest
                .and_then(|digest| {
                    trust
                        .load_for(item.provider, &item.id, item.hook.as_ref()?, digest)
                        .ok()
                        .flatten()
                })
                .is_some_and(|record| {
                    item.hook.as_ref().is_some_and(|metadata| {
                        record.handler_id == item.id
                            && record.handler_fingerprint == metadata.fingerprint
                            && record.invocation_fingerprint == metadata.invocation_fingerprint
                    })
                });
            json!({"item": item, "storedTrustDecision": stored_decision})
        })
        .collect::<Vec<_>>();
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "hooks": hooks}))
                .expect("hook inventory JSON")
        );
    } else if hooks.is_empty() {
        println!("No hooks.");
    } else {
        for hook in hooks {
            println!(
                "{} stored-trust={}",
                hook["item"]["id"].as_str().unwrap_or("unknown"),
                hook["storedTrustDecision"]
            );
        }
    }
    ExitCode::SUCCESS
}

fn coverage(options: HookRootOptions, provider: Option<&str>) -> ExitCode {
    let providers = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => vec![provider],
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => ProviderId::ALL.to_vec(),
    };
    let config = match resolve_config(&options.roots, options.app_state_root.clone()) {
        Ok(config) => config,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let installer = BridgeInstaller::new(&config.app_state_root);
    let coverage = match providers
        .into_iter()
        .map(|provider| -> Result<_, String> {
            let descriptor = hook_bridge_descriptor(provider);
            let installations = if descriptor.has_managed_asset() {
                installer
                    .list_statuses(provider)
                    .map_err(|error| error.to_string())?
            } else {
                Vec::new()
            };
            Ok(json!({
                "provider": provider,
                "adapter": descriptor.adapter,
                "builtInTools": descriptor.built_in_tools,
                "gatewayMcpTools": descriptor.gateway_mcp_tools,
                "nativeEvents": descriptor.native_events,
                "managedAsset": descriptor.managed_asset_file.is_some(),
                "verificationScope": "fixture-contract",
                "nativeHostActivation": "pending-live-verification",
                "managedBridgeInstallations": installations,
            }))
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(coverage) => coverage,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "coverage": coverage}))
                .expect("hook coverage JSON")
        );
    } else {
        for row in coverage {
            println!(
                "{} built-in={} gateway-mcp={}",
                row["provider"], row["builtInTools"], row["gatewayMcpTools"]
            );
        }
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn trust(
    options: HookRootOptions,
    provider: &str,
    id: &str,
    profile_digest: &str,
    session_id: &str,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
) -> ExitCode {
    let provider = match parse_provider_id(provider) {
        Some(provider) => provider,
        None => return command_error_exit(options.json, "failed", "unsupported provider"),
    };
    let context = match hook_context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let item =
        match context.discovery.items.iter().find(|item| {
            item.provider == provider && item.kind == DiscoveryKind::Hook && item.id == id
        }) {
            Some(item) => item,
            None => return command_error_exit(options.json, "failed", "hook not found"),
        };
    let metadata = item
        .hook
        .as_ref()
        .expect("hook discovery includes metadata");
    if let Err(error) = require_profile_membership(
        &context.config.app_state_root,
        &context.discovery,
        item,
        profile_digest,
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let identity = match context.config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let expectation = match metadata.trust_approval_expectation(
        provider,
        id,
        profile_digest,
        APPROVAL_ISSUER,
        APPROVAL_AUDIENCE,
        &identity.repository_key,
        &identity.workspace_key,
        session_id,
    ) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let fingerprint = expectation.effect_graph_digest.clone();
    if !apply {
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "planned",
                    "hook": item,
                    "expectation": expectation,
                    "planFingerprint": fingerprint,
                    "activation": "next-session-only",
                    "humanApprovalRequired": true,
                }))
                .expect("hook trust plan JSON")
            );
        } else {
            println!(
                "planned hook trust {} fingerprint={} activation=next-session-only",
                id, fingerprint
            );
        }
        return ExitCode::SUCCESS;
    }
    if !confirm {
        return command_error_exit(options.json, "blocked", "confirmation-required");
    }
    if reviewed_fingerprint != Some(fingerprint.as_str()) {
        return command_error_exit(options.json, "blocked", "plan-fingerprint-mismatch");
    }
    let fixture_mode = options.roots.fixture_root.is_some();
    if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
        fixture_mode,
        [
            context.config.app_state_root.as_path(),
            context.config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let now_unix = unix_now();
    let approval = match credentials::issue_human_approval(
        fixture_mode,
        &context.config.app_state_root,
        &expectation,
        &fingerprint,
        reviewed_fingerprint,
        now_unix,
    ) {
        Ok(approval) => approval,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let status = match HookTrustStore::new(&context.config.app_state_root).record(
        provider,
        id,
        metadata,
        profile_digest,
        approval.receipt(),
        approval.verifier(),
        now_unix,
        OwnerGeneration::new("unpin-cli-hook-trust", 1).expect("static owner is valid"),
        APPROVAL_ISSUER,
        APPROVAL_AUDIENCE,
        &identity.repository_key,
        &identity.workspace_key,
        session_id,
    ) {
        Ok(status) => status,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "trusted",
                "trust": status,
                "activation": "next-session-only",
            }))
            .expect("hook trust JSON")
        );
    } else {
        println!("hook trusted for profile; activation=next-session-only");
    }
    ExitCode::SUCCESS
}

struct HookContext {
    config: unpin_core::config::UnpinConfig,
    discovery: unpin_core::discovery::DiscoveryOutput,
}

fn hook_context(options: &HookRootOptions) -> Result<HookContext, String> {
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let roots = resolve_discovery_roots_with_config(&options.roots, &config)?
        .with_app_state_root(&config.app_state_root);
    let discovery = discover_all(&roots).map_err(|error| error.to_string())?;
    Ok(HookContext { config, discovery })
}
