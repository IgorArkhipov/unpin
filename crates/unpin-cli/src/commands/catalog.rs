use std::{path::PathBuf, process::ExitCode, sync::Arc};

use clap::{Args, Subcommand};
use serde_json::json;
use unpin_core::{
    catalog::{Catalog, CatalogRecord, adoption::plan_discovered_adoption},
    discovery::{DiscoveryItem, discover_all},
    sessions::SessionManager,
    state::atomic_json::OwnerGeneration,
    transitions::{
        CoordinatorError, EffectActivation, TransitionContext, TransitionCoordinator,
        TransitionOutcomeStatus,
    },
};

use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, unix_now,
};

const APPROVAL_ISSUER: &str = "unpin-cli-human";
const APPROVAL_AUDIENCE: &str = "unpin-core-transition";

#[derive(Debug, Subcommand)]
pub(crate) enum CatalogCommands {
    /// List normalized capabilities and provider fan-out.
    List(CatalogRootOptions),
    /// Show one normalized catalog capability.
    Show {
        #[command(flatten)]
        options: CatalogRootOptions,
        /// Stable catalog capability id.
        id: String,
    },
    /// Adopt one provider-owned skill or agent into Unpin catalog storage.
    Adopt {
        #[command(flatten)]
        options: CatalogRootOptions,
        /// Provider owning selected native view.
        #[arg(long)]
        provider: String,
        /// Exact discovered provider item id.
        #[arg(long)]
        id: String,
        /// Provider root allowed to contain selected source.
        #[arg(long)]
        provider_root: PathBuf,
        /// Apply reviewed adoption plan. Omit for dry-run.
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
pub(crate) struct CatalogRootOptions {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    /// Unpin-owned state root containing adopted catalog content.
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Render machine-readable JSON.
    #[arg(long)]
    json: bool,
}

pub(crate) fn run(command: CatalogCommands) -> ExitCode {
    match command {
        CatalogCommands::List(options) => list(options),
        CatalogCommands::Show { options, id } => show(options, &id),
        CatalogCommands::Adopt {
            options,
            provider,
            id,
            provider_root,
            apply,
            confirm,
            plan_fingerprint,
        } => adopt(
            options,
            &provider,
            &id,
            provider_root,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
        ),
    }
}

fn list(options: CatalogRootOptions) -> ExitCode {
    let (_, _, catalog) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let records = catalog.records.values().collect::<Vec<_>>();
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "capabilities": records}))
                .expect("catalog JSON")
        );
    } else if records.is_empty() {
        println!("No capabilities.");
    } else {
        for record in records {
            println!(
                "{} {} providers={} active={}",
                record.id,
                record.kind.as_str(),
                record.provider_fan_out(),
                record.lifecycle.active
            );
        }
    }
    ExitCode::SUCCESS
}

fn show(options: CatalogRootOptions, id: &str) -> ExitCode {
    let (_, _, catalog) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let Some(record) = catalog
        .records
        .values()
        .find(|record| record.id.as_str() == id)
    else {
        return command_error_exit(options.json, "failed", "catalog capability not found");
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": "ok", "capability": record}))
                .expect("catalog record JSON")
        );
    } else {
        println!(
            "{} {} providers={} fingerprint={}",
            record.id,
            record.kind.as_str(),
            record.provider_fan_out(),
            record.fingerprint
        );
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn adopt(
    options: CatalogRootOptions,
    provider: &str,
    id: &str,
    provider_root: PathBuf,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
) -> ExitCode {
    let provider = match parse_provider_id(provider) {
        Some(provider) => provider,
        None => return command_error_exit(options.json, "failed", "unsupported provider"),
    };
    let (config, discovery, catalog) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let Some(item) = discovery
        .items
        .iter()
        .find(|item| item.provider == provider && item.id == id)
    else {
        return command_error_exit(options.json, "failed", "provider item not found");
    };
    let Some(record) = catalog.find_provider_view(provider, id) else {
        return command_error_exit(options.json, "failed", "catalog capability not found");
    };
    let identity = match config.workspace_identity() {
        Ok(identity) => identity,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let operation_id = format!(
        "adopt-{}-{}",
        provider.as_str(),
        record.fingerprint.chars().take(24).collect::<String>()
    );
    let planned = match plan_discovered_adoption(
        item,
        record,
        operation_id,
        provider_root.clone(),
        &config.app_state_root,
        TransitionContext {
            repository_key: identity.repository_key,
            workspace_key: identity.workspace_key,
            session_id: None,
            profile_digest: None,
        },
        EffectActivation::NextSessionOnly,
    ) {
        Ok(planned) => planned,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let fingerprint = &planned.transition.effect_graph_digest;
    if !apply {
        return render_plan(options.json, item, record, &planned.transition);
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
            config.app_state_root.as_path(),
            config.project_root.as_path(),
            provider_root.as_path(),
        ],
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let backup_key = match credentials::resolve_backup_authentication_key(
        fixture_mode,
        &config.app_state_root,
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                options.json,
                "blocked",
                "backup authentication key missing; run `unpin auth backup init`",
            );
        }
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let session_authority_key =
        match credentials::resolve_session_authority_key(fixture_mode, &config.app_state_root) {
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
    let now_unix = unix_now();
    let expectation = planned
        .transition
        .approval_expectation(APPROVAL_ISSUER, APPROVAL_AUDIENCE);
    let approval = match credentials::issue_human_approval(
        fixture_mode,
        &config.app_state_root,
        &expectation,
        fingerprint,
        reviewed_fingerprint,
        now_unix,
    ) {
        Ok(approval) => approval,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let coordinator = match TransitionCoordinator::new(
        &config.app_state_root,
        APPROVAL_ISSUER,
        APPROVAL_AUDIENCE,
    ) {
        Ok(coordinator) => coordinator.with_conflict_checker(Arc::new(
            SessionManager::with_authority_key(&config.app_state_root, session_authority_key),
        )),
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let result = match coordinator.execute(
        &planned.transition,
        Some(approval.receipt()),
        approval.verifier(),
        now_unix,
        OwnerGeneration::new("unpin-cli-adoption", 1).expect("static owner is valid"),
        &planned.backend(backup_key),
    ) {
        Ok(result) => result,
        Err(error) => {
            return command_error_exit(
                options.json,
                adoption_error_status(&error),
                &error.to_string(),
            );
        }
    };
    let (status, success) = adoption_outcome_contract(result.status);
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": status,
                "result": result,
                "activation": "next-session-only",
            }))
            .expect("adoption result JSON")
        );
    } else {
        println!(
            "catalog adoption {status}; outcome={:?} activation=next-session-only backup={}",
            result.status, result.backup_id,
        );
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn adoption_outcome_contract(status: TransitionOutcomeStatus) -> (&'static str, bool) {
    match status {
        TransitionOutcomeStatus::Committed => ("completed", true),
        TransitionOutcomeStatus::RolledBack => ("rolled-back", false),
        TransitionOutcomeStatus::NeedsRepair => ("recovery-required", false),
    }
}

fn adoption_error_status(error: &CoordinatorError) -> &'static str {
    if matches!(error, CoordinatorError::RecoveryRequired(_)) {
        "recovery-required"
    } else {
        "blocked"
    }
}

fn context(
    options: &CatalogRootOptions,
) -> Result<
    (
        unpin_core::config::UnpinConfig,
        unpin_core::discovery::DiscoveryOutput,
        Catalog,
    ),
    String,
> {
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let roots = resolve_discovery_roots_with_config(&options.roots, &config)?
        .with_app_state_root(&config.app_state_root);
    let discovery = discover_all(&roots).map_err(|error| error.to_string())?;
    let catalog = Catalog::from_discovery(&discovery).map_err(|error| error.to_string())?;
    Ok((config, discovery, catalog))
}

fn render_plan(
    json_output: bool,
    item: &DiscoveryItem,
    record: &CatalogRecord,
    transition: &unpin_core::transitions::TransitionPlan,
) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "planned",
                "item": item,
                "capability": record,
                "transition": transition,
                "planFingerprint": transition.effect_graph_digest,
                "activation": "next-session-only",
                "humanApprovalRequired": true,
            }))
            .expect("adoption plan JSON")
        );
    } else {
        println!(
            "planned adoption {} fingerprint={} activation=next-session-only",
            record.id, transition.effect_graph_digest
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_terminal_outcomes_have_honest_machine_status_and_exit_contract() {
        assert_eq!(
            adoption_outcome_contract(TransitionOutcomeStatus::Committed),
            ("completed", true)
        );
        assert_eq!(
            adoption_outcome_contract(TransitionOutcomeStatus::RolledBack),
            ("rolled-back", false)
        );
        assert_eq!(
            adoption_outcome_contract(TransitionOutcomeStatus::NeedsRepair),
            ("recovery-required", false)
        );
    }

    #[test]
    fn cached_post_state_divergence_is_recovery_required() {
        assert_eq!(
            adoption_error_status(&CoordinatorError::RecoveryRequired(
                "operation-id".to_string()
            )),
            "recovery-required"
        );
    }
}
