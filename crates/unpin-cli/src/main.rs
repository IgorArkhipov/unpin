use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{
    env, io,
    io::{Read, Write},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

mod commands;
mod credentials;
mod gateway_session;
mod group_store;
mod hook_support;
mod session_process;
mod tui;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use unpin_core::{
    approval::ControlApprovalContext,
    capabilities::{CAPABILITY_ROWS, validate_capability_matrix, validate_provider_fixtures},
    config::{LoadConfigOptions, UnpinConfig, UnpinConfigOverrides, load_config},
    control::build_persistent_control_metadata,
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        DurableControlError,
    },
    discovery::{DiscoveryItem, DiscoveryOutput, DiscoveryRoots, DiscoveryWarning, discover_all},
    groups::{
        GroupAccessContext, McpGroupSessionBinding, McpGroupSessionLeaseStore, current_unix_seconds,
    },
    mcp::{
        McpApprovedGroupApplyContext, McpAuthenticationReadiness, McpContext,
        McpCredentialReadiness, McpDiscoveryCache, McpProviderScope, handle_stdio_request_once,
        handle_stdio_requests,
    },
    mutation::{
        BackupAuthenticationKey, MutationOperation, MutationTarget, NativeToggleControlError,
        NativeToggleController, RestoreControlError, RestoreController, RestoreResult,
        RestoreStatus, ToggleResult, ToggleStatus,
    },
    providers::ProviderId,
    snapshots::{SnapshotWriteOptions, SnapshotWriteResult, write_control_snapshot},
};

#[derive(Debug, Parser)]
#[command(
    name = "unpin",
    version,
    about = "Inspect and safely manage local AI-agent configuration."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Args)]
struct DiscoveryRootArgs {
    /// Discover from a deterministic fixture root instead of live provider roots.
    #[arg(long)]
    fixture_root: Option<PathBuf>,
    /// Home root used to resolve global provider configuration.
    #[arg(long)]
    home_root: Option<PathBuf>,
    /// Project root used to resolve project-scoped provider state.
    #[arg(long)]
    project_root: Option<PathBuf>,
    /// Cursor app-support root used to resolve Cursor profiles and workspace state.
    #[arg(long)]
    cursor_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum McpProviderScopeArg {
    #[default]
    All,
    Claude,
    Codex,
    Cursor,
    Pi,
    #[value(name = "opencode")]
    OpenCode,
    Zed,
}

impl From<McpProviderScopeArg> for McpProviderScope {
    fn from(value: McpProviderScopeArg) -> Self {
        match value {
            McpProviderScopeArg::All => Self::All,
            McpProviderScopeArg::Claude => Self::Provider(ProviderId::Claude),
            McpProviderScopeArg::Codex => Self::Provider(ProviderId::Codex),
            McpProviderScopeArg::Cursor => Self::Provider(ProviderId::Cursor),
            McpProviderScopeArg::Pi => Self::Provider(ProviderId::Pi),
            McpProviderScopeArg::OpenCode => Self::Provider(ProviderId::OpenCode),
            McpProviderScopeArg::Zed => Self::Provider(ProviderId::Zed),
        }
    }
}

impl DiscoveryRootArgs {
    fn config_overrides(&self, app_state_root: Option<PathBuf>) -> UnpinConfigOverrides {
        UnpinConfigOverrides {
            app_state_root,
            cursor_root: self.cursor_root.clone(),
            project_root: self.project_root.clone(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Manage credentials used by Unpin safety features.
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Print the provider capability matrix.
    Providers,
    /// Validate fixtures and local provider inputs.
    Doctor {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
    },
    /// Persist the current discovery inventory as a project snapshot.
    Snapshot {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Write snapshot state under this Unpin-owned root.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List discovered provider items.
    List {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Filter to one provider id.
        #[arg(long)]
        provider: Option<String>,
        /// Filter to one item kind.
        #[arg(long)]
        kind: Option<String>,
        /// Filter to global, project, or all layers.
        #[arg(long)]
        layer: Option<String>,
        /// Unpin-owned state root used to include vaulted disabled items.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Plan or apply a toggle for one discovered item.
    Toggle {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Use this Unpin-owned state root for vault path planning.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Provider to select, such as claude, codex, or cursor.
        #[arg(long)]
        provider: Option<String>,
        /// Mutation reach: selected provider or all providers. This is distinct
        /// from discovery/list visibility filters.
        #[arg(
            long,
            alias = "provider-reach",
            value_enum,
            default_value_t = commands::ProviderReachArg::Selected
        )]
        reach: commands::ProviderReachArg,
        /// Kind to select, such as skill or mcp.
        #[arg(long)]
        kind: Option<String>,
        /// Scope layer to select, such as global or project.
        #[arg(long)]
        layer: Option<String>,
        /// Full discovered item id.
        #[arg(long)]
        id: Option<String>,
        /// Apply the mutation instead of rendering a dry-run plan.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run plan.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Plan and apply reach-aware bulk native toggles.
    #[command(alias = "bulk-toggle", alias = "toggle-bulk")]
    Bulk {
        #[command(subcommand)]
        command: commands::toggle::BulkCommands,
    },
    /// Restore one previously saved backup.
    Restore {
        /// Backup identifier to restore.
        backup_id: Option<String>,
        /// Home root used to resolve Unpin user config.
        #[arg(long)]
        home_root: Option<PathBuf>,
        /// Project root used to resolve project-scoped Unpin config.
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Cursor root config override retained for shared config parity.
        #[arg(long)]
        cursor_root: Option<PathBuf>,
        /// Unpin-owned state root containing backups and audit logs.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Use deterministic fixture credentials instead of the OS keychain.
        #[arg(long)]
        fixture_root: Option<PathBuf>,
        /// Apply reviewed restore plan. Omit for dry-run.
        #[arg(long)]
        apply: bool,
        /// Explicit human confirmation required with --apply.
        #[arg(long, requires = "apply")]
        confirm: bool,
        /// Fingerprint emitted by matching dry-run plan.
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Launch or inspect isolated Unpin sessions.
    Session {
        #[command(subcommand)]
        command: commands::session::SessionCommands,
    },
    /// Inspect and safely adopt normalized capability catalog entries.
    Catalog {
        #[command(subcommand)]
        command: commands::catalog::CatalogCommands,
    },
    /// List, validate, and select reusable capability profiles.
    Profile {
        #[command(subcommand)]
        command: commands::profile::ProfileCommands,
    },
    /// Manage reusable named groups of inventory items.
    Group {
        #[command(subcommand)]
        command: commands::group::GroupCommands,
    },
    /// Install, inspect, activate, disable, or detach optional gateway routing.
    Gateway {
        #[command(subcommand)]
        command: commands::gateway::GatewayCommands,
    },
    /// Inspect hook handlers, provider coverage, and profile-bound trust.
    Hook {
        #[command(subcommand)]
        command: commands::hook::HookCommands,
    },
    /// Run the Unpin local MCP server over stdio.
    Mcp {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned state root containing backups and audit logs.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Restrict every MCP tool to one provider, or use all providers.
        #[arg(long, value_enum, default_value_t)]
        provider: McpProviderScopeArg,
        /// Read one newline-delimited request, write one response, then exit.
        #[arg(long)]
        once: bool,
        /// Enable persistent-session inventory-group apply with external one-time approval.
        #[arg(long)]
        enable_approved_group_apply: bool,
    },
    /// Open the Unpin terminal UI.
    #[command(alias = "dashboard")]
    Tui {
        #[command(flatten)]
        roots: DiscoveryRootArgs,
        /// Unpin-owned state root used for dry-run plan previews and vaulted items.
        #[arg(long)]
        app_state_root: Option<PathBuf>,
        /// Render a plain-text TUI snapshot and exit.
        #[arg(long)]
        headless: bool,
    },
    #[command(hide = true)]
    SessionChildWrapper {
        #[arg(long)]
        control_file: PathBuf,
        #[arg(long, hide = true)]
        app_state_root: PathBuf,
        #[arg(long, hide = true)]
        fixture_mode: bool,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Proxy one provider-owned MCP stdio connection into session gateway.
    #[command(hide = true)]
    GatewaySessionProxy {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommands {
    /// Manage backup authentication key.
    Backup {
        #[command(subcommand)]
        command: BackupAuthCommands,
    },
    /// Manage human approval signing key, separate from backup authentication.
    Approval {
        #[command(subcommand)]
        command: ApprovalAuthCommands,
    },
    /// Manage session state and launch-control authentication key.
    Session {
        #[command(subcommand)]
        command: SessionAuthorityAuthCommands,
    },
    /// Manage optional Cursor dashboard marketplace credential.
    CursorDashboard {
        #[command(subcommand)]
        command: CursorDashboardAuthCommands,
    },
}

#[derive(Debug, Subcommand)]
enum BackupAuthCommands {
    /// Create backup authentication key in OS keychain when absent.
    Init {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Report backup authentication key availability and fingerprint.
    Status {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalAuthCommands {
    /// Create human approval key in OS keychain when absent.
    Init {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Report human approval key availability and fingerprint.
    Status {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SessionAuthorityAuthCommands {
    /// Create session authority key in OS keychain when absent.
    Init {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Report session authority key availability and fingerprint.
    Status {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CursorDashboardAuthCommands {
    /// Read cookie from stdin and store it in OS keychain.
    Store {
        /// Render machine-readable JSON without credential value.
        #[arg(long)]
        json: bool,
    },
    /// Report credential availability without reading its value into output.
    Status {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove credential from OS keychain.
    Remove {
        /// Render machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(exit_code) => return exit_code,
    };

    match cli.command {
        Some(Commands::Auth { command }) => run_auth_command(command),
        Some(Commands::Providers) => {
            println!("{}", render_providers());
            ExitCode::SUCCESS
        }
        Some(Commands::Doctor { roots }) => match run_doctor(&roots) {
            Ok(result) => {
                println!("{}", result.output);
                if result.success {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(error) => {
                println!("doctor failed: {error}");
                ExitCode::FAILURE
            }
        },
        Some(Commands::List {
            roots,
            provider,
            kind,
            layer,
            app_state_root,
            json,
        }) => {
            if let Err(error) = validate_layer_filter(layer.as_deref()) {
                return command_error_exit(json, "failed", error);
            }

            let mut roots = match resolve_discovery_roots(&roots) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Some(app_state_root) = app_state_root {
                roots = roots.with_app_state_root(app_state_root);
            }

            match discover_all(&roots) {
                Ok(result) => {
                    let filtered = filter_discovery(
                        result,
                        provider.as_deref(),
                        kind.as_deref(),
                        layer.as_deref(),
                    );
                    match render_list(&filtered, json) {
                        Ok(output) => {
                            println!("{output}");
                            if !json && !filtered.warnings.is_empty() {
                                eprintln!("{}", render_discovery_warnings(&filtered.warnings));
                            }
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(error) => {
                    eprintln!("discovery failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::Snapshot {
            roots,
            app_state_root,
            json,
        }) => {
            let config = match resolve_config(&roots, app_state_root.clone()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            match resolve_discovery_roots_with_config(&roots, &config) {
                Ok(roots) => match discover_all(&roots.with_app_state_root(&config.app_state_root))
                {
                    Ok(discovery) => {
                        let control = match build_persistent_control_metadata(
                            &discovery,
                            &config.app_state_root,
                            &config.project_root,
                        ) {
                            Ok(control) => control,
                            Err(error) => {
                                eprintln!("snapshot control metadata failed: {error}");
                                return ExitCode::FAILURE;
                            }
                        };
                        match write_control_snapshot(
                            SnapshotWriteOptions {
                                app_state_root: config.app_state_root,
                                project_root: config.project_root,
                                discovery,
                                captured_at: None,
                                id: None,
                                max_history: 20,
                            },
                            control,
                        ) {
                            Ok(result) => {
                                let has_warnings = !result.snapshot.warnings.is_empty();
                                match render_snapshot(&result, json) {
                                    Ok(output) => {
                                        println!("{output}");
                                        if has_warnings {
                                            ExitCode::FAILURE
                                        } else {
                                            ExitCode::SUCCESS
                                        }
                                    }
                                    Err(error) => {
                                        eprintln!("{error}");
                                        ExitCode::FAILURE
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("snapshot failed: {error}");
                                ExitCode::FAILURE
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("discovery failed: {error}");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::Toggle {
            roots,
            app_state_root,
            provider,
            reach,
            kind,
            layer,
            id,
            apply,
            confirm,
            plan_fingerprint,
            json,
        }) => {
            if let Some(reason) = missing_toggle_selector(
                provider.as_deref(),
                kind.as_deref(),
                layer.as_deref(),
                id.as_deref(),
            ) {
                return command_error_exit(json, "failed", reason);
            }

            let provider = provider.expect("provider present after selector validation");
            let kind = kind.expect("kind present after selector validation");
            let layer = layer.expect("layer present after selector validation");
            let id = id.expect("id present after selector validation");
            let fixture_mode = roots.fixture_root.is_some();

            match resolve_config(&roots, app_state_root.clone()) {
                Ok(config) => {
                    match resolve_discovery_roots_with_config(&roots, &config) {
                        Ok(roots) => {
                            match discover_all(&roots.with_app_state_root(&config.app_state_root)) {
                                Ok(discovery) => {
                                    match select_toggle_item(
                                        &discovery, &provider, &kind, &layer, &id,
                                    ) {
                                        Some(item) => {
                                            let identity = match config.workspace_identity() {
                                                Ok(identity) => identity,
                                                Err(error) => {
                                                    return command_error_exit(
                                                        json,
                                                        "failed",
                                                        &error.to_string(),
                                                    );
                                                }
                                            };
                                            let approval_context = match ControlApprovalContext::new(
                                                &identity.repository_key,
                                                &identity.workspace_key,
                                            ) {
                                                Ok(context) => context,
                                                Err(error) => {
                                                    return command_error_exit(
                                                        json,
                                                        "failed",
                                                        &error.to_string(),
                                                    );
                                                }
                                            };
                                            let toggle_state_root = if fixture_mode {
                                                match std::fs::canonicalize(&config.app_state_root)
                                                {
                                                    Ok(root) => root,
                                                    Err(error) => {
                                                        return command_error_exit(
                                                            json,
                                                            "failed",
                                                            &format!(
                                                                "fixture state root could not be resolved: {error}"
                                                            ),
                                                        );
                                                    }
                                                }
                                            } else {
                                                config.app_state_root.clone()
                                            };
                                            let controller = match credentials::resolve_session_authority_key(fixture_mode, &toggle_state_root) {
                                                Ok(Some(key)) => NativeToggleController::with_session_authority_key(&toggle_state_root, key),
                                                Ok(None) if apply => return command_error_exit(
                                                    json,
                                                    "blocked",
                                                    "session authority key missing; run `unpin auth session init`",
                                                ),
                                                Ok(None) => NativeToggleController::new(&toggle_state_root),
                                                Err(error) => return command_error_exit(json, "blocked", &error),
                                            };
                                            let reach_input = match reach {
                                                commands::ProviderReachArg::Selected => {
                                                    unpin_core::provider_reach::ProviderReachInput::Omitted
                                                }
                                                commands::ProviderReachArg::All => {
                                                    unpin_core::provider_reach::ProviderReachInput::All
                                                }
                                            };
                                            let plan = match controller.plan_with_reach(
                                                item.clone(),
                                                &approval_context,
                                                unpin_core::provider_reach::ConnectionBoundary::All,
                                                reach_input,
                                                Vec::new(),
                                            ) {
                                                Ok(plan) => plan,
                                                Err(error) => {
                                                    return command_error_exit(
                                                        json,
                                                        "blocked",
                                                        &error.to_string(),
                                                    );
                                                }
                                            };
                                            let expectation = match plan
                                                .approval_expectation(&approval_context)
                                            {
                                                Ok(expectation) => expectation,
                                                Err(error) => {
                                                    return command_error_exit(
                                                        json,
                                                        "blocked",
                                                        &error.to_string(),
                                                    );
                                                }
                                            };
                                            let result = if apply {
                                                if !confirm {
                                                    return command_error_exit(
                                                        json,
                                                        "blocked",
                                                        "confirmation-required",
                                                    );
                                                }
                                                if plan_fingerprint.as_deref()
                                                    != Some(plan.plan_fingerprint.as_str())
                                                {
                                                    return command_error_exit(
                                                        json,
                                                        "blocked",
                                                        "plan-fingerprint-mismatch",
                                                    );
                                                }
                                                let mut fixture_write_paths =
                                                    vec![toggle_state_root.as_path()];
                                                for path in [
                                                    item.source_path.as_str(),
                                                    item.state_path.as_str(),
                                                ] {
                                                    if !path.is_empty() {
                                                        fixture_write_paths.push(Path::new(path));
                                                    }
                                                }
                                                if let Err(error) =
                            unpin_core::fixture::require_fixture_write_sandbox(
                                                        fixture_mode,
                                                        fixture_write_paths,
                                                    )
                                                {
                                                    return command_error_exit(
                                                        json, "blocked", &error,
                                                    );
                                                }
                                                let backup_authentication_key = match credentials::resolve_backup_authentication_key(fixture_mode, &toggle_state_root) {
                                                Ok(Some(key)) => key,
                                                Ok(None) => return command_error_exit(json, "blocked", "backup authentication key missing; run `unpin auth backup init`"),
                                                Err(error) => return command_error_exit(json, "blocked", &error),
                                            };
                                                let authorization =
                                                    match credentials::authorize_reviewed_control_decision(
                                                        fixture_mode,
                                                        &toggle_state_root,
                                                        &expectation,
                                                        &plan.plan_fingerprint,
                                                        plan_fingerprint.as_deref(),
                                                        "unpin-cli-native-toggle-approval",
                                                        unix_now(),
                                                    ) {
                                                        Ok(authorization) => authorization,
                                                        Err(error) => {
                                                            return command_error_exit(
                                                                json, "blocked", &error,
                                                            );
                                                        }
                                                    };
                                                match controller.apply(
                                                    &plan,
                                                    authorization,
                                                    &approval_context,
                                                    backup_authentication_key,
                                                ) {
                                                    Ok(result) => result,
                                                    Err(error) => {
                                                        return command_error_exit_code(
                                                            json,
                                                            native_toggle_control_error_status(
                                                                &error,
                                                            ),
                                                            &error.to_string(),
                                                            lifecycle_exit_code(
                                                                native_toggle_control_error_status(
                                                                    &error,
                                                                ),
                                                            ),
                                                        );
                                                    }
                                                }
                                            } else {
                                                plan.preview.clone()
                                            };
                                            let status = result.status;
                                            let operation = ControlOperationEnvelope::from_expectation(
                                            &expectation,
                                            &plan.plan_fingerprint,
                                            plan.transition.effects[0].activation,
                                            match status {
                                                ToggleStatus::Applied => ControlOperationLifecycle::Applied,
                                                ToggleStatus::RecoveryRequired => ControlOperationLifecycle::RecoveryRequired,
                                                ToggleStatus::Blocked => ControlOperationLifecycle::Blocked,
                                                ToggleStatus::DryRun => ControlOperationLifecycle::Planned,
                                            },
                                            (status == ToggleStatus::DryRun).then(|| ControlHumanAction {
                                                code: "confirm-and-apply".to_string(),
                                                guidance: "Re-run with --apply --confirm and this plan fingerprint".to_string(),
                                            }),
                                            status == ToggleStatus::DryRun,
                                            vec![item.provider],
                                            serde_json::json!({"result": result}),
                                        );

                                            match render_controlled_toggle(
                                                &result,
                                                &plan.plan_fingerprint,
                                                &operation,
                                                json,
                                            ) {
                                                Ok(output) => {
                                                    println!("{output}");
                                                    if matches!(
                                                        status,
                                                        ToggleStatus::Blocked
                                                            | ToggleStatus::RecoveryRequired
                                                    ) {
                                                        ExitCode::FAILURE
                                                    } else {
                                                        ExitCode::SUCCESS
                                                    }
                                                }
                                                Err(error) => {
                                                    eprintln!("{error}");
                                                    ExitCode::FAILURE
                                                }
                                            }
                                        }
                                        None => command_error_exit(
                                            json,
                                            "blocked",
                                            &format!("unknown selection for {id}"),
                                        ),
                                    }
                                }
                                Err(error) => {
                                    eprintln!("discovery failed: {error}");
                                    ExitCode::FAILURE
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("{error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::Restore {
            backup_id,
            home_root,
            project_root,
            cursor_root,
            app_state_root,
            fixture_root,
            apply,
            confirm,
            plan_fingerprint,
            json,
        }) => {
            let Some(backup_id) = backup_id else {
                return command_error_exit(json, "failed", "missing backup id");
            };
            let fixture_mode = fixture_root.is_some();
            let roots = DiscoveryRootArgs {
                fixture_root,
                home_root,
                project_root,
                cursor_root,
            };
            let config = match resolve_config(&roots, app_state_root) {
                Ok(config) => config,
                Err(error) => return command_error_exit(json, "failed", &error),
            };
            let identity = match config.workspace_identity() {
                Ok(identity) => identity,
                Err(error) => return command_error_exit(json, "failed", &error.to_string()),
            };
            let approval_context = match ControlApprovalContext::new(
                &identity.repository_key,
                &identity.workspace_key,
            ) {
                Ok(context) => context,
                Err(error) => return command_error_exit(json, "failed", &error.to_string()),
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
                Err(error) => return command_error_exit(json, "failed", &error),
            };
            let restore_state_root = if fixture_mode {
                match std::fs::canonicalize(&config.app_state_root) {
                    Ok(root) => root,
                    Err(error) => {
                        return command_error_exit(
                            json,
                            "failed",
                            &format!("fixture state root could not be resolved: {error}"),
                        );
                    }
                }
            } else {
                config.app_state_root.clone()
            };
            let controller = if apply {
                match credentials::resolve_session_authority_key(
                    fixture_mode,
                    &config.app_state_root,
                ) {
                    Ok(Some(key)) => {
                        RestoreController::with_session_authority_key(restore_state_root, key)
                    }
                    Ok(None) => {
                        return command_error_exit(
                            json,
                            "blocked",
                            "session authority key missing; run `unpin auth session init`",
                        );
                    }
                    Err(error) => return command_error_exit(json, "blocked", &error),
                }
            } else {
                RestoreController::new(restore_state_root)
            };
            let plan = match controller.plan(
                &backup_id,
                &approval_context,
                Some(&backup_authentication_key),
            ) {
                Ok(plan) => plan,
                Err(error) => return command_error_exit(json, "blocked", &error.to_string()),
            };
            if !apply {
                if json {
                    let expectation = plan
                        .approval_expectation(&approval_context)
                        .expect("validated restore plan has approval expectation");
                    let operation = ControlOperationEnvelope::from_expectation(
                        &expectation,
                        &plan.plan_fingerprint,
                        plan.activation,
                        ControlOperationLifecycle::Planned,
                        Some(ControlHumanAction {
                            code: "confirm-and-apply".to_string(),
                            guidance: "Re-run with --apply --confirm and this plan fingerprint"
                                .to_string(),
                        }),
                        true,
                        vec![plan.provider],
                        serde_json::json!({"plan": plan}),
                    );
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "planned",
                            "operation": operation,
                            "plan": plan,
                            "humanApprovalRequired": true,
                        })
                    );
                } else {
                    println!(
                        "planned restore {} fingerprint={} activation=live",
                        plan.backup_id, plan.plan_fingerprint
                    );
                }
                return ExitCode::SUCCESS;
            }
            if !confirm {
                return command_error_exit(json, "blocked", "confirmation-required");
            }
            if plan_fingerprint.as_deref() != Some(plan.plan_fingerprint.as_str()) {
                return command_error_exit(json, "blocked", "plan-fingerprint-mismatch");
            }
            let mut fixture_write_paths = vec![config.app_state_root.as_path()];
            fixture_write_paths.extend(
                plan.affected_resources
                    .iter()
                    .map(|resource| Path::new(resource.path.as_str())),
            );
            if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
                fixture_mode,
                fixture_write_paths,
            ) {
                return command_error_exit(json, "blocked", &error);
            }
            let expectation = match plan.approval_expectation(&approval_context) {
                Ok(expectation) => expectation,
                Err(error) => return command_error_exit(json, "blocked", &error.to_string()),
            };
            let authorization = match credentials::authorize_reviewed_control_decision(
                fixture_mode,
                &config.app_state_root,
                &expectation,
                &plan.plan_fingerprint,
                plan_fingerprint.as_deref(),
                "unpin-cli-restore-approval",
                unix_now(),
            ) {
                Ok(authorization) => authorization,
                Err(error) => return command_error_exit(json, "blocked", &error),
            };
            let result = match controller.apply(
                &plan,
                authorization,
                &approval_context,
                Some(backup_authentication_key),
            ) {
                Ok(result) => result,
                Err(error) => {
                    return command_error_exit(
                        json,
                        restore_control_error_status(&error),
                        &error.to_string(),
                    );
                }
            };
            let status = result.status;

            if json {
                let operation = ControlOperationEnvelope::from_expectation(
                    &expectation,
                    &plan.plan_fingerprint,
                    plan.activation,
                    if status == RestoreStatus::Restored {
                        ControlOperationLifecycle::Applied
                    } else {
                        ControlOperationLifecycle::RecoveryRequired
                    },
                    None,
                    status != RestoreStatus::Restored,
                    vec![plan.provider],
                    serde_json::json!({"result": result}),
                );
                let mut value = restore_json_value(&result);
                value["operation"] = serde_json::to_value(operation)
                    .expect("control operation envelope is serializable");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("restore JSON")
                );
                return if status == RestoreStatus::Restored {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }

            match render_restore(&result, false) {
                Ok(output) => {
                    println!("{output}");
                    if status == RestoreStatus::Restored {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::Session { command }) => commands::session::run(command),
        Some(Commands::Bulk { command }) => commands::toggle::run(command),
        Some(Commands::Catalog { command }) => commands::catalog::run(command),
        Some(Commands::Profile { command }) => commands::profile::run(command),
        Some(Commands::Group { command }) => commands::group::run(command),
        Some(Commands::Gateway { command }) => commands::gateway::run(command),
        Some(Commands::Hook { command }) => commands::hook::run(command),
        Some(Commands::Tui {
            roots,
            app_state_root,
            headless,
        }) => {
            let fixture_mode = roots.fixture_root.is_some();
            let config = match resolve_config(&roots, app_state_root.clone()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            match resolve_discovery_roots_with_config(&roots, &config) {
                Ok(roots) => {
                    let discovery_roots = roots.with_app_state_root(&config.app_state_root);
                    match discover_all(&discovery_roots) {
                        Ok(discovery) => {
                            let backup_authentication_key =
                                resolve_optional_backup_authentication_key(
                                    fixture_mode,
                                    &config.app_state_root,
                                );
                            let session_authority_key = resolve_optional_session_authority_key(
                                fixture_mode,
                                &config.app_state_root,
                            );
                            if headless {
                                println!(
                                    "{}",
                                    tui::render_headless_with_paths(
                                        &discovery,
                                        config.app_state_root,
                                        config.project_root,
                                        backup_authentication_key,
                                        session_authority_key,
                                    )
                                );
                                ExitCode::SUCCESS
                            } else {
                                match tui::run_interactive(
                                    discovery,
                                    config.app_state_root,
                                    config.project_root,
                                    discovery_roots,
                                    backup_authentication_key,
                                    session_authority_key,
                                    fixture_mode,
                                ) {
                                    Ok(()) => ExitCode::SUCCESS,
                                    Err(error) => {
                                        eprintln!("tui failed: {error}");
                                        ExitCode::FAILURE
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("discovery failed: {error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::Mcp {
            roots,
            app_state_root,
            provider,
            once,
            enable_approved_group_apply,
        }) => {
            if once && enable_approved_group_apply {
                eprintln!(
                    "--once cannot be combined with --enable-approved-group-apply; approved apply requires a persistent MCP session"
                );
                return ExitCode::FAILURE;
            }
            let fixture_mode = roots.fixture_root.is_some();
            let config = match resolve_config(&roots, app_state_root.clone()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            let discovery_roots = match resolve_discovery_roots_with_config(&roots, &config) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };
            let (backup_authentication_key, authentication) =
                resolve_mcp_authentication_readiness(fixture_mode, &config.app_state_root);
            let session_authority_key =
                resolve_optional_session_authority_key(fixture_mode, &config.app_state_root);
            let app_state_root = if fixture_mode {
                match std::fs::canonicalize(&config.app_state_root) {
                    Ok(root) => root,
                    Err(error) => {
                        eprintln!("fixture state root could not be resolved: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                config.app_state_root.clone()
            };
            let provider_scope: McpProviderScope = provider.into();
            let approved_group_apply = if enable_approved_group_apply {
                if backup_authentication_key.is_none() {
                    eprintln!(
                        "approved group apply requires backup authentication; run `unpin auth backup init`"
                    );
                    return ExitCode::FAILURE;
                }
                let Some(session_key) = session_authority_key.as_ref() else {
                    eprintln!(
                        "approved group apply requires session authority; run `unpin auth session init`"
                    );
                    return ExitCode::FAILURE;
                };
                let approval_key = match credentials::resolve_approval_key(
                    fixture_mode,
                    &app_state_root,
                ) {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        eprintln!(
                            "approved group apply requires approval signing; run `unpin auth approval init`"
                        );
                        return ExitCode::FAILURE;
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                };
                let group_access = match GroupAccessContext::from_config(
                    &config,
                    &discovery_roots.clone().with_app_state_root(&app_state_root),
                    provider_scope.provider(),
                    None,
                ) {
                    Ok(context) => context,
                    Err(error) => {
                        eprintln!("approved group apply context failed: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                let binding = McpGroupSessionBinding {
                    provider: provider_scope.provider(),
                    repository_key: group_access.repository_key().to_string(),
                    workspace_key: group_access.workspace_key().to_string(),
                };
                let now_unix = match current_unix_seconds() {
                    Ok(now) => now,
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                };
                if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
                    fixture_mode,
                    [app_state_root.as_path()],
                ) {
                    eprintln!("approved group apply session blocked: {error}");
                    return ExitCode::FAILURE;
                }
                let session = match McpGroupSessionLeaseStore::new(&app_state_root).create(
                    binding,
                    session_key,
                    now_unix,
                ) {
                    Ok(session) => session,
                    Err(error) => {
                        eprintln!("approved group apply session failed: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                Some(McpApprovedGroupApplyContext {
                    session,
                    approval_key,
                })
            } else {
                None
            };
            let context = McpContext {
                discovery_roots: discovery_roots.with_app_state_root(&app_state_root),
                fixture_root: roots.fixture_root.clone(),
                package_root: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                app_state_root,
                project_root: config.project_root,
                backup_authentication_key,
                session_authority_key,
                authentication,
                provider_scope,
                discovery_cache: McpDiscoveryCache::default(),
                approved_group_apply,
            };

            if once {
                match handle_stdio_request_once(&context, io::stdin()) {
                    Ok(output) => {
                        if let Err(error) = io::stdout().write_all(&output) {
                            eprintln!("mcp write failed: {error}");
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        }
                    }
                    Err(error) => {
                        eprintln!("mcp failed: {error}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                let heartbeat = context.approved_group_apply.as_ref().and_then(|approved| {
                    let session_key = context.session_authority_key.clone()?;
                    let store = McpGroupSessionLeaseStore::new(&context.app_state_root);
                    let session = approved.session.clone();
                    let stopped = Arc::new(AtomicBool::new(false));
                    let worker_stopped = Arc::clone(&stopped);
                    let handle = thread::spawn(move || {
                        while !worker_stopped.load(Ordering::Acquire) {
                            thread::park_timeout(Duration::from_secs(30));
                            if worker_stopped.load(Ordering::Acquire) {
                                break;
                            }
                            let now_unix = match current_unix_seconds() {
                                Ok(now_unix) => now_unix,
                                Err(error) => {
                                    eprintln!(
                                        "approved group apply heartbeat clock failed; retrying: {error}"
                                    );
                                    continue;
                                }
                            };
                            if let Err(error) = store.renew(&session, &session_key, now_unix) {
                                eprintln!(
                                    "approved group apply heartbeat renewal failed; retrying: {error}"
                                );
                            }
                        }
                    });
                    Some((stopped, handle))
                });
                let result =
                    handle_stdio_requests(&context, io::stdin().lock(), io::stdout().lock());
                if let Some((stopped, handle)) = heartbeat {
                    stopped.store(true, Ordering::Release);
                    handle.thread().unpark();
                    let _ = handle.join();
                }
                if let Err(error) = result {
                    eprintln!("mcp failed: {error}");
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
        }
        Some(Commands::SessionChildWrapper {
            control_file,
            app_state_root,
            fixture_mode,
            command,
        }) => {
            let authority_key =
                match credentials::resolve_session_authority_key(fixture_mode, &app_state_root) {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        eprintln!(
                            "session child wrapper failed: session authority key is unavailable"
                        );
                        return ExitCode::FAILURE;
                    }
                    Err(error) => {
                        eprintln!("session child wrapper failed: {error}");
                        return ExitCode::FAILURE;
                    }
                };
            match session_process::run_child_wrapper(&control_file, command, &authority_key) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("session child wrapper failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(Commands::GatewaySessionProxy { socket }) => {
            match gateway_session::run_gateway_proxy(&socket) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("session gateway proxy failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        None => {
            if let Err(error) = Cli::command().print_help() {
                eprintln!("failed to render help: {error}");
                return ExitCode::from(1);
            }
            println!();
            ExitCode::SUCCESS
        }
    }
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

fn parse_provider_id(value: &str) -> Option<ProviderId> {
    ProviderId::ALL
        .into_iter()
        .find(|provider| provider.as_str() == value)
}

fn run_auth_command(command: AuthCommands) -> ExitCode {
    let store = credentials::KeychainSecretStore;
    match command {
        AuthCommands::Backup {
            command: BackupAuthCommands::Init { json },
        } => match credentials::initialize_backup_authentication_key(&store) {
            Ok(credentials::BackupAuthenticationInitialization::Created { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "created", "keyId": key_id })
                    );
                } else {
                    println!("backup authentication key created: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::BackupAuthenticationInitialization::AlreadyExists { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("backup authentication key already exists: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::Backup {
            command: BackupAuthCommands::Status { json },
        } => match credentials::backup_authentication_status(&store) {
            Ok(credentials::BackupAuthenticationState::Missing) => {
                if json {
                    println!("{}", serde_json::json!({ "status": "missing" }));
                } else {
                    println!("backup authentication key: missing");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::BackupAuthenticationState::Ready { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("backup authentication key: ready ({key_id})");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::Approval {
            command: ApprovalAuthCommands::Init { json },
        } => match credentials::initialize_approval_key(&store) {
            Ok(credentials::ApprovalKeyInitialization::Created { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "created", "keyId": key_id })
                    );
                } else {
                    println!("approval key created: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::ApprovalKeyInitialization::AlreadyExists { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("approval key already exists: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::Approval {
            command: ApprovalAuthCommands::Status { json },
        } => match credentials::approval_key_status(&store) {
            Ok(credentials::ApprovalKeyState::Missing) => {
                if json {
                    println!("{}", serde_json::json!({ "status": "missing" }));
                } else {
                    println!("approval key: missing");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::ApprovalKeyState::Ready { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("approval key: ready ({key_id})");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::Session {
            command: SessionAuthorityAuthCommands::Init { json },
        } => match credentials::initialize_session_authority_key(&store) {
            Ok(credentials::SessionAuthorityKeyInitialization::Created { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "created", "keyId": key_id })
                    );
                } else {
                    println!("session authority key created: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::SessionAuthorityKeyInitialization::AlreadyExists { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("session authority key already exists: {key_id}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::Session {
            command: SessionAuthorityAuthCommands::Status { json },
        } => match credentials::session_authority_key_status(&store) {
            Ok(credentials::SessionAuthorityKeyState::Missing) => {
                if json {
                    println!("{}", serde_json::json!({ "status": "missing" }));
                } else {
                    println!("session authority key: missing");
                }
                ExitCode::SUCCESS
            }
            Ok(credentials::SessionAuthorityKeyState::Ready { key_id }) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "status": "ready", "keyId": key_id })
                    );
                } else {
                    println!("session authority key: ready ({key_id})");
                }
                ExitCode::SUCCESS
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::CursorDashboard {
            command: CursorDashboardAuthCommands::Store { json },
        } => store_cursor_dashboard_credential(&store, json),
        AuthCommands::CursorDashboard {
            command: CursorDashboardAuthCommands::Status { json },
        } => match credentials::cursor_dashboard_credential_status(&store) {
            Ok(credentials::CursorDashboardCredentialState::Missing) => {
                render_cursor_dashboard_credential_status(json, "missing")
            }
            Ok(credentials::CursorDashboardCredentialState::Ready) => {
                render_cursor_dashboard_credential_status(json, "ready")
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
        AuthCommands::CursorDashboard {
            command: CursorDashboardAuthCommands::Remove { json },
        } => match credentials::remove_cursor_dashboard_cookie(&store) {
            Ok(credentials::CursorDashboardCredentialRemoval::Removed) => {
                render_cursor_dashboard_credential_status(json, "removed")
            }
            Ok(credentials::CursorDashboardCredentialRemoval::Missing) => {
                render_cursor_dashboard_credential_status(json, "missing")
            }
            Err(error) => command_error_exit(json, "failed", &error),
        },
    }
}

fn store_cursor_dashboard_credential(
    store: &impl credentials::SecretStore,
    json: bool,
) -> ExitCode {
    let mut secret = Zeroizing::new(Vec::new());
    let read = io::stdin()
        .take((credentials::MAX_CURSOR_DASHBOARD_COOKIE_BYTES + 2) as u64)
        .read_to_end(&mut secret);
    if let Err(error) = read {
        return command_error_exit(json, "failed", &format!("credential input failed: {error}"));
    }
    if secret.last() == Some(&b'\n') {
        secret.pop();
        if secret.last() == Some(&b'\r') {
            secret.pop();
        }
    }
    let result = credentials::store_cursor_dashboard_cookie(store, &secret);
    match result {
        Ok(credentials::CursorDashboardCredentialUpdate::Created) => {
            render_cursor_dashboard_credential_status(json, "created")
        }
        Ok(credentials::CursorDashboardCredentialUpdate::Updated) => {
            render_cursor_dashboard_credential_status(json, "updated")
        }
        Err(error) => command_error_exit(json, "failed", &error),
    }
}

fn render_cursor_dashboard_credential_status(json: bool, status: &str) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": status,
                "credential": {
                    "id": "cursor-dashboard-cookie",
                    "provider": "cursor",
                    "purpose": "marketplace-dashboard",
                    "origin": "https://cursor.com",
                    "storage": "os-keychain",
                }
            })
        );
    } else {
        println!("Cursor dashboard credential: {status} (OS keychain)");
    }
    ExitCode::SUCCESS
}

fn resolve_optional_backup_authentication_key(
    fixture_mode: bool,
    app_state_root: &Path,
) -> Option<BackupAuthenticationKey> {
    match credentials::resolve_backup_authentication_key(fixture_mode, app_state_root) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("backup authentication unavailable; writes disabled: {error}");
            None
        }
    }
}

fn resolve_optional_session_authority_key(
    fixture_mode: bool,
    app_state_root: &Path,
) -> Option<unpin_core::sessions::SessionAuthorityKey> {
    match credentials::resolve_session_authority_key(fixture_mode, app_state_root) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("session authority unavailable; session controls disabled: {error}");
            None
        }
    }
}

fn resolve_mcp_authentication_readiness(
    fixture_mode: bool,
    app_state_root: &Path,
) -> (Option<BackupAuthenticationKey>, McpAuthenticationReadiness) {
    let (backup_authentication_key, backup_authentication) =
        match credentials::resolve_backup_authentication_key(fixture_mode, app_state_root) {
            Ok(Some(key)) => {
                let readiness = McpCredentialReadiness::ready(Some(key.key_id()));
                (Some(key), readiness)
            }
            Ok(None) => (None, McpCredentialReadiness::missing()),
            Err(error) => {
                eprintln!("backup authentication unavailable: {error}");
                (None, McpCredentialReadiness::unavailable())
            }
        };
    let approval_signing =
        match credentials::approval_key_status_for_mode(fixture_mode, app_state_root) {
            Ok(credentials::ApprovalKeyState::Ready { key_id }) => {
                McpCredentialReadiness::ready(Some(key_id))
            }
            Ok(credentials::ApprovalKeyState::Missing) => McpCredentialReadiness::missing(),
            Err(error) => {
                eprintln!("approval signing unavailable: {error}");
                McpCredentialReadiness::unavailable()
            }
        };
    let cursor_dashboard = if fixture_mode {
        McpCredentialReadiness::missing()
    } else {
        match credentials::cursor_dashboard_credential_status(&credentials::KeychainSecretStore) {
            Ok(credentials::CursorDashboardCredentialState::Ready) => {
                McpCredentialReadiness::ready(None)
            }
            Ok(credentials::CursorDashboardCredentialState::Missing) => {
                McpCredentialReadiness::missing()
            }
            Err(error) => {
                eprintln!("Cursor dashboard credential unavailable: {error}");
                McpCredentialReadiness::unavailable()
            }
        }
    };
    (
        backup_authentication_key,
        McpAuthenticationReadiness {
            backup_authentication,
            approval_signing,
            cursor_dashboard,
        },
    )
}

fn parse_cli() -> Result<Cli, ExitCode> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    validate_top_level_command(&args)?;
    Ok(Cli::parse())
}

fn validate_top_level_command(args: &[OsString]) -> Result<(), ExitCode> {
    let Some(first_arg) = args.first() else {
        eprintln!("No command specified.");
        return Err(ExitCode::FAILURE);
    };

    let first_arg = first_arg.to_string_lossy();
    if first_arg.starts_with('-') || is_known_top_level_command(&first_arg) {
        return Ok(());
    }

    let unknown = args
        .iter()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("Unknown command: {unknown}");
    Err(ExitCode::FAILURE)
}

fn is_known_top_level_command(command: &str) -> bool {
    command == "help" || Cli::command().find_subcommand(command).is_some()
}

fn render_providers() -> String {
    let mut lines = vec!["Supported providers".to_string(), String::new()];

    for row in CAPABILITY_ROWS {
        lines.push(format!("{} ({})", row.provider_name, row.provider_id));
        lines.push(render_capability_line("Skills", row.skills));
        lines.push(render_capability_line(
            "Configured MCPs",
            row.configured_mcps,
        ));
        lines.push(render_capability_line("Tools", row.tools));
        lines.push(render_capability_line("Agents", row.agents));
        lines.push(render_capability_line("Hooks", row.hooks));
        lines.push(render_capability_line(
            "Provider settings",
            row.provider_settings,
        ));
        lines.push(render_capability_line("Plugin configs", row.plugin_configs));
        lines.push(render_capability_line(
            "Plugin manifests",
            row.plugin_manifests,
        ));
        lines.push(render_capability_line(
            "Plugin global scope",
            row.plugin_global_scope,
        ));
        lines.push(render_capability_line(
            "Plugin project scope",
            row.plugin_project_scope,
        ));
        lines.push(render_capability_line("Extensions", row.extensions));
        lines.push(format!("  note:            {}", row.note));
        lines.push(String::new());
    }

    lines.join("\n").trim_end().to_string()
}

fn render_capability_line(label: &str, status: &str) -> String {
    let field_label = format!("{label}:");
    let padded_label = if field_label.len() >= 17 {
        format!("{field_label} ")
    } else {
        format!("{field_label:<17}")
    };
    format!("  {padded_label}{status}")
}

fn render_list(result: &DiscoveryOutput, json: bool) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(result);
    }

    let mut lines = Vec::new();
    if result.items.is_empty() {
        lines.push("No discovered items.".to_string());
    } else {
        lines.push("Discovered items:".to_string());
        lines.push(String::new());

        for item in &result.items {
            lines.push(format!(
                "- {} {} {} {}",
                item.provider.as_str(),
                item.layer.as_str(),
                item.category.as_str(),
                item.display_name
            ));
            lines.push(format!("  id: {}", item.id));
            lines.push(format!("  enabled: {}", item.enabled));
            lines.push(format!("  mutability: {:?}", item.mutability));
            lines.push(format!("  source: {}", item.source_path));
            lines.push(format!("  state: {}", item.state_path));
        }
    }

    Ok(lines.join("\n"))
}

fn render_discovery_warnings(warnings: &[DiscoveryWarning]) -> String {
    let mut lines = vec!["Warnings:".to_string(), String::new()];
    lines.extend(
        warnings
            .iter()
            .map(|warning| format!("- {}", render_warning_label(warning))),
    );
    lines.join("\n")
}

fn render_warning_label(warning: &DiscoveryWarning) -> String {
    let layer = warning
        .layer
        .map(|layer| format!(" {}", layer.as_str()))
        .unwrap_or_default();
    format!(
        "{}{} {}: {}",
        warning.provider.as_str(),
        layer,
        warning.code,
        warning.message
    )
}

fn validate_layer_filter(layer: Option<&str>) -> Result<(), &'static str> {
    match layer {
        Some("global" | "project" | "all") | None => Ok(()),
        Some(_) => Err("invalid layer: expected global, project, or all"),
    }
}

fn missing_toggle_selector(
    provider: Option<&str>,
    kind: Option<&str>,
    layer: Option<&str>,
    id: Option<&str>,
) -> Option<&'static str> {
    for (field, value) in [
        ("provider", provider),
        ("kind", kind),
        ("id", id),
        ("layer", layer),
    ] {
        if value.is_none_or(str::is_empty) {
            return Some(match field {
                "provider" => "missing required selector: --provider",
                "kind" => "missing required selector: --kind",
                "id" => "missing required selector: --id",
                "layer" => "missing required selector: --layer",
                _ => unreachable!("selector field is known"),
            });
        }
    }

    None
}

fn command_error_exit(json: bool, status: &str, reason: &str) -> ExitCode {
    match render_command_error(json, status, reason) {
        Ok(output) => {
            println!("{output}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("failed to render command error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn command_error_exit_code(json: bool, status: &str, reason: &str, code: u8) -> ExitCode {
    match render_command_error(json, status, reason) {
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

fn lifecycle_exit_code(status: &str) -> u8 {
    match status {
        "partial" => 2,
        "blocked" | "no-targets" | "no-targets-in-provider-reach" => 3,
        "recovery-required" => 4,
        _ => 1,
    }
}

fn render_command_error(
    json: bool,
    status: &str,
    reason: &str,
) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(&serde_json::json!({
            "status": status,
            "reason": reason,
        }));
    }

    if status == "blocked" {
        Ok(format!("blocked: {reason}"))
    } else {
        Ok(reason.to_string())
    }
}

fn filter_discovery(
    mut result: DiscoveryOutput,
    provider: Option<&str>,
    kind: Option<&str>,
    layer: Option<&str>,
) -> DiscoveryOutput {
    result.items.retain(|item| {
        provider.is_none_or(|provider| item.provider.as_str() == provider)
            && kind.is_none_or(|kind| item.kind.as_str() == kind)
            && layer.is_none_or(|layer| layer == "all" || item.layer.as_str() == layer)
    });
    result.warnings.retain(|warning| {
        provider.is_none_or(|provider| warning.provider.as_str() == provider)
            && layer.is_none_or(|layer| {
                layer == "all"
                    || warning
                        .layer
                        .is_none_or(|warning_layer| warning_layer.as_str() == layer)
            })
    });
    result
}

fn resolve_discovery_roots(args: &DiscoveryRootArgs) -> Result<DiscoveryRoots, String> {
    if let Some(fixture_root) = &args.fixture_root {
        return Ok(DiscoveryRoots::fixture_root(fixture_root));
    }

    let config = resolve_config(args, None)?;
    resolve_discovery_roots_with_config(args, &config)
        .map(|roots| roots.with_app_state_root(&config.app_state_root))
}

fn resolve_discovery_roots_with_config(
    args: &DiscoveryRootArgs,
    config: &UnpinConfig,
) -> Result<DiscoveryRoots, String> {
    if let Some(fixture_root) = &args.fixture_root {
        return Ok(DiscoveryRoots::fixture_root(fixture_root));
    }

    Ok(DiscoveryRoots::from_locations(
        home_root(args)?,
        &config.project_root,
        &config.cursor_root,
    ))
}

fn resolve_config(
    args: &DiscoveryRootArgs,
    app_state_root: Option<PathBuf>,
) -> Result<UnpinConfig, String> {
    let cwd = env::current_dir().map_err(|error| error.to_string())?;
    let home_dir = home_root(args)?;
    load_config(LoadConfigOptions {
        cwd,
        home_dir,
        overrides: args.config_overrides(app_state_root),
    })
    .map_err(|error| error.to_string())
}

fn home_root(args: &DiscoveryRootArgs) -> Result<PathBuf, String> {
    match &args.home_root {
        Some(home_root) => Ok(home_root.clone()),
        None => env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set; pass --home-root or --fixture-root".to_string()),
    }
}

struct DoctorOutput {
    output: String,
    success: bool,
}

fn run_doctor(args: &DiscoveryRootArgs) -> Result<DoctorOutput, String> {
    if let Some(fixture_root) = &args.fixture_root {
        let matrix_report = validate_capability_matrix(fixture_root);
        if !matrix_report.issues.is_empty() {
            let mut lines = vec![
                "unpin doctor: capability matrix validation failed".to_string(),
                String::new(),
            ];
            for issue in matrix_report.issues {
                lines.push(format!("- {issue}"));
            }
            return Ok(DoctorOutput {
                output: lines.join("\n"),
                success: false,
            });
        }
        let fixture_report = validate_provider_fixtures(fixture_root);
        if !fixture_report.issues.is_empty() {
            let mut lines = vec![
                "unpin doctor: fixture validation failed".to_string(),
                String::new(),
            ];
            for issue in fixture_report.issues {
                lines.push(format!(
                    "- {} {}: {}",
                    issue.provider_id, issue.relative_path, issue.message
                ));
            }
            return Ok(DoctorOutput {
                output: lines.join("\n"),
                success: false,
            });
        }
    }

    let roots = resolve_discovery_roots(args)?;
    let discovery = discover_all(&roots).map_err(|error| format!("discovery failed: {error}"))?;

    if !discovery.warnings.is_empty() {
        let mut lines = vec![
            "unpin doctor: provider issues detected".to_string(),
            String::new(),
        ];
        for warning in &discovery.warnings {
            lines.push(format!("- {}", render_warning_label(warning)));
        }

        return Ok(DoctorOutput {
            output: lines.join("\n"),
            success: false,
        });
    }

    let mut lines = vec!["OK".to_string()];

    if let Some(fixture_root) = &args.fixture_root {
        let matrix_path = fixture_root.join("capability-matrix.json");
        lines.push(format!("fixtures root: {}", fixture_root.display()));
        lines.push(format!("capability matrix: {}", matrix_path.display()));
    } else {
        lines.push("fixtures root: <not used>".to_string());
        lines.push("capability matrix: <not used>".to_string());
    }

    lines.push(format!("items discovered: {}", discovery.items.len()));

    Ok(DoctorOutput {
        output: lines.join("\n"),
        success: true,
    })
}

fn render_snapshot(result: &SnapshotWriteResult, json: bool) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(result);
    }

    let provider_lines = result
        .snapshot
        .inventory
        .providers
        .iter()
        .map(|provider| {
            format!(
                "  - {}: available={}, active={}, warnings={}",
                provider.provider.as_str(),
                provider.total_available,
                provider.total_active,
                provider.warning_count
            )
        })
        .collect::<Vec<_>>();

    let mut lines = vec![
        format!("Snapshot saved: {}", result.snapshot.id),
        format!("Latest path: {}", result.latest_path.display()),
        format!("History path: {}", result.history_path.display()),
        format!("Captured at: {}", result.snapshot.captured_at),
        format!("Project root: {}", result.snapshot.project_root),
        "Inventory semantics: available=discovered in the current scope, active=currently enabled within that scope.".to_string(),
        "Providers:".to_string(),
    ];
    lines.extend(provider_lines);

    if !result.snapshot.warnings.is_empty() {
        lines.push(String::new());
        lines.push("Warnings:".to_string());
        for warning in &result.snapshot.warnings {
            lines.push(format!("- {}", render_warning_label(warning)));
        }
    }

    Ok(lines.join("\n"))
}

fn select_toggle_item<'a>(
    discovery: &'a DiscoveryOutput,
    provider: &str,
    kind: &str,
    layer: &str,
    id: &str,
) -> Option<&'a DiscoveryItem> {
    discovery.items.iter().find(|item| {
        item.provider.as_str() == provider
            && item.kind.as_str() == kind
            && item.layer.as_str() == layer
            && item.id == id
    })
}

fn render_toggle(result: &ToggleResult, json: bool) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(&toggle_json_value(result));
    }

    let mut lines = vec![
        format!("status: {}", toggle_status_name(result.status)),
        format!("item: {}", result.selection.id),
        format!("targetEnabled: {}", result.target_enabled),
    ];

    if let Some(reason) = &result.reason {
        lines.push(format!("reason: {reason}"));
    }

    if let Some(backup_id) = &result.backup_id {
        lines.push(format!("backupId: {backup_id}"));
    }

    lines.push("operations:".to_string());
    if result.operations.is_empty() {
        lines.push("- none".to_string());
    } else {
        for operation in &result.operations {
            lines.push(format!("- {}", describe_operation(operation)));
        }
    }

    lines.push("affectedTargets:".to_string());
    if result.affected_targets.is_empty() {
        lines.push("- none".to_string());
    } else {
        for target in &result.affected_targets {
            lines.push(format!("- {}", describe_target(target)));
        }
    }

    if let Some(writes) = &result.writes {
        lines.push(format!("writes: {writes}"));
    }

    Ok(lines.join("\n"))
}

fn render_controlled_toggle(
    result: &ToggleResult,
    plan_fingerprint: &str,
    operation: &ControlOperationEnvelope,
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        let mut value = toggle_json_value(result);
        value["statusVersion"] = serde_json::json!(2);
        value["planFingerprint"] = serde_json::json!(plan_fingerprint);
        value["operation"] = serde_json::to_value(operation)?;
        return serde_json::to_string_pretty(&value);
    }
    let mut rendered = render_toggle(result, false)?;
    rendered.push_str(&format!("\nplanFingerprint: {plan_fingerprint}"));
    Ok(rendered)
}

fn toggle_json_value(result: &ToggleResult) -> serde_json::Value {
    let mut value = serde_json::json!({
        "statusVersion": 2,
        "status": toggle_status_name(result.status),
        "selection": result.selection,
        "targetEnabled": result.target_enabled,
        "operations": result
            .operations
            .iter()
            .map(|operation| {
                serde_json::json!({
                    "type": operation.operation_type,
                    "summary": describe_operation(operation),
                })
            })
            .collect::<Vec<_>>(),
        "affectedTargets": result
            .affected_targets
            .iter()
            .map(describe_target)
            .collect::<Vec<_>>(),
    });

    if let Some(reach) = result.provider_reach {
        value["providerReach"] = serde_json::to_value(reach).unwrap_or(serde_json::Value::Null);
    }
    if let Some(coverage) = &result.coverage {
        value["providerCoverage"] =
            serde_json::to_value(coverage).unwrap_or(serde_json::Value::Null);
    }

    if let Some(reason) = &result.reason {
        value["reason"] = serde_json::json!(reason);
    }
    if let Some(backup_id) = &result.backup_id {
        value["backupId"] = serde_json::json!(backup_id);
    }
    if let Some(writes) = &result.writes {
        value["writes"] = serde_json::json!(writes);
    }

    value
}

fn describe_operation(operation: &MutationOperation) -> String {
    match (
        operation.operation_type.as_str(),
        operation.from_path.as_deref(),
        operation.to_path.as_deref(),
    ) {
        ("createFile", _, Some(path)) | ("createFile", Some(path), _) => {
            format!("create file {path}")
        }
        ("replaceJsonValue", Some(path), _) => format!("replace JSON value {path}"),
        ("updateJsonObjectEntry", Some(path), _) => {
            format!("update JSON object entry {path}")
        }
        ("removeJsonObjectEntry", Some(path), _) => {
            format!("remove JSON object entry {path}")
        }
        ("renamePath", Some(from_path), Some(to_path)) => {
            format!(
                "rename path {from_path} -> {to_path}; {}",
                operation.summary
            )
        }
        ("deletePath", Some(path), _) => format!("delete path {path}"),
        ("replaceFile", Some(path), _) => {
            format!("replace file {path}; {}", operation.summary)
        }
        _ => operation.summary.clone(),
    }
}

fn describe_target(target: &MutationTarget) -> String {
    target.path.clone()
}

fn toggle_status_name(status: ToggleStatus) -> &'static str {
    match status {
        ToggleStatus::DryRun => "dry-run",
        ToggleStatus::Applied => "applied",
        ToggleStatus::Blocked => "blocked",
        ToggleStatus::RecoveryRequired => "recovery-required",
    }
}

fn render_restore(result: &RestoreResult, json: bool) -> Result<String, serde_json::Error> {
    if json {
        return serde_json::to_string_pretty(&restore_json_value(result));
    }

    let mut lines = vec![
        format!("status: {}", restore_status_name(result.status)),
        format!("backupId: {}", result.backup_id),
    ];

    if let Some(reason) = &result.reason {
        lines.push(format!("reason: {reason}"));
    }

    lines.push("affectedTargets:".to_string());
    if result.affected_targets.is_empty() {
        lines.push("- none".to_string());
    } else {
        for target in &result.affected_targets {
            lines.push(format!("- {}", describe_target(target)));
        }
    }

    Ok(lines.join("\n"))
}

fn restore_json_value(result: &RestoreResult) -> serde_json::Value {
    let mut value = serde_json::json!({
        "status": restore_status_name(result.status),
        "backupId": result.backup_id,
        "affectedTargets": result
            .affected_targets
            .iter()
            .map(describe_target)
            .collect::<Vec<_>>(),
    });

    if let Some(reason) = &result.reason {
        value["reason"] = serde_json::json!(reason);
    }

    value
}

fn restore_status_name(status: RestoreStatus) -> &'static str {
    match status {
        RestoreStatus::Restored => "restored",
        RestoreStatus::Failed => "failed",
    }
}

fn restore_control_error_status(error: &RestoreControlError) -> &'static str {
    if matches!(
        error,
        RestoreControlError::Durable(DurableControlError::RecoveryRequired(_))
    ) {
        "recovery-required"
    } else {
        "blocked"
    }
}

fn native_toggle_control_error_status(error: &NativeToggleControlError) -> &'static str {
    if matches!(error, NativeToggleControlError::RecoveryRequired(_)) {
        "recovery-required"
    } else {
        "blocked"
    }
}

#[cfg(test)]
mod recovery_status_tests {
    use super::*;

    #[test]
    fn restore_durable_recovery_has_distinct_machine_status() {
        let error = RestoreControlError::Durable(DurableControlError::RecoveryRequired(
            "restore-operation".to_string(),
        ));

        assert_eq!(restore_control_error_status(&error), "recovery-required");
    }

    #[test]
    fn native_toggle_recovery_has_distinct_machine_status() {
        let error = NativeToggleControlError::RecoveryRequired(
            "cached native toggle post-state diverged".to_string(),
        );

        assert_eq!(
            native_toggle_control_error_status(&error),
            "recovery-required"
        );
    }
}
