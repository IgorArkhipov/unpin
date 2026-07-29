use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, discover_all},
    groups::{
        GroupAccessContext, GroupApprovalArtifactStore, GroupDefinitionV1, GroupMemberIdentity,
        GroupPlanMode, GroupPlanner, GroupRef, GroupResolver, GroupRevision, GroupScope,
        GroupTargetState, McpGroupSessionLeaseStore, PersonalGroupStore, RepositoryGroupStore,
        authenticate_group_approval_challenge, current_unix_seconds,
        group_definition_change_fingerprint, load_group_operation_inspection,
        validate_new_group_members,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, ProviderReachLifecycle, ProviderReachRequest,
        SelectedProviderAuthority, SelectedProviderProvenance,
    },
    state::atomic_json::OwnerGeneration,
};

use super::ProviderReachArg;
use crate::{
    DiscoveryRootArgs, command_error_exit, group_store::ScopedGroupStore, parse_provider_id,
    resolve_config, resolve_discovery_roots_with_config,
};

#[derive(Debug, Subcommand)]
pub(crate) enum GroupCommands {
    /// List personal and repository inventory groups.
    List(GroupRootOptions),
    /// Show one qualified or unambiguous inventory group.
    Show {
        #[command(flatten)]
        options: GroupRootOptions,
        /// Group name, optionally qualified as personal:name or repository:name.
        group: String,
    },
    /// Create a revision-bound inventory group definition.
    Create {
        #[command(flatten)]
        options: GroupRootOptions,
        #[arg(long, value_enum)]
        scope: GroupScopeArg,
        #[arg(long)]
        name: String,
        /// Full member identity: provider:layer:kind:category:id. Repeat for each member.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        #[command(flatten)]
        write: DefinitionWriteOptions,
    },
    /// Replace a group's complete explicit member list.
    Edit {
        #[command(flatten)]
        options: GroupRootOptions,
        group: String,
        /// Full replacement member identity. Repeat for each member.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        #[arg(long)]
        expected_revision: String,
        #[command(flatten)]
        write: DefinitionWriteOptions,
    },
    /// Rename one group atomically within its current scope.
    Rename {
        #[command(flatten)]
        options: GroupRootOptions,
        group: String,
        #[arg(long)]
        new_name: String,
        #[arg(long)]
        expected_revision: String,
        #[command(flatten)]
        write: DefinitionWriteOptions,
    },
    /// Delete one group while retaining authenticated history.
    Delete {
        #[command(flatten)]
        options: GroupRootOptions,
        group: String,
        #[arg(long)]
        expected_revision: String,
        #[command(flatten)]
        write: DefinitionWriteOptions,
    },
    /// List definition history for one scope.
    History {
        #[command(flatten)]
        options: GroupRootOptions,
        #[arg(long, value_enum)]
        scope: GroupScopeArg,
    },
    /// Restore the definition that existed before a history record.
    RestoreDefinition {
        #[command(flatten)]
        options: GroupRootOptions,
        #[arg(long, value_enum)]
        scope: GroupScopeArg,
        history_id: String,
        #[arg(long)]
        expected_revision: Option<String>,
        #[command(flatten)]
        write: DefinitionWriteOptions,
    },
    /// Build a fresh, non-authorizable group toggle preview.
    Plan {
        #[command(flatten)]
        options: GroupRootOptions,
        group: String,
        #[arg(long, value_enum)]
        target: GroupTargetArg,
        #[arg(long, default_value_t = 256)]
        max_members: usize,
        /// Mutation reach. Group plans require an explicit selected or all
        /// provider choice.
        #[arg(long, alias = "provider-reach", value_enum)]
        reach: Option<ProviderReachArg>,
        /// Provider authority for selected-provider reach.
        #[arg(long)]
        selected_provider: Option<String>,
    },
    /// Review an authenticated MCP challenge and issue a one-time approval artifact.
    Approve {
        #[command(flatten)]
        options: GroupRootOptions,
        /// Opaque challenge returned by an approved persistent MCP group plan.
        #[arg(
            required_unless_present = "challenge_file",
            conflicts_with = "challenge_file"
        )]
        challenge: Option<String>,
        /// Read the opaque challenge from a file, or from stdin when PATH is `-`.
        #[arg(long, value_name = "PATH", conflicts_with = "challenge")]
        challenge_file: Option<PathBuf>,
    },
    /// Inspect durable group-operation evidence.
    OperationShow {
        #[command(flatten)]
        options: GroupRootOptions,
        operation_id: String,
    },
}

#[derive(Debug, Clone, Args)]
pub(crate) struct GroupRootOptions {
    #[command(flatten)]
    roots: DiscoveryRootArgs,
    /// Unpin-owned state root containing personal definitions and evidence.
    #[arg(long)]
    app_state_root: Option<PathBuf>,
    /// Render machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct DefinitionWriteOptions {
    /// Commit the reviewed definition change.
    #[arg(long)]
    apply: bool,
    /// Explicit human confirmation required with --apply.
    #[arg(long, requires = "apply")]
    confirm: bool,
    /// Revision/fingerprint emitted by the matching preview.
    #[arg(long, requires = "apply")]
    plan_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum GroupScopeArg {
    Personal,
    Repository,
}

impl From<GroupScopeArg> for GroupScope {
    fn from(scope: GroupScopeArg) -> Self {
        match scope {
            GroupScopeArg::Personal => Self::Personal,
            GroupScopeArg::Repository => Self::Repository,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum GroupTargetArg {
    Enable,
    Disable,
}

impl From<GroupTargetArg> for GroupTargetState {
    fn from(target: GroupTargetArg) -> Self {
        match target {
            GroupTargetArg::Enable => Self::Enable,
            GroupTargetArg::Disable => Self::Disable,
        }
    }
}

pub(crate) fn run(command: GroupCommands) -> ExitCode {
    match command {
        GroupCommands::List(options) => list(options),
        GroupCommands::Show { options, group } => show(options, &group),
        GroupCommands::Create {
            options,
            scope,
            name,
            members,
            write,
        } => create(options, scope.into(), &name, &members, write),
        GroupCommands::Edit {
            options,
            group,
            members,
            expected_revision,
            write,
        } => edit(options, &group, &members, &expected_revision, write),
        GroupCommands::Rename {
            options,
            group,
            new_name,
            expected_revision,
            write,
        } => rename(options, &group, &new_name, &expected_revision, write),
        GroupCommands::Delete {
            options,
            group,
            expected_revision,
            write,
        } => delete(options, &group, &expected_revision, write),
        GroupCommands::History { options, scope } => history(options, scope.into()),
        GroupCommands::RestoreDefinition {
            options,
            scope,
            history_id,
            expected_revision,
            write,
        } => restore_definition(
            options,
            scope.into(),
            &history_id,
            expected_revision.as_deref(),
            write,
        ),
        GroupCommands::Plan {
            options,
            group,
            target,
            max_members,
            reach,
            selected_provider,
        } => plan(
            options,
            &group,
            target.into(),
            max_members,
            reach,
            selected_provider.as_deref(),
        ),
        GroupCommands::Approve {
            options,
            challenge,
            challenge_file,
        } => approve_from_input(options, challenge.as_deref(), challenge_file.as_deref()),
        GroupCommands::OperationShow {
            options,
            operation_id,
        } => operation_show(options, &operation_id),
    }
}

fn list(options: GroupRootOptions) -> ExitCode {
    let (context, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let resolver = resolver(&context);
    let discovery = match discover_all(context.discovery_roots()) {
        Ok(discovery) => discovery,
        Err(error) => {
            return command_error_exit(options.json, "failed", &error.to_string());
        }
    };
    let (groups, warnings) = match resolver.list_views_with_warnings(&discovery) {
        Ok(result) => result,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"status": "ok", "groups": groups, "warnings": warnings})
            )
            .expect("group list JSON")
        );
    } else if groups.is_empty() {
        println!("No inventory groups are defined.");
    } else {
        for group in groups {
            println!(
                "{} state={:?} revision={} members={} compatible={}",
                group.qualified_name,
                group.observed_state(),
                group.revision,
                group.members.len(),
                group.context_compatible
            );
        }
    }
    if !options.json {
        for warning in warnings {
            eprintln!("warning: {}: {}", warning.code, warning.message);
        }
    }
    ExitCode::SUCCESS
}

fn show(options: GroupRootOptions, group: &str) -> ExitCode {
    let (context, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let reference = match GroupRef::parse(group) {
        Ok(reference) => reference,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let resolver = resolver(&context);
    let discovery = match discover_all(context.discovery_roots()) {
        Ok(discovery) => discovery,
        Err(error) => {
            return command_error_exit(options.json, "failed", &error.to_string());
        }
    };
    let view = match resolver.inspect(&reference, &discovery) {
        Ok(view) => view,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    render_json_or_debug(
        options.json,
        "group",
        serde_json::to_value(view).expect("group view JSON"),
    )
}

fn create(
    options: GroupRootOptions,
    scope: GroupScope,
    name: &str,
    member_selectors: &[String],
    write: DefinitionWriteOptions,
) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let definition = match parse_definition(name, member_selectors) {
        Ok(definition) => definition,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if let Err(error) = validate_new_group_members(&context, &definition, &BTreeSet::new()) {
        return command_error_exit(options.json, "blocked", &error.to_string());
    }
    let binding = match scope {
        GroupScope::Personal => context.binding_for_personal(&definition),
        GroupScope::Repository => context.binding_for_repository(&definition),
    };
    let fingerprint = match definition.revision(&binding) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if let Err(exit) = require_definition_apply(
        &options,
        &write,
        &fingerprint,
        json!({"change": "create", "scope": scope, "definition": definition}),
    ) {
        return exit;
    }
    if let Err(error) = require_write_sandbox(&options, &context, fixture_mode) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let store = match store_for_scope(&context, scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let result = match store.create(&definition, owner()) {
        Ok(result) => result,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "created",
        serde_json::to_value(result).expect("created group JSON"),
    )
}

fn edit(
    options: GroupRootOptions,
    group: &str,
    member_selectors: &[String],
    expected_revision: &str,
    write: DefinitionWriteOptions,
) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let reference = match qualified_reference(group) {
        Ok(reference) => reference,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let existing = match resolver(&context).resolve_definition(&reference) {
        Ok(record) => record,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let definition = match parse_definition(&existing.definition.name, member_selectors) {
        Ok(definition) => definition,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let retained = existing
        .definition
        .members
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if let Err(error) = validate_new_group_members(&context, &definition, &retained) {
        return command_error_exit(options.json, "blocked", &error.to_string());
    }
    let expected = match GroupRevision::parse(expected_revision) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let binding = match existing.scope {
        GroupScope::Personal => context.binding_for_personal(&definition),
        GroupScope::Repository => context.binding_for_repository(&definition),
    };
    let fingerprint = match definition.revision(&binding) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if let Err(exit) = require_definition_apply(
        &options,
        &write,
        &fingerprint,
        json!({"change": "edit", "before": existing, "after": definition}),
    ) {
        return exit;
    }
    if let Err(error) = require_write_sandbox(&options, &context, fixture_mode) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let store = match store_for_scope(&context, existing.scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let result = match store.replace(&definition, Some(&expected), owner()) {
        Ok(result) => result,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "updated",
        serde_json::to_value(result).expect("updated group JSON"),
    )
}

fn rename(
    options: GroupRootOptions,
    group: &str,
    new_name: &str,
    expected_revision: &str,
    write: DefinitionWriteOptions,
) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let reference = match qualified_reference(group) {
        Ok(reference) => reference,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let existing = match resolver(&context).resolve_definition(&reference) {
        Ok(record) => record,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let expected = match GroupRevision::parse(expected_revision) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let mut renamed = existing.definition.clone();
    renamed.name = new_name.to_string();
    if let Err(error) = renamed.canonicalize_and_validate() {
        return command_error_exit(options.json, "failed", &error.to_string());
    }
    let binding = match existing.scope {
        GroupScope::Personal => context.binding_for_personal(&renamed),
        GroupScope::Repository => context.binding_for_repository(&renamed),
    };
    let fingerprint = match renamed.revision(&binding) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if let Err(exit) = require_definition_apply(
        &options,
        &write,
        &fingerprint,
        json!({"change": "rename", "before": existing, "after": renamed}),
    ) {
        return exit;
    }
    if let Err(error) = require_write_sandbox(&options, &context, fixture_mode) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let store = match store_for_scope(&context, existing.scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let result = match store.rename(&existing.definition.name, new_name, &expected, owner()) {
        Ok(result) => result,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "renamed",
        serde_json::to_value(result).expect("renamed group JSON"),
    )
}

fn delete(
    options: GroupRootOptions,
    group: &str,
    expected_revision: &str,
    write: DefinitionWriteOptions,
) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let reference = match qualified_reference(group) {
        Ok(reference) => reference,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let existing = match resolver(&context).resolve_definition(&reference) {
        Ok(record) => record,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let expected = match GroupRevision::parse(expected_revision) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if let Err(exit) = require_definition_apply(
        &options,
        &write,
        &existing.revision,
        json!({"change": "delete", "before": existing}),
    ) {
        return exit;
    }
    if let Err(error) = require_write_sandbox(&options, &context, fixture_mode) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let store = match store_for_scope(&context, existing.scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let history = match store.delete(&existing.definition.name, &expected, owner()) {
        Ok(history) => history,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "deleted",
        serde_json::to_value(history).expect("deleted group history JSON"),
    )
}

fn history(options: GroupRootOptions, scope: GroupScope) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let store = match store_for_scope(&context, scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let records = match store.history() {
        Ok(records) => records,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "history",
        serde_json::to_value(records).expect("group history JSON"),
    )
}

fn restore_definition(
    options: GroupRootOptions,
    scope: GroupScope,
    history_id: &str,
    expected_revision: Option<&str>,
    write: DefinitionWriteOptions,
) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let expected = match expected_revision.map(GroupRevision::parse).transpose() {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let store = match store_for_scope(&context, scope, fixture_mode) {
        Ok(store) => store,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let history = match store
        .history()
        .map_err(|error| error.to_string())
        .and_then(|records| {
            records
                .into_iter()
                .find(|record| record.history_id == history_id)
                .ok_or_else(|| "group history record was not found".to_string())
        }) {
        Ok(history) => history,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let definition = match history.definition_before.as_ref() {
        Some(definition) => definition,
        None => {
            return command_error_exit(
                options.json,
                "blocked",
                "history record has no prior definition",
            );
        }
    };
    let binding = match scope {
        GroupScope::Personal => context.binding_for_personal(definition),
        GroupScope::Repository => context.binding_for_repository(definition),
    };
    let fingerprint = match definition.revision(&binding) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    if let Err(exit) = require_definition_apply(
        &options,
        &write,
        &fingerprint,
        json!({"change": "restore-definition", "history": history}),
    ) {
        return exit;
    }
    if let Err(error) = require_write_sandbox(&options, &context, fixture_mode) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let result = match store.restore(history_id, expected.as_ref(), owner()) {
        Ok(result) => result,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    render_json_or_debug(
        options.json,
        "restored",
        serde_json::to_value(result).expect("restored group JSON"),
    )
}

fn plan(
    options: GroupRootOptions,
    group: &str,
    target: GroupTargetState,
    max_members: usize,
    reach: Option<ProviderReachArg>,
    selected_provider: Option<&str>,
) -> ExitCode {
    let (context, _) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let reference = match GroupRef::parse(group) {
        Ok(reference) => reference,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let selected_provider = match selected_provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => Some(provider),
            None => {
                return crate::command_error_exit_code(
                    options.json,
                    "blocked",
                    "unsupported selected provider",
                    3,
                );
            }
        },
        None => None,
    };
    let reach_input = match reach {
        Some(reach) => match reach.input(selected_provider) {
            Ok(reach) => reach,
            Err(error) => {
                return crate::command_error_exit_code(options.json, "blocked", &error, 3);
            }
        },
        None => unpin_core::provider_reach::ProviderReachInput::Omitted,
    };
    let mut reach_request = ProviderReachRequest::new(
        ConnectionBoundary::All,
        reach_input,
        DerivedTargetKind::Group,
    );
    if let Some(provider) = selected_provider {
        reach_request = reach_request.with_authority(SelectedProviderAuthority::new(
            provider,
            SelectedProviderProvenance::ExplicitInput,
        ));
    }
    let plan = match GroupPlanner::new(resolver(&context)).plan_with_provider_reach_request(
        &reference,
        target,
        max_members,
        GroupPlanMode::PreviewOnly,
        reach_request,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return crate::command_error_exit_code(options.json, "blocked", &error.to_string(), 3);
        }
    };
    let exit = group_reach_lifecycle_exit(plan.lifecycle);
    let rendered = render_json_or_debug(
        options.json,
        "plan",
        serde_json::to_value(plan).expect("group plan JSON"),
    );
    if rendered == ExitCode::SUCCESS {
        exit
    } else {
        rendered
    }
}

fn group_reach_lifecycle_exit(lifecycle: ProviderReachLifecycle) -> ExitCode {
    ExitCode::from(match lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::NoOp => 0,
        ProviderReachLifecycle::Partial => 2,
        ProviderReachLifecycle::Blocked | ProviderReachLifecycle::NoTargetsInProviderReach => 3,
        ProviderReachLifecycle::RecoveryRequired => 4,
    })
}

fn approve(options: GroupRootOptions, challenge: &str) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let app_state_root = if fixture_mode {
        match std::fs::canonicalize(context.app_state_root()) {
            Ok(root) => root,
            Err(error) => {
                return command_error_exit(
                    options.json,
                    "failed",
                    &format!("fixture state root could not be resolved: {error}"),
                );
            }
        }
    } else {
        context.app_state_root().to_path_buf()
    };
    let session_key =
        match crate::credentials::resolve_session_authority_key(fixture_mode, &app_state_root) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return command_error_exit(
                    options.json,
                    "failed",
                    "session authority credential is unavailable",
                );
            }
            Err(error) => return command_error_exit(options.json, "failed", &error),
        };
    let now_unix = match current_unix_seconds() {
        Ok(now) => now,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    let claims = match authenticate_group_approval_challenge(challenge, &session_key) {
        Ok(claims) => claims,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    if claims.session.binding.repository_key != context.repository_key()
        || claims.session.binding.workspace_key != context.workspace_key()
    {
        return command_error_exit(
            options.json,
            "blocked",
            "inventory group approval context does not match this workspace",
        );
    }
    let lease_expires_at = match McpGroupSessionLeaseStore::new(&app_state_root).verify(
        &claims.session,
        &session_key,
        now_unix,
    ) {
        Ok(expires_at) => expires_at,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    if let Err(error) = claims.verify(&claims.session, lease_expires_at, now_unix) {
        return command_error_exit(options.json, "blocked", &error.to_string());
    }
    let approval_context =
        match ControlApprovalContext::new(context.repository_key(), context.workspace_key()) {
            Ok(context) => context,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        };
    let expectation = match claims.plan.approval_expectation(&approval_context) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    let approval = match crate::credentials::issue_inventory_group_approval(
        fixture_mode,
        &app_state_root,
        &expectation,
        &claims.plan,
        now_unix,
    ) {
        Ok(approval) => approval,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let artifact = match GroupApprovalArtifactStore::new(&app_state_root).issue(
        claims.session,
        &claims.plan,
        challenge,
        approval.receipt().clone(),
        &session_key,
        now_unix,
    ) {
        Ok(artifact) => artifact,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    render_json_or_debug(
        options.json,
        "approved",
        json!({
            "operationId": artifact.operation_id,
            "planFingerprint": artifact.plan_fingerprint,
            "approvalArtifact": artifact.artifact_id,
            "expiresAtUnix": artifact.expires_at_unix,
        }),
    )
}

fn approve_from_input(
    options: GroupRootOptions,
    challenge: Option<&str>,
    challenge_file: Option<&Path>,
) -> ExitCode {
    let challenge = match read_approval_challenge(challenge, challenge_file) {
        Ok(challenge) => challenge,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    approve(options, &challenge)
}

fn read_approval_challenge(
    challenge: Option<&str>,
    challenge_file: Option<&Path>,
) -> Result<String, String> {
    if let Some(challenge) = challenge {
        return Ok(challenge.to_string());
    }
    let path = challenge_file.ok_or_else(|| "inventory group challenge is required".to_string())?;
    let limit = unpin_core::groups::MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES;
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!("inventory group challenge stdin could not be read: {error}")
            })?;
    } else {
        std::fs::File::open(path)
            .map_err(|error| {
                format!(
                    "inventory group challenge file could not be opened: {}: {error}",
                    path.display()
                )
            })?
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!(
                    "inventory group challenge file could not be read: {}: {error}",
                    path.display()
                )
            })?;
    }
    if bytes.len() > limit {
        return Err("inventory group challenge input is too large".to_string());
    }
    let challenge = String::from_utf8(bytes)
        .map_err(|_| "inventory group challenge input is not valid UTF-8".to_string())?;
    let challenge = challenge.trim();
    if challenge.is_empty() {
        return Err("inventory group challenge input is empty".to_string());
    }
    Ok(challenge.to_string())
}

fn operation_show(options: GroupRootOptions, operation_id: &str) -> ExitCode {
    let (context, fixture_mode) = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let backup_authentication_key = match crate::credentials::resolve_backup_authentication_key(
        fixture_mode,
        context.app_state_root(),
    ) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return command_error_exit(
                options.json,
                "failed",
                "backup authentication credential is unavailable",
            );
        }
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let inspection = match load_group_operation_inspection(
        context.app_state_root(),
        backup_authentication_key,
        operation_id,
        context.repository_key(),
        context.workspace_key(),
    ) {
        Ok(Some(inspection)) => inspection,
        Ok(None) => {
            return command_error_exit(options.json, "failed", "group operation was not found");
        }
        Err(error) => return command_error_exit(options.json, "blocked", &error.to_string()),
    };
    render_json_or_debug(
        options.json,
        "operation",
        serde_json::to_value(inspection).expect("group operation inspection JSON"),
    )
}

fn context(options: &GroupRootOptions) -> Result<(GroupAccessContext, bool), String> {
    let fixture_mode = options.roots.fixture_root.is_some();
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let roots = resolve_discovery_roots_with_config(&options.roots, &config)?
        .with_app_state_root(&config.app_state_root);
    GroupAccessContext::from_config(&config, &roots, None, None)
        .map(|context| (context, fixture_mode))
        .map_err(|error| error.to_string())
}

fn resolver(context: &GroupAccessContext) -> GroupResolver {
    GroupResolver::new(
        context.clone(),
        PersonalGroupStore::new(context.clone()),
        RepositoryGroupStore::new(context.clone()),
    )
}

fn store_for_scope(
    context: &GroupAccessContext,
    scope: GroupScope,
    fixture_mode: bool,
) -> Result<ScopedGroupStore, String> {
    let authentication_key = crate::credentials::resolve_backup_authentication_key(
        fixture_mode,
        context.app_state_root(),
    )?
    .ok_or_else(|| "backup authentication key missing; run `unpin auth backup init`".to_string())?;
    Ok(match scope {
        GroupScope::Personal => ScopedGroupStore::Personal(
            PersonalGroupStore::new(context.clone())
                .with_history_authentication_key(authentication_key),
        ),
        GroupScope::Repository => ScopedGroupStore::Repository(
            RepositoryGroupStore::new(context.clone())
                .with_history_authentication_key(authentication_key),
        ),
    })
}

fn parse_definition(name: &str, members: &[String]) -> Result<GroupDefinitionV1, String> {
    members
        .iter()
        .map(|member| parse_member(member))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|members| {
            GroupDefinitionV1::new(name, members).map_err(|error| error.to_string())
        })
}

fn parse_member(value: &str) -> Result<GroupMemberIdentity, String> {
    let fields = value.splitn(5, ':').collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err("member must use provider:layer:kind:category:id full identity".to_string());
    }
    let provider =
        parse_provider_id(fields[0]).ok_or_else(|| "unsupported provider".to_string())?;
    let layer = match fields[1] {
        "global" => DiscoveryLayer::Global,
        "project" => DiscoveryLayer::Project,
        _ => return Err("unsupported member layer".to_string()),
    };
    let kind = match fields[2] {
        "skill" => DiscoveryKind::Skill,
        "mcp" => DiscoveryKind::Mcp,
        "plugin" => DiscoveryKind::Plugin,
        "agent" => DiscoveryKind::Agent,
        "hook" => DiscoveryKind::Hook,
        "setting" => DiscoveryKind::Setting,
        _ => return Err("unsupported member kind".to_string()),
    };
    let category = match fields[3] {
        "skill" => DiscoveryCategory::Skill,
        "configured-mcp" => DiscoveryCategory::ConfiguredMcp,
        "tool" => DiscoveryCategory::Tool,
        "agent" => DiscoveryCategory::Agent,
        "hook" => DiscoveryCategory::Hook,
        "provider-setting" => DiscoveryCategory::ProviderSetting,
        "plugin-config" => DiscoveryCategory::PluginConfig,
        "plugin-manifest" => DiscoveryCategory::PluginManifest,
        _ => return Err("unsupported member category".to_string()),
    };
    GroupMemberIdentity::new(provider, kind, category, layer, fields[4])
        .map_err(|error| error.to_string())
}

fn qualified_reference(value: &str) -> Result<GroupRef, String> {
    let reference = GroupRef::parse(value).map_err(|error| error.to_string())?;
    if reference.scope.is_none() {
        return Err("definition mutation requires personal:name or repository:name".to_string());
    }
    Ok(reference)
}

fn require_definition_apply(
    options: &GroupRootOptions,
    write: &DefinitionWriteOptions,
    fingerprint: &GroupRevision,
    preview: serde_json::Value,
) -> Result<(), ExitCode> {
    let plan_fingerprint = group_definition_change_fingerprint(fingerprint, &preview);
    if !write.apply {
        if options.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "planned",
                    "planFingerprint": plan_fingerprint,
                    "preview": preview,
                    "humanAction": {
                        "code": "confirm-definition-change",
                        "guidance": "Re-run with --apply --confirm and this plan fingerprint."
                    }
                }))
                .expect("group definition preview JSON")
            );
        } else {
            println!("planned group definition change fingerprint={plan_fingerprint}");
        }
        return Err(ExitCode::SUCCESS);
    }
    if !write.confirm {
        return Err(command_error_exit(
            options.json,
            "blocked",
            "confirmation-required",
        ));
    }
    if write.plan_fingerprint.as_deref() != Some(plan_fingerprint.as_str()) {
        return Err(command_error_exit(
            options.json,
            "blocked",
            "plan-fingerprint-mismatch",
        ));
    }
    Ok(())
}

fn require_write_sandbox(
    _options: &GroupRootOptions,
    context: &GroupAccessContext,
    fixture_mode: bool,
) -> Result<(), String> {
    unpin_core::fixture::require_fixture_write_sandbox(
        fixture_mode,
        [context.app_state_root(), context.workspace_root()],
    )
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new(unpin_core::groups::GROUP_DEFINITION_OWNER_ID, 1)
        .expect("static owner is valid")
}

fn render_json_or_debug(json_output: bool, status: &str, value: serde_json::Value) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": status, "result": value}))
                .expect("group command JSON")
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("group human rendering")
        );
    }
    ExitCode::SUCCESS
}
