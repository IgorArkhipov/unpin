use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER,
    },
    catalog::Catalog,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    discovery::discover_all,
    profiles::{
        CapabilityLockSnapshot, PolicyStore, PolicyTarget, ProfileDefinitionEntry,
        ProfileSourceScope, ProfileStore, compile_profile,
    },
    providers::ProviderId,
    sessions::WorkflowReloadLimitation,
    state::{
        atomic_json::{OwnerGeneration, StateRevision},
        workspace::WorkspaceIdentity,
    },
    transitions::EffectActivation,
    workflows::{
        CompiledWorkflowRevision, WorkflowDefinition, WorkflowDefinitionEntry, WorkflowStore,
        compile_workflow,
    },
};

use crate::{
    DiscoveryRootArgs, command_error_exit, credentials, parse_provider_id, resolve_config,
    resolve_discovery_roots_with_config, unix_now,
};

#[derive(Debug, Clone, Args)]
pub(crate) struct WorkflowRootOptions {
    #[command(flatten)]
    pub(crate) roots: DiscoveryRootArgs,
    /// Unpin-owned state root containing global workflows and revisions.
    #[arg(long)]
    pub(crate) app_state_root: Option<PathBuf>,
    /// Render machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WorkflowScopeArg {
    Auto,
    Global,
    Workspace,
}

impl WorkflowScopeArg {
    const fn allows_workspace(self) -> bool {
        matches!(self, Self::Auto | Self::Workspace)
    }

    const fn allows_global(self) -> bool {
        matches!(self, Self::Auto | Self::Global)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WorkflowMutationActionArg {
    Upsert,
    Delete,
}

#[derive(Debug, Subcommand)]
pub(crate) enum WorkflowCommands {
    /// List global and workspace workflow definitions.
    List(WorkflowRootOptions),
    /// Show one workflow definition using workspace-over-global precedence.
    Show {
        #[command(flatten)]
        options: WorkflowRootOptions,
        /// Workflow id.
        id: String,
        /// Definition scope to inspect.
        #[arg(long, value_enum, default_value_t = WorkflowScopeArg::Auto)]
        scope: WorkflowScopeArg,
    },
    /// Validate one stored or standalone workflow definition against profiles,
    /// the current catalog, and provider capability locks.
    Validate {
        #[command(flatten)]
        options: WorkflowRootOptions,
        /// Stored workflow id. Conflicts with --file.
        #[arg(long, conflicts_with = "file")]
        id: Option<String>,
        /// Standalone workflow definition JSON. .env files are rejected.
        #[arg(long, conflicts_with = "id")]
        file: Option<PathBuf>,
        /// Source scope assigned to --file definitions.
        #[arg(long, value_enum, default_value_t = WorkflowScopeArg::Workspace)]
        scope: WorkflowScopeArg,
        /// Provider to validate. Omit to validate all providers.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Propose a metadata-only workflow launch without changing state.
    Propose {
        #[command(flatten)]
        options: WorkflowRootOptions,
        /// Prompt text used only for local metadata matching; output contains its digest, not body.
        #[arg(long)]
        prompt: String,
        /// Provider context for a concrete proposal. Omit to request provider selection.
        #[arg(long)]
        provider: Option<String>,
    },
    /// Plan a reviewed global workflow definition upsert or delete.
    Plan {
        #[command(flatten)]
        options: WorkflowRootOptions,
        /// Existing workflow id, or id to require when --file is supplied.
        #[arg(long)]
        id: Option<String>,
        /// Standalone workflow definition JSON for an upsert.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Definition mutation to review.
        #[arg(long, value_enum, default_value_t = WorkflowMutationActionArg::Upsert)]
        action: WorkflowMutationActionArg,
        /// Definition scope. Mutations are global-only; workspace files are fixed-source.
        #[arg(long, value_enum, default_value_t = WorkflowScopeArg::Global)]
        scope: WorkflowScopeArg,
    },
    /// Apply a matching reviewed global workflow definition plan.
    Apply {
        #[command(flatten)]
        options: WorkflowRootOptions,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = WorkflowMutationActionArg::Upsert)]
        action: WorkflowMutationActionArg,
        #[arg(long, value_enum, default_value_t = WorkflowScopeArg::Global)]
        scope: WorkflowScopeArg,
        /// Explicit confirmation required with --apply.
        #[arg(long)]
        confirm: bool,
        /// Fingerprint emitted by the matching dry-run plan.
        #[arg(long)]
        plan_fingerprint: Option<String>,
        /// Read a signed operator receipt from this already-open descriptor.
        #[arg(long)]
        operator_credential_fd: Option<i32>,
    },
    /// Delete one reviewed global workflow definition.
    Delete {
        #[command(flatten)]
        options: WorkflowRootOptions,
        #[arg(long)]
        id: String,
        #[arg(long, value_enum, default_value_t = WorkflowScopeArg::Global)]
        scope: WorkflowScopeArg,
        /// Apply the reviewed deletion. Omit for a dry-run plan.
        #[arg(long)]
        apply: bool,
        #[arg(long, requires = "apply")]
        confirm: bool,
        #[arg(long, requires = "apply")]
        plan_fingerprint: Option<String>,
        #[arg(long)]
        operator_credential_fd: Option<i32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkflowDefinitionPlan {
    schema_version: u32,
    operation_id: String,
    operation_kind: String,
    action: WorkflowMutationActionArg,
    workflow_id: String,
    scope: ProfileSourceScope,
    definition_digest: Option<String>,
    expected_revision: Option<StateRevision>,
    plan_fingerprint: String,
    activation: String,
    human_approval_required: bool,
}

#[derive(Debug)]
struct WorkflowContext {
    config: unpin_core::config::UnpinConfig,
    store: WorkflowStore,
    profiles: ProfileStore,
    identity: WorkspaceIdentity,
}

pub(crate) fn run(command: WorkflowCommands) -> ExitCode {
    match command {
        WorkflowCommands::List(options) => list(options),
        WorkflowCommands::Show { options, id, scope } => show(options, &id, scope),
        WorkflowCommands::Validate {
            options,
            id,
            file,
            scope,
            provider,
        } => validate(
            options,
            id.as_deref(),
            file.as_deref(),
            scope,
            provider.as_deref(),
        ),
        WorkflowCommands::Propose {
            options,
            prompt,
            provider,
        } => propose(options, &prompt, provider.as_deref()),
        WorkflowCommands::Plan {
            options,
            id,
            file,
            action,
            scope,
        } => mutation(
            options,
            id.as_deref(),
            file.as_deref(),
            action,
            scope,
            false,
            false,
            None,
            None,
        ),
        WorkflowCommands::Apply {
            options,
            id,
            file,
            action,
            scope,
            confirm,
            plan_fingerprint,
            operator_credential_fd,
        } => mutation(
            options,
            id.as_deref(),
            file.as_deref(),
            action,
            scope,
            true,
            confirm,
            plan_fingerprint.as_deref(),
            operator_credential_fd,
        ),
        WorkflowCommands::Delete {
            options,
            id,
            scope,
            apply,
            confirm,
            plan_fingerprint,
            operator_credential_fd,
        } => mutation(
            options,
            Some(&id),
            None,
            WorkflowMutationActionArg::Delete,
            scope,
            apply,
            confirm,
            plan_fingerprint.as_deref(),
            operator_credential_fd,
        ),
    }
}

fn context(options: &WorkflowRootOptions) -> Result<WorkflowContext, String> {
    let config = resolve_config(&options.roots, options.app_state_root.clone())?;
    let identity = config
        .workspace_identity()
        .map_err(|error| error.to_string())?;
    Ok(WorkflowContext {
        store: WorkflowStore::new(&config.app_state_root),
        profiles: ProfileStore::new(&config.app_state_root),
        config,
        identity,
    })
}

fn list(options: WorkflowRootOptions) -> ExitCode {
    let context = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let mut workflows = match context.store.list_global_definitions() {
        Ok(workflows) => workflows,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    match WorkflowStore::list_workspace_definitions(&context.config.project_root) {
        Ok(mut workspace) => workflows.append(&mut workspace),
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    }
    workflows.sort_by(|left, right| {
        (left.definition.id.as_str(), left.scope).cmp(&(right.definition.id.as_str(), right.scope))
    });
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status":"ok","workflows":workflows}))
                .expect("workflow inventory JSON")
        );
    } else if workflows.is_empty() {
        println!("No workflows.");
    } else {
        for workflow in workflows {
            println!(
                "{} {:?} {} modes={}",
                workflow.definition.id,
                workflow.scope,
                workflow.definition.display_name,
                workflow.definition.modes.len()
            );
        }
    }
    ExitCode::SUCCESS
}

fn show(options: WorkflowRootOptions, id: &str, scope: WorkflowScopeArg) -> ExitCode {
    let context = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let workflow = match load_definition(&context, id, scope) {
        Ok(Some(workflow)) => workflow,
        Ok(None) => return command_error_exit(options.json, "failed", "workflow not found"),
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status":"ok","workflow":workflow}))
                .expect("workflow JSON")
        );
    } else {
        println!(
            "{} ({:?})\n  name: {}\n  baseline: {}\n  entry: {}\n  modes: {}",
            workflow.definition.id,
            workflow.scope,
            workflow.definition.display_name,
            workflow.definition.baseline_profile_id,
            workflow.definition.entry_mode,
            workflow.definition.modes.len()
        );
    }
    ExitCode::SUCCESS
}

fn validate(
    options: WorkflowRootOptions,
    id: Option<&str>,
    file: Option<&Path>,
    scope: WorkflowScopeArg,
    provider: Option<&str>,
) -> ExitCode {
    if id.is_none() == file.is_none() {
        return command_error_exit(
            options.json,
            "failed",
            "provide exactly one of --id or --file",
        );
    }
    let context = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let (definition, source_scope) = if let Some(id) = id {
        match load_definition(&context, id, scope) {
            Ok(Some(entry)) => (entry.definition, entry.scope),
            Ok(None) => return command_error_exit(options.json, "failed", "workflow not found"),
            Err(error) => return command_error_exit(options.json, "failed", &error),
        }
    } else {
        let file = file.expect("file is present after validation");
        if file
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".env"))
        {
            return command_error_exit(options.json, "failed", ".env workflow input is forbidden");
        }
        let raw = match fs::read_to_string(file) {
            Ok(raw) => raw,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        };
        let definition = match WorkflowDefinition::from_json(&raw) {
            Ok(definition) => definition,
            Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
        };
        let source_scope = if scope == WorkflowScopeArg::Global {
            ProfileSourceScope::Global
        } else {
            ProfileSourceScope::Workspace
        };
        (definition, source_scope)
    };
    let discovery = match discovery(options.roots.clone(), &context.config) {
        Ok(discovery) => discovery,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let providers = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => vec![provider],
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => ProviderId::ALL.to_vec(),
    };
    let mut revisions = Vec::new();
    for provider in providers {
        match compile_revision(&context, &definition, source_scope, provider, &discovery) {
            Ok(revision) => revisions.push(json!({
                "provider": provider,
                "workflowRevision": revision.digest,
                "capabilityCount": revision.maximum_envelope.authored_member_count,
                "systemControls": revision.system_controls,
                "baselineProfileDigest": revision.baseline_profile_digest,
                "maximumEnvelopeDigest": revision.maximum_envelope.digest,
            })),
            Err(error) => {
                return command_error_exit(options.json, "failed", &error);
            }
        }
    }
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status":"valid",
                "workflow": definition,
                "revisions": revisions,
            }))
            .expect("workflow validation JSON")
        );
    } else {
        println!(
            "valid workflow {} providers={} entry={} modes={}",
            definition.id,
            revisions.len(),
            definition.entry_mode,
            definition.modes.len()
        );
    }
    ExitCode::SUCCESS
}

fn propose(options: WorkflowRootOptions, prompt: &str, provider: Option<&str>) -> ExitCode {
    let provider = match provider {
        Some(provider) => match parse_provider_id(provider) {
            Some(provider) => Some(provider),
            None => return command_error_exit(options.json, "failed", "unsupported provider"),
        },
        None => None,
    };
    let context = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let mut workflows = match context.store.list_global_definitions() {
        Ok(workflows) => workflows,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    match WorkflowStore::list_workspace_definitions(&context.config.project_root) {
        Ok(mut workspace) => workflows.append(&mut workspace),
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    }
    let prompt_terms = text_terms(prompt);
    if prompt_terms.is_empty() {
        return command_error_exit(
            options.json,
            "failed",
            "workflow proposal prompt has no routable terms",
        );
    }
    workflows.sort_by(|left, right| {
        workflow_score(right, &prompt_terms)
            .cmp(&workflow_score(left, &prompt_terms))
            .then_with(|| left.definition.id.cmp(&right.definition.id))
    });
    let candidates = workflows
        .iter()
        .take(20)
        .map(|entry| {
            json!({
                "workflowId": entry.definition.id,
                "displayName": entry.definition.display_name,
                "scope": entry.scope,
                "score": workflow_score(entry, &prompt_terms),
                "entryMode": entry.definition.entry_mode,
            })
        })
        .collect::<Vec<_>>();
    let Some(entry) = workflows.first() else {
        return render_proposal(
            &options,
            "selection-required",
            json!({
                "schemaVersion": 1,
                "promptDigest": digest(prompt.as_bytes()),
                "provider": provider,
                "candidates": candidates,
                "recommended": null,
                "confirmationRequired": true,
                "mutatesState": false,
            }),
        );
    };
    let Some(provider) = provider else {
        return render_proposal(
            &options,
            "selection-required",
            json!({
                "schemaVersion": 1,
                "promptDigest": digest(prompt.as_bytes()),
                "provider": null,
                "candidates": candidates,
                "recommended": null,
                "confirmationRequired": true,
                "mutatesState": false,
                "nextAction": "select-provider-and-workflow",
            }),
        );
    };
    let discovery = match discovery(options.roots.clone(), &context.config) {
        Ok(discovery) => discovery,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let revision = match compile_revision(
        &context,
        &entry.definition,
        entry.scope,
        provider,
        &discovery,
    ) {
        Ok(revision) => revision,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let catalog_revision = catalog_digest(&discovery.catalog);
    let proposal = match unpin_core::sessions::WorkflowProposalV1::new(
        entry.definition.id.clone(),
        entry.definition.entry_mode.clone(),
        provider,
        context.identity.repository_key.clone(),
        context.identity.workspace_key.clone(),
        catalog_revision,
        revision.digest.clone(),
        prompt,
        revision.maximum_envelope.authored_member_count,
        true,
        WorkflowReloadLimitation::LiveRefreshExpected,
    ) {
        Ok(proposal) => proposal,
        Err(error) => return command_error_exit(options.json, "failed", &error.to_string()),
    };
    render_proposal(
        &options,
        "proposed",
        json!({
            "proposal": proposal,
            "candidates": candidates,
            "humanAction": {
                "code": "confirm-workflow-session",
                "guidance": "Choose this workflow explicitly when launching a session; this proposal never changes active exposure.",
            },
        }),
    )
}

fn render_proposal(
    options: &WorkflowRootOptions,
    status: &str,
    proposal: serde_json::Value,
) -> ExitCode {
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status": status, "proposal": proposal}))
                .expect("workflow proposal JSON")
        );
    } else {
        println!("workflow proposal {status}; confirmation required");
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn mutation(
    options: WorkflowRootOptions,
    id: Option<&str>,
    file: Option<&Path>,
    action: WorkflowMutationActionArg,
    scope: WorkflowScopeArg,
    apply: bool,
    confirm: bool,
    reviewed_fingerprint: Option<&str>,
    operator_credential_fd: Option<i32>,
) -> ExitCode {
    if !scope.allows_global() || scope == WorkflowScopeArg::Workspace {
        return command_error_exit(
            options.json,
            "blocked",
            "workflow definition mutation is global-only; workspace definitions are fixed-source",
        );
    }
    if action == WorkflowMutationActionArg::Upsert && id.is_none() && file.is_none() {
        return command_error_exit(options.json, "failed", "upsert requires --file or --id");
    }
    if action == WorkflowMutationActionArg::Delete && id.is_none() {
        return command_error_exit(options.json, "failed", "delete requires --id");
    }
    let context = match context(&options) {
        Ok(context) => context,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let (plan, definition, current_owner_generation) = match build_plan(&context, id, file, action)
    {
        Ok(value) => value,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    let expectation = match mutation_expectation(&plan, &context.identity) {
        Ok(expectation) => expectation,
        Err(error) => return command_error_exit(options.json, "failed", &error),
    };
    if !apply {
        return render_mutation_plan(&options, &plan, &expectation);
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
            context.config.app_state_root.as_path(),
            context.config.project_root.as_path(),
        ],
    ) {
        return command_error_exit(options.json, "blocked", &error);
    }
    let authorization = match operator_credential_fd {
        Some(descriptor) => credentials::authorize_operator_descriptor(
            options.roots.fixture_root.is_some(),
            &context.config.app_state_root,
            &expectation,
            &plan.plan_fingerprint,
            reviewed_fingerprint,
            "unpin-cli-workflow-definition",
            unix_now(),
            descriptor,
        ),
        None => credentials::authorize_reviewed_control_decision(
            options.roots.fixture_root.is_some(),
            &context.config.app_state_root,
            &expectation,
            &plan.plan_fingerprint,
            reviewed_fingerprint,
            "unpin-cli-workflow-definition",
            unix_now(),
        ),
    };
    let authorization = match authorization {
        Ok(authorization) => authorization,
        Err(error) => return command_error_exit(options.json, "blocked", &error),
    };
    let result = match action {
        WorkflowMutationActionArg::Upsert => {
            let definition = definition.expect("upsert plan has definition");
            let generation = match current_owner_generation.checked_add(1) {
                Some(generation) => generation,
                None => {
                    return command_error_exit(
                        options.json,
                        "recovery-required",
                        "workflow owner generation overflow",
                    );
                }
            };
            let owner = match OwnerGeneration::new(plan.operation_id.clone(), generation) {
                Ok(owner) => owner,
                Err(error) => {
                    return command_error_exit(options.json, "blocked", &error.to_string());
                }
            };
            match context.store.save_global_definition(
                &definition,
                plan.expected_revision.as_ref(),
                owner,
            ) {
                Ok(revision) => json!({"revision": revision, "definition": definition}),
                Err(error) => {
                    return command_error_exit(
                        options.json,
                        "recovery-required",
                        &error.to_string(),
                    );
                }
            }
        }
        WorkflowMutationActionArg::Delete => {
            let expected = plan.expected_revision.as_ref().expect("delete revision");
            if let Err(error) = context
                .store
                .delete_global_definition(&plan.workflow_id, expected)
            {
                return command_error_exit(options.json, "recovery-required", &error.to_string());
            }
            json!({"workflowId": plan.workflow_id, "deleted": true})
        }
    };
    let operation = ControlOperationEnvelope::from_expectation(
        &expectation,
        &plan.plan_fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Applied,
        None,
        false,
        Vec::new(),
        json!({"result": result, "decisionDigest": authorization.decision_digest()}),
    );
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "applied",
                "operation": operation,
                "planFingerprint": plan.plan_fingerprint,
                "result": result,
            }))
            .expect("workflow mutation JSON")
        );
    } else {
        println!(
            "workflow {} applied; activation=next-session-only",
            plan.workflow_id
        );
    }
    ExitCode::SUCCESS
}

fn build_plan(
    context: &WorkflowContext,
    id: Option<&str>,
    file: Option<&Path>,
    action: WorkflowMutationActionArg,
) -> Result<(WorkflowDefinitionPlan, Option<WorkflowDefinition>, u64), String> {
    let (workflow_id, definition, expected_revision, current_owner_generation) = match action {
        WorkflowMutationActionArg::Upsert => {
            let definition = if let Some(file) = file {
                if file
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".env"))
                {
                    return Err(".env workflow input is forbidden".to_string());
                }
                let raw = fs::read_to_string(file).map_err(|error| error.to_string())?;
                WorkflowDefinition::from_json(&raw).map_err(|error| error.to_string())?
            } else {
                let id = id.ok_or_else(|| "upsert requires --file or --id".to_string())?;
                context
                    .store
                    .load_global_definition(id)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "workflow not found".to_string())?
                    .value
            };
            if let Some(id) = id
                && id != definition.id
            {
                return Err("workflow id does not match definition id".to_string());
            }
            let snapshot = context
                .store
                .load_global_definition(&definition.id)
                .map_err(|error| error.to_string())?;
            (
                definition.id.clone(),
                Some(definition),
                snapshot.as_ref().map(|snapshot| snapshot.revision.clone()),
                snapshot.map_or(0, |snapshot| snapshot.owner.generation),
            )
        }
        WorkflowMutationActionArg::Delete => {
            let id = id.ok_or_else(|| "delete requires --id".to_string())?;
            let snapshot = context
                .store
                .load_global_definition(id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "workflow not found".to_string())?;
            (
                id.to_string(),
                None,
                Some(snapshot.revision),
                snapshot.owner.generation,
            )
        }
    };
    let definition_digest = definition
        .as_ref()
        .map(|definition| {
            definition
                .definition_digest()
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    let action_text = match action {
        WorkflowMutationActionArg::Upsert => "upsert",
        WorkflowMutationActionArg::Delete => "delete",
    };
    let fingerprint = digest(
        &serde_json::to_vec(&(
            1_u32,
            action_text,
            &workflow_id,
            &definition_digest,
            &expected_revision,
        ))
        .map_err(|error| error.to_string())?,
    );
    let operation_id = format!("workflow-definition-{}", &fingerprint[..24]);
    Ok((
        WorkflowDefinitionPlan {
            schema_version: 1,
            operation_id,
            operation_kind: "workflow-definition".to_string(),
            action,
            workflow_id,
            scope: ProfileSourceScope::Global,
            definition_digest,
            expected_revision,
            plan_fingerprint: fingerprint,
            activation: "next-session-only".to_string(),
            human_approval_required: true,
        },
        definition,
        current_owner_generation,
    ))
}

fn mutation_expectation(
    plan: &WorkflowDefinitionPlan,
    identity: &WorkspaceIdentity,
) -> Result<ApprovalExpectation, String> {
    let resource_fingerprint = plan
        .expected_revision
        .as_ref()
        .map(|revision| digest(revision.fingerprint.as_bytes()));
    Ok(ApprovalExpectation {
        issuer: CONTROL_APPROVAL_ISSUER.to_string(),
        audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
        operation_id: plan.operation_id.clone(),
        operation_kind: plan.operation_kind.clone(),
        effect_graph_digest: plan.plan_fingerprint.clone(),
        repository_key: identity.repository_key.clone(),
        workspace_key: identity.workspace_key.clone(),
        session_id: None,
        profile_digest: plan.definition_digest.clone(),
        resources: vec![ApprovalResourceBinding {
            resource_id: format!("workflow-definition-{}", plan.workflow_id),
            pre_state_fingerprint: resource_fingerprint,
        }],
    })
}

fn render_mutation_plan(
    options: &WorkflowRootOptions,
    plan: &WorkflowDefinitionPlan,
    expectation: &ApprovalExpectation,
) -> ExitCode {
    let operation = ControlOperationEnvelope::from_expectation(
        expectation,
        &plan.plan_fingerprint,
        EffectActivation::NextSessionOnly,
        ControlOperationLifecycle::Planned,
        Some(ControlHumanAction {
            code: "confirm-and-apply".to_string(),
            guidance: "Re-run with --apply --confirm and this plan fingerprint.".to_string(),
        }),
        true,
        Vec::new(),
        json!({"plan": workflow_plan_value(plan)}),
    );
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "planned",
                "operation": operation,
                "plan": workflow_plan_value(plan),
            }))
            .expect("workflow plan JSON")
        );
    } else {
        println!(
            "workflow {} planned action={:?} fingerprint={}",
            plan.workflow_id, plan.action, plan.plan_fingerprint
        );
    }
    ExitCode::SUCCESS
}

fn load_definition(
    context: &WorkflowContext,
    id: &str,
    scope: WorkflowScopeArg,
) -> Result<Option<WorkflowDefinitionEntry>, String> {
    if scope.allows_workspace()
        && let Some(workflow) =
            WorkflowStore::load_workspace_definition(&context.config.project_root, id)
                .map_err(|error| error.to_string())?
    {
        return Ok(Some(workflow));
    }
    if scope.allows_global()
        && let Some(snapshot) = context
            .store
            .load_global_definition(id)
            .map_err(|error| error.to_string())?
    {
        return Ok(Some(WorkflowDefinitionEntry {
            scope: ProfileSourceScope::Global,
            definition: snapshot.value,
            revision: Some(snapshot.revision),
        }));
    }
    Ok(None)
}

fn discovery(
    roots: DiscoveryRootArgs,
    config: &unpin_core::config::UnpinConfig,
) -> Result<DiscoveryContext, String> {
    let roots = resolve_discovery_roots_with_config(&roots, config)?
        .with_app_state_root(&config.app_state_root);
    let output = discover_all(&roots).map_err(|error| error.to_string())?;
    let catalog = Catalog::from_discovery(&output).map_err(|error| error.to_string())?;
    Ok(DiscoveryContext { catalog })
}

#[derive(Debug)]
struct DiscoveryContext {
    catalog: Catalog,
}

fn compile_revision(
    context: &WorkflowContext,
    definition: &WorkflowDefinition,
    source_scope: ProfileSourceScope,
    provider: ProviderId,
    discovery: &DiscoveryContext,
) -> Result<CompiledWorkflowRevision, String> {
    let mut profile_ids = BTreeSet::new();
    profile_ids.insert(definition.baseline_profile_id.clone());
    profile_ids.extend(definition.modes.iter().map(|mode| mode.profile_id.clone()));
    let mut profiles = BTreeMap::new();
    for profile_id in profile_ids {
        let entry = load_profile_definition(context, &profile_id)?
            .ok_or_else(|| format!("profile not found: {profile_id}"))?;
        let compiled = compile_profile(&entry.definition, &discovery.catalog, entry.scope)
            .map_err(|error| error.to_string())?;
        profiles.insert(profile_id, compiled);
    }
    let policy = PolicyStore::new(&context.config.app_state_root)
        .load(&PolicyTarget::Global)
        .map_err(|error| error.to_string())?;
    let locks = CapabilityLockSnapshot::compile(
        provider,
        policy
            .as_ref()
            .and_then(|snapshot| snapshot.policy.providers.get(&provider))
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )
    .map_err(|error| error.to_string())?;
    compile_workflow(
        definition,
        &profiles,
        &discovery.catalog,
        &locks,
        provider,
        source_scope,
    )
    .map_err(|error| error.to_string())
}

fn load_profile_definition(
    context: &WorkflowContext,
    id: &str,
) -> Result<Option<ProfileDefinitionEntry>, String> {
    if let Some(entry) = ProfileStore::load_workspace_definition(&context.config.project_root, id)
        .map_err(|error| error.to_string())?
    {
        return Ok(Some(entry));
    }
    context
        .profiles
        .load_global_definition(id)
        .map(|snapshot| {
            snapshot.map(|snapshot| ProfileDefinitionEntry {
                scope: ProfileSourceScope::Global,
                definition: snapshot.value,
                revision: Some(snapshot.revision),
            })
        })
        .map_err(|error| error.to_string())
}

fn workflow_score(entry: &WorkflowDefinitionEntry, terms: &BTreeSet<String>) -> usize {
    let mut text = format!(
        "{} {} {} {}",
        entry.definition.id,
        entry.definition.display_name,
        entry.definition.description.as_deref().unwrap_or_default(),
        entry.definition.entry_mode
    )
    .to_ascii_lowercase();
    text.push(' ');
    text.push_str(
        &entry
            .definition
            .modes
            .iter()
            .map(|mode| mode.name.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
    terms
        .iter()
        .filter(|term| text.contains(term.as_str()))
        .count()
}

fn text_terms(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| term.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn catalog_digest(catalog: &Catalog) -> String {
    digest(&serde_json::to_vec(catalog).expect("catalog serialization"))
}

fn digest(bytes: &[u8]) -> String {
    unpin_core::sha256_digest(bytes)
}

fn workflow_plan_value(plan: &WorkflowDefinitionPlan) -> serde_json::Value {
    json!({
        "schemaVersion": plan.schema_version,
        "operationId": plan.operation_id,
        "operationKind": plan.operation_kind,
        "action": match plan.action {
            WorkflowMutationActionArg::Upsert => "upsert",
            WorkflowMutationActionArg::Delete => "delete",
        },
        "workflowId": plan.workflow_id,
        "scope": "global",
        "definitionDigest": plan.definition_digest,
        "expectedRevision": plan.expected_revision,
        "planFingerprint": plan.plan_fingerprint,
        "activation": plan.activation,
        "humanApprovalRequired": plan.human_approval_required,
    })
}
