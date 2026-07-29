use std::{
    collections::BTreeMap,
    error::Error,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crossterm::{
    event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use serde_json::json;
use unpin_core::approval::ControlApprovalContext;
use unpin_core::control::{ControlOperationStatus, ControlStatus, build_control_status};
use unpin_core::control_operation::{
    ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle, DurableControlError,
};
use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryLayer, DiscoveryMutability, DiscoveryOutput,
    DiscoveryRoots, DiscoveryWarning, ProviderId, discover_all,
};
use unpin_core::groups::{GroupAccessContext, GroupMemberIdentity, GroupOperationLifecycle};
use unpin_core::mutation::{
    BackupAuthenticationKey, BackupAuthenticationStatus, BackupSummary, NativeToggleController,
    NativeTogglePlan, RestoreControlError, RestoreControlPlan, RestoreController, RestoreStatus,
    TogglePlanRequest, ToggleResult, ToggleStatus, load_backup_summaries_authenticated,
    plan_toggle,
};
use unpin_core::sessions::SessionAuthorityKey;
#[cfg(test)]
use unpin_core::snapshots::write_discovery_snapshot;
use unpin_core::snapshots::{SnapshotWriteOptions, write_control_snapshot};
use unpin_core::state::atomic_json::{AtomicJsonStore, OwnerGeneration};
use unpin_core::state::workspace::resolve_workspace_identity;

use crate::{credentials, unix_now};

mod gateway;
mod groups;
mod hooks;
mod profiles;
mod sessions;

type TuiResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkflowPhase {
    Browsing,
    Planned,
    Confirmed,
    Applied,
    Partial,
    RecoveryRequired,
    Blocked,
}

impl WorkflowPhase {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Browsing => "browsing",
            Self::Planned => "planned",
            Self::Confirmed => "confirmed",
            Self::Applied => "applied",
            Self::Partial => "partial",
            Self::RecoveryRequired => "recovery-required",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiView {
    Inventory,
    Groups,
    Profiles,
    Gateways,
    Sessions,
    Hooks,
    RestoreOperations,
}

impl TuiView {
    const ALL: [Self; 7] = [
        Self::Inventory,
        Self::Groups,
        Self::Profiles,
        Self::Gateways,
        Self::Sessions,
        Self::Hooks,
        Self::RestoreOperations,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Groups => "groups",
            Self::Profiles => "profiles",
            Self::Gateways => "gateways",
            Self::Sessions => "sessions",
            Self::Hooks => "hooks",
            Self::RestoreOperations => "restore/operations",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderFilter {
    All,
    Provider(ProviderId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerFilter {
    All,
    Layer(DiscoveryLayer),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryFilter {
    All,
    Category(DiscoveryCategory),
}

struct TuiState {
    items: Vec<DiscoveryItem>,
    warnings: Vec<DiscoveryWarning>,
    backups: Vec<BackupSummary>,
    app_state_root: PathBuf,
    project_root: PathBuf,
    discovery_roots: Option<DiscoveryRoots>,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    session_authority_key: Option<SessionAuthorityKey>,
    control_status: Option<ControlStatus>,
    control_status_error: Option<String>,
    approval_context: Option<ControlApprovalContext>,
    approval_context_error: Option<String>,
    fixture_mode: bool,
    view: TuiView,
    profile_workflow: profiles::ProfileWorkflow,
    group_workflow: groups::GroupWorkflow,
    gateway_workflow: gateway::GatewayWorkflow,
    session_workflow: sessions::SessionWorkflow,
    hook_workflow: hooks::HookWorkflow,
    restore_workflow: RestoreWorkflow,
    last_control_envelope: Option<ControlOperationEnvelope>,
    staged: BTreeMap<GroupMemberIdentity, StagedToggle>,
    pending_confirmation: bool,
    search_query: String,
    search_editing: bool,
    selected: usize,
    provider_filter: ProviderFilter,
    layer_filter: LayerFilter,
    category_filter: CategoryFilter,
    last_action: Option<TuiActionStatus>,
    mcp_approval_handoff: Option<groups::McpApprovalHandoff>,
    #[cfg(test)]
    _owned_app_state: Option<tempfile::TempDir>,
}

#[derive(Debug, Clone)]
struct StagedToggle {
    item: DiscoveryItem,
    plan: Option<NativeTogglePlan>,
    blocked_reason: Option<String>,
    target_enabled: bool,
}

fn inventory_item_key(item: &DiscoveryItem) -> GroupMemberIdentity {
    GroupMemberIdentity::try_from(item).expect("discovered inventory item identity is valid")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiActionStatus {
    Success(String),
    Error(String),
}

#[derive(Debug, Clone)]
struct ReviewedRestorePlan {
    plan: RestoreControlPlan,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
struct RestoreWorkflow {
    backups: Vec<BackupSummary>,
    operations: Vec<ControlOperationStatus>,
    selected: usize,
    reviewed: Option<ReviewedRestorePlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
}

impl RestoreWorkflow {
    fn new(backups: Vec<BackupSummary>, operations: Vec<ControlOperationStatus>) -> Self {
        Self {
            backups,
            operations,
            selected: 0,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    fn select_next(&mut self) {
        if !self.backups.is_empty() {
            self.selected = (self.selected + 1) % self.backups.len();
            self.reset_review();
        }
    }

    fn select_previous(&mut self) {
        if !self.backups.is_empty() {
            self.selected = if self.selected == 0 {
                self.backups.len() - 1
            } else {
                self.selected - 1
            };
            self.reset_review();
        }
    }

    fn rows(&self) -> Vec<String> {
        self.backups
            .iter()
            .enumerate()
            .map(|(index, backup)| {
                format!(
                    "{} {} entries={} restorable={} auth={}",
                    if index == self.selected { ">" } else { " " },
                    backup.backup_id,
                    backup.item_count,
                    backup.restorable,
                    backup_authentication_label(backup.authentication)
                )
            })
            .collect()
    }

    fn details(&self) -> Vec<String> {
        let recovery_count = self
            .operations
            .iter()
            .filter(|operation| operation.recovery_required)
            .count();
        let mut details = vec![format!(
            "Restore: backups={} operations={} recovery={} phase={}",
            self.backups.len(),
            self.operations.len(),
            recovery_count,
            self.phase.label()
        )];
        if let Some(backup) = self.backups.get(self.selected) {
            details.push(format!("selected: {}", backup.backup_id));
            details.push(format!("created: {}", backup.created_at));
            details.push(format!("targets: {}", backup.paths.len()));
        } else {
            details.push("selected: none".to_string());
        }
        for operation in &self.operations {
            details.push(format!(
                "operation: {} {} {:?} recovery={}",
                operation.operation_id,
                operation.operation_kind,
                operation.lifecycle,
                operation.recovery_required
            ));
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.plan.plan_fingerprint));
            details.push(format!(
                "resources: {}",
                reviewed.plan.affected_resources.len()
            ));
        }
        if let Some(envelope) = &self.last_envelope {
            details.push(format!(
                "result: {:?} {}",
                envelope.lifecycle, envelope.operation_id
            ));
        }
        if let Some(error) = &self.last_error {
            details.push(format!("error: {error}"));
        }
        details
    }

    fn plan(
        &mut self,
        app_state_root: &Path,
        context: &ControlApprovalContext,
        backup_key: Option<&BackupAuthenticationKey>,
    ) -> Result<&ControlOperationEnvelope, String> {
        let backup = self
            .backups
            .get(self.selected)
            .ok_or_else(|| "no backup selected".to_string())?;
        let plan = RestoreController::new(app_state_root)
            .plan(&backup.backup_id, context, backup_key)
            .map_err(|error| error.to_string())?;
        let expectation = plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            plan.activation,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Review authenticated backup and every affected target before restore."
                    .to_string(),
            }),
            false,
            vec![plan.provider],
            json!({"plan": plan}),
        );
        self.reviewed = Some(ReviewedRestorePlan { plan, envelope });
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(&self.reviewed.as_ref().expect("reviewed plan set").envelope)
    }

    fn confirm(&mut self) -> bool {
        if self.reviewed.is_none() {
            return false;
        }
        self.phase = WorkflowPhase::Confirmed;
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        backup_key: &BackupAuthenticationKey,
        fixture_mode: bool,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("restore plan must be confirmed before apply".to_string());
        }
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "restore plan is missing".to_string())?;
        let mut fixture_paths = vec![app_state_root, project_root];
        fixture_paths.extend(
            reviewed
                .plan
                .affected_resources
                .iter()
                .map(|resource| Path::new(resource.path.as_str())),
        );
        unpin_core::fixture::require_fixture_write_sandbox(fixture_mode, fixture_paths)?;
        let expectation = reviewed
            .plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let authorization = credentials::authorize_reviewed_control_decision(
            fixture_mode,
            app_state_root,
            &expectation,
            &reviewed.plan.plan_fingerprint,
            Some(&reviewed.plan.plan_fingerprint),
            "unpin-tui-restore-approval",
            unix_now(),
        )?;
        let result = match RestoreController::with_session_authority_key(
            app_state_root,
            authority_key.clone(),
        )
        .apply(
            &reviewed.plan,
            authorization,
            context,
            Some(backup_key.clone()),
        ) {
            Ok(result) => result,
            Err(error) => {
                if matches!(
                    &error,
                    RestoreControlError::Durable(DurableControlError::RecoveryRequired(_))
                ) {
                    self.phase = WorkflowPhase::RecoveryRequired;
                }
                return Err(error.to_string());
            }
        };
        let lifecycle = if result.status == RestoreStatus::Restored {
            ControlOperationLifecycle::Applied
        } else {
            ControlOperationLifecycle::RecoveryRequired
        };
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &expectation,
            &reviewed.plan.plan_fingerprint,
            reviewed.plan.activation,
            lifecycle,
            None,
            lifecycle == ControlOperationLifecycle::RecoveryRequired,
            vec![reviewed.plan.provider],
            json!({"result": result}),
        ));
        self.phase = if lifecycle == ControlOperationLifecycle::RecoveryRequired {
            WorkflowPhase::RecoveryRequired
        } else {
            WorkflowPhase::Applied
        };
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
    }

    fn reset_review(&mut self) {
        self.reviewed = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }
}

impl TuiState {
    #[cfg(test)]
    fn new(discovery: DiscoveryOutput) -> Self {
        let app_state = tempfile::TempDir::new().expect("temporary TUI app state");
        let mut state = Self::new_with_app_state_root(discovery, app_state.path().to_path_buf());
        state._owned_app_state = Some(app_state);
        state
    }

    #[cfg(test)]
    fn new_with_app_state_root(discovery: DiscoveryOutput, app_state_root: PathBuf) -> Self {
        Self::new_with_app_state_root_and_key(
            discovery,
            app_state_root,
            default_backup_authentication_key(),
        )
    }

    #[cfg(test)]
    fn new_with_app_state_root_and_key(
        discovery: DiscoveryOutput,
        app_state_root: PathBuf,
        backup_authentication_key: Option<BackupAuthenticationKey>,
    ) -> Self {
        Self::new_with_paths_and_key(
            discovery,
            app_state_root,
            PathBuf::from("."),
            backup_authentication_key,
            default_session_authority_key(),
        )
    }

    #[cfg(test)]
    fn new_with_paths(
        discovery: DiscoveryOutput,
        app_state_root: PathBuf,
        project_root: PathBuf,
    ) -> Self {
        Self::new_with_paths_and_key(
            discovery,
            app_state_root,
            project_root,
            default_backup_authentication_key(),
            default_session_authority_key(),
        )
    }

    fn new_with_paths_and_key(
        discovery: DiscoveryOutput,
        app_state_root: PathBuf,
        project_root: PathBuf,
        backup_authentication_key: Option<BackupAuthenticationKey>,
        session_authority_key: Option<SessionAuthorityKey>,
    ) -> Self {
        let app_state_root = if cfg!(test) {
            std::fs::canonicalize(&app_state_root).unwrap_or(app_state_root)
        } else {
            app_state_root
        };
        let backups = load_backup_summaries_authenticated(
            &app_state_root,
            backup_authentication_key.as_ref(),
        );
        let (control_status, control_status_error) = match session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority key is unavailable".to_string())
            .and_then(|key| {
                build_control_status(&discovery, &app_state_root, &project_root, key)
                    .map_err(|error| error.to_string())
            }) {
            Ok(status) => (Some(status), None),
            Err(error) => (None, Some(error)),
        };
        let (approval_context, approval_context_error) =
            match resolve_workspace_identity(&project_root)
                .map_err(|error| error.to_string())
                .and_then(|identity| {
                    ControlApprovalContext::new(identity.repository_key, identity.workspace_key)
                        .map_err(|error| error.to_string())
                }) {
                Ok(context) => (Some(context), None),
                Err(_error) if cfg!(test) => (
                    ControlApprovalContext::new("test-repository", "test-workspace").ok(),
                    None,
                ),
                Err(error) => (None, Some(error)),
            };
        let (profile_workflow, gateway_workflow, session_workflow, hook_workflow, operations) =
            match control_status.as_ref() {
                Some(control) => (
                    profiles::ProfileWorkflow::new_with_policy(
                        &control.repository_key,
                        &control.workspace_key,
                        control.profiles.clone(),
                        &control.policies,
                        &discovery,
                    ),
                    gateway::GatewayWorkflow::new(
                        &control.repository_key,
                        &control.workspace_key,
                        control.gateways.clone(),
                    ),
                    sessions::SessionWorkflow::new(control.sessions.clone()),
                    hooks::HookWorkflow::new(
                        &control.repository_key,
                        &control.workspace_key,
                        &discovery,
                        &control.sessions,
                        &app_state_root,
                    ),
                    control.operations.clone(),
                ),
                None => (
                    profiles::ProfileWorkflow::empty(),
                    gateway::GatewayWorkflow::empty(),
                    sessions::SessionWorkflow::new(Vec::new()),
                    hooks::HookWorkflow::empty(),
                    Vec::new(),
                ),
            };
        let restore_workflow = RestoreWorkflow::new(backups.clone(), operations);
        Self {
            items: discovery.items,
            warnings: discovery.warnings,
            backups,
            app_state_root,
            project_root,
            discovery_roots: None,
            backup_authentication_key,
            session_authority_key,
            control_status,
            control_status_error,
            approval_context,
            approval_context_error,
            fixture_mode: cfg!(test),
            view: TuiView::Inventory,
            profile_workflow,
            group_workflow: groups::GroupWorkflow::empty(),
            gateway_workflow,
            session_workflow,
            hook_workflow,
            restore_workflow,
            last_control_envelope: None,
            staged: BTreeMap::new(),
            pending_confirmation: false,
            search_query: String::new(),
            search_editing: false,
            selected: 0,
            provider_filter: ProviderFilter::All,
            layer_filter: LayerFilter::All,
            category_filter: CategoryFilter::All,
            last_action: None,
            mcp_approval_handoff: None,
            #[cfg(test)]
            _owned_app_state: None,
        }
    }

    #[cfg(test)]
    fn new_with_paths_and_roots(
        discovery: DiscoveryOutput,
        app_state_root: PathBuf,
        project_root: PathBuf,
        discovery_roots: DiscoveryRoots,
    ) -> Self {
        Self::new_with_paths_and_roots_and_key(
            discovery,
            app_state_root,
            project_root,
            discovery_roots,
            default_backup_authentication_key(),
            default_session_authority_key(),
        )
    }

    fn new_with_paths_and_roots_and_key(
        discovery: DiscoveryOutput,
        app_state_root: PathBuf,
        project_root: PathBuf,
        discovery_roots: DiscoveryRoots,
        backup_authentication_key: Option<BackupAuthenticationKey>,
        session_authority_key: Option<SessionAuthorityKey>,
    ) -> Self {
        let group_discovery = discovery.clone();
        let mut state = Self::new_with_paths_and_key(
            discovery,
            app_state_root,
            project_root,
            backup_authentication_key,
            session_authority_key,
        );
        state.discovery_roots = Some(discovery_roots);
        if let Err(error) = state.refresh_group_workflow(&group_discovery) {
            state.group_workflow.record_error(error);
        }
        state
    }

    fn selected_item(&self) -> Option<&DiscoveryItem> {
        let visible_indices = self.visible_indices();
        visible_indices
            .get(self.selected)
            .and_then(|index| self.items.get(*index))
    }

    fn cycle_view(&mut self) {
        let current = TuiView::ALL
            .iter()
            .position(|view| *view == self.view)
            .unwrap_or(0);
        self.view = TuiView::ALL[(current + 1) % TuiView::ALL.len()];
        self.search_editing = false;
    }

    fn active_rows(&self) -> Vec<String> {
        match self.view {
            TuiView::Inventory => self
                .visible_items()
                .into_iter()
                .map(|item| {
                    format!(
                        "{} {} {} [{}] {}",
                        item.provider.as_str(),
                        item.layer.as_str(),
                        item.category.as_str(),
                        enabled_label(item.enabled),
                        item.display_name
                    )
                })
                .collect(),
            TuiView::Profiles => self.profile_workflow.rows(),
            TuiView::Groups if self.group_workflow.uses_inventory_rows() => {
                self.group_workflow.rows(&self.visible_items())
            }
            TuiView::Groups => self.group_workflow.rows(&[]),
            TuiView::Gateways => self.gateway_workflow.rows(),
            TuiView::Sessions => self.session_workflow.rows(),
            TuiView::Hooks => self.hook_workflow.rows(),
            TuiView::RestoreOperations => self.restore_workflow.rows(),
        }
    }

    fn active_details(&self) -> Vec<String> {
        match self.view {
            TuiView::Inventory => self.selected_item().map_or_else(
                || vec!["No discovered items match current filters.".to_string()],
                |item| {
                    let mut details = selected_detail_strings(item);
                    details.extend(plan_preview_strings(self, item));
                    details
                },
            ),
            TuiView::Profiles => self.profile_workflow.details(),
            TuiView::Groups => {
                let mut details = self.group_workflow.details();
                if let Some(handoff) = &self.mcp_approval_handoff {
                    details.extend([
                        format!(
                            "MCP handoff ready: operation={} fingerprint={} artifact={} expires={}",
                            handoff.operation_id,
                            handoff.plan_fingerprint,
                            handoff.approval_artifact,
                            handoff.expires_at_unix,
                        ),
                        "No provider apply occurred. Press X to export the exact bound handoff as private JSON."
                            .to_string(),
                    ]);
                }
                details
            }
            TuiView::Gateways => self.gateway_workflow.details(),
            TuiView::Sessions => self.session_workflow.details(),
            TuiView::Hooks => self.hook_workflow.details(),
            TuiView::RestoreOperations => self.restore_workflow.details(),
        }
    }

    fn plan_active_action(&mut self) -> bool {
        if self.view == TuiView::Inventory {
            return self.stage_selected_toggle();
        }
        let Some(context) = self.approval_context.clone() else {
            self.last_action = Some(TuiActionStatus::Error(
                self.approval_context_error
                    .clone()
                    .unwrap_or_else(|| "workspace approval context unavailable".to_string()),
            ));
            return false;
        };
        let operation = match self.view {
            TuiView::Inventory => unreachable!("inventory handled above"),
            TuiView::Groups => self.group_workflow.plan(&context).cloned(),
            TuiView::Profiles => {
                let discovery = DiscoveryOutput {
                    items: self.items.clone(),
                    warnings: self.warnings.clone(),
                };
                self.profile_workflow
                    .plan(&discovery, &self.app_state_root, &context)
                    .cloned()
            }
            TuiView::Gateways => match (
                self.session_authority_key.as_ref(),
                self.backup_authentication_key.as_ref(),
            ) {
                (Some(key), Some(backup_key)) => self
                    .gateway_workflow
                    .plan(&self.app_state_root, &context, key, backup_key)
                    .cloned(),
                (None, _) => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
                (_, None) => Err(
                    "backup authentication key missing; run `unpin auth backup init`".to_string(),
                ),
            },
            TuiView::Sessions => match self.session_authority_key.as_ref() {
                Some(key) => self
                    .session_workflow
                    .plan(&self.app_state_root, &context, key)
                    .cloned(),
                None => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
            },
            TuiView::Hooks => {
                let discovery = DiscoveryOutput {
                    items: self.items.clone(),
                    warnings: self.warnings.clone(),
                };
                self.hook_workflow
                    .plan(&discovery, &self.app_state_root)
                    .cloned()
            }
            TuiView::RestoreOperations => self
                .restore_workflow
                .plan(
                    &self.app_state_root,
                    &context,
                    self.backup_authentication_key.as_ref(),
                )
                .cloned(),
        };
        match operation {
            Ok(envelope) => {
                let operation_id = envelope.operation_id.clone();
                self.last_control_envelope = Some(envelope);
                self.last_action = Some(TuiActionStatus::Success(format!(
                    "planned {operation_id}; confirmation required"
                )));
                true
            }
            Err(error) => {
                match self.view {
                    TuiView::Profiles => self.profile_workflow.record_error(error.clone()),
                    TuiView::Groups => self.group_workflow.record_error(error.clone()),
                    TuiView::Gateways => self.gateway_workflow.record_error(error.clone()),
                    TuiView::Sessions => self.session_workflow.record_error(error.clone()),
                    TuiView::Hooks => self.hook_workflow.record_error(error.clone()),
                    TuiView::RestoreOperations => {
                        self.restore_workflow.record_error(error.clone());
                    }
                    TuiView::Inventory => {}
                }
                self.last_action = Some(TuiActionStatus::Error(error));
                false
            }
        }
    }

    fn confirm_active_action(&mut self) -> bool {
        if self.view == TuiView::Inventory {
            return self.confirm_staged();
        }
        let confirmed = match self.view {
            TuiView::Profiles => self.profile_workflow.confirm(),
            TuiView::Groups => self.group_workflow.confirm(),
            TuiView::Gateways => self.gateway_workflow.confirm(),
            TuiView::Sessions => self.session_workflow.confirm(),
            TuiView::Hooks => self.hook_workflow.confirm(),
            TuiView::RestoreOperations => self.restore_workflow.confirm(),
            TuiView::Inventory => unreachable!("inventory handled above"),
        };
        if confirmed {
            self.last_action = Some(TuiActionStatus::Success(
                "control plan confirmed; apply still requires human presence".to_string(),
            ));
        }
        confirmed
    }

    fn apply_active_action(&mut self) {
        if self.view == TuiView::Inventory {
            self.apply_confirmed_staged();
            return;
        }
        if self.view == TuiView::Groups {
            self.apply_group_action();
            return;
        }
        let Some(context) = self.approval_context.clone() else {
            self.last_action = Some(TuiActionStatus::Error(
                self.approval_context_error
                    .clone()
                    .unwrap_or_else(|| "workspace approval context unavailable".to_string()),
            ));
            return;
        };
        let result = match self.view {
            TuiView::Groups => unreachable!("groups handled above"),
            TuiView::Profiles => match self.session_authority_key.as_ref() {
                Some(authority) => self.profile_workflow.apply(
                    &self.app_state_root,
                    &self.project_root,
                    &context,
                    authority,
                    self.fixture_mode,
                ),
                None => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
            },
            TuiView::Gateways => match (
                self.session_authority_key.as_ref(),
                self.backup_authentication_key.as_ref(),
            ) {
                (Some(authority), Some(backup)) => self.gateway_workflow.apply(
                    &self.app_state_root,
                    &self.project_root,
                    &context,
                    authority,
                    backup,
                    self.fixture_mode,
                ),
                (None, _) => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
                (_, None) => Err(
                    "backup authentication key missing; run `unpin auth backup init`".to_string(),
                ),
            },
            TuiView::Sessions => match self.session_authority_key.as_ref() {
                Some(authority) => self.session_workflow.apply(
                    &self.app_state_root,
                    &self.project_root,
                    &context,
                    authority,
                    self.fixture_mode,
                ),
                None => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
            },
            TuiView::Hooks => self.hook_workflow.apply(
                &self.app_state_root,
                &self.project_root,
                self.fixture_mode,
            ),
            TuiView::RestoreOperations => match (
                self.session_authority_key.as_ref(),
                self.backup_authentication_key.as_ref(),
            ) {
                (Some(authority), Some(backup)) => self.restore_workflow.apply(
                    &self.app_state_root,
                    &self.project_root,
                    &context,
                    authority,
                    backup,
                    self.fixture_mode,
                ),
                (None, _) => {
                    Err("session authority key missing; run `unpin auth session init`".to_string())
                }
                (_, None) => Err(
                    "backup authentication key missing; run `unpin auth backup init`".to_string(),
                ),
            },
            TuiView::Inventory => unreachable!("inventory handled above"),
        }
        .cloned();
        match result {
            Ok(envelope) => {
                let operation_id = envelope.operation_id.clone();
                let lifecycle = envelope.lifecycle;
                self.last_control_envelope = Some(envelope);
                let refresh = self.refresh_control_plane();
                match refresh {
                    Ok(()) => {
                        self.last_action = Some(TuiActionStatus::Success(format!(
                            "{operation_id} {lifecycle:?}"
                        )));
                    }
                    Err(error) => {
                        self.last_action = Some(TuiActionStatus::Error(format!(
                            "{operation_id} {lifecycle:?}; control refresh failed: {error}"
                        )));
                    }
                }
            }
            Err(error) => {
                match self.view {
                    TuiView::Profiles => self.profile_workflow.record_error(error.clone()),
                    TuiView::Groups => unreachable!("groups handled above"),
                    TuiView::Gateways => self.gateway_workflow.record_error(error.clone()),
                    TuiView::Sessions => self.session_workflow.record_error(error.clone()),
                    TuiView::Hooks => self.hook_workflow.record_error(error.clone()),
                    TuiView::RestoreOperations => {
                        self.restore_workflow.record_error(error.clone());
                    }
                    TuiView::Inventory => {}
                }
                self.last_action = Some(TuiActionStatus::Error(error));
            }
        }
    }

    fn apply_group_action(&mut self) {
        let Some(context) = self.approval_context.clone() else {
            self.last_action = Some(TuiActionStatus::Error(
                self.approval_context_error
                    .clone()
                    .unwrap_or_else(|| "workspace approval context unavailable".to_string()),
            ));
            return;
        };
        let Some(authority) = self.session_authority_key.as_ref() else {
            self.last_action = Some(TuiActionStatus::Error(
                "session authority key missing; run `unpin auth session init`".to_string(),
            ));
            return;
        };
        let outcome = self.group_workflow.apply_active(
            &self.app_state_root,
            &self.project_root,
            &context,
            authority,
            self.backup_authentication_key.as_ref(),
            self.fixture_mode,
        );
        match outcome {
            Ok(groups::GroupApplyOutcome::Direct {
                envelope,
                lifecycle: group_lifecycle,
            }) => {
                let envelope = *envelope;
                let operation_id = envelope.operation_id.clone();
                let lifecycle = envelope.lifecycle;
                self.last_control_envelope = Some(envelope);
                let refresh = self
                    .rediscover_after_apply()
                    .and_then(|discovery| self.refresh_control_plane_from(&discovery));
                self.last_action = Some(match (group_lifecycle, refresh) {
                    (GroupOperationLifecycle::Completed, Ok(())) => {
                        TuiActionStatus::Success(format!("{operation_id} {lifecycle:?}"))
                    }
                    (_, Ok(())) => TuiActionStatus::Error(format!(
                        "{operation_id} group outcome {group_lifecycle:?}; review member results and backup evidence"
                    )),
                    (_, Err(error)) => TuiActionStatus::Error(format!(
                        "{operation_id} group outcome {group_lifecycle:?}; control refresh failed: {error}"
                    )),
                });
            }
            Ok(groups::GroupApplyOutcome::DefinitionChanged { message, created }) => {
                if created {
                    self.clear_staged();
                }
                let discovery = DiscoveryOutput {
                    items: self.items.clone(),
                    warnings: self.warnings.clone(),
                };
                self.last_action = Some(match self.refresh_group_workflow(&discovery) {
                    Ok(()) => TuiActionStatus::Success(format!(
                        "inventory group definition {message}; authenticated history recorded"
                    )),
                    Err(error) => TuiActionStatus::Error(format!(
                        "inventory group definition {message}; refresh failed: {error}"
                    )),
                });
            }
            Ok(groups::GroupApplyOutcome::McpApprovalIssued(handoff)) => {
                let operation_id = handoff.operation_id.clone();
                let plan_fingerprint = handoff.plan_fingerprint.clone();
                let artifact_id = handoff.approval_artifact.clone();
                let expires_at_unix = handoff.expires_at_unix;
                self.mcp_approval_handoff = Some(handoff);
                self.last_action = Some(TuiActionStatus::Success(format!(
                    "MCP approval artifact {artifact_id} issued for {operation_id} fingerprint={plan_fingerprint} expires={expires_at_unix}; no group apply performed; press X to export"
                )));
            }
            Err(error) => {
                self.group_workflow.record_error(error.clone());
                self.last_action = Some(TuiActionStatus::Error(error));
            }
        }
    }

    fn cycle_active_action(&mut self) {
        match self.view {
            TuiView::Groups => self.group_workflow.cycle_target(),
            TuiView::Profiles => self.profile_workflow.cycle_backend(),
            TuiView::Gateways => self.gateway_workflow.cycle_action(),
            _ => {}
        }
    }

    fn cycle_profile_scope(&mut self) {
        match self.view {
            TuiView::Profiles => self.profile_workflow.cycle_scope(),
            TuiView::Groups => self.group_workflow.cycle_draft_scope(),
            _ => {}
        }
    }

    fn cycle_profile_provider(&mut self) {
        if self.view == TuiView::Profiles {
            self.profile_workflow.cycle_provider();
        }
    }

    fn cycle_group_provider_reach(&mut self) {
        if self.view == TuiView::Groups {
            self.group_workflow.cycle_provider_reach();
        }
    }

    fn toggle_gateway_force(&mut self) {
        if self.view == TuiView::Gateways {
            self.gateway_workflow.toggle_force();
        }
    }

    fn group_text_editing(&self) -> bool {
        self.view == TuiView::Groups && self.group_workflow.is_text_input()
    }

    fn push_group_text_char(&mut self, character: char) {
        self.group_workflow.push_text_char(character);
    }

    fn push_group_text(&mut self, text: &str) {
        self.group_workflow.push_text(text);
    }

    fn pop_group_text_char(&mut self) {
        self.group_workflow.pop_text_char();
    }

    fn finish_group_text_input(&mut self) {
        let submission = self.group_workflow.finish_text_input();
        match submission {
            Ok(groups::GroupTextSubmission::DefinitionName) => {
                self.last_action = Some(TuiActionStatus::Success(
                    "group name accepted; review member selection and press w to preview"
                        .to_string(),
                ));
            }
            Ok(groups::GroupTextSubmission::McpChallenge(challenge)) => {
                let result = self
                    .approval_context
                    .as_ref()
                    .ok_or_else(|| "workspace approval context unavailable".to_string())
                    .and_then(|context| {
                        self.session_authority_key
                            .as_ref()
                            .ok_or_else(|| {
                                "session authority key missing; run `unpin auth session init`"
                                    .to_string()
                            })
                            .and_then(|authority| {
                                self.group_workflow.review_mcp_challenge(
                                    challenge,
                                    &self.app_state_root,
                                    context,
                                    authority,
                                    unix_now(),
                                )
                            })
                    });
                match result {
                    Ok(()) => {
                        self.last_action = Some(TuiActionStatus::Success(
                            "MCP challenge authenticated; review every effect, then Enter confirms artifact issuance"
                                .to_string(),
                        ));
                    }
                    Err(error) => {
                        self.group_workflow.record_error(error.clone());
                        self.last_action = Some(TuiActionStatus::Error(error));
                    }
                }
            }
            Err(error) => {
                self.group_workflow.record_error(error.clone());
                self.last_action = Some(TuiActionStatus::Error(error));
            }
        }
    }

    fn start_group_create(&mut self) {
        if self.view != TuiView::Groups {
            return;
        }
        let members = self
            .staged
            .values()
            .map(|staged| GroupMemberIdentity::try_from(&staged.item))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string());
        let result = members.and_then(|members| self.group_workflow.start_create(members));
        self.record_group_definition_result(
            result,
            "enter a group name, then use inventory filters/search to edit members",
        );
    }

    fn start_group_edit(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.start_edit();
            self.record_group_definition_result(
                result,
                "editing selected group; Space toggles the highlighted full identity",
            );
        }
    }

    fn start_group_rename(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.start_rename();
            self.record_group_definition_result(result, "enter the new group name");
        }
    }

    fn start_group_delete(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.start_delete();
            self.record_group_definition_result(
                result,
                "delete preview ready; Enter confirms and a applies",
            );
        }
    }

    fn show_group_history(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.show_history();
            self.record_group_definition_result(
                result,
                "authenticated group history loaded; r previews the selected restore",
            );
        }
    }

    fn stage_group_restore(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.stage_history_restore();
            self.record_group_definition_result(
                result,
                "restore preview ready; Enter confirms and a applies",
            );
        }
    }

    fn start_group_mcp_approval(&mut self) {
        if self.view == TuiView::Groups {
            self.group_workflow.start_mcp_approval();
            self.last_action = Some(TuiActionStatus::Success(
                "paste the opaque MCP group challenge and press Enter; no apply will occur"
                    .to_string(),
            ));
        }
    }

    fn export_group_mcp_handoff(&mut self) {
        if self.view != TuiView::Groups {
            return;
        }
        let result = self
            .mcp_approval_handoff
            .as_ref()
            .ok_or_else(|| "no issued MCP approval handoff is available".to_string())
            .and_then(|handoff| {
                let export = handoff.export_value();
                let path = self
                    .app_state_root
                    .join("groups")
                    .join("handoff-exports")
                    .join(format!("{}.json", handoff.approval_artifact));
                let store = AtomicJsonStore::new(&path, 1);
                match store
                    .load::<serde_json::Value>()
                    .map_err(|error| error.to_string())?
                {
                    Some(snapshot) if snapshot.value == export => Ok(path),
                    Some(_) => Err(
                        "MCP approval handoff export already exists with different contents"
                            .to_string(),
                    ),
                    None => {
                        let owner = OwnerGeneration::new("unpin-tui-mcp-handoff-export", 1)
                            .map_err(|error| error.to_string())?;
                        store
                            .compare_and_swap(None, owner, &export)
                            .map_err(|error| error.to_string())?;
                        Ok(path)
                    }
                }
            });
        self.last_action = Some(match result {
            Ok(path) => TuiActionStatus::Success(format!(
                "MCP approval handoff exported to {}; no provider apply performed",
                path.display()
            )),
            Err(error) => TuiActionStatus::Error(error),
        });
    }

    fn stage_group_definition_save(&mut self) {
        if self.view == TuiView::Groups {
            let result = self.group_workflow.stage_definition_save();
            self.record_group_definition_result(
                result,
                "definition preview ready; Enter confirms and a applies",
            );
        }
    }

    fn toggle_group_member(&mut self) -> bool {
        if self.view != TuiView::Groups || !self.group_workflow.is_member_editor() {
            return false;
        }
        let visible = self.visible_items();
        let selected = visible
            .get(self.group_workflow.member_selected_index())
            .copied()
            .cloned();
        let result = selected
            .ok_or_else(|| "no inventory item matches the current filters".to_string())
            .and_then(|item| self.group_workflow.toggle_member(&item));
        self.record_group_definition_result(result, "group draft member selection updated");
        true
    }

    fn cancel_group_interaction(&mut self) -> bool {
        if self.view == TuiView::Groups && self.group_workflow.cancel_interaction() {
            self.last_action = Some(TuiActionStatus::Success(
                "group definition/MCP approval workflow cancelled without writing".to_string(),
            ));
            return true;
        }
        false
    }

    fn record_group_definition_result(&mut self, result: Result<(), String>, success: &str) {
        match result {
            Ok(()) => {
                self.last_action = Some(TuiActionStatus::Success(success.to_string()));
            }
            Err(error) => {
                self.group_workflow.record_error(error.clone());
                self.last_action = Some(TuiActionStatus::Error(error));
            }
        }
    }

    fn refresh_control_plane(&mut self) -> Result<(), String> {
        let discovery = DiscoveryOutput {
            items: self.items.clone(),
            warnings: self.warnings.clone(),
        };
        self.refresh_control_plane_from(&discovery)
    }

    fn refresh_control_plane_from(&mut self, discovery: &DiscoveryOutput) -> Result<(), String> {
        let key = self
            .session_authority_key
            .as_ref()
            .ok_or_else(|| "session authority key is unavailable".to_string())?;
        self.backups = load_backup_summaries_authenticated(
            &self.app_state_root,
            self.backup_authentication_key.as_ref(),
        );
        let control =
            build_control_status(discovery, &self.app_state_root, &self.project_root, key)
                .map_err(|error| error.to_string())?;
        self.install_control_status(control, discovery);
        self.refresh_group_workflow(discovery)?;
        Ok(())
    }

    fn refresh_group_workflow(&mut self, discovery: &DiscoveryOutput) -> Result<(), String> {
        let roots = self
            .discovery_roots
            .as_ref()
            .ok_or_else(|| "inventory group discovery roots are unavailable".to_string())?;
        let access = GroupAccessContext::from_runtime(
            &self.app_state_root,
            &self.project_root,
            roots,
            None,
            None,
        )
        .map_err(|error| error.to_string())?;
        self.group_workflow =
            groups::GroupWorkflow::new(access, self.backup_authentication_key.as_ref(), discovery)?;
        Ok(())
    }

    fn install_control_status(&mut self, control: ControlStatus, discovery: &DiscoveryOutput) {
        self.profile_workflow = profiles::ProfileWorkflow::new_with_policy(
            &control.repository_key,
            &control.workspace_key,
            control.profiles.clone(),
            &control.policies,
            discovery,
        );
        self.gateway_workflow = gateway::GatewayWorkflow::new(
            &control.repository_key,
            &control.workspace_key,
            control.gateways.clone(),
        );
        self.session_workflow = sessions::SessionWorkflow::new(control.sessions.clone());
        self.hook_workflow = hooks::HookWorkflow::new(
            &control.repository_key,
            &control.workspace_key,
            discovery,
            &control.sessions,
            &self.app_state_root,
        );
        self.restore_workflow =
            RestoreWorkflow::new(self.backups.clone(), control.operations.clone());
        self.control_status = Some(control);
        self.control_status_error = None;
    }

    fn stage_selected_toggle(&mut self) -> bool {
        let Some(item) = self.selected_item().cloned() else {
            return false;
        };
        if item.mutability != DiscoveryMutability::ReadWrite {
            return false;
        }

        let Some(context) = self.approval_context.as_ref() else {
            self.last_action = Some(TuiActionStatus::Error(
                self.approval_context_error
                    .clone()
                    .unwrap_or_else(|| "workspace approval context unavailable".to_string()),
            ));
            return false;
        };
        let (plan, blocked_reason, target_enabled) = match self
            .native_toggle_controller()
            .plan_with_inventory(item.clone(), &self.items, context)
        {
            Ok(plan) => {
                let target_enabled = plan.preview.target_enabled;
                (Some(plan), None, target_enabled)
            }
            Err(error) => (None, Some(error.to_string()), !item.enabled),
        };
        let staged = StagedToggle {
            item: item.clone(),
            plan,
            blocked_reason,
            target_enabled,
        };
        self.staged.insert(inventory_item_key(&item), staged);
        self.pending_confirmation = false;
        true
    }

    fn confirm_staged(&mut self) -> bool {
        if self.staged.is_empty() {
            return false;
        }
        self.pending_confirmation = true;
        true
    }

    fn apply_confirmed_staged(&mut self) -> Vec<ToggleResult> {
        if !self.pending_confirmation || self.staged.is_empty() {
            return Vec::new();
        }

        let staged = self.staged.values().cloned().collect::<Vec<_>>();
        let staged_count = staged.len();
        let mut results = Vec::new();
        for staged in &staged {
            let result = self.apply_staged_toggle(staged);
            if result.status == ToggleStatus::Applied
                && let Some(item) = self
                    .items
                    .iter_mut()
                    .find(|item| inventory_item_key(item) == inventory_item_key(&staged.item))
            {
                item.enabled = staged.target_enabled;
            }
            results.push(result);
        }

        let applied_count = results
            .iter()
            .filter(|result| result.status == ToggleStatus::Applied)
            .count();
        let mut failures = results
            .iter()
            .filter(|result| result.status != ToggleStatus::Applied)
            .map(|result| {
                format!(
                    "{} {}: {}",
                    result.selection.id,
                    toggle_status_label(result.status),
                    result.reason.as_deref().unwrap_or("no reason provided")
                )
            })
            .collect::<Vec<_>>();
        let failed_staged = staged
            .iter()
            .zip(&results)
            .filter(|(_, result)| result.status != ToggleStatus::Applied)
            .map(|(staged, _)| staged.clone())
            .collect::<Vec<_>>();

        let mut backups_reloaded = false;
        let refreshed_discovery = match self.rediscover_after_apply() {
            Ok(discovery) => {
                backups_reloaded = true;
                Some(discovery)
            }
            Err(error) => {
                let snapshot_note = if applied_count > 0 {
                    "; snapshot skipped"
                } else {
                    ""
                };
                failures.push(format!("refresh failed: {error}{snapshot_note}"));
                None
            }
        };
        let snapshot_discovery = if applied_count > 0 {
            refreshed_discovery
        } else {
            None
        };

        self.clear_staged();
        for mut staged in failed_staged {
            if let Some(current_item) = self
                .items
                .iter()
                .find(|item| inventory_item_key(item) == inventory_item_key(&staged.item))
            {
                if current_item.enabled == staged.target_enabled {
                    continue;
                }
                let Some(context) = self.approval_context.as_ref() else {
                    continue;
                };
                staged.item = current_item.clone();
                match self.native_toggle_controller().plan_with_inventory(
                    current_item.clone(),
                    &self.items,
                    context,
                ) {
                    Ok(plan) => {
                        staged.plan = Some(plan);
                        staged.blocked_reason = None;
                    }
                    Err(error) => {
                        staged.plan = None;
                        staged.blocked_reason = Some(error.to_string());
                    }
                }
            }
            self.staged.insert(inventory_item_key(&staged.item), staged);
        }
        if !backups_reloaded {
            self.backups = load_backup_summaries_authenticated(
                &self.app_state_root,
                self.backup_authentication_key.as_ref(),
            );
        }
        if let Some(discovery) = snapshot_discovery {
            let control = self
                .session_authority_key
                .as_ref()
                .ok_or_else(|| "session authority key is unavailable".to_string())
                .and_then(|key| {
                    build_control_status(&discovery, &self.app_state_root, &self.project_root, key)
                        .map_err(|error| error.to_string())
                });
            match control {
                Ok(control) => {
                    let metadata = control.persistent_metadata();
                    self.install_control_status(control, &discovery);
                    if let Err(error) = write_control_snapshot(
                        SnapshotWriteOptions {
                            app_state_root: self.app_state_root.clone(),
                            project_root: self.project_root.clone(),
                            discovery,
                            captured_at: None,
                            id: None,
                            max_history: 20,
                        },
                        metadata,
                    ) {
                        failures.push(format!("snapshot failed: {error}"));
                    }
                }
                Err(error) => {
                    self.control_status = None;
                    self.control_status_error = Some(error.to_string());
                    failures.push(format!("snapshot control metadata failed: {error}"));
                }
            }
        }

        let summary = format!(
            "Applied {applied_count}/{staged_count} {}",
            staged_change_label(staged_count)
        );
        self.last_action = Some(if failures.is_empty() {
            TuiActionStatus::Success(summary)
        } else {
            TuiActionStatus::Error(format!("{summary}; {}", failures.join("; ")))
        });
        results
    }

    fn apply_staged_toggle(&self, staged: &StagedToggle) -> ToggleResult {
        let Some(plan) = staged.plan.as_ref() else {
            let mut blocked = plan_toggle(TogglePlanRequest {
                app_state_root: self.app_state_root.clone(),
                item: staged.item.clone(),
            });
            blocked.status = ToggleStatus::Blocked;
            blocked.reason = staged.blocked_reason.clone().or(blocked.reason);
            return blocked;
        };
        let mut blocked = plan.preview.clone();
        blocked.status = ToggleStatus::Blocked;
        blocked.writes = Some("no writes were performed".to_string());
        let Some(context) = self.approval_context.as_ref() else {
            blocked.reason = Some(
                self.approval_context_error
                    .clone()
                    .unwrap_or_else(|| "workspace approval context unavailable".to_string()),
            );
            return blocked;
        };
        let Some(backup_key) = self.backup_authentication_key.clone() else {
            blocked.reason = Some("backup authentication key is required before apply".to_string());
            return blocked;
        };
        let mut fixture_write_paths = vec![self.app_state_root.as_path()];
        for path in [
            staged.item.source_path.as_str(),
            staged.item.state_path.as_str(),
        ] {
            if !path.is_empty() {
                fixture_write_paths.push(Path::new(path));
            }
        }
        if let Err(error) = unpin_core::fixture::require_fixture_write_sandbox(
            self.fixture_mode,
            fixture_write_paths,
        ) {
            blocked.reason = Some(error);
            return blocked;
        }
        let expectation = match plan.approval_expectation(context) {
            Ok(expectation) => expectation,
            Err(error) => {
                blocked.reason = Some(error.to_string());
                return blocked;
            }
        };
        let authorization = match credentials::authorize_control_decision(
            self.fixture_mode,
            &self.app_state_root,
            &expectation,
            "unpin-tui-native-toggle-approval",
            unix_now(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => {
                blocked.reason = Some(error);
                return blocked;
            }
        };
        match self
            .native_toggle_controller()
            .apply(plan, authorization, context, backup_key)
        {
            Ok(result) => result,
            Err(error) => {
                blocked.reason = Some(error.to_string());
                blocked
            }
        }
    }

    fn control_state_root(&self) -> PathBuf {
        if self.fixture_mode {
            std::fs::canonicalize(&self.app_state_root)
                .unwrap_or_else(|_| self.app_state_root.clone())
        } else {
            self.app_state_root.clone()
        }
    }

    fn native_toggle_controller(&self) -> NativeToggleController {
        match self.session_authority_key.clone() {
            Some(key) => {
                NativeToggleController::with_session_authority_key(self.control_state_root(), key)
            }
            None => NativeToggleController::new(self.control_state_root()),
        }
    }

    fn rediscover_after_apply(&mut self) -> Result<DiscoveryOutput, String> {
        let roots = self
            .discovery_roots
            .clone()
            .ok_or_else(|| "discovery roots are unavailable after apply".to_string())?;
        let roots = roots.with_app_state_root(&self.app_state_root);
        let discovery = discover_all(&roots).map_err(|error| error.to_string())?;
        self.refresh_discovery(&discovery);
        Ok(discovery)
    }

    fn clear_staged(&mut self) {
        self.staged.clear();
        self.pending_confirmation = false;
    }

    fn search_query(&self) -> &str {
        &self.search_query
    }

    fn search_editing(&self) -> bool {
        self.search_editing
    }

    fn start_search_editing(&mut self) {
        self.search_editing = true;
    }

    fn finish_search_editing(&mut self) {
        self.search_editing = false;
        self.clamp_selected();
    }

    #[cfg(test)]
    fn set_search_query(&mut self, query: impl Into<String>) {
        self.search_query = query.into();
        self.clamp_selected();
    }

    fn clear_search_query(&mut self) {
        self.search_query.clear();
        self.search_editing = false;
        self.clamp_selected();
    }

    fn push_search_char(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        self.search_query.push(ch);
        self.clamp_selected();
    }

    fn pop_search_char(&mut self) {
        self.search_query.pop();
        self.clamp_selected();
    }

    fn refresh_discovery(&mut self, discovery: &DiscoveryOutput) {
        self.items.clone_from(&discovery.items);
        self.warnings.clone_from(&discovery.warnings);
        self.backups = load_backup_summaries_authenticated(
            &self.app_state_root,
            self.backup_authentication_key.as_ref(),
        );
        self.selected = 0;
        self.clear_staged();
        self.clamp_selected();
    }

    fn staged_count(&self) -> usize {
        self.staged.len()
    }

    fn pending_confirmation(&self) -> bool {
        self.pending_confirmation
    }

    fn staged_summary_strings(&self) -> Vec<String> {
        self.staged.values().map(staged_toggle_label).collect()
    }

    fn move_next(&mut self) {
        match self.view {
            TuiView::Groups => {
                let visible_count = self.visible_count();
                return self.group_workflow.select_next(visible_count);
            }
            TuiView::Profiles => return self.profile_workflow.select_next(),
            TuiView::Gateways => return self.gateway_workflow.select_next(),
            TuiView::Sessions => return self.session_workflow.select_next(),
            TuiView::Hooks => return self.hook_workflow.select_next(),
            TuiView::RestoreOperations => return self.restore_workflow.select_next(),
            TuiView::Inventory => {}
        }
        let visible_count = self.visible_count();
        if visible_count == 0 {
            return;
        }

        self.selected = (self.selected + 1) % visible_count;
    }

    fn move_previous(&mut self) {
        match self.view {
            TuiView::Groups => {
                let visible_count = self.visible_count();
                return self.group_workflow.select_previous(visible_count);
            }
            TuiView::Profiles => return self.profile_workflow.select_previous(),
            TuiView::Gateways => return self.gateway_workflow.select_previous(),
            TuiView::Sessions => return self.session_workflow.select_previous(),
            TuiView::Hooks => return self.hook_workflow.select_previous(),
            TuiView::RestoreOperations => return self.restore_workflow.select_previous(),
            TuiView::Inventory => {}
        }
        let visible_count = self.visible_count();
        if visible_count == 0 {
            return;
        }

        self.selected = if self.selected == 0 {
            visible_count - 1
        } else {
            self.selected - 1
        };
    }

    fn cycle_provider_filter(&mut self) {
        let choices = self.provider_choices();
        self.provider_filter = next_choice(self.provider_filter, &choices);
        self.clamp_selected();
    }

    fn cycle_layer_filter(&mut self) {
        let choices = self.layer_choices();
        self.layer_filter = next_choice(self.layer_filter, &choices);
        self.clamp_selected();
    }

    fn cycle_category_filter(&mut self) {
        let choices = self.category_choices();
        self.category_filter = next_choice(self.category_filter, &choices);
        self.clamp_selected();
    }

    fn visible_items(&self) -> Vec<&DiscoveryItem> {
        self.visible_indices()
            .into_iter()
            .filter_map(|index| self.items.get(index))
            .collect()
    }

    fn visible_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| self.matches_filters(item))
            .count()
    }

    fn selected_position(&self) -> Option<(usize, usize)> {
        let visible_count = self.visible_count();
        if visible_count == 0 {
            None
        } else {
            Some((self.selected + 1, visible_count))
        }
    }

    fn filter_summary(&self) -> String {
        format!(
            "provider={} layer={} category={}",
            self.provider_filter.label(),
            self.layer_filter.label(),
            self.category_filter.label()
        )
    }

    fn visible_indices(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| self.matches_filters(item).then_some(index))
            .collect()
    }

    fn matches_filters(&self, item: &DiscoveryItem) -> bool {
        self.provider_filter.matches(item)
            && self.layer_filter.matches(item)
            && self.category_filter.matches(item)
            && self.matches_search(item)
    }

    fn matches_search(&self, item: &DiscoveryItem) -> bool {
        let query = self.search_query.trim();
        if query.is_empty() {
            return true;
        }

        let query = query.to_lowercase();
        [
            item.id.as_str(),
            item.display_name.as_str(),
            item.provider.as_str(),
            item.layer.as_str(),
            item.category.as_str(),
            item.kind.as_str(),
            item.source_path.as_str(),
            item.state_path.as_str(),
        ]
        .iter()
        .any(|field| field.to_lowercase().contains(&query))
    }

    fn clamp_selected(&mut self) {
        let visible_count = self.visible_count();
        if visible_count == 0 {
            self.selected = 0;
        } else if self.selected >= visible_count {
            self.selected = visible_count - 1;
        }
        self.group_workflow.clamp_member_selection(visible_count);
    }

    fn provider_choices(&self) -> Vec<ProviderFilter> {
        let mut choices = vec![ProviderFilter::All];
        for provider in ProviderId::ALL {
            if self.items.iter().any(|item| item.provider == provider) {
                choices.push(ProviderFilter::Provider(provider));
            }
        }
        choices
    }

    fn layer_choices(&self) -> Vec<LayerFilter> {
        let mut choices = vec![LayerFilter::All];
        for layer in [DiscoveryLayer::Global, DiscoveryLayer::Project] {
            if self.items.iter().any(|item| item.layer == layer) {
                choices.push(LayerFilter::Layer(layer));
            }
        }
        choices
    }

    fn category_choices(&self) -> Vec<CategoryFilter> {
        let mut choices = vec![CategoryFilter::All];
        for category in [
            DiscoveryCategory::Skill,
            DiscoveryCategory::ConfiguredMcp,
            DiscoveryCategory::Tool,
            DiscoveryCategory::Agent,
            DiscoveryCategory::Hook,
            DiscoveryCategory::ProviderSetting,
            DiscoveryCategory::PluginConfig,
            DiscoveryCategory::PluginManifest,
        ] {
            if self.items.iter().any(|item| item.category == category) {
                choices.push(CategoryFilter::Category(category));
            }
        }
        choices
    }
}

#[cfg(test)]
fn default_backup_authentication_key() -> Option<BackupAuthenticationKey> {
    Some(BackupAuthenticationKey::new([0x42; 32]))
}

#[cfg(test)]
fn default_session_authority_key() -> Option<SessionAuthorityKey> {
    Some(SessionAuthorityKey::new([0x53; 32]))
}

impl ProviderFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Provider(provider) => provider.as_str(),
        }
    }

    fn matches(self, item: &DiscoveryItem) -> bool {
        match self {
            Self::All => true,
            Self::Provider(provider) => item.provider == provider,
        }
    }
}

impl LayerFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Layer(layer) => layer.as_str(),
        }
    }

    fn matches(self, item: &DiscoveryItem) -> bool {
        match self {
            Self::All => true,
            Self::Layer(layer) => item.layer == layer,
        }
    }
}

impl CategoryFilter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Category(category) => category.as_str(),
        }
    }

    fn matches(self, item: &DiscoveryItem) -> bool {
        match self {
            Self::All => true,
            Self::Category(category) => item.category == category,
        }
    }
}

fn next_choice<T: Copy + Eq>(current: T, choices: &[T]) -> T {
    let Some(current_index) = choices.iter().position(|choice| *choice == current) else {
        return choices.first().copied().unwrap_or(current);
    };
    choices
        .get((current_index + 1) % choices.len())
        .copied()
        .unwrap_or(current)
}

pub fn render_headless_with_paths(
    discovery: &DiscoveryOutput,
    app_state_root: PathBuf,
    project_root: PathBuf,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    session_authority_key: Option<SessionAuthorityKey>,
) -> String {
    let state = TuiState::new_with_paths_and_key(
        discovery.clone(),
        app_state_root,
        project_root,
        backup_authentication_key,
        session_authority_key,
    );
    render_headless_state(&state)
}

fn render_headless_state(state: &TuiState) -> String {
    let mut lines = vec![
        "Unpin".to_string(),
        format!("Items: {}", state.items.len()),
        format!("Showing: {}", state.visible_count()),
        format!("Warnings: {}", state.warnings.len()),
        format!("Backups: {}", state.backups.len()),
        format!(
            "Backup authentication: {}",
            backup_authentication_readiness_label(state)
        ),
        format!("Staged: {}", state.staged_count()),
        format!("Last action: {}", last_action_label(state)),
        format!("Last control: {}", last_control_label(state)),
        format!("View: {}", state.view.label()),
        provider_summary(&state.items),
        format!("Filters: {}", state.filter_summary()),
        format!("Search: {}", search_summary(state)),
        String::new(),
    ];

    lines.push("Control plane:".to_string());
    if let Some(control) = &state.control_status {
        let active_gateways = control
            .gateways
            .iter()
            .filter(|row| {
                row.mode.as_ref().is_some_and(|mode| {
                    mode.routing == unpin_core::sessions::GatewayRoutingState::Active
                })
            })
            .count();
        lines.push(format!(
            "Catalog: total={} active={}",
            control.catalog.total, control.catalog.active
        ));
        lines.push(format!("Profiles: {}", state.profile_workflow.len()));
        lines.push(format!("Gateways: {}", state.gateway_workflow.len()));
        lines.push(format!("Gateway active targets: {active_gateways}"));
        lines.push(format!("Sessions: {}", state.session_workflow.len()));
        lines.push(format!("Hooks: {}", state.hook_workflow.len()));
        lines.push(format!("Hook coverage rows: {}", control.hooks.len()));
        lines.push(format!("Operations: {}", control.operations.len()));
    } else {
        lines.push(format!(
            "Unavailable: {}",
            state.control_status_error.as_deref().unwrap_or("unknown")
        ));
    }
    lines.push(String::new());

    if state.view == TuiView::Inventory {
        if let Some(item) = state.selected_item() {
            let (position, total) = state
                .selected_position()
                .expect("selected item has a visible position");
            lines.push(format!("Selected: {position}/{total}"));
            lines.extend(selected_detail_strings(item));
            lines.extend(plan_preview_strings(state, item));
        } else {
            lines.push("Selected: none".to_string());
            lines.push("No discovered items match current filters.".to_string());
        }
    } else {
        lines.push(format!("Control view: {}", state.view.label()));
        lines.extend(state.active_rows());
        lines.extend(state.active_details());
    }

    if !state.warnings.is_empty() {
        lines.push(String::new());
        lines.push("Warning details:".to_string());
        lines.extend(state.warnings.iter().map(warning_label));
    }

    if !state.backups.is_empty() {
        lines.push(String::new());
        lines.push("Backup details:".to_string());
        lines.extend(state.backups.iter().map(backup_label));
    }

    if !state.staged.is_empty() {
        lines.push(String::new());
        lines.push("Staged changes:".to_string());
        lines.extend(state.staged_summary_strings());
        if state.pending_confirmation() {
            lines.push("Pending confirmation:".to_string());
            lines.push(confirmation_summary_label(state.staged_count()));
        }
    }

    lines.push(String::new());
    lines.push(
        "Commands: v view | j/k move | m action/backend | s profile-scope | r profile-provider | P group-reach | f force | p provider-filter | l layer | c category | / search | space plan | enter confirm | a apply | groups: X export-MCP | u unstage | q quit"
            .to_string(),
    );
    lines.join("\n")
}

pub fn run_interactive(
    discovery: DiscoveryOutput,
    app_state_root: PathBuf,
    project_root: PathBuf,
    discovery_roots: DiscoveryRoots,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    session_authority_key: Option<SessionAuthorityKey>,
    fixture_mode: bool,
) -> TuiResult<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = TuiState::new_with_paths_and_roots_and_key(
        discovery,
        app_state_root,
        project_root,
        discovery_roots,
        backup_authentication_key,
        session_authority_key,
    );
    state.fixture_mode = fixture_mode;

    let loop_result = run_loop(&mut terminal, &mut state);
    let restore_result = restore_terminal(&mut terminal);

    loop_result?;
    restore_result?;
    Ok(())
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
) -> TuiResult<()> {
    terminal.draw(|frame| draw(frame, state))?;
    loop {
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        match handle_tui_event(state, event::read()?) {
            TuiEventOutcome::Quit => return Ok(()),
            TuiEventOutcome::Redraw => {
                terminal.draw(|frame| draw(frame, state))?;
            }
            TuiEventOutcome::Ignore => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiEventOutcome {
    Redraw,
    Ignore,
    Quit,
}

fn handle_tui_event(state: &mut TuiState, event: Event) -> TuiEventOutcome {
    let should_draw = match event {
        Event::Resize(_, _) => true,
        Event::Paste(text) if state.group_text_editing() => {
            state.push_group_text(&text);
            true
        }
        Event::Key(key) if state.group_text_editing() => match key.code {
            KeyCode::Esc => {
                state.cancel_group_interaction();
                true
            }
            KeyCode::Enter => {
                state.finish_group_text_input();
                true
            }
            KeyCode::Backspace => {
                state.pop_group_text_char();
                true
            }
            KeyCode::Char(ch) => {
                state.push_group_text_char(ch);
                true
            }
            _ => false,
        },
        Event::Key(key) if state.search_editing() => match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                state.finish_search_editing();
                true
            }
            KeyCode::Backspace => {
                state.pop_search_char();
                true
            }
            KeyCode::Char(ch) => {
                state.push_search_char(ch);
                true
            }
            _ => false,
        },
        Event::Key(key) => match key.code {
            KeyCode::Char('q') => return TuiEventOutcome::Quit,
            KeyCode::Esc => {
                if !state.cancel_group_interaction() {
                    return TuiEventOutcome::Quit;
                }
                true
            }
            KeyCode::Char('v') => {
                state.cycle_view();
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                state.move_next();
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                state.move_previous();
                true
            }
            KeyCode::Char('m') => {
                state.cycle_active_action();
                true
            }
            KeyCode::Char('f') => {
                state.toggle_gateway_force();
                true
            }
            KeyCode::Char('s') => {
                state.cycle_profile_scope();
                true
            }
            KeyCode::Char('r') => {
                if state.view == TuiView::Groups {
                    state.stage_group_restore();
                } else {
                    state.cycle_profile_provider();
                }
                true
            }
            KeyCode::Char('n') => {
                state.start_group_create();
                true
            }
            KeyCode::Char('e') => {
                state.start_group_edit();
                true
            }
            KeyCode::Char('R') => {
                state.start_group_rename();
                true
            }
            KeyCode::Char('d') => {
                state.start_group_delete();
                true
            }
            KeyCode::Char('h') => {
                state.show_group_history();
                true
            }
            KeyCode::Char('o') => {
                state.start_group_mcp_approval();
                true
            }
            KeyCode::Char('w') => {
                state.stage_group_definition_save();
                true
            }
            KeyCode::Char('p') => {
                state.cycle_provider_filter();
                true
            }
            KeyCode::Char('P') => {
                state.cycle_group_provider_reach();
                true
            }
            KeyCode::Char('l') => {
                state.cycle_layer_filter();
                true
            }
            KeyCode::Char('c') => {
                state.cycle_category_filter();
                true
            }
            KeyCode::Char('/') => {
                state.start_search_editing();
                true
            }
            KeyCode::Char('x') => {
                state.clear_search_query();
                true
            }
            KeyCode::Char('X') => {
                state.export_group_mcp_handoff();
                true
            }
            KeyCode::Char(' ') => {
                if !state.toggle_group_member() {
                    state.plan_active_action();
                }
                true
            }
            KeyCode::Enter => {
                state.confirm_active_action();
                true
            }
            KeyCode::Char('a') => {
                state.apply_active_action();
                true
            }
            KeyCode::Char('u') => {
                state.clear_staged();
                true
            }
            _ => false,
        },
        _ => false,
    };
    if should_draw {
        TuiEventOutcome::Redraw
    } else {
        TuiEventOutcome::Ignore
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> TuiResult<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn draw(frame: &mut Frame<'_>, state: &TuiState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(14),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "Unpin",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("Items: {}", state.items.len())),
        Line::from(format!("Showing: {}", state.visible_count())),
        Line::from(format!("Warnings: {}", state.warnings.len())),
        Line::from(format!(
            "Backups: {} | Backup authentication: {}",
            state.backups.len(),
            backup_authentication_readiness_label(state)
        )),
        Line::from(format!("Staged: {}", state.staged_count())),
        Line::from(format!("Last action: {}", last_action_label(state))),
        Line::from(format!("Last control: {}", last_control_label(state))),
        Line::from(format!("View: {}", state.view.label())),
        Line::from(provider_summary(&state.items)),
        Line::from(format!("Filters: {}", state.filter_summary())),
        Line::from(format!("Search: {}", search_summary(state))),
    ])
    .block(Block::default().borders(Borders::ALL).title("Inventory"));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(chunks[1]);

    let active_rows = state.active_rows();
    let list_items = if active_rows.is_empty() {
        vec![ListItem::new("No rows in this view.")]
    } else {
        active_rows
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>()
    };
    let list = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(state.view.label()),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    if state.view == TuiView::Inventory {
        let mut list_state = ListState::default();
        if state.visible_count() > 0 {
            list_state.select(Some(state.selected));
        }
        frame.render_stateful_widget(list, body[0], &mut list_state);
    } else {
        frame.render_widget(list, body[0]);
    }

    let detail_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(body[1]);

    frame.render_widget(selected_detail(state), detail_chunks[0]);
    frame.render_widget(warning_detail(state), detail_chunks[1]);
    frame.render_widget(backup_detail(state), detail_chunks[2]);

    let footer = Paragraph::new(
        "v view | j/k move | m action/target | p/l/c filters | / search | space select/plan | enter confirm | a apply | groups: n/e/R/d/h/r/o/w/X-export | u unstage | q quit",
    )
    .block(Block::default().borders(Borders::ALL).title("Commands"));
    frame.render_widget(footer, chunks[2]);
}

fn selected_detail(state: &TuiState) -> Paragraph<'static> {
    if state.view != TuiView::Inventory {
        let lines: Vec<_> = state.active_details().into_iter().map(Line::from).collect();
        return Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Control"));
    }
    let lines = if let Some(item) = state.selected_item() {
        let mut lines = Vec::new();
        if let Some((position, total)) = state.selected_position() {
            lines.push(Line::from(format!("selected: {position}/{total}")));
        }
        lines.extend(selected_detail_strings(item).into_iter().map(Line::from));
        lines.extend(
            plan_preview_strings(state, item)
                .into_iter()
                .map(Line::from),
        );
        lines
    } else {
        vec![
            Line::from("selected: none"),
            Line::from("No discovered items match current filters."),
        ]
    };

    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Selected"))
}

fn warning_detail(state: &TuiState) -> Paragraph<'static> {
    let lines = if state.warnings.is_empty() {
        vec![Line::from("No discovery warnings.")]
    } else {
        state
            .warnings
            .iter()
            .map(|warning| Line::from(warning_label(warning)))
            .collect()
    };

    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Warnings"))
}

fn backup_detail(state: &TuiState) -> Paragraph<'static> {
    let lines = if state.backups.is_empty() {
        vec![Line::from("No backups found.")]
    } else {
        state
            .backups
            .iter()
            .map(|backup| Line::from(backup_label(backup)))
            .collect()
    };

    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Backups"))
}

fn selected_detail_strings(item: &DiscoveryItem) -> Vec<String> {
    vec![
        format!("id: {}", item.id),
        format!("provider: {}", item.provider.as_str()),
        format!("layer: {}", item.layer.as_str()),
        format!("category: {}", item.category.as_str()),
        format!("kind: {}", item.kind.as_str()),
        format!("enabled: {}", item.enabled),
        format!("mutability: {}", mutability_label(item.mutability)),
        format!("source: {}", item.source_path),
        format!("state: {}", item.state_path),
    ]
}

fn plan_preview_strings(state: &TuiState, item: &DiscoveryItem) -> Vec<String> {
    let plan = plan_toggle(TogglePlanRequest {
        app_state_root: state.app_state_root.clone(),
        item: item.clone(),
    });

    render_plan_preview(&plan)
}

fn render_plan_preview(plan: &ToggleResult) -> Vec<String> {
    let mut lines = vec![
        "Plan preview:".to_string(),
        format!("plan status: {}", toggle_status_label(plan.status)),
        format!("target enabled: {}", plan.target_enabled),
    ];

    if plan.operations.is_empty() {
        lines.push("operation: none".to_string());
    } else {
        for operation in &plan.operations {
            lines.push(format!("operation: {}", operation.operation_type));
            if let Some(from_path) = &operation.from_path {
                lines.push(format!("  from: {from_path}"));
            }
            if let Some(to_path) = &operation.to_path {
                lines.push(format!("  to: {to_path}"));
            }
            lines.push(format!("  {}", operation.summary));
        }
    }

    if !plan.affected_targets.is_empty() {
        lines.push("affected targets:".to_string());
        for target in &plan.affected_targets {
            lines.push(format!("  {} {}", target.target_type, target.path));
        }
    }

    if let Some(reason) = &plan.reason {
        lines.push(format!("reason: {reason}"));
    }
    if let Some(writes) = &plan.writes {
        lines.push(format!("writes: {writes}"));
    }

    lines
}

fn toggle_status_label(status: ToggleStatus) -> &'static str {
    match status {
        ToggleStatus::DryRun => "dry-run",
        ToggleStatus::Applied => "applied",
        ToggleStatus::Blocked => "blocked",
        ToggleStatus::RecoveryRequired => "recovery-required",
    }
}

fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

fn mutability_label(mutability: DiscoveryMutability) -> &'static str {
    match mutability {
        DiscoveryMutability::ReadWrite => "read-write",
        DiscoveryMutability::ReadOnly => "read-only",
        DiscoveryMutability::Unsupported => "unsupported",
    }
}

fn warning_label(warning: &DiscoveryWarning) -> String {
    let layer = warning
        .layer
        .map(|layer| format!(" {}", layer.as_str()))
        .unwrap_or_default();
    format!(
        "- {}{} {}: {}",
        warning.provider.as_str(),
        layer,
        warning.code,
        warning.message
    )
}

fn backup_label(backup: &BackupSummary) -> String {
    format!(
        "- {} created: {} entries: {} restorable: {} authentication: {}",
        backup.backup_id,
        backup.created_at,
        backup.item_count,
        backup.restorable,
        backup_authentication_label(backup.authentication)
    )
}

fn backup_authentication_label(authentication: BackupAuthenticationStatus) -> &'static str {
    match authentication {
        BackupAuthenticationStatus::Verified => "verified",
        BackupAuthenticationStatus::LegacyUnauthenticated => "legacy-unauthenticated",
        BackupAuthenticationStatus::KeyUnavailable => "key-unavailable",
        BackupAuthenticationStatus::Failed => "failed",
    }
}

fn backup_authentication_readiness_label(state: &TuiState) -> &'static str {
    if state.backup_authentication_key.is_some() {
        "ready"
    } else {
        "unavailable (writes disabled)"
    }
}

fn staged_toggle_label(staged: &StagedToggle) -> String {
    format!(
        "- {} -> {}",
        staged.item.id,
        if staged.target_enabled { "on" } else { "off" }
    )
}

fn confirmation_summary_label(count: usize) -> String {
    format!("Confirm {count} {}", staged_change_label(count))
}

fn staged_change_label(count: usize) -> &'static str {
    if count == 1 {
        "staged change"
    } else {
        "staged changes"
    }
}

fn last_action_label(state: &TuiState) -> String {
    match &state.last_action {
        Some(TuiActionStatus::Success(message)) => format!("success: {message}"),
        Some(TuiActionStatus::Error(message)) => format!("error: {message}"),
        None => "none".to_string(),
    }
}

fn last_control_label(state: &TuiState) -> String {
    state.last_control_envelope.as_ref().map_or_else(
        || "none".to_string(),
        |envelope| {
            format!(
                "{} {:?} {}",
                envelope.operation_kind, envelope.lifecycle, envelope.operation_id
            )
        },
    )
}

fn search_summary(state: &TuiState) -> String {
    let query = state.search_query();
    if query.is_empty() {
        if state.search_editing() {
            "editing".to_string()
        } else {
            "none".to_string()
        }
    } else if state.search_editing() {
        format!("{query} (editing)")
    } else {
        query.to_string()
    }
}

fn provider_summary(items: &[DiscoveryItem]) -> String {
    let counts = ProviderId::ALL
        .into_iter()
        .map(|provider| format!("{}={}", provider.as_str(), count_provider(items, provider)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("Providers: {counts}")
}

fn count_provider(items: &[DiscoveryItem], provider: ProviderId) -> usize {
    items
        .iter()
        .filter(|item| item.provider == provider)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path, process::Command as StdCommand};
    use tempfile::TempDir;
    use unpin_core::discovery::{
        DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots,
        discover_all,
    };
    use unpin_core::groups::{
        GROUP_DEFINITION_SCHEMA_VERSION, GroupDefinitionV1, GroupPlanMode, GroupPlanner, GroupRef,
        GroupResolver, GroupTargetState, McpGroupSessionBinding, McpGroupSessionLeaseStore,
        PersonalGroupStore, RepositoryGroupStore, issue_group_approval_challenge,
    };
    use unpin_core::mutation::{
        TogglePlanRequest, ToggleStatus, authenticate_legacy_backup, plan_toggle,
    };
    use unpin_core::profiles::{PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileStore};
    use unpin_core::snapshots::load_latest_discovery_snapshot;
    use unpin_core::state::atomic_json::OwnerGeneration;

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cli crate has workspace crates parent")
            .join("unpin-core")
            .join("tests")
            .join("fixtures")
    }

    fn copy_dir_all(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create destination");
        for entry in fs::read_dir(source).expect("read source directory") {
            let entry = entry.expect("read directory entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if source_path.is_dir() {
                copy_dir_all(&source_path, &destination_path);
            } else {
                fs::copy(&source_path, &destination_path).expect("copy file");
            }
        }
    }

    fn key_event(code: KeyCode) -> Event {
        Event::Key(crossterm::event::KeyEvent::new(
            code,
            crossterm::event::KeyModifiers::NONE,
        ))
    }

    #[test]
    fn group_mcp_approval_event_path_issues_and_exports_without_provider_writes() {
        let temp = TempDir::new().expect("temporary TUI approval root");
        let root = fs::canonicalize(temp.path()).expect("canonical TUI approval root");
        let app_state_root = root.join("state");
        let project_root = root.join("project");
        fs::create_dir_all(&app_state_root).expect("app state");
        fs::create_dir_all(&project_root).expect("project root");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(&project_root)
            .output()
            .expect("git init");
        assert!(git.status.success());

        let roots =
            DiscoveryRoots::fixture_root(fixtures_root()).with_app_state_root(&app_state_root);
        let discovery = discover_all(&roots).expect("fixture discovery");
        let member_item = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:configured-mcp:github")
            .expect("toggleable fixture MCP");
        let member = GroupMemberIdentity::try_from(member_item).expect("group member identity");
        let provider_path = PathBuf::from(&member_item.source_path);
        let provider_before = fs::read(&provider_path).expect("provider config before approval");
        let backup_key = BackupAuthenticationKey::new([0x42; 32]);
        let session_key = SessionAuthorityKey::new([0x53; 32]);
        let access =
            GroupAccessContext::from_runtime(&app_state_root, &project_root, &roots, None, None)
                .expect("group access");
        let personal = PersonalGroupStore::new(access.clone())
            .with_history_authentication_key(backup_key.clone());
        personal
            .create(
                &GroupDefinitionV1 {
                    schema_version: GROUP_DEFINITION_SCHEMA_VERSION,
                    name: "event-approval".to_string(),
                    members: vec![member],
                },
                OwnerGeneration::new("tui-event-test", 1).expect("owner"),
            )
            .expect("create approval group");
        let repository = RepositoryGroupStore::new(access.clone())
            .with_history_authentication_key(backup_key.clone());
        let plan = GroupPlanner::new(GroupResolver::new(access.clone(), personal, repository))
            .plan(
                &GroupRef::parse("personal:event-approval").expect("group reference"),
                GroupTargetState::Disable,
                10,
                GroupPlanMode::McpHandoff,
            )
            .expect("MCP handoff plan");
        let now_unix = unix_now();
        let lease_store = McpGroupSessionLeaseStore::new(&app_state_root);
        let session = lease_store
            .create(
                McpGroupSessionBinding {
                    provider: None,
                    repository_key: access.repository_key().to_string(),
                    workspace_key: access.workspace_key().to_string(),
                },
                &session_key,
                now_unix,
            )
            .expect("MCP session lease");
        let lease_expires_at = lease_store
            .verify(&session, &session_key, now_unix)
            .expect("session expiry");
        let challenge =
            issue_group_approval_challenge(plan, session, lease_expires_at, &session_key, now_unix)
                .expect("approval challenge");

        let mut state = TuiState::new_with_paths_and_roots_and_key(
            discovery,
            app_state_root.clone(),
            project_root,
            roots,
            Some(backup_key),
            Some(session_key),
        );
        state.fixture_mode = true;
        state.view = TuiView::Groups;

        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('o'))),
            TuiEventOutcome::Redraw
        );
        assert!(state.group_text_editing());
        assert_eq!(
            handle_tui_event(&mut state, Event::Paste(challenge)),
            TuiEventOutcome::Redraw
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Enter)),
            TuiEventOutcome::Redraw
        );
        assert!(
            state
                .group_workflow
                .details()
                .iter()
                .any(|line| line.contains("MCP approval review"))
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Enter)),
            TuiEventOutcome::Redraw
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('a'))),
            TuiEventOutcome::Redraw
        );
        let handoff = state
            .mcp_approval_handoff
            .clone()
            .expect("issued handoff remains structured");
        assert_eq!(
            fs::read(&provider_path).expect("provider config after approval"),
            provider_before
        );
        assert!(!app_state_root.join("backups").exists());

        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('X'))),
            TuiEventOutcome::Redraw
        );
        let export_path = app_state_root
            .join("groups")
            .join("handoff-exports")
            .join(format!("{}.json", handoff.approval_artifact));
        let exported = AtomicJsonStore::new(export_path, 1)
            .load::<serde_json::Value>()
            .expect("load exported handoff")
            .expect("exported handoff document");
        assert_eq!(exported.value, handoff.export_value());

        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('o'))),
            TuiEventOutcome::Redraw
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Esc)),
            TuiEventOutcome::Redraw,
            "Esc cancels the active interaction before quitting"
        );
        assert!(!state.group_text_editing());
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Esc)),
            TuiEventOutcome::Quit
        );
    }

    fn item(
        id: &str,
        provider: ProviderId,
        layer: DiscoveryLayer,
        category: DiscoveryCategory,
        kind: DiscoveryKind,
    ) -> DiscoveryItem {
        DiscoveryItem {
            provider,
            kind,
            category,
            layer,
            id: id.to_string(),
            display_name: id.to_string(),
            enabled: true,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: format!("/fixtures/{id}"),
            state_path: format!("/state/{id}"),
            source_fingerprint: None,
            hook: None,
        }
    }

    fn discovery(items: Vec<DiscoveryItem>) -> DiscoveryOutput {
        DiscoveryOutput {
            items,
            warnings: Vec::new(),
        }
    }

    fn discovery_with_warnings(
        items: Vec<DiscoveryItem>,
        warnings: Vec<DiscoveryWarning>,
    ) -> DiscoveryOutput {
        DiscoveryOutput { items, warnings }
    }

    #[test]
    fn headless_state_renders_shared_control_plane_summary() {
        let temp = TempDir::new().expect("temporary TUI control root");
        let root = fs::canonicalize(temp.path()).expect("canonical TUI control root");
        let project = root.join("project");
        let state = root.join("state");
        fs::create_dir(&project).expect("project directory");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .output()
            .expect("git init");
        assert!(git.status.success());
        ProfileStore::new(&state)
            .save_global_definition(
                &ProfileDefinition {
                    version: PROFILE_DEFINITION_VERSION,
                    id: "review".to_string(),
                    display_name: "Review".to_string(),
                    description: None,
                    members: Vec::new(),
                    provider_members: BTreeMap::new(),
                    supported_providers: std::collections::BTreeSet::new(),
                },
                None,
                OwnerGeneration::new("tui-control-test", 1).unwrap(),
            )
            .expect("save profile");
        let discovered =
            discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).expect("discovery");

        let rendered = render_headless_with_paths(
            &discovered,
            state,
            project,
            None,
            default_session_authority_key(),
        );
        assert!(rendered.contains("Control plane:"));
        assert!(rendered.contains("Profiles: 1"));
        assert!(rendered.contains("Gateway active targets: 0"));
        assert!(rendered.contains("Sessions: 0"));
        assert!(rendered.contains("Hook coverage rows: 6"));
    }

    fn write_backup_manifest(
        app_state_root: &Path,
        backup_id: &str,
        created_at: &str,
        entry_count: usize,
    ) {
        let entries = (0..entry_count)
            .map(|index| {
                let entry_id = format!("entry-{index}");
                serde_json::json!({
                    "entryId": entry_id,
                    "target": {
                        "targetType": "path",
                        "path": "/tmp/unpin-live-target"
                    },
                    "existed": true,
                    "pathKind": "file",
                    "payload": {
                        "storage": "path",
                        "path": format!("entries/{entry_id}/payload")
                    }
                })
            })
            .collect::<Vec<_>>();
        write_backup_manifest_value(
            app_state_root,
            backup_id,
            serde_json::json!({
                "version": 1,
                "backupId": backup_id,
                "createdAt": created_at,
                "selection": {
                    "provider": "claude",
                    "kind": "skill",
                    "category": "skill",
                    "layer": "project",
                    "id": "claude:project:skill:example",
                    "displayName": "example",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": "/tmp/unpin-source",
                    "statePath": "/tmp/unpin-state"
                },
                "targetEnabled": false,
                "affectedTargets": [
                    {
                        "targetType": "path",
                        "path": "/tmp/unpin-live-target"
                    }
                ],
                "entries": entries
            }),
        );
        for index in 0..entry_count {
            write_backup_file_payload(app_state_root, backup_id, &format!("entry-{index}"));
        }
    }

    fn write_backup_manifest_value(
        app_state_root: &Path,
        backup_dir: &str,
        manifest: serde_json::Value,
    ) {
        let manifest_path = app_state_root
            .join("backups")
            .join(backup_dir)
            .join("manifest.json");
        fs::create_dir_all(manifest_path.parent().expect("manifest has parent"))
            .expect("create manifest parent");
        fs::write(manifest_path, manifest.to_string()).expect("write manifest");
    }

    fn write_backup_file_payload(app_state_root: &Path, backup_dir: &str, entry_id: &str) {
        let payload_path = app_state_root
            .join("backups")
            .join(backup_dir)
            .join("entries")
            .join(entry_id)
            .join("payload");
        fs::create_dir_all(payload_path.parent().expect("payload has parent"))
            .expect("create payload parent");
        fs::write(payload_path, "backup\n").expect("write payload");
    }

    fn backup_manifest(
        backup_id: &str,
        created_at: &str,
        payload_path: Option<&str>,
    ) -> serde_json::Value {
        let entries = payload_path
            .map(|path| {
                serde_json::json!([{
                    "entryId": "entry-1",
                    "target": {
                        "targetType": "path",
                        "path": "/tmp/unpin-live-target"
                    },
                    "existed": true,
                    "pathKind": "file",
                    "payload": {
                        "storage": "path",
                        "path": path
                    }
                }])
            })
            .unwrap_or_else(|| serde_json::json!([]));

        serde_json::json!({
            "version": 1,
            "backupId": backup_id,
            "createdAt": created_at,
            "selection": {
                "provider": "claude",
                "kind": "skill",
                "category": "skill",
                "layer": "project",
                "id": "claude:project:skill:example",
                "displayName": "example",
                "enabled": true,
                "mutability": "read-write",
                "sourcePath": "/tmp/unpin-source",
                "statePath": "/tmp/unpin-state"
            },
            "targetEnabled": false,
            "affectedTargets": [
                {
                    "targetType": "path",
                    "path": "/tmp/unpin-live-target"
                }
            ],
            "entries": entries
        })
    }

    #[test]
    fn tui_control_view_plans_and_confirms_profile_policy() {
        let temp = TempDir::new().expect("temporary TUI control root");
        let root = fs::canonicalize(temp.path()).expect("canonical TUI control root");
        let project = root.join("project");
        let state_root = root.join("state");
        fs::create_dir(&project).expect("project directory");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .output()
            .expect("git init");
        assert!(git.status.success());
        ProfileStore::new(&state_root)
            .save_global_definition(
                &ProfileDefinition {
                    version: PROFILE_DEFINITION_VERSION,
                    id: "review".to_string(),
                    display_name: "Review".to_string(),
                    description: None,
                    members: Vec::new(),
                    provider_members: BTreeMap::new(),
                    supported_providers: std::collections::BTreeSet::from([ProviderId::Codex]),
                },
                None,
                OwnerGeneration::new("tui-profile-workflow-test", 1).unwrap(),
            )
            .unwrap();
        let discovered = discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).unwrap();
        let mut state = TuiState::new_with_paths(discovered, state_root, project);

        state.cycle_view();
        state.cycle_view();
        assert_eq!(state.view, TuiView::Profiles);
        assert!(state.plan_active_action());
        assert_eq!(state.profile_workflow.phase(), WorkflowPhase::Planned);
        assert!(state.confirm_active_action());
        assert_eq!(state.profile_workflow.phase(), WorkflowPhase::Confirmed);
        assert!(render_headless_state(&state).contains("Control view: profiles"));
    }

    #[test]
    fn tui_restore_view_plans_authenticated_backup() {
        let temp = TempDir::new().expect("temporary TUI restore root");
        let root = fs::canonicalize(temp.path()).expect("canonical TUI restore root");
        let project = root.join("project");
        let state_root = root.join("state");
        fs::create_dir(&project).expect("project directory");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .output()
            .expect("git init");
        assert!(git.status.success());
        let live_target = root.join("live-target");
        fs::write(&live_target, "current\n").expect("write live target");
        let target = live_target.to_string_lossy().into_owned();
        write_backup_manifest_value(
            &state_root,
            "backup-one",
            serde_json::json!({
                "version": 1,
                "backupId": "backup-one",
                "createdAt": "2026-06-20T12:00:00Z",
                "selection": {
                    "provider": "claude",
                    "kind": "skill",
                    "category": "skill",
                    "layer": "project",
                    "id": "claude:project:skill:example",
                    "displayName": "example",
                    "enabled": true,
                    "mutability": "read-write",
                    "sourcePath": target.clone(),
                    "statePath": target.clone()
                },
                "targetEnabled": false,
                "affectedTargets": [{"targetType": "path", "path": target.clone()}],
                "entries": [{
                    "entryId": "entry-0",
                    "target": {"targetType": "path", "path": target},
                    "existed": true,
                    "pathKind": "file",
                    "payload": {"storage": "path", "path": "entries/entry-0/payload"}
                }]
            }),
        );
        write_backup_file_payload(&state_root, "backup-one", "entry-0");
        authenticate_legacy_backup(
            &state_root,
            "backup-one",
            &BackupAuthenticationKey::new([0x42; 32]),
        )
        .unwrap();
        let mut state =
            TuiState::new_with_paths(discovery(Vec::new()), state_root.clone(), project);

        for _ in 0..6 {
            state.cycle_view();
        }
        assert_eq!(state.view, TuiView::RestoreOperations);
        assert!(state.plan_active_action());
        assert_eq!(state.restore_workflow.phase, WorkflowPhase::Planned);
        assert!(state.confirm_active_action());
        assert_eq!(state.restore_workflow.phase, WorkflowPhase::Confirmed);
        assert!(
            state
                .active_details()
                .iter()
                .any(|line| line.starts_with("plan: "))
        );
        state.apply_active_action();
        assert_eq!(
            state
                .last_control_envelope
                .as_ref()
                .expect("restore result envelope")
                .lifecycle,
            ControlOperationLifecycle::Applied
        );
        assert!(
            state
                .control_status
                .as_ref()
                .is_some_and(|control| !control.operations.is_empty())
        );
        assert_eq!(fs::read_to_string(live_target).unwrap(), "backup\n");
    }

    fn skill_item_at(id: &str, path: &Path) -> DiscoveryItem {
        let mut item = item(
            id,
            ProviderId::Claude,
            DiscoveryLayer::Project,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        let path = path.to_string_lossy().to_string();
        item.source_path = path.clone();
        item.state_path = path;
        item
    }

    #[test]
    fn model_cycles_filters_and_clamps_selection() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-global-tool",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "codex-project-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
            item(
                "cursor-global-agent",
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                DiscoveryCategory::Agent,
                DiscoveryKind::Agent,
            ),
        ]));

        state.move_next();
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "codex-project-skill"
        );

        state.cycle_provider_filter();
        assert_eq!(
            state.filter_summary(),
            "provider=claude layer=all category=all"
        );
        assert_eq!(state.visible_count(), 1);
        assert_eq!(state.selected_position(), Some((1, 1)));
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "claude-global-tool"
        );

        state.cycle_provider_filter();
        state.cycle_layer_filter();
        assert_eq!(
            state.filter_summary(),
            "provider=codex layer=global category=all"
        );
        assert_eq!(state.visible_count(), 0);
        assert_eq!(state.selected_position(), None);
        assert!(state.selected_item().is_none());

        state.cycle_layer_filter();
        state.cycle_category_filter();
        assert_eq!(
            state.filter_summary(),
            "provider=codex layer=project category=skill"
        );
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "codex-project-skill"
        );
    }

    #[test]
    fn movement_wraps_within_filtered_items() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-first",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "claude-second",
                ProviderId::Claude,
                DiscoveryLayer::Project,
                DiscoveryCategory::Agent,
                DiscoveryKind::Agent,
            ),
            item(
                "codex-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
        ]));

        state.cycle_provider_filter();
        assert_eq!(state.visible_count(), 2);
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "claude-first"
        );

        state.move_next();
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "claude-second"
        );
        state.move_next();
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "claude-first"
        );
        state.move_previous();
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "claude-second"
        );
    }

    #[test]
    fn tui_search_filters_visible_items_case_insensitively() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-first",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "codex-project-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
            item(
                "cursor-global-agent",
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                DiscoveryCategory::Agent,
                DiscoveryKind::Agent,
            ),
        ]));

        state.set_search_query("PROJECT-SKILL");
        assert_eq!(state.visible_count(), 1);
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "codex-project-skill"
        );

        state.set_search_query("cursor");
        assert_eq!(state.visible_count(), 1);
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "cursor-global-agent"
        );

        state.set_search_query("missing");
        assert_eq!(state.visible_count(), 0);
        assert!(state.selected_item().is_none());

        state.clear_search_query();
        assert_eq!(state.visible_count(), 3);
    }

    #[test]
    fn tui_search_editing_updates_query_and_selection() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-first",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "codex-project-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
        ]));

        state.start_search_editing();
        assert!(state.search_editing());
        for ch in "codex".chars() {
            state.push_search_char(ch);
        }
        assert_eq!(state.search_query(), "codex");
        assert_eq!(state.visible_count(), 1);
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "codex-project-skill"
        );

        state.pop_search_char();
        assert_eq!(state.search_query(), "code");
        state.finish_search_editing();
        assert!(!state.search_editing());

        state.clear_search_query();
        assert_eq!(state.search_query(), "");
        assert_eq!(state.visible_count(), 2);
    }

    #[test]
    fn tui_search_renders_in_headless_state() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-first",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "codex-project-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
        ]));

        state.set_search_query("codex");
        let output = render_headless_state(&state);

        assert!(output.contains("Search: codex"));
        assert!(output.contains("Showing: 1"));
        assert!(output.contains("id: codex-project-skill"));
    }

    #[test]
    fn headless_state_reports_empty_filtered_result() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "claude-global-tool",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "codex-project-skill",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
        ]));

        state.cycle_provider_filter();
        state.cycle_layer_filter();
        state.cycle_layer_filter();

        let output = render_headless_state(&state);
        assert!(output.contains("Filters: provider=claude layer=project category=all"));
        assert!(output.contains("Showing: 0"));
        assert!(output.contains("No discovered items match current filters."));
    }

    #[test]
    fn headless_state_reports_discovery_warnings() {
        let state = TuiState::new(discovery_with_warnings(
            vec![item(
                "cursor-global-hook",
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                DiscoveryCategory::Hook,
                DiscoveryKind::Hook,
            )],
            vec![DiscoveryWarning {
                provider: ProviderId::Cursor,
                layer: Some(DiscoveryLayer::Global),
                code: "json-parse-error".to_string(),
                message: "cursor/global/hooks.json could not be parsed".to_string(),
            }],
        ));

        let output = render_headless_state(&state);

        assert!(output.contains("Warnings: 1"));
        assert!(output.contains("Warning details:"));
        assert!(output.contains("- cursor global json-parse-error:"));
        assert!(output.contains("cursor/global/hooks.json could not be parsed"));
    }

    #[test]
    fn headless_state_reports_backup_summaries_sorted_newest_first() {
        let app_state = TempDir::new().expect("temp app state");
        write_backup_manifest(app_state.path(), "backup-old", "2026-06-20T10:00:00Z", 0);
        write_backup_manifest(app_state.path(), "backup-new", "2026-06-20T12:00:00Z", 1);
        authenticate_legacy_backup(
            app_state.path(),
            "backup-new",
            &BackupAuthenticationKey::new([0x42; 32]),
        )
        .expect("authenticate valid backup");

        let state = TuiState::new_with_app_state_root(
            discovery(vec![item(
                "claude-global-tool",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            )]),
            app_state.path().to_path_buf(),
        );

        let output = render_headless_state(&state);

        assert!(output.contains("Backups: 2"));
        assert!(output.contains("Backup details:"));
        let new_index = output.find("backup-new").expect("new backup is rendered");
        let old_index = output.find("backup-old").expect("old backup is rendered");
        assert!(
            new_index < old_index,
            "backups should sort newest first; got:\n{output}"
        );
        assert!(
            output
                .contains("- backup-new created: 2026-06-20T12:00:00Z entries: 1 restorable: true")
        );
        assert!(
            output.contains(
                "- backup-old created: 2026-06-20T10:00:00Z entries: 0 restorable: false"
            )
        );
    }

    #[test]
    fn headless_state_marks_invalid_backup_manifests_unrestorable() {
        let app_state = TempDir::new().expect("temp app state");
        write_backup_manifest_value(
            app_state.path(),
            "backup-valid",
            backup_manifest(
                "backup-valid",
                "2026-06-20T12:03:00Z",
                Some("entries/entry-1/payload"),
            ),
        );
        write_backup_file_payload(app_state.path(), "backup-valid", "entry-1");
        authenticate_legacy_backup(
            app_state.path(),
            "backup-valid",
            &BackupAuthenticationKey::new([0x42; 32]),
        )
        .expect("authenticate valid backup");
        write_backup_manifest_value(
            app_state.path(),
            "backup-mismatch",
            backup_manifest(
                "backup-other",
                "2026-06-20T12:02:00Z",
                Some("entries/entry-1/payload"),
            ),
        );
        write_backup_manifest_value(
            app_state.path(),
            "backup-traversal",
            backup_manifest(
                "backup-traversal",
                "2026-06-20T12:01:00Z",
                Some("../../outside-payload"),
            ),
        );
        write_backup_manifest_value(
            app_state.path(),
            "backup-empty",
            backup_manifest("backup-empty", "2026-06-20T12:00:00Z", None),
        );

        let state = TuiState::new_with_app_state_root(
            discovery(vec![item(
                "claude-global-tool",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            )]),
            app_state.path().to_path_buf(),
        );

        let output = render_headless_state(&state);

        assert!(output.contains("Backups: 4"));
        assert!(
            output.contains(
                "- backup-valid created: 2026-06-20T12:03:00Z entries: 1 restorable: true"
            )
        );
        assert!(
            output.contains(
                "- backup-other created: 2026-06-20T12:02:00Z entries: 1 restorable: false"
            )
        );
        assert!(output.contains(
            "- backup-traversal created: 2026-06-20T12:01:00Z entries: 1 restorable: false"
        ));
        assert!(
            output.contains(
                "- backup-empty created: 2026-06-20T12:00:00Z entries: 0 restorable: false"
            )
        );
    }

    #[test]
    fn headless_state_reports_dry_run_plan_preview() {
        let state = TuiState::new_with_app_state_root(
            discovery(vec![item(
                "claude:project:skill:example",
                ProviderId::Claude,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            )]),
            PathBuf::from("/tmp/unpin-state"),
        );

        let output = render_headless_state(&state);

        assert!(output.contains("Plan preview:"));
        assert!(output.contains("plan status: dry-run"));
        assert!(output.contains("target enabled: false"));
        assert!(output.contains("operation: renamePath"));
        assert!(output.contains("/tmp/unpin-state/vault/claude/project/skill/"));
        assert!(output.contains("writes: no writes were performed"));
    }

    #[test]
    fn headless_state_reports_blocked_plan_preview() {
        let mut read_only = item(
            "cursor:global:tool:extension:example",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryCategory::Tool,
            DiscoveryKind::Plugin,
        );
        read_only.mutability = DiscoveryMutability::ReadOnly;
        let state =
            TuiState::new_with_app_state_root(discovery(vec![read_only]), PathBuf::from("/state"));

        let output = render_headless_state(&state);

        assert!(output.contains("Plan preview:"));
        assert!(output.contains("plan status: blocked"));
        assert!(output.contains("reason: read-only item cannot be planned for toggle"));
    }

    #[test]
    fn state_stages_selected_toggle_and_confirmation_summary() {
        let mut state = TuiState::new(discovery(vec![item(
            "claude-global-tool",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Tool,
            DiscoveryKind::Setting,
        )]));

        assert!(state.stage_selected_toggle());
        assert_eq!(state.staged_count(), 1);
        assert!(!state.pending_confirmation());

        assert!(state.confirm_staged());
        assert!(state.pending_confirmation());

        let output = render_headless_state(&state);
        assert!(output.contains("Staged: 1"));
        assert!(output.contains("Staged changes:"));
        assert!(output.contains("- claude-global-tool -> off"));
        assert!(output.contains("Pending confirmation:"));
        assert!(output.contains("Confirm 1 staged change"));
    }

    #[test]
    fn state_blocks_shared_source_outside_selected_provider_reach() {
        let mut claude = item(
            "claude:global:skill:shared",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        claude.source_path = "/fixtures/shared/SKILL.md".to_string();
        claude.state_path = "/fixtures/shared".to_string();
        let mut cursor = item(
            "cursor:global:skill:@compat/claude/shared",
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        cursor.source_path.clone_from(&claude.source_path);
        cursor.state_path.clone_from(&claude.state_path);
        let mut state = TuiState::new(discovery(vec![claude, cursor]));

        assert!(state.stage_selected_toggle());
        let staged = state.staged.values().next().expect("staged item");
        assert!(staged.plan.is_none());
        assert_eq!(
            staged.blocked_reason.as_deref(),
            Some("native toggle blocked: shared-source-crosses-provider-reach")
        );
    }

    #[test]
    fn staged_inventory_uses_full_identity_for_same_id_items() {
        let mut state = TuiState::new(discovery(vec![
            item(
                "shared-name",
                ProviderId::Claude,
                DiscoveryLayer::Global,
                DiscoveryCategory::Tool,
                DiscoveryKind::Setting,
            ),
            item(
                "shared-name",
                ProviderId::Codex,
                DiscoveryLayer::Project,
                DiscoveryCategory::Skill,
                DiscoveryKind::Skill,
            ),
        ]));

        assert!(state.stage_selected_toggle());
        state.move_next();
        assert!(state.stage_selected_toggle());

        assert_eq!(state.staged_count(), 2);
        assert_eq!(state.staged_summary_strings().len(), 2);
    }

    #[test]
    fn group_member_selection_is_clamped_when_inventory_filters_shrink() {
        let first = item(
            "first-group-member",
            ProviderId::Codex,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        let second = item(
            "second-group-member",
            ProviderId::Codex,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        let mut state = TuiState::new(discovery(vec![first, second]));
        assert!(state.stage_selected_toggle());
        state.move_next();
        assert!(state.stage_selected_toggle());
        state.cycle_view();
        state.start_group_create();
        for character in "clamped".chars() {
            state.push_group_text_char(character);
        }
        state.finish_group_text_input();
        state.group_workflow.select_next(2);
        assert_eq!(state.group_workflow.member_selected_index(), 1);

        state.set_search_query("first-group-member");

        assert_eq!(state.visible_count(), 1);
        assert_eq!(state.group_workflow.member_selected_index(), 0);
    }

    #[test]
    fn tui_group_create_uses_staged_members_and_authenticated_definition_flow() {
        let temp = TempDir::new().expect("temporary group TUI root");
        let root = fs::canonicalize(temp.path()).expect("canonical group TUI root");
        let project = root.join("project");
        let state_root = root.join("state");
        fs::create_dir(&project).expect("project directory");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(&project)
            .output()
            .expect("git init");
        assert!(git.status.success());
        let fixture_root = fs::canonicalize(fixtures_root()).expect("canonical fixture root");
        let mut discovered =
            discover_all(&DiscoveryRoots::fixture_root(&fixture_root)).expect("fixture discovery");
        discovered.items.retain(|item| {
            item.mutability == DiscoveryMutability::ReadWrite
                && plan_toggle(TogglePlanRequest {
                    app_state_root: state_root.clone(),
                    item: item.clone(),
                })
                .status
                    == ToggleStatus::DryRun
        });
        discovered.items.truncate(2);
        assert_eq!(
            discovered.items.len(),
            2,
            "fixture must expose two individually toggleable items"
        );
        let mut state = TuiState::new_with_paths_and_roots(
            discovered,
            state_root,
            project,
            DiscoveryRoots::fixture_root(fixture_root),
        );

        assert!(state.stage_selected_toggle());
        state.move_next();
        assert!(state.stage_selected_toggle());
        state.cycle_view();
        assert_eq!(state.view, TuiView::Groups);

        state.start_group_create();
        assert!(state.group_text_editing());
        for character in "brainstorming".chars() {
            state.push_group_text_char(character);
        }
        state.finish_group_text_input();
        state.stage_group_definition_save();
        assert!(state.confirm_active_action());
        state.apply_active_action();

        assert_eq!(state.group_workflow.len(), 1);
        let details = state.group_workflow.details();
        assert!(
            details
                .iter()
                .any(|line| line.contains("personal:brainstorming"))
        );
        assert!(matches!(
            state.last_action,
            Some(TuiActionStatus::Success(ref message))
                if message.contains("authenticated history recorded")
        ));
        assert_eq!(state.staged_count(), 0);
        assert!(!state.pending_confirmation);
    }

    #[test]
    fn refresh_discovery_clears_staged_state() {
        let mut state = TuiState::new(discovery(vec![item(
            "claude-global-tool",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Tool,
            DiscoveryKind::Setting,
        )]));
        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());

        state.refresh_discovery(&discovery(vec![item(
            "codex-project-skill",
            ProviderId::Codex,
            DiscoveryLayer::Project,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        )]));

        assert_eq!(state.staged_count(), 0);
        assert!(!state.pending_confirmation());
        assert_eq!(
            state.selected_item().expect("selected item").id,
            "codex-project-skill"
        );
        let output = render_headless_state(&state);
        assert!(output.contains("Staged: 0"));
        assert!(!output.contains("Pending confirmation:"));
    }

    #[test]
    fn staged_apply_requires_confirmation() {
        let app_state = TempDir::new().expect("temp app state");
        let live_root = TempDir::new().expect("temp live root");
        let live_skill = live_root.path().join("example-skill");
        fs::create_dir_all(&live_skill).expect("create skill");
        fs::write(live_skill.join("SKILL.md"), "# Example\n").expect("write skill");
        let mut state = TuiState::new_with_app_state_root(
            discovery(vec![skill_item_at(
                "claude:project:skill:example",
                &live_skill,
            )]),
            app_state.path().to_path_buf(),
        );

        assert!(state.stage_selected_toggle());
        let results = state.apply_confirmed_staged();

        assert!(results.is_empty());
        assert_eq!(state.staged_count(), 1);
        assert!(live_skill.exists());
        assert!(state.backups.is_empty());
    }

    #[test]
    fn staged_apply_without_backup_key_stays_blocked() {
        let app_state = TempDir::new().expect("temp app state");
        let live_root = TempDir::new().expect("temp live root");
        let live_skill = live_root.path().join("example-skill");
        fs::create_dir_all(&live_skill).expect("create skill");
        fs::write(live_skill.join("SKILL.md"), "# Example\n").expect("write skill");
        let mut state = TuiState::new_with_app_state_root_and_key(
            discovery(vec![skill_item_at(
                "claude:project:skill:example",
                &live_skill,
            )]),
            app_state.path().to_path_buf(),
            None,
        );

        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Blocked);
        assert_eq!(
            results[0].reason.as_deref(),
            Some("backup authentication key is required before apply")
        );
        assert_eq!(state.staged_count(), 1);
        assert!(live_skill.exists());
        assert!(state.backups.is_empty());
        assert!(
            render_headless_state(&state)
                .contains("Backup authentication: unavailable (writes disabled)")
        );
    }

    #[test]
    fn blocked_staged_apply_surfaces_failure_without_writing_snapshot() {
        let app_state = TempDir::new().expect("temp app state");
        let live_root = TempDir::new().expect("temp live root");
        let project_root = live_root.path().join("project");
        let missing_skill = live_root.path().join("missing-skill");
        let mut state = TuiState::new_with_paths(
            discovery(vec![skill_item_at(
                "claude:project:skill:missing",
                &missing_skill,
            )]),
            app_state.path().to_path_buf(),
            project_root.clone(),
        );

        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Blocked);
        assert_eq!(state.staged_count(), 1);
        assert!(!state.pending_confirmation());
        let output = render_headless_state(&state);
        assert!(output.contains("Last action: error: Applied 0/1 staged change"));
        assert!(output.contains("blocked:"));
        assert!(
            load_latest_discovery_snapshot(app_state.path(), &project_root)
                .expect("load latest snapshot")
                .is_none()
        );
    }

    #[test]
    fn fully_blocked_staged_apply_refreshes_external_drift_without_snapshot() {
        let app_state = TempDir::new().expect("temp app state");
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let project_root = fixture_copy.path().join("codex/project");
        let roots =
            DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
        let discovery = discover_all(&roots).expect("fixture discovery");
        let mut state = TuiState::new_with_paths_and_roots(
            discovery,
            app_state.path().to_path_buf(),
            project_root.clone(),
            roots,
        );
        state.provider_filter = ProviderFilter::Provider(ProviderId::Codex);
        state.layer_filter = LayerFilter::Layer(DiscoveryLayer::Global);
        state.category_filter = CategoryFilter::Category(DiscoveryCategory::Skill);
        state.clamp_selected();
        state.selected = state
            .visible_items()
            .iter()
            .position(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
            .expect("Codex admin skill position");
        let selected = state.selected_item().expect("selected Codex global skill");
        assert_eq!(
            selected.id,
            "codex:global:skill:admin/example-codex-admin-skill"
        );
        assert!(selected.enabled);
        assert!(state.stage_selected_toggle());

        let config_path = fixture_copy.path().join("codex/global/config.toml");
        let skill_path = fixture_copy
            .path()
            .join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
        let config = fs::read_to_string(&config_path).expect("Codex config fixture");
        fs::write(
            &config_path,
            format!(
                "{config}\n[[skills.config]]\npath = {:?}\nenabled = false\n",
                skill_path.to_string_lossy()
            ),
        )
        .expect("write external Codex skill drift");

        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Blocked);
        assert_eq!(state.staged_count(), 0);
        assert!(!state.pending_confirmation());
        assert!(
            !state
                .items
                .iter()
                .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
                .expect("refreshed Codex admin skill")
                .enabled
        );
        assert!(
            load_latest_discovery_snapshot(app_state.path(), &project_root)
                .expect("load latest snapshot")
                .is_none()
        );
    }

    #[test]
    fn staged_apply_surfaces_refresh_failure_and_skips_stale_snapshot() {
        let app_state = TempDir::new().expect("temp app state");
        let live_root = TempDir::new().expect("temp live root");
        let live_skill = live_root.path().join("example-skill");
        fs::create_dir_all(&live_skill).expect("create skill");
        fs::write(live_skill.join("SKILL.md"), "# Example\n").expect("write skill");

        let invalid_roots = TempDir::new().expect("temp invalid roots");
        let invalid_skill_root = invalid_roots.path().join("claude/global/skills");
        fs::create_dir_all(
            invalid_skill_root
                .parent()
                .expect("invalid skill root parent"),
        )
        .expect("create invalid root parent");
        fs::write(&invalid_skill_root, "not a directory").expect("write invalid skill root");
        let project_root = invalid_roots.path().join("claude/project");
        let roots = DiscoveryRoots::fixture_root(invalid_roots.path());
        let mut state = TuiState::new_with_paths_and_roots(
            discovery(vec![skill_item_at(
                "claude:project:skill:example",
                &live_skill,
            )]),
            app_state.path().to_path_buf(),
            project_root.clone(),
            roots,
        );

        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Applied);
        assert!(!live_skill.exists());
        let output = render_headless_state(&state);
        assert!(output.contains("Last action: error: Applied 1/1 staged change"));
        assert!(output.contains("refresh failed:"));
        assert!(output.contains("snapshot skipped"));
        assert!(
            load_latest_discovery_snapshot(app_state.path(), &project_root)
                .expect("load latest snapshot")
                .is_none()
        );
    }

    #[test]
    fn partial_staged_apply_keeps_only_blocked_change_staged() {
        let app_state = TempDir::new().expect("temp app state");
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let project_root = fixture_copy.path().join("pi/project");
        let roots =
            DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
        let mut discovery = discover_all(&roots).expect("fixture discovery");
        let missing_skill = project_root.join(".pi/skills/zz-missing");
        let mut missing_item = skill_item_at("pi:project:skill:zz-missing", &missing_skill);
        missing_item.provider = ProviderId::Pi;
        discovery.items.push(missing_item);
        let mut state = TuiState::new_with_paths_and_roots(
            discovery,
            app_state.path().to_path_buf(),
            project_root.clone(),
            roots,
        );
        state.provider_filter = ProviderFilter::Provider(ProviderId::Pi);
        state.layer_filter = LayerFilter::Layer(DiscoveryLayer::Project);
        state.category_filter = CategoryFilter::Category(DiscoveryCategory::Skill);
        state.clamp_selected();
        assert_eq!(state.visible_count(), 4);
        for _ in 0..state.visible_count() {
            if state
                .selected_item()
                .is_some_and(|item| item.id == "pi:project:skill:example-pi-project-skill")
            {
                break;
            }
            state.move_next();
        }
        let existing_id = state
            .selected_item()
            .expect("existing selected skill")
            .id
            .clone();

        assert!(state.stage_selected_toggle());
        for _ in 0..state.visible_count() {
            if state
                .selected_item()
                .is_some_and(|item| item.id == "pi:project:skill:zz-missing")
            {
                break;
            }
            state.move_next();
        }
        assert_eq!(
            state.selected_item().expect("missing selected skill").id,
            "pi:project:skill:zz-missing"
        );
        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 2);
        assert_eq!(
            results
                .iter()
                .filter(|result| result.status == ToggleStatus::Applied)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.status == ToggleStatus::Blocked)
                .count(),
            1
        );
        assert_eq!(state.staged_count(), 1);
        assert!(!state.pending_confirmation());
        assert_eq!(
            state.staged_summary_strings(),
            vec!["- pi:project:skill:zz-missing -> off"]
        );

        let output = render_headless_state(&state);
        assert!(output.contains("Last action: error: Applied 1/2 staged changes"));
        assert!(output.contains("pi:project:skill:zz-missing blocked:"));
        assert!(!output.contains("refresh failed:"));
        assert!(!output.contains("snapshot failed:"));

        let snapshot = load_latest_discovery_snapshot(app_state.path(), &project_root)
            .expect("load latest snapshot")
            .unwrap_or_else(|| panic!("{}", render_headless_state(&state)));
        assert!(
            snapshot
                .items
                .iter()
                .all(|item| item.id != "pi:project:skill:zz-missing")
        );
        assert!(
            !snapshot
                .items
                .iter()
                .find(|item| item.id == existing_id)
                .expect("snapshot applied skill")
                .enabled
        );
    }

    #[test]
    fn staged_apply_surfaces_snapshot_failure_after_successful_refresh() {
        let app_state = TempDir::new().expect("temp app state");
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let project_root = fixture_copy.path().join("pi/project");
        let roots =
            DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
        let discovery = discover_all(&roots).expect("fixture discovery");
        let seeded_snapshot = write_discovery_snapshot(SnapshotWriteOptions {
            app_state_root: app_state.path().to_path_buf(),
            project_root: project_root.clone(),
            discovery: discovery.clone(),
            captured_at: Some("2026-07-13T00:00:00Z".to_string()),
            id: Some("before-apply".to_string()),
            max_history: 20,
        })
        .expect("seed snapshot");
        let history_dir = seeded_snapshot
            .history_path
            .parent()
            .expect("snapshot history parent");
        fs::remove_dir_all(history_dir).expect("remove snapshot history directory");
        fs::write(history_dir, "not a directory").expect("block snapshot history directory");

        let mut state = TuiState::new_with_paths_and_roots(
            discovery,
            app_state.path().to_path_buf(),
            project_root.clone(),
            roots,
        );
        state.provider_filter = ProviderFilter::Provider(ProviderId::Pi);
        state.layer_filter = LayerFilter::Layer(DiscoveryLayer::Project);
        state.category_filter = CategoryFilter::Category(DiscoveryCategory::Skill);
        state.clamp_selected();
        for _ in 0..state.visible_count() {
            if state
                .selected_item()
                .is_some_and(|item| item.id == "pi:project:skill:example-pi-project-skill")
            {
                break;
            }
            state.move_next();
        }
        let original_state_path = PathBuf::from(
            &state
                .selected_item()
                .expect("selected Claude project skill")
                .state_path,
        );

        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Applied);
        assert!(!original_state_path.exists());
        assert_eq!(state.backups.len(), 1);
        let output = render_headless_state(&state);
        assert!(output.contains("Last action: error: Applied 1/1 staged change"));
        assert!(output.contains("snapshot failed:"), "{output}");

        let latest = load_latest_discovery_snapshot(app_state.path(), &project_root)
            .expect("load latest snapshot")
            .expect("seeded latest snapshot");
        let stale_item = latest
            .items
            .iter()
            .find(|item| item.id == "pi:project:skill:example-pi-project-skill")
            .expect("seeded snapshot skill");
        assert!(stale_item.enabled);
    }

    #[test]
    fn confirmed_staged_apply_delegates_to_mutation_and_reloads_backups() {
        let app_state = TempDir::new().expect("temp app state");
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let project_root = fixture_copy.path().join("pi").join("project");
        let roots =
            DiscoveryRoots::fixture_root(fixture_copy.path()).with_app_state_root(app_state.path());
        let discovery = discover_all(&roots).expect("fixture discovery");
        let mut state = TuiState::new_with_paths_and_roots(
            discovery,
            app_state.path().to_path_buf(),
            project_root.clone(),
            roots,
        );
        state.provider_filter = ProviderFilter::Provider(ProviderId::Pi);
        state.layer_filter = LayerFilter::Layer(DiscoveryLayer::Project);
        state.category_filter = CategoryFilter::Category(DiscoveryCategory::Skill);
        state.clamp_selected();
        for _ in 0..state.visible_count() {
            if state
                .selected_item()
                .is_some_and(|item| item.id == "pi:project:skill:example-pi-project-skill")
            {
                break;
            }
            state.move_next();
        }

        let selected_before = state.selected_item().expect("selected skill");
        assert_eq!(
            selected_before.id,
            "pi:project:skill:example-pi-project-skill"
        );
        let original_state_path = PathBuf::from(&selected_before.state_path);
        assert!(original_state_path.exists());

        assert!(state.stage_selected_toggle());
        assert!(state.confirm_staged());
        let results = state.apply_confirmed_staged();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ToggleStatus::Applied);
        assert_eq!(state.staged_count(), 0);
        assert!(!state.pending_confirmation());
        assert!(!original_state_path.exists());
        assert_eq!(state.backups.len(), 1);
        assert_eq!(
            state.backups[0].selection.id,
            "pi:project:skill:example-pi-project-skill"
        );
        assert!(!state.backups[0].target_enabled);
        let selected_after = state
            .items
            .iter()
            .find(|item| item.id == "pi:project:skill:example-pi-project-skill")
            .unwrap_or_else(|| panic!("{}", render_headless_state(&state)));
        assert!(!selected_after.enabled);
        assert!(
            selected_after.state_path.ends_with("entry.json"),
            "post-apply TUI state should come from live rediscovery, got {}",
            selected_after.state_path
        );

        let output = render_headless_state(&state);
        assert!(output.contains("Staged: 0"));
        assert!(output.contains("Backups: 1"));
        assert!(output.contains("Last action: success: Applied 1/1 staged change"));

        let snapshot = load_latest_discovery_snapshot(app_state.path(), &project_root)
            .expect("load latest snapshot")
            .expect("snapshot was written");
        let snapshot_item = snapshot
            .items
            .iter()
            .find(|item| item.id == "pi:project:skill:example-pi-project-skill")
            .expect("snapshot item");
        assert!(!snapshot_item.enabled);
        assert!(
            snapshot_item.state_path.ends_with("entry.json"),
            "snapshot should be written from live rediscovery, got {}",
            snapshot_item.state_path
        );
    }

    #[test]
    fn restore_recovery_required_phase_survives_later_error_recording() {
        let mut workflow = RestoreWorkflow::new(Vec::new(), Vec::new());
        workflow.phase = WorkflowPhase::RecoveryRequired;

        workflow.record_error("retry remains blocked".to_string());

        assert_eq!(workflow.phase, WorkflowPhase::RecoveryRequired);
        assert_eq!(
            workflow.last_error.as_deref(),
            Some("retry remains blocked")
        );
    }
}
