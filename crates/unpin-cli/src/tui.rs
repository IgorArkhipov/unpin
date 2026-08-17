use std::{
    collections::BTreeMap,
    error::Error,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
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
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use unpin_core::approval::ControlApprovalContext;
use unpin_core::control::{ControlStatus, build_control_status};
use unpin_core::control_operation::ControlOperationEnvelope;
use unpin_core::discovery::{
    DiscoveryCategory, DiscoveryError, DiscoveryItem, DiscoveryLayer, DiscoveryMutability,
    DiscoveryOutput, DiscoveryProgress, DiscoveryProgressPhase, DiscoveryRoots, DiscoveryWarning,
    ProviderId, discover_all, discover_all_with_progress,
};
use unpin_core::groups::{GroupAccessContext, GroupMemberIdentity, GroupOperationLifecycle};
use unpin_core::mutation::{
    BackupAuthenticationKey, BackupAuthenticationStatus, BackupSummary, NativeToggleController,
    NativeTogglePlan, TogglePlanRequest, ToggleResult, ToggleStatus,
    load_backup_summaries_authenticated, plan_toggle,
};
use unpin_core::sessions::SessionAuthorityKey;

#[cfg(test)]
use unpin_core::snapshots::write_discovery_snapshot;
use unpin_core::snapshots::{SnapshotWriteOptions, write_control_snapshot};
use unpin_core::state::atomic_json::{AtomicJsonStore, OwnerGeneration};
use unpin_core::state::workspace::resolve_workspace_identity;

use crate::{credentials, unix_now};

mod agent_plugins;
mod gateway;
mod groups;
mod hooks;
mod inventory;
mod profiles;
mod restore;
mod sessions;
mod startup;

use inventory::inventory_header_lines;
use restore::RestoreWorkflow;
use startup::{StartupCredentials, finish_after_terminal_run, resolve_startup_credentials};

type TuiResult<T> = Result<T, Box<dyn Error>>;

const CONTROL_SCROLL_STEP: u16 = 8;

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
pub(super) enum TuiView {
    Inventory,
    Packages,
    Groups,
    Profiles,
    Gateways,
    Sessions,
    Hooks,
    RestoreOperations,
}

impl TuiView {
    const ALL: [Self; 8] = [
        Self::Inventory,
        Self::Groups,
        Self::Profiles,
        Self::Gateways,
        Self::Sessions,
        Self::Hooks,
        Self::RestoreOperations,
        Self::Packages,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Packages => "packages",
            Self::Groups => "groups",
            Self::Profiles => "profiles",
            Self::Gateways => "gateways",
            Self::Sessions => "sessions",
            Self::Hooks => "hooks",
            Self::RestoreOperations => "restore/operations",
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::Inventory => "Inventory",
            Self::Packages => "Packages",
            Self::Groups => "Groups",
            Self::Profiles => "Profiles",
            Self::Gateways => "Gateways",
            Self::Sessions => "Sessions",
            Self::Hooks => "Hooks",
            Self::RestoreOperations => "Restore Operations",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderFilter {
    All,
    Provider(ProviderId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LayerFilter {
    All,
    Layer(DiscoveryLayer),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CategoryFilter {
    All,
    Category(DiscoveryCategory),
}

pub(super) struct TuiState {
    discovery: DiscoveryOutput,
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
    control_scroll: u16,
    control_scroll_limit: u16,
    profile_workflow: profiles::ProfileWorkflow,
    package_workflow: agent_plugins::AgentPluginWorkflow,
    group_workflow: groups::GroupWorkflow,
    gateway_workflow: gateway::GatewayWorkflow,
    session_workflow: sessions::SessionWorkflow,
    hook_workflow: hooks::HookWorkflow,
    restore_workflow: restore::RestoreWorkflow,
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
pub(super) struct StagedToggle {
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
        let workflow_snapshots = session_authority_key
            .as_ref()
            .map(|key| sessions::SessionWorkflow::load_workflows(&app_state_root, key))
            .unwrap_or_default();
        let (mut profile_workflow, gateway_workflow, session_workflow, hook_workflow, operations) =
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
                    sessions::SessionWorkflow::new_with_workflows(
                        control.sessions.clone(),
                        &workflow_snapshots,
                    ),
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
        profile_workflow.refresh_policy_maintenance(
            &app_state_root,
            &project_root,
            backup_authentication_key.as_ref(),
        );
        let restore_workflow = RestoreWorkflow::new(backups.clone(), operations);
        let package_workflow = agent_plugins::AgentPluginWorkflow::new(&discovery);
        Self {
            discovery,
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
            control_scroll: 0,
            control_scroll_limit: u16::MAX,
            profile_workflow,
            package_workflow,
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
            .and_then(|index| self.discovery.items.get(*index))
    }

    fn cycle_view(&mut self) {
        let current = TuiView::ALL
            .iter()
            .position(|view| *view == self.view)
            .unwrap_or(0);
        self.view = TuiView::ALL[(current + 1) % TuiView::ALL.len()];
        self.search_editing = false;
        self.control_scroll = 0;
        self.control_scroll_limit = u16::MAX;
    }

    fn scroll_control_up(&mut self) {
        self.control_scroll = self.control_scroll.saturating_sub(CONTROL_SCROLL_STEP);
    }

    fn scroll_control_down(&mut self) {
        self.control_scroll = self
            .control_scroll
            .saturating_add(CONTROL_SCROLL_STEP)
            .min(self.control_scroll_limit);
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
            TuiView::Packages => self.package_workflow.rows(),
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
            TuiView::Packages => self.package_workflow.details(),
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
        if self.view == TuiView::Packages {
            return self.plan_package_action();
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
            TuiView::Packages => unreachable!("packages handled above"),
            TuiView::Groups => self.group_workflow.plan(&context).cloned(),
            TuiView::Profiles => self
                .profile_workflow
                .plan(&self.discovery, &self.app_state_root, &context)
                .cloned(),
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
            TuiView::Hooks => self
                .hook_workflow
                .plan(&self.discovery, &self.app_state_root)
                .cloned(),
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
                    TuiView::Packages => unreachable!("packages handled above"),
                    TuiView::Inventory => {}
                }
                self.last_action = Some(TuiActionStatus::Error(error));
                false
            }
        }
    }

    fn plan_backup_deletion(&mut self) -> bool {
        if self.view != TuiView::RestoreOperations {
            return false;
        }
        match self.restore_workflow.plan_deletion(&self.app_state_root) {
            Ok(()) => {
                self.last_action = Some(TuiActionStatus::Success(
                    "backup deletion planned; press Enter to confirm, then A to apply".to_string(),
                ));
                true
            }
            Err(error) => {
                self.restore_workflow.record_error(error.clone());
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
            TuiView::Packages => self.package_workflow.confirm(),
            TuiView::Profiles => self.profile_workflow.confirm(),
            TuiView::Groups => self.group_workflow.confirm(),
            TuiView::Gateways => self.gateway_workflow.confirm(),
            TuiView::Sessions => self.session_workflow.confirm(),
            TuiView::Hooks => self.hook_workflow.confirm(),
            TuiView::RestoreOperations => self.restore_workflow.confirm(),
            TuiView::Inventory => unreachable!("inventory handled above"),
        };
        if confirmed {
            let message = if self.view == TuiView::Packages {
                "aggregate package plan confirmed; press A to apply or U/Esc to cancel"
            } else if self.view == TuiView::RestoreOperations
                && self.restore_workflow.has_pending_deletion()
            {
                "backup deletion confirmed; press A to apply"
            } else {
                "control plan confirmed; apply still requires human presence"
            };
            self.last_action = Some(TuiActionStatus::Success(message.to_string()));
        }
        confirmed
    }

    fn apply_active_action(&mut self) {
        if self.view == TuiView::Inventory {
            self.apply_confirmed_staged();
            return;
        }
        if self.view == TuiView::Packages {
            self.apply_package_action();
            return;
        }
        if self.view == TuiView::Groups {
            self.apply_group_action();
            return;
        }
        if self.view == TuiView::RestoreOperations && self.restore_workflow.has_pending_deletion() {
            let deletion_was_confirmed = self.restore_workflow.deletion_is_confirmed();
            match self.restore_workflow.apply_deletion(&self.app_state_root) {
                Ok(result) => {
                    self.backups = load_backup_summaries_authenticated(
                        &self.app_state_root,
                        self.backup_authentication_key.as_ref(),
                    );
                    self.restore_workflow.replace_backups(self.backups.clone());
                    self.last_action = Some(TuiActionStatus::Success(format!(
                        "backup {} deleted",
                        result.backup_id
                    )));
                }
                Err(error) => {
                    if deletion_was_confirmed {
                        self.backups = load_backup_summaries_authenticated(
                            &self.app_state_root,
                            self.backup_authentication_key.as_ref(),
                        );
                        self.restore_workflow.replace_backups(self.backups.clone());
                    }
                    self.restore_workflow.record_error(error.clone());
                    self.last_action = Some(TuiActionStatus::Error(error));
                }
            }
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
            TuiView::Packages => unreachable!("packages handled above"),
            TuiView::Groups => unreachable!("groups handled above"),
            TuiView::Profiles => match (
                self.session_authority_key.as_ref(),
                self.backup_authentication_key.as_ref(),
            ) {
                (Some(authority), Some(backup)) => self.profile_workflow.apply(
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
                    TuiView::Packages => unreachable!("packages handled above"),
                    TuiView::Inventory => {}
                }
                self.last_action = Some(TuiActionStatus::Error(error));
            }
        }
    }

    fn plan_package_action(&mut self) -> bool {
        let result = self
            .package_workflow
            .plan(&self.discovery, &self.app_state_root)
            .map(|plan| {
                (
                    plan.operation_id.clone(),
                    plan.included_count(),
                    plan.write_count(),
                    plan.blocked_count(),
                )
            });
        match result {
            Ok((operation_id, included, writes, blocked)) => {
                self.last_action = Some(TuiActionStatus::Success(format!(
                    "planned aggregate package operation {operation_id}: included={included} writes={writes} blocked={blocked}; Enter confirms"
                )));
                true
            }
            Err(error) => {
                self.package_workflow.record_error(error.clone());
                self.last_action = Some(TuiActionStatus::Error(error));
                false
            }
        }
    }

    fn apply_package_action(&mut self) {
        let Some(roots) = self.discovery_roots.clone() else {
            let error =
                "package apply requires retained discovery roots; refresh and replan".to_string();
            self.package_workflow.record_error(error.clone());
            self.last_action = Some(TuiActionStatus::Error(error));
            return;
        };
        let fresh_roots = roots.clone().with_app_state_root(&self.app_state_root);
        let fresh_discovery = match discover_all(&fresh_roots) {
            Ok(discovery) => discovery,
            Err(error) => {
                let error = format!("package refresh failed before apply: {error}");
                self.package_workflow.record_error(error.clone());
                self.last_action = Some(TuiActionStatus::Error(error));
                return;
            }
        };
        let result = self
            .package_workflow
            .apply(
                fresh_discovery,
                &self.app_state_root,
                &self.project_root,
                &roots,
                self.fixture_mode,
            )
            .map(|result| (result.operation_id.clone(), result.lifecycle));
        match result {
            Ok((operation_id, lifecycle)) => match self.rediscover_after_apply() {
                Ok(discovery) => {
                    let refresh = self.refresh_control_plane_from(&discovery);
                    self.last_action = Some(match refresh {
                        Ok(()) => TuiActionStatus::Success(format!(
                            "aggregate package operation {operation_id} {lifecycle:?}; discovery refreshed; replan before another mutation"
                        )),
                        Err(error) => TuiActionStatus::Error(format!(
                            "aggregate package operation {operation_id} {lifecycle:?}; discovery refreshed but control status failed: {error}"
                        )),
                    });
                }
                Err(error) => {
                    self.last_action = Some(TuiActionStatus::Error(format!(
                        "aggregate package operation {operation_id} {lifecycle:?}; refresh failed: {error}; inspect durable status and Restore Operations"
                    )));
                }
            },
            Err(error) => {
                self.package_workflow.record_error(error.clone());
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
                let discovery = self.discovery.clone();
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
            TuiView::Packages => self.package_workflow.cycle_target(),
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

    fn cycle_active_provider_reach(&mut self) {
        match self.view {
            TuiView::Packages => self.package_workflow.cycle_reach(),
            TuiView::Groups => self.group_workflow.cycle_provider_reach(),
            _ => {}
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

    fn cancel_package_interaction(&mut self) -> bool {
        if self.view == TuiView::Packages && self.package_workflow.cancel() {
            self.last_action = Some(TuiActionStatus::Success(
                "package review cancelled without provider writes; choose reach and replan when ready"
                    .to_string(),
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
        let discovery = self.discovery.clone();
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
        self.profile_workflow.refresh_policy_maintenance(
            &self.app_state_root,
            &self.project_root,
            self.backup_authentication_key.as_ref(),
        );
        self.gateway_workflow = gateway::GatewayWorkflow::new(
            &control.repository_key,
            &control.workspace_key,
            control.gateways.clone(),
        );
        let workflows = self
            .session_authority_key
            .as_ref()
            .map(|key| sessions::SessionWorkflow::load_workflows(&self.app_state_root, key))
            .unwrap_or_default();
        self.session_workflow =
            sessions::SessionWorkflow::new_with_workflows(control.sessions.clone(), &workflows);
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
            .plan_with_inventory(item.clone(), &self.discovery.items, context)
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
                    .discovery
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
                .discovery
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
                    &self.discovery.items,
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

pub(super) fn next_choice<T: Copy + Eq>(current: T, choices: &[T]) -> T {
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
        format!("Items: {}", state.discovery.items.len()),
        format!("Packages: {}", state.package_workflow.len()),
        format!("Showing: {}", state.visible_count()),
        format!("Warnings: {}", state.discovery.warnings.len()),
        format!("Backups: {}", state.backups.len()),
        format!(
            "Backup authentication: {}",
            backup_authentication_readiness_label(state)
        ),
        format!("Staged: {}", state.staged_count()),
        format!("Last action: {}", last_action_label(state)),
        format!("Last control: {}", last_control_label(state)),
        format!("View: {}", state.view.label()),
        provider_summary(&state.discovery.items),
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
        lines.push("Workflow session projection:".to_string());
        lines.extend(state.session_workflow.projection_rows());
    } else {
        lines.push(format!(
            "Unavailable: {}",
            state.control_status_error.as_deref().unwrap_or("unknown")
        ));
        lines.push("Workflow session projection:".to_string());
        lines.extend(state.session_workflow.projection_rows());
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

    if !state.discovery.warnings.is_empty() {
        lines.push(String::new());
        lines.push("Warning details:".to_string());
        lines.extend(state.discovery.warnings.iter().map(warning_label));
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
    lines.push("Commands:".to_string());
    lines.extend(headless_command_legend(state.view));
    for view in TuiView::ALL {
        if view != state.view {
            lines.push(format!("Commands ({}):", view.title()));
            lines.extend(headless_command_legend(view));
        }
    }
    lines.join("\n")
}

pub fn run_interactive(
    app_state_root: PathBuf,
    project_root: PathBuf,
    discovery_roots: DiscoveryRoots,
    fixture_mode: bool,
) -> TuiResult<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let loop_result = (|| -> TuiResult<()> {
        let loading_state = LoadingState::default();
        terminal.draw(|frame| draw_loading(frame, &loading_state))?;
        let Some(startup) = run_loading_loop(
            &mut terminal,
            &discovery_roots,
            &app_state_root,
            fixture_mode,
        )?
        else {
            return Ok(());
        };
        let mut state = TuiState::new_with_paths_and_roots_and_key(
            startup.discovery,
            app_state_root,
            project_root,
            discovery_roots,
            startup.credentials.backup_authentication_key,
            startup.credentials.session_authority_key,
        );
        state.fixture_mode = fixture_mode;
        record_startup_warnings(&mut state, startup.credentials.warnings);
        run_loop(&mut terminal, &mut state)
    })();
    finish_after_terminal_run(loop_result, || restore_terminal(&mut terminal))
}

#[derive(Default)]
struct LoadingState {
    progress: Option<DiscoveryProgress>,
}

fn draw_loading(frame: &mut Frame, state: &LoadingState) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(loading_status(state)),
            Line::from("Press Q or Esc to cancel."),
        ])
        .block(Block::default().borders(Borders::ALL).title("Unpin")),
        frame.area(),
    );
}

fn run_loading_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    discovery_roots: &DiscoveryRoots,
    app_state_root: &Path,
    fixture_mode: bool,
) -> TuiResult<Option<TuiStartup>> {
    let (receiver, cancellation) = start_discovery(
        discovery_roots.clone(),
        app_state_root.to_path_buf(),
        fixture_mode,
    );
    let mut loading_state = LoadingState::default();
    loop {
        let previous_progress = loading_state.progress;
        if let Some(startup) = try_take_startup(&receiver, &mut loading_state)? {
            return Ok(Some(startup));
        }
        if loading_state.progress != previous_progress {
            terminal.draw(|frame| draw_loading(frame, &loading_state))?;
        }
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        match loading_event(event::read()?) {
            LoadingEvent::Redraw => {
                terminal.draw(|frame| draw_loading(frame, &loading_state))?;
            }
            LoadingEvent::Quit => {
                cancellation.store(true, Ordering::Relaxed);
                return Ok(None);
            }
            LoadingEvent::Ignore => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadingEvent {
    Redraw,
    Quit,
    Ignore,
}

fn loading_event(event: Event) -> LoadingEvent {
    match event {
        Event::Resize(_, _) => LoadingEvent::Redraw,
        Event::Key(key) if matches!(key.code, KeyCode::Char('q' | 'Q') | KeyCode::Esc) => {
            LoadingEvent::Quit
        }
        _ => LoadingEvent::Ignore,
    }
}

struct TuiStartup {
    discovery: DiscoveryOutput,
    credentials: StartupCredentials,
}

enum TuiStartupEvent {
    Progress(DiscoveryProgress),
    Complete(Result<TuiStartup, DiscoveryError>),
}

fn start_discovery(
    discovery_roots: DiscoveryRoots,
    app_state_root: PathBuf,
    fixture_mode: bool,
) -> (Receiver<TuiStartupEvent>, Arc<AtomicBool>) {
    let (sender, receiver) = mpsc::channel();
    let cancellation = Arc::new(AtomicBool::new(false));
    let worker_cancellation = Arc::clone(&cancellation);
    let discovery_cancellation = Arc::clone(&cancellation);
    let progress_sender = sender.clone();
    start_discovery_worker(sender, worker_cancellation, move || {
        let discovery = discover_all_with_progress(&discovery_roots, |progress| {
            if discovery_cancellation.load(Ordering::Relaxed) {
                return false;
            }
            let sent_progress = progress_sender
                .send(TuiStartupEvent::Progress(progress))
                .is_ok();
            #[cfg(test)]
            if sent_progress {
                wait_for_startup_progress_test_pause(&app_state_root);
            }
            sent_progress && !discovery_cancellation.load(Ordering::Relaxed)
        });
        if discovery_cancellation.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let discovery = discovery?;
        let Some(startup_credentials) = resolve_startup_credentials(
            || credentials::resolve_backup_authentication_key(fixture_mode, &app_state_root),
            || discovery_cancellation.load(Ordering::Relaxed),
            || credentials::resolve_session_authority_key(fixture_mode, &app_state_root),
        ) else {
            return Ok(None);
        };
        Ok(Some(TuiStartup {
            discovery,
            credentials: startup_credentials,
        }))
    });
    (receiver, cancellation)
}

fn start_discovery_worker(
    sender: mpsc::Sender<TuiStartupEvent>,
    cancellation: Arc<AtomicBool>,
    work: impl FnOnce() -> Result<Option<TuiStartup>, DiscoveryError> + Send + 'static,
) {
    thread::spawn(move || {
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
            Ok(result) => result,
            Err(payload) => {
                let message = if let Some(message) = payload.downcast_ref::<&str>() {
                    (*message).to_string()
                } else if let Some(message) = payload.downcast_ref::<String>() {
                    message.clone()
                } else {
                    "non-string panic payload".to_string()
                };
                Err(
                    io::Error::other(format!("startup discovery worker panicked: {message}"))
                        .into(),
                )
            }
        };
        let result = match result {
            Ok(Some(startup)) => Ok(startup),
            Ok(None) => return,
            Err(error) => Err(error),
        };
        if !cancellation.load(Ordering::Relaxed) {
            let _ = sender.send(TuiStartupEvent::Complete(result));
        }
    });
}

#[cfg(test)]
fn startup_progress_test_pauses()
-> &'static std::sync::Mutex<std::collections::BTreeMap<PathBuf, mpsc::SyncSender<()>>> {
    static PAUSES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<PathBuf, mpsc::SyncSender<()>>>,
    > = std::sync::OnceLock::new();
    PAUSES.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn wait_for_startup_progress_test_pause(app_state_root: &Path) {
    let pause = startup_progress_test_pauses()
        .lock()
        .expect("startup progress test pauses lock")
        .get(app_state_root)
        .cloned();
    if let Some(pause) = pause {
        let _ = pause.send(());
    }
}

fn try_take_startup(
    receiver: &Receiver<TuiStartupEvent>,
    loading_state: &mut LoadingState,
) -> TuiResult<Option<TuiStartup>> {
    loop {
        match receiver.try_recv() {
            Ok(TuiStartupEvent::Progress(progress)) => loading_state.progress = Some(progress),
            Ok(TuiStartupEvent::Complete(Ok(startup))) => return Ok(Some(startup)),
            Ok(TuiStartupEvent::Complete(Err(error))) => return Err(error),
            Err(TryRecvError::Empty) => return Ok(None),
            Err(TryRecvError::Disconnected) => {
                return Err(io::Error::other("discovery worker stopped before completing").into());
            }
        }
    }
}

fn loading_status(state: &LoadingState) -> String {
    match state.progress {
        Some(DiscoveryProgress {
            phase: DiscoveryProgressPhase::ScanningProjectScopes,
            ..
        }) => "Scanning project skill scopes…".to_string(),
        Some(DiscoveryProgress {
            phase: DiscoveryProgressPhase::DiscoveringProvider(provider),
            completed_providers,
            provider_count,
        }) => format!(
            "Discovering {} configuration and project skills… ({}/{})",
            provider.as_str(),
            completed_providers + 1,
            provider_count,
        ),
        Some(DiscoveryProgress {
            phase: DiscoveryProgressPhase::Finalizing,
            ..
        }) => "Finalizing discovery inventory…".to_string(),
        None => "Preparing configuration discovery…".to_string(),
    }
}

fn record_startup_warnings(state: &mut TuiState, credential_warnings: Vec<String>) {
    if !credential_warnings.is_empty() {
        state.last_action = Some(TuiActionStatus::Error(credential_warnings.join("; ")));
    }
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
            KeyCode::Char('q' | 'Q') => return TuiEventOutcome::Quit,
            KeyCode::Esc => {
                if !state.cancel_package_interaction() && !state.cancel_group_interaction() {
                    return TuiEventOutcome::Quit;
                }
                true
            }
            KeyCode::Char('v' | 'V') => {
                state.cycle_view();
                true
            }
            KeyCode::PageUp if state.view != TuiView::Inventory => {
                state.scroll_control_up();
                true
            }
            KeyCode::PageDown if state.view != TuiView::Inventory => {
                state.scroll_control_down();
                true
            }
            KeyCode::Down => {
                state.move_next();
                true
            }
            KeyCode::Up => {
                state.move_previous();
                true
            }
            KeyCode::Char('m' | 'M') => {
                state.cycle_active_action();
                true
            }
            KeyCode::Char('f' | 'F') => {
                state.toggle_gateway_force();
                true
            }
            KeyCode::Char('s' | 'S') if state.scope_control_available() => {
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
            KeyCode::Char('n' | 'N') => {
                state.start_group_create();
                true
            }
            KeyCode::Char('e' | 'E') => {
                state.start_group_edit();
                true
            }
            KeyCode::Char('R') => {
                state.start_group_rename();
                true
            }
            KeyCode::Char('D') if state.view == TuiView::RestoreOperations => {
                state.plan_backup_deletion();
                true
            }
            KeyCode::Char('d' | 'D') => {
                state.start_group_delete();
                true
            }
            KeyCode::Char('h' | 'H') => {
                state.show_group_history();
                true
            }
            KeyCode::Char('o' | 'O') => {
                state.start_group_mcp_approval();
                true
            }
            KeyCode::Char('w' | 'W') => {
                state.stage_group_definition_save();
                true
            }
            KeyCode::Char('p') if state.inventory_filters_available() => {
                state.cycle_provider_filter();
                true
            }
            KeyCode::Char('P') => {
                state.cycle_active_provider_reach();
                true
            }
            KeyCode::Char('l' | 'L') if state.inventory_filters_available() => {
                state.cycle_layer_filter();
                true
            }
            KeyCode::Char('c' | 'C') if state.inventory_filters_available() => {
                state.cycle_category_filter();
                true
            }
            KeyCode::Char('/') if state.inventory_filters_available() => {
                state.start_search_editing();
                true
            }
            KeyCode::Char('x') if state.inventory_filters_available() => {
                state.clear_search_query();
                true
            }
            KeyCode::Char('X') if state.group_mcp_export_available() => {
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
            KeyCode::Char('a' | 'A') => {
                state.apply_active_action();
                true
            }
            KeyCode::Char('u' | 'U') => {
                if !state.cancel_package_interaction() {
                    state.clear_staged();
                }
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

fn command_legend(view: TuiView) -> Vec<Line<'static>> {
    let mnemonic_style = Style::default().add_modifier(Modifier::UNDERLINED);
    let supports_active_action = matches!(
        view,
        TuiView::Packages | TuiView::Groups | TuiView::Profiles | TuiView::Gateways
    );
    let mut primary_controls = vec![
        Span::styled("V", mnemonic_style),
        Span::raw(if view == TuiView::Inventory {
            "iew | ↑/↓ move | filter: "
        } else if supports_active_action {
            "iew | ↑/↓ move | PgUp/PgDn scroll | "
        } else {
            "iew | ↑/↓ move | PgUp/PgDn scroll"
        }),
    ];
    if supports_active_action {
        primary_controls.extend([Span::styled("M", mnemonic_style), Span::raw("ode/action")]);
    }
    if view == TuiView::Inventory {
        primary_controls.extend([
            Span::styled("p", mnemonic_style),
            Span::raw("rovider/"),
            Span::styled("l", mnemonic_style),
            Span::raw("ayer/"),
            Span::styled("c", mnemonic_style),
            Span::raw("ategory"),
        ]);
    }

    let mut secondary_controls = vec![
        Span::raw("Space select/plan | Enter confirm | "),
        Span::styled("A", mnemonic_style),
        Span::raw("pply | "),
        Span::styled("U", mnemonic_style),
        Span::raw("nstage | "),
        Span::styled("Q", mnemonic_style),
        Span::raw("uit | Esc end input/quit"),
    ];
    if view == TuiView::Inventory {
        secondary_controls.splice(
            0..0,
            [
                Span::raw("/ search | "),
                Span::styled("x", mnemonic_style),
                Span::raw(" clear search | "),
            ],
        );
    }
    let mut lines = vec![Line::from(primary_controls), Line::from(secondary_controls)];

    match view {
        TuiView::Packages => lines.push(Line::from(vec![
            Span::raw("Packages: "),
            Span::styled("P", mnemonic_style),
            Span::raw(" reach | "),
            Span::styled("M", mnemonic_style),
            Span::raw(" target | U/Esc cancel review"),
        ])),
        TuiView::Profiles => lines.push(Line::from(vec![
            Span::raw("Profiles: "),
            Span::styled("s", mnemonic_style),
            Span::raw("cope | "),
            Span::styled("r", mnemonic_style),
            Span::raw(" provider"),
        ])),
        TuiView::Gateways => lines.push(Line::from(vec![
            Span::raw("Gateways: "),
            Span::styled("f", mnemonic_style),
            Span::raw("orce"),
        ])),
        TuiView::Groups => lines.extend([
            Line::from(vec![
                Span::raw("Groups: "),
                Span::styled("P", mnemonic_style),
                Span::raw(" reach | "),
                Span::styled("N", mnemonic_style),
                Span::raw("ew | "),
                Span::styled("E", mnemonic_style),
                Span::raw("dit | "),
                Span::styled("R", mnemonic_style),
                Span::raw("ename | "),
                Span::styled("D", mnemonic_style),
                Span::raw("elete"),
            ]),
            Line::from(vec![
                Span::styled("H", mnemonic_style),
                Span::raw("istory | "),
                Span::styled("r", mnemonic_style),
                Span::raw("estore | "),
                Span::styled("O", mnemonic_style),
                Span::raw("pen approval | "),
                Span::styled("W", mnemonic_style),
                Span::raw("rite definition"),
            ]),
        ]),
        TuiView::RestoreOperations => lines.push(Line::from(vec![
            Span::raw("Restore: "),
            Span::styled("D", mnemonic_style),
            Span::raw("elete backup"),
        ])),
        _ => {}
    }

    lines
}

fn command_legend_for_state(state: &TuiState) -> Vec<Line<'static>> {
    if state.group_text_editing() {
        return vec![Line::from(
            "Group input: type | backspace delete | enter submit | esc cancel",
        )];
    }
    if state.search_editing() {
        return vec![Line::from(
            "Search input: type | backspace delete | enter/esc finish",
        )];
    }

    let mut lines = command_legend(state.view);
    if state.view == TuiView::Groups && state.inventory_filters_available() {
        let mnemonic_style = Style::default().add_modifier(Modifier::UNDERLINED);
        lines[0].spans.extend([
            Span::raw(" | filter: "),
            Span::styled("p", mnemonic_style),
            Span::raw("rovider/"),
            Span::styled("l", mnemonic_style),
            Span::raw("ayer/"),
            Span::styled("c", mnemonic_style),
            Span::raw("ategory"),
        ]);
        lines[1].spans.splice(
            0..0,
            [
                Span::raw("/ search | "),
                Span::styled("x", mnemonic_style),
                Span::raw(" clear search | "),
            ],
        );
    }
    if state.view == TuiView::Groups && state.group_workflow.can_cycle_draft_scope() {
        lines.push(Line::from(vec![
            Span::raw("Groups draft: "),
            Span::styled("s", Style::default().add_modifier(Modifier::UNDERLINED)),
            Span::raw("cope"),
        ]));
    }
    if state.group_mcp_export_available() {
        lines.push(Line::from(vec![
            Span::raw("MCP approval: e"),
            Span::styled("X", Style::default().add_modifier(Modifier::UNDERLINED)),
            Span::raw("port"),
        ]));
    }
    lines
}

fn headless_command_legend(view: TuiView) -> Vec<String> {
    let mut lines = command_legend(view)
        .into_iter()
        .map(|line| {
            line.spans
                .into_iter()
                .map(|span| {
                    let content = span.content.into_owned();
                    if span.style.add_modifier.contains(Modifier::UNDERLINED) {
                        format!("[{content}]")
                    } else {
                        content
                    }
                })
                .collect()
        })
        .collect::<Vec<_>>();
    if view == TuiView::Groups {
        lines.push("MCP approval: e[X]port (after approval)".to_string());
    }
    lines
}

fn command_footer(command_legend: Vec<Line<'static>>) -> Paragraph<'static> {
    Paragraph::new(command_legend)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Commands"))
}

fn wrapped_line_height(lines: &[Line<'_>], available_width: u16) -> u16 {
    let details = lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let content_width = usize::from(available_width.saturating_sub(2)).max(1);

    u16::try_from(wrapped_control_line_count(&details, content_width)).unwrap_or(u16::MAX)
}

fn command_footer_height(command_legend: &[Line<'_>], available_width: u16) -> u16 {
    wrapped_line_height(command_legend, available_width).saturating_add(2)
}

fn draw(frame: &mut Frame<'_>, state: &mut TuiState) {
    const MIN_BODY_HEIGHT: u16 = 6;
    const MIN_HEADER_HEIGHT: u16 = 3;
    const MIN_FOOTER_HEIGHT: u16 = 3;
    const MAX_HEADER_HEIGHT: u16 = 14;

    let area = frame.area();
    let command_legend = command_legend_for_state(state);
    let requested_footer_height = command_footer_height(&command_legend, area.width);
    let header_minimum = MIN_HEADER_HEIGHT.min(area.height);
    let footer_minimum = MIN_FOOTER_HEIGHT.min(area.height.saturating_sub(header_minimum));
    let body_height = MIN_BODY_HEIGHT.min(
        area.height
            .saturating_sub(header_minimum.saturating_add(footer_minimum)),
    );
    let remaining_height = area.height.saturating_sub(body_height);
    let max_header_height = remaining_height
        .saturating_sub(footer_minimum)
        .min(MAX_HEADER_HEIGHT);
    let full_header_lines = inventory_header_lines(state, u16::MAX);
    let full_header_height = wrapped_line_height(&full_header_lines, area.width).saturating_add(2);
    let header_lines =
        if full_header_height.saturating_add(requested_footer_height) <= remaining_height {
            full_header_lines
        } else {
            inventory_header_lines(
                state,
                u16::try_from(full_header_lines.len().saturating_sub(1)).unwrap_or(u16::MAX),
            )
        };
    let header_height = wrapped_line_height(&header_lines, area.width)
        .saturating_add(2)
        .min(max_header_height);
    let header_height = header_height.max(header_minimum).min(max_header_height);
    let footer_height = requested_footer_height
        .min(remaining_height.saturating_sub(header_height))
        .max(footer_minimum);
    let footer = command_footer(command_legend);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(body_height),
            Constraint::Length(footer_height),
        ])
        .split(area);

    let header = Paragraph::new(header_lines)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Inventory"));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(chunks[1]);

    let active_rows = state.active_rows();
    let selected_row = if state.view == TuiView::Inventory {
        (state.visible_count() > 0).then_some(state.selected)
    } else {
        active_rows.iter().position(|row| row.starts_with('>'))
    };
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
                .title(state.view.title()),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    list_state.select(selected_row);
    frame.render_stateful_widget(list, body[0], &mut list_state);

    let detail_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(body[1]);

    let control_scroll_limit = control_scroll_offset(
        &state.active_details(),
        u16::MAX,
        detail_chunks[0].width,
        detail_chunks[0].height,
    );
    state.control_scroll_limit = control_scroll_limit;
    let control_scroll = state.control_scroll.min(control_scroll_limit);
    state.control_scroll = control_scroll;
    frame.render_widget(selected_detail(state, control_scroll), detail_chunks[0]);
    frame.render_widget(warning_detail(state), detail_chunks[1]);
    frame.render_widget(backup_detail(state), detail_chunks[2]);

    frame.render_widget(footer, chunks[2]);
}

fn selected_detail(state: &TuiState, control_scroll: u16) -> Paragraph<'static> {
    if state.view != TuiView::Inventory {
        let lines: Vec<_> = state.active_details().into_iter().map(Line::from).collect();
        return Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .scroll((control_scroll, 0))
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

fn control_scroll_offset(
    details: &[String],
    requested: u16,
    area_width: u16,
    area_height: u16,
) -> u16 {
    let line_count =
        wrapped_control_line_count(details, usize::from(area_width.saturating_sub(2).max(1)));
    let max_scroll = line_count
        .saturating_sub(usize::from(area_height.saturating_sub(2)))
        .min(usize::from(u16::MAX)) as u16;
    requested.min(max_scroll)
}

fn wrapped_control_line_count(details: &[String], width: usize) -> usize {
    details
        .iter()
        .map(|detail| {
            let mut complete_rows = 0;
            let mut current_width = 0;
            let mut saw_word = false;

            for word in detail.split_whitespace() {
                saw_word = true;
                let word_width = Line::from(word).width();
                if word_width > width {
                    if current_width > 0 {
                        complete_rows += 1;
                    }
                    complete_rows += word_width / width;
                    current_width = word_width % width;
                } else if current_width == 0 {
                    current_width = word_width;
                } else if current_width + 1 + word_width <= width {
                    current_width += 1 + word_width;
                } else {
                    complete_rows += 1;
                    current_width = word_width;
                }
            }

            complete_rows + usize::from(current_width > 0 || !saw_word)
        })
        .sum()
}

fn warning_detail(state: &TuiState) -> Paragraph<'static> {
    let lines = if state.discovery.warnings.is_empty() {
        vec![Line::from("No discovery warnings.")]
    } else {
        state
            .discovery
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
        "- {} created: {} entries: {} restorable: {} authentication: {} id: {}",
        backup_display_label(backup),
        backup.created_at,
        backup.item_count,
        backup.restorable,
        backup_authentication_label(backup.authentication),
        backup.backup_id,
    )
}

pub(super) fn backup_display_label(backup: &BackupSummary) -> String {
    format!(
        "{} {} {} → {}",
        backup.providers.join(","),
        backup.layers.join(","),
        backup.selection.display_name,
        if backup.target_enabled {
            "enabled"
        } else {
            "disabled"
        },
    )
}

pub(super) fn backup_authentication_label(
    authentication: BackupAuthenticationStatus,
) -> &'static str {
    match authentication {
        BackupAuthenticationStatus::Verified => "verified",
        BackupAuthenticationStatus::LegacyUnauthenticated => "legacy-unauthenticated",
        BackupAuthenticationStatus::KeyUnavailable => "key-unavailable",
        BackupAuthenticationStatus::Failed => "failed",
    }
}

pub(super) fn backup_authentication_readiness_label(state: &TuiState) -> &'static str {
    if state.backup_authentication_key.is_some() {
        "ready"
    } else {
        "unavailable (writes disabled)"
    }
}

pub(super) fn staged_toggle_label(staged: &StagedToggle) -> String {
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

pub(super) fn last_action_label(state: &TuiState) -> String {
    match &state.last_action {
        Some(TuiActionStatus::Success(message)) => format!("success: {message}"),
        Some(TuiActionStatus::Error(message)) => format!("error: {message}"),
        None => "none".to_string(),
    }
}

pub(super) fn last_control_label(state: &TuiState) -> String {
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

pub(super) fn search_summary(state: &TuiState) -> String {
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

pub(super) fn provider_summary(items: &[DiscoveryItem]) -> String {
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
    use ratatui::backend::TestBackend;
    use std::{fs, path::Path, process::Command as StdCommand};
    use tempfile::TempDir;
    use unpin_core::control_operation::ControlOperationLifecycle;
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
    fn loading_view_explains_discovery_and_cancellation() {
        let backend = TestBackend::new(60, 5);
        let mut terminal = Terminal::new(backend).expect("loading test terminal");
        let loading_state = LoadingState::default();
        terminal
            .draw(|frame| draw_loading(frame, &loading_state))
            .expect("draw loading view");

        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(rendered.contains("Preparing configuration discovery…"));
        assert!(rendered.contains("Press Q or Esc to cancel."));
    }

    #[test]
    fn loading_view_reports_provider_progress() {
        assert_eq!(
            loading_status(&LoadingState {
                progress: Some(DiscoveryProgress {
                    phase: DiscoveryProgressPhase::ScanningProjectScopes,
                    completed_providers: 0,
                    provider_count: ProviderId::ALL.len(),
                }),
            }),
            "Scanning project skill scopes…"
        );

        let state = LoadingState {
            progress: Some(DiscoveryProgress {
                phase: DiscoveryProgressPhase::DiscoveringProvider(ProviderId::Codex),
                completed_providers: 1,
                provider_count: ProviderId::ALL.len(),
            }),
        };
        assert_eq!(
            loading_status(&state),
            "Discovering codex configuration and project skills… (2/6)"
        );

        let state = LoadingState {
            progress: Some(DiscoveryProgress {
                phase: DiscoveryProgressPhase::Finalizing,
                completed_providers: ProviderId::ALL.len(),
                provider_count: ProviderId::ALL.len(),
            }),
        };
        assert_eq!(loading_status(&state), "Finalizing discovery inventory…");
    }

    #[test]
    fn loading_startup_accepts_discovery_without_waiting_for_input() {
        let (sender, receiver) = std::sync::mpsc::channel::<TuiStartupEvent>();
        let mut loading_state = LoadingState::default();
        assert!(
            try_take_startup(&receiver, &mut loading_state)
                .expect("pending discovery is not an error")
                .is_none()
        );

        sender
            .send(TuiStartupEvent::Progress(DiscoveryProgress {
                phase: DiscoveryProgressPhase::DiscoveringProvider(ProviderId::Codex),
                completed_providers: 1,
                provider_count: ProviderId::ALL.len(),
            }))
            .expect("send discovery progress");
        sender
            .send(TuiStartupEvent::Complete(Ok(TuiStartup {
                discovery: discovery(vec![item(
                    "loading-result",
                    ProviderId::Codex,
                    DiscoveryLayer::Project,
                    DiscoveryCategory::Skill,
                    DiscoveryKind::Skill,
                )]),
                credentials: StartupCredentials {
                    backup_authentication_key: None,
                    session_authority_key: None,
                    warnings: Vec::new(),
                },
            })))
            .expect("send discovery result");

        let ready = try_take_startup(&receiver, &mut loading_state)
            .expect("completed discovery is not an error")
            .expect("completed discovery is available without an input event");
        assert_eq!(ready.discovery.items.len(), 1);
        assert_eq!(ready.discovery.items[0].id, "loading-result");
        assert_eq!(
            loading_state.progress,
            Some(DiscoveryProgress {
                phase: DiscoveryProgressPhase::DiscoveringProvider(ProviderId::Codex),
                completed_providers: 1,
                provider_count: ProviderId::ALL.len(),
            })
        );
    }

    #[test]
    fn loading_event_quits_for_q_and_escape() {
        for code in [KeyCode::Char('q'), KeyCode::Char('Q'), KeyCode::Esc] {
            assert_eq!(loading_event(key_event(code)), LoadingEvent::Quit);
        }
        assert_eq!(loading_event(Event::Resize(80, 24)), LoadingEvent::Redraw);
    }

    #[test]
    fn loading_startup_discovers_fixture_inventory_on_worker() {
        let app_state = TempDir::new().expect("temporary startup app state");
        let roots =
            DiscoveryRoots::fixture_root(fixtures_root()).with_app_state_root(app_state.path());
        let (receiver, _cancellation) =
            start_discovery(roots, app_state.path().to_path_buf(), true);
        let mut progress = Vec::new();
        let startup = loop {
            match receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("startup worker completes")
            {
                TuiStartupEvent::Progress(update) => progress.push(update),
                TuiStartupEvent::Complete(Ok(startup)) => break startup,
                TuiStartupEvent::Complete(Err(error)) => {
                    panic!("fixture discovery succeeds: {error}")
                }
            }
        };
        let mut inventory = startup
            .discovery
            .items
            .iter()
            .map(|item| {
                format!(
                    "{}|{}|{}|{}|{}",
                    item.id,
                    item.provider.as_str(),
                    item.layer.as_str(),
                    item.kind.as_str(),
                    item.enabled
                )
            })
            .collect::<Vec<_>>();
        inventory.sort_unstable();
        let expected = [
            "claude:global:agent:claude-global-reviewer|claude|global|agent|true",
            "claude:global:configured-mcp:global-docs|claude|global|mcp|true",
            "claude:global:hook:settings:PreToolUse:b0d4bd3ac8311f87:0|claude|global|hook|true",
            "claude:global:hook:settings:PreToolUse:d465dcd66d4f095b:0|claude|global|hook|true",
            "claude:global:setting:settings-local|claude|global|setting|true",
            "claude:global:setting:settings|claude|global|setting|true",
            "claude:global:skill:example-claude-global-skill|claude|global|skill|true",
            "claude:global:tool:settings-local:project-auditor|claude|global|plugin|true",
            "claude:global:tool:settings:connector-kit@example-marketplace|claude|global|plugin|true",
            "claude:global:tool:settings:demo-formatter|claude|global|plugin|false",
            "claude:global:tool:settings:safe-shell|claude|global|plugin|true",
            "claude:project:agent:claude-project-helper|claude|project|agent|true",
            "claude:project:configured-mcp:all-project-mcp-servers|claude|project|mcp|false",
            "claude:project:configured-mcp:github|claude|project|mcp|true",
            "claude:project:hook:settings-local:PostToolUse:082f8bb906aaa448:0|claude|project|hook|true",
            "claude:project:setting:settings-local|claude|project|setting|true",
            "claude:project:setting:settings|claude|project|setting|true",
            "claude:project:skill:example-claude-skill|claude|project|skill|true",
            "claude:project:tool:settings-local:local-shell|claude|project|plugin|false",
            "claude:project:tool:settings:github|claude|project|plugin|true",
            "codex:global:agent:codex-global-reviewer|codex|global|agent|true",
            "codex:global:configured-mcp:disabled-docs|codex|global|mcp|false",
            "codex:global:configured-mcp:github|codex|global|mcp|true",
            "codex:global:hook:config-toml:PreToolUse:da4582ee1ce6bf1e:0|codex|global|hook|true",
            "codex:global:hook:hooks-json:PostToolUse:d2b77d0f04613c78:0|codex|global|hook|true",
            "codex:global:hook:hooks-json:PostToolUse:f792360f58824223:0|codex|global|hook|true",
            "codex:global:plugin-config:config:connector-kit@example-marketplace|codex|global|plugin|true",
            "codex:global:plugin-config:config:disabled-helper|codex|global|plugin|false",
            "codex:global:plugin-config:config:safe-shell|codex|global|plugin|true",
            "codex:global:setting:config-toml|codex|global|setting|true",
            "codex:global:setting:hooks-json|codex|global|setting|true",
            "codex:global:skill:admin/example-codex-admin-skill|codex|global|skill|true",
            "codex:global:skill:example-shared-global-skill|codex|global|skill|true",
            "codex:project:agent:codex-project-helper|codex|project|agent|true",
            "codex:project:configured-mcp:project-docs|codex|project|mcp|false",
            "codex:project:hook:config-toml:ProjectStart:dca1d74aec19cb71:0|codex|project|hook|true",
            "codex:project:hook:hooks-json:ProjectStop:79e06e4de1bb408a:0|codex|project|hook|true",
            "codex:project:setting:config-toml|codex|project|setting|true",
            "codex:project:setting:hooks-json|codex|project|setting|true",
            "codex:project:skill:example-shared-project-skill|codex|project|skill|true",
            "cursor:global:agent:cursor-global-reviewer|cursor|global|agent|true",
            "cursor:global:configured-mcp:modern-global|cursor|global|mcp|true",
            "cursor:global:hook:hooks-json:BeforeShellExecution:8bfd0e74a63e361e:0|cursor|global|hook|true",
            "cursor:global:plugin-manifest:local:claude-compatible|cursor|global|plugin|true",
            "cursor:global:plugin-manifest:local:example-plugin|cursor|global|plugin|true",
            "cursor:global:setting:cli-config-json|cursor|global|setting|true",
            "cursor:global:setting:hooks-json|cursor|global|setting|true",
            "cursor:global:setting:permissions-json|cursor|global|setting|true",
            "cursor:global:setting:sandbox-json|cursor|global|setting|true",
            "cursor:global:skill:@compat/agents/example-shared-global-skill|cursor|global|skill|true",
            "cursor:global:skill:@compat/claude/example-claude-global-skill|cursor|global|skill|true",
            "cursor:global:skill:example-cursor-skill|cursor|global|skill|true",
            "cursor:project:agent:cursor-project-helper|cursor|project|agent|true",
            "cursor:project:configured-mcp:project-docs|cursor|project|mcp|true",
            "cursor:project:hook:hooks-json:AfterFileEdit:0c581592ab0e1948:0|cursor|project|hook|true",
            "cursor:project:setting:cli-json|cursor|project|setting|true",
            "cursor:project:setting:hooks-json|cursor|project|setting|true",
            "cursor:project:setting:permissions-json|cursor|project|setting|true",
            "cursor:project:setting:sandbox-json|cursor|project|setting|true",
            "cursor:project:skill:@compat/agents/example-shared-project-skill|cursor|project|skill|true",
            "cursor:project:skill:@compat/claude/example-claude-skill|cursor|project|skill|true",
            "cursor:project:skill:example-cursor-project-skill|cursor|project|skill|true",
            "opencode:global:configured-mcp:example-global|opencode|global|mcp|true",
            "opencode:global:plugin-config:npm:example-opencode-connector|opencode|global|plugin|true",
            "opencode:global:plugin-manifest:local:example-local.ts|opencode|global|plugin|true",
            "opencode:global:setting:opencode.jsonc|opencode|global|setting|true",
            "opencode:global:skill:@compat/agents/example-shared-global-skill|opencode|global|skill|true",
            "opencode:global:skill:@compat/claude/example-claude-global-skill|opencode|global|skill|true",
            "opencode:global:skill:example-opencode-global-skill|opencode|global|skill|true",
            "opencode:project:configured-mcp:example-project|opencode|project|mcp|false",
            "opencode:project:plugin-config:npm:example-opencode-project-connector|opencode|project|plugin|true",
            "opencode:project:plugin-manifest:local:example-project.js|opencode|project|plugin|true",
            "opencode:project:setting:opencode.json|opencode|project|setting|true",
            "opencode:project:skill:@compat/agents/example-shared-project-skill|opencode|project|skill|true",
            "opencode:project:skill:@compat/claude/example-claude-skill|opencode|project|skill|true",
            "opencode:project:skill:example-opencode-project-skill|opencode|project|skill|true",
            "pi:global:plugin-config:package-extensions:npm:example-pi-connector|pi|global|plugin|true",
            "pi:global:setting:settings-json|pi|global|setting|true",
            "pi:global:skill:@compat/agents/example-shared-global-skill|pi|global|skill|true",
            "pi:global:skill:@file/example-pi-file-skill|pi|global|skill|true",
            "pi:global:skill:workflows/example-pi-global-skill|pi|global|skill|true",
            "pi:project:plugin-config:package-extensions:npm:example-pi-project-connector|pi|project|plugin|true",
            "pi:project:setting:settings-json|pi|project|setting|true",
            "pi:project:skill:@compat/agents/example-shared-project-skill|pi|project|skill|true",
            "pi:project:skill:@file/example-pi-project-file-skill|pi|project|skill|true",
            "pi:project:skill:example-pi-project-skill|pi|project|skill|true",
            "zed:global:configured-mcp:github|zed|global|mcp|true",
            "zed:global:setting:agents-md|zed|global|setting|true",
            "zed:global:setting:settings-json|zed|global|setting|true",
            "zed:global:skill:example-shared-global-skill|zed|global|skill|true",
            "zed:project:configured-mcp:local-docs|zed|project|mcp|true",
            "zed:project:setting:agents-md|zed|project|setting|true",
            "zed:project:setting:settings-json|zed|project|setting|true",
            "zed:project:skill:example-shared-project-skill|zed|project|skill|true",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert_eq!(inventory, expected);
        assert_eq!(startup.discovery.warnings, Vec::new());
        assert_eq!(progress.len(), ProviderId::ALL.len() + 2);
        assert_eq!(
            progress[0],
            DiscoveryProgress {
                phase: DiscoveryProgressPhase::ScanningProjectScopes,
                completed_providers: 0,
                provider_count: ProviderId::ALL.len(),
            }
        );
        for (completed_providers, provider) in ProviderId::ALL.into_iter().enumerate() {
            assert_eq!(
                progress[completed_providers + 1],
                DiscoveryProgress {
                    phase: DiscoveryProgressPhase::DiscoveringProvider(provider),
                    completed_providers,
                    provider_count: ProviderId::ALL.len(),
                }
            );
        }
        assert_eq!(
            progress[ProviderId::ALL.len() + 1],
            DiscoveryProgress {
                phase: DiscoveryProgressPhase::Finalizing,
                completed_providers: ProviderId::ALL.len(),
                provider_count: ProviderId::ALL.len(),
            }
        );
        assert!(startup.credentials.backup_authentication_key.is_some());
        assert!(startup.credentials.session_authority_key.is_some());
        assert!(startup.credentials.warnings.is_empty());
    }

    #[test]
    fn loading_startup_surfaces_worker_error_and_disconnect() {
        let (sender, receiver) = std::sync::mpsc::channel::<TuiStartupEvent>();
        let mut loading_state = LoadingState::default();
        sender
            .send(TuiStartupEvent::Complete(Err(io::Error::other(
                "discovery failed",
            )
            .into())))
            .expect("send worker error");
        let error = match try_take_startup(&receiver, &mut loading_state) {
            Err(error) => error,
            Ok(_) => panic!("worker error is surfaced"),
        };
        assert!(error.to_string().contains("discovery failed"));

        let (sender, receiver) = std::sync::mpsc::channel::<TuiStartupEvent>();
        let mut loading_state = LoadingState::default();
        drop(sender);
        let error = match try_take_startup(&receiver, &mut loading_state) {
            Err(error) => error,
            Ok(_) => panic!("disconnect is surfaced"),
        };
        assert!(
            error
                .to_string()
                .contains("discovery worker stopped before completing")
        );
    }

    #[test]
    fn loading_startup_surfaces_worker_panic() {
        let (sender, receiver) = std::sync::mpsc::channel::<TuiStartupEvent>();
        let cancellation = Arc::new(AtomicBool::new(false));
        start_discovery_worker(sender, cancellation, || panic!("synthetic startup panic"));

        let mut loading_state = LoadingState::default();
        for _ in 0..100 {
            match try_take_startup(&receiver, &mut loading_state) {
                Err(error) => {
                    assert!(
                        error
                            .to_string()
                            .contains("startup discovery worker panicked: synthetic startup panic")
                    );
                    return;
                }
                Ok(Some(_)) => panic!("panic cannot complete startup successfully"),
                Ok(None) => thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("worker panic is surfaced through loading error handling");
    }

    #[test]
    fn loading_startup_cancellation_after_progress_does_not_complete_successfully() {
        let app_state = TempDir::new().expect("temporary startup app state");
        let (pause_started, pause_release) = std::sync::mpsc::sync_channel(0);
        assert!(
            startup_progress_test_pauses()
                .lock()
                .expect("startup progress test pauses lock")
                .insert(app_state.path().to_path_buf(), pause_started)
                .is_none()
        );
        let roots =
            DiscoveryRoots::fixture_root(fixtures_root()).with_app_state_root(app_state.path());
        let (receiver, cancellation) = start_discovery(roots, app_state.path().to_path_buf(), true);

        match receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("receive initial progress")
        {
            TuiStartupEvent::Progress(progress) => {
                assert_eq!(progress.completed_providers, 0);
            }
            TuiStartupEvent::Complete(Ok(_)) => panic!("startup cannot complete before progress"),
            TuiStartupEvent::Complete(Err(error)) => {
                panic!("startup worker succeeds before cancellation: {error}")
            }
        }
        cancellation.store(true, Ordering::Relaxed);
        pause_release
            .recv_timeout(Duration::from_secs(5))
            .expect("release worker after cancellation");

        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(5)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        ));
        startup_progress_test_pauses()
            .lock()
            .expect("startup progress test pauses lock")
            .remove(app_state.path());
    }

    #[test]
    fn loading_startup_records_credential_warnings() {
        let mut state = TuiState::new(discovery(Vec::new()));
        record_startup_warnings(
            &mut state,
            vec![
                "backup authentication unavailable".to_string(),
                "session authority unavailable".to_string(),
            ],
        );
        assert_eq!(
            state.last_action,
            Some(TuiActionStatus::Error(
                "backup authentication unavailable; session authority unavailable".to_string()
            ))
        );
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
        let export_legend = command_legend_for_state(&state)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(export_legend.contains("MCP approval: eXport"));
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
            ..DiscoveryOutput::default()
        }
    }

    fn discovery_with_warnings(
        items: Vec<DiscoveryItem>,
        warnings: Vec<DiscoveryWarning>,
    ) -> DiscoveryOutput {
        DiscoveryOutput {
            items,
            warnings,
            ..DiscoveryOutput::default()
        }
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
        assert!(output.contains("claude project example → disabled created: 2026-06-20T12:00:00Z entries: 1 restorable: true"));
        assert!(output.contains("id: backup-new"));
        assert!(output.contains("claude project example → disabled created: 2026-06-20T10:00:00Z entries: 0 restorable: false"));
        assert!(output.contains("id: backup-old"));
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
        assert!(output.contains("created: 2026-06-20T12:03:00Z entries: 1 restorable: true"));
        assert!(output.contains("id: backup-valid"));
        assert!(output.contains("created: 2026-06-20T12:02:00Z entries: 1 restorable: false"));
        assert!(output.contains("id: backup-mismatch"));
        assert!(output.contains("created: 2026-06-20T12:01:00Z entries: 1 restorable: false"));
        assert!(output.contains("id: backup-traversal"));
        assert!(output.contains("created: 2026-06-20T12:00:00Z entries: 0 restorable: false"));
        assert!(output.contains("id: backup-empty"));
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
                .discovery
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
            .discovery
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

    #[test]
    fn group_control_uses_a_title_case_view_name_and_wraps_details() {
        use ratatui::widgets::Widget;

        assert_eq!(TuiView::Groups.title(), "Groups");

        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.view = TuiView::Groups;

        let area = ratatui::layout::Rect::new(0, 0, 28, 8);
        let mut buffer = ratatui::buffer::Buffer::empty(area);
        selected_detail(&state, 0).render(area, &mut buffer);
        let rendered = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("phase=browsing"), "{rendered}");
    }

    #[test]
    fn group_control_scrolls_within_wrapped_content() {
        let details = vec![
            "a detailed group plan line that must wrap across the narrow control pane".to_string(),
        ];
        let capped = control_scroll_offset(&details, u16::MAX, 16, 5);
        assert!(capped > 0, "wrapped content should be scrollable");
        assert!(
            capped < u16::MAX,
            "scroll must be capped to rendered content"
        );

        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.view = TuiView::Groups;
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::PageDown)),
            TuiEventOutcome::Redraw
        );
        assert_eq!(state.control_scroll, CONTROL_SCROLL_STEP);
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::PageUp)),
            TuiEventOutcome::Redraw
        );
        assert_eq!(state.control_scroll, 0);
    }

    #[test]
    fn drawing_clamps_group_control_scroll_before_the_next_key_event() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.view = TuiView::Groups;
        state.control_scroll = u16::MAX;

        let backend = ratatui::backend::TestBackend::new(28, 30);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw control pane");

        assert!(state.control_scroll < u16::MAX);
        let max_scroll = state.control_scroll_limit;
        assert_eq!(state.control_scroll, max_scroll);

        for _ in 0..32 {
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::PageDown)),
                TuiEventOutcome::Redraw
            );
        }
        assert_eq!(state.control_scroll, max_scroll);
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::PageUp)),
            TuiEventOutcome::Redraw
        );
        assert_eq!(
            state.control_scroll,
            max_scroll.saturating_sub(CONTROL_SCROLL_STEP)
        );
    }

    #[test]
    fn command_legend_underlines_printable_action_mnemonics() {
        let legend = command_legend(TuiView::Inventory);
        let underlined = legend
            .iter()
            .flat_map(|line| line.spans.iter())
            .filter(|span| span.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>();

        assert_eq!(underlined, ["V", "p", "l", "c", "x", "A", "U", "Q"]);
    }

    #[test]
    fn inventory_legend_omits_disabled_control_scrolling() {
        assert!(
            !command_legend(TuiView::Inventory)
                .iter()
                .flat_map(|line| line.spans.iter())
                .any(|span| span.content.contains("PgUp/PgDn"))
        );
    }

    #[test]
    fn footer_height_accounts_for_wrapped_command_legend() {
        let legend = vec![Line::from("12345678")];

        assert_eq!(command_footer_height(&legend, 10), 3);
        assert_eq!(command_footer_height(&legend, 6), 4);
        assert!(
            command_footer_height(&command_legend(TuiView::Groups), 30)
                > u16::try_from(command_legend(TuiView::Groups).len())
                    .unwrap()
                    .saturating_add(2)
        );
    }

    #[test]
    fn headless_command_legend_preserves_literal_action_labels() {
        let rendered = headless_command_legend(TuiView::Inventory).join("\n");

        assert!(rendered.contains("[V]iew | ↑/↓ move | filter: [p]rovider/[l]ayer/[c]ategory"));
        assert!(rendered.contains("[x] clear search"));
        assert!(rendered.contains("[A]pply"));
        assert!(rendered.contains("[Q]uit"));
        assert!(!rendered.contains('\u{0332}'));

        let groups = headless_command_legend(TuiView::Groups).join("\n");
        assert!(groups.contains("MCP approval: e[X]port (after approval)"));
    }

    #[test]
    fn group_command_legend_names_each_group_action() {
        let legend = command_legend(TuiView::Groups);
        let rendered = legend
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(rendered.contains("Groups: P reach | New | Edit | Rename | Delete"));
        assert!(rendered.contains("History | restore | Open approval"));
        assert!(rendered.contains("Write definition"));
        assert!(!rendered.contains("eXport"));

        let underlined = legend
            .iter()
            .flat_map(|line| line.spans.iter())
            .filter(|span| span.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            underlined,
            [
                "V", "M", "A", "U", "Q", "P", "N", "E", "R", "D", "H", "r", "O", "W"
            ]
        );
    }

    #[test]
    fn command_legend_includes_view_specific_controls() {
        let rendered = |view| {
            command_legend(view)
                .iter()
                .flat_map(|line| line.spans.iter())
                .map(|span| span.content.as_ref())
                .collect::<String>()
        };

        assert!(rendered(TuiView::Profiles).contains("Profiles: scope | r provider"));
        assert!(rendered(TuiView::Gateways).contains("Gateways: force"));
        assert!(rendered(TuiView::Groups).contains("Mode/action"));
        assert!(rendered(TuiView::Groups).contains("Esc end input/quit"));
        assert!(!rendered(TuiView::Sessions).contains("Mode/action"));
        assert!(!rendered(TuiView::Sessions).contains("filter: provider/layer/category"));
        assert!(!rendered(TuiView::Sessions).ends_with(" | "));
        assert!(
            TuiView::ALL
                .iter()
                .all(|view| !command_legend(*view).is_empty())
        );
    }

    #[test]
    fn text_input_legend_hides_consumed_command_mnemonics() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('/'))),
            TuiEventOutcome::Redraw
        );

        let rendered = command_legend_for_state(&state)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(
            rendered,
            "Search input: type | backspace delete | enter/esc finish"
        );
        assert!(!rendered.contains("Apply"));
    }

    #[test]
    fn displayed_mnemonics_dispatch_to_tui_actions() {
        let new_state = |view| {
            let mut state = TuiState::new(DiscoveryOutput {
                items: Vec::new(),
                warnings: Vec::new(),
                ..DiscoveryOutput::default()
            });
            state.view = view;
            state
        };

        let mut state = new_state(TuiView::Inventory);
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('V'))),
            TuiEventOutcome::Redraw
        );
        assert_eq!(state.view, TuiView::Groups);
        let mut state = TuiState::new(discovery(vec![item(
            "mnemonic-inventory-filter",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        )]));
        for mnemonic in ['p', 'l', 'c'] {
            let filters_before = state.filter_summary();
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::Char(mnemonic))),
                TuiEventOutcome::Redraw,
                "{mnemonic} should be bound"
            );
            assert_ne!(state.filter_summary(), filters_before);
        }
        assert!(state.stage_selected_toggle());
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('U'))),
            TuiEventOutcome::Redraw
        );
        assert_eq!(state.staged_count(), 0, "U should clear staged changes");
        let mut state = new_state(TuiView::Inventory);
        state.set_search_query("clear me");
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('x'))),
            TuiEventOutcome::Redraw
        );
        assert!(
            state.search_query.is_empty(),
            "x should clear the search query"
        );
        assert_eq!(
            handle_tui_event(
                &mut new_state(TuiView::Inventory),
                key_event(KeyCode::Char('Q'))
            ),
            TuiEventOutcome::Quit
        );
        let mut state = new_state(TuiView::Groups);
        let details_before = state.active_details();
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('P'))),
            TuiEventOutcome::Redraw
        );
        assert_ne!(
            state.active_details(),
            details_before,
            "P should change the active group reach"
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('s'))),
            TuiEventOutcome::Ignore,
            "s should not be active outside a group-create draft"
        );
        for mnemonic in ['N', 'E', 'R', 'D', 'H', 'r', 'O', 'W'] {
            let mut state = new_state(TuiView::Groups);
            let details_before = state.active_details();
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::Char(mnemonic))),
                TuiEventOutcome::Redraw,
                "{mnemonic} should be bound in Groups"
            );
            assert_ne!(
                state.active_details(),
                details_before,
                "{mnemonic} should report an observable Groups result"
            );
        }
        let mut state = TuiState::new(discovery(vec![item(
            "mnemonic-group-member",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        )]));
        assert!(state.stage_selected_toggle());
        state.view = TuiView::Groups;
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('N'))),
            TuiEventOutcome::Redraw
        );
        assert!(state.group_text_editing(), "N should start a group draft");
        assert_eq!(
            command_legend_for_state(&state)
                .iter()
                .flat_map(|line| line.spans.iter())
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "Group input: type | backspace delete | enter submit | esc cancel"
        );
        assert_eq!(
            handle_tui_event(&mut state, Event::Paste("mnemonics".to_string())),
            TuiEventOutcome::Redraw
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Enter)),
            TuiEventOutcome::Redraw
        );
        let details_before = state.active_details();
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('s'))),
            TuiEventOutcome::Redraw
        );
        assert_ne!(
            state.active_details(),
            details_before,
            "s should change the group draft scope"
        );
        let filters_before = state.filter_summary();
        for mnemonic in ['p', 'l', 'c'] {
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::Char(mnemonic))),
                TuiEventOutcome::Redraw
            );
        }
        assert_ne!(state.filter_summary(), filters_before);
        let draft_legend = command_legend_for_state(&state)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(draft_legend.contains("filter: provider/layer/category"));
        assert!(draft_legend.contains("/ search | x clear search"));
        assert!(draft_legend.contains("Groups draft: scope"));
        let mut state = new_state(TuiView::Groups);
        let filters_before = state.filter_summary();
        for mnemonic in ['p', 'l', 'c'] {
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::Char(mnemonic))),
                TuiEventOutcome::Ignore
            );
        }
        assert_eq!(state.filter_summary(), filters_before);
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('/'))),
            TuiEventOutcome::Ignore
        );
        for (view, mnemonic, name) in [
            (TuiView::Groups, 'M', "Groups"),
            (TuiView::Profiles, 'r', "Profiles"),
            (TuiView::Gateways, 'f', "Gateways"),
        ] {
            let mut state = new_state(view);
            let details_before = state.active_details();
            assert_eq!(
                handle_tui_event(&mut state, key_event(KeyCode::Char(mnemonic))),
                TuiEventOutcome::Redraw,
                "{mnemonic} should be bound in {name}"
            );
            assert_ne!(
                state.active_details(),
                details_before,
                "{mnemonic} should change {name} state"
            );
        }
    }

    #[test]
    fn groups_footer_and_header_are_visible_in_a_narrow_terminal() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.view = TuiView::Groups;

        let backend = ratatui::backend::TestBackend::new(61, 24);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw groups footer");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("Groups: P reach | New | Edit | Rename | Delete"));
        assert!(rendered.contains("Unpin | View: Groups"));
        assert!(rendered.contains("Filters:"));
        assert!(rendered.contains("Search:"));
        assert!(rendered.contains("History | restore | Open approval"));
        assert!(rendered.contains("Write definition"));
        assert!(!rendered.contains("eXport"));
    }

    #[test]
    fn inventory_header_wraps_active_filters_and_search_in_a_narrow_terminal() {
        let mut state = TuiState::new(discovery(vec![item(
            "narrow-inventory",
            ProviderId::Claude,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        )]));
        state.cycle_provider_filter();
        state.cycle_layer_filter();
        state.cycle_category_filter();
        state.set_search_query("narrow-header");

        let backend = ratatui::backend::TestBackend::new(61, 24);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw inventory header");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("Filters:"));
        assert!(rendered.contains("Search:"));
        assert!(rendered.contains("narrow-header"));
    }

    #[test]
    fn short_terminal_layout_does_not_overcommit_rows() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        let backend = ratatui::backend::TestBackend::new(20, 16);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw short terminal");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Unpin"));
        assert!(rendered.contains("Items:"));
    }

    #[test]
    fn short_narrow_layout_preserves_filter_and_search_state() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.view = TuiView::Groups;
        let backend = ratatui::backend::TestBackend::new(40, 20);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw short narrow terminal");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Filters:"));
        assert!(rendered.contains("Search:"));
    }

    #[test]
    fn shortest_layout_reserves_a_header_state_line_before_footer_detail() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        let backend = ratatui::backend::TestBackend::new(40, 7);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw shortest terminal");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Unpin"));
        assert!(rendered.contains("View:"));
    }

    fn restore_backup_summary(index: usize) -> BackupSummary {
        let mut selection = item(
            &format!("backup-target-{index}"),
            ProviderId::Codex,
            DiscoveryLayer::Global,
            DiscoveryCategory::Skill,
            DiscoveryKind::Skill,
        );
        selection.display_name = format!("target-{index}");
        BackupSummary {
            backup_id: format!("backup-{index:03}"),
            created_at: format!("2026-08-01T00:{index:02}:00Z"),
            item_count: 1,
            providers: vec!["codex".to_string()],
            layers: vec!["global".to_string()],
            paths: vec![format!("/state/backup-target-{index}")],
            restorable: true,
            authentication: BackupAuthenticationStatus::Verified,
            selection,
            target_enabled: index.is_multiple_of(2),
        }
    }

    #[test]
    fn restore_list_follows_the_selected_backup_and_uses_descriptive_labels() {
        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        let backups = (0..30).map(restore_backup_summary).collect::<Vec<_>>();
        state.backups.clone_from(&backups);
        state.restore_workflow = RestoreWorkflow::new(backups, Vec::new());
        state.view = TuiView::RestoreOperations;
        for _ in 0..20 {
            state.move_next();
        }

        let backend = ratatui::backend::TestBackend::new(100, 20);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw restore list");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("> codex global target-20 → enabled"));
        assert!(!state.restore_workflow.rows()[20].contains("backup-020"));
    }

    #[test]
    fn restore_backup_label_discloses_every_bundle_provider() {
        let mut backup = restore_backup_summary(0);
        backup.providers = vec!["codex".to_string(), "zed".to_string()];

        assert_eq!(
            backup_display_label(&backup),
            "codex,zed global target-0 → enabled"
        );
    }

    #[test]
    fn restore_backup_deletion_requires_confirmation_before_apply() {
        let app_state = TempDir::new().expect("temporary app state");
        let mut state = TuiState::new_with_app_state_root(
            DiscoveryOutput {
                items: Vec::new(),
                warnings: Vec::new(),
                ..DiscoveryOutput::default()
            },
            app_state.path().to_path_buf(),
        );
        let backup = restore_backup_summary(1);
        let backup_root = state.app_state_root.join("backups").join(&backup.backup_id);
        fs::create_dir_all(&backup_root).expect("backup directory");
        fs::write(
            backup_root.join("manifest.json"),
            "{\"backupId\":\"backup-001\"}\n",
        )
        .expect("backup manifest");
        state.backups = vec![backup.clone()];
        state.restore_workflow = RestoreWorkflow::new(vec![backup], Vec::new());
        state.view = TuiView::RestoreOperations;

        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('D'))),
            TuiEventOutcome::Redraw
        );
        assert!(backup_root.is_dir());
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('A'))),
            TuiEventOutcome::Redraw
        );
        assert!(backup_root.is_dir(), "unconfirmed deletion must not apply");
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Enter)),
            TuiEventOutcome::Redraw
        );
        assert!(matches!(
            state.last_action,
            Some(TuiActionStatus::Success(ref message))
                if message == "backup deletion confirmed; press A to apply"
        ));
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('A'))),
            TuiEventOutcome::Redraw
        );
        assert!(!backup_root.exists());
        assert!(state.restore_workflow.rows().is_empty());
        assert!(
            state
                .restore_workflow
                .details()
                .iter()
                .any(|detail| detail == "selected: none")
        );

        let backend = ratatui::backend::TestBackend::new(100, 20);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw empty restore list");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("No rows in this view."));
    }

    #[test]
    fn command_legend_uses_arrow_navigation_and_capitalized_actions() {
        let legend = command_legend(TuiView::RestoreOperations)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(legend.contains("↑/↓ move"));
        assert!(legend.contains("PgUp/PgDn scroll"));
        assert!(legend.contains("Space select/plan | Enter confirm"));
        assert!(legend.contains("Restore: Delete backup"));
        assert!(!legend.contains("j/k"));
        assert!(!legend.contains("Control"));

        let mut state = TuiState::new(DiscoveryOutput {
            items: Vec::new(),
            warnings: Vec::new(),
            ..DiscoveryOutput::default()
        });
        state.restore_workflow = RestoreWorkflow::new(
            vec![restore_backup_summary(0), restore_backup_summary(1)],
            Vec::new(),
        );
        state.view = TuiView::RestoreOperations;
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('j'))),
            TuiEventOutcome::Ignore
        );
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Down)),
            TuiEventOutcome::Redraw
        );
        assert!(state.active_rows()[1].starts_with('>'));
    }

    fn agent_plugin_fixture_state() -> (TempDir, TempDir, TuiState) {
        let fixture = TempDir::new().expect("temporary Agent Plugin TUI fixture");
        copy_dir_all(&fixtures_root(), fixture.path());
        let app_state = TempDir::new().expect("temporary Agent Plugin TUI state");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(fixture.path())
            .output()
            .expect("initialize Agent Plugin TUI fixture repository");
        assert!(git.status.success());
        let project_root = fs::canonicalize(fixture.path()).expect("canonical fixture root");
        let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state root");
        let roots =
            DiscoveryRoots::fixture_root(&project_root).with_app_state_root(&app_state_root);
        let discovery = discover_all(&roots).expect("discover Agent Plugin TUI fixture");
        let mut state =
            TuiState::new_with_paths_and_roots(discovery, app_state_root, project_root, roots);
        state.view = TuiView::Packages;
        (fixture, app_state, state)
    }

    #[test]
    fn agent_plugin_tui_empty_guidance_distinguishes_packages_from_groups() {
        let mut state = TuiState::new(DiscoveryOutput::default());
        state.view = TuiView::Packages;

        assert!(state.active_rows().is_empty());
        let details = state.active_details().join("\n");
        assert!(details.contains("No Agent Plugin packages"));
        assert!(details.contains("Packages are derived"));
        assert!(details.contains("Groups are editable"));
    }

    #[test]
    fn agent_plugin_tui_navigation_and_state_labels_are_explicit() {
        use unpin_core::agent_plugins::AgentPluginState;

        for (state, expected) in [
            (AgentPluginState::On, "on"),
            (AgentPluginState::Off, "off"),
            (AgentPluginState::Mixed, "mixed"),
            (AgentPluginState::Unknown, "unknown"),
        ] {
            assert_eq!(agent_plugins::state_label(state), expected);
        }

        let (_fixture, _app_state, mut state) = agent_plugin_fixture_state();
        let rows = state.active_rows();
        assert!(!rows.is_empty());
        assert!(rows[0].starts_with("> [on]"));
        assert!(
            state
                .active_details()
                .join("\n")
                .contains("Packages vs Groups")
        );
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).expect("package TUI test terminal");
        terminal
            .draw(|frame| draw(frame, &mut state))
            .expect("draw package view");
        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Packages"));
        assert!(rendered.contains("[on]"));
        state.move_next();
        assert!(state.active_rows()[state.package_workflow.selected()].starts_with('>'));
    }

    #[test]
    fn agent_plugin_tui_requires_explicit_reach_and_builds_one_aggregate_plan() {
        let (_fixture, _app_state, mut state) = agent_plugin_fixture_state();
        state.cycle_active_action();
        assert!(!state.plan_active_action());
        assert!(matches!(
            state.last_action,
            Some(TuiActionStatus::Error(ref message))
                if message.contains("choose explicit package reach")
        ));

        state.provider_filter = ProviderFilter::Provider(ProviderId::Codex);
        state.set_search_query("no inventory row matches this");
        assert_eq!(
            handle_tui_event(&mut state, key_event(KeyCode::Char('P'))),
            TuiEventOutcome::Redraw
        );
        assert!(state.plan_active_action());
        let reviewed = state
            .package_workflow
            .reviewed_plan()
            .expect("aggregate package plan");
        assert_eq!(reviewed.included_count(), 2);
        assert_eq!(reviewed.write_count(), 2);
        assert_eq!(reviewed.selector.exact_identities.len(), 2);
        assert_eq!(state.package_workflow.reach_label(), "all");
        assert_eq!(
            state.staged_count(),
            0,
            "package planning is never per-item staging"
        );
    }

    #[test]
    fn agent_plugin_tui_confirm_cancel_and_apply_use_reviewed_bulk_lifecycle() {
        let (_fixture, app_state, mut state) = agent_plugin_fixture_state();
        let before = state.discovery.clone();
        state.cycle_active_action();
        state.cycle_active_provider_reach();
        assert!(state.plan_active_action());
        assert!(state.confirm_active_action());
        assert_eq!(state.package_workflow.phase(), WorkflowPhase::Confirmed);
        assert!(state.cancel_package_interaction());
        assert!(state.package_workflow.reviewed_plan().is_none());
        assert_eq!(state.discovery, before, "cancel must not mutate providers");
        assert!(
            !app_state.path().join("transitions").exists(),
            "cancelled package preview must not persist a durable handoff"
        );

        assert!(
            state.plan_active_action(),
            "replan after cancel failed: {:?}",
            state.last_action
        );
        assert!(state.confirm_active_action());
        state.apply_active_action();
        assert_eq!(state.package_workflow.phase(), WorkflowPhase::Applied);
        assert!(state.package_workflow.reviewed_plan().is_none());
        assert!(!state.confirm_active_action());
        let packages = state.discovery.agent_plugins();
        assert_eq!(packages.len(), 1);
        assert_eq!(
            agent_plugins::state_label(packages[0].state),
            "off",
            "one aggregate apply refreshes both native activations"
        );
        let details = state.package_workflow.details().join("\n");
        assert!(details.contains("last apply:"));
        assert!(!details.contains("requires replanning"));
    }

    #[test]
    fn agent_plugin_tui_redacts_internal_plan_error_details() {
        let message =
            agent_plugins::safe_plan_error(unpin_core::mutation::BulkTogglePlanError::ReachAware(
                "private provider path and journal detail".to_string(),
            ));

        assert_eq!(
            message,
            "package plan blocked; refresh inventory and review package diagnostics"
        );
        assert!(!message.contains("private provider path"));
    }

    #[test]
    fn agent_plugin_tui_diagnostics_only_plan_never_creates_writes() {
        let fixture = TempDir::new().expect("temporary diagnostics-only package fixture");
        let app_state = TempDir::new().expect("temporary diagnostics-only app state");
        let package_root = fixture
            .path()
            .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
        fs::create_dir_all(package_root.join("skills/review")).expect("create package fixture");
        fs::write(
            fixture.path().join("codex/global/config.toml"),
            "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
        )
        .expect("write native activation");
        fs::write(
            package_root.join("plugin.json"),
            r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"connector-kit","version":"1.0.0"}"#,
        )
        .expect("write plugin manifest");
        fs::write(
            package_root.join("skills/review/SKILL.md"),
            "---\nname: review\ndescription: Review changes.\n---\n",
        )
        .expect("write package skill");
        fs::write(package_root.join("mcp.json"), "{").expect("write invalid MCP component");
        let activation_path = fixture.path().join("codex/global/config.toml");
        let activation_before =
            fs::read(&activation_path).expect("read native activation before plan");
        let git = StdCommand::new("git")
            .args(["init", "-q"])
            .current_dir(fixture.path())
            .output()
            .expect("initialize diagnostics-only fixture repository");
        assert!(git.status.success());
        let project_root = fs::canonicalize(fixture.path()).expect("canonical fixture root");
        let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app state root");
        let roots =
            DiscoveryRoots::fixture_root(&project_root).with_app_state_root(&app_state_root);
        let discovery = discover_all(&roots).expect("discover diagnostics-only package");
        let mut state = TuiState::new_with_paths_and_roots(
            discovery,
            app_state_root.clone(),
            project_root,
            roots,
        );
        state.view = TuiView::Packages;
        state.cycle_active_action();
        state.cycle_active_provider_reach();

        assert!(!state.plan_active_action());
        assert!(matches!(
            state.last_action,
            Some(TuiActionStatus::Error(ref message))
                if message.contains("diagnostics-only")
        ));
        assert!(!app_state_root.join("operations").exists());
        assert_eq!(
            fs::read(activation_path).expect("read native activation after blocked plan"),
            activation_before
        );
    }
}
