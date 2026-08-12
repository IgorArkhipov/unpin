use std::path::Path;

use unpin_core::{
    agent_plugins::{
        AgentPluginAccess, AgentPluginComponentDisposition, AgentPluginState, AgentPluginSummary,
    },
    config::{UnpinConfig, UnpinConfigPaths},
    discovery::{DiscoveryOutput, DiscoveryRoots, ProviderId},
    mutation::{
        BulkToggleApplyResult, BulkToggleController, BulkTogglePlan, BulkTogglePlanError,
        BulkToggleRequest,
    },
    provider_reach::{
        ConnectionBoundary, ProviderReachInput, ProviderReachLifecycle, SelectedProviderAuthority,
        SelectedProviderProvenance,
    },
};

use super::WorkflowPhase;
use crate::{
    commands::toggle::{durable_context, lifecycle_name},
    credentials, unix_now,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageReach {
    Required,
    All,
    Selected(ProviderId),
}

#[derive(Debug, Clone)]
pub(super) struct AgentPluginWorkflow {
    packages: Vec<AgentPluginSummary>,
    inventory_complete: bool,
    selected: usize,
    reach: PackageReach,
    target_enabled: bool,
    reviewed: Option<BulkTogglePlan>,
    confirmed: bool,
    phase: WorkflowPhase,
    last_result: Option<BulkToggleApplyResult>,
    last_error: Option<String>,
    replan_required: bool,
}

impl AgentPluginWorkflow {
    pub(super) fn new(discovery: &DiscoveryOutput) -> Self {
        Self {
            packages: discovery.agent_plugins(),
            inventory_complete: discovery.agent_plugin_inventory_complete(),
            selected: 0,
            reach: PackageReach::Required,
            target_enabled: true,
            reviewed: None,
            confirmed: false,
            phase: WorkflowPhase::Browsing,
            last_result: None,
            last_error: None,
            replan_required: false,
        }
    }

    pub(super) fn refresh(&mut self, discovery: &DiscoveryOutput) {
        let selected_id = self
            .selected_package()
            .map(|package| package.logical_id.clone());
        self.packages = discovery.agent_plugins();
        self.inventory_complete = discovery.agent_plugin_inventory_complete();
        self.selected = selected_id
            .as_deref()
            .and_then(|logical_id| {
                self.packages
                    .iter()
                    .position(|package| package.logical_id == logical_id)
            })
            .unwrap_or(0)
            .min(self.packages.len().saturating_sub(1));
        self.replan_required = self.reviewed.as_ref().is_some_and(|reviewed| {
            self.selected_package().is_none_or(|package| {
                reviewed.selection_context_fingerprint.as_deref()
                    != Some(package.projection_fingerprint.as_str())
            })
        });
    }

    #[cfg(test)]
    pub(super) fn selected(&self) -> usize {
        self.selected
    }

    pub(super) fn len(&self) -> usize {
        self.packages.len()
    }

    #[cfg(test)]
    pub(super) fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    #[cfg(test)]
    pub(super) fn reviewed_plan(&self) -> Option<&BulkTogglePlan> {
        self.reviewed.as_ref()
    }

    pub(super) fn reach_label(&self) -> String {
        match self.reach {
            PackageReach::Required => "required".to_string(),
            PackageReach::All => "all".to_string(),
            PackageReach::Selected(provider) => format!("selected:{}", provider.as_str()),
        }
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.packages
            .iter()
            .enumerate()
            .map(|(index, package)| {
                format!(
                    "{} [{}] {} instances={} access={}",
                    if index == self.selected { ">" } else { " " },
                    state_label(package.state),
                    package.name,
                    package.instances.len(),
                    access_label(package.access),
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![
            "Packages vs Groups: Packages are derived logical views; Groups are editable Unpin-owned selections."
                .to_string(),
            "Package activation changes always use one aggregate reviewed plan; inventory filters and per-item staging do not change package reach."
            .to_string(),
        ];
        if !self.inventory_complete {
            details.push(
                "Inventory incomplete: one or more Agent Plugin cache locations could not be read; refresh after fixing access."
                    .to_string(),
            );
        }
        if self.phase == WorkflowPhase::RecoveryRequired {
            details.push(
                "Recovery required: do not reapply. Inspect Restore Operations durable operation status before recovery."
                    .to_string(),
            );
        }
        let Some(package) = self.selected_package() else {
            details.push("No Agent Plugin packages were derived from discovery.".to_string());
            details.push(
                "Packages are derived from standard manifests plus native activation anchors. Groups are editable even when no packages are present."
                    .to_string(),
            );
            return details;
        };

        details.extend([
            format!(
                "selected package: {} ({})",
                package.name, package.logical_id
            ),
            format!(
                "state: {} | access: {} | instances: {}",
                state_label(package.state),
                access_label(package.access),
                package.instances.len()
            ),
            format!(
                "target: {} | reach: {} | phase: {}",
                if self.target_enabled { "on" } else { "off" },
                self.reach_label(),
                self.phase.label()
            ),
        ]);
        if self.reach == PackageReach::Required {
            details.push(
                "Reach required: press P to choose all providers or an explicit selected provider; filters never imply reach."
                    .to_string(),
            );
        }
        details.push(match package.access {
            AgentPluginAccess::Actionable => {
                "Actionable: M changes the target, Space reviews one aggregate plan, Enter confirms, A applies, and U/Esc cancels without provider writes."
                    .to_string()
            }
            AgentPluginAccess::DiagnosticsOnly => {
                "Diagnostics-only: resolve invalid components or missing activation coverage, refresh, then replan; no apply action is available."
                    .to_string()
            }
            AgentPluginAccess::Unsupported => {
                "Unsupported provider/layer: package details are informational and no apply action is available."
                    .to_string()
            }
        });
        for instance in &package.instances {
            details.push(format!(
                "instance: {} {} state={} access={} activations={} components={}",
                instance.provider.as_str(),
                instance.layer.as_str(),
                state_label(instance.state),
                access_label(instance.access),
                instance.activations.len(),
                instance.components.len(),
            ));
            for component in &instance.components {
                if component.disposition != AgentPluginComponentDisposition::Available {
                    details.push(format!(
                        "component diagnostic: {} {} {:?}{}",
                        instance.provider.as_str(),
                        component.name,
                        component.disposition,
                        component
                            .reason
                            .as_deref()
                            .map_or_else(String::new, |reason| format!(" ({reason})")),
                    ));
                }
            }
            details.extend(
                instance
                    .blockers
                    .iter()
                    .map(|reason| format!("blocker: {} {reason}", instance.provider.as_str())),
            );
            details.extend(
                instance
                    .diagnostics
                    .iter()
                    .map(|reason| format!("diagnostic: {} {reason}", instance.provider.as_str())),
            );
        }
        if let Some(reviewed) = &self.reviewed {
            details.extend([
                format!("reviewed operation: {}", reviewed.operation_id),
                format!(
                    "aggregate counts: included={} writes={} no-op={} blocked={} reach-excluded={}",
                    reviewed.included_count(),
                    reviewed.write_count(),
                    reviewed
                        .included_count()
                        .saturating_sub(reviewed.write_count()),
                    reviewed.blocked_count(),
                    reviewed.provider_coverage.reach_excluded_count(),
                ),
                format!("reviewed lifecycle: {}", lifecycle_name(reviewed.lifecycle)),
            ]);
        }
        if let Some(result) = &self.last_result {
            details.push(format!(
                "last apply: {} {} items={}",
                result.operation_id,
                lifecycle_name(result.lifecycle),
                result.items.len()
            ));
        }
        if self.replan_required {
            details.push(
                "Projection changed after review/apply: refresh is complete; a new mutation requires replanning."
                    .to_string(),
            );
        }
        if let Some(error) = &self.last_error {
            details.push(format!("error: {error}"));
        }
        details
    }

    pub(super) fn select_next(&mut self) {
        if self.packages.len() > 1 {
            self.selected = (self.selected + 1) % self.packages.len();
            self.reset_for_selection();
        }
    }

    pub(super) fn select_previous(&mut self) {
        if self.packages.len() > 1 {
            self.selected = if self.selected == 0 {
                self.packages.len() - 1
            } else {
                self.selected - 1
            };
            self.reset_for_selection();
        }
    }

    pub(super) fn cycle_target(&mut self) {
        self.target_enabled = !self.target_enabled;
        self.clear_review();
    }

    pub(super) fn cycle_reach(&mut self) {
        let providers = self.selected_providers();
        self.reach = match self.reach {
            PackageReach::Required => PackageReach::All,
            PackageReach::All => providers
                .first()
                .copied()
                .map_or(PackageReach::Required, PackageReach::Selected),
            PackageReach::Selected(current) => providers
                .iter()
                .position(|provider| *provider == current)
                .and_then(|index| providers.get(index + 1))
                .copied()
                .map_or(PackageReach::Required, PackageReach::Selected),
        };
        self.clear_review();
    }

    pub(super) fn plan(
        &mut self,
        discovery: &DiscoveryOutput,
        app_state_root: &Path,
    ) -> Result<&BulkTogglePlan, String> {
        let logical_id = self
            .selected_package()
            .map(|package| package.logical_id.clone())
            .ok_or_else(|| "no Agent Plugin package selected".to_string())?;
        let package = discovery
            .agent_plugins()
            .into_iter()
            .find(|package| package.logical_id == logical_id)
            .ok_or_else(|| "selected Agent Plugin package is no longer discovered".to_string())?;
        let mut request =
            BulkToggleRequest::for_agent_plugin_summary(discovery, &package, self.target_enabled)
                .map_err(safe_plan_error)?;
        request = match self.reach {
            PackageReach::Required => {
                return Err(
                    "choose explicit package reach with P: all providers or one selected provider"
                        .to_string(),
                );
            }
            PackageReach::All => {
                request.with_reach(ConnectionBoundary::All, ProviderReachInput::All)
            }
            PackageReach::Selected(provider) => request
                .with_reach(
                    ConnectionBoundary::All,
                    ProviderReachInput::selected(
                        provider,
                        SelectedProviderProvenance::ExplicitInput,
                    ),
                )
                .with_authority(SelectedProviderAuthority::new(
                    provider,
                    SelectedProviderProvenance::ExplicitInput,
                )),
        };
        BulkToggleController::validate_before_discovery(&request).map_err(safe_plan_error)?;
        let controller = BulkToggleController::new(app_state_root);
        let reviewed = controller
            .plan_agent_plugin_from_discovery(discovery.clone(), request, &package)
            .map_err(safe_plan_error)?;
        self.reviewed = Some(reviewed);
        self.confirmed = false;
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        self.replan_required = false;
        Ok(self.reviewed.as_ref().expect("reviewed package plan set"))
    }

    pub(super) fn confirm(&mut self) -> bool {
        if self.reviewed.is_none() || self.replan_required {
            return false;
        }
        self.confirmed = true;
        self.phase = WorkflowPhase::Confirmed;
        true
    }

    pub(super) fn cancel(&mut self) -> bool {
        if self.reviewed.is_none() && !self.confirmed {
            return false;
        }
        self.clear_review();
        self.last_error = None;
        true
    }

    pub(super) fn apply(
        &mut self,
        fresh_discovery: DiscoveryOutput,
        app_state_root: &Path,
        project_root: &Path,
        roots: &DiscoveryRoots,
        fixture_mode: bool,
    ) -> Result<&BulkToggleApplyResult, String> {
        if !self.confirmed {
            return Err("confirm the reviewed package plan before apply".to_string());
        }
        let reviewed = self
            .reviewed
            .clone()
            .ok_or_else(|| "review the package plan before apply".to_string())?;
        let logical_id = self
            .selected_package()
            .map(|package| package.logical_id.clone())
            .ok_or_else(|| "selected package disappeared; refresh and replan".to_string())?;
        let current = BulkToggleRequest::for_agent_plugin(
            &fresh_discovery,
            &logical_id,
            reviewed.target_enabled,
        )
        .map_err(safe_plan_error)?;
        if current.selector != reviewed.selector
            || current.selection_context_fingerprint != reviewed.selection_context_fingerprint
        {
            self.replan_required = true;
            return Err(
                "package projection changed after review; refresh and create a new plan"
                    .to_string(),
            );
        }
        let config = package_config(app_state_root, project_root, roots);
        let (controller, durable) =
            durable_context(app_state_root, roots, &config, &reviewed, fixture_mode)?;
        let expectation = reviewed
            .approval_expectation(&durable.approval_context, &durable.principal.session_id)
            .map_err(safe_plan_error)?;
        let digest = reviewed
            .plan_fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&reviewed.plan_fingerprint);
        let authorization = credentials::authorize_reviewed_control_decision(
            fixture_mode,
            app_state_root,
            &expectation,
            digest,
            Some(digest),
            "unpin-tui-agent-plugin-approval",
            unix_now(),
        )?;
        let result = controller
            .apply_with_reach_aware(&reviewed, authorization, durable, fresh_discovery)
            .map_err(safe_plan_error)?;
        let phase = phase_from_lifecycle(result.lifecycle);
        self.last_error = None;
        self.last_result = Some(result);
        self.clear_review();
        self.phase = phase;
        Ok(self.last_result.as_ref().expect("package apply result set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
    }

    fn selected_package(&self) -> Option<&AgentPluginSummary> {
        self.packages.get(self.selected)
    }

    fn selected_providers(&self) -> Vec<ProviderId> {
        self.selected_package()
            .map(|package| {
                let mut providers = package
                    .instances
                    .iter()
                    .map(|instance| instance.provider)
                    .collect::<Vec<_>>();
                providers.sort();
                providers.dedup();
                providers
            })
            .unwrap_or_default()
    }

    fn reset_for_selection(&mut self) {
        self.reach = PackageReach::Required;
        self.target_enabled = true;
        self.clear_review();
        self.last_result = None;
        self.last_error = None;
    }

    fn clear_review(&mut self) {
        self.reviewed = None;
        self.confirmed = false;
        self.phase = WorkflowPhase::Browsing;
        self.replan_required = false;
    }
}

pub(super) const fn state_label(state: AgentPluginState) -> &'static str {
    match state {
        AgentPluginState::On => "on",
        AgentPluginState::Off => "off",
        AgentPluginState::Mixed => "mixed",
        AgentPluginState::Unknown => "unknown",
    }
}

const fn access_label(access: AgentPluginAccess) -> &'static str {
    match access {
        AgentPluginAccess::Actionable => "actionable",
        AgentPluginAccess::DiagnosticsOnly => "diagnostics-only",
        AgentPluginAccess::Unsupported => "unsupported",
    }
}

fn phase_from_lifecycle(lifecycle: ProviderReachLifecycle) -> WorkflowPhase {
    match lifecycle {
        ProviderReachLifecycle::Applied | ProviderReachLifecycle::NoOp => WorkflowPhase::Applied,
        ProviderReachLifecycle::Partial => WorkflowPhase::Partial,
        ProviderReachLifecycle::RecoveryRequired => WorkflowPhase::RecoveryRequired,
        ProviderReachLifecycle::Blocked | ProviderReachLifecycle::NoTargetsInProviderReach => {
            WorkflowPhase::Blocked
        }
    }
}

pub(super) fn safe_plan_error(error: BulkTogglePlanError) -> String {
    match error {
        BulkTogglePlanError::AgentPluginInventoryIncomplete => {
            "Agent Plugin inventory is incomplete; refresh discovery before planning.".to_string()
        }
        BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors => {
            "A diagnostics-only package instance has writable native activation anchors; resolve diagnostics before planning.".to_string()
        }
        BulkTogglePlanError::AgentPluginHasNoActionableActivationAnchors => {
            "diagnostics-only package has no safe apply action; resolve component diagnostics and refresh"
                .to_string()
        }
        BulkTogglePlanError::AgentPluginHasNoActivationAnchors => {
            "diagnostics-only package has no native activation anchors; no apply action is available"
                .to_string()
        }
        BulkTogglePlanError::SelectionContextFingerprintMismatch
        | BulkTogglePlanError::PlanFingerprintMismatch => {
            "package projection changed after review; refresh and replan".to_string()
        }
        BulkTogglePlanError::AgentPluginNotFound => {
            "Agent Plugin package disappeared; refresh inventory and replan".to_string()
        }
        BulkTogglePlanError::NoTargetsInProviderReach => {
            "selected provider reach has no package activation anchors; choose another reach"
                .to_string()
        }
        _ => "package plan blocked; refresh inventory and review package diagnostics".to_string(),
    }
}

fn package_config(
    app_state_root: &Path,
    project_root: &Path,
    roots: &DiscoveryRoots,
) -> UnpinConfig {
    UnpinConfig {
        version: 1,
        app_state_root: app_state_root.to_path_buf(),
        cursor_root: roots.cursor_global.clone(),
        project_root: project_root.to_path_buf(),
        config_paths: UnpinConfigPaths {
            user_config_path: app_state_root.join("config.json"),
            project_config_path: project_root.join(".unpin.json"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_guidance_stays_visible_after_the_selected_package_disappears() {
        let mut workflow = AgentPluginWorkflow::new(&DiscoveryOutput::default());
        workflow.phase = WorkflowPhase::RecoveryRequired;

        assert!(
            workflow
                .details()
                .iter()
                .any(|line| line.starts_with("Recovery required: do not reapply."))
        );
    }
}
