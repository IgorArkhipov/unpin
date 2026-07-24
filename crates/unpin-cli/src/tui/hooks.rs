use std::path::Path;

use serde_json::json;
use unpin_core::{
    approval::ApprovalExpectation,
    control::SessionControlStatus,
    control_operation::{ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle},
    discovery::{DiscoveryItem, DiscoveryKind, DiscoveryOutput},
    hooks::HookTrustStore,
    state::atomic_json::OwnerGeneration,
    transitions::EffectActivation,
};

#[cfg(test)]
use unpin_core::profiles::ProfileStore;

use crate::{credentials, hook_support::require_profile_membership, unix_now};

use super::WorkflowPhase;

const APPROVAL_ISSUER: &str = "unpin-cli-human";
const APPROVAL_AUDIENCE: &str = "unpin-core-hook-trust";

#[derive(Debug, Clone)]
struct HookRow {
    item: DiscoveryItem,
    profile_digest: Option<String>,
    session_id: Option<String>,
    stored_trust: bool,
}

#[derive(Debug, Clone)]
struct ReviewedHookPlan {
    expectation: ApprovalExpectation,
    fingerprint: String,
    profile_digest: String,
    session_id: String,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone)]
pub(super) struct HookWorkflow {
    repository_key: String,
    workspace_key: String,
    rows: Vec<HookRow>,
    selected: usize,
    reviewed: Option<ReviewedHookPlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_error: Option<String>,
}

impl HookWorkflow {
    pub(super) fn new(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        discovery: &DiscoveryOutput,
        sessions: &[SessionControlStatus],
        app_state_root: &Path,
    ) -> Self {
        let repository_key = repository_key.into();
        let workspace_key = workspace_key.into();
        let trust = HookTrustStore::new(app_state_root);
        let rows = discovery
            .items
            .iter()
            .filter(|item| item.kind == DiscoveryKind::Hook)
            .map(|item| {
                let session = sessions.iter().find(|session| {
                    session.provider == item.provider && session.profile_digest.is_some()
                });
                let profile_digest = session.and_then(|session| session.profile_digest.clone());
                let session_id = session.map(|session| session.session_id.clone());
                let stored_trust = profile_digest
                    .as_deref()
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
                HookRow {
                    item: item.clone(),
                    profile_digest,
                    session_id,
                    stored_trust,
                }
            })
            .collect();
        Self {
            repository_key,
            workspace_key,
            rows,
            selected: 0,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    pub(super) fn empty() -> Self {
        Self {
            repository_key: "unavailable".to_string(),
            workspace_key: "unavailable".to_string(),
            rows: Vec::new(),
            selected: 0,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_error: None,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn phase(&self) -> WorkflowPhase {
        self.phase
    }

    pub(super) fn select_next(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1) % self.rows.len();
            self.reset_review();
        }
    }

    pub(super) fn select_previous(&mut self) {
        if !self.rows.is_empty() {
            self.selected = if self.selected == 0 {
                self.rows.len() - 1
            } else {
                self.selected - 1
            };
            self.reset_review();
        }
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                format!(
                    "{} {} {} trust={} profile={}",
                    if index == self.selected { ">" } else { " " },
                    row.item.provider.as_str(),
                    row.item.display_name,
                    row.stored_trust,
                    if row.profile_digest.is_some() {
                        "session"
                    } else {
                        "unbound"
                    }
                )
            })
            .collect()
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![format!(
            "Hooks: {} | phase={}",
            self.rows.len(),
            self.phase().label()
        )];
        if let Some(row) = self.rows.get(self.selected) {
            details.push(format!("selected: {}", row.item.id));
            details.push(format!("provider: {}", row.item.provider.as_str()));
            details.push(format!("stored trust: {}", row.stored_trust));
            details.push(format!(
                "profile binding: {}",
                row.profile_digest.as_deref().unwrap_or("none")
            ));
        } else {
            details.push("selected: none".to_string());
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!("plan: {}", reviewed.fingerprint));
            details.push("activation: next-session-only".to_string());
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

    pub(super) fn plan(
        &mut self,
        discovery: &DiscoveryOutput,
        app_state_root: &Path,
    ) -> Result<&ControlOperationEnvelope, String> {
        let row = self
            .rows
            .get(self.selected)
            .ok_or_else(|| "no hook selected".to_string())?;
        let metadata = row
            .item
            .hook
            .as_ref()
            .ok_or_else(|| "selected hook has no invocation metadata".to_string())?;
        let profile_digest = row
            .profile_digest
            .clone()
            .ok_or_else(|| "hook trust requires an active session profile binding".to_string())?;
        let session_id = row
            .session_id
            .clone()
            .ok_or_else(|| "hook trust requires an active session binding".to_string())?;
        require_profile_membership(app_state_root, discovery, &row.item, &profile_digest)?;
        let expectation = metadata
            .trust_approval_expectation(
                row.item.provider,
                &row.item.id,
                &profile_digest,
                APPROVAL_ISSUER,
                APPROVAL_AUDIENCE,
                &self.repository_key,
                &self.workspace_key,
                &session_id,
            )
            .map_err(|error| error.to_string())?;
        let fingerprint = expectation.effect_graph_digest.clone();
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &fingerprint,
            EffectActivation::NextSessionOnly,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply".to_string(),
                guidance: "Review executable or network hook invocation and profile binding."
                    .to_string(),
            }),
            false,
            vec![row.item.provider],
            json!({"hook": row.item, "storedTrustDecision": row.stored_trust}),
        );
        self.reviewed = Some(ReviewedHookPlan {
            expectation,
            fingerprint,
            profile_digest,
            session_id,
            envelope,
        });
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(&self.reviewed.as_ref().expect("reviewed plan set").envelope)
    }

    pub(super) fn confirm(&mut self) -> bool {
        if self.reviewed.is_none() {
            return false;
        }
        self.phase = WorkflowPhase::Confirmed;
        true
    }

    pub(super) fn apply(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        fixture_mode: bool,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("hook trust plan must be confirmed before apply".to_string());
        }
        unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [app_state_root, project_root],
        )?;
        let row = self
            .rows
            .get(self.selected)
            .ok_or_else(|| "selected hook disappeared".to_string())?;
        let metadata = row
            .item
            .hook
            .as_ref()
            .ok_or_else(|| "selected hook has no invocation metadata".to_string())?;
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "hook trust plan is missing".to_string())?;
        let now = unix_now();
        let approval = credentials::issue_human_approval(
            fixture_mode,
            &reviewed.expectation,
            &reviewed.fingerprint,
            Some(&reviewed.fingerprint),
            now,
        )?;
        let status = HookTrustStore::new(app_state_root)
            .record(
                row.item.provider,
                &row.item.id,
                metadata,
                &reviewed.profile_digest,
                approval.receipt(),
                approval.verifier(),
                now,
                OwnerGeneration::new("unpin-tui-hook-trust", 1)
                    .map_err(|error| error.to_string())?,
                APPROVAL_ISSUER,
                APPROVAL_AUDIENCE,
                &self.repository_key,
                &self.workspace_key,
                &reviewed.session_id,
            )
            .map_err(|error| error.to_string())?;
        self.last_envelope = Some(ControlOperationEnvelope::from_expectation(
            &reviewed.expectation,
            &reviewed.fingerprint,
            EffectActivation::NextSessionOnly,
            ControlOperationLifecycle::Applied,
            None,
            false,
            vec![row.item.provider],
            json!({"trust": status}),
        ));
        if let Some(row) = self.rows.get_mut(self.selected) {
            row.stored_trust = true;
        }
        self.phase = WorkflowPhase::Applied;
        self.last_error = None;
        Ok(self.last_envelope.as_ref().expect("result envelope set"))
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        self.phase = WorkflowPhase::Blocked;
    }

    fn reset_review(&mut self) {
        self.reviewed = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, path::PathBuf};
    use unpin_core::{
        catalog::Catalog,
        discovery::{DiscoveryRoots, discover_all},
        profiles::{
            PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope, compile_profile,
        },
        sessions::{CoverageLevel, IsolationLevel, LeaseLifecycle, LiveExposureStatus},
    };

    fn fixtures_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("unpin-core")
            .join("tests")
            .join("fixtures")
    }

    #[test]
    fn hook_workflow_plans_bound_profile_trust() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let discovery = discover_all(&DiscoveryRoots::fixture_root(fixtures_root())).unwrap();
        let hook = discovery
            .items
            .iter()
            .find(|item| item.kind == DiscoveryKind::Hook)
            .unwrap();
        let catalog = Catalog::from_discovery(&discovery).unwrap();
        let capability = catalog.find_provider_view(hook.provider, &hook.id).unwrap();
        let compiled = compile_profile(
            &ProfileDefinition {
                version: PROFILE_DEFINITION_VERSION,
                id: "hook-review".to_string(),
                display_name: "Hook review".to_string(),
                description: None,
                members: vec![capability.id.clone()],
                provider_members: BTreeMap::new(),
            },
            &catalog,
            ProfileSourceScope::Workspace,
        )
        .unwrap();
        ProfileStore::new(&root)
            .materialize_revision(
                &compiled,
                OwnerGeneration::new("hook-workflow-test", 1).unwrap(),
            )
            .unwrap();
        let sessions = vec![SessionControlStatus {
            session_id: "session-one".to_string(),
            provider: hook.provider,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            profile_digest: Some(compiled.digest),
            desired_exposure_revision: "a".repeat(64),
            observed_exposure_revision: "a".repeat(64),
            live_status: LiveExposureStatus::Configured,
            isolation: IsolationLevel::ConnectionScoped,
            coverage: CoverageLevel::VerifiedMasked,
            lifecycle: LeaseLifecycle::Active,
            in_flight_calls: 0,
        }];
        let mut workflow = HookWorkflow::new("repo", "worktree", &discovery, &sessions, &root);
        let envelope = workflow.plan(&discovery, &root).unwrap();

        assert_eq!(
            envelope.lifecycle,
            ControlOperationLifecycle::AwaitingHumanAction
        );
        assert_eq!(workflow.phase(), WorkflowPhase::Planned);
        assert!(workflow.confirm());
        let result = workflow
            .apply(&root, &root, true)
            .expect("fixture hook trust apply");
        assert_eq!(result.lifecycle, ControlOperationLifecycle::Applied);
        assert_eq!(workflow.phase(), WorkflowPhase::Applied);
    }
}
