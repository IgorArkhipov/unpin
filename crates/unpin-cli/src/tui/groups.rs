use std::{collections::BTreeSet, path::Path};

use serde_json::json;
use unpin_core::{
    approval::ControlApprovalContext,
    control_operation::{
        ControlHumanAction, ControlOperationEnvelope, ControlOperationLifecycle,
        ReachAwarePrincipal, ReachAwareRootBinding,
    },
    discovery::{DiscoveryItem, DiscoveryOutput},
    groups::{
        GROUP_APPROVAL_AUDIENCE, GROUP_DEFINITION_SCHEMA_VERSION, GroupAccessContext,
        GroupApplyResult, GroupApprovalArtifactStore, GroupApprovalChallengeClaims,
        GroupController, GroupDefinitionV1, GroupDefinitionView, GroupHistoryRecord,
        GroupMemberIdentity, GroupOperationLifecycle, GroupPlanDisposition, GroupPlanMode,
        GroupPlanner, GroupReachAwareApplyContext, GroupRecord, GroupRef, GroupResolver,
        GroupRevision, GroupScope, GroupTargetState, GroupTogglePlan, McpGroupSessionLeaseStore,
        PersonalGroupStore, RepositoryGroupStore, authenticate_group_approval_challenge,
        validate_new_group_members,
    },
    mutation::BackupAuthenticationKey,
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, ProviderReach, ProviderReachInput,
        ProviderReachRequest, SelectedProviderProvenance,
    },
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::OwnerGeneration,
    transitions::EffectActivation,
};

use crate::{credentials, group_store::ScopedGroupStore, unix_now};

use super::WorkflowPhase;

#[derive(Debug, Clone)]
struct ReviewedGroupPlan {
    plan: GroupTogglePlan,
    envelope: ControlOperationEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupScreen {
    Browse,
    Members,
    History,
    NameInput,
    ChallengeInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupTextInputKind {
    CreateName,
    Rename,
    McpChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupTextSubmission {
    DefinitionName,
    McpChallenge(String),
}

#[derive(Debug, Clone)]
struct GroupDraft {
    scope: GroupScope,
    definition: GroupDefinitionV1,
    expected_revision: Option<GroupRevision>,
    creating: bool,
}

#[derive(Debug, Clone)]
enum DefinitionAction {
    Create {
        scope: GroupScope,
        definition: GroupDefinitionV1,
    },
    Replace {
        scope: GroupScope,
        definition: GroupDefinitionV1,
        expected: GroupRevision,
    },
    Rename {
        scope: GroupScope,
        old_name: String,
        new_name: String,
        expected: GroupRevision,
        definition: GroupDefinitionV1,
    },
    Delete {
        scope: GroupScope,
        name: String,
        expected: GroupRevision,
        definition: GroupDefinitionV1,
    },
    Restore {
        scope: GroupScope,
        history_id: String,
        expected: Option<GroupRevision>,
        definition: GroupDefinitionV1,
    },
}

impl DefinitionAction {
    fn definition(&self) -> &GroupDefinitionV1 {
        match self {
            Self::Create { definition, .. }
            | Self::Replace { definition, .. }
            | Self::Rename { definition, .. }
            | Self::Delete { definition, .. }
            | Self::Restore { definition, .. } => definition,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Replace { .. } => "edit",
            Self::Rename { .. } => "rename",
            Self::Delete { .. } => "delete",
            Self::Restore { .. } => "restore",
        }
    }
}

#[derive(Debug, Clone)]
struct ReviewedDefinitionChange {
    action: DefinitionAction,
}

impl ReviewedDefinitionChange {
    fn definition(&self) -> &GroupDefinitionV1 {
        self.action.definition()
    }
}

#[derive(Debug, Clone)]
struct ReviewedMcpHandoff {
    challenge: String,
    claims: GroupApprovalChallengeClaims,
}

#[derive(Debug, Clone)]
pub(super) enum GroupApplyOutcome {
    Direct {
        envelope: Box<ControlOperationEnvelope>,
        lifecycle: GroupOperationLifecycle,
    },
    DefinitionChanged {
        message: String,
        created: bool,
    },
    McpApprovalIssued(McpApprovalHandoff),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct McpApprovalHandoff {
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub challenge: String,
    pub approval_artifact: String,
    pub expires_at_unix: i64,
}

impl McpApprovalHandoff {
    pub(super) fn export_value(&self) -> serde_json::Value {
        json!({
            "operationId": self.operation_id,
            "planFingerprint": self.plan_fingerprint,
            "challenge": self.challenge,
            "approvalArtifact": self.approval_artifact,
            "expiresAtUnix": self.expires_at_unix,
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct GroupWorkflow {
    resolver: Option<GroupResolver>,
    authenticated_definition_writes: bool,
    records: Vec<GroupRecord>,
    groups: Vec<GroupDefinitionView>,
    list_warnings: Vec<unpin_core::groups::GroupListWarning>,
    selected: usize,
    screen: GroupScreen,
    draft: Option<GroupDraft>,
    member_selected: usize,
    history: Vec<GroupHistoryRecord>,
    history_selected: usize,
    text_input_kind: Option<GroupTextInputKind>,
    text_input: String,
    pending_definition: Option<ReviewedDefinitionChange>,
    reviewed_mcp_handoff: Option<ReviewedMcpHandoff>,
    target: GroupTargetState,
    provider_reach: ProviderReach,
    reviewed: Option<ReviewedGroupPlan>,
    phase: WorkflowPhase,
    last_envelope: Option<ControlOperationEnvelope>,
    last_result: Option<GroupApplyResult>,
    last_error: Option<String>,
}

impl GroupWorkflow {
    pub(super) fn empty() -> Self {
        Self {
            resolver: None,
            authenticated_definition_writes: false,
            records: Vec::new(),
            groups: Vec::new(),
            list_warnings: Vec::new(),
            selected: 0,
            screen: GroupScreen::Browse,
            draft: None,
            member_selected: 0,
            history: Vec::new(),
            history_selected: 0,
            text_input_kind: None,
            text_input: String::new(),
            pending_definition: None,
            reviewed_mcp_handoff: None,
            target: GroupTargetState::Enable,
            provider_reach: ProviderReach::All,
            reviewed: None,
            phase: WorkflowPhase::Browsing,
            last_envelope: None,
            last_result: None,
            last_error: None,
        }
    }

    pub(super) fn new(
        access: GroupAccessContext,
        backup_key: Option<&BackupAuthenticationKey>,
        discovery: &DiscoveryOutput,
    ) -> Result<Self, String> {
        let mut workflow = Self::empty();
        let personal = backup_key.map_or_else(
            || PersonalGroupStore::new(access.clone()),
            |key| {
                PersonalGroupStore::new(access.clone()).with_history_authentication_key(key.clone())
            },
        );
        let repository = backup_key.map_or_else(
            || RepositoryGroupStore::new(access.clone()),
            |key| {
                RepositoryGroupStore::new(access.clone())
                    .with_history_authentication_key(key.clone())
            },
        );
        workflow.resolver = Some(GroupResolver::new(access, personal, repository));
        workflow.authenticated_definition_writes = backup_key.is_some();
        workflow.refresh(discovery)?;
        Ok(workflow)
    }

    pub(super) fn refresh(&mut self, discovery: &DiscoveryOutput) -> Result<(), String> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or_else(|| "inventory group context is unavailable".to_string())?;
        let listing = resolver
            .list_records_and_views_with_warnings(discovery)
            .map_err(|error| error.to_string())?;
        self.records = listing.records;
        self.groups = listing.views;
        self.list_warnings = listing.warnings;
        self.selected = self.selected.min(self.groups.len().saturating_sub(1));
        self.reviewed = None;
        self.pending_definition = None;
        self.reviewed_mcp_handoff = None;
        self.screen = GroupScreen::Browse;
        self.draft = None;
        self.history.clear();
        self.text_input_kind = None;
        self.text_input.clear();
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.groups.len()
    }

    pub(super) fn select_next(&mut self, visible_member_count: usize) {
        match self.screen {
            GroupScreen::Members if visible_member_count > 0 => {
                self.member_selected = (self.member_selected + 1) % visible_member_count;
            }
            GroupScreen::History if !self.history.is_empty() => {
                self.history_selected = (self.history_selected + 1) % self.history.len();
            }
            GroupScreen::Browse | GroupScreen::NameInput | GroupScreen::ChallengeInput
                if !self.groups.is_empty() =>
            {
                self.selected = (self.selected + 1) % self.groups.len();
                self.reset_review();
            }
            _ => {}
        }
    }

    pub(super) fn select_previous(&mut self, visible_member_count: usize) {
        match self.screen {
            GroupScreen::Members if visible_member_count > 0 => {
                self.member_selected = if self.member_selected == 0 {
                    visible_member_count - 1
                } else {
                    self.member_selected - 1
                };
            }
            GroupScreen::History if !self.history.is_empty() => {
                self.history_selected = if self.history_selected == 0 {
                    self.history.len() - 1
                } else {
                    self.history_selected - 1
                };
            }
            GroupScreen::Browse | GroupScreen::NameInput | GroupScreen::ChallengeInput
                if !self.groups.is_empty() =>
            {
                self.selected = if self.selected == 0 {
                    self.groups.len() - 1
                } else {
                    self.selected - 1
                };
                self.reset_review();
            }
            _ => {}
        }
    }

    pub(super) fn cycle_target(&mut self) {
        self.target = match self.target {
            GroupTargetState::Enable => GroupTargetState::Disable,
            GroupTargetState::Disable => GroupTargetState::Enable,
        };
        self.reset_review();
    }

    pub(super) fn cycle_provider_reach(&mut self) {
        self.provider_reach = match self.provider_reach {
            ProviderReach::All => {
                ProviderReach::selected(ProviderId::ALL[0], SelectedProviderProvenance::TuiControl)
            }
            ProviderReach::Selected { provider, .. } => ProviderId::ALL
                .iter()
                .position(|candidate| *candidate == provider)
                .and_then(|index| ProviderId::ALL.get(index + 1).copied())
                .map_or(ProviderReach::All, |provider| {
                    ProviderReach::selected(provider, SelectedProviderProvenance::TuiControl)
                }),
        };
        self.reset_review();
    }

    pub(super) fn rows(&self, visible_members: &[&DiscoveryItem]) -> Vec<String> {
        if self.screen == GroupScreen::Members {
            let selected_members = self
                .draft
                .as_ref()
                .map(|draft| draft.definition.members.iter().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            return visible_members
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let identity = GroupMemberIdentity::try_from(*item).ok();
                    let label = format!(
                        "{} | {} | {} | {}",
                        provider_display_name(item.provider),
                        item.layer.as_str(),
                        item.kind.as_str(),
                        item.display_name,
                    );
                    format!(
                        "{} [{}] {label}",
                        if index == self.member_selected {
                            ">"
                        } else {
                            " "
                        },
                        if identity
                            .as_ref()
                            .is_some_and(|identity| selected_members.contains(identity))
                        {
                            "x"
                        } else {
                            " "
                        },
                    )
                })
                .collect();
        }
        if self.screen == GroupScreen::History {
            return self
                .history
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    format!(
                        "{} {} {:?} {} -> {}",
                        if index == self.history_selected {
                            ">"
                        } else {
                            " "
                        },
                        entry.created_at,
                        entry.change,
                        entry.name_before.as_deref().unwrap_or("-"),
                        entry.name_after.as_deref().unwrap_or("-"),
                    )
                })
                .collect();
        }
        self.groups
            .iter()
            .enumerate()
            .map(|(index, group)| {
                format!(
                    "{} {} [{:?}] members={} on={} off={} blocked={} missing={}",
                    if index == self.selected { ">" } else { " " },
                    group.qualified_name,
                    group.observed_state(),
                    group.members.len(),
                    group.counts.enabled,
                    group.counts.disabled,
                    group.counts.blocked,
                    group.counts.missing + group.counts.ambiguous,
                )
            })
            .collect()
    }

    pub(super) fn uses_inventory_rows(&self) -> bool {
        self.screen == GroupScreen::Members
    }

    pub(super) fn details(&self) -> Vec<String> {
        let mut details = vec![format!(
            "Groups: {} | target={} | reach={:?} | phase={} | screen={:?}",
            self.groups.len(),
            target_label(self.target),
            self.provider_reach,
            self.phase.label(),
            self.screen,
        )];
        details.extend(
            self.list_warnings
                .iter()
                .map(|warning| format!("warning: {}: {}", warning.code, warning.message)),
        );
        if let Some(kind) = self.text_input_kind {
            details.push(format!(
                "input {:?}: {}",
                kind,
                if kind == GroupTextInputKind::McpChallenge {
                    format!("<opaque challenge: {} bytes>", self.text_input.len())
                } else {
                    self.text_input.clone()
                }
            ));
            details.push("Enter submits this value; Esc cancels without writing.".to_string());
        }
        if let Some(draft) = &self.draft {
            details.push(format!(
                "draft: {}:{} members={} expectedRevision={}",
                draft.scope,
                draft.definition.name,
                draft.definition.members.len(),
                draft
                    .expected_revision
                    .as_ref()
                    .map_or("none", GroupRevision::as_str),
            ));
            details.push(
                "Use current inventory filters/search, ↑/↓ to move, Space to select, w to preview."
                    .to_string(),
            );
        }
        if let Some(review) = &self.pending_definition {
            details.push(format!(
                "definition review: {} {}:{} members={} revision-bound=true",
                review.action.label(),
                definition_scope(&review.action),
                review.definition().name,
                review.definition().members.len(),
            ));
            details.push(
                "Enter confirms the exact definition change; a applies it with authenticated history."
                    .to_string(),
            );
        }
        if let Some(review) = &self.reviewed_mcp_handoff {
            details.push(format!(
                "MCP approval review: operation={} fingerprint={} members={} expires={}",
                review
                    .claims
                    .plan
                    .operation_id
                    .as_deref()
                    .unwrap_or("missing"),
                review.claims.plan.plan_fingerprint,
                review.claims.plan.total_members,
                review.claims.expires_at_unix,
            ));
            for member in &review.claims.plan.members {
                details.push(format!(
                    "MCP effect: {} outcome={:?} reason={}",
                    group_member_label(&member.identity),
                    member.outcome,
                    member.reason.as_deref().unwrap_or("none"),
                ));
            }
            details.push(
                "This issues a one-use MCP approval artifact only; it does not apply the group."
                    .to_string(),
            );
        }
        if self.screen == GroupScreen::History {
            details.push(
                "History is authenticated. Select an entry and press r to preview restore."
                    .to_string(),
            );
        }
        if let Some(group) = self.groups.get(self.selected) {
            details.push(format!(
                "selected: {} | scope={:?} | revision={:?}",
                group.qualified_name, group.scope, group.revision
            ));
            details.push(format!(
                "state={:?} fresh={} compatible={} providers={}",
                group.observed_state(),
                group.observation_is_fresh(),
                group.context_compatible,
                group
                    .provider_coverage
                    .iter()
                    .map(|provider| provider.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
            for member in &group.members {
                details.push(format!(
                    "{} enabled={:?} eligible={} reason={:?}",
                    group_member_label(&member.identity),
                    member.enabled,
                    member.eligible,
                    member.reason,
                ));
            }
        } else {
            details.push("selected: none".to_string());
            details.push("Press n to create a group from staged inventory members.".to_string());
        }
        if let Some(reviewed) = &self.reviewed {
            details.push(format!(
                "review: {} reach={:?} members={} cohorts={} resources={} fingerprint={}",
                disposition_label(reviewed.plan.disposition),
                reviewed.plan.provider_reach,
                reviewed.plan.total_members,
                reviewed.plan.cohorts.len(),
                reviewed.plan.resources.len(),
                reviewed.plan.plan_fingerprint,
            ));
            for coverage in &reviewed.plan.provider_coverage.entries {
                details.push(format!(
                    "coverage: {} included={} reason={}",
                    coverage_target_label(coverage.provider, &coverage.target_id),
                    coverage.included,
                    coverage.reason.map_or("none", |reason| reason.as_str()),
                ));
            }
            for member in &reviewed.plan.members {
                details.push(format!(
                    "effect: {} outcome={:?} reason={}",
                    group_member_label(&member.identity),
                    member.outcome,
                    member.reason.as_deref().unwrap_or("none"),
                ));
            }
        }
        if let Some(result) = &self.last_result {
            details.push(format!(
                "result: {:?} final={:?} observationFresh={} operation={}",
                result.lifecycle, result.final_state, result.observation_fresh, result.operation_id,
            ));
            if let Some(reason) = &result.observation_reason {
                details.push(format!("observation: {reason}"));
            }
            for member in &result.members {
                details.push(format!(
                    "member result: {} status={:?} cohort={} failure={} backup={} reason={}",
                    group_member_label(&member.identity),
                    member.status,
                    member.cohort_id.as_deref().unwrap_or("none"),
                    member
                        .failure_mode
                        .as_ref()
                        .map_or_else(|| "none".to_string(), |failure| format!("{failure:?}")),
                    member.backup_id.as_deref().unwrap_or("none"),
                    member.reason.as_deref().unwrap_or("none"),
                ));
            }
            if !result.backup_ids.is_empty() {
                details.push(format!("recovery backups: {}", result.backup_ids.join(","),));
            }
            if matches!(
                result.lifecycle,
                GroupOperationLifecycle::Partial | GroupOperationLifecycle::RecoveryRequired
            ) {
                details.push(format!(
                    "recovery: inspect `unpin group operation-show {} --json` before retrying or restoring",
                    result.operation_id
                ));
            }
        }
        if let Some(error) = &self.last_error {
            details.push(format!("error: {error}"));
        }
        details.push(
            "Group keys: n create | e edit | R rename | d delete | h history | r restore | o approve-MCP | w preview-save"
                .to_string(),
        );
        details
    }

    pub(super) fn is_member_editor(&self) -> bool {
        self.screen == GroupScreen::Members
    }

    pub(super) fn member_selected_index(&self) -> usize {
        self.member_selected
    }

    pub(super) fn clamp_member_selection(&mut self, visible_member_count: usize) {
        self.member_selected = if visible_member_count == 0 {
            0
        } else {
            self.member_selected.min(visible_member_count - 1)
        };
    }

    pub(super) fn is_text_input(&self) -> bool {
        matches!(
            self.screen,
            GroupScreen::NameInput | GroupScreen::ChallengeInput
        )
    }

    pub(super) fn start_create(&mut self, members: Vec<GroupMemberIdentity>) -> Result<(), String> {
        if members.is_empty() {
            return Err("stage at least one inventory item before creating a group".to_string());
        }
        let members = members.into_iter().collect::<BTreeSet<_>>();
        self.draft = Some(GroupDraft {
            scope: GroupScope::Personal,
            definition: GroupDefinitionV1 {
                schema_version: GROUP_DEFINITION_SCHEMA_VERSION,
                name: String::new(),
                members: members.into_iter().collect(),
            },
            expected_revision: None,
            creating: true,
        });
        self.start_text_input(GroupTextInputKind::CreateName);
        Ok(())
    }

    pub(super) fn start_edit(&mut self) -> Result<(), String> {
        let record = self.selected_record()?.clone();
        self.draft = Some(GroupDraft {
            scope: record.scope,
            definition: record.definition,
            expected_revision: Some(record.revision),
            creating: false,
        });
        self.screen = GroupScreen::Members;
        self.member_selected = 0;
        self.reset_review();
        Ok(())
    }

    pub(super) fn start_rename(&mut self) -> Result<(), String> {
        self.selected_record()?;
        self.start_text_input(GroupTextInputKind::Rename);
        Ok(())
    }

    pub(super) fn start_delete(&mut self) -> Result<(), String> {
        let record = self.selected_record()?.clone();
        self.pending_definition = Some(ReviewedDefinitionChange {
            action: DefinitionAction::Delete {
                scope: record.scope,
                name: record.definition.name.clone(),
                expected: record.revision,
                definition: record.definition,
            },
        });
        self.screen = GroupScreen::Browse;
        self.phase = WorkflowPhase::Planned;
        self.reviewed = None;
        self.reviewed_mcp_handoff = None;
        self.last_error = None;
        Ok(())
    }

    pub(super) fn show_history(&mut self) -> Result<(), String> {
        let record = self.selected_record()?.clone();
        let history = self.store(record.scope)?.history()?;
        let mut history = history_for_group_name(history, record.scope, &record.definition.name);
        history.reverse();
        self.history = history;
        self.history_selected = 0;
        self.screen = GroupScreen::History;
        self.reset_review();
        Ok(())
    }

    pub(super) fn stage_history_restore(&mut self) -> Result<(), String> {
        if self.screen != GroupScreen::History {
            return Err("open group history before selecting a restore point".to_string());
        }
        let history = self
            .history
            .get(self.history_selected)
            .cloned()
            .ok_or_else(|| "no restorable group history entry selected".to_string())?;
        let definition = history
            .definition_before
            .clone()
            .ok_or_else(|| "selected history entry has no prior definition".to_string())?;
        let current_name = history
            .definition_after
            .as_ref()
            .map_or(definition.name.as_str(), |current| current.name.as_str());
        let expected = self
            .records
            .iter()
            .find(|record| record.scope == history.scope && record.definition.name == current_name)
            .map(|record| record.revision.clone());
        self.pending_definition = Some(ReviewedDefinitionChange {
            action: DefinitionAction::Restore {
                scope: history.scope,
                history_id: history.history_id,
                expected,
                definition,
            },
        });
        self.screen = GroupScreen::Browse;
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(())
    }

    pub(super) fn start_mcp_approval(&mut self) {
        self.start_text_input(GroupTextInputKind::McpChallenge);
    }

    pub(super) fn push_text_char(&mut self, character: char) {
        let mut encoded = [0_u8; 4];
        self.push_text(character.encode_utf8(&mut encoded));
    }

    pub(super) fn push_text(&mut self, text: &str) {
        let maximum = if self.text_input_kind == Some(GroupTextInputKind::McpChallenge) {
            unpin_core::groups::MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES
        } else {
            256
        };
        for character in text.chars().filter(|character| !character.is_control()) {
            let next_length = self.text_input.len() + character.len_utf8();
            if next_length > maximum {
                break;
            }
            self.text_input.push(character);
        }
    }

    pub(super) fn pop_text_char(&mut self) {
        self.text_input.pop();
    }

    pub(super) fn finish_text_input(&mut self) -> Result<GroupTextSubmission, String> {
        let kind = self
            .text_input_kind
            .as_ref()
            .copied()
            .ok_or_else(|| "group text input is not active".to_string())?;
        let value = self.text_input.clone();
        match kind {
            GroupTextInputKind::CreateName => {
                let draft = self
                    .draft
                    .as_mut()
                    .ok_or_else(|| "group create draft is missing".to_string())?;
                draft.definition.name = value;
                draft
                    .definition
                    .canonicalize_and_validate()
                    .map_err(|error| error.to_string())?;
                self.text_input_kind = None;
                self.text_input.clear();
                self.screen = GroupScreen::Members;
                self.member_selected = 0;
                Ok(GroupTextSubmission::DefinitionName)
            }
            GroupTextInputKind::Rename => {
                let record = self.selected_record()?.clone();
                let mut definition = record.definition.clone();
                definition.name = value;
                definition
                    .canonicalize_and_validate()
                    .map_err(|error| error.to_string())?;
                self.pending_definition = Some(ReviewedDefinitionChange {
                    action: DefinitionAction::Rename {
                        scope: record.scope,
                        old_name: record.definition.name,
                        new_name: definition.name.clone(),
                        expected: record.revision,
                        definition,
                    },
                });
                self.text_input_kind = None;
                self.text_input.clear();
                self.screen = GroupScreen::Browse;
                self.phase = WorkflowPhase::Planned;
                self.reviewed = None;
                self.last_error = None;
                Ok(GroupTextSubmission::DefinitionName)
            }
            GroupTextInputKind::McpChallenge => {
                if value.is_empty() {
                    return Err("MCP approval challenge cannot be empty".to_string());
                }
                self.text_input_kind = None;
                self.text_input.clear();
                self.screen = GroupScreen::Browse;
                Ok(GroupTextSubmission::McpChallenge(value))
            }
        }
    }

    pub(super) fn cancel_interaction(&mut self) -> bool {
        if self.screen == GroupScreen::Browse
            && self.pending_definition.is_none()
            && self.reviewed_mcp_handoff.is_none()
            && self.reviewed.is_none()
            && self.phase == WorkflowPhase::Browsing
        {
            return false;
        }
        self.screen = GroupScreen::Browse;
        self.draft = None;
        self.history.clear();
        self.text_input_kind = None;
        self.text_input.clear();
        self.pending_definition = None;
        self.reviewed_mcp_handoff = None;
        self.reset_review();
        true
    }

    pub(super) fn cycle_draft_scope(&mut self) {
        if let Some(draft) = self.draft.as_mut()
            && draft.creating
        {
            draft.scope = match draft.scope {
                GroupScope::Personal => GroupScope::Repository,
                GroupScope::Repository => GroupScope::Personal,
            };
            self.pending_definition = None;
            self.phase = WorkflowPhase::Browsing;
        }
    }

    pub(super) fn can_cycle_draft_scope(&self) -> bool {
        self.draft.as_ref().is_some_and(|draft| draft.creating)
    }

    pub(super) fn toggle_member(&mut self, item: &DiscoveryItem) -> Result<(), String> {
        if self.screen != GroupScreen::Members {
            return Err("open a group member editor before selecting members".to_string());
        }
        let identity = GroupMemberIdentity::try_from(item).map_err(|error| error.to_string())?;
        let draft = self
            .draft
            .as_mut()
            .ok_or_else(|| "group definition draft is missing".to_string())?;
        if let Some(index) = draft
            .definition
            .members
            .iter()
            .position(|member| member == &identity)
        {
            draft.definition.members.remove(index);
        } else {
            draft.definition.members.push(identity);
            draft.definition.members.sort();
        }
        self.pending_definition = None;
        self.phase = WorkflowPhase::Browsing;
        Ok(())
    }

    pub(super) fn stage_definition_save(&mut self) -> Result<(), String> {
        if self.screen != GroupScreen::Members {
            return Err("open a group member editor before previewing a save".to_string());
        }
        let draft = self
            .draft
            .as_ref()
            .ok_or_else(|| "group definition draft is missing".to_string())?;
        let mut definition = draft.definition.clone();
        definition
            .canonicalize_and_validate()
            .map_err(|error| error.to_string())?;
        let retained = if draft.creating {
            BTreeSet::new()
        } else {
            self.records
                .iter()
                .find(|record| {
                    record.scope == draft.scope && record.definition.name == definition.name
                })
                .map(|record| record.definition.members.iter().cloned().collect())
                .unwrap_or_default()
        };
        let context = self
            .resolver
            .as_ref()
            .ok_or_else(|| "inventory group context is unavailable".to_string())?
            .context();
        validate_new_group_members(context, &definition, &retained)
            .map_err(|error| error.to_string())?;
        let action = if draft.creating {
            DefinitionAction::Create {
                scope: draft.scope,
                definition,
            }
        } else {
            DefinitionAction::Replace {
                scope: draft.scope,
                definition,
                expected: draft
                    .expected_revision
                    .clone()
                    .ok_or_else(|| "group edit revision is missing".to_string())?,
            }
        };
        self.pending_definition = Some(ReviewedDefinitionChange { action });
        self.phase = WorkflowPhase::Planned;
        self.reviewed = None;
        self.reviewed_mcp_handoff = None;
        self.last_error = None;
        Ok(())
    }

    pub(super) fn review_mcp_challenge(
        &mut self,
        challenge: String,
        app_state_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<(), String> {
        let claims = authenticate_group_approval_challenge(&challenge, authority_key)
            .map_err(|error| error.to_string())?;
        if claims.session.binding.repository_key != context.repository_key()
            || claims.session.binding.workspace_key != context.workspace_key()
        {
            return Err(
                "inventory group approval context does not match this workspace".to_string(),
            );
        }
        let lease_expires_at = McpGroupSessionLeaseStore::new(app_state_root)
            .verify(&claims.session, authority_key, now_unix)
            .map_err(|error| error.to_string())?;
        claims
            .verify(&claims.session, lease_expires_at, now_unix)
            .map_err(|error| error.to_string())?;
        claims
            .plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        self.reviewed_mcp_handoff = Some(ReviewedMcpHandoff { challenge, claims });
        self.pending_definition = None;
        self.reviewed = None;
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(())
    }

    pub(super) fn plan(
        &mut self,
        context: &ControlApprovalContext,
    ) -> Result<&ControlOperationEnvelope, String> {
        if self.screen != GroupScreen::Browse
            || self.pending_definition.is_some()
            || self.reviewed_mcp_handoff.is_some()
        {
            return Err(
                "finish or cancel the active group definition/MCP approval workflow first"
                    .to_string(),
            );
        }
        let group = self
            .groups
            .get(self.selected)
            .ok_or_else(|| "no inventory group selected".to_string())?;
        let resolver = self
            .resolver
            .clone()
            .ok_or_else(|| "inventory group context is unavailable".to_string())?;
        let reference =
            GroupRef::parse(&group.qualified_name).map_err(|error| error.to_string())?;
        let reach = match self.provider_reach {
            ProviderReach::All => ProviderReachInput::All,
            ProviderReach::Selected {
                provider,
                provenance,
            } => ProviderReachInput::selected(provider, provenance),
        };
        let plan = GroupPlanner::new(resolver)
            .plan_with_provider_reach_request(
                &reference,
                self.target,
                group.members.len().max(1),
                GroupPlanMode::LocalInteractive,
                ProviderReachRequest::new(ConnectionBoundary::All, reach, DerivedTargetKind::Group),
            )
            .map_err(|error| error.to_string())?;
        if plan.disposition != GroupPlanDisposition::Actionable {
            self.reviewed = None;
            self.phase = if plan.disposition == GroupPlanDisposition::Blocked {
                WorkflowPhase::Blocked
            } else {
                WorkflowPhase::Browsing
            };
            self.last_error = Some(format!(
                "group plan is {}; approval is not required",
                disposition_label(plan.disposition)
            ));
            return Err(self.last_error.clone().expect("group plan message set"));
        }
        let expectation = plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let activation = plan
            .resources
            .iter()
            .fold(EffectActivation::Live, |activation, resource| {
                activation.max(resource.activation)
            });
        let providers = plan
            .provider_coverage
            .included()
            .map(|entry| entry.provider)
            .collect();
        let envelope = ControlOperationEnvelope::from_expectation(
            &expectation,
            &plan.plan_fingerprint,
            activation,
            ControlOperationLifecycle::AwaitingHumanAction,
            Some(ControlHumanAction {
                code: "confirm-and-apply-group".to_string(),
                guidance:
                    "Review every member outcome, connected cohort, resource, and exact fingerprint."
                        .to_string(),
            }),
            false,
            providers,
            json!({"plan": plan}),
        );
        self.reviewed = Some(ReviewedGroupPlan { plan, envelope });
        self.phase = WorkflowPhase::Planned;
        self.last_error = None;
        Ok(&self.reviewed.as_ref().expect("reviewed group set").envelope)
    }

    pub(super) fn confirm(&mut self) -> bool {
        if self.reviewed.is_none()
            && self.pending_definition.is_none()
            && self.reviewed_mcp_handoff.is_none()
        {
            return false;
        }
        self.phase = WorkflowPhase::Confirmed;
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_active(
        &mut self,
        app_state_root: &Path,
        project_root: &Path,
        context: &ControlApprovalContext,
        authority_key: &SessionAuthorityKey,
        backup_key: Option<&BackupAuthenticationKey>,
        fixture_mode: bool,
    ) -> Result<GroupApplyOutcome, String> {
        if self.phase != WorkflowPhase::Confirmed {
            return Err("inventory group plan must be confirmed before apply".to_string());
        }
        unpin_core::fixture::require_fixture_write_sandbox(
            fixture_mode,
            [app_state_root, project_root],
        )?;
        if let Some(review) = self.pending_definition.clone() {
            if !self.authenticated_definition_writes {
                return Err(
                    "backup authentication key missing; run `unpin auth backup init`".to_string(),
                );
            }
            let created = matches!(review.action, DefinitionAction::Create { .. });
            let message = self.apply_definition_change(&review.action)?;
            self.pending_definition = None;
            self.draft = None;
            self.screen = GroupScreen::Browse;
            self.phase = WorkflowPhase::Applied;
            self.last_error = None;
            return Ok(GroupApplyOutcome::DefinitionChanged { message, created });
        }
        if let Some(review) = self.reviewed_mcp_handoff.clone() {
            let now_unix = unix_now();
            let lease_expires_at = McpGroupSessionLeaseStore::new(app_state_root)
                .verify(&review.claims.session, authority_key, now_unix)
                .map_err(|error| error.to_string())?;
            review
                .claims
                .verify(&review.claims.session, lease_expires_at, now_unix)
                .map_err(|error| error.to_string())?;
            let expectation = review
                .claims
                .plan
                .approval_expectation(context)
                .map_err(|error| error.to_string())?;
            let approval = credentials::issue_inventory_group_approval(
                fixture_mode,
                app_state_root,
                &expectation,
                &review.claims.plan,
                now_unix,
            )?;
            let artifact = GroupApprovalArtifactStore::new(app_state_root)
                .issue(
                    review.claims.session,
                    &review.claims.plan,
                    &review.challenge,
                    approval.receipt().clone(),
                    authority_key,
                    now_unix,
                )
                .map_err(|error| error.to_string())?;
            self.reviewed_mcp_handoff = None;
            self.phase = WorkflowPhase::Applied;
            self.last_error = None;
            return Ok(GroupApplyOutcome::McpApprovalIssued(McpApprovalHandoff {
                operation_id: artifact.operation_id,
                plan_fingerprint: artifact.plan_fingerprint,
                challenge: review.challenge,
                approval_artifact: artifact.artifact_id,
                expires_at_unix: artifact.expires_at_unix,
            }));
        }
        let backup_key = backup_key.ok_or_else(|| {
            "backup authentication key missing; run `unpin auth backup init`".to_string()
        })?;
        let reviewed = self
            .reviewed
            .as_ref()
            .ok_or_else(|| "inventory group plan is missing".to_string())?;
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
            "unpin-tui-inventory-group-approval",
            unix_now(),
        )?;
        let resolver = self
            .resolver
            .clone()
            .ok_or_else(|| "inventory group context is unavailable".to_string())?;
        let controller = GroupController::new(
            GroupPlanner::new(resolver),
            backup_key.clone(),
            authority_key.clone(),
        );
        let result = if reviewed.plan.schema_version
            >= unpin_core::groups::GROUP_PLAN_SCHEMA_VERSION
        {
            let session_id = reviewed
                .plan
                .operation_id
                .clone()
                .ok_or_else(|| "reach-aware group operation id is missing".to_string())?;
            let provider_roots = reviewed
                .plan
                .provider_coverage
                .included()
                .map(|entry| entry.provider)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|provider| {
                    (
                        provider,
                        group_provider_root(
                            self.resolver
                                .as_ref()
                                .expect("group resolver available")
                                .context()
                                .discovery_roots(),
                            provider,
                        )
                        .to_path_buf(),
                        "tui-discovery-root".to_string(),
                    )
                })
                .collect();
            let roots = ReachAwareRootBinding::from_provider_paths(
                app_state_root,
                provider_roots,
                "unpin-tui-inventory-group",
            )
            .map_err(|error| error.to_string())?;
            let scope_digest = group_reach_scope_digest(&expectation, &session_id);
            let boundary = match reviewed.plan.provider_reach {
                ProviderReach::Selected {
                    provider,
                    provenance:
                        unpin_core::provider_reach::SelectedProviderProvenance::PinnedMcpBoundary,
                } => ConnectionBoundary::Pinned(provider),
                ProviderReach::All | ProviderReach::Selected { .. } => ConnectionBoundary::All,
            };
            let principal =
                ReachAwarePrincipal::sign(session_id, scope_digest, boundary, authority_key)
                    .map_err(|error| error.to_string())?;
            let now_unix = unix_now();
            let durable = GroupReachAwareApplyContext {
                roots,
                principal,
                audience: GROUP_APPROVAL_AUDIENCE.to_string(),
                issued_at_unix: now_unix,
                expires_at_unix: now_unix + 3600,
                now_unix,
            };
            controller.apply_with_reach_aware(&reviewed.plan, authorization, durable)
        } else {
            // Keep the schema-v1 adapter available only for genuinely legacy
            // plans; all current group plans carry the reach-aware contract.
            controller.apply(&reviewed.plan, authorization)
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                let provider_writes_started = reviewed
                    .plan
                    .operation_id
                    .as_deref()
                    .and_then(|operation_id| controller.operation(operation_id).ok().flatten())
                    .is_some_and(|operation| operation.provider_writes_started);
                if provider_writes_started {
                    self.phase = WorkflowPhase::RecoveryRequired;
                    return Err(format!(
                        "recovery-required: provider writes may have started; inspect the durable operation and backup evidence ({error})"
                    ));
                }
                return Err(error.to_string());
            }
        };
        let group_lifecycle = result.lifecycle;
        let (phase, _lifecycle, last_error) = group_lifecycle_presentation(group_lifecycle)?;
        self.phase = phase;
        let providers = reviewed
            .plan
            .definition_view
            .provider_coverage
            .iter()
            .copied()
            .collect();
        self.last_envelope = Some(
            result
                .control_operation_envelope(
                    &expectation,
                    reviewed
                        .plan
                        .resources
                        .first()
                        .map_or(EffectActivation::Live, |resource| resource.activation),
                    providers,
                )
                .map_err(|error| error.to_string())?,
        );
        self.last_result = Some(result);
        self.last_error = last_error.map(str::to_string);
        Ok(GroupApplyOutcome::Direct {
            envelope: Box::new(
                self.last_envelope
                    .as_ref()
                    .expect("group result envelope set")
                    .clone(),
            ),
            lifecycle: group_lifecycle,
        })
    }

    pub(super) fn record_error(&mut self, error: String) {
        self.last_error = Some(error);
        if self.phase != WorkflowPhase::RecoveryRequired {
            self.phase = WorkflowPhase::Blocked;
        }
    }

    fn reset_review(&mut self) {
        self.reviewed = None;
        self.pending_definition = None;
        self.reviewed_mcp_handoff = None;
        self.phase = WorkflowPhase::Browsing;
        self.last_error = None;
    }

    fn start_text_input(&mut self, kind: GroupTextInputKind) {
        self.text_input_kind = Some(kind);
        self.text_input.clear();
        self.screen = if kind == GroupTextInputKind::McpChallenge {
            GroupScreen::ChallengeInput
        } else {
            GroupScreen::NameInput
        };
        self.reset_review();
    }

    fn selected_record(&self) -> Result<&GroupRecord, String> {
        self.records
            .get(self.selected)
            .ok_or_else(|| "no inventory group selected".to_string())
    }

    fn store(&self, scope: GroupScope) -> Result<ScopedGroupStore, String> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or_else(|| "inventory group context is unavailable".to_string())?;
        match scope {
            GroupScope::Personal => Ok(ScopedGroupStore::Personal(
                resolver.personal_store().clone(),
            )),
            GroupScope::Repository => Ok(ScopedGroupStore::Repository(
                resolver.repository_store().clone(),
            )),
        }
    }

    fn apply_definition_change(&self, action: &DefinitionAction) -> Result<String, String> {
        let owner = OwnerGeneration::new(unpin_core::groups::GROUP_DEFINITION_OWNER_ID, 1)
            .expect("static TUI owner is valid");
        match action {
            DefinitionAction::Create { scope, definition } => {
                self.store(*scope)?.create(definition, owner)?;
            }
            DefinitionAction::Replace {
                scope,
                definition,
                expected,
            } => {
                self.store(*scope)?
                    .replace(definition, Some(expected), owner)?;
            }
            DefinitionAction::Rename {
                scope,
                old_name,
                new_name,
                expected,
                ..
            } => {
                self.store(*scope)?
                    .rename(old_name, new_name, expected, owner)?;
            }
            DefinitionAction::Delete {
                scope,
                name,
                expected,
                ..
            } => {
                self.store(*scope)?.delete(name, expected, owner)?;
            }
            DefinitionAction::Restore {
                scope,
                history_id,
                expected,
                ..
            } => {
                self.store(*scope)?
                    .restore(history_id, expected.as_ref(), owner)?;
            }
        }
        Ok(format!(
            "{} {}:{}",
            action.label(),
            definition_scope(action),
            action.definition().name,
        ))
    }
}

fn group_lifecycle_presentation(
    lifecycle: GroupOperationLifecycle,
) -> Result<
    (
        WorkflowPhase,
        ControlOperationLifecycle,
        Option<&'static str>,
    ),
    String,
> {
    match lifecycle {
        GroupOperationLifecycle::Completed => Ok((
            WorkflowPhase::Applied,
            ControlOperationLifecycle::Applied,
            None,
        )),
        GroupOperationLifecycle::Partial => Ok((
            WorkflowPhase::Partial,
            ControlOperationLifecycle::Blocked,
            Some(
                "inventory group operation completed partially; review member results and backup evidence",
            ),
        )),
        GroupOperationLifecycle::Failed => Ok((
            WorkflowPhase::Blocked,
            ControlOperationLifecycle::Blocked,
            Some("inventory group operation failed; review member results"),
        )),
        GroupOperationLifecycle::RecoveryRequired => Ok((
            WorkflowPhase::RecoveryRequired,
            ControlOperationLifecycle::RecoveryRequired,
            Some("inventory group operation requires authenticated recovery before retrying"),
        )),
        GroupOperationLifecycle::InProgress => {
            Err("inventory group operation did not reach a terminal state".to_string())
        }
    }
}

fn history_for_group_name(
    history: Vec<GroupHistoryRecord>,
    scope: GroupScope,
    current_name: &str,
) -> Vec<GroupHistoryRecord> {
    let mut names = BTreeSet::from([current_name.to_string()]);
    loop {
        let before = names.len();
        for entry in history.iter().filter(|entry| entry.scope == scope) {
            if entry
                .name_before
                .as_ref()
                .is_some_and(|name| names.contains(name))
                || entry
                    .name_after
                    .as_ref()
                    .is_some_and(|name| names.contains(name))
            {
                names.extend(entry.name_before.iter().cloned());
                names.extend(entry.name_after.iter().cloned());
            }
        }
        if names.len() == before {
            break;
        }
    }
    history
        .into_iter()
        .filter(|entry| {
            entry.scope == scope
                && (entry
                    .name_before
                    .as_ref()
                    .is_some_and(|name| names.contains(name))
                    || entry
                        .name_after
                        .as_ref()
                        .is_some_and(|name| names.contains(name)))
        })
        .collect()
}

fn definition_scope(action: &DefinitionAction) -> GroupScope {
    match action {
        DefinitionAction::Create { scope, .. }
        | DefinitionAction::Replace { scope, .. }
        | DefinitionAction::Rename { scope, .. }
        | DefinitionAction::Delete { scope, .. }
        | DefinitionAction::Restore { scope, .. } => *scope,
    }
}

fn target_label(target: GroupTargetState) -> &'static str {
    match target {
        GroupTargetState::Enable => "enable",
        GroupTargetState::Disable => "disable",
    }
}

fn group_member_label(member: &GroupMemberIdentity) -> String {
    format!(
        "{} | {} | {} | {}",
        provider_display_name(member.provider),
        member.layer.as_str(),
        member.kind.as_str(),
        group_member_name(member),
    )
}

fn coverage_target_label(provider: ProviderId, target_id: &str) -> String {
    let mut parts = target_id.splitn(4, ':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(target_provider), Some(layer), Some(kind), Some(name))
            if target_provider == provider.as_str() =>
        {
            format!(
                "{} | {layer} | {} | {name}",
                provider_display_name(provider),
                coverage_target_kind(kind)
            )
        }
        _ => target_id.to_string(),
    }
}

fn coverage_target_kind(category: &str) -> &str {
    match category {
        "skill" => "skill",
        "configured-mcp" => "mcp",
        "agent" => "agent",
        "hook" => "hook",
        "provider-setting" => "setting",
        "tool" | "plugin-config" | "plugin-manifest" => "plugin",
        other => other,
    }
}

fn provider_display_name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Claude => "Claude Code",
        ProviderId::Codex => "Codex",
        ProviderId::Cursor => "Cursor",
        ProviderId::Pi => "Pi",
        ProviderId::OpenCode => "OpenCode",
        ProviderId::Zed => "Zed",
    }
}

fn group_member_name(member: &GroupMemberIdentity) -> &str {
    let mut parts = member.id.splitn(4, ':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(provider), Some(layer), Some(_), Some(name))
            if provider == member.provider.as_str() && layer == member.layer.as_str() =>
        {
            name
        }
        _ => &member.id,
    }
}

fn group_provider_root(
    roots: &unpin_core::discovery::DiscoveryRoots,
    provider: ProviderId,
) -> &Path {
    match provider {
        ProviderId::Claude => roots.claude_global.as_path(),
        ProviderId::Codex => roots.codex_global.as_path(),
        ProviderId::Cursor => roots.cursor_config.as_path(),
        ProviderId::Pi => roots.pi_global.as_path(),
        ProviderId::OpenCode => roots.opencode_global.as_path(),
        ProviderId::Zed => roots.zed_global.as_path(),
    }
}

fn group_reach_scope_digest(
    expectation: &unpin_core::approval::ApprovalExpectation,
    session_id: &str,
) -> String {
    unpin_core::mutation::reach_scope_digest(expectation, session_id)
}

fn disposition_label(disposition: GroupPlanDisposition) -> &'static str {
    match disposition {
        GroupPlanDisposition::Preview => "preview",
        GroupPlanDisposition::Actionable => "actionable",
        GroupPlanDisposition::NoOp => "no-op",
        GroupPlanDisposition::Blocked => "blocked",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::TempDir;

    use super::*;
    use unpin_core::{
        config::{UnpinConfig, UnpinConfigPaths},
        discovery::{
            DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots,
            ProviderId, discover_all,
        },
        groups::{GroupChangeKind, GroupHistoryLifecycle},
    };

    fn workflow_with_fixture() -> (TempDir, GroupWorkflow, DiscoveryOutput) {
        let root = TempDir::new().expect("tempdir");
        let workspace = root.path().join("workspace");
        let app_state = root.path().join("state");
        fs::create_dir_all(workspace.join(".git")).expect("workspace");
        fs::create_dir_all(&app_state).expect("app state");
        let config = UnpinConfig {
            version: 1,
            app_state_root: app_state,
            cursor_root: root.path().join("cursor"),
            project_root: workspace,
            config_paths: UnpinConfigPaths {
                user_config_path: root.path().join("user.json"),
                project_config_path: root.path().join("project.json"),
            },
        };
        let fixture_root = fs::canonicalize(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../unpin-core/tests/fixtures"),
        )
        .expect("canonical fixture root");
        let roots =
            DiscoveryRoots::fixture_root(fixture_root).with_app_state_root(&config.app_state_root);
        let access =
            GroupAccessContext::from_config(&config, &roots, None, None).expect("group context");
        let discovery = discover_all(&roots).expect("fixture discovery");
        let backup_key = BackupAuthenticationKey::new([0x62; 32]);
        let workflow =
            GroupWorkflow::new(access, Some(&backup_key), &discovery).expect("group workflow");
        (root, workflow, discovery)
    }

    #[test]
    fn empty_workflow_explains_definition_creation() {
        let workflow = GroupWorkflow::empty();
        assert_eq!(workflow.len(), 0);
        assert!(
            workflow
                .details()
                .iter()
                .any(|line| line.contains("Press n to create"))
        );
    }

    #[test]
    fn target_cycles_between_enable_and_disable() {
        let mut workflow = GroupWorkflow::empty();
        assert_eq!(workflow.target, GroupTargetState::Enable);
        workflow.cycle_target();
        assert_eq!(workflow.target, GroupTargetState::Disable);
        workflow.cycle_target();
        assert_eq!(workflow.target, GroupTargetState::Enable);
    }

    #[test]
    fn member_rows_use_compact_identity_labels() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let item = discovery
            .items
            .iter()
            .find(|item| item.id == "claude:global:skill:example-claude-global-skill")
            .expect("Claude fixture skill");
        let mcp_item = discovery
            .items
            .iter()
            .find(|item| item.provider == ProviderId::Claude && item.display_name == "global-docs")
            .expect("Claude fixture MCP");
        let identity = GroupMemberIdentity::try_from(item).expect("group member identity");

        workflow
            .start_create(vec![identity])
            .expect("start group draft");
        for character in "release-kit".chars() {
            workflow.push_text_char(character);
        }
        workflow.finish_text_input().expect("finish group name");

        let rows = workflow.rows(&[item, mcp_item]);
        assert_eq!(
            rows,
            vec![
                "> [x] Claude Code | global | skill | example-claude-global-skill".to_string(),
                "  [ ] Claude Code | global | mcp | global-docs".to_string(),
            ]
        );
        assert!(!rows[0].contains("skill:skill"));
        assert!(!rows[0].contains("claude:global:skill:claude:global"));
    }

    #[test]
    fn group_member_label_compacts_matching_ids_and_preserves_other_ids() {
        let matching = GroupMemberIdentity::new(
            ProviderId::Claude,
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Global,
            "claude:global:skill:example-claude-global-skill",
        )
        .expect("matching identity");
        assert_eq!(
            group_member_label(&matching),
            "Claude Code | global | skill | example-claude-global-skill"
        );

        let non_matching = GroupMemberIdentity::new(
            ProviderId::Claude,
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            DiscoveryLayer::Global,
            "legacy:global:skill:example-claude-global-skill",
        )
        .expect("non-matching identity");
        assert_eq!(
            group_member_label(&non_matching),
            "Claude Code | global | skill | legacy:global:skill:example-claude-global-skill"
        );
    }

    #[test]
    fn coverage_target_label_compacts_matching_ids_and_preserves_other_ids() {
        assert_eq!(
            coverage_target_label(
                ProviderId::Claude,
                "claude:global:skill:example-claude-global-skill",
            ),
            "Claude Code | global | skill | example-claude-global-skill"
        );
        assert_eq!(
            coverage_target_label(ProviderId::Codex, "codex:global:configured-mcp:github",),
            "Codex | global | mcp | github"
        );
        assert_eq!(
            coverage_target_label(
                ProviderId::Claude,
                "claude:global:tool:plugin-source:example-plugin",
            ),
            "Claude Code | global | plugin | plugin-source:example-plugin"
        );
        assert_eq!(
            coverage_target_label(
                ProviderId::Claude,
                "legacy:global:skill:example-claude-global-skill",
            ),
            "legacy:global:skill:example-claude-global-skill"
        );
    }

    #[test]
    fn reviewed_plan_details_use_compact_coverage_and_effect_labels() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let item = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:configured-mcp:github")
            .expect("toggleable Codex fixture MCP");
        let zed_item = discovery
            .items
            .iter()
            .find(|item| item.id == "zed:global:configured-mcp:github")
            .expect("Zed fixture MCP");
        let identity = GroupMemberIdentity::try_from(item).expect("group member identity");
        let zed_identity = GroupMemberIdentity::try_from(zed_item).expect("Zed group member");
        let store = workflow
            .resolver
            .as_ref()
            .expect("group resolver")
            .personal_store()
            .clone();
        store
            .create(
                &GroupDefinitionV1::new("compact-details", vec![identity, zed_identity])
                    .expect("group definition"),
                OwnerGeneration::new("tui-compact-details-test", 1).expect("owner"),
            )
            .expect("create group");
        workflow.refresh(&discovery).expect("refresh groups");
        workflow.selected = workflow
            .records
            .iter()
            .position(|record| record.definition.name == "compact-details")
            .expect("selected compact-details group");
        workflow.target = if item.enabled {
            GroupTargetState::Disable
        } else {
            GroupTargetState::Enable
        };
        workflow.provider_reach =
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::TuiControl);
        let access = workflow
            .resolver
            .as_ref()
            .expect("group resolver")
            .context()
            .clone();
        let approval_context =
            ControlApprovalContext::new(access.repository_key(), access.workspace_key())
                .expect("approval context");

        workflow.plan(&approval_context).expect("review plan");
        let details = workflow.details();
        let coverage_label = "Codex | global | mcp | github";
        let effect_label = "Codex | global | mcp | github";
        assert!(
            details
                .iter()
                .any(|detail| detail.contains(&format!("coverage: {coverage_label}"))),
            "{details:#?}"
        );
        assert!(
            details
                .iter()
                .any(|detail| detail.contains(&format!("effect: {effect_label}"))),
            "{details:#?}"
        );
        assert!(
            !details
                .iter()
                .any(|detail| detail.contains("codex:global:configured-mcp:github"))
        );
    }

    #[test]
    fn create_draft_keeps_distinct_full_member_identities_until_contextual_review() {
        let members = vec![
            GroupMemberIdentity::new(
                ProviderId::Claude,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Global,
                "shared-name",
            )
            .expect("first member"),
            GroupMemberIdentity::new(
                ProviderId::Codex,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Project,
                "shared-name",
            )
            .expect("second member"),
        ];
        let mut workflow = GroupWorkflow::empty();

        workflow.start_create(members).expect("start create");
        for character in "brainstorming".chars() {
            workflow.push_text_char(character);
        }
        assert!(matches!(
            workflow.finish_text_input().expect("finish name"),
            GroupTextSubmission::DefinitionName
        ));
        assert_eq!(
            workflow
                .draft
                .as_ref()
                .expect("definition draft")
                .definition
                .members
                .len(),
            2
        );
        assert!(workflow.stage_definition_save().is_err());
        assert!(workflow.pending_definition.is_none());
    }

    #[test]
    fn cancel_interaction_resets_an_active_toggle_review() {
        let mut workflow = GroupWorkflow::empty();
        workflow.phase = WorkflowPhase::Planned;

        assert!(workflow.cancel_interaction());
        assert_eq!(workflow.phase, WorkflowPhase::Browsing);
        assert!(workflow.reviewed.is_none());
        assert!(!workflow.cancel_interaction());
    }

    #[test]
    fn changing_group_provider_reach_invalidates_confirmation() {
        let mut workflow = GroupWorkflow::empty();
        workflow.phase = WorkflowPhase::Confirmed;

        workflow.cycle_provider_reach();

        assert_eq!(workflow.phase, WorkflowPhase::Browsing);
        assert!(matches!(
            workflow.provider_reach,
            ProviderReach::Selected {
                provider: ProviderId::Claude,
                provenance: SelectedProviderProvenance::TuiControl,
            }
        ));
        assert!(!workflow.confirm());
    }

    #[test]
    fn definition_review_rejects_new_read_only_inventory_member() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let read_only = discovery
            .items
            .iter()
            .find(|item| item.mutability != DiscoveryMutability::ReadWrite)
            .expect("read-only fixture item");
        let identity = GroupMemberIdentity::try_from(read_only).expect("member identity");

        workflow.start_create(vec![identity]).expect("start create");
        for character in "read-only".chars() {
            workflow.push_text_char(character);
        }
        workflow.finish_text_input().expect("finish name");
        let error = workflow
            .stage_definition_save()
            .expect_err("read-only member must not be saved");

        assert!(error.contains("not individually toggleable"));
        assert!(workflow.pending_definition.is_none());
    }

    #[test]
    fn confirmed_definition_review_applies_and_persists_exact_members() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let item = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:configured-mcp:github")
            .expect("toggleable fixture MCP");
        let identity = GroupMemberIdentity::try_from(item).expect("member identity");
        workflow
            .start_create(vec![identity.clone()])
            .expect("start create");
        for character in "tui-group".chars() {
            workflow.push_text_char(character);
        }
        workflow.finish_text_input().expect("finish name");
        workflow
            .stage_definition_save()
            .expect("stage definition save");
        assert_eq!(workflow.phase, WorkflowPhase::Planned);
        assert!(workflow.confirm());

        let access = workflow
            .resolver
            .as_ref()
            .expect("resolver")
            .context()
            .clone();
        let approval_context =
            ControlApprovalContext::new(access.repository_key(), access.workspace_key())
                .expect("approval context");
        let outcome = workflow
            .apply_active(
                access.app_state_root(),
                access.workspace_root(),
                &approval_context,
                &SessionAuthorityKey::new([0x53; 32]),
                None,
                true,
            )
            .expect("apply definition");

        assert!(matches!(
            outcome,
            GroupApplyOutcome::DefinitionChanged {
                message,
                created: true,
            } if message == "create personal:tui-group"
        ));
        assert_eq!(workflow.phase, WorkflowPhase::Applied);
        let stored = workflow
            .resolver
            .as_ref()
            .expect("resolver")
            .personal_store()
            .load("tui-group")
            .expect("load group")
            .expect("stored group");
        assert_eq!(stored.definition.members, vec![identity]);
    }

    #[test]
    fn reach_aware_group_apply_uses_signed_context_for_partial_noop() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let codex_item = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:configured-mcp:github")
            .expect("Codex fixture MCP");
        let zed_item = discovery
            .items
            .iter()
            .find(|item| item.id == "zed:global:configured-mcp:github")
            .expect("Zed fixture MCP");
        let codex = GroupMemberIdentity::try_from(codex_item).expect("Codex identity");
        let zed = GroupMemberIdentity::try_from(zed_item).expect("Zed identity");
        let store = workflow
            .resolver
            .as_ref()
            .expect("group resolver")
            .personal_store()
            .clone();
        store
            .create(
                &GroupDefinitionV1::new("reach-aware-partial", vec![codex]).expect("definition"),
                OwnerGeneration::new("tui-reach-aware-test", 1).expect("owner"),
            )
            .expect("create group");
        let current = store
            .load("reach-aware-partial")
            .expect("load created group")
            .expect("created group");
        store
            .replace(
                &GroupDefinitionV1::new(
                    "reach-aware-partial",
                    vec![current.definition.members[0].clone(), zed],
                )
                .expect("mixed definition"),
                Some(&current.revision),
                OwnerGeneration::new("tui-reach-aware-test", 2).expect("owner"),
            )
            .expect("expand group");
        workflow.refresh(&discovery).expect("refresh groups");
        workflow.selected = workflow
            .records
            .iter()
            .position(|record| record.definition.name == "reach-aware-partial")
            .expect("selected mixed group");
        workflow.target = if codex_item.enabled {
            GroupTargetState::Enable
        } else {
            GroupTargetState::Disable
        };
        workflow.provider_reach =
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::TuiControl);
        let access = workflow
            .resolver
            .as_ref()
            .expect("resolver")
            .context()
            .clone();
        let approval_context =
            ControlApprovalContext::new(access.repository_key(), access.workspace_key())
                .expect("approval context");
        workflow
            .plan(&approval_context)
            .expect("plan partial group");
        assert!(workflow.confirm());
        let backup_key = BackupAuthenticationKey::new([0x62; 32]);
        let outcome = workflow
            .apply_active(
                access.app_state_root(),
                access.workspace_root(),
                &approval_context,
                &SessionAuthorityKey::new([0x53; 32]),
                Some(&backup_key),
                true,
            )
            .expect("reach-aware partial apply");
        assert!(matches!(
            outcome,
            GroupApplyOutcome::Direct {
                lifecycle: GroupOperationLifecycle::Partial,
                ..
            }
        ));
        assert_eq!(workflow.phase, WorkflowPhase::Partial);
        let details = workflow.details();
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("member result:"))
        );
        assert!(details.iter().any(|detail| detail.contains("backup=")));
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("unpin group operation-show"))
        );
    }

    #[test]
    fn rename_history_restore_binds_expected_revision_to_current_name() {
        let (_root, mut workflow, discovery) = workflow_with_fixture();
        let identity = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:configured-mcp:github")
            .map(GroupMemberIdentity::try_from)
            .transpose()
            .expect("member identity")
            .expect("toggleable fixture MCP");
        let owner = OwnerGeneration::new(unpin_core::groups::GROUP_DEFINITION_OWNER_ID, 1)
            .expect("group owner");
        let store = workflow
            .resolver
            .as_ref()
            .expect("resolver")
            .personal_store()
            .clone();
        let created = store
            .create(
                &GroupDefinitionV1::new("before-rename", vec![identity]).expect("group definition"),
                owner.clone(),
            )
            .expect("create group");
        let renamed = store
            .rename("before-rename", "after-rename", &created.revision, owner)
            .expect("rename group");
        workflow.refresh(&discovery).expect("refresh groups");
        workflow.selected = workflow
            .records
            .iter()
            .position(|record| record.definition.name == "after-rename")
            .expect("renamed group");
        workflow.show_history().expect("show rename history");
        workflow.history_selected = workflow
            .history
            .iter()
            .position(|history| {
                history
                    .definition_after
                    .as_ref()
                    .is_some_and(|definition| definition.name == "after-rename")
                    && history
                        .definition_before
                        .as_ref()
                        .is_some_and(|definition| definition.name == "before-rename")
            })
            .expect("rename history entry");
        workflow
            .stage_history_restore()
            .expect("stage rename restore");
        assert!(matches!(
            workflow
                .pending_definition
                .as_ref()
                .map(|review| &review.action),
            Some(DefinitionAction::Restore {
                expected: Some(expected),
                ..
            }) if expected == &renamed.revision
        ));
        assert!(workflow.confirm());
        let access = workflow
            .resolver
            .as_ref()
            .expect("resolver")
            .context()
            .clone();
        let approval_context =
            ControlApprovalContext::new(access.repository_key(), access.workspace_key())
                .expect("approval context");
        workflow
            .apply_active(
                access.app_state_root(),
                access.workspace_root(),
                &approval_context,
                &SessionAuthorityKey::new([0x53; 32]),
                None,
                true,
            )
            .expect("restore renamed group");
        assert!(
            store
                .load("before-rename")
                .expect("load restored")
                .is_some()
        );
        assert!(store.load("after-rename").expect("load current").is_none());
    }

    #[test]
    fn group_lifecycle_presentation_preserves_partial_failed_and_recovery_outcomes() {
        let (phase, envelope_lifecycle, error) =
            group_lifecycle_presentation(GroupOperationLifecycle::Partial)
                .expect("partial presentation");
        assert_eq!(phase, WorkflowPhase::Partial);
        assert_eq!(envelope_lifecycle, ControlOperationLifecycle::Blocked);
        assert!(error.is_some());
        let (phase, envelope_lifecycle, error) =
            group_lifecycle_presentation(GroupOperationLifecycle::Failed)
                .expect("failed presentation");
        assert_eq!(phase, WorkflowPhase::Blocked);
        assert_eq!(envelope_lifecycle, ControlOperationLifecycle::Blocked);
        assert!(error.is_some());
        let (phase, envelope_lifecycle, error) =
            group_lifecycle_presentation(GroupOperationLifecycle::RecoveryRequired)
                .expect("recovery presentation");
        assert_eq!(phase, WorkflowPhase::RecoveryRequired);
        assert_eq!(
            envelope_lifecycle,
            ControlOperationLifecycle::RecoveryRequired
        );
        assert!(error.is_some());
        assert!(group_lifecycle_presentation(GroupOperationLifecycle::InProgress).is_err());
    }

    #[test]
    fn challenge_paste_accepts_the_protocol_maximum_and_truncates_excess() {
        let mut workflow = GroupWorkflow::empty();
        workflow.start_mcp_approval();
        workflow.push_text(
            &"a".repeat(unpin_core::groups::MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES + 64),
        );

        assert_eq!(
            workflow.text_input.len(),
            unpin_core::groups::MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES
        );
    }

    #[test]
    fn history_filter_follows_a_group_across_rename_chain() {
        fn record(
            id: &str,
            scope: GroupScope,
            before: Option<&str>,
            after: Option<&str>,
        ) -> GroupHistoryRecord {
            GroupHistoryRecord {
                schema_version: 2,
                history_id: id.to_string(),
                created_at: "2026-07-26T00:00:00Z".to_string(),
                scope,
                change: GroupChangeKind::Rename,
                lifecycle: GroupHistoryLifecycle::Committed,
                name_before: before.map(str::to_string),
                name_after: after.map(str::to_string),
                revision_before: None,
                revision_after: None,
                definition_before: None,
                definition_after: None,
                binding_before: None,
                binding_after: None,
                authentication_key_id: None,
                integrity_digest: String::new(),
            }
        }

        let filtered = history_for_group_name(
            vec![
                record("first", GroupScope::Personal, Some("alpha"), Some("beta")),
                record("second", GroupScope::Personal, Some("beta"), Some("gamma")),
                record(
                    "unrelated",
                    GroupScope::Personal,
                    Some("other"),
                    Some("elsewhere"),
                ),
                record(
                    "repository",
                    GroupScope::Repository,
                    Some("gamma"),
                    Some("delta"),
                ),
            ],
            GroupScope::Personal,
            "gamma",
        );

        assert_eq!(
            filtered
                .iter()
                .map(|entry| entry.history_id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }
}
