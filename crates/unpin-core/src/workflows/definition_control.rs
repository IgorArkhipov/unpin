use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
    },
    control_operation::{
        DurableControlError, DurableControlJournal, DurableControlStart,
        DurableControlTerminalStatus,
    },
    mutation::BackupAuthenticationKey,
    profiles::ProfileSourceScope,
    state::atomic_json::{OwnerGeneration, StateError, StateRevision, StateSnapshot},
    transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionKind, TransitionPlan, TransitionPlanError,
    },
};

use super::{
    WorkflowDefinition, WorkflowDefinitionHistoryError, WorkflowDefinitionHistoryLifecycle,
    WorkflowDefinitionHistoryPrepared, WorkflowDefinitionHistoryRecord,
    WorkflowDefinitionHistoryStore, WorkflowStore, WorkflowStoreError,
};

pub const WORKFLOW_DEFINITION_PLAN_SCHEMA_VERSION: u32 = 1;
const WORKFLOW_DEFINITION_OPERATION_KIND: &str = "workflow-definition";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowDefinitionAction {
    Upsert,
    Delete,
    Restore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowDefinitionDisposition {
    Actionable,
    NoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowDefinitionApplyStatus {
    Applied,
    NoOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowDefinitionMutationRequest {
    Upsert(WorkflowDefinition),
    Delete(String),
    Restore(String),
}

impl WorkflowDefinitionMutationRequest {
    #[must_use]
    pub fn upsert(definition: WorkflowDefinition) -> Self {
        Self::Upsert(definition)
    }

    #[must_use]
    pub fn delete(workflow_id: impl Into<String>) -> Self {
        Self::Delete(workflow_id.into())
    }

    #[must_use]
    pub fn restore(history_id: impl Into<String>) -> Self {
        Self::Restore(history_id.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinitionPlan {
    pub schema_version: u32,
    pub operation_id: String,
    pub operation_kind: String,
    pub action: WorkflowDefinitionAction,
    pub disposition: WorkflowDefinitionDisposition,
    pub workflow_id: String,
    pub scope: ProfileSourceScope,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_history_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_history_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_before: Option<WorkflowDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_owner: Option<OwnerGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_after: Option<WorkflowDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_digest: Option<String>,
    pub pre_state_fingerprint: String,
    pub post_state_fingerprint: String,
    pub plan_fingerprint: String,
    pub activation: EffectActivation,
    pub human_approval_required: bool,
}

impl WorkflowDefinitionPlan {
    pub fn verify(&self) -> Result<(), WorkflowDefinitionControlError> {
        if self.schema_version != WORKFLOW_DEFINITION_PLAN_SCHEMA_VERSION
            || self.operation_kind != WORKFLOW_DEFINITION_OPERATION_KIND
            || self.scope != ProfileSourceScope::Global
            || self.workflow_id.is_empty()
            || self.repository_key.is_empty()
            || self.workspace_key.is_empty()
            || self.activation != EffectActivation::NextSessionOnly
            || !self.human_approval_required
            || self.definition_before.is_some() != self.expected_revision.is_some()
            || self.definition_before.is_some() != self.expected_owner.is_some()
            || self
                .definition_before
                .as_ref()
                .is_some_and(|definition| definition.id != self.workflow_id)
            || self
                .definition_after
                .as_ref()
                .is_some_and(|definition| definition.id != self.workflow_id)
            || self.disposition
                != if self.definition_before == self.definition_after {
                    WorkflowDefinitionDisposition::NoOp
                } else {
                    WorkflowDefinitionDisposition::Actionable
                }
            || match self.action {
                WorkflowDefinitionAction::Upsert => {
                    self.definition_after.is_none()
                        || self.source_history_id.is_some()
                        || self.source_history_digest.is_some()
                }
                WorkflowDefinitionAction::Delete => {
                    self.definition_before.is_none()
                        || self.definition_after.is_some()
                        || self.source_history_id.is_some()
                        || self.source_history_digest.is_some()
                }
                WorkflowDefinitionAction::Restore => {
                    self.source_history_id.is_none() || self.source_history_digest.is_none()
                }
            }
        {
            return Err(WorkflowDefinitionControlError::InvalidPlan);
        }
        for definition in [
            self.definition_before.as_ref(),
            self.definition_after.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            definition.validate()?;
        }
        if self.definition_digest != definition_digest(self.definition_after.as_ref())?
            || self.pre_state_fingerprint
                != state_fingerprint(
                    self.definition_before.as_ref(),
                    self.expected_revision.as_ref(),
                    self.expected_owner.as_ref(),
                )?
            || self.post_state_fingerprint != target_fingerprint(self.definition_after.as_ref())?
        {
            return Err(WorkflowDefinitionControlError::InvalidPlan);
        }
        let fingerprint = self.fingerprint()?;
        if self.plan_fingerprint != fingerprint
            || self.operation_id != operation_id(&fingerprint)
            || !crate::is_lower_hex_digest(&self.plan_fingerprint)
        {
            return Err(WorkflowDefinitionControlError::PlanFingerprintMismatch);
        }
        Ok(())
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, WorkflowDefinitionControlError> {
        self.verify()?;
        if self.repository_key != context.repository_key()
            || self.workspace_key != context.workspace_key()
        {
            return Err(WorkflowDefinitionControlError::ContextMismatch);
        }
        Ok(ApprovalExpectation {
            issuer: CONTROL_APPROVAL_ISSUER.to_string(),
            audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
            operation_id: self.operation_id.clone(),
            operation_kind: self.operation_kind.clone(),
            effect_graph_digest: self.plan_fingerprint.clone(),
            repository_key: self.repository_key.clone(),
            workspace_key: self.workspace_key.clone(),
            session_id: None,
            profile_digest: self.definition_digest.clone(),
            resources: vec![ApprovalResourceBinding {
                resource_id: format!("workflow-definition-{}", self.workflow_id),
                pre_state_fingerprint: Some(self.pre_state_fingerprint.clone()),
            }],
        })
    }

    fn fingerprint(&self) -> Result<String, WorkflowDefinitionControlError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FingerprintBody<'a> {
            schema_version: u32,
            operation_kind: &'a str,
            action: WorkflowDefinitionAction,
            disposition: WorkflowDefinitionDisposition,
            workflow_id: &'a str,
            scope: ProfileSourceScope,
            repository_key: &'a str,
            workspace_key: &'a str,
            source_history_id: &'a Option<String>,
            source_history_digest: &'a Option<String>,
            definition_before: &'a Option<WorkflowDefinition>,
            expected_revision: &'a Option<StateRevision>,
            expected_owner: &'a Option<OwnerGeneration>,
            definition_after: &'a Option<WorkflowDefinition>,
            definition_digest: &'a Option<String>,
            pre_state_fingerprint: &'a str,
            post_state_fingerprint: &'a str,
            activation: EffectActivation,
            human_approval_required: bool,
        }
        let body = FingerprintBody {
            schema_version: self.schema_version,
            operation_kind: &self.operation_kind,
            action: self.action,
            disposition: self.disposition,
            workflow_id: &self.workflow_id,
            scope: self.scope,
            repository_key: &self.repository_key,
            workspace_key: &self.workspace_key,
            source_history_id: &self.source_history_id,
            source_history_digest: &self.source_history_digest,
            definition_before: &self.definition_before,
            expected_revision: &self.expected_revision,
            expected_owner: &self.expected_owner,
            definition_after: &self.definition_after,
            definition_digest: &self.definition_digest,
            pre_state_fingerprint: &self.pre_state_fingerprint,
            post_state_fingerprint: &self.post_state_fingerprint,
            activation: self.activation,
            human_approval_required: self.human_approval_required,
        };
        hash_serialized(&body)
    }

    fn transition_plan(&self) -> Result<TransitionPlan, WorkflowDefinitionControlError> {
        TransitionPlan::new(
            self.operation_id.clone(),
            TransitionKind::GatewayWorkflow,
            TransitionContext {
                repository_key: self.repository_key.clone(),
                workspace_key: self.workspace_key.clone(),
                session_id: None,
                profile_digest: self.definition_digest.clone(),
            },
            vec![TransitionEffect {
                effect_id: "workflow-definition-effect".to_string(),
                kind: if self.definition_after.is_some() {
                    TransitionEffectKind::CopyCanonicalContent
                } else {
                    TransitionEffectKind::WithdrawView
                },
                resource_id: format!("workflow-definition-{}", self.workflow_id),
                target_type: "workflow-definition".to_string(),
                summary: "Apply reviewed workflow definition for future sessions".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: self.activation,
                expected_pre_fingerprint: Some(self.pre_state_fingerprint.clone()),
                expected_post_fingerprint: Some(self.post_state_fingerprint.clone()),
                provider_views: Vec::new(),
            }],
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinitionMutationResult {
    pub action: WorkflowDefinitionAction,
    pub workflow_id: String,
    pub status: WorkflowDefinitionApplyStatus,
    pub activation: EffectActivation,
    pub cached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<WorkflowDefinition>,
}

#[derive(Debug, Clone)]
pub struct WorkflowDefinitionController {
    app_state_root: PathBuf,
    store: WorkflowStore,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    journal: DurableControlJournal,
}

impl WorkflowDefinitionController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            store: WorkflowStore::new(&app_state_root),
            journal: DurableControlJournal::new(&app_state_root),
            app_state_root,
            backup_authentication_key: None,
        }
    }

    #[must_use]
    pub fn with_backup_authentication_key(
        app_state_root: impl Into<PathBuf>,
        backup_authentication_key: BackupAuthenticationKey,
    ) -> Self {
        let mut controller = Self::new(app_state_root);
        controller.backup_authentication_key = Some(backup_authentication_key);
        controller
    }

    pub fn plan(
        &self,
        request: WorkflowDefinitionMutationRequest,
        context: &ControlApprovalContext,
    ) -> Result<WorkflowDefinitionPlan, WorkflowDefinitionControlError> {
        let (action, workflow_id, definition_after, source_history_id, source_history_digest) =
            match request {
                WorkflowDefinitionMutationRequest::Upsert(definition) => {
                    definition.validate()?;
                    (
                        WorkflowDefinitionAction::Upsert,
                        definition.id.clone(),
                        Some(definition),
                        None,
                        None,
                    )
                }
                WorkflowDefinitionMutationRequest::Delete(workflow_id) => {
                    let current = self.store.load_global_definition(&workflow_id)?;
                    if current.is_none() {
                        return Err(WorkflowDefinitionControlError::OwnershipEvidenceRequired(
                            workflow_id,
                        ));
                    }
                    (
                        WorkflowDefinitionAction::Delete,
                        workflow_id,
                        None,
                        None,
                        None,
                    )
                }
                WorkflowDefinitionMutationRequest::Restore(history_id) => {
                    let history = self
                        .history_store()?
                        .load_committed(&history_id)?
                        .ok_or_else(|| {
                            WorkflowDefinitionControlError::HistoryNotFound(history_id.clone())
                        })?;
                    if history.repository_key != context.repository_key()
                        || history.workspace_key != context.workspace_key()
                    {
                        return Err(WorkflowDefinitionControlError::ContextMismatch);
                    }
                    let current = self.store.load_global_definition(&history.workflow_id)?;
                    if !snapshot_matches_history_state(
                        current.as_ref(),
                        history.definition_after.as_ref(),
                        history.revision_after.as_ref(),
                        history.owner_after.as_ref(),
                    ) && !snapshot_matches_history_state(
                        current.as_ref(),
                        history.definition_before.as_ref(),
                        history.revision_before.as_ref(),
                        history.owner_before.as_ref(),
                    ) {
                        return Err(WorkflowDefinitionControlError::HistoryStateMismatch(
                            history_id,
                        ));
                    }
                    (
                        WorkflowDefinitionAction::Restore,
                        history.workflow_id,
                        history.definition_before,
                        Some(history.history_id),
                        Some(history.integrity_digest),
                    )
                }
            };
        let current = self.store.load_global_definition(&workflow_id)?;
        build_plan(
            action,
            workflow_id,
            current,
            definition_after,
            source_history_id,
            source_history_digest,
            context,
        )
    }

    pub fn apply(
        &self,
        reviewed: &WorkflowDefinitionPlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
    ) -> Result<WorkflowDefinitionMutationResult, WorkflowDefinitionControlError> {
        let expectation = reviewed.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        let history_store = if reviewed.disposition == WorkflowDefinitionDisposition::Actionable {
            Some(self.history_store()?)
        } else {
            None
        };
        self.verify_restore_source(reviewed)?;
        let transition = reviewed.transition_plan()?;
        let start =
            match self
                .journal
                .begin(&transition, &authorization, "unpin-workflow-definition")
            {
                Ok(start) => start,
                Err(DurableControlError::AuthorizationDecisionConflict) => {
                    if let Ok(result) = self.cached_result(reviewed, history_store.as_ref()) {
                        return Ok(result);
                    }
                    return Err(WorkflowDefinitionControlError::Durable(
                        DurableControlError::AuthorizationDecisionConflict,
                    ));
                }
                Err(error) => return Err(error.into()),
            };
        let DurableControlStart::Apply(journal) = start else {
            let DurableControlStart::Cached(terminal) = start else {
                unreachable!()
            };
            if terminal.operation_id != reviewed.operation_id
                || terminal.status
                    != if reviewed.disposition == WorkflowDefinitionDisposition::NoOp {
                        DurableControlTerminalStatus::NoOp
                    } else {
                        DurableControlTerminalStatus::Applied
                    }
            {
                return Err(WorkflowDefinitionControlError::RecoveryRequired(
                    reviewed.operation_id.clone(),
                ));
            }
            return self.cached_result(reviewed, history_store.as_ref());
        };

        if reviewed.disposition == WorkflowDefinitionDisposition::NoOp {
            if !self.current_matches_before(reviewed)? {
                if journal.is_resumed() {
                    journal.needs_repair("workflow-definition-no-op-drift")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                journal.abort("workflow-definition-plan-drift")?;
                return Err(WorkflowDefinitionControlError::PlanDrift);
            }
            journal.commit_with_terminal_status(DurableControlTerminalStatus::NoOp)?;
            return Ok(result_for(reviewed, None, None, false));
        }

        let history_store = history_store.expect("actionable plans require history");
        let history_id = history_id(&reviewed.plan_fingerprint);
        let prepared = match history_store.load_snapshot(&history_id)? {
            Some(existing) => {
                if !history_matches_plan(&existing.record, reviewed) {
                    journal.needs_repair("workflow-definition-history-conflict")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                if existing.record.lifecycle == WorkflowDefinitionHistoryLifecycle::Committed {
                    if self.current_matches_after(reviewed)? {
                        journal
                            .commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
                        return Ok(result_for(
                            reviewed,
                            Some(existing.record),
                            self.store.load_global_definition(&reviewed.workflow_id)?,
                            true,
                        ));
                    }
                    journal.needs_repair("workflow-definition-terminal-state-diverged")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                if existing.record.lifecycle == WorkflowDefinitionHistoryLifecycle::Aborted {
                    journal.needs_repair("workflow-definition-history-aborted")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                if self.current_matches_after(reviewed)? {
                    let current = self.store.load_global_definition(&reviewed.workflow_id)?;
                    let committed = history_store.commit(
                        &existing,
                        current.as_ref().map(|snapshot| snapshot.revision.clone()),
                        current.as_ref().map(|snapshot| snapshot.owner.clone()),
                    )?;
                    journal.commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
                    return Ok(result_for(reviewed, Some(committed), current, false));
                }
                if !self.current_matches_before(reviewed)? {
                    journal.needs_repair("workflow-definition-resume-state-diverged")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                existing
            }
            None => {
                if journal.is_resumed() || !self.current_matches_before(reviewed)? {
                    if journal.is_resumed() {
                        journal.needs_repair("workflow-definition-backup-missing")?;
                        return Err(WorkflowDefinitionControlError::RecoveryRequired(
                            reviewed.operation_id.clone(),
                        ));
                    }
                    journal.abort("workflow-definition-plan-drift")?;
                    return Err(WorkflowDefinitionControlError::PlanDrift);
                }
                history_store.prepare(&WorkflowDefinitionHistoryRecord::prepared(
                    WorkflowDefinitionHistoryPrepared {
                        history_id,
                        operation_id: reviewed.operation_id.clone(),
                        plan_fingerprint: reviewed.plan_fingerprint.clone(),
                        action: reviewed.action,
                        workflow_id: reviewed.workflow_id.clone(),
                        repository_key: reviewed.repository_key.clone(),
                        workspace_key: reviewed.workspace_key.clone(),
                        source_history_id: reviewed.source_history_id.clone(),
                        definition_before: reviewed.definition_before.clone(),
                        revision_before: reviewed.expected_revision.clone(),
                        owner_before: reviewed.expected_owner.clone(),
                        definition_after: reviewed.definition_after.clone(),
                    },
                ))?
            }
        };

        if !self.current_matches_before(reviewed)? {
            if journal.is_resumed() {
                journal.needs_repair("workflow-definition-prewrite-drift")?;
                return Err(WorkflowDefinitionControlError::RecoveryRequired(
                    reviewed.operation_id.clone(),
                ));
            }
            let _ = history_store.abort(&prepared);
            journal.abort("workflow-definition-plan-drift")?;
            return Err(WorkflowDefinitionControlError::PlanDrift);
        }

        let mutation = self.apply_store_mutation(reviewed);
        let current = match mutation {
            Ok(current) => current,
            Err(WorkflowStoreError::State(StateError::StaleRevision { .. })) => {
                if history_store.abort(&prepared).is_err() {
                    journal.needs_repair("workflow-definition-stale-abort-failed")?;
                    return Err(WorkflowDefinitionControlError::RecoveryRequired(
                        reviewed.operation_id.clone(),
                    ));
                }
                journal.abort("workflow-definition-plan-drift")?;
                return Err(WorkflowDefinitionControlError::PlanDrift);
            }
            Err(error) => {
                journal.needs_repair("workflow-definition-write-failed")?;
                return Err(WorkflowDefinitionControlError::RecoveryRequired(format!(
                    "{}: {error}",
                    reviewed.operation_id
                )));
            }
        };
        let committed = match history_store.commit(
            &prepared,
            current.as_ref().map(|snapshot| snapshot.revision.clone()),
            current.as_ref().map(|snapshot| snapshot.owner.clone()),
        ) {
            Ok(committed) => committed,
            Err(error) => {
                journal.needs_repair("workflow-definition-history-commit-failed")?;
                return Err(WorkflowDefinitionControlError::RecoveryRequired(format!(
                    "{}: {error}",
                    reviewed.operation_id
                )));
            }
        };
        journal.commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
        Ok(result_for(reviewed, Some(committed), current, false))
    }

    pub fn history(
        &self,
    ) -> Result<Vec<WorkflowDefinitionHistoryRecord>, WorkflowDefinitionControlError> {
        self.history_store()?.list().map_err(Into::into)
    }

    fn history_store(
        &self,
    ) -> Result<WorkflowDefinitionHistoryStore, WorkflowDefinitionControlError> {
        let key = self
            .backup_authentication_key
            .as_ref()
            .ok_or(WorkflowDefinitionControlError::BackupAuthenticationRequired)?;
        Ok(WorkflowDefinitionHistoryStore::new(
            self.app_state_root.join("workflows").join("history"),
            key.clone(),
        ))
    }

    fn verify_restore_source(
        &self,
        reviewed: &WorkflowDefinitionPlan,
    ) -> Result<(), WorkflowDefinitionControlError> {
        if reviewed.action != WorkflowDefinitionAction::Restore {
            return Ok(());
        }
        let source_id = reviewed
            .source_history_id
            .as_deref()
            .ok_or(WorkflowDefinitionControlError::InvalidPlan)?;
        let source = self
            .history_store()?
            .load_committed(source_id)?
            .ok_or_else(|| {
                WorkflowDefinitionControlError::HistoryNotFound(source_id.to_string())
            })?;
        if Some(source.integrity_digest.as_str()) != reviewed.source_history_digest.as_deref()
            || source.workflow_id != reviewed.workflow_id
            || source.definition_before != reviewed.definition_after
            || source.repository_key != reviewed.repository_key
            || source.workspace_key != reviewed.workspace_key
        {
            return Err(WorkflowDefinitionControlError::HistoryStateMismatch(
                source_id.to_string(),
            ));
        }
        Ok(())
    }

    fn apply_store_mutation(
        &self,
        reviewed: &WorkflowDefinitionPlan,
    ) -> Result<Option<StateSnapshot<WorkflowDefinition>>, WorkflowStoreError> {
        if let Some(definition) = reviewed.definition_after.as_ref() {
            let generation = reviewed
                .expected_owner
                .as_ref()
                .map_or(1, |owner| owner.generation.saturating_add(1));
            if generation == u64::MAX
                && reviewed
                    .expected_owner
                    .as_ref()
                    .is_some_and(|owner| owner.generation == u64::MAX)
            {
                return Err(WorkflowStoreError::State(StateError::RevisionOverflow));
            }
            let owner = OwnerGeneration::new(reviewed.operation_id.clone(), generation)
                .map_err(WorkflowStoreError::State)?;
            self.store.upsert_global_definition(
                definition,
                reviewed.expected_revision.as_ref(),
                owner,
            )?;
            self.store.load_global_definition(&reviewed.workflow_id)
        } else {
            let expected = reviewed.expected_revision.as_ref().ok_or_else(|| {
                WorkflowStoreError::InvalidWorkflowId(reviewed.workflow_id.clone())
            })?;
            self.store
                .delete_global_definition(&reviewed.workflow_id, expected)?;
            Ok(None)
        }
    }

    fn current_matches_before(
        &self,
        reviewed: &WorkflowDefinitionPlan,
    ) -> Result<bool, WorkflowDefinitionControlError> {
        let current = self.store.load_global_definition(&reviewed.workflow_id)?;
        Ok(snapshot_matches_history_state(
            current.as_ref(),
            reviewed.definition_before.as_ref(),
            reviewed.expected_revision.as_ref(),
            reviewed.expected_owner.as_ref(),
        ))
    }

    fn current_matches_after(
        &self,
        reviewed: &WorkflowDefinitionPlan,
    ) -> Result<bool, WorkflowDefinitionControlError> {
        let current = self.store.load_global_definition(&reviewed.workflow_id)?;
        Ok(
            match (current.as_ref(), reviewed.definition_after.as_ref()) {
                (None, None) => true,
                (Some(snapshot), Some(definition)) => {
                    snapshot.value == *definition
                        && snapshot.owner.owner_id == reviewed.operation_id
                }
                _ => false,
            },
        )
    }

    fn cached_result(
        &self,
        reviewed: &WorkflowDefinitionPlan,
        history_store: Option<&WorkflowDefinitionHistoryStore>,
    ) -> Result<WorkflowDefinitionMutationResult, WorkflowDefinitionControlError> {
        if reviewed.disposition == WorkflowDefinitionDisposition::NoOp {
            if !self.current_matches_before(reviewed)? {
                return Err(WorkflowDefinitionControlError::PlanDrift);
            }
            return Ok(result_for(reviewed, None, None, true));
        }
        let record = history_store
            .ok_or(WorkflowDefinitionControlError::BackupAuthenticationRequired)?
            .load_committed(&history_id(&reviewed.plan_fingerprint))?
            .ok_or_else(|| {
                WorkflowDefinitionControlError::RecoveryRequired(reviewed.operation_id.clone())
            })?;
        if !history_matches_plan(&record, reviewed) || !self.current_matches_after(reviewed)? {
            return Err(WorkflowDefinitionControlError::PlanDrift);
        }
        let current = self.store.load_global_definition(&reviewed.workflow_id)?;
        Ok(result_for(reviewed, Some(record), current, true))
    }
}

fn build_plan(
    action: WorkflowDefinitionAction,
    workflow_id: String,
    current: Option<StateSnapshot<WorkflowDefinition>>,
    definition_after: Option<WorkflowDefinition>,
    source_history_id: Option<String>,
    source_history_digest: Option<String>,
    context: &ControlApprovalContext,
) -> Result<WorkflowDefinitionPlan, WorkflowDefinitionControlError> {
    let definition_before = current.as_ref().map(|snapshot| snapshot.value.clone());
    let expected_revision = current.as_ref().map(|snapshot| snapshot.revision.clone());
    let expected_owner = current.as_ref().map(|snapshot| snapshot.owner.clone());
    let disposition = if definition_before == definition_after {
        WorkflowDefinitionDisposition::NoOp
    } else {
        WorkflowDefinitionDisposition::Actionable
    };
    let definition_digest = definition_digest(definition_after.as_ref())?;
    let pre_state_fingerprint = state_fingerprint(
        definition_before.as_ref(),
        expected_revision.as_ref(),
        expected_owner.as_ref(),
    )?;
    let post_state_fingerprint = target_fingerprint(definition_after.as_ref())?;
    let mut plan = WorkflowDefinitionPlan {
        schema_version: WORKFLOW_DEFINITION_PLAN_SCHEMA_VERSION,
        operation_id: String::new(),
        operation_kind: WORKFLOW_DEFINITION_OPERATION_KIND.to_string(),
        action,
        disposition,
        workflow_id,
        scope: ProfileSourceScope::Global,
        repository_key: context.repository_key().to_string(),
        workspace_key: context.workspace_key().to_string(),
        source_history_id,
        source_history_digest,
        definition_before,
        expected_revision,
        expected_owner,
        definition_after,
        definition_digest,
        pre_state_fingerprint,
        post_state_fingerprint,
        plan_fingerprint: String::new(),
        activation: EffectActivation::NextSessionOnly,
        human_approval_required: true,
    };
    plan.plan_fingerprint = plan.fingerprint()?;
    plan.operation_id = operation_id(&plan.plan_fingerprint);
    plan.verify()?;
    Ok(plan)
}

fn definition_digest(
    definition: Option<&WorkflowDefinition>,
) -> Result<Option<String>, WorkflowDefinitionControlError> {
    definition
        .map(|definition| definition.definition_digest().map_err(Into::into))
        .transpose()
}

fn state_fingerprint(
    definition: Option<&WorkflowDefinition>,
    revision: Option<&StateRevision>,
    owner: Option<&OwnerGeneration>,
) -> Result<String, WorkflowDefinitionControlError> {
    hash_serialized(&(definition, revision, owner))
}

fn target_fingerprint(
    definition: Option<&WorkflowDefinition>,
) -> Result<String, WorkflowDefinitionControlError> {
    hash_serialized(&("workflow-definition-target-v1", definition))
}

fn hash_serialized(value: &impl Serialize) -> Result<String, WorkflowDefinitionControlError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| WorkflowDefinitionControlError::Serialization(error.to_string()))?;
    Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
}

fn operation_id(plan_fingerprint: &str) -> String {
    format!("workflow-definition-{}", &plan_fingerprint[..24])
}

fn history_id(plan_fingerprint: &str) -> String {
    format!("workflow-history-{}", &plan_fingerprint[..32])
}

fn snapshot_matches_history_state(
    snapshot: Option<&StateSnapshot<WorkflowDefinition>>,
    definition: Option<&WorkflowDefinition>,
    revision: Option<&StateRevision>,
    owner: Option<&OwnerGeneration>,
) -> bool {
    match (snapshot, definition, revision, owner) {
        (None, None, None, None) => true,
        (Some(snapshot), Some(definition), Some(revision), Some(owner)) => {
            snapshot.value == *definition
                && snapshot.revision == *revision
                && snapshot.owner == *owner
        }
        _ => false,
    }
}

fn history_matches_plan(
    history: &WorkflowDefinitionHistoryRecord,
    plan: &WorkflowDefinitionPlan,
) -> bool {
    matches!(
        history.lifecycle,
        WorkflowDefinitionHistoryLifecycle::Committed
            | WorkflowDefinitionHistoryLifecycle::Prepared
    ) && history.operation_id == plan.operation_id
        && history.plan_fingerprint == plan.plan_fingerprint
        && history.action == plan.action
        && history.workflow_id == plan.workflow_id
        && history.repository_key == plan.repository_key
        && history.workspace_key == plan.workspace_key
        && history.source_history_id == plan.source_history_id
        && history.definition_before == plan.definition_before
        && history.revision_before == plan.expected_revision
        && history.owner_before == plan.expected_owner
        && history.definition_after == plan.definition_after
}

fn result_for(
    plan: &WorkflowDefinitionPlan,
    history: Option<WorkflowDefinitionHistoryRecord>,
    current: Option<StateSnapshot<WorkflowDefinition>>,
    cached: bool,
) -> WorkflowDefinitionMutationResult {
    WorkflowDefinitionMutationResult {
        action: plan.action,
        workflow_id: plan.workflow_id.clone(),
        status: if plan.disposition == WorkflowDefinitionDisposition::NoOp {
            WorkflowDefinitionApplyStatus::NoOp
        } else {
            WorkflowDefinitionApplyStatus::Applied
        },
        activation: plan.activation,
        cached,
        history_id: history.map(|history| history.history_id),
        revision: current.as_ref().map(|snapshot| snapshot.revision.clone()),
        definition: current.map(|snapshot| snapshot.value),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowDefinitionErrorClass {
    Blocked,
    ReplanRequired,
    RecoveryRequired,
}

#[derive(Debug)]
pub enum WorkflowDefinitionControlError {
    Approval(ApprovalError),
    Durable(DurableControlError),
    Store(WorkflowStoreError),
    History(WorkflowDefinitionHistoryError),
    TransitionPlan(TransitionPlanError),
    Validation(super::WorkflowValidationError),
    BackupAuthenticationRequired,
    OwnershipEvidenceRequired(String),
    HistoryNotFound(String),
    HistoryStateMismatch(String),
    ContextMismatch,
    InvalidPlan,
    PlanFingerprintMismatch,
    PlanDrift,
    RecoveryRequired(String),
    Serialization(String),
}

impl WorkflowDefinitionControlError {
    #[must_use]
    pub const fn class(&self) -> WorkflowDefinitionErrorClass {
        match self {
            Self::PlanDrift | Self::PlanFingerprintMismatch => {
                WorkflowDefinitionErrorClass::ReplanRequired
            }
            Self::History(_)
            | Self::HistoryStateMismatch(_)
            | Self::RecoveryRequired(_)
            | Self::Durable(DurableControlError::RecoveryRequired(_))
            | Self::Durable(DurableControlError::TerminalOutcomeUnavailable(_))
            | Self::Durable(DurableControlError::Journal(_))
            | Self::Durable(DurableControlError::State(_)) => {
                WorkflowDefinitionErrorClass::RecoveryRequired
            }
            _ => WorkflowDefinitionErrorClass::Blocked,
        }
    }
}

impl From<ApprovalError> for WorkflowDefinitionControlError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<DurableControlError> for WorkflowDefinitionControlError {
    fn from(error: DurableControlError) -> Self {
        Self::Durable(error)
    }
}

impl From<WorkflowStoreError> for WorkflowDefinitionControlError {
    fn from(error: WorkflowStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<WorkflowDefinitionHistoryError> for WorkflowDefinitionControlError {
    fn from(error: WorkflowDefinitionHistoryError) -> Self {
        Self::History(error)
    }
}

impl From<TransitionPlanError> for WorkflowDefinitionControlError {
    fn from(error: TransitionPlanError) -> Self {
        Self::TransitionPlan(error)
    }
}

impl From<super::WorkflowValidationError> for WorkflowDefinitionControlError {
    fn from(error: super::WorkflowValidationError) -> Self {
        Self::Validation(error)
    }
}

impl fmt::Display for WorkflowDefinitionControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Durable(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::History(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::BackupAuthenticationRequired => formatter
                .write_str("backup authentication key is required for workflow definition history"),
            Self::OwnershipEvidenceRequired(id) => write!(
                formatter,
                "workflow definition {id:?} is absent and has no authenticated ownership tombstone"
            ),
            Self::HistoryNotFound(id) => write!(formatter, "workflow history not found: {id}"),
            Self::HistoryStateMismatch(id) => write!(
                formatter,
                "workflow history state no longer matches the current definition: {id}"
            ),
            Self::ContextMismatch => {
                formatter.write_str("workflow definition plan context does not match workspace")
            }
            Self::InvalidPlan => formatter.write_str("workflow definition plan is invalid"),
            Self::PlanFingerprintMismatch => formatter
                .write_str("workflow definition plan fingerprint does not match its contents"),
            Self::PlanDrift => {
                formatter.write_str("reviewed workflow definition plan no longer matches state")
            }
            Self::RecoveryRequired(operation_id) => {
                write!(
                    formatter,
                    "workflow definition recovery required: {operation_id}"
                )
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "workflow definition plan serialization failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for WorkflowDefinitionControlError {}
