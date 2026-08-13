use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    profiles::ProfileSourceScope,
    providers::ProviderId,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

use super::lease::{
    SessionAuthorityKey, constant_time_equal, validate_digest, validate_identifier,
};
use super::{
    LeaseSnapshot, PinnedExposure, PinnedProfile, SessionHandle, SessionManager, WorkflowJournal,
    WorkflowOperationLifecycle, WorkflowOperationRecord,
};

pub const WORKFLOW_PROPOSAL_SCHEMA_VERSION: u32 = 1;
pub const WORKFLOW_HIGH_WATER_SCHEMA_VERSION: u32 = 1;
const AUTHENTICATION_ALGORITHM: &str = "hmac-sha256";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowTransitionRequest {
    pub operation_id: String,
    pub operation_fingerprint: String,
    pub source_state_sequence: u64,
    pub target_mode: String,
    pub requested_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowTransitionResult {
    pub operation_id: String,
    pub lifecycle: WorkflowOperationLifecycle,
    pub reason_code: String,
    pub previous_mode: String,
    pub desired_mode: String,
    pub previous_exposure_revision: String,
    pub desired_exposure_revision: String,
    pub lease_state_sequence: u64,
    pub next_action: String,
}

pub struct WorkflowRouter {
    sessions: SessionManager,
    journal: WorkflowJournal,
}

impl WorkflowRouter {
    #[must_use]
    pub fn new(sessions: SessionManager) -> Self {
        let journal = WorkflowJournal::new(sessions.app_state_root());
        Self { sessions, journal }
    }

    pub fn enter_mode(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        request: WorkflowTransitionRequest,
    ) -> Result<WorkflowTransitionResult, WorkflowRouterError> {
        self.enter_mode_with_timing(handle, expected, request, false)
    }

    pub(crate) fn enter_mode_next_session_only(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        request: WorkflowTransitionRequest,
    ) -> Result<WorkflowTransitionResult, WorkflowRouterError> {
        self.enter_mode_with_timing(handle, expected, request, true)
    }

    fn enter_mode_with_timing(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        request: WorkflowTransitionRequest,
        next_session_only: bool,
    ) -> Result<WorkflowTransitionResult, WorkflowRouterError> {
        validate_identifier("workflow operation id", &request.operation_id)?;
        validate_identifier("workflow mode", &request.target_mode)?;
        validate_digest(
            "workflow operation fingerprint",
            &request.operation_fingerprint,
        )?;
        let current = self.sessions.load_for_handle(handle)?;
        if current.revision != *expected || request.source_state_sequence != expected.sequence {
            return Err(WorkflowRouterError::StaleOperation);
        }
        let workflow = current
            .lease
            .workflow
            .as_deref()
            .ok_or(WorkflowRouterError::WorkflowNotPinned)?;
        let existing = self
            .journal
            .load(handle.session_id(), &request.operation_id)?;
        let exact_proposed_retry = existing.as_ref().is_some_and(|snapshot| {
            let record = &snapshot.value;
            record.lifecycle == WorkflowOperationLifecycle::Proposed
                && record.kind == super::WorkflowOperationKind::Transition
                && record.source_state_sequence == expected.sequence
                && record.target_state_sequence == expected.sequence + 1
                && record.operation_fingerprint == request.operation_fingerprint
                && record.source_mode.as_deref() == Some(workflow.active_mode.as_str())
                && record.target_mode.as_deref() == Some(request.target_mode.as_str())
        });
        if current.lease.desired_exposure != current.lease.observed_exposure
            || self.journal.has_nonterminal_except(
                handle.session_id(),
                exact_proposed_retry.then_some(request.operation_id.as_str()),
            )?
        {
            return Err(WorkflowRouterError::TransitionInProgress);
        }
        if existing.is_some() && !exact_proposed_retry {
            return Err(WorkflowRouterError::TransitionInProgress);
        }
        let previous_mode = workflow.active_mode.clone();
        let previous_exposure_revision = current.lease.observed_exposure.revision.clone();
        let Some(target_profile_digest) = workflow.profile_revisions.get(&request.target_mode)
        else {
            self.record_denial(handle, &current, &request)?;
            return Err(WorkflowRouterError::ExpansionRequiresOperatorReview);
        };
        let target_exposure = resolved_mode_exposure(
            workflow,
            &request.target_mode,
            target_profile_digest,
            current.lease.desired_exposure.capability_locks.clone(),
        );
        if previous_mode == request.target_mode {
            return Ok(WorkflowTransitionResult {
                operation_id: request.operation_id,
                lifecycle: WorkflowOperationLifecycle::Observed,
                reason_code: "workflow-mode-already-active".to_string(),
                previous_mode: previous_mode.clone(),
                desired_mode: previous_mode,
                previous_exposure_revision: previous_exposure_revision.clone(),
                desired_exposure_revision: previous_exposure_revision,
                lease_state_sequence: current.revision.sequence,
                next_action: "none".to_string(),
            });
        }
        let mut record = WorkflowOperationRecord {
            schema_version: super::WORKFLOW_OPERATION_SCHEMA_VERSION,
            session_id: handle.session_id().to_string(),
            operation_id: request.operation_id.clone(),
            kind: super::WorkflowOperationKind::Transition,
            lifecycle: WorkflowOperationLifecycle::Proposed,
            reason_code: "workflow-transition-requested".to_string(),
            source_state_sequence: expected.sequence,
            target_state_sequence: expected.sequence + 1,
            operation_fingerprint: request.operation_fingerprint,
            source_mode: Some(previous_mode.clone()),
            target_mode: Some(request.target_mode.clone()),
            created_at_unix: request.requested_at_unix,
            terminal_at_unix: None,
        };
        let owner = OwnerGeneration::new(handle.owner_id(), expected.sequence)?;
        let journal_revision = if let Some(existing) = existing {
            existing.revision
        } else {
            self.journal
                .compare_and_swap(&record, None, owner.clone())?
        };
        let updated = if next_session_only {
            self.sessions.defer_workflow_mode_to_next_session(
                handle,
                expected,
                &previous_mode,
                request.requested_at_unix,
            )?
        } else {
            self.sessions.update_workflow_mode(
                handle,
                expected,
                &request.target_mode,
                target_exposure.clone(),
                request.requested_at_unix,
            )?
        };
        record.lifecycle = WorkflowOperationLifecycle::Staged;
        record.reason_code = "workflow-transition-staged".to_string();
        record.target_state_sequence = updated.revision.sequence;
        self.journal.compare_and_swap(
            &record,
            Some(&journal_revision),
            OwnerGeneration::new(handle.owner_id(), expected.sequence + 1)?,
        )?;
        Ok(WorkflowTransitionResult {
            operation_id: request.operation_id,
            lifecycle: WorkflowOperationLifecycle::Staged,
            reason_code: "workflow-transition-staged".to_string(),
            previous_mode,
            desired_mode: request.target_mode,
            previous_exposure_revision,
            desired_exposure_revision: target_exposure.revision,
            lease_state_sequence: updated.revision.sequence,
            next_action: if next_session_only {
                "start-new-session-or-cancel-transition".to_string()
            } else {
                "observe-or-cancel-transition".to_string()
            },
        })
    }

    fn record_denial(
        &self,
        handle: &SessionHandle,
        current: &LeaseSnapshot,
        request: &WorkflowTransitionRequest,
    ) -> Result<(), WorkflowRouterError> {
        let binding = serde_json::to_vec(&(
            handle.session_id(),
            current.revision.sequence,
            &request.operation_fingerprint,
        ))?;
        let record = WorkflowOperationRecord {
            schema_version: super::WORKFLOW_OPERATION_SCHEMA_VERSION,
            session_id: handle.session_id().to_string(),
            operation_id: format!(
                "workflow-denial-{}",
                &domain_digest(b"unpin.workflow.denial-id.v1", &binding)[..24]
            ),
            kind: super::WorkflowOperationKind::Denial,
            lifecycle: WorkflowOperationLifecycle::Denied,
            reason_code: "workflow-envelope-expansion-review-required".to_string(),
            source_state_sequence: current.revision.sequence,
            target_state_sequence: current.revision.sequence,
            operation_fingerprint: domain_digest(b"unpin.workflow.denial.v1", &binding),
            source_mode: None,
            target_mode: None,
            created_at_unix: request.requested_at_unix,
            terminal_at_unix: Some(request.requested_at_unix),
        };
        self.journal.compare_and_swap(
            &record,
            None,
            OwnerGeneration::new(handle.owner_id(), current.revision.sequence)?,
        )?;
        Ok(())
    }

    pub fn cancel_transition(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, WorkflowRouterError> {
        let current = self.sessions.load_for_handle(handle)?;
        if current.revision != *expected {
            return Err(WorkflowRouterError::StaleOperation);
        }
        let operation = self
            .journal
            .load(handle.session_id(), operation_id)?
            .ok_or(WorkflowRouterError::OperationNotFound)?;
        if operation.value.lifecycle == WorkflowOperationLifecycle::Cancelled {
            return Ok(current);
        }
        if !matches!(
            operation.value.lifecycle,
            WorkflowOperationLifecycle::Proposed | WorkflowOperationLifecycle::Staged
        ) {
            return Err(WorkflowRouterError::OperationNotCancellable);
        }
        let workflow = current
            .lease
            .workflow
            .as_deref()
            .ok_or(WorkflowRouterError::WorkflowNotPinned)?;
        let source_mode = operation
            .value
            .source_mode
            .clone()
            .ok_or(WorkflowRouterError::OperationBindingMismatch)?;
        let target_mode = operation
            .value
            .target_mode
            .clone()
            .ok_or(WorkflowRouterError::OperationBindingMismatch)?;
        if operation.value.session_id != handle.session_id()
            || operation.value.source_state_sequence >= operation.value.target_state_sequence
            || operation.value.target_state_sequence > current.revision.sequence
        {
            return Err(WorkflowRouterError::OperationBindingMismatch);
        }
        if current.lease.desired_exposure == current.lease.observed_exposure {
            if workflow.active_mode != source_mode {
                return Err(WorkflowRouterError::OperationBindingMismatch);
            }
            let current = if current.lease.live_status == super::LiveExposureStatus::NextSessionOnly
            {
                self.sessions
                    .restore_observed_exposure(handle, &current.revision, now_unix)?
            } else {
                current
            };
            let mut terminal = operation.value;
            terminal.lifecycle = WorkflowOperationLifecycle::Cancelled;
            terminal.reason_code = "workflow-transition-cancelled".to_string();
            terminal.target_state_sequence = current.revision.sequence;
            terminal.terminal_at_unix = Some(now_unix);
            self.journal.compare_and_swap(
                &terminal,
                Some(&operation.revision),
                OwnerGeneration::new(handle.owner_id(), current.revision.sequence)?,
            )?;
            return Ok(current);
        }
        if workflow.active_mode != target_mode
            || !transition_binding_matches_current_lease(&operation.value, &current)
            || current.lease.admission_open
        {
            return Err(WorkflowRouterError::OperationBindingMismatch);
        }
        let restored = self.sessions.cancel_workflow_transition(
            handle,
            expected,
            &source_mode,
            current.lease.observed_exposure.clone(),
            now_unix,
        )?;
        let mut terminal = operation.value;
        terminal.lifecycle = WorkflowOperationLifecycle::Cancelled;
        terminal.reason_code = "workflow-transition-cancelled".to_string();
        terminal.target_state_sequence = restored.revision.sequence;
        terminal.terminal_at_unix = Some(now_unix);
        self.journal.compare_and_swap(
            &terminal,
            Some(&operation.revision),
            OwnerGeneration::new(handle.owner_id(), restored.revision.sequence)?,
        )?;
        Ok(restored)
    }
}

fn transition_binding_matches_current_lease(
    operation: &WorkflowOperationRecord,
    current: &LeaseSnapshot,
) -> bool {
    let expected_target_revision = current.lease.workflow.as_ref().and_then(|workflow| {
        operation
            .target_mode
            .as_deref()
            .and_then(|mode| workflow.profile_revisions.get(mode))
    });
    current.revision.sequence >= operation.target_state_sequence
        && current.lease.lifecycle == super::LeaseLifecycle::Active
        && expected_target_revision == Some(&current.lease.desired_exposure.revision)
        && current.lease.desired_exposure != current.lease.observed_exposure
        && current.lease.workspace_start_revision == current.lease.last_workspace_revision
        && !current.lease.workspace_drifted
        && matches!(
            current.lease.live_status,
            super::LiveExposureStatus::Configured
                | super::LiveExposureStatus::NotificationSent
                | super::LiveExposureStatus::ReloadRequired
        )
}

pub fn resolved_mode_exposure(
    workflow: &super::PinnedWorkflowEnvelope,
    target_mode: &str,
    target_profile_digest: &str,
    capability_locks: Option<Box<crate::profiles::CapabilityLockSnapshot>>,
) -> PinnedExposure {
    PinnedExposure {
        revision: target_profile_digest.to_string(),
        profile: PinnedProfile::Profile {
            profile_id: format!("{}.{}", workflow.workflow_id, target_mode),
            profile_digest: target_profile_digest.to_string(),
            origin_scope: ProfileSourceScope::Session,
            definition_digest: workflow.workflow_revision.clone(),
        },
        capability_locks,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowReloadLimitation {
    LiveRefreshExpected,
    ReloadRequired,
    RefreshUnconfirmed,
    NextSessionOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowProposalV1 {
    pub schema_version: u32,
    pub proposal_id: String,
    pub proposal_fingerprint: String,
    pub workflow_id: String,
    pub entry_mode: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub catalog_revision: String,
    pub workflow_revision: String,
    pub prompt_digest: String,
    pub capability_count: usize,
    pub gateway_required: bool,
    pub reload_limitation: WorkflowReloadLimitation,
    pub approval_expectation: String,
    pub next_action: String,
}

impl WorkflowProposalV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_id: impl Into<String>,
        entry_mode: impl Into<String>,
        provider: ProviderId,
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        catalog_revision: impl Into<String>,
        workflow_revision: impl Into<String>,
        opening_prompt: impl AsRef<[u8]>,
        capability_count: usize,
        gateway_required: bool,
        reload_limitation: WorkflowReloadLimitation,
    ) -> Result<Self, WorkflowRouterError> {
        let workflow_id = workflow_id.into();
        let entry_mode = entry_mode.into();
        let repository_key = repository_key.into();
        let workspace_key = workspace_key.into();
        let catalog_revision = catalog_revision.into();
        let workflow_revision = workflow_revision.into();
        validate_identifier("workflow id", &workflow_id)?;
        validate_identifier("workflow mode", &entry_mode)?;
        validate_identifier("repository key", &repository_key)?;
        validate_identifier("workspace key", &workspace_key)?;
        validate_digest("catalog revision", &catalog_revision)?;
        validate_digest("workflow revision", &workflow_revision)?;
        let opening_prompt = opening_prompt.as_ref();
        if opening_prompt.is_empty() || opening_prompt.len() > 16 * 1024 {
            return Err(WorkflowRouterError::InvalidProposal);
        }
        let prompt_digest = domain_digest(b"unpin.workflow.prompt.v1", opening_prompt);
        let proposal_id = format!(
            "workflow-proposal-{}",
            &domain_digest(
                b"unpin.workflow.proposal-id.v1",
                &serde_json::to_vec(&(
                    &workflow_id,
                    &entry_mode,
                    provider,
                    &repository_key,
                    &workspace_key,
                    &catalog_revision,
                    &workflow_revision,
                    &prompt_digest,
                ))?,
            )[..24]
        );
        let fingerprint = domain_digest(
            b"unpin.workflow.proposal.v1",
            &serde_json::to_vec(&(
                WORKFLOW_PROPOSAL_SCHEMA_VERSION,
                &proposal_id,
                &workflow_id,
                &entry_mode,
                provider,
                &repository_key,
                &workspace_key,
                &catalog_revision,
                &workflow_revision,
                &prompt_digest,
                capability_count,
                gateway_required,
                reload_limitation,
            ))?,
        );
        Ok(Self {
            schema_version: WORKFLOW_PROPOSAL_SCHEMA_VERSION,
            proposal_id,
            proposal_fingerprint: fingerprint,
            workflow_id,
            entry_mode,
            provider,
            repository_key,
            workspace_key,
            catalog_revision,
            workflow_revision,
            prompt_digest,
            capability_count,
            gateway_required,
            reload_limitation,
            approval_expectation: "explicit-confirmation-required".to_string(),
            next_action: "confirm-workflow-session".to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingWorkflowHighWater {
    pub source_lease_revision: StateRevision,
    pub source_lease_authentication_tag: String,
    pub target_lease_schema_version: u32,
    pub target_state_sequence: u64,
    pub target_sealed_generation: u64,
    pub target_lease_authentication_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowHighWater {
    pub session_id: String,
    pub lease_schema_version: u32,
    pub state_sequence: u64,
    pub sealed_generation: u64,
    pub lease_authentication_tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Box<PendingWorkflowHighWater>>,
    pub authentication_algorithm: String,
    pub authority_key_id: String,
    pub authentication_tag: String,
}

impl WorkflowHighWater {
    pub fn new(
        session_id: impl Into<String>,
        lease_schema_version: u32,
        state_sequence: u64,
        sealed_generation: u64,
        lease_authentication_tag: impl Into<String>,
    ) -> Result<Self, WorkflowRouterError> {
        let value = Self {
            session_id: session_id.into(),
            lease_schema_version,
            state_sequence,
            sealed_generation,
            lease_authentication_tag: lease_authentication_tag.into(),
            pending: None,
            authentication_algorithm: String::new(),
            authority_key_id: String::new(),
            authentication_tag: String::new(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn prepare_transition(
        mut self,
        source_lease_revision: StateRevision,
        source_lease_authentication_tag: String,
        target_lease_schema_version: u32,
        target_state_sequence: u64,
        target_sealed_generation: u64,
        target_lease_authentication_tag: String,
    ) -> Result<Self, WorkflowRouterError> {
        self.pending = Some(Box::new(PendingWorkflowHighWater {
            source_lease_revision,
            source_lease_authentication_tag,
            target_lease_schema_version,
            target_state_sequence,
            target_sealed_generation,
            target_lease_authentication_tag,
        }));
        self.validate_shape()?;
        Ok(self)
    }

    pub fn finalized_target(&self) -> Result<Self, WorkflowRouterError> {
        let pending = self
            .pending
            .as_deref()
            .ok_or(WorkflowRouterError::InvalidHighWater)?;
        Self::new(
            &self.session_id,
            pending.target_lease_schema_version,
            pending.target_state_sequence,
            pending.target_sealed_generation,
            &pending.target_lease_authentication_tag,
        )
    }

    fn validate_shape(&self) -> Result<(), WorkflowRouterError> {
        validate_identifier("session id", &self.session_id)?;
        if self.lease_schema_version == 0 || self.state_sequence == 0 || self.sealed_generation == 0
        {
            return Err(WorkflowRouterError::InvalidHighWater);
        }
        validate_digest(
            "workflow high-water lease authentication tag",
            &self.lease_authentication_tag,
        )?;
        if let Some(pending) = &self.pending {
            validate_digest(
                "source lease revision fingerprint",
                pending
                    .source_lease_revision
                    .fingerprint
                    .strip_prefix("sha256:")
                    .ok_or(WorkflowRouterError::InvalidHighWater)?,
            )?;
            validate_digest(
                "source lease authentication tag",
                &pending.source_lease_authentication_tag,
            )?;
            validate_digest(
                "target lease authentication tag",
                &pending.target_lease_authentication_tag,
            )?;
            if pending.source_lease_revision.sequence == 0
                || pending.target_lease_schema_version == 0
                || pending.target_state_sequence < self.state_sequence
                || pending.target_sealed_generation < self.sealed_generation
            {
                return Err(WorkflowRouterError::InvalidHighWater);
            }
        }
        Ok(())
    }

    fn authentication_message(&self) -> Result<Vec<u8>, WorkflowRouterError> {
        Ok(serde_json::to_vec(&(
            &self.session_id,
            self.lease_schema_version,
            self.state_sequence,
            self.sealed_generation,
            &self.lease_authentication_tag,
            &self.pending,
            &self.authentication_algorithm,
            &self.authority_key_id,
        ))?)
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowHighWaterStore {
    app_state_root: PathBuf,
    authentication_key: SessionAuthorityKey,
}

impl WorkflowHighWaterStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>, authentication_key: [u8; 32]) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            authentication_key: SessionAuthorityKey::new(authentication_key),
        }
    }

    pub(crate) fn with_authority_key(
        app_state_root: impl Into<PathBuf>,
        authentication_key: SessionAuthorityKey,
    ) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            authentication_key,
        }
    }

    pub fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<StateSnapshot<WorkflowHighWater>>, WorkflowHighWaterError> {
        validate_identifier("session id", session_id).map_err(WorkflowRouterError::from)?;
        let snapshot = self.store(session_id).load::<WorkflowHighWater>()?;
        if let Some(snapshot) = &snapshot {
            if snapshot.value.session_id != session_id {
                return Err(WorkflowHighWaterError::SessionMismatch);
            }
            self.verify(&snapshot.value)?;
        }
        Ok(snapshot)
    }

    pub fn publish(
        &self,
        session_id: &str,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
        mut value: WorkflowHighWater,
    ) -> Result<StateRevision, WorkflowHighWaterError> {
        if value.session_id != session_id {
            return Err(WorkflowHighWaterError::SessionMismatch);
        }
        value
            .validate_shape()
            .map_err(WorkflowHighWaterError::from)?;
        let current = self.load(session_id)?;
        if current.as_ref().map(|snapshot| &snapshot.revision) != expected {
            return Err(StateError::StaleRevision {
                expected: expected.cloned(),
                actual: current.map(|snapshot| snapshot.revision),
            }
            .into());
        }
        if let Some(current) = current.as_ref().map(|snapshot| &snapshot.value) {
            let moving_forward = value.lease_schema_version >= current.lease_schema_version
                && value.state_sequence >= current.state_sequence
                && value.sealed_generation >= current.sealed_generation;
            let clearing_pending = current.pending.is_some()
                && value.pending.is_none()
                && value.lease_schema_version == current.lease_schema_version
                && value.state_sequence == current.state_sequence
                && value.sealed_generation == current.sealed_generation
                && value.lease_authentication_tag == current.lease_authentication_tag;
            let finalizing_pending = current.pending.as_deref().is_some_and(|pending| {
                value.pending.is_none()
                    && value.lease_schema_version == pending.target_lease_schema_version
                    && value.state_sequence == pending.target_state_sequence
                    && value.sealed_generation == pending.target_sealed_generation
                    && value.lease_authentication_tag == pending.target_lease_authentication_tag
            });
            if !moving_forward
                || (current.pending.is_some() && !clearing_pending && !finalizing_pending)
            {
                return Err(WorkflowHighWaterError::Replay);
            }
        }
        self.seal(&mut value)?;
        self.store(session_id)
            .compare_and_swap(expected, owner, &value)
            .map_err(Into::into)
    }

    pub fn remove_if_revision(
        &self,
        session_id: &str,
        expected: &StateRevision,
    ) -> Result<(), WorkflowHighWaterError> {
        validate_identifier("session id", session_id).map_err(WorkflowRouterError::from)?;
        self.store(session_id)
            .remove_if_revision(expected)
            .map_err(Into::into)
    }

    fn store(&self, session_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.app_state_root
                .join("sessions")
                .join("workflow-high-water")
                .join(format!("{}.json", crate::encode_path_segment(session_id))),
            WORKFLOW_HIGH_WATER_SCHEMA_VERSION,
        )
    }

    fn seal(&self, value: &mut WorkflowHighWater) -> Result<(), WorkflowHighWaterError> {
        value.authentication_algorithm = AUTHENTICATION_ALGORITHM.to_string();
        value.authority_key_id = self.key_id();
        value.authentication_tag.clear();
        value.authentication_tag = self.authenticate(&value.authentication_message()?)?;
        Ok(())
    }

    fn verify(&self, value: &WorkflowHighWater) -> Result<(), WorkflowHighWaterError> {
        value.validate_shape()?;
        if value.authentication_algorithm != AUTHENTICATION_ALGORITHM
            || value.authority_key_id != self.key_id()
        {
            return Err(WorkflowHighWaterError::AuthenticationFailed);
        }
        let expected = self.authenticate(&value.authentication_message()?)?;
        if constant_time_equal(expected.as_bytes(), value.authentication_tag.as_bytes()) {
            Ok(())
        } else {
            Err(WorkflowHighWaterError::AuthenticationFailed)
        }
    }

    fn key_id(&self) -> String {
        self.authentication_key.key_id()
    }

    fn authenticate(&self, message: &[u8]) -> Result<String, WorkflowHighWaterError> {
        self.authentication_key
            .authenticate_workflow_high_water(message)
            .map_err(|_| WorkflowHighWaterError::AuthenticationFailed)
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    crate::encode_lower_hex(&hasher.finalize())
}

#[derive(Debug)]
pub enum WorkflowRouterError {
    InvalidProposal,
    InvalidHighWater,
    StaleOperation,
    WorkflowNotPinned,
    TransitionInProgress,
    ExpansionRequiresOperatorReview,
    OperationNotFound,
    OperationNotCancellable,
    OperationBindingMismatch,
    Session(String),
    Journal(String),
    State(String),
    Lease(String),
    Serialization(String),
}

impl From<super::lease::LeaseValidationError> for WorkflowRouterError {
    fn from(error: super::lease::LeaseValidationError) -> Self {
        Self::Lease(error.to_string())
    }
}

impl From<serde_json::Error> for WorkflowRouterError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

impl From<super::LeaseError> for WorkflowRouterError {
    fn from(error: super::LeaseError) -> Self {
        Self::Session(error.to_string())
    }
}

impl From<super::WorkflowJournalError> for WorkflowRouterError {
    fn from(error: super::WorkflowJournalError) -> Self {
        Self::Journal(error.to_string())
    }
}

impl From<StateError> for WorkflowRouterError {
    fn from(error: StateError) -> Self {
        Self::State(error.to_string())
    }
}

impl fmt::Display for WorkflowRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProposal => formatter.write_str("invalid workflow proposal"),
            Self::InvalidHighWater => formatter.write_str("invalid workflow high-water record"),
            Self::StaleOperation => formatter.write_str("workflow operation is stale"),
            Self::WorkflowNotPinned => formatter.write_str("session workflow is not pinned"),
            Self::TransitionInProgress => {
                formatter.write_str("workflow transition is already in progress")
            }
            Self::ExpansionRequiresOperatorReview => {
                formatter.write_str("workflow expansion requires operator review")
            }
            Self::OperationNotFound => formatter.write_str("workflow operation not found"),
            Self::OperationNotCancellable => {
                formatter.write_str("workflow operation is not cancellable")
            }
            Self::OperationBindingMismatch => {
                formatter.write_str("workflow operation binding does not match session state")
            }
            Self::Session(message)
            | Self::Journal(message)
            | Self::State(message)
            | Self::Lease(message)
            | Self::Serialization(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for WorkflowRouterError {}

#[derive(Debug)]
pub enum WorkflowHighWaterError {
    State(StateError),
    Router(WorkflowRouterError),
    AuthenticationFailed,
    SessionMismatch,
    Replay,
}

impl From<StateError> for WorkflowHighWaterError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<WorkflowRouterError> for WorkflowHighWaterError {
    fn from(error: WorkflowRouterError) -> Self {
        Self::Router(error)
    }
}

impl fmt::Display for WorkflowHighWaterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Router(error) => error.fmt(formatter),
            Self::AuthenticationFailed => {
                formatter.write_str("workflow high-water authentication failed")
            }
            Self::SessionMismatch => formatter.write_str("workflow high-water session mismatch"),
            Self::Replay => formatter.write_str("workflow state replay rejected"),
        }
    }
}

impl std::error::Error for WorkflowHighWaterError {}
