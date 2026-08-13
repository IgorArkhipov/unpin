use std::{fmt, fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    mutation::BackupAuthenticationKey,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
};

use super::{WorkflowDefinition, WorkflowDefinitionAction};

const WORKFLOW_DEFINITION_HISTORY_SCHEMA_VERSION: u32 = 1;
const WORKFLOW_DEFINITION_HISTORY_AUTHENTICATION_PURPOSE: &[u8] =
    b"unpin-workflow-definition-history-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowDefinitionHistoryLifecycle {
    Prepared,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinitionHistoryRecord {
    pub schema_version: u32,
    pub history_id: String,
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub action: WorkflowDefinitionAction,
    pub lifecycle: WorkflowDefinitionHistoryLifecycle,
    pub workflow_id: String,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_history_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_before: Option<WorkflowDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_before: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_before: Option<OwnerGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_after: Option<WorkflowDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_after: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_after: Option<OwnerGeneration>,
    pub authentication_key_id: String,
    pub integrity_digest: String,
}

impl WorkflowDefinitionHistoryRecord {
    pub(super) fn prepared(input: WorkflowDefinitionHistoryPrepared) -> Self {
        Self {
            schema_version: WORKFLOW_DEFINITION_HISTORY_SCHEMA_VERSION,
            history_id: input.history_id,
            operation_id: input.operation_id,
            plan_fingerprint: input.plan_fingerprint,
            action: input.action,
            lifecycle: WorkflowDefinitionHistoryLifecycle::Prepared,
            workflow_id: input.workflow_id,
            repository_key: input.repository_key,
            workspace_key: input.workspace_key,
            source_history_id: input.source_history_id,
            definition_before: input.definition_before,
            revision_before: input.revision_before,
            owner_before: input.owner_before,
            definition_after: input.definition_after,
            revision_after: None,
            owner_after: None,
            authentication_key_id: String::new(),
            integrity_digest: String::new(),
        }
    }

    pub fn verify(
        &self,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), WorkflowDefinitionHistoryError> {
        if self.schema_version != WORKFLOW_DEFINITION_HISTORY_SCHEMA_VERSION
            || !valid_history_id(&self.history_id)
            || self.operation_id.is_empty()
            || !crate::is_lower_hex_digest(&self.plan_fingerprint)
            || self.workflow_id.is_empty()
            || self.repository_key.is_empty()
            || self.workspace_key.is_empty()
            || self.authentication_key_id != authentication_key.key_id()
            || self
                .definition_before
                .as_ref()
                .is_some_and(|definition| definition.id != self.workflow_id)
            || self
                .definition_after
                .as_ref()
                .is_some_and(|definition| definition.id != self.workflow_id)
            || self.definition_before.is_some() != self.revision_before.is_some()
            || self.definition_before.is_some() != self.owner_before.is_some()
            || self.definition_after.is_none()
                && (self.revision_after.is_some() || self.owner_after.is_some())
            || self.revision_after.is_some() != self.owner_after.is_some()
        {
            return Err(WorkflowDefinitionHistoryError::InvalidRecord);
        }
        if let Some(definition) = self.definition_before.as_ref() {
            definition
                .validate()
                .map_err(|_| WorkflowDefinitionHistoryError::InvalidRecord)?;
        }
        if let Some(definition) = self.definition_after.as_ref() {
            definition
                .validate()
                .map_err(|_| WorkflowDefinitionHistoryError::InvalidRecord)?;
        }
        let mut unsigned = self.clone();
        let tag = std::mem::take(&mut unsigned.integrity_digest);
        let bytes = serde_json::to_vec(&unsigned).map_err(WorkflowDefinitionHistoryError::Json)?;
        authentication_key
            .verify_purpose(
                WORKFLOW_DEFINITION_HISTORY_AUTHENTICATION_PURPOSE,
                &bytes,
                &tag,
            )
            .map_err(|_| WorkflowDefinitionHistoryError::AuthenticationFailed)
    }

    fn seal(
        &mut self,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), WorkflowDefinitionHistoryError> {
        self.authentication_key_id = authentication_key.key_id();
        self.integrity_digest.clear();
        let bytes = serde_json::to_vec(self).map_err(WorkflowDefinitionHistoryError::Json)?;
        self.integrity_digest = authentication_key
            .authenticate_purpose(WORKFLOW_DEFINITION_HISTORY_AUTHENTICATION_PURPOSE, &bytes)
            .map_err(WorkflowDefinitionHistoryError::Authentication)?;
        self.verify(authentication_key)
    }

    pub(super) fn same_transaction(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.history_id == other.history_id
            && self.operation_id == other.operation_id
            && self.plan_fingerprint == other.plan_fingerprint
            && self.action == other.action
            && self.workflow_id == other.workflow_id
            && self.repository_key == other.repository_key
            && self.workspace_key == other.workspace_key
            && self.source_history_id == other.source_history_id
            && self.definition_before == other.definition_before
            && self.revision_before == other.revision_before
            && self.owner_before == other.owner_before
            && self.definition_after == other.definition_after
    }
}

pub(super) struct WorkflowDefinitionHistoryPrepared {
    pub(super) history_id: String,
    pub(super) operation_id: String,
    pub(super) plan_fingerprint: String,
    pub(super) action: WorkflowDefinitionAction,
    pub(super) workflow_id: String,
    pub(super) repository_key: String,
    pub(super) workspace_key: String,
    pub(super) source_history_id: Option<String>,
    pub(super) definition_before: Option<WorkflowDefinition>,
    pub(super) revision_before: Option<StateRevision>,
    pub(super) owner_before: Option<OwnerGeneration>,
    pub(super) definition_after: Option<WorkflowDefinition>,
}

pub(super) struct WorkflowDefinitionHistorySnapshot {
    pub(super) record: WorkflowDefinitionHistoryRecord,
    revision: StateRevision,
    owner: OwnerGeneration,
}

#[derive(Debug, Clone)]
pub(super) struct WorkflowDefinitionHistoryStore {
    root: PathBuf,
    authentication_key: BackupAuthenticationKey,
}

impl WorkflowDefinitionHistoryStore {
    pub(super) fn new(root: PathBuf, authentication_key: BackupAuthenticationKey) -> Self {
        Self {
            root,
            authentication_key,
        }
    }

    pub(super) fn prepare(
        &self,
        record: &WorkflowDefinitionHistoryRecord,
    ) -> Result<WorkflowDefinitionHistorySnapshot, WorkflowDefinitionHistoryError> {
        if record.lifecycle != WorkflowDefinitionHistoryLifecycle::Prepared {
            return Err(WorkflowDefinitionHistoryError::InvalidTransition);
        }
        if let Some(existing) = self.load_snapshot(&record.history_id)? {
            if !existing.record.same_transaction(record) {
                return Err(WorkflowDefinitionHistoryError::TransactionConflict);
            }
            return Ok(existing);
        }
        let mut record = record.clone();
        record.seal(&self.authentication_key)?;
        let owner = OwnerGeneration::new(record.operation_id.clone(), 1)?;
        let revision =
            self.store(&record.history_id)
                .compare_and_swap(None, owner.clone(), &record)?;
        Ok(WorkflowDefinitionHistorySnapshot {
            record,
            revision,
            owner,
        })
    }

    pub(super) fn commit(
        &self,
        snapshot: &WorkflowDefinitionHistorySnapshot,
        revision_after: Option<StateRevision>,
        owner_after: Option<OwnerGeneration>,
    ) -> Result<WorkflowDefinitionHistoryRecord, WorkflowDefinitionHistoryError> {
        if snapshot.record.lifecycle == WorkflowDefinitionHistoryLifecycle::Committed {
            if snapshot.record.revision_after == revision_after
                && snapshot.record.owner_after == owner_after
            {
                return Ok(snapshot.record.clone());
            }
            return Err(WorkflowDefinitionHistoryError::TransactionConflict);
        }
        if snapshot.record.lifecycle != WorkflowDefinitionHistoryLifecycle::Prepared
            || revision_after.is_some() != owner_after.is_some()
            || snapshot.record.definition_after.is_some() != revision_after.is_some()
        {
            return Err(WorkflowDefinitionHistoryError::InvalidTransition);
        }
        let mut record = snapshot.record.clone();
        record.lifecycle = WorkflowDefinitionHistoryLifecycle::Committed;
        record.revision_after = revision_after;
        record.owner_after = owner_after;
        self.finish(snapshot, record)
    }

    pub(super) fn abort(
        &self,
        snapshot: &WorkflowDefinitionHistorySnapshot,
    ) -> Result<WorkflowDefinitionHistoryRecord, WorkflowDefinitionHistoryError> {
        if snapshot.record.lifecycle == WorkflowDefinitionHistoryLifecycle::Aborted {
            return Ok(snapshot.record.clone());
        }
        if snapshot.record.lifecycle != WorkflowDefinitionHistoryLifecycle::Prepared {
            return Err(WorkflowDefinitionHistoryError::InvalidTransition);
        }
        let mut record = snapshot.record.clone();
        record.lifecycle = WorkflowDefinitionHistoryLifecycle::Aborted;
        self.finish(snapshot, record)
    }

    pub(super) fn load_snapshot(
        &self,
        history_id: &str,
    ) -> Result<Option<WorkflowDefinitionHistorySnapshot>, WorkflowDefinitionHistoryError> {
        if !valid_history_id(history_id) {
            return Err(WorkflowDefinitionHistoryError::InvalidHistoryId);
        }
        let Some(snapshot) = self
            .store(history_id)
            .load::<WorkflowDefinitionHistoryRecord>()?
        else {
            return Ok(None);
        };
        snapshot.value.verify(&self.authentication_key)?;
        if snapshot.value.history_id != history_id {
            return Err(WorkflowDefinitionHistoryError::InvalidRecord);
        }
        Ok(Some(WorkflowDefinitionHistorySnapshot {
            record: snapshot.value,
            revision: snapshot.revision,
            owner: snapshot.owner,
        }))
    }

    pub(super) fn load_committed(
        &self,
        history_id: &str,
    ) -> Result<Option<WorkflowDefinitionHistoryRecord>, WorkflowDefinitionHistoryError> {
        Ok(self.load_snapshot(history_id)?.and_then(|snapshot| {
            (snapshot.record.lifecycle == WorkflowDefinitionHistoryLifecycle::Committed)
                .then_some(snapshot.record)
        }))
    }

    pub(super) fn list(
        &self,
    ) -> Result<Vec<WorkflowDefinitionHistoryRecord>, WorkflowDefinitionHistoryError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(WorkflowDefinitionHistoryError::Io(error)),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(WorkflowDefinitionHistoryError::Io)?;
            let file_type = entry
                .file_type()
                .map_err(WorkflowDefinitionHistoryError::Io)?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(WorkflowDefinitionHistoryError::UnsafeEntry);
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
                || path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.starts_with(".env"))
            {
                continue;
            }
            let snapshot = AtomicJsonStore::new(path, WORKFLOW_DEFINITION_HISTORY_SCHEMA_VERSION)
                .load::<WorkflowDefinitionHistoryRecord>()?
                .ok_or(WorkflowDefinitionHistoryError::MissingRecord)?;
            snapshot.value.verify(&self.authentication_key)?;
            if snapshot.value.lifecycle == WorkflowDefinitionHistoryLifecycle::Committed {
                records.push(snapshot.value);
            }
        }
        records.sort_by(|left, right| left.history_id.cmp(&right.history_id));
        Ok(records)
    }

    fn finish(
        &self,
        snapshot: &WorkflowDefinitionHistorySnapshot,
        mut record: WorkflowDefinitionHistoryRecord,
    ) -> Result<WorkflowDefinitionHistoryRecord, WorkflowDefinitionHistoryError> {
        record.seal(&self.authentication_key)?;
        let generation = snapshot
            .owner
            .generation
            .checked_add(1)
            .ok_or(WorkflowDefinitionHistoryError::GenerationOverflow)?;
        let owner = OwnerGeneration::new(snapshot.owner.owner_id.clone(), generation)?;
        self.store(&record.history_id).compare_and_swap(
            Some(&snapshot.revision),
            owner,
            &record,
        )?;
        Ok(record)
    }

    fn store(&self, history_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.root.join(format!("{history_id}.json")),
            WORKFLOW_DEFINITION_HISTORY_SCHEMA_VERSION,
        )
    }
}

fn valid_history_id(value: &str) -> bool {
    value
        .strip_prefix("workflow-history-")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

#[derive(Debug)]
pub enum WorkflowDefinitionHistoryError {
    State(StateError),
    Io(std::io::Error),
    Json(serde_json::Error),
    AuthenticationFailed,
    Authentication(String),
    InvalidHistoryId,
    InvalidRecord,
    InvalidTransition,
    TransactionConflict,
    UnsafeEntry,
    MissingRecord,
    GenerationOverflow,
}

impl From<StateError> for WorkflowDefinitionHistoryError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for WorkflowDefinitionHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "workflow history I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "workflow history JSON failed: {error}"),
            Self::AuthenticationFailed | Self::Authentication(_) => {
                formatter.write_str("workflow history authentication failed")
            }
            Self::InvalidHistoryId => formatter.write_str("workflow history id is invalid"),
            Self::InvalidRecord => formatter.write_str("workflow history record is invalid"),
            Self::InvalidTransition => {
                formatter.write_str("workflow history lifecycle transition is invalid")
            }
            Self::TransactionConflict => {
                formatter.write_str("workflow history transaction conflicts with existing evidence")
            }
            Self::UnsafeEntry => formatter.write_str("workflow history entry is unsafe"),
            Self::MissingRecord => formatter.write_str("workflow history record disappeared"),
            Self::GenerationOverflow => {
                formatter.write_str("workflow history owner generation overflowed")
            }
        }
    }
}

impl std::error::Error for WorkflowDefinitionHistoryError {}
