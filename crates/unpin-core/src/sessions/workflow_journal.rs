use std::{fmt, fs, io, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::state::atomic_json::{
    AtomicJsonStore, OwnerGeneration, StateError, StateResourceLock, StateRevision, StateSnapshot,
};

use super::lease::{validate_digest, validate_identifier};

pub const WORKFLOW_OPERATION_SCHEMA_VERSION: u32 = 1;
pub const WORKFLOW_TERMINAL_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const MAX_WORKFLOW_OPERATION_RECORDS: usize = 1_024;
/// Denials are durable audit evidence, but caller-controlled fingerprints must
/// not be able to exhaust the operation journal. Keep a bounded recent set;
/// active transitions and observations are never evicted for this budget.
pub const MAX_WORKFLOW_DENIAL_RECORDS: usize = 64;
const MAX_WORKFLOW_JOURNAL_ENTRIES: usize =
    MAX_WORKFLOW_OPERATION_RECORDS + MAX_WORKFLOW_DENIAL_RECORDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowOperationKind {
    Transition,
    Cancel,
    Denial,
    Observation,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowOperationLifecycle {
    Proposed,
    Staged,
    Observed,
    Cancelled,
    Denied,
    RecoveryRequired,
}

impl WorkflowOperationLifecycle {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Observed | Self::Cancelled | Self::Denied | Self::RecoveryRequired
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowOperationRecord {
    pub schema_version: u32,
    pub session_id: String,
    pub operation_id: String,
    pub kind: WorkflowOperationKind,
    pub lifecycle: WorkflowOperationLifecycle,
    pub reason_code: String,
    pub source_state_sequence: u64,
    pub target_state_sequence: u64,
    pub operation_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_mode: Option<String>,
    pub created_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at_unix: Option<i64>,
}

impl WorkflowOperationRecord {
    pub fn verify(&self) -> Result<(), WorkflowJournalError> {
        validate_identifier("session id", &self.session_id)?;
        validate_identifier("workflow operation id", &self.operation_id)?;
        validate_identifier("workflow reason code", &self.reason_code)?;
        validate_digest(
            "workflow operation fingerprint",
            &self.operation_fingerprint,
        )?;
        for mode in [&self.source_mode, &self.target_mode].into_iter().flatten() {
            validate_identifier("workflow mode", mode)?;
        }
        if self.schema_version != WORKFLOW_OPERATION_SCHEMA_VERSION
            || self.source_state_sequence == 0
            || self.target_state_sequence < self.source_state_sequence
            || self.lifecycle.is_terminal() != self.terminal_at_unix.is_some()
        {
            return Err(WorkflowJournalError::InvalidRecord);
        }
        Ok(())
    }

    #[must_use]
    pub fn prune_eligible(&self, now_unix: i64, referenced: bool) -> bool {
        !referenced
            && self.lifecycle.is_terminal()
            && self
                .terminal_at_unix
                .and_then(|terminal| now_unix.checked_sub(terminal))
                .is_some_and(|age| age >= WORKFLOW_TERMINAL_RETENTION_SECONDS)
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowJournal {
    app_state_root: PathBuf,
}

impl WorkflowJournal {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn load(
        &self,
        session_id: &str,
        operation_id: &str,
    ) -> Result<Option<StateSnapshot<WorkflowOperationRecord>>, WorkflowJournalError> {
        let snapshot = self
            .store(session_id, operation_id)
            .load::<WorkflowOperationRecord>()?;
        if let Some(snapshot) = &snapshot {
            snapshot.value.verify()?;
            if snapshot.value.session_id != session_id
                || snapshot.value.operation_id != operation_id
            {
                return Err(WorkflowJournalError::PathMismatch);
            }
        }
        Ok(snapshot)
    }

    pub fn compare_and_swap(
        &self,
        record: &WorkflowOperationRecord,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, WorkflowJournalError> {
        record.verify()?;
        let _session_lock = self.session_lock(&record.session_id)?;
        self.compare_and_swap_locked(record, expected, owner)
    }

    fn compare_and_swap_locked(
        &self,
        record: &WorkflowOperationRecord,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, WorkflowJournalError> {
        if let Some(current) = self.load(&record.session_id, &record.operation_id)?
            && current.value.lifecycle.is_terminal()
        {
            // Deterministic terminal records (notably repeated denials) are
            // safe to replay even when the caller has no pre-existing
            // revision. Terminal records remain immutable otherwise.
            if current.value == *record
                && (expected.is_none() || expected == Some(&current.revision))
            {
                return Ok(current.revision);
            }
            return Err(WorkflowJournalError::TerminalMutation);
        }
        let revision = self
            .store(&record.session_id, &record.operation_id)
            .compare_and_swap(expected, owner, record)
            .map_err(WorkflowJournalError::from)?;
        if record.lifecycle.is_terminal() {
            // Retention is best effort. A terminal write must not be reported
            // as failed merely because an unrelated stale record cannot yet
            // be pruned.
            let _ = self.prune_terminal_locked(
                &record.session_id,
                record.terminal_at_unix.unwrap_or_default(),
            );
        }
        Ok(revision)
    }

    /// Persist a denial while reserving journal capacity for workflow
    /// transitions and observations. When a session has more denial records
    /// than its bounded budget, the oldest denial is evicted. No non-denial
    /// record is eligible for this eviction.
    pub fn compare_and_swap_denial(
        &self,
        record: &WorkflowOperationRecord,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, WorkflowJournalError> {
        record.verify()?;
        if record.kind != WorkflowOperationKind::Denial
            || record.lifecycle != WorkflowOperationLifecycle::Denied
        {
            return Err(WorkflowJournalError::InvalidRecord);
        }
        let _session_lock = self.session_lock(&record.session_id)?;
        if self
            .load(&record.session_id, &record.operation_id)?
            .is_none()
        {
            self.reserve_denial_capacity(&record.session_id, &record.operation_id)?;
        }
        self.compare_and_swap_locked(record, expected, owner)
    }

    pub fn has_nonterminal(&self, session_id: &str) -> Result<bool, WorkflowJournalError> {
        self.has_nonterminal_except(session_id, None)
    }

    /// Return the durable operations that still require an owner action.
    /// Callers use this to make cancellation/recovery explicit instead of
    /// guessing from the lease's desired and observed revisions.
    pub fn nonterminal_records(
        &self,
        session_id: &str,
    ) -> Result<Vec<WorkflowOperationRecord>, WorkflowJournalError> {
        validate_identifier("session id", session_id)?;
        let mut records = self
            .nonterminal_snapshots(&self.operation_directory(session_id), session_id)?
            .unwrap_or_default()
            .into_iter()
            .map(|snapshot| snapshot.value)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        Ok(records)
    }

    /// Remove terminal records past the retention window. Nonterminal records
    /// are never pruned; the revision check makes a concurrent rewrite fail
    /// closed rather than deleting a newer operation.
    pub fn prune_terminal(
        &self,
        session_id: &str,
        now_unix: i64,
    ) -> Result<usize, WorkflowJournalError> {
        validate_identifier("session id", session_id)?;
        let _session_lock = self.session_lock(session_id)?;
        self.prune_terminal_locked(session_id, now_unix)
    }

    fn prune_terminal_locked(
        &self,
        session_id: &str,
        now_unix: i64,
    ) -> Result<usize, WorkflowJournalError> {
        let directory = self.operation_directory(session_id);
        let snapshots = self.all_snapshots(&directory, session_id)?;
        let mut removed = 0;
        for snapshot in snapshots {
            if snapshot.value.prune_eligible(now_unix, false) {
                self.store(session_id, &snapshot.value.operation_id)
                    .remove_if_revision(&snapshot.revision)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn session_lock(&self, session_id: &str) -> Result<StateResourceLock, WorkflowJournalError> {
        StateResourceLock::acquire(
            self.operation_directory(session_id)
                .join(".workflow-journal-session-domain"),
        )
        .map_err(WorkflowJournalError::from)
    }

    fn reserve_denial_capacity(
        &self,
        session_id: &str,
        operation_id: &str,
    ) -> Result<(), WorkflowJournalError> {
        let directory = self.operation_directory(session_id);
        let mut snapshots = self.all_snapshots(&directory, session_id)?;
        if snapshots
            .iter()
            .any(|snapshot| snapshot.value.operation_id == operation_id)
        {
            return Ok(());
        }
        let mut denials = snapshots
            .iter()
            .filter(|snapshot| snapshot.value.kind == WorkflowOperationKind::Denial)
            .cloned()
            .collect::<Vec<_>>();
        if snapshots.len().saturating_sub(denials.len()) >= MAX_WORKFLOW_OPERATION_RECORDS {
            return Err(WorkflowJournalError::TooManyEntries);
        }
        denials.sort_by(|left, right| {
            left.value
                .terminal_at_unix
                .cmp(&right.value.terminal_at_unix)
                .then_with(|| left.value.operation_id.cmp(&right.value.operation_id))
        });
        while denials.len() >= MAX_WORKFLOW_DENIAL_RECORDS {
            let Some(oldest) = denials.first().cloned() else {
                return Err(WorkflowJournalError::TooManyEntries);
            };
            self.store(session_id, &oldest.value.operation_id)
                .remove_if_revision(&oldest.revision)?;
            denials.remove(0);
            snapshots.retain(|snapshot| snapshot.value.operation_id != oldest.value.operation_id);
        }
        Ok(())
    }

    /// Terminalize the one staged transition whose target is now the
    /// authenticated observed workflow exposure. A successful gateway
    /// re-list is the authority for this change; notification alone is not.
    pub(crate) fn observe_matching_transition(
        &self,
        session_id: &str,
        target_mode: &str,
        target_exposure_revision: &str,
        target_state_sequence: u64,
        owner_id: &str,
        now_unix: i64,
    ) -> Result<Option<String>, WorkflowJournalError> {
        validate_identifier("session id", session_id)?;
        validate_identifier("workflow mode", target_mode)?;
        validate_digest("workflow exposure revision", target_exposure_revision)?;
        let directory = self.operation_directory(session_id);
        let snapshots = match self.nonterminal_snapshots(&directory, session_id)? {
            Some(snapshots) => snapshots,
            None => return Ok(None),
        };
        let mut matching = snapshots
            .into_iter()
            .filter(|snapshot| {
                snapshot.value.kind == WorkflowOperationKind::Transition
                    && snapshot.value.lifecycle == WorkflowOperationLifecycle::Staged
                    && snapshot.value.target_mode.as_deref() == Some(target_mode)
                    && snapshot.value.target_state_sequence <= target_state_sequence
            })
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err(WorkflowJournalError::InvalidRecord);
        }
        let Some(snapshot) = matching.pop() else {
            return Ok(None);
        };
        let mut observed = snapshot.value;
        observed.lifecycle = WorkflowOperationLifecycle::Observed;
        observed.reason_code = "workflow-transition-observed".to_string();
        observed.target_state_sequence = target_state_sequence;
        observed.terminal_at_unix = Some(now_unix);
        let operation_id = observed.operation_id.clone();
        self.compare_and_swap(
            &observed,
            Some(&snapshot.revision),
            OwnerGeneration::new(owner_id, target_state_sequence)?,
        )?;
        Ok(Some(operation_id))
    }

    pub fn has_nonterminal_except(
        &self,
        session_id: &str,
        operation_id: Option<&str>,
    ) -> Result<bool, WorkflowJournalError> {
        validate_identifier("session id", session_id)?;
        if let Some(operation_id) = operation_id {
            validate_identifier("workflow operation id", operation_id)?;
        }
        let directory = self.operation_directory(session_id);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(state_io_error(&directory, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkflowJournalError::UnexpectedEntry(directory));
        }
        let mut denial_count = 0;
        let mut operation_count = 0;
        let mut found = false;
        let mut entry_count = 0;
        for entry in fs::read_dir(&directory).map_err(|error| state_io_error(&directory, error))? {
            let entry = entry.map_err(|error| state_io_error(&directory, error))?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            if file_name.starts_with('.') {
                continue;
            }
            entry_count += 1;
            if entry_count > MAX_WORKFLOW_JOURNAL_ENTRIES {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            let Some(encoded_operation_id) = file_name.strip_suffix(".json") else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            let store = AtomicJsonStore::new(entry.path(), WORKFLOW_OPERATION_SCHEMA_VERSION);
            let snapshot = store
                .load::<WorkflowOperationRecord>()?
                .ok_or_else(|| WorkflowJournalError::UnexpectedEntry(entry.path()))?;
            snapshot.value.verify()?;
            if snapshot.value.session_id != session_id
                || crate::encode_path_segment(&snapshot.value.operation_id) != encoded_operation_id
            {
                return Err(WorkflowJournalError::PathMismatch);
            }
            if snapshot.value.kind == WorkflowOperationKind::Denial {
                denial_count += 1;
            } else {
                operation_count += 1;
            }
            if denial_count > MAX_WORKFLOW_DENIAL_RECORDS
                || operation_count > MAX_WORKFLOW_OPERATION_RECORDS
            {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            if !snapshot.value.lifecycle.is_terminal()
                && operation_id != Some(snapshot.value.operation_id.as_str())
            {
                found = true;
            }
        }
        Ok(found)
    }

    fn operation_directory(&self, session_id: &str) -> PathBuf {
        self.app_state_root
            .join("sessions")
            .join("workflow-operations")
            .join(crate::encode_path_segment(session_id))
    }

    fn nonterminal_snapshots(
        &self,
        directory: &PathBuf,
        session_id: &str,
    ) -> Result<Option<Vec<StateSnapshot<WorkflowOperationRecord>>>, WorkflowJournalError> {
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(state_io_error(directory, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkflowJournalError::UnexpectedEntry(directory.clone()));
        }
        let mut snapshots = Vec::new();
        let mut entry_count = 0;
        let mut denial_count = 0;
        let mut operation_count = 0;
        for entry in fs::read_dir(directory).map_err(|error| state_io_error(directory, error))? {
            let entry = entry.map_err(|error| state_io_error(directory, error))?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            if file_name.starts_with('.') {
                continue;
            }
            entry_count += 1;
            if entry_count > MAX_WORKFLOW_JOURNAL_ENTRIES {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            let Some(encoded_operation_id) = file_name.strip_suffix(".json") else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            let store = AtomicJsonStore::new(entry.path(), WORKFLOW_OPERATION_SCHEMA_VERSION);
            let snapshot = store
                .load::<WorkflowOperationRecord>()?
                .ok_or_else(|| WorkflowJournalError::UnexpectedEntry(entry.path()))?;
            snapshot.value.verify()?;
            if snapshot.value.session_id != session_id
                || crate::encode_path_segment(&snapshot.value.operation_id) != encoded_operation_id
            {
                return Err(WorkflowJournalError::PathMismatch);
            }
            if snapshot.value.kind == WorkflowOperationKind::Denial {
                denial_count += 1;
            } else {
                operation_count += 1;
            }
            if denial_count > MAX_WORKFLOW_DENIAL_RECORDS
                || operation_count > MAX_WORKFLOW_OPERATION_RECORDS
            {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            if !snapshot.value.lifecycle.is_terminal() {
                snapshots.push(snapshot);
            }
        }
        Ok(Some(snapshots))
    }

    fn all_snapshots(
        &self,
        directory: &PathBuf,
        session_id: &str,
    ) -> Result<Vec<StateSnapshot<WorkflowOperationRecord>>, WorkflowJournalError> {
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(state_io_error(directory, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkflowJournalError::UnexpectedEntry(directory.clone()));
        }
        let mut snapshots = Vec::new();
        let mut denial_count = 0;
        let mut operation_count = 0;
        let mut entry_count = 0;
        for entry in fs::read_dir(directory).map_err(|error| state_io_error(directory, error))? {
            let entry = entry.map_err(|error| state_io_error(directory, error))?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            if file_name.starts_with('.') {
                continue;
            }
            entry_count += 1;
            if entry_count > MAX_WORKFLOW_JOURNAL_ENTRIES {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            let Some(encoded_operation_id) = file_name.strip_suffix(".json") else {
                return Err(WorkflowJournalError::UnexpectedEntry(entry.path()));
            };
            let store = AtomicJsonStore::new(entry.path(), WORKFLOW_OPERATION_SCHEMA_VERSION);
            let snapshot = store
                .load::<WorkflowOperationRecord>()?
                .ok_or_else(|| WorkflowJournalError::UnexpectedEntry(entry.path()))?;
            snapshot.value.verify()?;
            if snapshot.value.session_id != session_id
                || crate::encode_path_segment(&snapshot.value.operation_id) != encoded_operation_id
            {
                return Err(WorkflowJournalError::PathMismatch);
            }
            if snapshot.value.kind == WorkflowOperationKind::Denial {
                denial_count += 1;
            } else {
                operation_count += 1;
            }
            if denial_count > MAX_WORKFLOW_DENIAL_RECORDS
                || operation_count > MAX_WORKFLOW_OPERATION_RECORDS
            {
                return Err(WorkflowJournalError::TooManyEntries);
            }
            snapshots.push(snapshot);
        }
        Ok(snapshots)
    }

    fn store(&self, session_id: &str, operation_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.app_state_root
                .join("sessions")
                .join("workflow-operations")
                .join(crate::encode_path_segment(session_id))
                .join(format!("{}.json", crate::encode_path_segment(operation_id))),
            WORKFLOW_OPERATION_SCHEMA_VERSION,
        )
    }
}

#[derive(Debug)]
pub enum WorkflowJournalError {
    State(StateError),
    InvalidRecord,
    PathMismatch,
    TerminalMutation,
    UnexpectedEntry(PathBuf),
    TooManyEntries,
    Lease(String),
}

impl From<StateError> for WorkflowJournalError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<super::lease::LeaseValidationError> for WorkflowJournalError {
    fn from(error: super::lease::LeaseValidationError) -> Self {
        Self::Lease(error.to_string())
    }
}

impl fmt::Display for WorkflowJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::InvalidRecord => formatter.write_str("invalid workflow operation record"),
            Self::PathMismatch => formatter.write_str("workflow operation path mismatch"),
            Self::TerminalMutation => {
                formatter.write_str("terminal workflow operation is immutable")
            }
            Self::UnexpectedEntry(path) => {
                write!(
                    formatter,
                    "unexpected workflow journal entry: {}",
                    path.display()
                )
            }
            Self::TooManyEntries => formatter.write_str("workflow journal has too many records"),
            Self::Lease(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for WorkflowJournalError {}

fn state_io_error(path: &std::path::Path, error: io::Error) -> WorkflowJournalError {
    WorkflowJournalError::State(StateError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}
