use std::{collections::BTreeSet, fmt, fs, io, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::get_transition_journal_path,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

use super::plan::TransitionPlan;

pub const TRANSITION_JOURNAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionLifecycle {
    Planned,
    AwaitingHumanAction,
    Approved,
    Locked,
    BackedUp,
    Applying,
    Cancelling,
    RollingBack,
    Recovering,
    Committed,
    RolledBack,
    NeedsRepair,
}

impl TransitionLifecycle {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack | Self::NeedsRepair)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingHumanAction => "awaiting-human-action",
            Self::Approved => "approved",
            Self::Locked => "locked",
            Self::BackedUp => "backed-up",
            Self::Applying => "applying",
            Self::Cancelling => "cancelling",
            Self::RollingBack => "rolling-back",
            Self::Recovering => "recovering",
            Self::Committed => "committed",
            Self::RolledBack => "rolled-back",
            Self::NeedsRepair => "needs-repair",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectCheckpointStatus {
    Pending,
    BackedUp,
    Applied,
    RolledBack,
    NeedsRepair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectCheckpoint {
    pub effect_id: String,
    pub resource_id: String,
    pub expected_pre_fingerprint: Option<String>,
    pub expected_post_fingerprint: Option<String>,
    pub status: EffectCheckpointStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalEvent {
    pub sequence: u64,
    pub lifecycle: TransitionLifecycle,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionJournal {
    pub operation_id: String,
    pub operation_kind: String,
    pub effect_graph_digest: String,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
    pub lifecycle: TransitionLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_decision_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_decision_history: Vec<String>,
    pub backup_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_manifest_digest: Option<String>,
    pub effects: Vec<EffectCheckpoint>,
    pub audit: Vec<JournalEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_code: Option<String>,
}

impl TransitionJournal {
    pub fn from_plan(plan: &TransitionPlan) -> Result<Self, JournalError> {
        plan.verify()
            .map_err(|error| JournalError::InvalidPlan(error.to_string()))?;
        let backup_id = deterministic_backup_id(plan);
        let effects = plan
            .effects
            .iter()
            .map(|effect| EffectCheckpoint {
                effect_id: effect.effect_id.clone(),
                resource_id: effect.resource_id.clone(),
                expected_pre_fingerprint: effect.expected_pre_fingerprint.clone(),
                expected_post_fingerprint: effect.expected_post_fingerprint.clone(),
                status: EffectCheckpointStatus::Pending,
            })
            .collect();
        let mut journal = Self {
            operation_id: plan.operation_id.clone(),
            operation_kind: plan.kind.as_str().to_string(),
            effect_graph_digest: plan.effect_graph_digest.clone(),
            repository_key: plan.context.repository_key.clone(),
            workspace_key: plan.context.workspace_key.clone(),
            session_id: plan.context.session_id.clone(),
            profile_digest: plan.context.profile_digest.clone(),
            lifecycle: TransitionLifecycle::Planned,
            authorization_decision_digest: None,
            authorization_decision_history: Vec::new(),
            backup_id,
            backup_manifest_digest: None,
            effects,
            audit: Vec::new(),
            terminal_code: None,
        };
        journal.record(TransitionLifecycle::Planned, "planned", None)?;
        Ok(journal)
    }

    pub fn verify_plan(&self, plan: &TransitionPlan) -> Result<(), JournalError> {
        let matches = self.operation_id == plan.operation_id
            && self.operation_kind == plan.kind.as_str()
            && self.effect_graph_digest == plan.effect_graph_digest
            && self.repository_key == plan.context.repository_key
            && self.workspace_key == plan.context.workspace_key
            && self.session_id == plan.context.session_id
            && self.profile_digest == plan.context.profile_digest
            && self.effects.len() == plan.effects.len()
            && self
                .effects
                .iter()
                .zip(&plan.effects)
                .all(|(checkpoint, effect)| {
                    checkpoint.effect_id == effect.effect_id
                        && checkpoint.resource_id == effect.resource_id
                        && checkpoint.expected_pre_fingerprint == effect.expected_pre_fingerprint
                        && checkpoint.expected_post_fingerprint == effect.expected_post_fingerprint
                });
        if matches {
            self.verify_audit_chain()
        } else {
            Err(JournalError::OperationConflict)
        }
    }

    pub fn record(
        &mut self,
        lifecycle: TransitionLifecycle,
        code: impl Into<String>,
        effect_id: Option<&str>,
    ) -> Result<(), JournalError> {
        if !self.audit.is_empty() && self.lifecycle.is_terminal() {
            return Err(JournalError::TerminalMutation);
        }
        let code = code.into();
        validate_event_code(&code)?;
        let sequence = u64::try_from(self.audit.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or(JournalError::AuditOverflow)?;
        let previous_digest = self.audit.last().map(|event| event.digest.clone());
        let digest = event_digest(
            sequence,
            lifecycle,
            &code,
            effect_id,
            previous_digest.as_deref(),
        );
        self.lifecycle = lifecycle;
        self.audit.push(JournalEvent {
            sequence,
            lifecycle,
            code,
            effect_id: effect_id.map(str::to_owned),
            previous_digest,
            digest,
        });
        Ok(())
    }

    pub fn verify_audit_chain(&self) -> Result<(), JournalError> {
        let mut previous: Option<&str> = None;
        for (index, event) in self.audit.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(JournalError::AuditOverflow)?;
            let digest = event_digest(
                event.sequence,
                event.lifecycle,
                &event.code,
                event.effect_id.as_deref(),
                event.previous_digest.as_deref(),
            );
            if event.sequence != expected_sequence
                || event.previous_digest.as_deref() != previous
                || event.digest != digest
            {
                return Err(JournalError::InvalidAuditChain);
            }
            previous = Some(&event.digest);
        }
        if self.audit.last().map(|event| event.lifecycle) == Some(self.lifecycle) {
            Ok(())
        } else {
            Err(JournalError::InvalidAuditChain)
        }
    }

    fn may_require_recovery_before_new_writes(&self) -> bool {
        if matches!(
            self.lifecycle,
            TransitionLifecycle::Committed | TransitionLifecycle::RolledBack
        ) {
            return false;
        }
        self.lifecycle == TransitionLifecycle::NeedsRepair
            || matches!(
                self.lifecycle,
                TransitionLifecycle::Applying
                    | TransitionLifecycle::Cancelling
                    | TransitionLifecycle::RollingBack
                    | TransitionLifecycle::Recovering
            )
            || self.effects.iter().any(|effect| {
                matches!(
                    effect.status,
                    EffectCheckpointStatus::Applied
                        | EffectCheckpointStatus::RolledBack
                        | EffectCheckpointStatus::NeedsRepair
                )
            })
    }
}

#[derive(Debug, Clone)]
pub struct TransitionJournalStore {
    app_state_root: PathBuf,
}

impl TransitionJournalStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn create_or_attach(
        &self,
        plan: &TransitionPlan,
        owner: OwnerGeneration,
    ) -> Result<JournalHandle, JournalError> {
        let store = self.store(&plan.operation_id);
        let journal = TransitionJournal::from_plan(plan)?;
        match store.compare_and_swap(None, owner.clone(), &journal) {
            Ok(revision) => Ok(JournalHandle {
                journal,
                revision,
                owner,
            }),
            Err(StateError::StaleRevision { .. }) => {
                let snapshot = store
                    .load::<TransitionJournal>()?
                    .ok_or(JournalError::JournalDisappeared)?;
                snapshot.value.verify_plan(plan)?;
                Ok(JournalHandle::from_snapshot(snapshot, owner))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn load(
        &self,
        plan: &TransitionPlan,
        owner: OwnerGeneration,
    ) -> Result<JournalHandle, JournalError> {
        let snapshot = self
            .store(&plan.operation_id)
            .load::<TransitionJournal>()?
            .ok_or(JournalError::JournalDisappeared)?;
        snapshot.value.verify_plan(plan)?;
        Ok(JournalHandle::from_snapshot(snapshot, owner))
    }

    pub fn save(&self, handle: &mut JournalHandle) -> Result<(), JournalError> {
        handle.journal.verify_audit_chain()?;
        let revision = self.store(&handle.journal.operation_id).compare_and_swap(
            Some(&handle.revision),
            handle.owner.clone(),
            &handle.journal,
        )?;
        handle.revision = revision;
        Ok(())
    }

    pub fn blocking_operation_for(
        &self,
        plan: &TransitionPlan,
    ) -> Result<Option<String>, JournalError> {
        plan.verify()
            .map_err(|error| JournalError::InvalidPlan(error.to_string()))?;
        let transaction_root = self.app_state_root.join("transactions");
        let metadata = match fs::symlink_metadata(&transaction_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(JournalError::Io(transaction_root, error.to_string())),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(JournalError::UnsafeJournalDirectory(transaction_root));
        }

        let current_path = get_transition_journal_path(&self.app_state_root, &plan.operation_id);
        let resources = plan
            .effects
            .iter()
            .map(|effect| effect.resource_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut paths = fs::read_dir(&transaction_root)
            .map_err(|error| JournalError::Io(transaction_root.clone(), error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| JournalError::Io(transaction_root.clone(), error.to_string()))?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
                    && !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            })
            .collect::<Vec<_>>();
        paths.sort();

        for path in paths {
            if path == current_path {
                continue;
            }
            let snapshot = AtomicJsonStore::new(&path, TRANSITION_JOURNAL_SCHEMA_VERSION)
                .load::<TransitionJournal>()?
                .ok_or(JournalError::JournalDisappeared)?;
            let journal = snapshot.value;
            journal.verify_audit_chain()?;
            if get_transition_journal_path(&self.app_state_root, &journal.operation_id) != path {
                return Err(JournalError::JournalPathMismatch);
            }
            let overlaps = journal
                .effects
                .iter()
                .any(|effect| resources.contains(effect.resource_id.as_str()));
            if overlaps && journal.may_require_recovery_before_new_writes() {
                return Ok(Some(journal.operation_id));
            }
        }
        Ok(None)
    }

    pub fn list(&self) -> Result<Vec<TransitionJournal>, JournalError> {
        let transaction_root = self.app_state_root.join("transactions");
        let metadata = match fs::symlink_metadata(&transaction_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(JournalError::Io(transaction_root, error.to_string())),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(JournalError::UnsafeJournalDirectory(transaction_root));
        }
        let mut paths = fs::read_dir(&transaction_root)
            .map_err(|error| JournalError::Io(transaction_root.clone(), error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| JournalError::Io(transaction_root.clone(), error.to_string()))?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
                    && !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            })
            .collect::<Vec<_>>();
        paths.sort();
        let mut journals = Vec::with_capacity(paths.len());
        for path in paths {
            let snapshot = AtomicJsonStore::new(&path, TRANSITION_JOURNAL_SCHEMA_VERSION)
                .load::<TransitionJournal>()?
                .ok_or(JournalError::JournalDisappeared)?;
            let journal = snapshot.value;
            journal.verify_audit_chain()?;
            if get_transition_journal_path(&self.app_state_root, &journal.operation_id) != path {
                return Err(JournalError::JournalPathMismatch);
            }
            journals.push(journal);
        }
        journals.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        Ok(journals)
    }

    fn store(&self, operation_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            get_transition_journal_path(&self.app_state_root, operation_id),
            TRANSITION_JOURNAL_SCHEMA_VERSION,
        )
    }
}

#[derive(Debug, Clone)]
pub struct JournalHandle {
    pub journal: TransitionJournal,
    revision: StateRevision,
    owner: OwnerGeneration,
}

impl JournalHandle {
    fn from_snapshot(snapshot: StateSnapshot<TransitionJournal>, owner: OwnerGeneration) -> Self {
        Self {
            journal: snapshot.value,
            revision: snapshot.revision,
            owner,
        }
    }
}

fn deterministic_backup_id(plan: &TransitionPlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-transition-backup-v1\0");
    hasher.update(plan.operation_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(plan.effect_graph_digest.as_bytes());
    format!(
        "backup-transition-{}",
        crate::encode_lower_hex(&hasher.finalize())
    )
}

fn event_digest(
    sequence: u64,
    lifecycle: TransitionLifecycle,
    code: &str,
    effect_id: Option<&str>,
    previous_digest: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-transition-audit-v1\0");
    hasher.update(sequence.to_be_bytes());
    digest_field(&mut hasher, lifecycle.as_str().as_bytes());
    digest_field(&mut hasher, code.as_bytes());
    digest_field(&mut hasher, effect_id.unwrap_or_default().as_bytes());
    digest_field(&mut hasher, previous_digest.unwrap_or_default().as_bytes());
    crate::encode_lower_hex(&hasher.finalize())
}

fn digest_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_event_code(code: &str) -> Result<(), JournalError> {
    if code.is_empty()
        || code.len() > 128
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Err(JournalError::InvalidEventCode)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum JournalError {
    InvalidPlan(String),
    OperationConflict,
    JournalDisappeared,
    InvalidEventCode,
    AuditOverflow,
    InvalidAuditChain,
    TerminalMutation,
    UnsafeJournalDirectory(PathBuf),
    JournalPathMismatch,
    Io(PathBuf, String),
    State(StateError),
}

impl From<StateError> for JournalError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(message) => write!(formatter, "invalid transition plan: {message}"),
            Self::OperationConflict => {
                formatter.write_str("operation id is already bound to another transition")
            }
            Self::JournalDisappeared => formatter.write_str("transition journal disappeared"),
            Self::InvalidEventCode => formatter.write_str("transition audit event code is invalid"),
            Self::AuditOverflow => formatter.write_str("transition audit sequence overflow"),
            Self::InvalidAuditChain => formatter.write_str("transition audit chain is invalid"),
            Self::TerminalMutation => {
                formatter.write_str("terminal transition journal cannot be mutated")
            }
            Self::UnsafeJournalDirectory(path) => {
                write!(
                    formatter,
                    "transition journal directory is unsafe: {}",
                    path.display()
                )
            }
            Self::JournalPathMismatch => {
                formatter.write_str("transition journal path does not match its operation id")
            }
            Self::Io(path, message) => write!(formatter, "{}: {message}", path.display()),
            Self::State(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for JournalError {}
