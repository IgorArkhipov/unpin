use std::{fmt, fs, path::PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    clock::{current_timestamp, unix_nanos_id},
    encode_lower_hex,
    groups::{GroupContextBinding, GroupDefinitionV1, GroupRevision, GroupScope},
    mutation::BackupAuthenticationKey,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
};

const GROUP_HISTORY_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupChangeKind {
    Create,
    Replace,
    Rename,
    Delete,
    Restore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupHistoryLifecycle {
    Prepared,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupHistoryRecord {
    pub schema_version: u8,
    pub history_id: String,
    pub created_at: String,
    pub scope: GroupScope,
    pub change: GroupChangeKind,
    pub lifecycle: GroupHistoryLifecycle,
    pub name_before: Option<String>,
    pub name_after: Option<String>,
    pub revision_before: Option<GroupRevision>,
    pub revision_after: Option<GroupRevision>,
    pub definition_before: Option<GroupDefinitionV1>,
    pub definition_after: Option<GroupDefinitionV1>,
    pub binding_before: Option<GroupContextBinding>,
    pub binding_after: Option<GroupContextBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_key_id: Option<String>,
    pub integrity_digest: String,
}

impl GroupHistoryRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope: GroupScope,
        change: GroupChangeKind,
        definition_before: Option<GroupDefinitionV1>,
        binding_before: Option<GroupContextBinding>,
        definition_after: Option<GroupDefinitionV1>,
        binding_after: Option<GroupContextBinding>,
    ) -> Result<Self, GroupHistoryError> {
        let history_id = unix_nanos_id("group-history").map_err(GroupHistoryError::Clock)?;
        let created_at = current_timestamp().map_err(GroupHistoryError::Clock)?;
        let revision_before = definition_before
            .as_ref()
            .zip(binding_before.as_ref())
            .map(|(definition, binding)| definition.revision(binding))
            .transpose()
            .map_err(|error| GroupHistoryError::Invalid(error.to_string()))?;
        let revision_after = definition_after
            .as_ref()
            .zip(binding_after.as_ref())
            .map(|(definition, binding)| definition.revision(binding))
            .transpose()
            .map_err(|error| GroupHistoryError::Invalid(error.to_string()))?;
        let mut record = Self {
            schema_version: 2,
            history_id,
            created_at,
            scope,
            change,
            lifecycle: GroupHistoryLifecycle::Prepared,
            name_before: definition_before
                .as_ref()
                .map(|definition| definition.name.clone()),
            name_after: definition_after
                .as_ref()
                .map(|definition| definition.name.clone()),
            revision_before,
            revision_after,
            definition_before,
            definition_after,
            binding_before,
            binding_after,
            authentication_key_id: None,
            integrity_digest: String::new(),
        };
        record.integrity_digest = record.expected_integrity_digest()?;
        Ok(record)
    }

    pub fn verify(&self) -> Result<(), GroupHistoryError> {
        self.verify_with_key(None)
    }

    pub fn verify_with_key(
        &self,
        authentication_key: Option<&BackupAuthenticationKey>,
    ) -> Result<(), GroupHistoryError> {
        if self.schema_version != 2 || self.history_id.is_empty() {
            return Err(GroupHistoryError::Invalid(
                "unsupported or incomplete group history record".to_string(),
            ));
        }
        match (&self.authentication_key_id, authentication_key) {
            (Some(key_id), Some(key)) if key_id == &key.key_id() => {
                let mut unsigned = self.clone();
                let tag = std::mem::take(&mut unsigned.integrity_digest);
                let bytes = serde_json::to_vec(&unsigned).map_err(GroupHistoryError::Json)?;
                key.verify_purpose(
                    b"unpin-inventory-group-definition-history-v2\0",
                    &bytes,
                    &tag,
                )
                .map_err(|_| GroupHistoryError::AuthenticationFailed)?;
            }
            (None, None) => {
                if self.expected_integrity_digest()? != self.integrity_digest {
                    return Err(GroupHistoryError::AuthenticationFailed);
                }
            }
            _ => return Err(GroupHistoryError::AuthenticationFailed),
        }
        Ok(())
    }

    fn authenticate(
        &mut self,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), GroupHistoryError> {
        self.authentication_key_id = Some(authentication_key.key_id());
        self.integrity_digest.clear();
        let bytes = serde_json::to_vec(self).map_err(GroupHistoryError::Json)?;
        self.integrity_digest = authentication_key
            .authenticate_purpose(b"unpin-inventory-group-definition-history-v2\0", &bytes)
            .map_err(GroupHistoryError::Authentication)?;
        self.verify_with_key(Some(authentication_key))
    }

    fn expected_integrity_digest(&self) -> Result<String, GroupHistoryError> {
        let mut unsigned = self.clone();
        unsigned.integrity_digest.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(GroupHistoryError::Json)?;
        let mut hasher = Sha256::new();
        hasher.update(b"unpin-group-history-v2\0");
        hasher.update(bytes);
        Ok(encode_lower_hex(&hasher.finalize()))
    }
}

pub(crate) struct GroupHistorySnapshot {
    pub(crate) record: GroupHistoryRecord,
    revision: StateRevision,
    owner: OwnerGeneration,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupHistoryStore {
    root: PathBuf,
    authentication_key: Option<BackupAuthenticationKey>,
}

impl GroupHistoryStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            authentication_key: None,
        }
    }

    pub(crate) fn new_authenticated(
        root: PathBuf,
        authentication_key: BackupAuthenticationKey,
    ) -> Self {
        Self {
            root,
            authentication_key: Some(authentication_key),
        }
    }

    pub(crate) fn prepare(
        &self,
        record: &GroupHistoryRecord,
        owner: OwnerGeneration,
    ) -> Result<GroupHistorySnapshot, GroupHistoryError> {
        let mut record = record.clone();
        if record.lifecycle != GroupHistoryLifecycle::Prepared {
            return Err(GroupHistoryError::Invalid(
                "group history transaction is not prepared".to_string(),
            ));
        }
        self.seal(&mut record)?;
        let path = self.root.join(format!("{}.json", record.history_id));
        let revision = AtomicJsonStore::new(path, GROUP_HISTORY_SCHEMA_VERSION).compare_and_swap(
            None,
            owner.clone(),
            &record,
        )?;
        Ok(GroupHistorySnapshot {
            record,
            revision,
            owner,
        })
    }

    pub(crate) fn commit(
        &self,
        snapshot: &GroupHistorySnapshot,
    ) -> Result<GroupHistoryRecord, GroupHistoryError> {
        self.finish(snapshot, GroupHistoryLifecycle::Committed)
    }

    pub(crate) fn abort(
        &self,
        snapshot: &GroupHistorySnapshot,
    ) -> Result<GroupHistoryRecord, GroupHistoryError> {
        self.finish(snapshot, GroupHistoryLifecycle::Aborted)
    }

    pub(crate) fn pending(&self) -> Result<Vec<GroupHistorySnapshot>, GroupHistoryError> {
        self.snapshots().map(|snapshots| {
            snapshots
                .into_iter()
                .filter(|snapshot| snapshot.record.lifecycle == GroupHistoryLifecycle::Prepared)
                .collect()
        })
    }

    pub(crate) fn list(&self) -> Result<Vec<GroupHistoryRecord>, GroupHistoryError> {
        let mut records = self
            .snapshots()?
            .into_iter()
            .filter(|snapshot| snapshot.record.lifecycle == GroupHistoryLifecycle::Committed)
            .map(|snapshot| snapshot.record)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.history_id.cmp(&right.history_id))
        });
        Ok(records)
    }

    fn snapshots(&self) -> Result<Vec<GroupHistorySnapshot>, GroupHistoryError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(GroupHistoryError::Io(error)),
        };
        let mut snapshots = Vec::new();
        for entry in entries {
            let entry = entry.map_err(GroupHistoryError::Io)?;
            let file_type = entry.file_type().map_err(GroupHistoryError::Io)?;
            if file_type.is_symlink() {
                return Err(GroupHistoryError::UnsafeEntry);
            }
            if !file_type.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let snapshot = AtomicJsonStore::new(entry.path(), GROUP_HISTORY_SCHEMA_VERSION)
                .load::<GroupHistoryRecord>()?
                .ok_or(GroupHistoryError::MissingRecord)?;
            snapshot
                .value
                .verify_with_key(self.authentication_key.as_ref())?;
            snapshots.push(GroupHistorySnapshot {
                record: snapshot.value,
                revision: snapshot.revision,
                owner: snapshot.owner,
            });
        }
        snapshots.sort_by(|left, right| {
            left.record
                .created_at
                .cmp(&right.record.created_at)
                .then_with(|| left.record.history_id.cmp(&right.record.history_id))
        });
        Ok(snapshots)
    }

    pub(crate) fn load(
        &self,
        history_id: &str,
    ) -> Result<Option<GroupHistoryRecord>, GroupHistoryError> {
        if !valid_history_id(history_id) {
            return Err(GroupHistoryError::Invalid(
                "invalid group history id".to_string(),
            ));
        }
        let Some(snapshot) = AtomicJsonStore::new(
            self.root.join(format!("{history_id}.json")),
            GROUP_HISTORY_SCHEMA_VERSION,
        )
        .load::<GroupHistoryRecord>()?
        else {
            return Ok(None);
        };
        snapshot
            .value
            .verify_with_key(self.authentication_key.as_ref())?;
        if snapshot.value.history_id != history_id {
            return Err(GroupHistoryError::Invalid(
                "group history record identity does not match its filename".to_string(),
            ));
        }
        if snapshot.value.lifecycle == GroupHistoryLifecycle::Committed {
            Ok(Some(snapshot.value))
        } else {
            Ok(None)
        }
    }

    fn finish(
        &self,
        snapshot: &GroupHistorySnapshot,
        lifecycle: GroupHistoryLifecycle,
    ) -> Result<GroupHistoryRecord, GroupHistoryError> {
        if snapshot.record.lifecycle != GroupHistoryLifecycle::Prepared
            || lifecycle == GroupHistoryLifecycle::Prepared
        {
            return Err(GroupHistoryError::Invalid(
                "invalid group history transaction transition".to_string(),
            ));
        }
        let mut record = snapshot.record.clone();
        record.lifecycle = lifecycle;
        self.seal(&mut record)?;
        AtomicJsonStore::new(
            self.root.join(format!("{}.json", record.history_id)),
            GROUP_HISTORY_SCHEMA_VERSION,
        )
        .compare_and_swap(Some(&snapshot.revision), snapshot.owner.clone(), &record)?;
        Ok(record)
    }

    fn seal(&self, record: &mut GroupHistoryRecord) -> Result<(), GroupHistoryError> {
        if let Some(key) = self.authentication_key.as_ref() {
            record.authenticate(key)
        } else {
            record.authentication_key_id = None;
            record.integrity_digest = record.expected_integrity_digest()?;
            record.verify()
        }
    }
}

fn valid_history_id(value: &str) -> bool {
    value.strip_prefix("group-history-").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[derive(Debug)]
pub enum GroupHistoryError {
    State(StateError),
    Io(std::io::Error),
    Json(serde_json::Error),
    Clock(String),
    Invalid(String),
    AuthenticationFailed,
    Authentication(String),
    UnsafeEntry,
    MissingRecord,
}

impl From<StateError> for GroupHistoryError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for GroupHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "group history I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "group history JSON failed: {error}"),
            Self::Clock(error) => write!(formatter, "group history clock failed: {error}"),
            Self::Invalid(error) => formatter.write_str(error),
            Self::AuthenticationFailed => {
                formatter.write_str("group history authentication failed")
            }
            Self::Authentication(_) => formatter.write_str("group history authentication failed"),
            Self::UnsafeEntry => formatter.write_str("group history entry is unsafe"),
            Self::MissingRecord => formatter.write_str("group history record disappeared"),
        }
    }
}

impl std::error::Error for GroupHistoryError {}
