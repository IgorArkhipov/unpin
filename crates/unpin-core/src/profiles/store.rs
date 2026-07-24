use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{
        get_global_profile_definition_path, get_global_profiles_dir, get_profile_revision_path,
        get_workspace_profiles_dir,
    },
    profiles::model::valid_profile_id,
    profiles::{CompiledProfileRevision, ProfileDefinition, ProfileValidationError},
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

const PROFILE_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDefinitionEntry {
    pub scope: crate::profiles::ProfileSourceScope,
    pub definition: ProfileDefinition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<StateRevision>,
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    app_state_root: PathBuf,
}

impl ProfileStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn save_global_definition(
        &self,
        definition: &ProfileDefinition,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, ProfileStoreError> {
        definition.to_export_json()?;
        AtomicJsonStore::new(
            get_global_profile_definition_path(&self.app_state_root, &definition.id),
            PROFILE_STATE_SCHEMA_VERSION,
        )
        .compare_and_swap(expected, owner, definition)
        .map_err(Into::into)
    }

    pub fn load_global_definition(
        &self,
        profile_id: &str,
    ) -> Result<Option<StateSnapshot<ProfileDefinition>>, ProfileStoreError> {
        if !valid_profile_id(profile_id) {
            return Err(ProfileStoreError::InvalidProfileId {
                profile_id: profile_id.to_string(),
            });
        }
        AtomicJsonStore::new(
            get_global_profile_definition_path(&self.app_state_root, profile_id),
            PROFILE_STATE_SCHEMA_VERSION,
        )
        .load()
        .map_err(Into::into)
    }

    pub fn list_global_definitions(
        &self,
    ) -> Result<Vec<ProfileDefinitionEntry>, ProfileStoreError> {
        let directory = get_global_profiles_dir(&self.app_state_root);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ProfileStoreError::Io(error)),
        };
        let mut definitions = Vec::new();
        for entry in entries {
            let entry = entry.map_err(ProfileStoreError::Io)?;
            let file_type = entry.file_type().map_err(ProfileStoreError::Io)?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(ProfileStoreError::UnsafeDefinitionEntry);
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let snapshot = AtomicJsonStore::new(&path, PROFILE_STATE_SCHEMA_VERSION)
                .load::<ProfileDefinition>()?
                .ok_or(ProfileStoreError::MissingDefinitionState)?;
            if get_global_profile_definition_path(&self.app_state_root, &snapshot.value.id) != path
            {
                return Err(ProfileStoreError::DefinitionPathMismatch);
            }
            snapshot.value.to_export_json()?;
            definitions.push(ProfileDefinitionEntry {
                scope: crate::profiles::ProfileSourceScope::Global,
                definition: snapshot.value,
                revision: Some(snapshot.revision),
            });
        }
        definitions.sort_by(|left, right| left.definition.id.cmp(&right.definition.id));
        Ok(definitions)
    }

    pub fn load_workspace_definition(
        workspace_root: impl AsRef<Path>,
        profile_id: &str,
    ) -> Result<Option<ProfileDefinitionEntry>, ProfileStoreError> {
        if !valid_profile_id(profile_id) {
            return Err(ProfileStoreError::InvalidProfileId {
                profile_id: profile_id.to_string(),
            });
        }
        let path = workspace_definition_path(workspace_root.as_ref(), profile_id);
        let Some(definition) = read_workspace_definition(&path)? else {
            return Ok(None);
        };
        if definition.id != profile_id {
            return Err(ProfileStoreError::DefinitionPathMismatch);
        }
        Ok(Some(ProfileDefinitionEntry {
            scope: crate::profiles::ProfileSourceScope::Workspace,
            definition,
            revision: None,
        }))
    }

    pub fn list_workspace_definitions(
        workspace_root: impl AsRef<Path>,
    ) -> Result<Vec<ProfileDefinitionEntry>, ProfileStoreError> {
        let directory = get_workspace_profiles_dir(workspace_root);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(ProfileStoreError::Io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProfileStoreError::UnsafeDefinitionEntry);
        }
        let mut definitions = Vec::new();
        for entry in fs::read_dir(&directory).map_err(ProfileStoreError::Io)? {
            let entry = entry.map_err(ProfileStoreError::Io)?;
            let file_type = entry.file_type().map_err(ProfileStoreError::Io)?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(ProfileStoreError::UnsafeDefinitionEntry);
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let definition = read_workspace_definition(&path)?
                .ok_or(ProfileStoreError::MissingDefinitionState)?;
            if directory.join(format!(
                "{}.json",
                crate::encode_path_segment(&definition.id)
            )) != path
            {
                return Err(ProfileStoreError::DefinitionPathMismatch);
            }
            definitions.push(ProfileDefinitionEntry {
                scope: crate::profiles::ProfileSourceScope::Workspace,
                definition,
                revision: None,
            });
        }
        definitions.sort_by(|left, right| left.definition.id.cmp(&right.definition.id));
        Ok(definitions)
    }

    pub fn materialize_revision(
        &self,
        revision: &CompiledProfileRevision,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, ProfileStoreError> {
        revision.verify_digest()?;
        let store = AtomicJsonStore::new(
            get_profile_revision_path(&self.app_state_root, &revision.digest),
            PROFILE_STATE_SCHEMA_VERSION,
        );
        match store.compare_and_swap(None, owner, revision) {
            Ok(state_revision) => Ok(state_revision),
            Err(StateError::StaleRevision { .. }) => {
                let existing = store.load::<CompiledProfileRevision>()?.ok_or_else(|| {
                    ProfileStoreError::MissingRevision {
                        digest: revision.digest.clone(),
                    }
                })?;
                if existing.value != *revision {
                    return Err(ProfileStoreError::ImmutableCollision {
                        digest: revision.digest.clone(),
                    });
                }
                Ok(existing.revision)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn load_revision(
        &self,
        digest: &str,
    ) -> Result<Option<CompiledProfileRevision>, ProfileStoreError> {
        if !valid_digest(digest) {
            return Err(ProfileStoreError::InvalidDigest {
                digest: digest.to_string(),
            });
        }
        let Some(snapshot) = AtomicJsonStore::new(
            get_profile_revision_path(&self.app_state_root, digest),
            PROFILE_STATE_SCHEMA_VERSION,
        )
        .load::<CompiledProfileRevision>()?
        else {
            return Ok(None);
        };
        if snapshot.value.digest != digest {
            return Err(ProfileStoreError::DigestMismatch {
                expected: digest.to_string(),
                actual: snapshot.value.digest,
            });
        }
        snapshot.value.verify_digest()?;
        Ok(Some(snapshot.value))
    }
}

#[derive(Debug)]
pub enum ProfileStoreError {
    State(StateError),
    Validation(ProfileValidationError),
    InvalidProfileId { profile_id: String },
    InvalidDigest { digest: String },
    MissingRevision { digest: String },
    ImmutableCollision { digest: String },
    DigestMismatch { expected: String, actual: String },
    Io(std::io::Error),
    UnsafeDefinitionEntry,
    MissingDefinitionState,
    DefinitionPathMismatch,
}

impl From<StateError> for ProfileStoreError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<ProfileValidationError> for ProfileStoreError {
    fn from(error: ProfileValidationError) -> Self {
        Self::Validation(error)
    }
}

impl fmt::Display for ProfileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::InvalidProfileId { profile_id } => {
                write!(formatter, "invalid profile id: {profile_id:?}")
            }
            Self::InvalidDigest { digest } => {
                write!(formatter, "invalid profile digest: {digest:?}")
            }
            Self::MissingRevision { digest } => {
                write!(formatter, "compiled profile revision disappeared: {digest}")
            }
            Self::ImmutableCollision { digest } => {
                write!(formatter, "compiled profile digest collision: {digest}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "profile revision digest mismatch: expected {expected}, found {actual}"
            ),
            Self::Io(error) => write!(formatter, "profile definition I/O failed: {error}"),
            Self::UnsafeDefinitionEntry => {
                formatter.write_str("profile definition entry is not a regular file")
            }
            Self::MissingDefinitionState => {
                formatter.write_str("profile definition disappeared during inventory")
            }
            Self::DefinitionPathMismatch => {
                formatter.write_str("profile definition id does not match its storage path")
            }
        }
    }
}

impl std::error::Error for ProfileStoreError {}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn workspace_definition_path(workspace_root: &Path, profile_id: &str) -> PathBuf {
    get_workspace_profiles_dir(workspace_root)
        .join(format!("{}.json", crate::encode_path_segment(profile_id)))
}

fn read_workspace_definition(path: &Path) -> Result<Option<ProfileDefinition>, ProfileStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProfileStoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProfileStoreError::UnsafeDefinitionEntry);
    }
    if metadata.len() > crate::profiles::MAX_PROFILE_DEFINITION_BYTES as u64 {
        return Err(ProfileValidationError::DefinitionTooLarge {
            actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            maximum: crate::profiles::MAX_PROFILE_DEFINITION_BYTES,
        }
        .into());
    }
    let mut file = fs::File::open(path).map_err(ProfileStoreError::Io)?;
    let opened = file.metadata().map_err(ProfileStoreError::Io)?;
    let current = fs::symlink_metadata(path).map_err(ProfileStoreError::Io)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || !same_file_identity(&opened, &current)
    {
        return Err(ProfileStoreError::UnsafeDefinitionEntry);
    }
    let mut raw = String::new();
    file.by_ref()
        .take((crate::profiles::MAX_PROFILE_DEFINITION_BYTES + 1) as u64)
        .read_to_string(&mut raw)
        .map_err(ProfileStoreError::Io)?;
    if raw.len() > crate::profiles::MAX_PROFILE_DEFINITION_BYTES {
        return Err(ProfileValidationError::DefinitionTooLarge {
            actual: raw.len(),
            maximum: crate::profiles::MAX_PROFILE_DEFINITION_BYTES,
        }
        .into());
    }
    ProfileDefinition::from_json(&raw)
        .map(Some)
        .map_err(Into::into)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}
