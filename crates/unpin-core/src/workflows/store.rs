use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    profiles::ProfileSourceScope,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

use super::{
    CompiledWorkflowRevision, MAX_WORKFLOW_DEFINITION_BYTES, WorkflowDefinition,
    WorkflowValidationError,
};

const WORKFLOW_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinitionEntry {
    pub scope: ProfileSourceScope,
    pub definition: WorkflowDefinition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<StateRevision>,
}

#[derive(Debug, Clone)]
pub struct WorkflowStore {
    app_state_root: PathBuf,
}

impl WorkflowStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn save_global_definition(
        &self,
        definition: &WorkflowDefinition,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, WorkflowStoreError> {
        definition.validate()?;
        AtomicJsonStore::new(
            global_definition_path(&self.app_state_root, &definition.id),
            WORKFLOW_STATE_SCHEMA_VERSION,
        )
        .compare_and_swap(expected, owner, definition)
        .map_err(Into::into)
    }

    pub fn load_global_definition(
        &self,
        workflow_id: &str,
    ) -> Result<Option<StateSnapshot<WorkflowDefinition>>, WorkflowStoreError> {
        validate_storage_id(workflow_id)?;
        AtomicJsonStore::new(
            global_definition_path(&self.app_state_root, workflow_id),
            WORKFLOW_STATE_SCHEMA_VERSION,
        )
        .load()
        .map_err(Into::into)
    }

    pub fn list_global_definitions(
        &self,
    ) -> Result<Vec<WorkflowDefinitionEntry>, WorkflowStoreError> {
        let directory = global_workflows_dir(&self.app_state_root);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(WorkflowStoreError::Io(error)),
        };
        let mut definitions = Vec::new();
        for entry in entries {
            let entry = entry.map_err(WorkflowStoreError::Io)?;
            let file_type = entry.file_type().map_err(WorkflowStoreError::Io)?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(WorkflowStoreError::UnsafeDefinitionEntry);
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let snapshot = AtomicJsonStore::new(&path, WORKFLOW_STATE_SCHEMA_VERSION)
                .load::<WorkflowDefinition>()?
                .ok_or(WorkflowStoreError::MissingDefinitionState)?;
            snapshot.value.validate()?;
            if global_definition_path(&self.app_state_root, &snapshot.value.id) != path {
                return Err(WorkflowStoreError::DefinitionPathMismatch);
            }
            definitions.push(WorkflowDefinitionEntry {
                scope: ProfileSourceScope::Global,
                definition: snapshot.value,
                revision: Some(snapshot.revision),
            });
        }
        definitions.sort_by(|left, right| left.definition.id.cmp(&right.definition.id));
        Ok(definitions)
    }

    pub fn load_workspace_definition(
        workspace_root: impl AsRef<Path>,
        workflow_id: &str,
    ) -> Result<Option<WorkflowDefinitionEntry>, WorkflowStoreError> {
        validate_storage_id(workflow_id)?;
        validate_workspace_root(workspace_root.as_ref())?;
        let path = workspace_definition_path(workspace_root.as_ref(), workflow_id);
        let Some(definition) = read_workspace_definition(&path)? else {
            return Ok(None);
        };
        if definition.id != workflow_id {
            return Err(WorkflowStoreError::DefinitionPathMismatch);
        }
        Ok(Some(WorkflowDefinitionEntry {
            scope: ProfileSourceScope::Workspace,
            definition,
            revision: None,
        }))
    }

    pub fn list_workspace_definitions(
        workspace_root: impl AsRef<Path>,
    ) -> Result<Vec<WorkflowDefinitionEntry>, WorkflowStoreError> {
        validate_workspace_root(workspace_root.as_ref())?;
        let directory = workspace_workflows_dir(workspace_root.as_ref());
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(WorkflowStoreError::Io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkflowStoreError::UnsafeDefinitionEntry);
        }
        let mut definitions = Vec::new();
        for entry in fs::read_dir(&directory).map_err(WorkflowStoreError::Io)? {
            let entry = entry.map_err(WorkflowStoreError::Io)?;
            let file_type = entry.file_type().map_err(WorkflowStoreError::Io)?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(WorkflowStoreError::UnsafeDefinitionEntry);
            }
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let definition = read_workspace_definition(&path)?
                .ok_or(WorkflowStoreError::MissingDefinitionState)?;
            if workspace_definition_path(workspace_root.as_ref(), &definition.id) != path {
                return Err(WorkflowStoreError::DefinitionPathMismatch);
            }
            definitions.push(WorkflowDefinitionEntry {
                scope: ProfileSourceScope::Workspace,
                definition,
                revision: None,
            });
        }
        definitions.sort_by(|left, right| left.definition.id.cmp(&right.definition.id));
        Ok(definitions)
    }

    pub fn materialize_revision(
        &self,
        revision: &CompiledWorkflowRevision,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, WorkflowStoreError> {
        revision.verify_digest()?;
        let store = AtomicJsonStore::new(
            workflow_revision_path(&self.app_state_root, &revision.digest),
            WORKFLOW_STATE_SCHEMA_VERSION,
        );
        match store.compare_and_swap(None, owner, revision) {
            Ok(state_revision) => Ok(state_revision),
            Err(StateError::StaleRevision { .. }) => {
                let existing = store
                    .load::<CompiledWorkflowRevision>()?
                    .ok_or_else(|| WorkflowStoreError::MissingRevision(revision.digest.clone()))?;
                if existing.value != *revision {
                    return Err(WorkflowStoreError::ImmutableCollision(
                        revision.digest.clone(),
                    ));
                }
                Ok(existing.revision)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn load_revision(
        &self,
        digest: &str,
    ) -> Result<Option<CompiledWorkflowRevision>, WorkflowStoreError> {
        if !crate::is_lower_hex_digest(digest) {
            return Err(WorkflowStoreError::InvalidDigest(digest.to_string()));
        }
        let Some(snapshot) = AtomicJsonStore::new(
            workflow_revision_path(&self.app_state_root, digest),
            WORKFLOW_STATE_SCHEMA_VERSION,
        )
        .load::<CompiledWorkflowRevision>()?
        else {
            return Ok(None);
        };
        if snapshot.value.digest != digest {
            return Err(WorkflowStoreError::DigestMismatch {
                expected: digest.to_string(),
                actual: snapshot.value.digest,
            });
        }
        snapshot.value.verify_digest()?;
        Ok(Some(snapshot.value))
    }
}

fn global_workflows_dir(app_state_root: &Path) -> PathBuf {
    app_state_root.join("workflows")
}

fn global_definition_path(app_state_root: &Path, workflow_id: &str) -> PathBuf {
    global_workflows_dir(app_state_root)
        .join(format!("{}.json", crate::encode_path_segment(workflow_id)))
}

fn workflow_revision_path(app_state_root: &Path, digest: &str) -> PathBuf {
    global_workflows_dir(app_state_root)
        .join("revisions")
        .join(format!("{}.json", crate::encode_path_segment(digest)))
}

#[must_use]
pub fn workspace_workflows_dir(workspace_root: impl AsRef<Path>) -> PathBuf {
    workspace_root.as_ref().join(".unpin").join("workflows")
}

fn workspace_definition_path(workspace_root: &Path, workflow_id: &str) -> PathBuf {
    workspace_workflows_dir(workspace_root)
        .join(format!("{}.json", crate::encode_path_segment(workflow_id)))
}

fn validate_storage_id(value: &str) -> Result<(), WorkflowStoreError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(WorkflowStoreError::InvalidWorkflowId(value.to_string()))
    } else {
        Ok(())
    }
}

fn validate_workspace_root(root: &Path) -> Result<(), WorkflowStoreError> {
    if !root.is_absolute() {
        return Err(WorkflowStoreError::UnsafeWorkspaceRoot);
    }
    let metadata = fs::symlink_metadata(root).map_err(WorkflowStoreError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorkflowStoreError::UnsafeWorkspaceRoot);
    }
    Ok(())
}

fn read_workspace_definition(
    path: &Path,
) -> Result<Option<WorkflowDefinition>, WorkflowStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(WorkflowStoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkflowStoreError::UnsafeDefinitionEntry);
    }
    if metadata.len() > MAX_WORKFLOW_DEFINITION_BYTES as u64 {
        return Err(WorkflowValidationError::DefinitionTooLarge {
            actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            maximum: MAX_WORKFLOW_DEFINITION_BYTES,
        }
        .into());
    }
    let mut file = fs::File::open(path).map_err(WorkflowStoreError::Io)?;
    let current = fs::symlink_metadata(path).map_err(WorkflowStoreError::Io)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || !crate::fs_support::path_matches_open_file(path, &file)
            .map_err(WorkflowStoreError::Io)?
    {
        return Err(WorkflowStoreError::UnsafeDefinitionEntry);
    }
    let mut raw = String::new();
    file.by_ref()
        .take((MAX_WORKFLOW_DEFINITION_BYTES + 1) as u64)
        .read_to_string(&mut raw)
        .map_err(WorkflowStoreError::Io)?;
    WorkflowDefinition::from_json(&raw)
        .map(Some)
        .map_err(Into::into)
}

#[derive(Debug)]
pub enum WorkflowStoreError {
    State(StateError),
    Validation(WorkflowValidationError),
    InvalidWorkflowId(String),
    InvalidDigest(String),
    MissingRevision(String),
    ImmutableCollision(String),
    DigestMismatch { expected: String, actual: String },
    Io(std::io::Error),
    UnsafeWorkspaceRoot,
    UnsafeDefinitionEntry,
    MissingDefinitionState,
    DefinitionPathMismatch,
}

impl From<StateError> for WorkflowStoreError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<WorkflowValidationError> for WorkflowStoreError {
    fn from(error: WorkflowValidationError) -> Self {
        Self::Validation(error)
    }
}

impl fmt::Display for WorkflowStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::InvalidWorkflowId(id) => write!(formatter, "invalid workflow id: {id:?}"),
            Self::InvalidDigest(digest) => write!(formatter, "invalid workflow digest: {digest:?}"),
            Self::MissingRevision(digest) => write!(
                formatter,
                "compiled workflow revision disappeared: {digest}"
            ),
            Self::ImmutableCollision(digest) => {
                write!(formatter, "compiled workflow digest collision: {digest}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "workflow revision digest mismatch: expected {expected}, found {actual}"
            ),
            Self::Io(error) => write!(formatter, "workflow definition I/O failed: {error}"),
            Self::UnsafeWorkspaceRoot => {
                formatter.write_str("workflow workspace root is not a trusted absolute directory")
            }
            Self::UnsafeDefinitionEntry => {
                formatter.write_str("workflow definition entry is not a safe regular file")
            }
            Self::MissingDefinitionState => {
                formatter.write_str("workflow definition disappeared during inventory")
            }
            Self::DefinitionPathMismatch => {
                formatter.write_str("workflow definition id does not match its storage path")
            }
        }
    }
}

impl std::error::Error for WorkflowStoreError {}
