use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub type StateResult<T> = Result<T, StateError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerGeneration {
    pub owner_id: String,
    pub generation: u64,
}

impl OwnerGeneration {
    pub fn new(owner_id: impl Into<String>, generation: u64) -> StateResult<Self> {
        let owner = Self {
            owner_id: owner_id.into(),
            generation,
        };
        validate_owner_generation(&owner)?;
        Ok(owner)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRevision {
    pub sequence: u64,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot<T> {
    pub schema_version: u32,
    pub revision: StateRevision,
    pub owner: OwnerGeneration,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PhysicalResourceId(String);

impl PhysicalResourceId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct AtomicJsonStore {
    requested_path: PathBuf,
    schema_version: u32,
}

impl AtomicJsonStore {
    #[must_use]
    pub fn new(path: impl AsRef<Path>, schema_version: u32) -> Self {
        Self {
            requested_path: path.as_ref().to_path_buf(),
            schema_version,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.requested_path
    }

    pub fn physical_resource_id(&self) -> StateResult<PhysicalResourceId> {
        let physical_path = resolve_physical_path(&self.requested_path, false)?;
        Ok(physical_resource_id(&physical_path))
    }

    pub fn load<T>(&self) -> StateResult<Option<StateSnapshot<T>>>
    where
        T: DeserializeOwned,
    {
        self.validate_schema_version()?;
        let physical_path = resolve_physical_path(&self.requested_path, false)?;
        read_snapshot(&physical_path, self.schema_version)
    }

    /// Loads state whose outer document schema is either the store's current
    /// schema or one of the explicitly named compatible schemas. Callers must
    /// still decode an exact value type for the returned schema.
    pub fn load_compatible<T>(
        &self,
        compatible_schemas: &[u32],
    ) -> StateResult<Option<StateSnapshot<T>>>
    where
        T: DeserializeOwned,
    {
        self.validate_schema_version()?;
        validate_compatible_schemas(self.schema_version, compatible_schemas)?;
        let physical_path = resolve_physical_path(&self.requested_path, false)?;
        read_snapshot_compatible(&physical_path, self.schema_version, compatible_schemas)
    }

    /// Atomically replaces state when `expected` still names current physical document.
    /// `None` is create-only: it succeeds only while document is absent.
    pub fn compare_and_swap<T>(
        &self,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
        value: &T,
    ) -> StateResult<StateRevision>
    where
        T: Serialize,
    {
        self.validate_schema_version()?;
        validate_owner_generation(&owner)?;
        ensure_private_writes_supported(&self.requested_path)?;

        let physical_path = resolve_physical_path(&self.requested_path, true)?;
        let _lock = ResourceLock::acquire(&physical_path)?;
        let locked_path = resolve_physical_path(&self.requested_path, true)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }

        let current = read_snapshot::<serde_json::Value>(&locked_path, self.schema_version)?;
        let actual_revision = current.as_ref().map(|snapshot| snapshot.revision.clone());
        if expected != actual_revision.as_ref() {
            return Err(StateError::StaleRevision {
                expected: expected.cloned(),
                actual: actual_revision,
            });
        }

        if let Some(current) = &current {
            validate_owner_transition(&current.owner, &owner)?;
        }
        let sequence = match &current {
            Some(snapshot) => snapshot
                .revision
                .sequence
                .checked_add(1)
                .ok_or(StateError::RevisionOverflow)?,
            None => 1,
        };
        let document = StoredDocumentRef {
            schema_version: self.schema_version,
            revision: sequence,
            owner: &owner,
            value,
        };
        let mut serialized =
            serde_json::to_vec_pretty(&document).map_err(|error| StateError::Serialization {
                path: locked_path.clone(),
                message: error.to_string(),
            })?;
        serialized.push(b'\n');

        let candidate = StateRevision {
            sequence,
            fingerprint: fingerprint(&serialized),
        };
        write_atomically(&locked_path, &serialized, &candidate)?;
        Ok(candidate)
    }

    /// Atomically replaces a document using the store's current schema after
    /// proving the existing document has the explicitly expected old schema.
    pub fn compare_and_swap_migrating_schema<T>(
        &self,
        expected: &StateRevision,
        expected_schema: u32,
        owner: OwnerGeneration,
        value: &T,
    ) -> StateResult<StateRevision>
    where
        T: Serialize,
    {
        self.validate_schema_version()?;
        validate_compatible_schemas(self.schema_version, &[expected_schema])?;
        validate_owner_generation(&owner)?;
        ensure_private_writes_supported(&self.requested_path)?;

        let physical_path = resolve_physical_path(&self.requested_path, true)?;
        let _lock = ResourceLock::acquire(&physical_path)?;
        let locked_path = resolve_physical_path(&self.requested_path, true)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }

        let current = read_snapshot::<serde_json::Value>(&locked_path, expected_schema)?
            .ok_or_else(|| StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual: None,
            })?;
        if current.revision != *expected {
            return Err(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual: Some(current.revision),
            });
        }
        validate_owner_transition(&current.owner, &owner)?;
        let sequence = current
            .revision
            .sequence
            .checked_add(1)
            .ok_or(StateError::RevisionOverflow)?;
        write_document(&locked_path, self.schema_version, sequence, &owner, value)
    }

    /// Removes current state only when its revision still matches `expected`.
    pub fn remove_if_revision(&self, expected: &StateRevision) -> StateResult<()> {
        self.validate_schema_version()?;
        ensure_private_writes_supported(&self.requested_path)?;

        let physical_path = resolve_physical_path(&self.requested_path, false)?;
        let _lock = ResourceLock::acquire(&physical_path)?;
        let locked_path = resolve_physical_path(&self.requested_path, false)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }
        let current = read_snapshot::<serde_json::Value>(&locked_path, self.schema_version)?;
        let actual = current.map(|snapshot| snapshot.revision);
        if actual.as_ref() != Some(expected) {
            return Err(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual,
            });
        }
        fs::remove_file(&locked_path).map_err(|error| io_error(&locked_path, error))?;
        sync_parent_directory(locked_path.parent().expect("state file has parent"))
    }

    /// Removes current state when its schema is either the store's current
    /// schema or one explicitly named compatible schema.
    pub fn remove_if_revision_compatible(
        &self,
        expected: &StateRevision,
        compatible_schemas: &[u32],
    ) -> StateResult<()> {
        self.validate_schema_version()?;
        validate_compatible_schemas(self.schema_version, compatible_schemas)?;
        ensure_private_writes_supported(&self.requested_path)?;

        let physical_path = resolve_physical_path(&self.requested_path, false)?;
        let _lock = ResourceLock::acquire(&physical_path)?;
        let locked_path = resolve_physical_path(&self.requested_path, false)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }

        let current = read_snapshot_compatible::<serde_json::Value>(
            &locked_path,
            self.schema_version,
            compatible_schemas,
        )?;
        let actual = current.map(|snapshot| snapshot.revision);
        if actual.as_ref() != Some(expected) {
            return Err(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual,
            });
        }
        fs::remove_file(&locked_path).map_err(|error| io_error(&locked_path, error))?;
        sync_parent_directory(locked_path.parent().expect("state file has parent"))
    }

    fn validate_schema_version(&self) -> StateResult<()> {
        if self.schema_version == 0 {
            Err(StateError::InvalidSchemaVersion)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredDocument<T> {
    schema_version: u32,
    revision: u64,
    owner: OwnerGeneration,
    value: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredDocumentRef<'a, T> {
    schema_version: u32,
    revision: u64,
    owner: &'a OwnerGeneration,
    value: &'a T,
}

fn read_snapshot<T>(path: &Path, expected_schema: u32) -> StateResult<Option<StateSnapshot<T>>>
where
    T: DeserializeOwned,
{
    read_snapshot_compatible(path, expected_schema, &[])
}

fn read_snapshot_compatible<T>(
    path: &Path,
    expected_schema: u32,
    compatible_schemas: &[u32],
) -> StateResult<Option<StateSnapshot<T>>>
where
    T: DeserializeOwned,
{
    reject_state_file_symlink(path)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
        Ok(metadata) if !metadata.is_file() => {
            return Err(StateError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        Ok(_) => {}
    }

    let mut file = File::open(path).map_err(|error| io_error(path, error))?;
    validate_opened_file(path, &file)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|error| io_error(path, error))?;
    let document: StoredDocument<T> =
        serde_json::from_slice(&raw).map_err(|error| StateError::InvalidJson {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if document.schema_version != expected_schema
        && !compatible_schemas.contains(&document.schema_version)
    {
        return Err(StateError::SchemaVersionMismatch {
            expected: expected_schema,
            actual: document.schema_version,
        });
    }
    if document.revision == 0 {
        return Err(StateError::InvalidRevision {
            path: path.to_path_buf(),
        });
    }
    validate_owner_generation(&document.owner)?;

    Ok(Some(StateSnapshot {
        schema_version: document.schema_version,
        revision: StateRevision {
            sequence: document.revision,
            fingerprint: fingerprint(&raw),
        },
        owner: document.owner,
        value: document.value,
    }))
}

fn validate_compatible_schemas(current: u32, compatible: &[u32]) -> StateResult<()> {
    if compatible
        .iter()
        .any(|schema| *schema == 0 || *schema == current)
    {
        Err(StateError::InvalidSchemaVersion)
    } else {
        Ok(())
    }
}

fn write_document<T>(
    path: &Path,
    schema_version: u32,
    sequence: u64,
    owner: &OwnerGeneration,
    value: &T,
) -> StateResult<StateRevision>
where
    T: Serialize,
{
    let document = StoredDocumentRef {
        schema_version,
        revision: sequence,
        owner,
        value,
    };
    let mut serialized =
        serde_json::to_vec_pretty(&document).map_err(|error| StateError::Serialization {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    serialized.push(b'\n');
    let candidate = StateRevision {
        sequence,
        fingerprint: fingerprint(&serialized),
    };
    write_atomically(path, &serialized, &candidate)?;
    Ok(candidate)
}

fn validate_owner_generation(owner: &OwnerGeneration) -> StateResult<()> {
    if owner.owner_id.trim().is_empty() || owner.generation == 0 || owner.generation == u64::MAX {
        return Err(StateError::InvalidOwnerGeneration);
    }
    Ok(())
}

fn validate_owner_transition(
    current: &OwnerGeneration,
    requested: &OwnerGeneration,
) -> StateResult<()> {
    let valid = if current.owner_id == requested.owner_id {
        requested.generation >= current.generation
    } else {
        requested.generation > current.generation
    };
    if valid {
        Ok(())
    } else {
        Err(StateError::StaleOwnerGeneration {
            current: current.clone(),
            requested: requested.clone(),
        })
    }
}

fn resolve_physical_path(requested_path: &Path, create_parent: bool) -> StateResult<PathBuf> {
    let absolute = absolute_lexical_path(requested_path)?;
    if absolute.file_name().is_none() {
        return Err(StateError::NotRegularFile { path: absolute });
    }

    let parent = absolute
        .parent()
        .ok_or_else(|| StateError::NotRegularFile {
            path: absolute.clone(),
        })?;
    if create_parent {
        create_private_directories(parent)?;
    } else {
        validate_directory_chain(parent)?;
    }
    validate_directory_chain(parent)?;
    reject_state_file_symlink(&absolute)?;
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) if !metadata.is_file() => Err(StateError::NotRegularFile { path: absolute }),
        Ok(_) => Ok(absolute),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(absolute),
        Err(error) => Err(io_error(&absolute, error)),
    }
}

fn absolute_lexical_path(requested_path: &Path) -> StateResult<PathBuf> {
    let joined = if requested_path.is_absolute() {
        requested_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error(requested_path, error))?
            .join(requested_path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(StateError::NotRegularFile { path: joined });
                }
            }
        }
    }
    Ok(normalized)
}

fn validate_directory_chain(path: &Path) -> StateResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::SymlinkRejected { path: current });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(StateError::NotRegularFile { path: current });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(&current, error)),
        }
    }
    Ok(())
}

fn create_private_directories(path: &Path) -> StateResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let created = match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::SymlinkRejected { path: current });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(StateError::NotRegularFile { path: current });
            }
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match create_private_directory(&current) {
                    Ok(()) => true,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                    Err(error) => return Err(io_error(&current, error)),
                }
            }
            Err(error) => return Err(io_error(&current, error)),
        };
        let metadata = fs::symlink_metadata(&current).map_err(|error| io_error(&current, error))?;
        if metadata.file_type().is_symlink() {
            return Err(StateError::SymlinkRejected { path: current });
        }
        if !metadata.is_dir() {
            return Err(StateError::NotRegularFile { path: current });
        }
        if created {
            verify_private_directory(&current)?;
            sync_parent_directory(&current)?;
            if let Some(parent) = current.parent() {
                sync_parent_directory(parent)?;
            }
        }
    }
    validate_directory_chain(path)?;
    verify_private_directory(path)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> StateResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::symlink_metadata(path)
        .map_err(|error| io_error(path, error))?
        .permissions()
        .mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(StateError::InsecurePrivatePermissions {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(not(unix))]
fn verify_private_directory(path: &Path) -> StateResult<()> {
    Err(StateError::PrivatePermissionsUnsupported {
        path: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn ensure_private_writes_supported(_path: &Path) -> StateResult<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_writes_supported(path: &Path) -> StateResult<()> {
    Err(StateError::PrivatePermissionsUnsupported {
        path: path.to_path_buf(),
    })
}

fn reject_state_file_symlink(path: &Path) -> StateResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StateError::SymlinkRejected {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

struct ResourceLock {
    _file: File,
}

/// Cross-process lock for one physical state resource. Lock path stays private
/// and stable so deleting the guarded resource cannot split the lock domain.
pub struct StateResourceLock {
    _inner: ResourceLock,
}

impl StateResourceLock {
    pub fn acquire(resource_path: impl AsRef<Path>) -> StateResult<Self> {
        ensure_private_writes_supported(resource_path.as_ref())?;
        let physical_path = resolve_physical_path(resource_path.as_ref(), true)?;
        let inner = ResourceLock::acquire(&physical_path)?;
        let locked_path = resolve_physical_path(resource_path.as_ref(), true)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }
        Ok(Self { _inner: inner })
    }

    pub fn acquire_with_timeout(
        resource_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> StateResult<Self> {
        ensure_private_writes_supported(resource_path.as_ref())?;
        let physical_path = resolve_physical_path(resource_path.as_ref(), true)?;
        let inner = ResourceLock::acquire_with_timeout(&physical_path, timeout)?;
        let locked_path = resolve_physical_path(resource_path.as_ref(), true)?;
        if physical_resource_id(&locked_path) != physical_resource_id(&physical_path) {
            return Err(StateError::PhysicalResourceChanged {
                before: physical_path,
                after: locked_path,
            });
        }
        Ok(Self { _inner: inner })
    }
}

impl ResourceLock {
    fn acquire(resource_path: &Path) -> StateResult<Self> {
        let resource_id = physical_resource_id(resource_path);
        let lock_path =
            resource_path.with_file_name(format!(".unpin-resource-{}.lock", resource_id.as_str()));
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::SymlinkRejected { path: lock_path });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(StateError::NotRegularFile { path: lock_path });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&lock_path, error)),
        }
        let file = open_private_lock_file(&lock_path)?;
        file.lock().map_err(|error| io_error(&lock_path, error))?;
        validate_opened_file(&lock_path, &file)?;
        Ok(Self { _file: file })
    }

    fn acquire_with_timeout(resource_path: &Path, timeout: Duration) -> StateResult<Self> {
        let resource_id = physical_resource_id(resource_path);
        let lock_path =
            resource_path.with_file_name(format!(".unpin-resource-{}.lock", resource_id.as_str()));
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StateError::SymlinkRejected { path: lock_path });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(StateError::NotRegularFile { path: lock_path });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&lock_path, error)),
        }
        let file = open_private_lock_file(&lock_path)?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if started.elapsed() < timeout => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(StateError::LockUnavailable { path: lock_path });
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(io_error(&lock_path, error));
                }
            }
        }
        validate_opened_file(&lock_path, &file)?;
        Ok(Self { _file: file })
    }
}

fn open_private_lock_file(path: &Path) -> StateResult<File> {
    let mut create_options = OpenOptions::new();
    create_options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options.mode(0o600);
    }
    let file = match create_options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| io_error(path, error))?,
        Err(error) => return Err(io_error(path, error)),
    };
    validate_opened_file(path, &file)?;
    set_private_open_file_permissions(path, &file)?;
    Ok(file)
}

#[cfg(any(unix, windows))]
fn validate_opened_file(path: &Path, file: &File) -> StateResult<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if path_metadata.file_type().is_symlink() {
        return Err(StateError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    if !path_metadata.is_file() {
        return Err(StateError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if !crate::fs_support::path_matches_open_file(path, file)
        .map_err(|error| io_error(path, error))?
    {
        return Err(StateError::PhysicalResourceChanged {
            before: path.to_path_buf(),
            after: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_opened_file(path: &Path, _file: &File) -> StateResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StateError::SymlinkRejected {
            path: path.to_path_buf(),
        }),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(StateError::NotRegularFile {
            path: path.to_path_buf(),
        }),
        Err(error) => Err(io_error(path, error)),
    }
}

fn write_atomically(path: &Path, bytes: &[u8], candidate: &StateRevision) -> StateResult<()> {
    write_atomically_with_sync(path, bytes, candidate, sync_parent_directory)
}

fn write_atomically_with_sync<F>(
    path: &Path,
    bytes: &[u8],
    candidate: &StateRevision,
    sync_parent: F,
) -> StateResult<()>
where
    F: FnOnce(&Path) -> StateResult<()>,
{
    let parent = path.parent().ok_or_else(|| StateError::NotRegularFile {
        path: path.to_path_buf(),
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let temporary_path = parent.join(format!(
        ".{file_name}.unpin-{}-{}.tmp",
        process::id(),
        TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let precommit_result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut temporary = options
            .open(&temporary_path)
            .map_err(|error| io_error(&temporary_path, error))?;
        validate_opened_file(&temporary_path, &temporary)?;
        set_private_open_file_permissions(&temporary_path, &temporary)?;
        temporary
            .write_all(bytes)
            .map_err(|error| io_error(&temporary_path, error))?;
        temporary
            .sync_all()
            .map_err(|error| io_error(&temporary_path, error))?;
        validate_opened_file(&temporary_path, &temporary)?;
        drop(temporary);
        Ok(())
    })();
    if let Err(error) = precommit_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = replace_file(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    sync_parent(parent).map_err(|error| StateError::CommitUncertain {
        path: path.to_path_buf(),
        candidate: candidate.clone(),
        message: error.to_string(),
    })
}

fn replace_file(temporary_path: &Path, path: &Path) -> StateResult<()> {
    fs::rename(temporary_path, path).map_err(|error| io_error(path, error))
}

#[cfg(unix)]
fn set_private_open_file_permissions(path: &Path, file: &File) -> StateResult<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
fn set_private_open_file_permissions(path: &Path, _file: &File) -> StateResult<()> {
    Err(StateError::PrivatePermissionsUnsupported {
        path: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> StateResult<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(parent, error))
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> StateResult<()> {
    Ok(())
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}

fn physical_resource_id(path: &Path) -> PhysicalResourceId {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-physical-resource-v1\0");
    update_hasher_with_path(&mut hasher, path);
    let encoded = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    PhysicalResourceId(encoded)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    hasher.update(bytes.len().to_be_bytes());
    hasher.update(bytes);
}

#[cfg(target_os = "macos")]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    let normalized = path.to_string_lossy().to_lowercase();
    hasher.update(normalized.len().to_be_bytes());
    hasher.update(normalized.as_bytes());
}

#[cfg(windows)]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    let units = path
        .to_string_lossy()
        .to_lowercase()
        .encode_utf16()
        .collect::<Vec<_>>();
    hasher.update(units.len().to_be_bytes());
    for unit in units {
        hasher.update(unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    let value = path.to_string_lossy();
    hasher.update(value.len().to_be_bytes());
    hasher.update(value.as_bytes());
}

fn io_error(path: &Path, error: io::Error) -> StateError {
    StateError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Io {
        path: PathBuf,
        message: String,
    },
    InvalidJson {
        path: PathBuf,
        message: String,
    },
    Serialization {
        path: PathBuf,
        message: String,
    },
    SymlinkRejected {
        path: PathBuf,
    },
    NotRegularFile {
        path: PathBuf,
    },
    InvalidSchemaVersion,
    SchemaVersionMismatch {
        expected: u32,
        actual: u32,
    },
    InvalidRevision {
        path: PathBuf,
    },
    RevisionOverflow,
    InvalidOwnerGeneration,
    PrivatePermissionsUnsupported {
        path: PathBuf,
    },
    InsecurePrivatePermissions {
        path: PathBuf,
    },
    PhysicalResourceChanged {
        before: PathBuf,
        after: PathBuf,
    },
    CommitUncertain {
        path: PathBuf,
        candidate: StateRevision,
        message: String,
    },
    StaleRevision {
        expected: Option<StateRevision>,
        actual: Option<StateRevision>,
    },
    StaleOwnerGeneration {
        current: OwnerGeneration,
        requested: OwnerGeneration,
    },
    LockUnavailable {
        path: PathBuf,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "{}: {message}", path.display()),
            Self::InvalidJson { path, message } => {
                write!(
                    formatter,
                    "{} is not valid state JSON: {message}",
                    path.display()
                )
            }
            Self::Serialization { path, message } => {
                write!(
                    formatter,
                    "could not serialize state for {}: {message}",
                    path.display()
                )
            }
            Self::SymlinkRejected { path } => {
                write!(
                    formatter,
                    "state symlink is not allowed: {}",
                    path.display()
                )
            }
            Self::NotRegularFile { path } => {
                write!(
                    formatter,
                    "state path is not a regular file: {}",
                    path.display()
                )
            }
            Self::InvalidSchemaVersion => {
                formatter.write_str("state schema version must be positive")
            }
            Self::SchemaVersionMismatch { expected, actual } => write!(
                formatter,
                "state schema version mismatch: expected {expected}, found {actual}"
            ),
            Self::InvalidRevision { path } => {
                write!(
                    formatter,
                    "state revision must be positive: {}",
                    path.display()
                )
            }
            Self::RevisionOverflow => formatter.write_str("state revision overflow"),
            Self::InvalidOwnerGeneration => {
                formatter.write_str(
                    "state owner id must be non-empty and generation must be between 1 and u64::MAX - 1",
                )
            }
            Self::PrivatePermissionsUnsupported { path } => {
                write!(
                    formatter,
                    "private state permissions are unsupported on this platform: {}",
                    path.display()
                )
            }
            Self::InsecurePrivatePermissions { path } => {
                write!(
                    formatter,
                    "state directory is not private: {}",
                    path.display()
                )
            }
            Self::PhysicalResourceChanged { before, after } => {
                write!(
                    formatter,
                    "state physical resource changed while locking: {} -> {}",
                    before.display(),
                    after.display()
                )
            }
            Self::CommitUncertain {
                path,
                candidate,
                message,
            } => {
                write!(
                    formatter,
                    "state replacement may have committed at {} (revision {}, fingerprint {}), but durability confirmation failed: {message}",
                    path.display(),
                    candidate.sequence,
                    candidate.fingerprint
                )
            }
            Self::StaleRevision { .. } => formatter.write_str("state revision is stale"),
            Self::StaleOwnerGeneration { .. } => {
                formatter.write_str("state owner generation is stale")
            }
            Self::LockUnavailable { path } => {
                write!(formatter, "state resource lock is busy: {}", path.display())
            }
        }
    }
}

impl std::error::Error for StateError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parent_sync_failure_reports_commit_uncertain_with_live_candidate() {
        let temp = TempDir::new().expect("temporary state");
        let parent = fs::canonicalize(temp.path()).expect("physical temporary root");
        let path = parent.join("state.json");
        let bytes = b"{\n  \"schemaVersion\": 1,\n  \"revision\": 7,\n  \"owner\": {\n    \"ownerId\": \"owner\",\n    \"generation\": 1\n  },\n  \"value\": {\n    \"candidate\": true\n  }\n}\n";
        let candidate = StateRevision {
            sequence: 7,
            fingerprint: fingerprint(bytes),
        };

        let error = write_atomically_with_sync(&path, bytes, &candidate, |directory| {
            Err(StateError::Io {
                path: directory.to_path_buf(),
                message: "injected parent sync failure".to_owned(),
            })
        })
        .expect_err("injected sync failure");

        assert_eq!(
            error,
            StateError::CommitUncertain {
                path: path.clone(),
                candidate: candidate.clone(),
                message: format!("{}: injected parent sync failure", parent.display()),
            }
        );
        assert_eq!(fs::read(&path).expect("candidate is live"), bytes);
        let reloaded = read_snapshot::<serde_json::Value>(&path, 1)
            .expect("reconcile candidate")
            .expect("candidate exists");
        assert_eq!(reloaded.revision, candidate);
    }
}
