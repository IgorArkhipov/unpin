use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type WorkspaceResult<T> = Result<T, WorkspaceIdentityError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    pub repository_key: String,
    pub workspace_key: String,
    pub canonical_root: PathBuf,
    pub git_common_dir: Option<PathBuf>,
    pub git_worktree_dir: Option<PathBuf>,
    pub diagnostics: WorkspaceDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhysicalDirectoryEvidence {
    pub canonical_path: PathBuf,
    pub incarnation_digest: String,
    pub reliable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspacePhysicalEvidence {
    pub repository_key: String,
    pub workspace_key: String,
    pub workspace_root: PhysicalDirectoryEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_common_dir: Option<PhysicalDirectoryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_worktree_dir: Option<PhysicalDirectoryEvidence>,
}

impl WorkspacePhysicalEvidence {
    #[must_use]
    pub fn is_reliable_git_workspace(&self) -> bool {
        self.workspace_root.reliable
            && self
                .git_common_dir
                .as_ref()
                .is_some_and(|evidence| evidence.reliable)
            && self
                .git_worktree_dir
                .as_ref()
                .is_some_and(|evidence| evidence.reliable)
    }

    #[must_use]
    pub fn same_physical_workspace(&self, other: &Self) -> bool {
        self.is_reliable_git_workspace()
            && other.is_reliable_git_workspace()
            && self.workspace_root.incarnation_digest == other.workspace_root.incarnation_digest
            && self
                .git_common_dir
                .as_ref()
                .zip(other.git_common_dir.as_ref())
                .is_some_and(|(left, right)| left.incarnation_digest == right.incarnation_digest)
            && self
                .git_worktree_dir
                .as_ref()
                .zip(other.git_worktree_dir.as_ref())
                .is_some_and(|(left, right)| left.incarnation_digest == right.incarnation_digest)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceDiagnostics {
    pub branch: Option<String>,
    pub head: Option<String>,
    pub warnings: Vec<WorkspaceDiagnosticWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceDiagnosticWarning {
    pub source: WorkspaceDiagnosticSource,
    pub kind: WorkspaceDiagnosticWarningKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDiagnosticSource {
    Head,
    LooseReference,
    PackedReferences,
    RepositoryIdentity,
    WorkspaceIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDiagnosticWarningKind {
    ReadFailed,
    InvalidReference,
    InvalidObjectId,
    SymlinkRejected,
    StableFilesystemIdentityUnavailable,
}

pub fn resolve_workspace_identity(
    project_root: impl AsRef<Path>,
) -> WorkspaceResult<WorkspaceIdentity> {
    let requested_root = project_root.as_ref();
    let canonical_input = fs::canonicalize(requested_root)
        .map_err(|error| identity_io_error(requested_root, error))?;
    let search_root = if canonical_input.is_dir() {
        canonical_input
    } else {
        canonical_input
            .parent()
            .ok_or_else(|| WorkspaceIdentityError::InvalidRoot {
                path: requested_root.to_path_buf(),
            })?
            .to_path_buf()
    };

    let Some((canonical_root, git_marker)) = find_git_root(&search_root)? else {
        let incarnation = filesystem_incarnation(&search_root)?;
        let repository_key = hash_key("repository-root-v2", &[&search_root], &[&incarnation]);
        let workspace_key = hash_key(
            "workspace-root-v2",
            &[Path::new(&repository_key), &search_root],
            &[&incarnation],
        );
        let mut diagnostics = WorkspaceDiagnostics::default();
        if incarnation.is_degraded() {
            diagnostics.warn(
                WorkspaceDiagnosticSource::RepositoryIdentity,
                WorkspaceDiagnosticWarningKind::StableFilesystemIdentityUnavailable,
            );
        }
        return Ok(WorkspaceIdentity {
            repository_key,
            workspace_key,
            canonical_root: search_root,
            git_common_dir: None,
            git_worktree_dir: None,
            diagnostics,
        });
    };

    let (git_worktree_dir, git_common_dir) = resolve_git_dirs(&git_marker)?;
    let repository_incarnation = filesystem_incarnation(&git_common_dir)?;
    let root_incarnation = filesystem_incarnation(&canonical_root)?;
    let workspace_incarnation = filesystem_incarnation(&git_worktree_dir)?;
    let repository_key = hash_key(
        "git-common-dir-v2",
        &[&git_common_dir],
        &[&repository_incarnation],
    );
    let workspace_key = hash_key(
        "git-workspace-v2",
        &[
            Path::new(&repository_key),
            &canonical_root,
            &git_worktree_dir,
        ],
        &[&root_incarnation, &workspace_incarnation],
    );
    let mut diagnostics = read_git_diagnostics(&git_worktree_dir, &git_common_dir);
    if repository_incarnation.is_degraded() {
        diagnostics.warn(
            WorkspaceDiagnosticSource::RepositoryIdentity,
            WorkspaceDiagnosticWarningKind::StableFilesystemIdentityUnavailable,
        );
    }
    if root_incarnation.is_degraded() || workspace_incarnation.is_degraded() {
        diagnostics.warn(
            WorkspaceDiagnosticSource::WorkspaceIdentity,
            WorkspaceDiagnosticWarningKind::StableFilesystemIdentityUnavailable,
        );
    }

    Ok(WorkspaceIdentity {
        repository_key,
        workspace_key,
        canonical_root,
        git_common_dir: Some(git_common_dir),
        git_worktree_dir: Some(git_worktree_dir),
        diagnostics,
    })
}

pub fn capture_workspace_physical_evidence(
    project_root: impl AsRef<Path>,
) -> WorkspaceResult<WorkspacePhysicalEvidence> {
    let identity = resolve_workspace_identity(project_root)?;
    let workspace_root = directory_evidence(&identity.canonical_root)?;
    let git_common_dir = identity
        .git_common_dir
        .as_deref()
        .map(directory_evidence)
        .transpose()?;
    let git_worktree_dir = identity
        .git_worktree_dir
        .as_deref()
        .map(directory_evidence)
        .transpose()?;
    Ok(WorkspacePhysicalEvidence {
        repository_key: identity.repository_key,
        workspace_key: identity.workspace_key,
        workspace_root,
        git_common_dir,
        git_worktree_dir,
    })
}

fn directory_evidence(path: &Path) -> WorkspaceResult<PhysicalDirectoryEvidence> {
    let incarnation = filesystem_incarnation(path)?;
    let reliable = !incarnation.is_degraded();
    Ok(PhysicalDirectoryEvidence {
        canonical_path: path.to_path_buf(),
        incarnation_digest: incarnation_digest(&incarnation),
        reliable,
    })
}

fn incarnation_digest(incarnation: &FilesystemIncarnation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-workspace-physical-incarnation-v1\0");
    update_hasher_with_incarnation(&mut hasher, incarnation);
    crate::encode_lower_hex(&hasher.finalize())
}

fn find_git_root(search_root: &Path) -> WorkspaceResult<Option<(PathBuf, PathBuf)>> {
    for ancestor in search_root.ancestors() {
        let marker = ancestor.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(WorkspaceIdentityError::SymlinkedGitMetadata { path: marker });
            }
            Ok(metadata) if metadata.is_dir() || metadata.is_file() => {
                let root = fs::canonicalize(ancestor)
                    .map_err(|error| identity_io_error(ancestor, error))?;
                return Ok(Some((root, marker)));
            }
            Ok(_) => return Err(WorkspaceIdentityError::InvalidGitMetadata { path: marker }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(identity_io_error(&marker, error)),
        }
    }
    Ok(None)
}

fn resolve_git_dirs(git_marker: &Path) -> WorkspaceResult<(PathBuf, PathBuf)> {
    let metadata =
        fs::symlink_metadata(git_marker).map_err(|error| identity_io_error(git_marker, error))?;
    let git_worktree_dir = if metadata.is_dir() {
        fs::canonicalize(git_marker).map_err(|error| identity_io_error(git_marker, error))?
    } else if metadata.is_file() {
        let raw =
            fs::read_to_string(git_marker).map_err(|error| identity_io_error(git_marker, error))?;
        let path = raw
            .trim()
            .strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| WorkspaceIdentityError::InvalidGitMetadata {
                path: git_marker.to_path_buf(),
            })?;
        let path = Path::new(path);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            git_marker
                .parent()
                .expect(".git marker has parent")
                .join(path)
        };
        fs::canonicalize(&resolved).map_err(|error| identity_io_error(&resolved, error))?
    } else {
        return Err(WorkspaceIdentityError::InvalidGitMetadata {
            path: git_marker.to_path_buf(),
        });
    };

    let common_dir_file = git_worktree_dir.join("commondir");
    let git_common_dir = match fs::read_to_string(&common_dir_file) {
        Ok(raw) => {
            let path = Path::new(raw.trim());
            if path.as_os_str().is_empty() {
                return Err(WorkspaceIdentityError::InvalidGitMetadata {
                    path: common_dir_file,
                });
            }
            let resolved = if path.is_absolute() {
                path.to_path_buf()
            } else {
                git_worktree_dir.join(path)
            };
            fs::canonicalize(&resolved).map_err(|error| identity_io_error(&resolved, error))?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => git_worktree_dir.clone(),
        Err(error) => return Err(identity_io_error(&common_dir_file, error)),
    };
    if !git_common_dir.is_dir() {
        return Err(WorkspaceIdentityError::InvalidGitMetadata {
            path: git_common_dir,
        });
    }

    Ok((git_worktree_dir, git_common_dir))
}

impl WorkspaceDiagnostics {
    fn warn(&mut self, source: WorkspaceDiagnosticSource, kind: WorkspaceDiagnosticWarningKind) {
        let warning = WorkspaceDiagnosticWarning { source, kind };
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
}

fn read_git_diagnostics(git_worktree_dir: &Path, git_common_dir: &Path) -> WorkspaceDiagnostics {
    let mut diagnostics = WorkspaceDiagnostics::default();
    let head_path = git_worktree_dir.join("HEAD");
    let raw = match read_diagnostic_file(
        &head_path,
        WorkspaceDiagnosticSource::Head,
        &mut diagnostics,
    ) {
        DiagnosticRead::Content(raw) => raw,
        DiagnosticRead::Missing | DiagnosticRead::Rejected => return diagnostics,
    };
    let Some(head_value) = single_diagnostic_line(&raw) else {
        diagnostics.warn(
            WorkspaceDiagnosticSource::Head,
            if raw.starts_with("ref: ") {
                WorkspaceDiagnosticWarningKind::InvalidReference
            } else {
                WorkspaceDiagnosticWarningKind::InvalidObjectId
            },
        );
        return diagnostics;
    };
    if let Some(reference) = head_value.strip_prefix("ref: ") {
        if !is_valid_symbolic_reference(reference) {
            diagnostics.warn(
                WorkspaceDiagnosticSource::Head,
                WorkspaceDiagnosticWarningKind::InvalidReference,
            );
            return diagnostics;
        }
        diagnostics.branch = reference.strip_prefix("refs/heads/").map(ToOwned::to_owned);
        diagnostics.head = resolve_git_reference(
            reference,
            git_worktree_dir,
            git_common_dir,
            &mut diagnostics,
        );
    } else if is_valid_object_id(head_value) {
        diagnostics.head = Some(head_value.to_string());
    } else {
        diagnostics.warn(
            WorkspaceDiagnosticSource::Head,
            WorkspaceDiagnosticWarningKind::InvalidObjectId,
        );
    }
    diagnostics
}

fn resolve_git_reference(
    reference: &str,
    git_worktree_dir: &Path,
    git_common_dir: &Path,
    diagnostics: &mut WorkspaceDiagnostics,
) -> Option<String> {
    for root in [
        Some(git_worktree_dir),
        (git_worktree_dir != git_common_dir).then_some(git_common_dir),
    ]
    .into_iter()
    .flatten()
    {
        match read_relative_diagnostic_file(
            root,
            reference,
            WorkspaceDiagnosticSource::LooseReference,
            diagnostics,
        ) {
            DiagnosticRead::Content(raw) => {
                let Some(object_id) = single_diagnostic_line(&raw) else {
                    diagnostics.warn(
                        WorkspaceDiagnosticSource::LooseReference,
                        WorkspaceDiagnosticWarningKind::InvalidObjectId,
                    );
                    return None;
                };
                if is_valid_object_id(object_id) {
                    return Some(object_id.to_string());
                }
                diagnostics.warn(
                    WorkspaceDiagnosticSource::LooseReference,
                    WorkspaceDiagnosticWarningKind::InvalidObjectId,
                );
                return None;
            }
            DiagnosticRead::Missing => {}
            DiagnosticRead::Rejected => return None,
        }
    }

    let packed_refs = git_common_dir.join("packed-refs");
    let raw = match read_diagnostic_file(
        &packed_refs,
        WorkspaceDiagnosticSource::PackedReferences,
        diagnostics,
    ) {
        DiagnosticRead::Content(raw) => raw,
        DiagnosticRead::Missing | DiagnosticRead::Rejected => return None,
    };
    for line in raw.lines() {
        if line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let Some((object_id, candidate)) = line.split_once(' ') else {
            continue;
        };
        if candidate != reference {
            continue;
        }
        if is_valid_object_id(object_id) {
            return Some(object_id.to_string());
        }
        diagnostics.warn(
            WorkspaceDiagnosticSource::PackedReferences,
            WorkspaceDiagnosticWarningKind::InvalidObjectId,
        );
        return None;
    }
    None
}

#[derive(Debug)]
enum DiagnosticRead {
    Missing,
    Content(String),
    Rejected,
}

fn read_diagnostic_file(
    path: &Path,
    source: WorkspaceDiagnosticSource,
    diagnostics: &mut WorkspaceDiagnostics,
) -> DiagnosticRead {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return DiagnosticRead::Missing,
        Err(_) => {
            diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
            return DiagnosticRead::Rejected;
        }
    };
    if metadata.file_type().is_symlink() {
        diagnostics.warn(source, WorkspaceDiagnosticWarningKind::SymlinkRejected);
        return DiagnosticRead::Rejected;
    }
    if !metadata.is_file() {
        diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
        return DiagnosticRead::Rejected;
    }
    match fs::read_to_string(path) {
        Ok(raw) => DiagnosticRead::Content(raw),
        Err(_) => {
            diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
            DiagnosticRead::Rejected
        }
    }
}

fn read_relative_diagnostic_file(
    root: &Path,
    reference: &str,
    source: WorkspaceDiagnosticSource,
    diagnostics: &mut WorkspaceDiagnostics,
) -> DiagnosticRead {
    debug_assert!(is_valid_symbolic_reference(reference));
    let components = reference.split('/').collect::<Vec<_>>();
    let mut path = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return DiagnosticRead::Missing;
            }
            Err(_) => {
                diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
                return DiagnosticRead::Rejected;
            }
        };
        if metadata.file_type().is_symlink() {
            diagnostics.warn(source, WorkspaceDiagnosticWarningKind::SymlinkRejected);
            return DiagnosticRead::Rejected;
        }
        let is_leaf = index + 1 == components.len();
        if (is_leaf && !metadata.is_file()) || (!is_leaf && !metadata.is_dir()) {
            diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
            return DiagnosticRead::Rejected;
        }
    }
    match fs::read_to_string(&path) {
        Ok(raw) => DiagnosticRead::Content(raw),
        Err(_) => {
            diagnostics.warn(source, WorkspaceDiagnosticWarningKind::ReadFailed);
            DiagnosticRead::Rejected
        }
    }
}

fn single_diagnostic_line(raw: &str) -> Option<&str> {
    let raw = raw.strip_suffix('\n').unwrap_or(raw);
    let raw = raw.strip_suffix('\r').unwrap_or(raw);
    (!raw.is_empty() && !raw.chars().any(char::is_control)).then_some(raw)
}

fn is_valid_symbolic_reference(reference: &str) -> bool {
    if !reference.starts_with("refs/")
        || reference.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\\'
        })
        || Path::new(reference)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return false;
    }
    let mut components = reference.split('/');
    if components.next() != Some("refs") {
        return false;
    }
    let mut count = 0;
    for component in components {
        if component.is_empty() || matches!(component, "." | "..") {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn is_valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemIncarnation {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows {
        volume: u32,
        file_index: u64,
        reliable: bool,
    },
    #[cfg(not(any(unix, windows)))]
    CreationTime {
        before_unix_epoch: bool,
        seconds: u64,
        nanoseconds: u32,
    },
    #[cfg(not(any(unix, windows)))]
    Degraded,
}

impl FilesystemIncarnation {
    fn is_degraded(self) -> bool {
        #[cfg(unix)]
        {
            false
        }
        #[cfg(windows)]
        {
            matches!(
                self,
                Self::Windows {
                    reliable: false,
                    ..
                }
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            matches!(self, Self::Degraded)
        }
    }
}

#[cfg(not(windows))]
fn filesystem_incarnation(path: &Path) -> WorkspaceResult<FilesystemIncarnation> {
    let metadata = fs::metadata(path).map_err(|error| identity_io_error(path, error))?;
    Ok(platform_filesystem_incarnation(path, &metadata))
}

#[cfg(windows)]
fn filesystem_incarnation(path: &Path) -> WorkspaceResult<FilesystemIncarnation> {
    let identity = crate::fs_support::windows_path_identity(path)
        .map_err(|error| identity_io_error(path, error))?;
    Ok(FilesystemIncarnation::Windows {
        volume: identity.legacy_volume,
        file_index: identity.legacy_file_index,
        reliable: identity.workspace_reliable,
    })
}

#[cfg(unix)]
fn platform_filesystem_incarnation(_path: &Path, metadata: &fs::Metadata) -> FilesystemIncarnation {
    use std::os::unix::fs::MetadataExt;

    FilesystemIncarnation::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_filesystem_incarnation(_path: &Path, metadata: &fs::Metadata) -> FilesystemIncarnation {
    creation_time_incarnation(metadata)
}

#[cfg(not(any(unix, windows)))]
fn creation_time_incarnation(metadata: &fs::Metadata) -> FilesystemIncarnation {
    use std::time::UNIX_EPOCH;

    let Ok(created) = metadata.created() else {
        return FilesystemIncarnation::Degraded;
    };
    let (before_unix_epoch, duration) = match created.duration_since(UNIX_EPOCH) {
        Ok(duration) => (false, duration),
        Err(error) => (true, error.duration()),
    };
    FilesystemIncarnation::CreationTime {
        before_unix_epoch,
        seconds: duration.as_secs(),
        nanoseconds: duration.subsec_nanos(),
    }
}

fn hash_key(domain: &str, paths: &[&Path], incarnations: &[&FilesystemIncarnation]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for path in paths {
        hasher.update([0]);
        update_hasher_with_path(&mut hasher, path);
    }
    for incarnation in incarnations {
        hasher.update([1]);
        update_hasher_with_incarnation(&mut hasher, incarnation);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn update_hasher_with_incarnation(hasher: &mut Sha256, incarnation: &FilesystemIncarnation) {
    match incarnation {
        #[cfg(unix)]
        FilesystemIncarnation::Unix { device, inode } => {
            hasher.update(b"unix");
            hasher.update(device.to_be_bytes());
            hasher.update(inode.to_be_bytes());
        }
        #[cfg(windows)]
        FilesystemIncarnation::Windows {
            volume,
            file_index,
            reliable: _,
        } => {
            // Preserve the original Windows workspace-key encoding so existing
            // repository and worktree policy state remains addressable.
            hasher.update(b"windows");
            hasher.update(volume.to_be_bytes());
            hasher.update(file_index.to_be_bytes());
        }
        #[cfg(not(any(unix, windows)))]
        FilesystemIncarnation::CreationTime {
            before_unix_epoch,
            seconds,
            nanoseconds,
        } => {
            hasher.update(b"creation-time");
            hasher.update([u8::from(*before_unix_epoch)]);
            hasher.update(seconds.to_be_bytes());
            hasher.update(nanoseconds.to_be_bytes());
        }
        #[cfg(not(any(unix, windows)))]
        FilesystemIncarnation::Degraded => hasher.update(b"path-only-degraded"),
    }
}

#[cfg(unix)]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    hasher.update(bytes.len().to_be_bytes());
    hasher.update(bytes);
}

#[cfg(windows)]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt;

    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
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

fn identity_io_error(path: &Path, error: io::Error) -> WorkspaceIdentityError {
    WorkspaceIdentityError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceIdentityError {
    Io { path: PathBuf, message: String },
    InvalidRoot { path: PathBuf },
    InvalidGitMetadata { path: PathBuf },
    SymlinkedGitMetadata { path: PathBuf },
}

impl fmt::Display for WorkspaceIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "{}: {message}", path.display()),
            Self::InvalidRoot { path } => {
                write!(formatter, "workspace root is invalid: {}", path.display())
            }
            Self::InvalidGitMetadata { path } => {
                write!(formatter, "Git metadata is invalid: {}", path.display())
            }
            Self::SymlinkedGitMetadata { path } => write!(
                formatter,
                "Git metadata symlink cannot prove workspace identity: {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for WorkspaceIdentityError {}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{FilesystemIncarnation, hash_key};
    use std::path::Path;

    #[test]
    fn degraded_windows_identity_preserves_legacy_workspace_key() {
        let reliable = FilesystemIncarnation::Windows {
            volume: 7,
            file_index: 11,
            reliable: true,
        };
        let degraded = FilesystemIncarnation::Windows {
            volume: 7,
            file_index: 11,
            reliable: false,
        };

        assert!(!reliable.is_degraded());
        assert!(degraded.is_degraded());
        assert_eq!(
            hash_key("workspace-root-v2", &[Path::new("root")], &[&reliable]),
            hash_key("workspace-root-v2", &[Path::new("root")], &[&degraded]),
        );
    }
}
