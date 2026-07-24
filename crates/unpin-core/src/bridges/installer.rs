use std::{
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};

use crate::{
    hooks::{
        HookHandler, HookHandlerSpec, HookOwnership, HookRouteOwner, HookSourceLayer, stable_hash,
    },
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
};

use super::{BRIDGE_ASSET_VERSION, HookBridgeAdapter, hook_bridge_descriptor, managed_asset};

const BRIDGE_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeLifecycle {
    Installing,
    InstalledInactive,
    Active,
    Detaching,
    Detached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeIntegrity {
    Exact,
    Missing,
    Tampered,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BridgeInstallationRecord {
    version: u32,
    provider: ProviderId,
    adapter: HookBridgeAdapter,
    asset_path: String,
    asset_fingerprint: String,
    lifecycle: BridgeLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_socket_path: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeInstallPlan {
    provider: ProviderId,
    target_root: PathBuf,
    asset_path: PathBuf,
    asset_fingerprint: String,
    state_path: PathBuf,
    expected_revision: Option<StateRevision>,
}

impl fmt::Debug for BridgeInstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeInstallPlan")
            .field("provider", &self.provider)
            .field("target_root", &"[REDACTED]")
            .field("asset_path", &"[REDACTED]")
            .field("asset_fingerprint", &self.asset_fingerprint)
            .field("state_path", &"[REDACTED]")
            .field("expected_revision", &self.expected_revision)
            .finish()
    }
}

impl BridgeInstallPlan {
    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn asset_fingerprint(&self) -> &str {
        &self.asset_fingerprint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgeStatus {
    pub installation_id: String,
    pub provider: ProviderId,
    pub adapter: HookBridgeAdapter,
    pub lifecycle: BridgeLifecycle,
    pub integrity: BridgeIntegrity,
    pub control_plane_available: bool,
    pub asset_fingerprint: String,
}

impl BridgeStatus {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.lifecycle == BridgeLifecycle::Active
            && self.integrity == BridgeIntegrity::Exact
            && self.control_plane_available
    }
}

#[derive(Debug, Clone)]
pub struct BridgeInstaller {
    app_state_root: PathBuf,
}

impl BridgeInstaller {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn plan_install(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
    ) -> Result<BridgeInstallPlan, BridgeError> {
        let descriptor = hook_bridge_descriptor(provider);
        let asset_name = descriptor
            .managed_asset_file
            .ok_or(BridgeError::ManagedAssetUnsupported)?;
        let asset = managed_asset(provider).ok_or(BridgeError::ManagedAssetUnsupported)?;
        let target_root = verified_directory(target_root.as_ref())?;
        let asset_path = target_root.join(asset_name);
        reject_existing_target(&asset_path)?;
        let state_path = self.state_path(provider, &asset_path);
        let store = AtomicJsonStore::new(&state_path, BRIDGE_STATE_SCHEMA_VERSION);
        let current = store.load::<BridgeInstallationRecord>()?;
        if current
            .as_ref()
            .is_some_and(|snapshot| snapshot.value.lifecycle != BridgeLifecycle::Detached)
        {
            return Err(BridgeError::AlreadyInstalled);
        }
        Ok(BridgeInstallPlan {
            provider,
            target_root,
            asset_path,
            asset_fingerprint: stable_hash(asset.as_bytes()),
            state_path,
            expected_revision: current.map(|snapshot| snapshot.revision),
        })
    }

    pub fn install(
        &self,
        plan: &BridgeInstallPlan,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        let descriptor = hook_bridge_descriptor(plan.provider);
        let asset = managed_asset(plan.provider).ok_or(BridgeError::ManagedAssetUnsupported)?;
        let expected_name = descriptor
            .managed_asset_file
            .ok_or(BridgeError::ManagedAssetUnsupported)?;
        if verified_directory(&plan.target_root)? != plan.target_root
            || plan.asset_path != plan.target_root.join(expected_name)
            || stable_hash(asset.as_bytes()) != plan.asset_fingerprint
            || self.state_path(plan.provider, &plan.asset_path) != plan.state_path
        {
            return Err(BridgeError::InvalidPlan);
        }
        reject_existing_target(&plan.asset_path)?;
        let store = AtomicJsonStore::new(&plan.state_path, BRIDGE_STATE_SCHEMA_VERSION);
        let installing = BridgeInstallationRecord {
            version: BRIDGE_ASSET_VERSION,
            provider: plan.provider,
            adapter: descriptor.adapter,
            asset_path: plan.asset_path.to_string_lossy().into_owned(),
            asset_fingerprint: plan.asset_fingerprint.clone(),
            lifecycle: BridgeLifecycle::Installing,
            control_socket_path: None,
        };
        let installing_revision =
            store.compare_and_swap(plan.expected_revision.as_ref(), owner.clone(), &installing)?;
        write_new_private_file(&plan.asset_path, asset.as_bytes())?;
        let installed = BridgeInstallationRecord {
            lifecycle: BridgeLifecycle::InstalledInactive,
            ..installing
        };
        store.compare_and_swap(Some(&installing_revision), owner, &installed)?;
        Ok(status_for_record(&installed))
    }

    pub fn status(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
    ) -> Result<Option<BridgeStatus>, BridgeError> {
        let (_store, record, _) = self.load(provider, target_root.as_ref())?;
        let Some(record) = record else {
            return Ok(None);
        };
        Ok(Some(status_for_record(&record)))
    }

    pub fn list_statuses(&self, provider: ProviderId) -> Result<Vec<BridgeStatus>, BridgeError> {
        let directory = self.app_state_root.join("bridges").join(provider.as_str());
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(BridgeError::Io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::InvalidState);
        }
        let mut paths = fs::read_dir(&directory)
            .map_err(BridgeError::Io)?
            .map(|entry| entry.map(|entry| entry.path()).map_err(BridgeError::Io))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        let mut statuses = Vec::new();
        for path in paths {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(BridgeError::InvalidState)?;
            if file_name.starts_with('.') || path.extension().is_none_or(|value| value != "json") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(BridgeError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BridgeError::InvalidState);
            }
            let snapshot = AtomicJsonStore::new(&path, BRIDGE_STATE_SCHEMA_VERSION)
                .load::<BridgeInstallationRecord>()?
                .ok_or(BridgeError::InvalidState)?;
            let record = snapshot.value;
            let descriptor = hook_bridge_descriptor(provider);
            let asset_path = Path::new(&record.asset_path);
            if record.version != BRIDGE_ASSET_VERSION
                || record.provider != provider
                || record.adapter != descriptor.adapter
                || asset_path.file_name().and_then(|name| name.to_str())
                    != descriptor.managed_asset_file
                || self.state_path(provider, asset_path) != path
            {
                return Err(BridgeError::InvalidState);
            }
            statuses.push(status_for_record(&record));
        }
        Ok(statuses)
    }

    pub fn activate(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
        control_socket: impl AsRef<Path>,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        let control_socket = verified_control_socket(control_socket.as_ref())?;
        let (store, record, revision) = self.load(provider, target_root.as_ref())?;
        let mut record = record.ok_or(BridgeError::NotInstalled)?;
        let revision = revision.expect("bridge record revision exists");
        if record.lifecycle != BridgeLifecycle::InstalledInactive
            || record_integrity(&record) != BridgeIntegrity::Exact
        {
            return Err(BridgeError::IntegrityMismatch);
        }
        record.lifecycle = BridgeLifecycle::Active;
        record.control_socket_path = Some(control_socket.to_string_lossy().into_owned());
        store.compare_and_swap(Some(&revision), owner, &record)?;
        Ok(status_for_record(&record))
    }

    pub fn deactivate(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        self.update_lifecycle(
            provider,
            target_root.as_ref(),
            BridgeLifecycle::Active,
            BridgeLifecycle::InstalledInactive,
            owner,
        )
    }

    pub fn detach(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        let (store, record, revision) = self.load(provider, target_root.as_ref())?;
        let mut record = record.ok_or(BridgeError::NotInstalled)?;
        let revision = revision.expect("bridge record revision exists");
        if record.lifecycle == BridgeLifecycle::Active {
            return Err(BridgeError::BridgeActive);
        }
        if record.lifecycle != BridgeLifecycle::InstalledInactive
            || record_integrity(&record) != BridgeIntegrity::Exact
        {
            return Err(BridgeError::IntegrityMismatch);
        }
        record.lifecycle = BridgeLifecycle::Detaching;
        record.control_socket_path = None;
        let detaching_revision = store.compare_and_swap(Some(&revision), owner.clone(), &record)?;
        remove_verified_asset(Path::new(&record.asset_path), &record.asset_fingerprint)?;
        record.lifecycle = BridgeLifecycle::Detached;
        store.compare_and_swap(Some(&detaching_revision), owner, &record)?;
        Ok(status_for_record(&record))
    }

    pub fn recover_partial(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        let (store, record, revision) = self.load(provider, target_root.as_ref())?;
        let mut record = record.ok_or(BridgeError::NotInstalled)?;
        let revision = revision.expect("bridge record revision exists");
        let integrity = record_integrity(&record);
        record.lifecycle = match record.lifecycle {
            BridgeLifecycle::Installing => match integrity {
                BridgeIntegrity::Exact => BridgeLifecycle::InstalledInactive,
                BridgeIntegrity::Missing => BridgeLifecycle::Detached,
                BridgeIntegrity::Tampered | BridgeIntegrity::Partial => BridgeLifecycle::Detached,
            },
            BridgeLifecycle::Detaching => match integrity {
                BridgeIntegrity::Missing => BridgeLifecycle::Detached,
                BridgeIntegrity::Exact | BridgeIntegrity::Tampered | BridgeIntegrity::Partial => {
                    BridgeLifecycle::InstalledInactive
                }
            },
            BridgeLifecycle::InstalledInactive
            | BridgeLifecycle::Active
            | BridgeLifecycle::Detached => return Err(BridgeError::RecoveryNotRequired),
        };
        record.control_socket_path = None;
        store.compare_and_swap(Some(&revision), owner, &record)?;
        Ok(status_for_record(&record))
    }

    pub fn managed_handler(
        &self,
        provider: ProviderId,
        target_root: impl AsRef<Path>,
        spec: HookHandlerSpec,
    ) -> Result<HookHandler, BridgeError> {
        let status = self
            .status(provider, target_root)?
            .ok_or(BridgeError::NotInstalled)?;
        let descriptor = hook_bridge_descriptor(provider);
        if !status.is_active()
            || spec.provider != provider
            || spec.ownership != HookOwnership::AdministratorManaged
            || !matches!(
                spec.source_layer,
                HookSourceLayer::Managed | HookSourceLayer::Component
            )
            || spec.route_owner != HookRouteOwner::ProviderBridge
            || spec.action.component_reference() != Some(descriptor.managed_component_reference)
        {
            return Err(BridgeError::InvalidManagedHandler);
        }
        HookHandler::new_managed(spec).map_err(|_| BridgeError::InvalidManagedHandler)
    }

    fn update_lifecycle(
        &self,
        provider: ProviderId,
        target_root: &Path,
        expected: BridgeLifecycle,
        next: BridgeLifecycle,
        owner: OwnerGeneration,
    ) -> Result<BridgeStatus, BridgeError> {
        let (store, record, revision) = self.load(provider, target_root)?;
        let mut record = record.ok_or(BridgeError::NotInstalled)?;
        let revision = revision.expect("bridge record revision exists");
        if record.lifecycle != expected || record_integrity(&record) != BridgeIntegrity::Exact {
            return Err(BridgeError::IntegrityMismatch);
        }
        record.lifecycle = next;
        if next != BridgeLifecycle::Active {
            record.control_socket_path = None;
        }
        store.compare_and_swap(Some(&revision), owner, &record)?;
        Ok(status_for_record(&record))
    }

    fn load(
        &self,
        provider: ProviderId,
        target_root: &Path,
    ) -> Result<
        (
            AtomicJsonStore,
            Option<BridgeInstallationRecord>,
            Option<StateRevision>,
        ),
        BridgeError,
    > {
        let descriptor = hook_bridge_descriptor(provider);
        let asset_name = descriptor
            .managed_asset_file
            .ok_or(BridgeError::ManagedAssetUnsupported)?;
        let target_root = verified_directory(target_root)?;
        let asset_path = target_root.join(asset_name);
        let store = AtomicJsonStore::new(
            self.state_path(provider, &asset_path),
            BRIDGE_STATE_SCHEMA_VERSION,
        );
        let snapshot = store.load::<BridgeInstallationRecord>()?;
        if let Some(snapshot) = &snapshot
            && (snapshot.value.version != BRIDGE_ASSET_VERSION
                || snapshot.value.provider != provider
                || snapshot.value.adapter != descriptor.adapter
                || Path::new(&snapshot.value.asset_path) != asset_path)
        {
            return Err(BridgeError::InvalidState);
        }
        let (record, revision) = snapshot.map_or((None, None), |snapshot| {
            (Some(snapshot.value), Some(snapshot.revision))
        });
        Ok((store, record, revision))
    }

    fn state_path(&self, provider: ProviderId, asset_path: &Path) -> PathBuf {
        let key = stable_hash(asset_path.to_string_lossy().as_bytes());
        self.app_state_root
            .join("bridges")
            .join(provider.as_str())
            .join(format!("{key}.json"))
    }
}

fn verified_directory(path: &Path) -> Result<PathBuf, BridgeError> {
    let metadata = fs::symlink_metadata(path).map_err(BridgeError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BridgeError::UnsafeTarget);
    }
    fs::canonicalize(path).map_err(BridgeError::Io)
}

fn verified_control_socket(path: &Path) -> Result<PathBuf, BridgeError> {
    if !path.is_absolute() {
        return Err(BridgeError::ControlPlaneUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        let metadata =
            fs::symlink_metadata(path).map_err(|_| BridgeError::ControlPlaneUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(BridgeError::ControlPlaneUnavailable);
        }
        fs::canonicalize(path).map_err(|_| BridgeError::ControlPlaneUnavailable)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(BridgeError::ControlPlaneUnavailable)
    }
}

fn reject_existing_target(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BridgeError::TargetOccupied),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BridgeError::Io(error)),
    }
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), BridgeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(BridgeError::Io)?;
    file.write_all(bytes).map_err(BridgeError::Io)?;
    file.sync_all().map_err(BridgeError::Io)
}

fn remove_verified_asset(path: &Path, expected_fingerprint: &str) -> Result<(), BridgeError> {
    let path_metadata = fs::symlink_metadata(path).map_err(BridgeError::Io)?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(BridgeError::IntegrityMismatch);
    }
    let mut file = File::open(path).map_err(BridgeError::Io)?;
    let open_metadata = file.metadata().map_err(BridgeError::Io)?;
    if !same_file_identity(&path_metadata, &open_metadata) {
        return Err(BridgeError::IntegrityMismatch);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(BridgeError::Io)?;
    if stable_hash(&bytes) != expected_fingerprint {
        return Err(BridgeError::IntegrityMismatch);
    }
    let final_metadata = fs::symlink_metadata(path).map_err(BridgeError::Io)?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.is_file()
        || !same_file_identity(&open_metadata, &final_metadata)
    {
        return Err(BridgeError::IntegrityMismatch);
    }
    fs::remove_file(path).map_err(BridgeError::Io)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.created().ok() == right.created().ok()
        && left.modified().ok() == right.modified().ok()
}

fn record_integrity(record: &BridgeInstallationRecord) -> BridgeIntegrity {
    let path = Path::new(&record.asset_path);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if record.lifecycle == BridgeLifecycle::Detached {
                BridgeIntegrity::Exact
            } else {
                BridgeIntegrity::Missing
            }
        }
        Err(_) => BridgeIntegrity::Partial,
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            BridgeIntegrity::Tampered
        }
        Ok(_) => match fs::read(path) {
            Ok(bytes) if stable_hash(&bytes) == record.asset_fingerprint => {
                if record.lifecycle == BridgeLifecycle::Detached {
                    BridgeIntegrity::Partial
                } else {
                    BridgeIntegrity::Exact
                }
            }
            Ok(_) => BridgeIntegrity::Tampered,
            Err(_) => BridgeIntegrity::Partial,
        },
    }
}

fn status_for_record(record: &BridgeInstallationRecord) -> BridgeStatus {
    BridgeStatus {
        installation_id: stable_hash(record.asset_path.as_bytes()),
        provider: record.provider,
        adapter: record.adapter,
        lifecycle: record.lifecycle,
        integrity: record_integrity(record),
        control_plane_available: record_control_plane_available(record),
        asset_fingerprint: record.asset_fingerprint.clone(),
    }
}

fn record_control_plane_available(record: &BridgeInstallationRecord) -> bool {
    record.lifecycle == BridgeLifecycle::Active
        && record
            .control_socket_path
            .as_deref()
            .is_some_and(|path| verified_control_socket(Path::new(path)).is_ok())
}

#[derive(Debug)]
pub enum BridgeError {
    ManagedAssetUnsupported,
    UnsafeTarget,
    TargetOccupied,
    AlreadyInstalled,
    NotInstalled,
    BridgeActive,
    ControlPlaneUnavailable,
    IntegrityMismatch,
    RecoveryNotRequired,
    InvalidManagedHandler,
    InvalidPlan,
    InvalidState,
    Io(io::Error),
    State(StateError),
}

impl From<StateError> for BridgeError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManagedAssetUnsupported => {
                formatter.write_str("provider has no managed hook bridge asset")
            }
            Self::UnsafeTarget => formatter.write_str("bridge target directory is unsafe"),
            Self::TargetOccupied => formatter.write_str("bridge target is already occupied"),
            Self::AlreadyInstalled => formatter.write_str("bridge is already installed"),
            Self::NotInstalled => formatter.write_str("bridge is not installed"),
            Self::BridgeActive => formatter.write_str("active bridge must be deactivated first"),
            Self::ControlPlaneUnavailable => {
                formatter.write_str("bridge control plane is unavailable")
            }
            Self::IntegrityMismatch => formatter.write_str("bridge integrity check failed"),
            Self::RecoveryNotRequired => formatter.write_str("bridge recovery is not required"),
            Self::InvalidManagedHandler => {
                formatter.write_str("managed hook handler does not match active bridge")
            }
            Self::InvalidPlan => formatter.write_str("bridge installation plan is invalid"),
            Self::InvalidState => formatter.write_str("bridge installation state is invalid"),
            Self::Io(_) => formatter.write_str("bridge filesystem operation failed"),
            Self::State(_) => formatter.write_str("bridge state operation failed"),
        }
    }
}

impl std::error::Error for BridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::State(error) => Some(error),
            Self::ManagedAssetUnsupported
            | Self::UnsafeTarget
            | Self::TargetOccupied
            | Self::AlreadyInstalled
            | Self::NotInstalled
            | Self::BridgeActive
            | Self::ControlPlaneUnavailable
            | Self::IntegrityMismatch
            | Self::RecoveryNotRequired
            | Self::InvalidManagedHandler
            | Self::InvalidPlan
            | Self::InvalidState => None,
        }
    }
}
