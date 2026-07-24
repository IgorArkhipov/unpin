use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
use std::process::Command;

use serde::Deserialize;

use crate::{
    config::{
        get_gateway_modes_dir, get_session_lease_path, get_session_leases_dir,
        get_session_overlay_root, get_session_registry_lock_path,
        get_session_transition_admission_lock_path,
    },
    providers::ProviderId,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateResourceLock, StateRevision,
    },
    transitions::{
        TransitionConflict, TransitionConflictChecker, TransitionConflictGuard, TransitionPlan,
    },
};

use super::lease::{
    BootstrapAuthority, BootstrapRequest, ConnectionClaim, LeaseLifecycle, LeaseValidationError,
    LiveExposureStatus, PendingBootstrap, PinnedExposure, ProcessEvidence,
    SESSION_LEASE_SCHEMA_VERSION, SESSION_OVERLAY_MARKER, SessionAuthorityKey, SessionHandle,
    SessionLease, SessionRecord, constant_time_equal, digest_bytes, validate_identifier,
    validate_workspace_revision,
};
use super::mode::{GATEWAY_MODE_SCHEMA_VERSION, GatewayModeState, GatewayModeTarget};

pub const DEFAULT_STALE_AFTER_SECONDS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSnapshot {
    pub revision: StateRevision,
    pub lease: SessionLease,
}

pub struct ClaimedSession {
    pub lease: LeaseSnapshot,
    pub handle: SessionHandle,
}

impl fmt::Debug for ClaimedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedSession")
            .field("lease", &self.lease)
            .field("handle", &self.handle)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallAdmission {
    session_id: String,
    call_id: String,
    exposure_revision: String,
    admitted_at_revision: u64,
}

struct SessionTransitionGuard {
    _resource_guards: Vec<StateResourceLock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightClosePolicy {
    RequireDrained,
    Abandon,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OverlayMarker {
    version: u32,
    session_id: String,
}

impl CallAdmission {
    #[must_use]
    pub fn exposure_revision(&self) -> &str {
        &self.exposure_revision
    }
}

pub trait ProcessInspector {
    fn matches(&self, evidence: &ProcessEvidence) -> bool;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessInspector;

impl ProcessInspector for SystemProcessInspector {
    fn matches(&self, evidence: &ProcessEvidence) -> bool {
        capture_process_evidence(evidence.pid)
            .is_ok_and(|current| current.start_marker == evidence.start_marker)
    }
}

pub fn capture_process_evidence(pid: u32) -> Result<ProcessEvidence, LeaseError> {
    if pid == 0 {
        return Err(LeaseError::InvalidProcessEvidence);
    }
    let evidence = ProcessEvidence {
        pid,
        start_marker: capture_process_start_marker(pid)?,
    };
    evidence.validate().map_err(LeaseError::from)?;
    Ok(evidence)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn capture_process_start_marker(pid: u32) -> Result<String, LeaseError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LeaseError::ProcessNotRunning(pid)
        } else {
            LeaseError::ProcessInspection(error.to_string())
        }
    })?;
    // Field two (`comm`) is parenthesized and may contain spaces or `)`, so
    // split after its final delimiter. Field 22 is process start time in ticks
    // since boot and remains stable across observations of one PID generation.
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| LeaseError::ProcessInspection("invalid /proc stat record".to_string()))?;
    let start_time = fields
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| LeaseError::ProcessInspection("invalid /proc start time".to_string()))?;
    Ok(format!("proc:{start_time}"))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn capture_process_start_marker(pid: u32) -> Result<String, LeaseError> {
    let ps = [Path::new("/bin/ps"), Path::new("/usr/bin/ps")]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| LeaseError::ProcessInspection("system ps is unavailable".to_string()))?;
    let output = Command::new(ps)
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| LeaseError::ProcessInspection(error.to_string()))?;
    if !output.status.success() {
        return Err(LeaseError::ProcessNotRunning(pid));
    }
    let marker = String::from_utf8(output.stdout)
        .map_err(|error| LeaseError::ProcessInspection(error.to_string()))?;
    let marker = marker.trim();
    if marker.is_empty() {
        return Err(LeaseError::ProcessNotRunning(pid));
    }
    Ok(format!("ps:{marker}"))
}

#[cfg(not(unix))]
fn capture_process_start_marker(_pid: u32) -> Result<String, LeaseError> {
    Err(LeaseError::ProcessInspection(
        "process generation inspection is unsupported on this platform".to_string(),
    ))
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    app_state_root: PathBuf,
    authority_key: Option<SessionAuthorityKey>,
}

impl SessionManager {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            authority_key: None,
        }
    }

    #[must_use]
    pub fn with_authority_key(
        app_state_root: impl Into<PathBuf>,
        authority_key: SessionAuthorityKey,
    ) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            authority_key: Some(authority_key),
        }
    }

    #[must_use]
    pub fn app_state_root(&self) -> &Path {
        &self.app_state_root
    }

    pub fn authority_key_id(&self) -> Result<String, LeaseError> {
        Ok(self.authority_key()?.key_id())
    }

    pub fn prepare_bootstrap(
        &self,
        request: BootstrapRequest,
        now_unix: i64,
    ) -> Result<BootstrapAuthority, LeaseError> {
        let authority_key = self.authority_key()?;
        request.validate(now_unix).map_err(LeaseError::from)?;
        self.reconcile_stale(now_unix)?;
        let _registry = self.registry_lock()?;
        let secret = secure_random_secret()?;
        let mut session_material = Vec::with_capacity(secret.len() + 24);
        session_material.extend_from_slice(&secret);
        session_material.extend_from_slice(&now_unix.to_le_bytes());
        session_material.extend_from_slice(&std::process::id().to_le_bytes());
        let session_digest = digest_bytes(&session_material);
        let session_id = format!("session-{}", &session_digest[..32]);
        let authority = BootstrapAuthority::new(session_id.clone(), secret);
        let pending = PendingBootstrap::from_request(
            session_id.clone(),
            request,
            authority.secret_digest(),
            now_unix,
            authority_key,
        )
        .map_err(LeaseError::from)?;
        let store = self.store(&session_id);
        store.compare_and_swap(
            None,
            OwnerGeneration::new(format!("bootstrap-{session_id}"), 1)?,
            &SessionRecord::Pending {
                claim: Box::new(pending),
            },
        )?;
        Ok(authority)
    }

    pub fn claim_bootstrap(
        &self,
        authority: &BootstrapAuthority,
        claim: &ConnectionClaim,
        now_unix: i64,
    ) -> Result<ClaimedSession, LeaseError> {
        let authority_key = self.authority_key()?;
        claim.validate().map_err(LeaseError::from)?;
        let store = self.store(authority.session_id());
        let preflight = store
            .load::<SessionRecord>()?
            .ok_or(LeaseError::SessionNotFound)?;
        preflight
            .value
            .verify(authority_key)
            .map_err(LeaseError::from)?;
        let protected_resources = match preflight.value {
            SessionRecord::Pending { claim } => claim.protected_resources,
            SessionRecord::Established { .. } => {
                return Err(LeaseError::BootstrapAlreadyConsumed);
            }
        };
        let _transition_admission =
            self.acquire_transition_admission(protected_resources.iter().map(String::as_str))?;
        let _registry = self.registry_lock()?;
        let snapshot = store
            .load::<SessionRecord>()?
            .ok_or(LeaseError::SessionNotFound)?;
        snapshot
            .value
            .verify(authority_key)
            .map_err(LeaseError::from)?;
        let pending = match snapshot.value {
            SessionRecord::Pending { claim } => *claim,
            SessionRecord::Established { .. } => {
                return Err(LeaseError::BootstrapAlreadyConsumed);
            }
        };
        if pending.bootstrap_expires_at_unix <= now_unix {
            return Err(LeaseError::BootstrapExpired);
        }
        if !constant_time_equal(
            pending.secret_digest.as_bytes(),
            authority.secret_digest().as_bytes(),
        ) {
            return Err(LeaseError::BootstrapAuthenticationFailed);
        }
        if !pending.matches_claim(claim) {
            return Err(LeaseError::BindingMismatch);
        }
        if pending.exposure.profile.requires_gateway_routing()
            && self.gateway_admission_blocked(
                pending.provider,
                &pending.repository_key,
                &pending.workspace_key,
            )?
        {
            return Err(LeaseError::GatewayAdmissionClosed);
        }
        if self.list_unlocked()?.iter().any(|candidate| {
            candidate.lease.lifecycle.contributes_active_intent()
                && candidate.lease.connection_scope_digest == pending.connection_scope_digest
        }) {
            return Err(LeaseError::MultiplexedConnection);
        }

        let owner_secret = secure_random_secret()?;
        let handle = SessionHandle::new(
            pending.session_id.clone(),
            claim.connection_owner_id.clone(),
            owner_secret,
        );
        let lease = pending
            .into_lease(claim, handle.secret_digest(), now_unix, authority_key)
            .map_err(LeaseError::from)?;
        let owner_generation = snapshot
            .owner
            .generation
            .checked_add(1)
            .ok_or(LeaseError::OwnerGenerationOverflow)?;
        let revision = match store.compare_and_swap(
            Some(&snapshot.revision),
            OwnerGeneration::new(claim.connection_owner_id.clone(), owner_generation)?,
            &SessionRecord::Established {
                lease: Box::new(lease.clone()),
            },
        ) {
            Ok(revision) => revision,
            Err(StateError::StaleRevision { .. }) => {
                return Err(LeaseError::BootstrapAlreadyConsumed);
            }
            Err(error) => return Err(error.into()),
        };
        Ok(ClaimedSession {
            lease: LeaseSnapshot { revision, lease },
            handle,
        })
    }

    pub fn cancel_bootstrap(&self, authority: &BootstrapAuthority) -> Result<(), LeaseError> {
        let authority_key = self.authority_key()?;
        let _registry = self.registry_lock()?;
        let store = self.store(authority.session_id());
        let snapshot = store
            .load::<SessionRecord>()?
            .ok_or(LeaseError::SessionNotFound)?;
        snapshot
            .value
            .verify(authority_key)
            .map_err(LeaseError::from)?;
        match snapshot.value {
            SessionRecord::Pending { claim } => {
                if !constant_time_equal(
                    claim.secret_digest.as_bytes(),
                    authority.secret_digest().as_bytes(),
                ) {
                    return Err(LeaseError::BootstrapAuthenticationFailed);
                }
                store.remove_if_revision(&snapshot.revision)?;
                Ok(())
            }
            SessionRecord::Established { .. } => Err(LeaseError::BootstrapAlreadyConsumed),
        }
    }

    pub fn list(&self) -> Result<Vec<LeaseSnapshot>, LeaseError> {
        let _registry = self.registry_lock()?;
        self.list_unlocked()
    }

    pub fn load_for_handle(&self, handle: &SessionHandle) -> Result<LeaseSnapshot, LeaseError> {
        let snapshot = self.load_established(handle.session_id())?;
        snapshot
            .lease
            .verify_handle(handle)
            .map_err(LeaseError::from)?;
        Ok(snapshot)
    }

    pub fn assert_bound_context(
        &self,
        handle: &SessionHandle,
        provider: ProviderId,
        repository_key: &str,
        workspace_key: &str,
    ) -> Result<(), LeaseError> {
        let snapshot = self.load_for_handle(handle)?;
        if snapshot.lease.provider == provider
            && snapshot.lease.repository_key == repository_key
            && snapshot.lease.workspace_key == workspace_key
        {
            Ok(())
        } else {
            Err(LeaseError::ContextMismatch)
        }
    }

    pub fn request_exposure(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        exposure: PinnedExposure,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        exposure.validate().map_err(LeaseError::from)?;
        self.update_owned_lease(handle, expected, now_unix, |lease| {
            require_active(lease)?;
            if lease.lease_expires_at_unix <= now_unix {
                return Err(LeaseError::LeaseExpired);
            }
            lease.desired_exposure = exposure;
            lease.live_status = LiveExposureStatus::Configured;
            Ok(())
        })
    }

    pub fn observe_exposure(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        status: LiveExposureStatus,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        if !matches!(
            status,
            LiveExposureStatus::NotificationSent
                | LiveExposureStatus::ObservedRefresh
                | LiveExposureStatus::ReloadRequired
                | LiveExposureStatus::NextSessionOnly
                | LiveExposureStatus::Unknown
        ) {
            return Err(LeaseError::InvalidExposureStatus);
        }
        self.update_owned_lease(handle, expected, now_unix, |lease| {
            require_active(lease)?;
            if status == LiveExposureStatus::ObservedRefresh {
                lease.observed_exposure = lease.desired_exposure.clone();
            }
            lease.live_status = status;
            Ok(())
        })
    }

    pub fn report_workspace_revision(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        current_revision: Option<String>,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        if let Some(revision) = &current_revision {
            validate_workspace_revision(revision).map_err(LeaseError::from)?;
        }
        self.update_owned_lease(handle, expected, now_unix, |lease| {
            require_active(lease)?;
            lease.workspace_drifted = current_revision != lease.workspace_start_revision;
            lease.last_workspace_revision = current_revision;
            Ok(())
        })
    }

    pub fn heartbeat(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        let _registry = self.registry_lock()?;
        let loaded = self.load_for_handle(handle)?;
        if loaded.lease.lease_expires_at_unix <= now_unix {
            return Err(LeaseError::LeaseExpired);
        }
        if !loaded.lease.lifecycle.contributes_active_intent() {
            return Err(LeaseError::LeaseNotActive);
        }
        // Force-off and heartbeat share the registry lock. When force-off wins,
        // rebase the owner's keepalive onto the revoking record so it observes
        // the fence instead of receiving a misleading stale-revision error.
        let update_revision = if loaded.lease.lifecycle == LeaseLifecycle::Revoking
            && loaded.lease.closed_reason.as_deref() == Some("gateway-force-off")
        {
            loaded.revision
        } else {
            expected.clone()
        };
        self.update_lease(
            handle.session_id(),
            &update_revision,
            handle.owner_id(),
            |lease| {
                lease.verify_handle(handle).map_err(LeaseError::from)?;
                if !lease.lifecycle.contributes_active_intent() {
                    return Err(LeaseError::LeaseNotActive);
                }
                lease.heartbeat_at_unix = now_unix;
                Ok(())
            },
        )
    }

    pub fn admit_call(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        now_unix: i64,
    ) -> Result<CallAdmission, LeaseError> {
        self.admit_call_with_snapshot(handle, expected, now_unix)
            .map(|(admission, _)| admission)
    }

    pub fn admit_call_with_snapshot(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        now_unix: i64,
    ) -> Result<(CallAdmission, LeaseSnapshot), LeaseError> {
        let call_id = digest_bytes(
            format!(
                "session-call-v1\0{}\0{}\0{now_unix}",
                handle.session_id(),
                expected.sequence
            )
            .as_bytes(),
        );
        let updated = self.update_owned_lease(handle, expected, now_unix, |lease| {
            if lease.lifecycle != LeaseLifecycle::Active || !lease.admission_open {
                return Err(LeaseError::AdmissionClosed);
            }
            if !lease.in_flight_call_ids.insert(call_id.clone()) {
                return Err(LeaseError::InvalidCallAdmission);
            }
            lease.in_flight_calls = u32::try_from(lease.in_flight_call_ids.len())
                .map_err(|_| LeaseError::InFlightOverflow)?;
            Ok(())
        })?;
        let admission = CallAdmission {
            session_id: updated.lease.session_id.clone(),
            call_id,
            exposure_revision: updated.lease.observed_exposure.revision.clone(),
            admitted_at_revision: updated.revision.sequence,
        };
        Ok((admission, updated))
    }

    pub fn finish_call(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        admission: CallAdmission,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        if admission.session_id != handle.session_id()
            || admission.admitted_at_revision > expected.sequence
        {
            return Err(LeaseError::InvalidCallAdmission);
        }
        self.update_owned_lease(handle, expected, now_unix, |lease| {
            if !lease.in_flight_call_ids.remove(&admission.call_id) {
                return Err(LeaseError::InvalidCallAdmission);
            }
            lease.in_flight_calls = u32::try_from(lease.in_flight_call_ids.len())
                .map_err(|_| LeaseError::InFlightOverflow)?;
            Ok(())
        })
    }

    /// Fences a stopped gateway runtime and abandons admissions that can no
    /// longer complete because every serving task has terminated.
    pub fn reconcile_stopped_runtime(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        self.update_owned_lease(handle, expected, now_unix, |lease| {
            lease.lifecycle = LeaseLifecycle::Revoking;
            lease.admission_open = false;
            lease.in_flight_call_ids.clear();
            lease.in_flight_calls = 0;
            lease.closed_reason = Some("gateway-runtime-stopped".to_string());
            Ok(())
        })
    }

    pub fn close_owned(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        reason: &str,
        now_unix: i64,
    ) -> Result<(), LeaseError> {
        validate_identifier("close reason", reason).map_err(LeaseError::from)?;
        let _registry = self.registry_lock()?;
        let current = self.load_for_handle(handle)?;
        if &current.revision != expected {
            return Err(LeaseError::State(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual: Some(current.revision),
            }));
        }
        if current.lease.in_flight_calls != 0 || !current.lease.in_flight_call_ids.is_empty() {
            return Err(LeaseError::SessionDraining);
        }
        self.close_and_remove_unlocked(
            current,
            handle.owner_id(),
            reason,
            now_unix,
            LeaseLifecycle::Closed,
            InFlightClosePolicy::RequireDrained,
        )
    }

    /// Fence one established session without deleting its process-owned overlay.
    /// Owner cleanup removes lease and overlay after child exit; stale reaping remains fallback.
    pub fn request_revoke(
        &self,
        session_id: &str,
        expected: &StateRevision,
        actor_id: &str,
        reason: &str,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        validate_identifier("session id", session_id).map_err(LeaseError::from)?;
        validate_identifier("session revoke reason", reason).map_err(LeaseError::from)?;
        let _registry = self.registry_lock()?;
        let current = self.load_established(session_id)?;
        if &current.revision != expected {
            return Err(LeaseError::State(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual: Some(current.revision),
            }));
        }
        if !current.lease.lifecycle.contributes_active_intent() {
            return Err(LeaseError::LeaseNotActive);
        }
        self.update_lease(session_id, expected, actor_id, |lease| {
            lease.lifecycle = LeaseLifecycle::Revoking;
            lease.admission_open = false;
            lease.heartbeat_at_unix = now_unix;
            lease.closed_reason = Some(reason.to_string());
            Ok(())
        })
    }

    pub fn expire_stale(
        &self,
        now_unix: i64,
        stale_after_seconds: i64,
        inspector: &dyn ProcessInspector,
    ) -> Result<Vec<String>, LeaseError> {
        if stale_after_seconds <= 0 {
            return Err(LeaseError::InvalidStaleWindow);
        }
        let _registry = self.registry_lock()?;
        for snapshot in self.scan_records()? {
            if let SessionRecord::Pending { claim } = snapshot.value
                && claim.bootstrap_expires_at_unix <= now_unix
            {
                self.cleanup_overlay(&claim.session_id)?;
                self.store(&claim.session_id)
                    .remove_if_revision(&snapshot.revision)?;
            }
        }
        let mut expired = Vec::new();
        for snapshot in self.list_unlocked()? {
            let heartbeat_stale = now_unix
                .checked_sub(snapshot.lease.heartbeat_at_unix)
                .is_some_and(|age| age >= stale_after_seconds);
            let hard_expired = now_unix >= snapshot.lease.lease_expires_at_unix;
            if hard_expired || (heartbeat_stale && !inspector.matches(&snapshot.lease.process)) {
                let session_id = snapshot.lease.session_id.clone();
                let expired_snapshot = self.close_unlocked(
                    snapshot,
                    "stale-session-reaper",
                    "stale-process-or-heartbeat",
                    now_unix,
                    LeaseLifecycle::Expired,
                    InFlightClosePolicy::Abandon,
                )?;
                self.cleanup_overlay(&session_id)?;
                self.store(&session_id)
                    .remove_if_revision(&expired_snapshot.revision)?;
                expired.push(session_id);
            }
        }
        expired.sort();
        Ok(expired)
    }

    pub fn reconcile_stale(&self, now_unix: i64) -> Result<Vec<String>, LeaseError> {
        self.expire_stale(
            now_unix,
            DEFAULT_STALE_AFTER_SECONDS,
            &SystemProcessInspector,
        )
    }

    pub fn cleanup_overlay(&self, session_id: &str) -> Result<bool, LeaseError> {
        let _authority_key = self.authority_key()?;
        validate_identifier("session id", session_id).map_err(LeaseError::from)?;
        let overlay_root = get_session_overlay_root(&self.app_state_root, session_id);
        let metadata = match fs::symlink_metadata(&overlay_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(state_io_error(&overlay_root, error)),
        };
        for directory in [
            self.app_state_root.clone(),
            self.app_state_root.join("runtime"),
            self.app_state_root.join("runtime").join("overlays"),
        ] {
            let directory_metadata = fs::symlink_metadata(&directory)
                .map_err(|error| state_io_error(&directory, error))?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(LeaseError::UnsafeOverlay(overlay_root));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if directory_metadata.permissions().mode() & 0o077 != 0 {
                    return Err(LeaseError::UnsafeOverlay(overlay_root));
                }
            }
        }
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LeaseError::UnsafeOverlay(overlay_root));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(LeaseError::UnsafeOverlay(overlay_root));
            }
        }
        let marker_path = overlay_root.join(SESSION_OVERLAY_MARKER);
        let marker_metadata = fs::symlink_metadata(&marker_path)
            .map_err(|error| state_io_error(&marker_path, error))?;
        if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
            return Err(LeaseError::UnsafeOverlay(overlay_root));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if marker_metadata.permissions().mode() & 0o077 != 0 {
                return Err(LeaseError::UnsafeOverlay(overlay_root));
            }
        }
        let marker: OverlayMarker = serde_json::from_slice(
            &fs::read(&marker_path).map_err(|error| state_io_error(&marker_path, error))?,
        )
        .map_err(|_| LeaseError::UnsafeOverlay(overlay_root.clone()))?;
        if marker.version != 1 || marker.session_id != session_id {
            return Err(LeaseError::UnsafeOverlay(overlay_root));
        }
        fs::remove_dir_all(&overlay_root).map_err(|error| state_io_error(&overlay_root, error))?;
        if let Some(parent) = overlay_root.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| state_io_error(parent, error))?;
        }
        Ok(true)
    }

    pub(crate) fn registry_lock(&self) -> Result<StateResourceLock, LeaseError> {
        StateResourceLock::acquire(get_session_registry_lock_path(&self.app_state_root))
            .map_err(LeaseError::from)
    }

    fn acquire_transition_admission<'a>(
        &self,
        resources: impl IntoIterator<Item = &'a str>,
    ) -> Result<SessionTransitionGuard, LeaseError> {
        let resources = resources.into_iter().collect::<BTreeSet<_>>();
        let mut guards = Vec::with_capacity(resources.len());
        for resource in resources {
            validate_identifier("protected resource", resource).map_err(LeaseError::from)?;
            let digest = digest_bytes(resource.as_bytes());
            guards.push(StateResourceLock::acquire(
                get_session_transition_admission_lock_path(&self.app_state_root, &digest),
            )?);
        }
        Ok(SessionTransitionGuard {
            _resource_guards: guards,
        })
    }

    pub(crate) fn list_unlocked(&self) -> Result<Vec<LeaseSnapshot>, LeaseError> {
        let authority_key = self.authority_key()?;
        let mut leases = Vec::new();
        for snapshot in self.scan_records()? {
            if let SessionRecord::Established { lease } = snapshot.value {
                lease.verify(authority_key).map_err(LeaseError::from)?;
                leases.push(LeaseSnapshot {
                    revision: snapshot.revision,
                    lease: *lease,
                });
            }
        }
        leases.sort_by(|left, right| left.lease.session_id.cmp(&right.lease.session_id));
        Ok(leases)
    }

    pub(crate) fn begin_revoke_unlocked(
        &self,
        snapshot: LeaseSnapshot,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<LeaseSnapshot, LeaseError> {
        self.update_lease(
            &snapshot.lease.session_id,
            &snapshot.revision,
            actor_id,
            |lease| {
                if lease.lifecycle.contributes_active_intent() {
                    lease.lifecycle = LeaseLifecycle::Revoking;
                    lease.admission_open = false;
                    lease.heartbeat_at_unix = now_unix;
                    lease.closed_reason = Some("gateway-force-off".to_string());
                    Ok(())
                } else {
                    Err(LeaseError::LeaseNotActive)
                }
            },
        )
    }

    pub(crate) fn remove_drained_unlocked(
        &self,
        snapshot: LeaseSnapshot,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<bool, LeaseError> {
        if snapshot.lease.in_flight_calls != 0 || !snapshot.lease.in_flight_call_ids.is_empty() {
            return Ok(false);
        }
        self.close_and_remove_unlocked(
            snapshot,
            actor_id,
            "gateway-off",
            now_unix,
            LeaseLifecycle::Closed,
            InFlightClosePolicy::RequireDrained,
        )?;
        Ok(true)
    }

    fn update_owned_lease<F>(
        &self,
        handle: &SessionHandle,
        expected: &StateRevision,
        now_unix: i64,
        mutation: F,
    ) -> Result<LeaseSnapshot, LeaseError>
    where
        F: FnOnce(&mut SessionLease) -> Result<(), LeaseError>,
    {
        let _registry = self.registry_lock()?;
        let loaded = self.load_established(handle.session_id())?;
        loaded
            .lease
            .verify_handle(handle)
            .map_err(LeaseError::from)?;
        if loaded.lease.lease_expires_at_unix <= now_unix {
            return Err(LeaseError::LeaseExpired);
        }
        self.update_lease(handle.session_id(), expected, handle.owner_id(), |lease| {
            lease.verify_handle(handle).map_err(LeaseError::from)?;
            mutation(lease)?;
            lease.heartbeat_at_unix = now_unix;
            Ok(())
        })
    }

    fn update_lease<F>(
        &self,
        session_id: &str,
        expected: &StateRevision,
        actor_id: &str,
        mutation: F,
    ) -> Result<LeaseSnapshot, LeaseError>
    where
        F: FnOnce(&mut SessionLease) -> Result<(), LeaseError>,
    {
        let authority_key = self.authority_key()?;
        validate_identifier("session id", session_id).map_err(LeaseError::from)?;
        validate_identifier("state actor", actor_id).map_err(LeaseError::from)?;
        let store = self.store(session_id);
        let snapshot = store
            .load::<SessionRecord>()?
            .ok_or(LeaseError::SessionNotFound)?;
        snapshot
            .value
            .verify(authority_key)
            .map_err(LeaseError::from)?;
        if &snapshot.revision != expected {
            return Err(LeaseError::State(StateError::StaleRevision {
                expected: Some(expected.clone()),
                actual: Some(snapshot.revision),
            }));
        }
        let mut lease = match snapshot.value {
            SessionRecord::Established { lease } => *lease,
            SessionRecord::Pending { .. } => return Err(LeaseError::BootstrapNotConsumed),
        };
        mutation(&mut lease)?;
        lease.seal(authority_key).map_err(LeaseError::from)?;
        lease.verify(authority_key).map_err(LeaseError::from)?;
        let generation = snapshot
            .owner
            .generation
            .checked_add(1)
            .ok_or(LeaseError::OwnerGenerationOverflow)?;
        let revision = store.compare_and_swap(
            Some(expected),
            OwnerGeneration::new(actor_id, generation)?,
            &SessionRecord::Established {
                lease: Box::new(lease.clone()),
            },
        )?;
        Ok(LeaseSnapshot { revision, lease })
    }

    fn close_and_remove_unlocked(
        &self,
        snapshot: LeaseSnapshot,
        actor_id: &str,
        reason: &str,
        now_unix: i64,
        lifecycle: LeaseLifecycle,
        in_flight_policy: InFlightClosePolicy,
    ) -> Result<(), LeaseError> {
        let closed = self.close_unlocked(
            snapshot,
            actor_id,
            reason,
            now_unix,
            lifecycle,
            in_flight_policy,
        )?;
        self.store(&closed.lease.session_id)
            .remove_if_revision(&closed.revision)?;
        Ok(())
    }

    fn close_unlocked(
        &self,
        snapshot: LeaseSnapshot,
        actor_id: &str,
        reason: &str,
        now_unix: i64,
        lifecycle: LeaseLifecycle,
        in_flight_policy: InFlightClosePolicy,
    ) -> Result<LeaseSnapshot, LeaseError> {
        self.update_lease(
            &snapshot.lease.session_id,
            &snapshot.revision,
            actor_id,
            |lease| {
                if in_flight_policy == InFlightClosePolicy::RequireDrained
                    && (lease.in_flight_calls != 0 || !lease.in_flight_call_ids.is_empty())
                {
                    return Err(LeaseError::SessionDraining);
                }
                lease.lifecycle = lifecycle;
                lease.admission_open = false;
                lease.in_flight_calls = 0;
                lease.in_flight_call_ids.clear();
                lease.heartbeat_at_unix = now_unix;
                lease.closed_reason = Some(reason.to_string());
                Ok(())
            },
        )
    }

    fn load_established(&self, session_id: &str) -> Result<LeaseSnapshot, LeaseError> {
        let authority_key = self.authority_key()?;
        validate_identifier("session id", session_id).map_err(LeaseError::from)?;
        let snapshot = self
            .store(session_id)
            .load::<SessionRecord>()?
            .ok_or(LeaseError::SessionNotFound)?;
        snapshot
            .value
            .verify(authority_key)
            .map_err(LeaseError::from)?;
        if snapshot.value.session_id() != session_id {
            return Err(LeaseError::SessionPathMismatch);
        }
        match snapshot.value {
            SessionRecord::Established { lease } => Ok(LeaseSnapshot {
                revision: snapshot.revision,
                lease: *lease,
            }),
            SessionRecord::Pending { .. } => Err(LeaseError::BootstrapNotConsumed),
        }
    }

    fn scan_records(
        &self,
    ) -> Result<Vec<crate::state::atomic_json::StateSnapshot<SessionRecord>>, LeaseError> {
        let authority_key = self.authority_key()?;
        let directory = get_session_leases_dir(&self.app_state_root);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(state_io_error(&directory, error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(LeaseError::State(StateError::SymlinkRejected {
                path: directory,
            }));
        }
        if !metadata.is_dir() {
            return Err(LeaseError::State(StateError::NotRegularFile {
                path: directory,
            }));
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|error| state_io_error(&directory, error))? {
            let entry = entry.map_err(|error| state_io_error(&directory, error))?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(LeaseError::UnexpectedSessionEntry(entry.path()));
            };
            if file_name.starts_with('.') {
                continue;
            }
            let Some(encoded_id) = file_name.strip_suffix(".json") else {
                return Err(LeaseError::UnexpectedSessionEntry(entry.path()));
            };
            let store = AtomicJsonStore::new(entry.path(), SESSION_LEASE_SCHEMA_VERSION);
            let snapshot = store
                .load::<SessionRecord>()?
                .ok_or(LeaseError::SessionNotFound)?;
            snapshot
                .value
                .verify(authority_key)
                .map_err(LeaseError::from)?;
            let expected_name = crate::encode_path_segment(snapshot.value.session_id());
            if expected_name != encoded_id {
                return Err(LeaseError::SessionPathMismatch);
            }
            records.push(snapshot);
        }
        records.sort_by(|left, right| left.value.session_id().cmp(right.value.session_id()));
        Ok(records)
    }

    fn gateway_admission_blocked(
        &self,
        provider: ProviderId,
        repository_key: &str,
        workspace_key: &str,
    ) -> Result<bool, LeaseError> {
        let directory = get_gateway_modes_dir(&self.app_state_root);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(state_io_error(&directory, error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(LeaseError::State(StateError::SymlinkRejected {
                path: directory,
            }));
        }
        if !metadata.is_dir() {
            return Err(LeaseError::State(StateError::NotRegularFile {
                path: directory,
            }));
        }

        let mut selected = None::<(u8, bool)>;
        for entry in fs::read_dir(&directory).map_err(|error| state_io_error(&directory, error))? {
            let entry = entry.map_err(|error| state_io_error(&directory, error))?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                return Err(LeaseError::UnexpectedModeEntry(entry.path()));
            };
            if file_name.starts_with('.') {
                continue;
            }
            let Some(encoded_key) = file_name.strip_suffix(".json") else {
                return Err(LeaseError::UnexpectedModeEntry(entry.path()));
            };
            let snapshot = AtomicJsonStore::new(entry.path(), GATEWAY_MODE_SCHEMA_VERSION)
                .load::<GatewayModeState>()?
                .ok_or(LeaseError::GatewayNotInstalled)?;
            snapshot.value.verify()?;
            if crate::encode_path_segment(&snapshot.value.target.key()?) != encoded_key {
                return Err(LeaseError::SessionPathMismatch);
            }
            if snapshot
                .value
                .target
                .matches_binding(provider, repository_key, workspace_key)
            {
                let candidate = (
                    snapshot.value.target.specificity(),
                    snapshot.value.admission_open,
                );
                if selected.is_none_or(|current| candidate.0 > current.0) {
                    selected = Some(candidate);
                }
            }
        }
        Ok(selected.is_some_and(|(_, admission_open)| !admission_open))
    }

    fn store(&self, session_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            get_session_lease_path(&self.app_state_root, session_id),
            SESSION_LEASE_SCHEMA_VERSION,
        )
    }

    fn authority_key(&self) -> Result<&SessionAuthorityKey, LeaseError> {
        self.authority_key
            .as_ref()
            .ok_or(LeaseError::SessionAuthorityUnavailable)
    }
}

impl TransitionConflictChecker for SessionManager {
    fn acquire(
        &self,
        plan: &TransitionPlan,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict> {
        self.acquire_with_allowed_lease(plan, |_| false)
    }
}

impl SessionManager {
    pub(crate) fn acquire_gateway_workflow(
        &self,
        plan: &TransitionPlan,
        target: &GatewayModeTarget,
        allow_forced_drain: bool,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict> {
        self.acquire_with_allowed_lease(plan, |lease| {
            allow_forced_drain
                && target.matches(lease)
                && lease.desired_exposure.profile.requires_gateway_routing()
        })
    }

    fn acquire_with_allowed_lease(
        &self,
        plan: &TransitionPlan,
        allowed: impl Fn(&SessionLease) -> bool,
    ) -> Result<Box<dyn TransitionConflictGuard>, TransitionConflict> {
        let resources = plan
            .effects
            .iter()
            .map(|effect| effect.resource_id.as_str())
            .collect::<BTreeSet<_>>();
        let admission = self
            .acquire_transition_admission(resources.iter().copied())
            .map_err(|_| conflict("session-state-unavailable"))?;
        let registry = self
            .registry_lock()
            .map_err(|_| conflict("session-state-unavailable"))?;
        for lease in self
            .list_unlocked()
            .map_err(|_| conflict("session-state-unavailable"))?
        {
            if !lease.lease.lifecycle.contributes_active_intent() {
                continue;
            }
            if allowed(&lease.lease) {
                continue;
            }
            if let Some(resource) = lease
                .lease
                .protected_resources
                .iter()
                .find(|resource| resources.contains(resource.as_str()))
            {
                return Err(conflict(&format!("active-lease-{resource}")));
            }
        }
        drop(registry);
        Ok(Box::new(admission))
    }
}

fn require_active(lease: &SessionLease) -> Result<(), LeaseError> {
    if lease.lifecycle == LeaseLifecycle::Active {
        Ok(())
    } else if lease.lifecycle == LeaseLifecycle::Revoking {
        Err(LeaseError::AdmissionClosed)
    } else {
        Err(LeaseError::LeaseNotActive)
    }
}

fn conflict(code: &str) -> TransitionConflict {
    TransitionConflict::new(code).expect("session conflict codes are safe")
}

fn secure_random_secret() -> Result<[u8; 32], LeaseError> {
    let mut file = File::open("/dev/urandom").map_err(|_| LeaseError::SecureRandomUnavailable)?;
    let mut secret = [0_u8; 32];
    file.read_exact(&mut secret)
        .map_err(|_| LeaseError::SecureRandomUnavailable)?;
    Ok(secret)
}

fn state_io_error(path: &Path, error: io::Error) -> LeaseError {
    LeaseError::State(StateError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

#[derive(Debug)]
pub enum LeaseError {
    State(StateError),
    SessionAuthorityUnavailable,
    SessionNotFound,
    SessionPathMismatch,
    UnexpectedSessionEntry(PathBuf),
    UnexpectedModeEntry(PathBuf),
    UnsafeOverlay(PathBuf),
    BootstrapNotConsumed,
    BootstrapAlreadyConsumed,
    BootstrapExpired,
    BootstrapAuthenticationFailed,
    BindingMismatch,
    MultiplexedConnection,
    GatewayAdmissionClosed,
    StrictIsolationUnavailable,
    ContextMismatch,
    OwnerAuthenticationFailed,
    IntegrityMismatch,
    InvalidProcessEvidence,
    InvalidState(String),
    InvalidExposureStatus,
    InvalidCallAdmission,
    InvalidStaleWindow,
    LeaseExpired,
    LeaseNotActive,
    AdmissionClosed,
    InFlightOverflow,
    SessionDraining,
    OwnerGenerationOverflow,
    SecureRandomUnavailable,
    ProcessInspection(String),
    ProcessNotRunning(u32),
    ActiveLeases { session_ids: Vec<String> },
    GatewayNotInstalled,
    GatewayMustBeOff,
}

impl From<StateError> for LeaseError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<LeaseValidationError> for LeaseError {
    fn from(error: LeaseValidationError) -> Self {
        match error {
            LeaseValidationError::StrictIsolationUnavailable => Self::StrictIsolationUnavailable,
            LeaseValidationError::OwnerAuthenticationFailed => Self::OwnerAuthenticationFailed,
            LeaseValidationError::AuthenticationFailed => Self::IntegrityMismatch,
            LeaseValidationError::InvalidProcessEvidence => Self::InvalidProcessEvidence,
            other => Self::InvalidState(other.to_string()),
        }
    }
}

impl fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "session state error: {error}"),
            Self::SessionAuthorityUnavailable => {
                formatter.write_str("session authority key is unavailable")
            }
            Self::SessionNotFound => formatter.write_str("session was not found"),
            Self::SessionPathMismatch => formatter.write_str("session state path does not match id"),
            Self::UnexpectedSessionEntry(path) => {
                write!(formatter, "unexpected session state entry: {}", path.display())
            }
            Self::UnexpectedModeEntry(path) => {
                write!(formatter, "unexpected gateway mode entry: {}", path.display())
            }
            Self::UnsafeOverlay(path) => {
                write!(formatter, "session overlay is unsafe or contested: {}", path.display())
            }
            Self::BootstrapNotConsumed => formatter.write_str("bootstrap has not been consumed"),
            Self::BootstrapAlreadyConsumed => formatter.write_str("bootstrap was already consumed"),
            Self::BootstrapExpired => formatter.write_str("bootstrap authority expired"),
            Self::BootstrapAuthenticationFailed => {
                formatter.write_str("bootstrap authentication failed")
            }
            Self::BindingMismatch => formatter.write_str("bootstrap binding mismatch"),
            Self::MultiplexedConnection => formatter.write_str(
                "connection already owns a session lease; strict logical-session isolation is unavailable",
            ),
            Self::GatewayAdmissionClosed => {
                formatter.write_str("gateway mode is not admitting new sessions")
            }
            Self::StrictIsolationUnavailable => {
                formatter.write_str("strict isolation is unavailable for current native coverage")
            }
            Self::ContextMismatch => formatter.write_str("session context mismatch"),
            Self::OwnerAuthenticationFailed => {
                formatter.write_str("session owner authentication failed")
            }
            Self::IntegrityMismatch => formatter.write_str("session state integrity mismatch"),
            Self::InvalidProcessEvidence => formatter.write_str("invalid process evidence"),
            Self::InvalidState(message) => write!(formatter, "invalid session state: {message}"),
            Self::InvalidExposureStatus => formatter.write_str("invalid exposure observation status"),
            Self::InvalidCallAdmission => formatter.write_str("invalid call admission token"),
            Self::InvalidStaleWindow => formatter.write_str("stale window must be positive"),
            Self::LeaseExpired => formatter.write_str("session lease expired"),
            Self::LeaseNotActive => formatter.write_str("session lease is not active"),
            Self::AdmissionClosed => formatter.write_str("session is not admitting new calls"),
            Self::InFlightOverflow => formatter.write_str("in-flight call counter overflow"),
            Self::SessionDraining => formatter.write_str("session still has in-flight calls"),
            Self::OwnerGenerationOverflow => formatter.write_str("session owner generation overflow"),
            Self::SecureRandomUnavailable => formatter.write_str("secure OS randomness unavailable"),
            Self::ProcessInspection(message) => write!(formatter, "process inspection failed: {message}"),
            Self::ProcessNotRunning(pid) => write!(formatter, "process {pid} is not running"),
            Self::ActiveLeases { session_ids } => {
                write!(formatter, "gateway target has active leases: {}", session_ids.join(", "))
            }
            Self::GatewayNotInstalled => formatter.write_str("gateway is not installed"),
            Self::GatewayMustBeOff => formatter.write_str("gateway routing must be off before detach"),
        }
    }
}

impl std::error::Error for LeaseError {}
