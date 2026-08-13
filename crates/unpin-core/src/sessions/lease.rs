use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Read, Write},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    profiles::{CapabilityLockSnapshot, ProfileSourceScope},
    providers::ProviderId,
};

pub const SESSION_LEASE_STORE_SCHEMA_V2: u32 = 2;
pub const SESSION_LEASE_STORE_SCHEMA_V3: u32 = 3;
pub const SESSION_LEASE_SCHEMA_VERSION: u32 = SESSION_LEASE_STORE_SCHEMA_V3;
pub const BOOTSTRAP_LIFETIME_SECONDS: i64 = 5 * 60;
pub const MAX_SESSION_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const SESSION_OVERLAY_MARKER: &str = ".unpin-overlay.json";
const SECRET_BYTES: usize = 32;
const SESSION_AUTHENTICATION_ALGORITHM: &str = "hmac-sha256";
const BOOTSTRAP_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-session-bootstrap-v2\0";
const LEASE_AUTHENTICATION_PURPOSE_V2: &[u8] = b"unpin-session-lease-v2\0";
const LEASE_AUTHENTICATION_PURPOSE_V3: &[u8] = b"unpin-session-lease-v3\0";
const LAUNCH_CONTROL_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-session-launch-control-v1\0";
const RUNTIME_REGISTRATION_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-runtime-registration-v1\0";
const INVENTORY_GROUP_AUTHENTICATION_PURPOSE: &[u8] =
    b"unpin-inventory-group-session-authority-v1\0";
const REACH_AWARE_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-reach-aware-operation-v2\0";

#[derive(Clone)]
pub struct SessionAuthorityKey([u8; SECRET_BYTES]);

impl SessionAuthorityKey {
    #[must_use]
    pub const fn new(bytes: [u8; SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes: [u8; SECRET_BYTES] = bytes
            .try_into()
            .map_err(|_| "session authority key must be exactly 32 bytes".to_string())?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn key_id(&self) -> String {
        format!(
            "sha256:{}",
            &crate::encode_lower_hex(&Sha256::digest(self.0))[..16]
        )
    }

    pub fn authenticate_launch_control(&self, payload: &[u8]) -> Result<String, String> {
        self.authenticate(LAUNCH_CONTROL_AUTHENTICATION_PURPOSE, payload)
            .map_err(|error| error.to_string())
    }

    pub fn verify_launch_control(&self, payload: &[u8], tag: &str) -> Result<(), String> {
        self.verify(LAUNCH_CONTROL_AUTHENTICATION_PURPOSE, payload, tag)
            .map_err(|error| error.to_string())
    }

    pub fn authenticate_runtime_registration(&self, payload: &[u8]) -> Result<String, String> {
        self.authenticate(RUNTIME_REGISTRATION_AUTHENTICATION_PURPOSE, payload)
            .map_err(|error| error.to_string())
    }

    pub fn verify_runtime_registration(&self, payload: &[u8], tag: &str) -> Result<(), String> {
        self.verify(RUNTIME_REGISTRATION_AUTHENTICATION_PURPOSE, payload, tag)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn authenticate_inventory_group(&self, payload: &[u8]) -> Result<String, String> {
        self.authenticate(INVENTORY_GROUP_AUTHENTICATION_PURPOSE, payload)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn verify_inventory_group(&self, payload: &[u8], tag: &str) -> Result<(), String> {
        self.verify(INVENTORY_GROUP_AUTHENTICATION_PURPOSE, payload, tag)
            .map_err(|error| error.to_string())
    }

    pub fn authenticate_reach_aware(&self, payload: &[u8]) -> Result<String, String> {
        self.authenticate(REACH_AWARE_AUTHENTICATION_PURPOSE, payload)
            .map_err(|error| error.to_string())
    }

    pub fn verify_reach_aware(&self, payload: &[u8], tag: &str) -> Result<(), String> {
        self.verify(REACH_AWARE_AUTHENTICATION_PURPOSE, payload, tag)
            .map_err(|error| error.to_string())
    }

    fn authenticate(&self, purpose: &[u8], payload: &[u8]) -> Result<String, LeaseValidationError> {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.0)
            .map_err(|_| LeaseValidationError::InvalidAuthorityKey)?;
        mac.update(purpose);
        mac.update(payload);
        Ok(crate::encode_lower_hex(&mac.finalize().into_bytes()))
    }

    fn verify(
        &self,
        purpose: &[u8],
        payload: &[u8],
        tag: &str,
    ) -> Result<(), LeaseValidationError> {
        let tag = decode_authentication_tag(tag)?;
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.0)
            .map_err(|_| LeaseValidationError::InvalidAuthorityKey)?;
        mac.update(purpose);
        mac.update(payload);
        mac.verify_slice(&tag)
            .map_err(|_| LeaseValidationError::AuthenticationFailed)
    }

    pub(crate) fn authenticate_workflow_high_water(
        &self,
        payload: &[u8],
    ) -> Result<String, LeaseValidationError> {
        self.authenticate(b"unpin-session-workflow-high-water-v1\0", payload)
    }
}

impl fmt::Debug for SessionAuthorityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthorityKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl Drop for SessionAuthorityKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PinnedProfile {
    Native,
    None,
    Profile {
        profile_id: String,
        profile_digest: String,
        origin_scope: ProfileSourceScope,
        definition_digest: String,
    },
}

impl PinnedProfile {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        match self {
            Self::Native | Self::None => Ok(()),
            Self::Profile {
                profile_id,
                profile_digest,
                definition_digest,
                ..
            } => {
                validate_identifier("profile id", profile_id)?;
                validate_digest("profile", profile_digest)?;
                validate_digest("profile definition", definition_digest)
            }
        }
    }

    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        match self {
            Self::Profile { profile_digest, .. } => Some(profile_digest),
            Self::Native | Self::None => None,
        }
    }

    #[must_use]
    pub(crate) const fn requires_gateway_routing(&self) -> bool {
        !matches!(self, Self::Native)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedExposure {
    pub revision: String,
    pub profile: PinnedProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_locks: Option<Box<CapabilityLockSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedWorkflowEnvelope {
    pub workflow_id: String,
    pub workflow_revision: String,
    pub baseline_profile_id: String,
    pub baseline_profile_digest: String,
    pub profile_revisions: std::collections::BTreeMap<String, String>,
    pub active_mode: String,
    pub active_effective_profile_digest: String,
    pub maximum_envelope_digest: String,
    pub capability_lock_digest: String,
    pub catalog_revision: String,
    pub proposal_id: String,
    pub proposal_fingerprint: String,
    pub state_sequence: u64,
    pub sealed_generation: u64,
}

impl PinnedWorkflowEnvelope {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        validate_identifier("workflow id", &self.workflow_id)?;
        validate_identifier("baseline profile id", &self.baseline_profile_id)?;
        validate_identifier("workflow mode", &self.active_mode)?;
        validate_identifier("workflow proposal id", &self.proposal_id)?;
        for (mode, digest) in &self.profile_revisions {
            validate_identifier("workflow mode", mode)?;
            validate_digest("workflow profile", digest)?;
        }
        for (label, digest) in [
            ("workflow revision", &self.workflow_revision),
            ("baseline profile", &self.baseline_profile_digest),
            ("effective profile", &self.active_effective_profile_digest),
            ("maximum envelope", &self.maximum_envelope_digest),
            ("capability lock", &self.capability_lock_digest),
            ("catalog revision", &self.catalog_revision),
            ("proposal fingerprint", &self.proposal_fingerprint),
        ] {
            validate_digest(label, digest)?;
        }
        if self.profile_revisions.is_empty()
            || !self.profile_revisions.contains_key(&self.active_mode)
            || self.state_sequence == 0
            || self.sealed_generation == 0
        {
            return Err(LeaseValidationError::InvalidWorkflowEnvelope);
        }
        Ok(())
    }
}

impl PinnedExposure {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        validate_digest("exposure revision", &self.revision)?;
        self.profile.validate()?;
        if let Some(locks) = &self.capability_locks {
            locks
                .verify()
                .map_err(|_| LeaseValidationError::InvalidCapabilityLocks)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationLevel {
    Strict,
    ConnectionScoped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CoverageLevel {
    VerifiedMasked,
    ExternalDegraded { reasons: Vec<String> },
}

impl CoverageLevel {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        match self {
            Self::VerifiedMasked => Ok(()),
            Self::ExternalDegraded { reasons } => {
                if reasons.is_empty() {
                    return Err(LeaseValidationError::InvalidCoverage);
                }
                for reason in reasons {
                    validate_identifier("coverage reason", reason)?;
                }
                let mut canonical = reasons.clone();
                canonical.sort();
                canonical.dedup();
                if canonical != *reasons {
                    return Err(LeaseValidationError::InvalidCoverage);
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub const fn supports_strict_isolation(&self) -> bool {
        matches!(self, Self::VerifiedMasked)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessEvidence {
    pub pid: u32,
    pub start_marker: String,
}

impl ProcessEvidence {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        if self.pid == 0 {
            return Err(LeaseValidationError::InvalidProcessEvidence);
        }
        validate_identifier("process start marker", &self.start_marker)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRequest {
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub workspace_revision: Option<String>,
    pub exposure: PinnedExposure,
    pub process: ProcessEvidence,
    pub connection_scope_id: String,
    pub isolation: IsolationLevel,
    pub coverage: CoverageLevel,
    pub protected_resources: BTreeSet<String>,
    pub lease_expires_at_unix: i64,
}

impl BootstrapRequest {
    pub(crate) fn validate(&self, now_unix: i64) -> Result<(), LeaseValidationError> {
        validate_identifier("repository key", &self.repository_key)?;
        validate_identifier("workspace key", &self.workspace_key)?;
        validate_identifier("connection scope", &self.connection_scope_id)?;
        if let Some(revision) = &self.workspace_revision {
            validate_workspace_revision(revision)?;
        }
        self.exposure.validate()?;
        if self
            .exposure
            .capability_locks
            .as_ref()
            .is_some_and(|locks| locks.provider != self.provider)
        {
            return Err(LeaseValidationError::InvalidCapabilityLocks);
        }
        self.process.validate()?;
        self.coverage.validate()?;
        if self.isolation == IsolationLevel::Strict && !self.coverage.supports_strict_isolation() {
            return Err(LeaseValidationError::StrictIsolationUnavailable);
        }
        for resource in &self.protected_resources {
            validate_identifier("protected resource", resource)?;
        }
        validate_lifetime(
            now_unix,
            self.lease_expires_at_unix,
            MAX_SESSION_LIFETIME_SECONDS,
            LeaseValidationError::InvalidLeaseExpiry,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClaim {
    pub connection_owner_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub process: ProcessEvidence,
    pub connection_scope_id: String,
}

impl ConnectionClaim {
    pub(crate) fn validate(&self) -> Result<(), LeaseValidationError> {
        validate_identifier("connection owner", &self.connection_owner_id)?;
        validate_identifier("repository key", &self.repository_key)?;
        validate_identifier("workspace key", &self.workspace_key)?;
        validate_identifier("connection scope", &self.connection_scope_id)?;
        self.process.validate()
    }
}

pub struct BootstrapAuthority {
    session_id: String,
    secret: [u8; SECRET_BYTES],
}

impl BootstrapAuthority {
    pub(crate) fn new(session_id: String, secret: [u8; SECRET_BYTES]) -> Self {
        Self { session_id, secret }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn write_secret(&self, mut writer: impl Write) -> io::Result<()> {
        let encoded = Zeroizing::new(crate::encode_lower_hex(&self.secret));
        writer.write_all(encoded.as_bytes())
    }

    pub fn read_secret(session_id: String, reader: impl Read) -> io::Result<Self> {
        validate_identifier("session id", &session_id)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut raw = Zeroizing::new(String::new());
        reader.take(129).read_to_string(&mut raw)?;
        let secret = decode_secret(raw.trim())?;
        Ok(Self { session_id, secret })
    }

    pub(crate) fn secret_digest(&self) -> String {
        digest_bytes(&self.secret)
    }
}

impl fmt::Debug for BootstrapAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapAuthority")
            .field("session_id", &self.session_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for BootstrapAuthority {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

pub struct SessionHandle {
    session_id: String,
    owner_id: String,
    secret: [u8; SECRET_BYTES],
}

impl SessionHandle {
    pub(crate) fn new(session_id: String, owner_id: String, secret: [u8; SECRET_BYTES]) -> Self {
        Self {
            session_id,
            owner_id,
            secret,
        }
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub fn write_secret(&self, mut writer: impl Write) -> io::Result<()> {
        let encoded = Zeroizing::new(crate::encode_lower_hex(&self.secret));
        writer.write_all(encoded.as_bytes())
    }

    pub fn read_secret(
        session_id: String,
        owner_id: String,
        reader: impl Read,
    ) -> io::Result<Self> {
        validate_identifier("session id", &session_id)
            .and_then(|()| validate_identifier("connection owner", &owner_id))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut raw = Zeroizing::new(String::new());
        reader.take(129).read_to_string(&mut raw)?;
        let secret = decode_secret(raw.trim())?;
        Ok(Self {
            session_id,
            owner_id,
            secret,
        })
    }

    pub(crate) fn secret_digest(&self) -> String {
        digest_bytes(&self.secret)
    }
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionHandle")
            .field("session_id", &self.session_id)
            .field("owner_id", &self.owner_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseLifecycle {
    Active,
    Revoking,
    Closed,
    Expired,
}

impl LeaseLifecycle {
    #[must_use]
    pub const fn contributes_active_intent(self) -> bool {
        matches!(self, Self::Active | Self::Revoking)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveExposureStatus {
    Configured,
    NotificationSent,
    ObservedRefresh,
    ReloadRequired,
    NextSessionOnly,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionLease {
    pub session_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub workspace_start_revision: Option<String>,
    pub last_workspace_revision: Option<String>,
    pub workspace_drifted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<Box<PinnedWorkflowEnvelope>>,
    pub desired_exposure: PinnedExposure,
    pub observed_exposure: PinnedExposure,
    pub live_status: LiveExposureStatus,
    pub process: ProcessEvidence,
    pub isolation: IsolationLevel,
    pub coverage: CoverageLevel,
    pub protected_resources: BTreeSet<String>,
    pub lifecycle: LeaseLifecycle,
    pub admission_open: bool,
    pub in_flight_calls: u32,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) in_flight_call_ids: BTreeSet<String>,
    pub heartbeat_at_unix: i64,
    pub lease_expires_at_unix: i64,
    pub connection_owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_reason: Option<String>,
    pub(crate) connection_scope_digest: String,
    pub(crate) owner_secret_digest: String,
    pub(crate) authentication_algorithm: String,
    pub(crate) authority_key_id: String,
    pub(crate) authentication_tag: String,
}

impl SessionLease {
    #[must_use]
    pub const fn store_schema_version(&self) -> u32 {
        if self.workflow.is_some() {
            SESSION_LEASE_STORE_SCHEMA_V3
        } else {
            SESSION_LEASE_STORE_SCHEMA_V2
        }
    }

    pub(crate) fn seal(
        &mut self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), LeaseValidationError> {
        self.authentication_algorithm = SESSION_AUTHENTICATION_ALGORITHM.to_string();
        self.authority_key_id = authority_key.key_id();
        let message = self.authentication_message_v3()?;
        self.authentication_tag =
            authority_key.authenticate(LEASE_AUTHENTICATION_PURPOSE_V3, &message)?;
        Ok(())
    }

    pub(crate) fn verify_for_store_schema(
        &self,
        authority_key: &SessionAuthorityKey,
        store_schema_version: u32,
    ) -> Result<(), LeaseValidationError> {
        self.validate_shape()?;
        if self.authentication_algorithm != SESSION_AUTHENTICATION_ALGORITHM
            || self.authority_key_id != authority_key.key_id()
        {
            return Err(LeaseValidationError::AuthenticationFailed);
        }
        match store_schema_version {
            SESSION_LEASE_STORE_SCHEMA_V2 => authority_key.verify(
                LEASE_AUTHENTICATION_PURPOSE_V2,
                &self.authentication_message_v2()?,
                &self.authentication_tag,
            ),
            SESSION_LEASE_STORE_SCHEMA_V3 => authority_key.verify(
                LEASE_AUTHENTICATION_PURPOSE_V3,
                &self.authentication_message_v3()?,
                &self.authentication_tag,
            ),
            _ => Err(LeaseValidationError::AuthenticationFailed),
        }
    }

    pub(crate) fn verify_handle(&self, handle: &SessionHandle) -> Result<(), LeaseValidationError> {
        if self.session_id == handle.session_id
            && self.connection_owner_id == handle.owner_id
            && constant_time_equal(
                self.owner_secret_digest.as_bytes(),
                handle.secret_digest().as_bytes(),
            )
        {
            Ok(())
        } else {
            Err(LeaseValidationError::OwnerAuthenticationFailed)
        }
    }

    fn validate_shape(&self) -> Result<(), LeaseValidationError> {
        validate_identifier("session id", &self.session_id)?;
        validate_identifier("repository key", &self.repository_key)?;
        validate_identifier("workspace key", &self.workspace_key)?;
        if let Some(revision) = &self.workspace_start_revision {
            validate_workspace_revision(revision)?;
        }
        if let Some(revision) = &self.last_workspace_revision {
            validate_workspace_revision(revision)?;
        }
        self.desired_exposure.validate()?;
        self.observed_exposure.validate()?;
        if let Some(workflow) = &self.workflow {
            workflow.validate()?;
            if workflow.active_effective_profile_digest != self.desired_exposure.revision {
                return Err(LeaseValidationError::InvalidWorkflowEnvelope);
            }
        }
        self.process.validate()?;
        self.coverage.validate()?;
        if self.isolation == IsolationLevel::Strict && !self.coverage.supports_strict_isolation() {
            return Err(LeaseValidationError::StrictIsolationUnavailable);
        }
        for resource in &self.protected_resources {
            validate_identifier("protected resource", resource)?;
        }
        validate_identifier("connection owner", &self.connection_owner_id)?;
        if let Some(reason) = &self.closed_reason {
            validate_identifier("closed reason", reason)?;
        }
        validate_digest("connection scope", &self.connection_scope_digest)?;
        validate_digest("owner secret", &self.owner_secret_digest)?;
        validate_authentication_metadata(
            &self.authentication_algorithm,
            &self.authority_key_id,
            &self.authentication_tag,
        )?;
        for call_id in &self.in_flight_call_ids {
            validate_digest("in-flight call", call_id)?;
        }
        if usize::try_from(self.in_flight_calls).ok() != Some(self.in_flight_call_ids.len()) {
            return Err(LeaseValidationError::InvalidLifecycle);
        }
        if self.lifecycle.contributes_active_intent() {
            validate_lifetime(
                self.heartbeat_at_unix,
                self.lease_expires_at_unix,
                MAX_SESSION_LIFETIME_SECONDS,
                LeaseValidationError::InvalidLeaseExpiry,
            )?;
        }
        if self.lifecycle == LeaseLifecycle::Active
            && !self.admission_open
            && !(self.workflow.is_some()
                && self.desired_exposure != self.observed_exposure
                && matches!(
                    self.live_status,
                    LiveExposureStatus::Configured
                        | LiveExposureStatus::NotificationSent
                        | LiveExposureStatus::ReloadRequired
                ))
            && !(self.workflow.is_some() && self.live_status == LiveExposureStatus::Unknown)
        {
            return Err(LeaseValidationError::InvalidLifecycle);
        }
        if matches!(
            self.lifecycle,
            LeaseLifecycle::Closed | LeaseLifecycle::Expired
        ) && (self.admission_open
            || self.in_flight_calls != 0
            || !self.in_flight_call_ids.is_empty())
        {
            return Err(LeaseValidationError::InvalidLifecycle);
        }
        Ok(())
    }

    fn authentication_message_v3(&self) -> Result<Vec<u8>, LeaseValidationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AuthenticationBody<'a> {
            session_id: &'a str,
            provider: ProviderId,
            repository_key: &'a str,
            workspace_key: &'a str,
            workspace_start_revision: &'a Option<String>,
            last_workspace_revision: &'a Option<String>,
            workspace_drifted: bool,
            workflow: &'a Option<Box<PinnedWorkflowEnvelope>>,
            desired_exposure: &'a PinnedExposure,
            observed_exposure: &'a PinnedExposure,
            live_status: LiveExposureStatus,
            process: &'a ProcessEvidence,
            isolation: IsolationLevel,
            coverage: &'a CoverageLevel,
            protected_resources: &'a BTreeSet<String>,
            lifecycle: LeaseLifecycle,
            admission_open: bool,
            in_flight_calls: u32,
            in_flight_call_ids: &'a BTreeSet<String>,
            heartbeat_at_unix: i64,
            lease_expires_at_unix: i64,
            connection_owner_id: &'a str,
            closed_reason: &'a Option<String>,
            connection_scope_digest: &'a str,
            owner_secret_digest: &'a str,
            authentication_algorithm: &'a str,
            authority_key_id: &'a str,
        }
        serde_json::to_vec(&AuthenticationBody {
            session_id: &self.session_id,
            provider: self.provider,
            repository_key: &self.repository_key,
            workspace_key: &self.workspace_key,
            workspace_start_revision: &self.workspace_start_revision,
            last_workspace_revision: &self.last_workspace_revision,
            workspace_drifted: self.workspace_drifted,
            workflow: &self.workflow,
            desired_exposure: &self.desired_exposure,
            observed_exposure: &self.observed_exposure,
            live_status: self.live_status,
            process: &self.process,
            isolation: self.isolation,
            coverage: &self.coverage,
            protected_resources: &self.protected_resources,
            lifecycle: self.lifecycle,
            admission_open: self.admission_open,
            in_flight_calls: self.in_flight_calls,
            in_flight_call_ids: &self.in_flight_call_ids,
            heartbeat_at_unix: self.heartbeat_at_unix,
            lease_expires_at_unix: self.lease_expires_at_unix,
            connection_owner_id: &self.connection_owner_id,
            closed_reason: &self.closed_reason,
            connection_scope_digest: &self.connection_scope_digest,
            owner_secret_digest: &self.owner_secret_digest,
            authentication_algorithm: &self.authentication_algorithm,
            authority_key_id: &self.authority_key_id,
        })
        .map_err(|error| LeaseValidationError::Serialization(error.to_string()))
    }

    fn authentication_message_v2(&self) -> Result<Vec<u8>, LeaseValidationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AuthenticationBody<'a> {
            session_id: &'a str,
            provider: ProviderId,
            repository_key: &'a str,
            workspace_key: &'a str,
            workspace_start_revision: &'a Option<String>,
            last_workspace_revision: &'a Option<String>,
            workspace_drifted: bool,
            desired_exposure: &'a PinnedExposure,
            observed_exposure: &'a PinnedExposure,
            live_status: LiveExposureStatus,
            process: &'a ProcessEvidence,
            isolation: IsolationLevel,
            coverage: &'a CoverageLevel,
            protected_resources: &'a BTreeSet<String>,
            lifecycle: LeaseLifecycle,
            admission_open: bool,
            in_flight_calls: u32,
            in_flight_call_ids: &'a BTreeSet<String>,
            heartbeat_at_unix: i64,
            lease_expires_at_unix: i64,
            connection_owner_id: &'a str,
            closed_reason: &'a Option<String>,
            connection_scope_digest: &'a str,
            owner_secret_digest: &'a str,
            authentication_algorithm: &'a str,
            authority_key_id: &'a str,
        }
        serde_json::to_vec(&AuthenticationBody {
            session_id: &self.session_id,
            provider: self.provider,
            repository_key: &self.repository_key,
            workspace_key: &self.workspace_key,
            workspace_start_revision: &self.workspace_start_revision,
            last_workspace_revision: &self.last_workspace_revision,
            workspace_drifted: self.workspace_drifted,
            desired_exposure: &self.desired_exposure,
            observed_exposure: &self.observed_exposure,
            live_status: self.live_status,
            process: &self.process,
            isolation: self.isolation,
            coverage: &self.coverage,
            protected_resources: &self.protected_resources,
            lifecycle: self.lifecycle,
            admission_open: self.admission_open,
            in_flight_calls: self.in_flight_calls,
            in_flight_call_ids: &self.in_flight_call_ids,
            heartbeat_at_unix: self.heartbeat_at_unix,
            lease_expires_at_unix: self.lease_expires_at_unix,
            connection_owner_id: &self.connection_owner_id,
            closed_reason: &self.closed_reason,
            connection_scope_digest: &self.connection_scope_digest,
            owner_secret_digest: &self.owner_secret_digest,
            authentication_algorithm: &self.authentication_algorithm,
            authority_key_id: &self.authority_key_id,
        })
        .map_err(|error| LeaseValidationError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingBootstrap {
    pub session_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub workspace_revision: Option<String>,
    pub exposure: PinnedExposure,
    pub process: ProcessEvidence,
    pub connection_scope_digest: String,
    pub isolation: IsolationLevel,
    pub coverage: CoverageLevel,
    pub protected_resources: BTreeSet<String>,
    pub lease_expires_at_unix: i64,
    pub issued_at_unix: i64,
    pub bootstrap_expires_at_unix: i64,
    pub secret_digest: String,
    pub authentication_algorithm: String,
    pub authority_key_id: String,
    pub authentication_tag: String,
}

impl PendingBootstrap {
    pub(crate) fn from_request(
        session_id: String,
        request: BootstrapRequest,
        secret_digest: String,
        now_unix: i64,
        authority_key: &SessionAuthorityKey,
    ) -> Result<Self, LeaseValidationError> {
        request.validate(now_unix)?;
        let mut pending = Self {
            session_id,
            provider: request.provider,
            repository_key: request.repository_key,
            workspace_key: request.workspace_key,
            workspace_revision: request.workspace_revision,
            exposure: request.exposure,
            process: request.process,
            connection_scope_digest: digest_bytes(request.connection_scope_id.as_bytes()),
            isolation: request.isolation,
            coverage: request.coverage,
            protected_resources: request.protected_resources,
            lease_expires_at_unix: request.lease_expires_at_unix,
            issued_at_unix: now_unix,
            bootstrap_expires_at_unix: now_unix
                .checked_add(BOOTSTRAP_LIFETIME_SECONDS)
                .ok_or(LeaseValidationError::InvalidBootstrapExpiry)?,
            secret_digest,
            authentication_algorithm: SESSION_AUTHENTICATION_ALGORITHM.to_string(),
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        let message = pending.authentication_message()?;
        pending.authentication_tag =
            authority_key.authenticate(BOOTSTRAP_AUTHENTICATION_PURPOSE, &message)?;
        pending.verify(authority_key)?;
        Ok(pending)
    }

    pub(crate) fn verify(
        &self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), LeaseValidationError> {
        validate_identifier("session id", &self.session_id)?;
        validate_identifier("repository key", &self.repository_key)?;
        validate_identifier("workspace key", &self.workspace_key)?;
        if let Some(revision) = &self.workspace_revision {
            validate_workspace_revision(revision)?;
        }
        self.exposure.validate()?;
        self.process.validate()?;
        self.coverage.validate()?;
        for resource in &self.protected_resources {
            validate_identifier("protected resource", resource)?;
        }
        validate_digest("connection scope", &self.connection_scope_digest)?;
        validate_digest("bootstrap secret", &self.secret_digest)?;
        validate_authentication_metadata(
            &self.authentication_algorithm,
            &self.authority_key_id,
            &self.authentication_tag,
        )?;
        validate_lifetime(
            self.issued_at_unix,
            self.bootstrap_expires_at_unix,
            BOOTSTRAP_LIFETIME_SECONDS,
            LeaseValidationError::InvalidBootstrapExpiry,
        )?;
        validate_lifetime(
            self.issued_at_unix,
            self.lease_expires_at_unix,
            MAX_SESSION_LIFETIME_SECONDS,
            LeaseValidationError::InvalidLeaseExpiry,
        )?;
        if self.authentication_algorithm != SESSION_AUTHENTICATION_ALGORITHM
            || self.authority_key_id != authority_key.key_id()
        {
            return Err(LeaseValidationError::AuthenticationFailed);
        }
        let message = self.authentication_message()?;
        authority_key.verify(
            BOOTSTRAP_AUTHENTICATION_PURPOSE,
            &message,
            &self.authentication_tag,
        )
    }

    pub(crate) fn matches_claim(&self, claim: &ConnectionClaim) -> bool {
        self.provider == claim.provider
            && self.repository_key == claim.repository_key
            && self.workspace_key == claim.workspace_key
            && self.process == claim.process
            && self.connection_scope_digest == digest_bytes(claim.connection_scope_id.as_bytes())
    }

    pub(crate) fn into_lease(
        self,
        claim: &ConnectionClaim,
        owner_secret_digest: String,
        now_unix: i64,
        authority_key: &SessionAuthorityKey,
    ) -> Result<SessionLease, LeaseValidationError> {
        let mut lease = SessionLease {
            session_id: self.session_id,
            provider: self.provider,
            repository_key: self.repository_key,
            workspace_key: self.workspace_key,
            workspace_start_revision: self.workspace_revision.clone(),
            last_workspace_revision: self.workspace_revision,
            workspace_drifted: false,
            workflow: None,
            desired_exposure: self.exposure.clone(),
            observed_exposure: self.exposure,
            live_status: LiveExposureStatus::ObservedRefresh,
            process: self.process,
            isolation: self.isolation,
            coverage: self.coverage,
            protected_resources: self.protected_resources,
            lifecycle: LeaseLifecycle::Active,
            admission_open: true,
            in_flight_calls: 0,
            in_flight_call_ids: BTreeSet::new(),
            heartbeat_at_unix: now_unix,
            lease_expires_at_unix: self.lease_expires_at_unix,
            connection_owner_id: claim.connection_owner_id.clone(),
            closed_reason: None,
            connection_scope_digest: self.connection_scope_digest,
            owner_secret_digest,
            authentication_algorithm: SESSION_AUTHENTICATION_ALGORITHM.to_string(),
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        lease.seal(authority_key)?;
        lease.verify_for_store_schema(authority_key, SESSION_LEASE_STORE_SCHEMA_V3)?;
        Ok(lease)
    }

    fn authentication_message(&self) -> Result<Vec<u8>, LeaseValidationError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AuthenticationBody<'a> {
            session_id: &'a str,
            provider: ProviderId,
            repository_key: &'a str,
            workspace_key: &'a str,
            workspace_revision: &'a Option<String>,
            exposure: &'a PinnedExposure,
            process: &'a ProcessEvidence,
            connection_scope_digest: &'a str,
            isolation: IsolationLevel,
            coverage: &'a CoverageLevel,
            protected_resources: &'a BTreeSet<String>,
            lease_expires_at_unix: i64,
            issued_at_unix: i64,
            bootstrap_expires_at_unix: i64,
            secret_digest: &'a str,
            authentication_algorithm: &'a str,
            authority_key_id: &'a str,
        }
        serde_json::to_vec(&AuthenticationBody {
            session_id: &self.session_id,
            provider: self.provider,
            repository_key: &self.repository_key,
            workspace_key: &self.workspace_key,
            workspace_revision: &self.workspace_revision,
            exposure: &self.exposure,
            process: &self.process,
            connection_scope_digest: &self.connection_scope_digest,
            isolation: self.isolation,
            coverage: &self.coverage,
            protected_resources: &self.protected_resources,
            lease_expires_at_unix: self.lease_expires_at_unix,
            issued_at_unix: self.issued_at_unix,
            bootstrap_expires_at_unix: self.bootstrap_expires_at_unix,
            secret_digest: &self.secret_digest,
            authentication_algorithm: &self.authentication_algorithm,
            authority_key_id: &self.authority_key_id,
        })
        .map_err(|error| LeaseValidationError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SessionRecord {
    Pending { claim: Box<PendingBootstrap> },
    Established { lease: Box<SessionLease> },
}

impl SessionRecord {
    pub(crate) fn session_id(&self) -> &str {
        match self {
            Self::Pending { claim } => &claim.session_id,
            Self::Established { lease } => &lease.session_id,
        }
    }

    pub(crate) fn workflow_counters(&self) -> Option<(u64, u64)> {
        match self {
            Self::Established { lease } => lease
                .workflow
                .as_ref()
                .map(|workflow| (workflow.state_sequence, workflow.sealed_generation)),
            Self::Pending { .. } => None,
        }
    }

    pub(crate) fn lease_authentication_tag(&self) -> Result<&str, LeaseValidationError> {
        match self {
            Self::Established { lease } => Ok(&lease.authentication_tag),
            Self::Pending { .. } => Err(LeaseValidationError::InvalidLifecycle),
        }
    }

    pub(crate) fn verify_for_store_schema(
        &self,
        authority_key: &SessionAuthorityKey,
        store_schema_version: u32,
    ) -> Result<(), LeaseValidationError> {
        match self {
            Self::Pending { claim } => claim.verify(authority_key),
            Self::Established { lease } => {
                lease.verify_for_store_schema(authority_key, store_schema_version)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LeaseValidationError {
    InvalidIdentifier(&'static str),
    InvalidDigest(&'static str),
    InvalidAuthorityKey,
    InvalidAuthenticationMetadata,
    InvalidProcessEvidence,
    InvalidCoverage,
    InvalidCapabilityLocks,
    StrictIsolationUnavailable,
    InvalidLeaseExpiry,
    InvalidBootstrapExpiry,
    InvalidLifecycle,
    InvalidWorkflowEnvelope,
    OwnerAuthenticationFailed,
    AuthenticationFailed,
    Serialization(String),
}

impl fmt::Display for LeaseValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(label) => write!(formatter, "invalid {label}"),
            Self::InvalidDigest(label) => write!(formatter, "invalid {label} digest"),
            Self::InvalidAuthorityKey => formatter.write_str("invalid session authority key"),
            Self::InvalidAuthenticationMetadata => {
                formatter.write_str("invalid session authentication metadata")
            }
            Self::InvalidProcessEvidence => formatter.write_str("invalid process evidence"),
            Self::InvalidCoverage => formatter.write_str("invalid native coverage evidence"),
            Self::InvalidCapabilityLocks => formatter.write_str("invalid pinned capability locks"),
            Self::StrictIsolationUnavailable => {
                formatter.write_str("strict isolation requires verified masked native coverage")
            }
            Self::InvalidLeaseExpiry => formatter.write_str("invalid session lease expiry"),
            Self::InvalidBootstrapExpiry => formatter.write_str("invalid bootstrap expiry"),
            Self::InvalidLifecycle => formatter.write_str("invalid session lease lifecycle"),
            Self::InvalidWorkflowEnvelope => {
                formatter.write_str("invalid pinned workflow envelope")
            }
            Self::OwnerAuthenticationFailed => {
                formatter.write_str("session owner authentication failed")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("session state authentication failed")
            }
            Self::Serialization(message) => {
                write!(formatter, "session state serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for LeaseValidationError {}

pub(crate) fn validate_identifier(
    label: &'static str,
    value: &str,
) -> Result<(), LeaseValidationError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err(LeaseValidationError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_digest(
    label: &'static str,
    value: &str,
) -> Result<(), LeaseValidationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(LeaseValidationError::InvalidDigest(label))
    }
}

pub(crate) fn validate_workspace_revision(value: &str) -> Result<(), LeaseValidationError> {
    if matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(LeaseValidationError::InvalidDigest("workspace revision"))
    }
}

fn validate_lifetime(
    starts_at_unix: i64,
    expires_at_unix: i64,
    maximum_seconds: i64,
    error: LeaseValidationError,
) -> Result<(), LeaseValidationError> {
    let lifetime = expires_at_unix
        .checked_sub(starts_at_unix)
        .ok_or_else(|| error.clone())?;
    if lifetime <= 0 || lifetime > maximum_seconds {
        Err(error)
    } else {
        Ok(())
    }
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    crate::encode_lower_hex(&Sha256::digest(bytes))
}

fn validate_authentication_metadata(
    algorithm: &str,
    key_id: &str,
    tag: &str,
) -> Result<(), LeaseValidationError> {
    let key_id_digest = key_id
        .strip_prefix("sha256:")
        .ok_or(LeaseValidationError::InvalidAuthenticationMetadata)?;
    if algorithm != SESSION_AUTHENTICATION_ALGORITHM
        || key_id_digest.len() != 16
        || !key_id_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LeaseValidationError::InvalidAuthenticationMetadata);
    }
    validate_digest("session authentication tag", tag)
}

pub(crate) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn decode_secret(raw: &str) -> io::Result<[u8; SECRET_BYTES]> {
    if raw.len() != SECRET_BYTES * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bootstrap authority must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut secret = [0_u8; SECRET_BYTES];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid bootstrap authority")
        })?;
    }
    Ok(secret)
}

fn decode_authentication_tag(raw: &str) -> Result<[u8; SECRET_BYTES], LeaseValidationError> {
    decode_secret(raw).map_err(|_| LeaseValidationError::InvalidAuthenticationMetadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(expires_at_unix: i64) -> BootstrapRequest {
        BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "e".repeat(64),
                profile: PinnedProfile::Native,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: 42,
                start_marker: "process-start".to_string(),
            },
            connection_scope_id: "connection-scope".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::from(["provider-config".to_string()]),
            lease_expires_at_unix: expires_at_unix,
        }
    }

    fn resign_pending(pending: &mut PendingBootstrap, authority_key: &SessionAuthorityKey) {
        pending.authentication_tag = authority_key
            .authenticate(
                BOOTSTRAP_AUTHENTICATION_PURPOSE,
                &pending.authentication_message().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn authenticated_persisted_records_enforce_lifetime_ceilings() {
        let now_unix = 1_000;
        let authority_key = SessionAuthorityKey::new([0x53; 32]);
        let mut pending = PendingBootstrap::from_request(
            "session-one".to_string(),
            request(now_unix + 60),
            digest_bytes(b"bootstrap-secret"),
            now_unix,
            &authority_key,
        )
        .unwrap();

        pending.bootstrap_expires_at_unix = pending.issued_at_unix + BOOTSTRAP_LIFETIME_SECONDS + 1;
        resign_pending(&mut pending, &authority_key);
        assert_eq!(
            pending.verify(&authority_key),
            Err(LeaseValidationError::InvalidBootstrapExpiry)
        );

        pending.bootstrap_expires_at_unix = pending.issued_at_unix + BOOTSTRAP_LIFETIME_SECONDS;
        pending.lease_expires_at_unix = pending.issued_at_unix + MAX_SESSION_LIFETIME_SECONDS + 1;
        resign_pending(&mut pending, &authority_key);
        assert_eq!(
            pending.verify(&authority_key),
            Err(LeaseValidationError::InvalidLeaseExpiry)
        );

        pending.lease_expires_at_unix = pending.issued_at_unix + 60;
        resign_pending(&mut pending, &authority_key);
        let claim = ConnectionClaim {
            connection_owner_id: "connection-owner".to_string(),
            provider: pending.provider,
            repository_key: pending.repository_key.clone(),
            workspace_key: pending.workspace_key.clone(),
            process: pending.process.clone(),
            connection_scope_id: "connection-scope".to_string(),
        };
        let mut lease = pending
            .into_lease(
                &claim,
                digest_bytes(b"owner-secret"),
                now_unix + 1,
                &authority_key,
            )
            .unwrap();
        lease.lease_expires_at_unix = lease.heartbeat_at_unix + MAX_SESSION_LIFETIME_SECONDS + 1;
        lease.seal(&authority_key).unwrap();
        assert_eq!(
            lease.verify_for_store_schema(&authority_key, SESSION_LEASE_STORE_SCHEMA_V3),
            Err(LeaseValidationError::InvalidLeaseExpiry)
        );
    }
}
