use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sessions::{LeaseLifecycle, ProcessEvidence};

use super::service::GatewayExposure;
use super::{GatewayControlPlane, GatewayError};

const CLAIM_PURPOSE: &[u8] = b"unpin-gateway-connection-claim-v1\0";

type ClaimMac = Hmac<Sha256>;

/// The role assigned by the gateway when a transport connection is accepted.
///
/// A primary connection is the only connection that may receive or observe
/// authored exposure. Auxiliary connections remain useful for typed status and
/// mode controls, but never gain access to the projected capability set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayConnectionRole {
    Primary,
    Auxiliary,
}

/// An opaque, server-issued binding for one accepted gateway connection.
///
/// The fields are intentionally private. A transport must retain the value
/// returned by [`GatewayConnectionRegistry::issue_claim`] and pass it back to
/// the core entry points; request JSON cannot manufacture a claim.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayConnectionClaim {
    session_id: String,
    owner_id: String,
    process_generation: String,
    connection_epoch: u64,
    role: GatewayConnectionRole,
    authentication_tag: String,
}

impl std::fmt::Debug for GatewayConnectionClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayConnectionClaim")
            .field("session_id", &self.session_id)
            .field("owner_id", &self.owner_id)
            .field("process_generation", &self.process_generation)
            .field("connection_epoch", &self.connection_epoch)
            .field("role", &self.role)
            .field("authentication_tag", &"[REDACTED]")
            .finish()
    }
}

impl GatewayConnectionClaim {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Returns the process generation bound into the claim. This is a digest,
    /// not the process start marker or any other private process evidence.
    #[must_use]
    pub fn process_generation(&self) -> &str {
        &self.process_generation
    }

    #[must_use]
    pub const fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }

    #[must_use]
    pub const fn role(&self) -> GatewayConnectionRole {
        self.role
    }

    #[must_use]
    pub const fn is_primary(&self) -> bool {
        matches!(self.role, GatewayConnectionRole::Primary)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayConnectionStatus {
    pub session_id: String,
    pub owner_id: String,
    pub process_generation: String,
    pub connection_epoch: u64,
    pub role: GatewayConnectionRole,
    pub connected: bool,
    pub observation_sequence: u64,
    pub observed_exposure_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_exposure_revision: Option<String>,
    /// Durable evidence that the desired lease state is not safely callable
    /// from this connection yet. This survives a transport disconnect when a
    /// replacement claim is issued against the same active session.
    pub recovery_required: bool,
}

#[derive(Debug)]
struct ConnectionState {
    claim: GatewayConnectionClaim,
    observed: Arc<GatewayExposure>,
    pending: Option<Arc<GatewayExposure>>,
    observation_sequence: u64,
}

#[derive(Debug, Default)]
struct RegistryState {
    next_epoch: u64,
    primary_epoch: Option<u64>,
    connections: BTreeMap<u64, ConnectionState>,
}

/// Connection-local exposure and claim registry for one authenticated session.
#[derive(Debug)]
pub struct GatewayConnectionRegistry {
    control: Arc<GatewayControlPlane>,
    state: Mutex<RegistryState>,
}

impl GatewayConnectionRegistry {
    pub(crate) fn new(control: Arc<GatewayControlPlane>) -> Self {
        Self {
            control,
            state: Mutex::new(RegistryState {
                next_epoch: 1,
                ..RegistryState::default()
            }),
        }
    }

    /// Issue a claim for a newly accepted transport connection.
    ///
    /// No role, process evidence, session identity, or epoch is accepted from
    /// the caller. They are derived from the authenticated lease and registry
    /// state; the first live connection is primary and all later connections
    /// are auxiliary until the primary disconnects.
    pub(crate) fn issue_claim_with_exposure(
        &self,
        observed: Arc<GatewayExposure>,
    ) -> Result<GatewayConnectionClaim, GatewayError> {
        let snapshot = self.control.snapshot()?;
        if snapshot.lease.lifecycle != LeaseLifecycle::Active {
            return Err(GatewayError::ConnectionClaimInvalid);
        }
        let process_generation = process_generation(
            &snapshot.lease.session_id,
            &snapshot.lease.process,
            &snapshot.lease.connection_owner_id,
        );
        let mut state = self.lock_state()?;
        let role = if state.primary_epoch.is_none() {
            GatewayConnectionRole::Primary
        } else {
            GatewayConnectionRole::Auxiliary
        };
        let epoch = state.next_epoch;
        state.next_epoch = state
            .next_epoch
            .checked_add(1)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        let mut claim = GatewayConnectionClaim {
            session_id: snapshot.lease.session_id.clone(),
            owner_id: snapshot.lease.connection_owner_id.clone(),
            process_generation,
            connection_epoch: epoch,
            role,
            authentication_tag: String::new(),
        };
        claim.authentication_tag = authenticate_claim(&snapshot.lease.owner_secret_digest, &claim);
        state.connections.insert(
            epoch,
            ConnectionState {
                claim: claim.clone(),
                observed,
                pending: None,
                observation_sequence: 0,
            },
        );
        if role == GatewayConnectionRole::Primary {
            state.primary_epoch = Some(epoch);
        }
        Ok(claim)
    }

    pub(crate) fn primary_claim(&self) -> Result<Option<GatewayConnectionClaim>, GatewayError> {
        let state = self.lock_state()?;
        Ok(state
            .primary_epoch
            .and_then(|epoch| state.connections.get(&epoch))
            .map(|connection| connection.claim.clone()))
    }

    /// Disconnect a claim. A primary disconnect is a hard runtime fence: its
    /// pending exposure is discarded and the claim can never be reused. The
    /// caller decides whether to reconcile the durable lease after removing
    /// the claim.
    pub fn disconnect(&self, claim: &GatewayConnectionClaim) -> Result<(), GatewayError> {
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        if connection.claim != *claim {
            return Err(GatewayError::ConnectionClaimInvalid);
        }
        state
            .connections
            .remove(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        if state.primary_epoch == Some(claim.connection_epoch) {
            state.primary_epoch = None;
        }
        Ok(())
    }

    pub(crate) fn authorize(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        let snapshot = self.control.snapshot()?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        if connection.claim != *claim
            || claim.session_id != snapshot.lease.session_id
            || claim.owner_id != snapshot.lease.connection_owner_id
            || claim.process_generation
                != process_generation(
                    &snapshot.lease.session_id,
                    &snapshot.lease.process,
                    &snapshot.lease.connection_owner_id,
                )
            || authenticate_claim(&snapshot.lease.owner_secret_digest, claim)
                != claim.authentication_tag
        {
            return Err(GatewayError::ConnectionClaimInvalid);
        }
        // Treat a stale lease as a stale connection epoch. This prevents a
        // process restart from reviving a claim that happened to carry the
        // same numeric epoch in a newly-created in-memory registry.
        if snapshot.lease.lifecycle != LeaseLifecycle::Active {
            state.connections.remove(&claim.connection_epoch);
            if state.primary_epoch == Some(claim.connection_epoch) {
                state.primary_epoch = None;
            }
            return Err(GatewayError::ConnectionEpochStale);
        }
        Ok(status_for(
            connection,
            snapshot.lease.desired_exposure != snapshot.lease.observed_exposure
                || !snapshot.lease.admission_open
                || snapshot.lease.live_status
                    != crate::sessions::LiveExposureStatus::ObservedRefresh,
        ))
    }

    pub(crate) fn require_primary(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        let status = self.authorize(claim)?;
        if status.role != GatewayConnectionRole::Primary
            || self
                .primary_claim()?
                .as_ref()
                .is_none_or(|primary| primary.connection_epoch != claim.connection_epoch)
        {
            return Err(GatewayError::ConnectionControlOnly);
        }
        Ok(status)
    }

    pub(crate) fn status(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        self.authorize(claim)
    }

    pub(crate) fn observed(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<Arc<GatewayExposure>, GatewayError> {
        self.require_primary(claim)?;
        let state = self.lock_state()?;
        state
            .connections
            .get(&claim.connection_epoch)
            .map(|connection| Arc::clone(&connection.observed))
            .ok_or(GatewayError::ConnectionEpochStale)
    }

    pub(crate) fn stage_pending(
        &self,
        claim: &GatewayConnectionClaim,
        exposure: Arc<GatewayExposure>,
    ) -> Result<(), GatewayError> {
        self.require_primary(claim)?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get_mut(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        connection.pending = Some(exposure);
        connection.observation_sequence = connection
            .observation_sequence
            .checked_add(1)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        Ok(())
    }

    pub(crate) fn pending(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<Option<Arc<GatewayExposure>>, GatewayError> {
        self.require_primary(claim)?;
        let state = self.lock_state()?;
        Ok(state
            .connections
            .get(&claim.connection_epoch)
            .and_then(|connection| connection.pending.as_ref().map(Arc::clone)))
    }

    pub(crate) fn take_pending(
        &self,
        claim: &GatewayConnectionClaim,
        desired_revision: &str,
    ) -> Result<Option<Arc<GatewayExposure>>, GatewayError> {
        self.require_primary(claim)?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get_mut(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        if connection
            .pending
            .as_ref()
            .is_some_and(|pending| pending.pinned().revision == desired_revision)
        {
            Ok(connection.pending.take())
        } else {
            Ok(None)
        }
    }

    pub(crate) fn restore_pending(
        &self,
        claim: &GatewayConnectionClaim,
        exposure: Arc<GatewayExposure>,
    ) -> Result<(), GatewayError> {
        self.require_primary(claim)?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get_mut(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        connection.pending = Some(exposure);
        Ok(())
    }

    pub(crate) fn mark_observed(
        &self,
        claim: &GatewayConnectionClaim,
        exposure: Arc<GatewayExposure>,
    ) -> Result<(), GatewayError> {
        self.require_primary(claim)?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get_mut(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        connection.observed = exposure;
        connection.pending = None;
        connection.observation_sequence = connection
            .observation_sequence
            .checked_add(1)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        Ok(())
    }

    pub(crate) fn clear_pending(&self, claim: &GatewayConnectionClaim) -> Result<(), GatewayError> {
        self.require_primary(claim)?;
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get_mut(&claim.connection_epoch)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        connection.pending = None;
        connection.observation_sequence = connection
            .observation_sequence
            .checked_add(1)
            .ok_or(GatewayError::ConnectionEpochStale)?;
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, RegistryState>, GatewayError> {
        self.state.lock().map_err(|_| GatewayError::StatePoisoned)
    }
}

fn status_for(connection: &ConnectionState, recovery_required: bool) -> GatewayConnectionStatus {
    GatewayConnectionStatus {
        session_id: connection.claim.session_id.clone(),
        owner_id: connection.claim.owner_id.clone(),
        process_generation: connection.claim.process_generation.clone(),
        connection_epoch: connection.claim.connection_epoch,
        role: connection.claim.role,
        connected: true,
        observation_sequence: connection.observation_sequence,
        observed_exposure_revision: connection.observed.pinned().revision.clone(),
        pending_exposure_revision: connection
            .pending
            .as_ref()
            .map(|pending| pending.pinned().revision.clone()),
        recovery_required,
    }
}

fn process_generation(session_id: &str, process: &ProcessEvidence, owner_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"unpin-gateway-process-generation-v1\0");
    digest.update(session_id.as_bytes());
    digest.update([0]);
    digest.update(owner_id.as_bytes());
    digest.update([0]);
    digest.update(process.pid.to_be_bytes());
    digest.update([0]);
    digest.update(process.start_marker.as_bytes());
    format!("sha256:{}", crate::encode_lower_hex(&digest.finalize()))
}

fn authenticate_claim(secret_digest: &str, claim: &GatewayConnectionClaim) -> String {
    let mut mac = ClaimMac::new_from_slice(secret_digest.as_bytes())
        .expect("HMAC accepts a non-empty lease secret digest");
    mac.update(CLAIM_PURPOSE);
    mac.update(claim.session_id.as_bytes());
    mac.update(&[0]);
    mac.update(claim.owner_id.as_bytes());
    mac.update(&[0]);
    mac.update(claim.process_generation.as_bytes());
    mac.update(&[0]);
    mac.update(&claim.connection_epoch.to_be_bytes());
    mac.update(&[0]);
    mac.update(match claim.role {
        GatewayConnectionRole::Primary => b"primary" as &[u8],
        GatewayConnectionRole::Auxiliary => b"auxiliary" as &[u8],
    });
    format!(
        "sha256:{}",
        crate::encode_lower_hex(&mac.finalize().into_bytes())
    )
}
