use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    config::get_gateway_mode_path,
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateRevision},
};

use super::{
    lease::{SessionLease, digest_bytes, validate_identifier},
    manager::{LeaseError, SessionManager},
};

pub(crate) const GATEWAY_MODE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayModeTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
}

impl GatewayModeTarget {
    pub fn global_provider(provider: ProviderId) -> Self {
        Self {
            repository_key: None,
            workspace_key: None,
            provider: Some(provider),
        }
    }

    pub fn repository(repository_key: impl Into<String>) -> Result<Self, LeaseError> {
        let target = Self {
            repository_key: Some(repository_key.into()),
            workspace_key: None,
            provider: None,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn repository_provider(
        repository_key: impl Into<String>,
        provider: ProviderId,
    ) -> Result<Self, LeaseError> {
        let target = Self {
            repository_key: Some(repository_key.into()),
            workspace_key: None,
            provider: Some(provider),
        };
        target.validate()?;
        Ok(target)
    }

    pub fn workspace_provider(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        provider: ProviderId,
    ) -> Result<Self, LeaseError> {
        let target = Self {
            repository_key: Some(repository_key.into()),
            workspace_key: Some(workspace_key.into()),
            provider: Some(provider),
        };
        target.validate()?;
        Ok(target)
    }

    pub fn workspace(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
    ) -> Result<Self, LeaseError> {
        let target = Self {
            repository_key: Some(repository_key.into()),
            workspace_key: Some(workspace_key.into()),
            provider: None,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn global() -> Self {
        Self {
            repository_key: None,
            workspace_key: None,
            provider: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), LeaseError> {
        if let Some(repository_key) = &self.repository_key {
            validate_identifier("gateway repository key", repository_key)
                .map_err(LeaseError::from)?;
        }
        if let Some(workspace_key) = &self.workspace_key {
            validate_identifier("gateway workspace key", workspace_key)
                .map_err(LeaseError::from)?;
            if self.repository_key.is_none() {
                return Err(LeaseError::InvalidState(
                    "workspace gateway target requires repository key".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, lease: &SessionLease) -> bool {
        self.matches_binding(lease.provider, &lease.repository_key, &lease.workspace_key)
    }

    pub(crate) fn matches_binding(
        &self,
        provider: ProviderId,
        repository_key: &str,
        workspace_key: &str,
    ) -> bool {
        self.repository_key
            .as_ref()
            .is_none_or(|key| key == repository_key)
            && self
                .workspace_key
                .as_ref()
                .is_none_or(|key| key == workspace_key)
            && self.provider.is_none_or(|expected| expected == provider)
    }

    pub(crate) const fn specificity(&self) -> u8 {
        (self.repository_key.is_some() as u8) * 2
            + (self.workspace_key.is_some() as u8) * 4
            + (self.provider.is_some() as u8)
    }

    pub(crate) fn key(&self) -> Result<String, LeaseError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|bytes| digest_bytes(&bytes))
            .map_err(|error| LeaseError::InvalidState(error.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayInstallState {
    Detached,
    Installed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayRoutingState {
    Off,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceMode {
    No,
    Yes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayModeState {
    pub target: GatewayModeTarget,
    pub installation: GatewayInstallState,
    pub routing: GatewayRoutingState,
    pub admission_open: bool,
    pub changed_at_unix: i64,
    pub changed_by: String,
    integrity_digest: String,
}

impl GatewayModeState {
    fn new(target: GatewayModeTarget, actor_id: &str, now_unix: i64) -> Result<Self, LeaseError> {
        let mut state = Self {
            target,
            installation: GatewayInstallState::Detached,
            routing: GatewayRoutingState::Off,
            admission_open: false,
            changed_at_unix: now_unix,
            changed_by: actor_id.to_string(),
            integrity_digest: String::new(),
        };
        state.seal()?;
        Ok(state)
    }

    fn seal(&mut self) -> Result<(), LeaseError> {
        self.validate_shape()?;
        self.integrity_digest = self.calculate_integrity()?;
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<(), LeaseError> {
        self.validate_shape()?;
        let actual = self.calculate_integrity()?;
        if actual == self.integrity_digest {
            Ok(())
        } else {
            Err(LeaseError::IntegrityMismatch)
        }
    }

    fn validate_shape(&self) -> Result<(), LeaseError> {
        self.target.validate()?;
        validate_identifier("gateway mode actor", &self.changed_by).map_err(LeaseError::from)?;
        if self.installation == GatewayInstallState::Detached
            && self.routing != GatewayRoutingState::Off
        {
            return Err(LeaseError::InvalidState(
                "detached gateway cannot route sessions".to_string(),
            ));
        }
        if self.routing == GatewayRoutingState::Off && self.admission_open {
            return Err(LeaseError::InvalidState(
                "gateway admission cannot stay open while routing is off".to_string(),
            ));
        }
        if self.installation == GatewayInstallState::Detached && self.admission_open {
            return Err(LeaseError::InvalidState(
                "detached gateway cannot admit sessions".to_string(),
            ));
        }
        Ok(())
    }

    fn calculate_integrity(&self) -> Result<String, LeaseError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct IntegrityBody<'a> {
            target: &'a GatewayModeTarget,
            installation: GatewayInstallState,
            routing: GatewayRoutingState,
            admission_open: bool,
            changed_at_unix: i64,
            changed_by: &'a str,
        }
        serde_json::to_vec(&IntegrityBody {
            target: &self.target,
            installation: self.installation,
            routing: self.routing,
            admission_open: self.admission_open,
            changed_at_unix: self.changed_at_unix,
            changed_by: &self.changed_by,
        })
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|error| LeaseError::InvalidState(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayModeSnapshot {
    pub revision: StateRevision,
    pub mode: GatewayModeState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayModeOutcome {
    pub mode: GatewayModeState,
    pub draining_sessions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GatewayModeManager {
    app_state_root: PathBuf,
    sessions: SessionManager,
}

impl GatewayModeManager {
    pub fn new(app_state_root: impl Into<PathBuf>, sessions: SessionManager) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            sessions,
        }
    }

    pub fn load(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<Option<GatewayModeSnapshot>, LeaseError> {
        let store = self.store(target)?;
        let snapshot = store.load::<GatewayModeState>()?;
        snapshot
            .map(|snapshot| {
                snapshot.value.verify()?;
                if &snapshot.value.target != target {
                    return Err(LeaseError::InvalidState(
                        "gateway mode target does not match state path".to_string(),
                    ));
                }
                Ok(GatewayModeSnapshot {
                    revision: snapshot.revision,
                    mode: snapshot.value,
                })
            })
            .transpose()
    }

    pub fn install(
        &self,
        target: GatewayModeTarget,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeSnapshot, LeaseError> {
        let _registry = self.sessions.registry_lock()?;
        self.update(target, actor_id, now_unix, |state| {
            state.installation = GatewayInstallState::Installed;
            state.routing = GatewayRoutingState::Off;
            state.admission_open = false;
            Ok(())
        })
    }

    pub fn activate(
        &self,
        target: GatewayModeTarget,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeSnapshot, LeaseError> {
        let _registry = self.sessions.registry_lock()?;
        self.update(target, actor_id, now_unix, |state| {
            if state.installation != GatewayInstallState::Installed {
                return Err(LeaseError::GatewayNotInstalled);
            }
            state.routing = GatewayRoutingState::Active;
            state.admission_open = true;
            Ok(())
        })
    }

    pub fn turn_off(
        &self,
        target: GatewayModeTarget,
        force: ForceMode,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeOutcome, LeaseError> {
        target.validate()?;
        validate_identifier("gateway mode actor", actor_id).map_err(LeaseError::from)?;
        self.sessions.reconcile_stale(now_unix)?;
        let _registry = self.sessions.registry_lock()?;
        self.turn_off_unlocked(target, force, actor_id, now_unix)
    }

    fn turn_off_unlocked(
        &self,
        target: GatewayModeTarget,
        force: ForceMode,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeOutcome, LeaseError> {
        let matching = self
            .sessions
            .list_unlocked()?
            .into_iter()
            .filter(|lease| {
                target.matches(&lease.lease)
                    && lease
                        .lease
                        .desired_exposure
                        .profile
                        .requires_gateway_routing()
                    && lease.lease.lifecycle.contributes_active_intent()
            })
            .collect::<Vec<_>>();
        if force == ForceMode::No && !matching.is_empty() {
            return Err(LeaseError::ActiveLeases {
                session_ids: matching
                    .iter()
                    .map(|lease| lease.lease.session_id.clone())
                    .collect(),
            });
        }

        let mut fenced = self.update(target.clone(), actor_id, now_unix, |state| {
            state.admission_open = false;
            if matching.is_empty() {
                state.routing = GatewayRoutingState::Off;
            }
            Ok(())
        })?;

        let mut draining = Vec::new();
        if force == ForceMode::Yes {
            for lease in matching {
                let revoked = if lease.lease.lifecycle == super::lease::LeaseLifecycle::Active {
                    self.sessions
                        .begin_revoke_unlocked(lease, actor_id, now_unix)?
                } else {
                    lease
                };
                if !self
                    .sessions
                    .remove_drained_unlocked(revoked.clone(), actor_id, now_unix)?
                {
                    draining.push(revoked.lease.session_id);
                }
            }
        }
        draining.sort();

        if draining.is_empty() && fenced.mode.routing != GatewayRoutingState::Off {
            fenced = self.update(target, actor_id, now_unix, |state| {
                state.routing = GatewayRoutingState::Off;
                state.admission_open = false;
                Ok(())
            })?;
        }
        Ok(GatewayModeOutcome {
            mode: fenced.mode,
            draining_sessions: draining,
        })
    }

    pub fn detach(
        &self,
        target: GatewayModeTarget,
        force: ForceMode,
        actor_id: &str,
        now_unix: i64,
    ) -> Result<GatewayModeOutcome, LeaseError> {
        target.validate()?;
        validate_identifier("gateway mode actor", actor_id).map_err(LeaseError::from)?;
        self.sessions.reconcile_stale(now_unix)?;
        let _registry = self.sessions.registry_lock()?;
        let off = self.turn_off_unlocked(target.clone(), force, actor_id, now_unix)?;
        if !off.draining_sessions.is_empty() || off.mode.routing != GatewayRoutingState::Off {
            return Err(LeaseError::GatewayMustBeOff);
        }
        let snapshot = self.update(target, actor_id, now_unix, |state| {
            state.routing = GatewayRoutingState::Off;
            state.installation = GatewayInstallState::Detached;
            state.admission_open = false;
            Ok(())
        })?;
        Ok(GatewayModeOutcome {
            mode: snapshot.mode,
            draining_sessions: Vec::new(),
        })
    }

    fn update<F>(
        &self,
        target: GatewayModeTarget,
        actor_id: &str,
        now_unix: i64,
        mutation: F,
    ) -> Result<GatewayModeSnapshot, LeaseError>
    where
        F: FnOnce(&mut GatewayModeState) -> Result<(), LeaseError>,
    {
        target.validate()?;
        validate_identifier("gateway mode actor", actor_id).map_err(LeaseError::from)?;
        let store = self.store(&target)?;
        let current = store.load::<GatewayModeState>()?;
        let (expected, owner_generation, mut state) = match current {
            Some(snapshot) => {
                snapshot.value.verify()?;
                if snapshot.value.target != target {
                    return Err(LeaseError::InvalidState(
                        "gateway mode target does not match state path".to_string(),
                    ));
                }
                let generation = snapshot
                    .owner
                    .generation
                    .checked_add(1)
                    .ok_or(LeaseError::OwnerGenerationOverflow)?;
                (Some(snapshot.revision), generation, snapshot.value)
            }
            None => (None, 1, GatewayModeState::new(target, actor_id, now_unix)?),
        };
        mutation(&mut state)?;
        state.changed_at_unix = now_unix;
        state.changed_by = actor_id.to_string();
        state.seal()?;
        let revision = store.compare_and_swap(
            expected.as_ref(),
            OwnerGeneration::new(actor_id, owner_generation)?,
            &state,
        )?;
        Ok(GatewayModeSnapshot {
            revision,
            mode: state,
        })
    }

    fn store(&self, target: &GatewayModeTarget) -> Result<AtomicJsonStore, LeaseError> {
        Ok(AtomicJsonStore::new(
            get_gateway_mode_path(&self.app_state_root, &target.key()?),
            GATEWAY_MODE_SCHEMA_VERSION,
        ))
    }
}

impl fmt::Display for GatewayModeTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "gateway-mode:{}",
            self.key().unwrap_or_else(|_| "invalid".into())
        )
    }
}
