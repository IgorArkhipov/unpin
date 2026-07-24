use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    catalog::{CapabilityId, CapabilityKind, CapabilityMutability, Catalog},
    profiles::{EffectivePolicy, PolicyScope, ResolvedGatewayMode, ResolvedProfileSelection},
    providers::ProviderId,
};

pub const CAPABILITY_LOCK_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityLockState {
    HardEnabled,
    HardDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementKind {
    NativeStrict,
    NativeBestEffort,
    GatewayStrict,
    ReadOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationRequirement {
    Immediate,
    ReloadRequired,
    NextSessionOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityLockEnforcement {
    pub provider: ProviderId,
    pub capability_id: CapabilityId,
    pub state: CapabilityLockState,
    pub source: PolicyScope,
    pub enforcement: EnforcementKind,
    pub activation: ActivationRequirement,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityLockSnapshot {
    pub schema_version: u32,
    pub provider: ProviderId,
    pub digest: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<CapabilityId, CapabilityLockState>,
}

impl CapabilityLockSnapshot {
    pub fn compile(
        provider: ProviderId,
        entries: BTreeMap<CapabilityId, CapabilityLockState>,
    ) -> Result<Self, CapabilityLockError> {
        let digest = lock_digest(CAPABILITY_LOCK_SNAPSHOT_SCHEMA_VERSION, provider, &entries)?;
        Ok(Self {
            schema_version: CAPABILITY_LOCK_SNAPSHOT_SCHEMA_VERSION,
            provider,
            digest,
            entries,
        })
    }

    pub fn empty(provider: ProviderId) -> Self {
        Self::compile(provider, BTreeMap::new())
            .expect("empty capability lock snapshot serialization is infallible")
    }

    pub fn verify(&self) -> Result<(), CapabilityLockError> {
        if self.schema_version != CAPABILITY_LOCK_SNAPSHOT_SCHEMA_VERSION {
            return Err(CapabilityLockError::UnsupportedSchema {
                actual: self.schema_version,
            });
        }
        let actual = lock_digest(self.schema_version, self.provider, &self.entries)?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(CapabilityLockError::DigestMismatch {
                expected: self.digest.clone(),
                actual,
            })
        }
    }
}

#[must_use]
pub fn capability_lock_enforcement(
    snapshot: &CapabilityLockSnapshot,
    catalog: &Catalog,
    gateway: ResolvedGatewayMode,
) -> Vec<CapabilityLockEnforcement> {
    snapshot
        .entries
        .iter()
        .map(|(capability_id, state)| {
            let (enforcement, reason) = match catalog.get(capability_id) {
                None => (
                    EnforcementKind::Unsupported,
                    "capability is not present in the current catalog",
                ),
                Some(record) => match record
                    .provider_views
                    .iter()
                    .find(|view| view.provider == snapshot.provider)
                {
                    None => (
                        EnforcementKind::Unsupported,
                        "capability has no view for this provider",
                    ),
                    Some(view) if view.mutability == CapabilityMutability::Unsupported => (
                        EnforcementKind::Unsupported,
                        "provider reports this capability as unsupported",
                    ),
                    Some(view) if view.mutability == CapabilityMutability::ReadOnly => (
                        EnforcementKind::ReadOnly,
                        "provider view is read-only; policy is reported but cannot be mutated",
                    ),
                    Some(_)
                        if gateway == ResolvedGatewayMode::Gateway
                            && matches!(
                                record.kind,
                                CapabilityKind::Skill
                                    | CapabilityKind::McpTool
                                    | CapabilityKind::Hook
                            ) =>
                    {
                        (
                            EnforcementKind::GatewayStrict,
                            "Unpin gateway filters the pinned session exposure",
                        )
                    }
                    Some(_) => (
                        EnforcementKind::NativeBestEffort,
                        "provider-native configuration cannot guarantee live strict enforcement",
                    ),
                },
            };
            CapabilityLockEnforcement {
                provider: snapshot.provider,
                capability_id: capability_id.clone(),
                state: *state,
                source: PolicyScope::Global,
                enforcement,
                activation: ActivationRequirement::NextSessionOnly,
                reason: reason.to_string(),
            }
        })
        .collect()
}

pub fn resolve_effective_capabilities(
    policy: &EffectivePolicy,
    catalog: &Catalog,
) -> Result<BTreeSet<CapabilityId>, CapabilityLockError> {
    policy.capability_locks.verify()?;
    if policy.capability_locks.provider != policy.provider {
        return Err(CapabilityLockError::ProviderMismatch {
            expected: policy.provider,
            actual: policy.capability_locks.provider,
        });
    }

    let mut selected = match &policy.profile {
        ResolvedProfileSelection::Native => catalog
            .records
            .values()
            .filter(|record| {
                record.provider_views.iter().any(|view| {
                    view.provider == policy.provider && view.enabled && record.lifecycle.active
                })
            })
            .map(|record| record.id.clone())
            .collect(),
        ResolvedProfileSelection::None => BTreeSet::new(),
        ResolvedProfileSelection::Profile(profile) => {
            let mut selected = BTreeSet::new();
            for member in profile.members_for_provider(policy.provider) {
                let record = catalog.get(&member.capability_id).ok_or_else(|| {
                    CapabilityLockError::MissingCapability {
                        capability_id: member.capability_id.clone(),
                    }
                })?;
                if record.fingerprint != member.capability_fingerprint
                    || record.origin.canonical_key != member.catalog_origin_key
                    || !record.supports_provider(policy.provider)
                {
                    return Err(CapabilityLockError::StaleProfileCapability {
                        capability_id: member.capability_id.clone(),
                    });
                }
                selected.insert(member.capability_id.clone());
            }
            selected
        }
    };

    for (capability_id, state) in &policy.capability_locks.entries {
        let record =
            catalog
                .get(capability_id)
                .ok_or_else(|| CapabilityLockError::MissingCapability {
                    capability_id: capability_id.clone(),
                })?;
        if !record.supports_provider(policy.provider) {
            return Err(CapabilityLockError::UnsupportedProvider {
                capability_id: capability_id.clone(),
                provider: policy.provider,
            });
        }
        match state {
            CapabilityLockState::HardEnabled => {
                selected.insert(capability_id.clone());
            }
            CapabilityLockState::HardDisabled => {
                selected.remove(capability_id);
            }
        }
    }

    Ok(selected)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityLockDigestBody<'a> {
    schema_version: u32,
    provider: ProviderId,
    entries: &'a BTreeMap<CapabilityId, CapabilityLockState>,
}

fn lock_digest(
    schema_version: u32,
    provider: ProviderId,
    entries: &BTreeMap<CapabilityId, CapabilityLockState>,
) -> Result<String, CapabilityLockError> {
    let bytes = serde_json::to_vec(&CapabilityLockDigestBody {
        schema_version,
        provider,
        entries,
    })
    .map_err(|error| CapabilityLockError::Serialization {
        message: error.to_string(),
    })?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityLockError {
    Serialization {
        message: String,
    },
    UnsupportedSchema {
        actual: u32,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
    ProviderMismatch {
        expected: ProviderId,
        actual: ProviderId,
    },
    MissingCapability {
        capability_id: CapabilityId,
    },
    StaleProfileCapability {
        capability_id: CapabilityId,
    },
    UnsupportedProvider {
        capability_id: CapabilityId,
        provider: ProviderId,
    },
}

impl fmt::Display for CapabilityLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization { message } => {
                write!(formatter, "capability lock serialization failed: {message}")
            }
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported capability lock schema: {actual}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "capability lock digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ProviderMismatch { expected, actual } => write!(
                formatter,
                "capability lock provider mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::MissingCapability { capability_id } => {
                write!(formatter, "locked capability is missing: {capability_id}")
            }
            Self::StaleProfileCapability { capability_id } => {
                write!(formatter, "profile capability is stale: {capability_id}")
            }
            Self::UnsupportedProvider {
                capability_id,
                provider,
            } => write!(
                formatter,
                "capability {capability_id} does not support provider {}",
                provider.as_str()
            ),
        }
    }
}

impl std::error::Error for CapabilityLockError {}
