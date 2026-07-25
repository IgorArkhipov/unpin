use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    catalog::CapabilityId,
    profiles::{
        CapabilityLockError, CapabilityLockSnapshot, CapabilityLockState, CompiledProfileRevision,
        ProfileSourceScope, ProfileValidationError,
    },
    providers::ProviderId,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileReference {
    pub profile_id: String,
    pub digest: String,
    pub origin_scope: ProfileSourceScope,
}

impl From<&CompiledProfileRevision> for ProfileReference {
    fn from(revision: &CompiledProfileRevision) -> Self {
        Self {
            profile_id: revision.profile_id.clone(),
            digest: revision.digest.clone(),
            origin_scope: revision.origin.scope,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProfileSelection {
    #[default]
    Inherit,
    Native,
    None,
    Profile {
        reference: ProfileReference,
    },
}

impl ProfileSelection {
    #[must_use]
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewaySelection {
    #[default]
    Inherit,
    Native,
    Gateway,
}

impl GatewaySelection {
    #[must_use]
    pub const fn is_inherit(self) -> bool {
        matches!(self, Self::Inherit)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPolicy {
    #[serde(default)]
    pub profile: ProfileSelection,
    #[serde(default)]
    pub gateway: GatewaySelection,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capability_locks: BTreeMap<CapabilityId, CapabilityLockState>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopePolicy {
    #[serde(default)]
    pub profile: ProfileSelection,
    #[serde(default)]
    pub gateway: GatewaySelection,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<ProviderId, ProviderPolicy>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolutionPolicies {
    pub global: ScopePolicy,
    pub repository: Option<ScopePolicy>,
    pub workspace: Option<ScopePolicy>,
    /// Connection-local input. Resolver never persists or shares this value.
    pub session: Option<ScopePolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyScope {
    Session,
    Workspace,
    Repository,
    Global,
    NativeDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolutionSource {
    pub scope: PolicyScope,
    pub provider_specific: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedProfileSelection {
    Native,
    None,
    Profile(CompiledProfileRevision),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolvedGatewayMode {
    Native,
    Gateway,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub provider: ProviderId,
    pub profile: ResolvedProfileSelection,
    pub profile_source: ResolutionSource,
    pub gateway: ResolvedGatewayMode,
    pub gateway_source: ResolutionSource,
    pub capability_locks: CapabilityLockSnapshot,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileRevisionSet {
    revisions: BTreeMap<String, CompiledProfileRevision>,
}

impl ProfileRevisionSet {
    pub fn insert(
        &mut self,
        revision: CompiledProfileRevision,
    ) -> Result<(), PolicyResolutionError> {
        revision.verify_digest()?;
        if let Some(existing) = self.revisions.get(&revision.digest) {
            if existing != &revision {
                return Err(PolicyResolutionError::RevisionCollision {
                    digest: revision.digest,
                });
            }
            return Ok(());
        }
        self.revisions.insert(revision.digest.clone(), revision);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, digest: &str) -> Option<&CompiledProfileRevision> {
        self.revisions.get(digest)
    }
}

pub fn resolve_effective_policy(
    provider: ProviderId,
    policies: &ResolutionPolicies,
    revisions: &ProfileRevisionSet,
) -> Result<EffectivePolicy, PolicyResolutionError> {
    let profile_candidate = ordered_scopes(policies)
        .find_map(|(scope, policy)| explicit_profile(policy, provider).map(|value| (scope, value)))
        .unwrap_or((
            PolicyScope::NativeDefault,
            (false, &ProfileSelection::Native),
        ));
    let (profile_scope, (profile_provider_specific, profile_selection)) = profile_candidate;
    let profile = resolve_profile_selection(provider, profile_scope, profile_selection, revisions)?;

    let (gateway, gateway_source) = resolve_effective_gateway(provider, policies);
    let capability_locks = CapabilityLockSnapshot::compile(
        provider,
        policies
            .global
            .providers
            .get(&provider)
            .map(|policy| policy.capability_locks.clone())
            .unwrap_or_default(),
    )?;

    Ok(EffectivePolicy {
        provider,
        profile,
        profile_source: ResolutionSource {
            scope: profile_scope,
            provider_specific: profile_provider_specific,
        },
        gateway,
        gateway_source,
        capability_locks,
    })
}

#[must_use]
pub fn resolve_effective_gateway(
    provider: ProviderId,
    policies: &ResolutionPolicies,
) -> (ResolvedGatewayMode, ResolutionSource) {
    let (scope, (provider_specific, selection)) = ordered_scopes(policies)
        .find_map(|(scope, policy)| explicit_gateway(policy, provider).map(|value| (scope, value)))
        .unwrap_or((
            PolicyScope::NativeDefault,
            (false, GatewaySelection::Native),
        ));
    let gateway = match selection {
        GatewaySelection::Native => ResolvedGatewayMode::Native,
        GatewaySelection::Gateway => ResolvedGatewayMode::Gateway,
        GatewaySelection::Inherit => unreachable!("inherit candidates are skipped"),
    };
    (
        gateway,
        ResolutionSource {
            scope,
            provider_specific,
        },
    )
}

fn ordered_scopes(
    policies: &ResolutionPolicies,
) -> impl Iterator<Item = (PolicyScope, &ScopePolicy)> {
    [
        policies
            .session
            .as_ref()
            .map(|policy| (PolicyScope::Session, policy)),
        policies
            .workspace
            .as_ref()
            .map(|policy| (PolicyScope::Workspace, policy)),
        policies
            .repository
            .as_ref()
            .map(|policy| (PolicyScope::Repository, policy)),
        Some((PolicyScope::Global, &policies.global)),
    ]
    .into_iter()
    .flatten()
}

fn explicit_profile(
    policy: &ScopePolicy,
    provider: ProviderId,
) -> Option<(bool, &ProfileSelection)> {
    if let Some(provider_policy) = policy.providers.get(&provider)
        && !provider_policy.profile.is_inherit()
    {
        return Some((true, &provider_policy.profile));
    }
    (!policy.profile.is_inherit()).then_some((false, &policy.profile))
}

fn explicit_gateway(
    policy: &ScopePolicy,
    provider: ProviderId,
) -> Option<(bool, GatewaySelection)> {
    if let Some(provider_policy) = policy.providers.get(&provider)
        && !provider_policy.gateway.is_inherit()
    {
        return Some((true, provider_policy.gateway));
    }
    (!policy.gateway.is_inherit()).then_some((false, policy.gateway))
}

fn resolve_profile_selection(
    provider: ProviderId,
    policy_scope: PolicyScope,
    selection: &ProfileSelection,
    revisions: &ProfileRevisionSet,
) -> Result<ResolvedProfileSelection, PolicyResolutionError> {
    match selection {
        ProfileSelection::Inherit => unreachable!("inherit candidates are skipped"),
        ProfileSelection::Native => Ok(ResolvedProfileSelection::Native),
        ProfileSelection::None => Ok(ResolvedProfileSelection::None),
        ProfileSelection::Profile { reference } => {
            let revision = revisions.get(&reference.digest).ok_or_else(|| {
                PolicyResolutionError::MissingRevision {
                    digest: reference.digest.clone(),
                }
            })?;
            if revision.profile_id != reference.profile_id {
                return Err(PolicyResolutionError::ProfileIdMismatch {
                    expected: reference.profile_id.clone(),
                    actual: revision.profile_id.clone(),
                });
            }
            if revision.origin.scope != reference.origin_scope {
                return Err(PolicyResolutionError::OriginMismatch {
                    expected: reference.origin_scope,
                    actual: revision.origin.scope,
                });
            }
            validate_origin_for_policy(policy_scope, revision.origin.scope)?;
            revision.verify_digest()?;
            if !revision.members.is_empty() && !revision.supports_provider(provider) {
                return Err(PolicyResolutionError::ProfileUnavailableForProvider {
                    profile_id: revision.profile_id.clone(),
                    provider,
                });
            }
            Ok(ResolvedProfileSelection::Profile(revision.clone()))
        }
    }
}

fn validate_origin_for_policy(
    policy_scope: PolicyScope,
    origin_scope: ProfileSourceScope,
) -> Result<(), PolicyResolutionError> {
    let allowed = match policy_scope {
        PolicyScope::Global | PolicyScope::Repository => origin_scope == ProfileSourceScope::Global,
        PolicyScope::Workspace => matches!(
            origin_scope,
            ProfileSourceScope::Global | ProfileSourceScope::Workspace
        ),
        PolicyScope::Session => true,
        PolicyScope::NativeDefault => true,
    };
    if allowed {
        Ok(())
    } else {
        Err(PolicyResolutionError::InvalidOriginForPolicy {
            policy_scope,
            origin_scope,
        })
    }
}

#[derive(Debug)]
pub enum PolicyResolutionError {
    Profile(ProfileValidationError),
    CapabilityLocks(CapabilityLockError),
    MissingRevision {
        digest: String,
    },
    RevisionCollision {
        digest: String,
    },
    ProfileIdMismatch {
        expected: String,
        actual: String,
    },
    OriginMismatch {
        expected: ProfileSourceScope,
        actual: ProfileSourceScope,
    },
    InvalidOriginForPolicy {
        policy_scope: PolicyScope,
        origin_scope: ProfileSourceScope,
    },
    ProfileUnavailableForProvider {
        profile_id: String,
        provider: ProviderId,
    },
}

impl From<ProfileValidationError> for PolicyResolutionError {
    fn from(error: ProfileValidationError) -> Self {
        Self::Profile(error)
    }
}

impl From<CapabilityLockError> for PolicyResolutionError {
    fn from(error: CapabilityLockError) -> Self {
        Self::CapabilityLocks(error)
    }
}

impl fmt::Display for PolicyResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => error.fmt(formatter),
            Self::CapabilityLocks(error) => error.fmt(formatter),
            Self::MissingRevision { digest } => {
                write!(formatter, "compiled profile revision is missing: {digest}")
            }
            Self::RevisionCollision { digest } => {
                write!(formatter, "compiled profile revision collision: {digest}")
            }
            Self::ProfileIdMismatch { expected, actual } => write!(
                formatter,
                "profile reference id mismatch: expected {expected}, found {actual}"
            ),
            Self::OriginMismatch { expected, actual } => write!(
                formatter,
                "profile reference origin mismatch: expected {expected:?}, found {actual:?}"
            ),
            Self::InvalidOriginForPolicy {
                policy_scope,
                origin_scope,
            } => write!(
                formatter,
                "{policy_scope:?} policy cannot reference {origin_scope:?} profile origin"
            ),
            Self::ProfileUnavailableForProvider {
                profile_id,
                provider,
            } => write!(
                formatter,
                "profile {profile_id} has no {} capability view",
                provider.as_str()
            ),
        }
    }
}

impl std::error::Error for PolicyResolutionError {}
