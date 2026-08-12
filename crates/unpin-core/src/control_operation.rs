use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    approval::{ApprovalExpectation, ControlAuthorization},
    provider_reach::{
        ConnectionBoundary, ProviderReach, ProviderReachCoverage, ProviderReachLifecycle,
        SelectedProviderAuthority,
    },
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::{OwnerGeneration, StateRevision},
    transitions::{
        EffectActivation, JournalError, JournalHandle, TransitionJournalStore, TransitionLifecycle,
        TransitionPlan, journal::MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES,
    },
};

pub const CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION: u32 = 1;
/// Reach-aware mutation records intentionally use a separate schema so the
/// long-lived v1 control envelope and read-only projections remain unchanged.
pub const REACH_AWARE_CONTROL_OPERATION_SCHEMA_VERSION: u32 = 2;
pub const CONTROL_OPERATION_REACH_AWARE_SCHEMA_VERSION: u32 =
    REACH_AWARE_CONTROL_OPERATION_SCHEMA_VERSION;

/// Operation families own their payload schemas.  The shared reach-aware
/// envelope only carries this typed reference and its digest; family payloads
/// never get copied into the shared control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReachAwareOperationFamily {
    NativeToggle,
    BulkToggle,
    GroupToggle,
    Profile,
    Gateway,
    Session,
    Restore,
}

impl ReachAwareOperationFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeToggle => "native-toggle",
            Self::BulkToggle => "bulk-toggle",
            Self::GroupToggle => "group-toggle",
            Self::Profile => "profile",
            Self::Gateway => "gateway",
            Self::Session => "session",
            Self::Restore => "restore",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwarePayloadReference {
    pub family: ReachAwareOperationFamily,
    pub schema_version: u32,
    pub reference: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareJournalBinding {
    pub owner: OwnerGeneration,
    pub revision: StateRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOperationLifecycle {
    Planned,
    AwaitingHumanAction,
    Applied,
    NoOp,
    Blocked,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlResolvedContext {
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlHumanAction {
    pub code: String,
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlOperationEnvelope {
    pub schema_version: u32,
    pub operation_id: String,
    pub operation_kind: String,
    pub plan_fingerprint: String,
    pub context: ControlResolvedContext,
    pub lifecycle: ControlOperationLifecycle,
    pub activation: EffectActivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_action: Option<ControlHumanAction>,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_coverage: Vec<ProviderId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

impl ControlOperationEnvelope {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        operation_id: impl Into<String>,
        operation_kind: impl Into<String>,
        plan_fingerprint: impl Into<String>,
        context: ControlResolvedContext,
        lifecycle: ControlOperationLifecycle,
        activation: EffectActivation,
        human_action: Option<ControlHumanAction>,
        retryable: bool,
        mut provider_coverage: Vec<ProviderId>,
        details: Value,
    ) -> Self {
        provider_coverage.sort();
        provider_coverage.dedup();
        Self {
            schema_version: CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            operation_kind: operation_kind.into(),
            plan_fingerprint: plan_fingerprint.into(),
            context,
            lifecycle,
            activation,
            human_action,
            retryable,
            provider_coverage,
            details,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_expectation(
        expectation: &ApprovalExpectation,
        plan_fingerprint: impl Into<String>,
        activation: EffectActivation,
        lifecycle: ControlOperationLifecycle,
        human_action: Option<ControlHumanAction>,
        retryable: bool,
        provider_coverage: Vec<ProviderId>,
        details: Value,
    ) -> Self {
        Self::new(
            expectation.operation_id.clone(),
            expectation.operation_kind.clone(),
            plan_fingerprint,
            ControlResolvedContext {
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
            },
            lifecycle,
            activation,
            human_action,
            retryable,
            provider_coverage,
            details,
        )
    }
}

/// Sanitized roots sealed into a reach-aware operation. Roots are canonical
/// strings only; provider payloads and repository-owned redirect settings are
/// never persisted in this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareRootBinding {
    pub app_state_root: String,
    pub provider_roots: Vec<ReachAwareProviderRoot>,
    pub provenance: String,
}

/// Which trusted discovery-root slot an authenticated provider root restores.
///
/// Most reach-aware operations have one primary root per provider. Agent
/// Plugins can also mutate Claude project activation state, so their sealed
/// handoffs bind that independent project root explicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReachAwareRootScope {
    #[default]
    Primary,
    Project,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareProviderRoot {
    pub provider: ProviderId,
    #[serde(default)]
    pub scope: ReachAwareRootScope,
    pub root: String,
    pub provenance: String,
}

impl ReachAwareRootBinding {
    pub fn from_provider_paths(
        app_state_root: impl AsRef<Path>,
        provider_roots: Vec<(ProviderId, PathBuf, String)>,
        provenance: impl Into<String>,
    ) -> Result<Self, ReachAwareEnvelopeError> {
        Self::from_scoped_provider_paths(
            app_state_root,
            provider_roots
                .into_iter()
                .map(|(provider, root, provider_provenance)| {
                    (
                        provider,
                        ReachAwareRootScope::Primary,
                        root,
                        provider_provenance,
                    )
                })
                .collect(),
            provenance,
        )
    }

    pub fn from_scoped_provider_paths(
        app_state_root: impl AsRef<Path>,
        provider_roots: Vec<(ProviderId, ReachAwareRootScope, PathBuf, String)>,
        provenance: impl Into<String>,
    ) -> Result<Self, ReachAwareEnvelopeError> {
        let app_state_root = canonical_root(app_state_root.as_ref())?;
        let provenance = provenance.into();
        validate_safe_text(&provenance, "root provenance")?;
        let mut normalized = provider_roots
            .into_iter()
            .map(|(provider, scope, root, provider_provenance)| {
                let provider_provenance = {
                    validate_safe_text(&provider_provenance, "provider root provenance")?;
                    provider_provenance
                };
                Ok(ReachAwareProviderRoot {
                    provider,
                    scope,
                    root: canonical_root(&root)?,
                    provenance: provider_provenance,
                })
            })
            .collect::<Result<Vec<_>, ReachAwareEnvelopeError>>()?;
        normalized.sort_by_key(|entry| (entry.provider, entry.scope));
        if normalized
            .windows(2)
            .any(|pair| pair[0].provider == pair[1].provider && pair[0].scope == pair[1].scope)
        {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        Ok(Self {
            app_state_root,
            provider_roots: normalized,
            provenance,
        })
    }

    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            app_state_root: redact_path(&self.app_state_root),
            provider_roots: self
                .provider_roots
                .iter()
                .map(|entry| ReachAwareProviderRoot {
                    provider: entry.provider,
                    scope: entry.scope,
                    root: redact_path(&entry.root),
                    provenance: entry.provenance.clone(),
                })
                .collect(),
            provenance: self.provenance.clone(),
        }
    }

    pub fn verify(&self) -> Result<(), ReachAwareEnvelopeError> {
        if self.app_state_root.is_empty()
            || !Path::new(&self.app_state_root).is_absolute()
            || self.provenance.is_empty()
            || self.provenance == "unbound"
            || self
                .provider_roots
                .windows(2)
                .any(|pair| (pair[0].provider, pair[0].scope) >= (pair[1].provider, pair[1].scope))
            || self.provider_roots.iter().any(|entry| {
                entry.root.is_empty()
                    || !Path::new(&entry.root).is_absolute()
                    || entry.provenance.is_empty()
                    || entry.provenance == "unbound"
            })
        {
            return Err(ReachAwareEnvelopeError::UnsafeRoot(PathBuf::from(
                self.provenance.clone(),
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwarePriorState {
    pub target_id: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareRecoveryEvidence {
    pub writes_started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwarePrincipal {
    pub session_id: String,
    pub connection_scope_id: String,
    pub connection_boundary: ConnectionBoundary,
    pub authority_key_id: String,
    pub authentication_tag: String,
}

impl ReachAwarePrincipal {
    pub fn sign(
        session_id: impl Into<String>,
        connection_scope_id: impl Into<String>,
        connection_boundary: ConnectionBoundary,
        authority_key: &SessionAuthorityKey,
    ) -> Result<Self, ReachAwareEnvelopeError> {
        let mut principal = Self {
            session_id: session_id.into(),
            connection_scope_id: connection_scope_id.into(),
            connection_boundary,
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        validate_safe_text(&principal.session_id, "principal session")?;
        validate_safe_text(&principal.connection_scope_id, "principal scope")?;
        principal.authentication_tag = authority_key
            .authenticate_reach_aware(&principal.signing_payload()?)
            .map_err(ReachAwareEnvelopeError::Authentication)?;
        Ok(principal)
    }

    pub fn verify(
        &self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        if self.authority_key_id != authority_key.key_id() {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        authority_key
            .verify_reach_aware(&self.signing_payload()?, &self.authentication_tag)
            .map_err(|_| ReachAwareEnvelopeError::AuthenticationFailed)
    }

    fn signing_payload(&self) -> Result<Vec<u8>, ReachAwareEnvelopeError> {
        serde_json::to_vec(&serde_json::json!({
            "sessionId": self.session_id,
            "connectionScopeId": self.connection_scope_id,
            "connectionBoundary": self.connection_boundary,
            "authorityKeyId": self.authority_key_id,
        }))
        .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareTransferCapability {
    pub capability_id: String,
    pub audience: String,
    pub scope_digest: String,
    pub operation_id: String,
    pub connection_boundary: ConnectionBoundary,
    pub principal_session_id: String,
    pub principal_scope_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// Legacy wire state is retained for dual-read compatibility, but durable
    /// consumption is recorded in the transition journal under CAS.  This
    /// flag is never used as the source of truth and must remain false.
    pub consumed: bool,
    pub authority_key_id: String,
    pub authentication_tag: String,
}

impl ReachAwareTransferCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        capability_id: impl Into<String>,
        audience: impl Into<String>,
        scope_digest: impl Into<String>,
        operation_id: impl Into<String>,
        principal: &ReachAwarePrincipal,
        issued_at_unix: i64,
        expires_at_unix: i64,
        authority_key: &SessionAuthorityKey,
    ) -> Result<Self, ReachAwareEnvelopeError> {
        principal.verify(authority_key)?;
        let mut capability = Self {
            capability_id: capability_id.into(),
            audience: audience.into(),
            scope_digest: scope_digest.into(),
            operation_id: operation_id.into(),
            connection_boundary: principal.connection_boundary,
            principal_session_id: principal.session_id.clone(),
            principal_scope_id: principal.connection_scope_id.clone(),
            issued_at_unix,
            expires_at_unix,
            consumed: false,
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        capability.validate_structure()?;
        capability.authentication_tag = authority_key
            .authenticate_reach_aware(&capability.signing_payload()?)
            .map_err(ReachAwareEnvelopeError::Authentication)?;
        Ok(capability)
    }

    pub fn validate_for(
        &self,
        operation_id: &str,
        audience: &str,
        scope_digest: &str,
        principal: &ReachAwarePrincipal,
        now_unix: i64,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        principal.verify(authority_key)?;
        self.validate_structure()?;
        if self.consumed || now_unix < self.issued_at_unix || now_unix >= self.expires_at_unix {
            return Err(ReachAwareEnvelopeError::CapabilityUnavailable);
        }
        if self.operation_id != operation_id
            || self.connection_boundary != principal.connection_boundary
            || self.audience != audience
            || self.scope_digest != scope_digest
            || self.principal_session_id != principal.session_id
            || self.principal_scope_id != principal.connection_scope_id
        {
            return Err(ReachAwareEnvelopeError::InvalidCapability);
        }
        self.verify_authenticated(authority_key)
    }

    pub fn verify_authenticated(
        &self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        self.validate_structure()?;
        if self.authority_key_id != authority_key.key_id() {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        if self.authentication_tag.is_empty() {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        authority_key
            .verify_reach_aware(&self.signing_payload()?, &self.authentication_tag)
            .map_err(|_| ReachAwareEnvelopeError::AuthenticationFailed)
    }

    fn validate_structure(&self) -> Result<(), ReachAwareEnvelopeError> {
        validate_safe_text(&self.capability_id, "capability id")?;
        validate_safe_text(&self.audience, "capability audience")?;
        validate_safe_text(&self.scope_digest, "capability scope")?;
        validate_safe_text(&self.operation_id, "capability operation")?;
        validate_safe_text(&self.principal_session_id, "capability principal")?;
        validate_safe_text(&self.principal_scope_id, "capability principal scope")?;
        if self.expires_at_unix <= self.issued_at_unix || self.authority_key_id.is_empty() {
            return Err(ReachAwareEnvelopeError::InvalidCapability);
        }
        Ok(())
    }

    fn signing_payload(&self) -> Result<Vec<u8>, ReachAwareEnvelopeError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ReachAwareEnvelopeError::Serialization("capability is not an object".to_string())
        })?;
        object.remove("authenticationTag");
        serde_json::to_vec(&value)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareCapabilityConsumption {
    pub capability_id: String,
    pub operation_id: String,
    pub connection_boundary: ConnectionBoundary,
    pub audience: String,
    pub scope_digest: String,
    pub principal_session_id: String,
    pub principal_scope_id: String,
    pub consumed_at_unix: i64,
    pub authority_key_id: String,
    pub authentication_tag: String,
}

impl ReachAwareCapabilityConsumption {
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        capability: &ReachAwareTransferCapability,
        operation_id: &str,
        audience: &str,
        scope_digest: &str,
        principal: &ReachAwarePrincipal,
        consumed_at_unix: i64,
        authority_key: &SessionAuthorityKey,
    ) -> Result<Self, ReachAwareEnvelopeError> {
        capability.validate_for(
            operation_id,
            audience,
            scope_digest,
            principal,
            consumed_at_unix,
            authority_key,
        )?;
        let mut receipt = Self {
            capability_id: capability.capability_id.clone(),
            operation_id: operation_id.to_string(),
            connection_boundary: capability.connection_boundary,
            audience: audience.to_string(),
            scope_digest: scope_digest.to_string(),
            principal_session_id: principal.session_id.clone(),
            principal_scope_id: principal.connection_scope_id.clone(),
            consumed_at_unix,
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        receipt.validate_structure(capability)?;
        receipt.authentication_tag = authority_key
            .authenticate_reach_aware(&receipt.signing_payload()?)
            .map_err(ReachAwareEnvelopeError::Authentication)?;
        Ok(receipt)
    }

    pub fn verify_for(
        &self,
        capability: &ReachAwareTransferCapability,
        principal: &ReachAwarePrincipal,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        principal.verify(authority_key)?;
        capability.verify_authenticated(authority_key)?;
        self.validate_structure(capability)?;
        if self.authority_key_id != authority_key.key_id()
            || self.authentication_tag.is_empty()
            || self.principal_session_id != principal.session_id
            || self.principal_scope_id != principal.connection_scope_id
        {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        authority_key
            .verify_reach_aware(&self.signing_payload()?, &self.authentication_tag)
            .map_err(|_| ReachAwareEnvelopeError::AuthenticationFailed)
    }

    fn validate_structure(
        &self,
        capability: &ReachAwareTransferCapability,
    ) -> Result<(), ReachAwareEnvelopeError> {
        validate_safe_text(&self.capability_id, "consumed capability id")?;
        validate_safe_text(&self.operation_id, "consumed capability operation")?;
        validate_safe_text(&self.audience, "consumed capability audience")?;
        validate_safe_text(&self.scope_digest, "consumed capability scope")?;
        validate_safe_text(&self.principal_session_id, "consumed capability principal")?;
        validate_safe_text(
            &self.principal_scope_id,
            "consumed capability principal scope",
        )?;
        if self.capability_id != capability.capability_id
            || self.operation_id != capability.operation_id
            || self.connection_boundary != capability.connection_boundary
            || self.audience != capability.audience
            || self.scope_digest != capability.scope_digest
            || self.principal_session_id != capability.principal_session_id
            || self.principal_scope_id != capability.principal_scope_id
            || self.consumed_at_unix < capability.issued_at_unix
            || self.consumed_at_unix >= capability.expires_at_unix
            || self.authority_key_id.is_empty()
        {
            return Err(ReachAwareEnvelopeError::InvalidCapability);
        }
        Ok(())
    }

    fn signing_payload(&self) -> Result<Vec<u8>, ReachAwareEnvelopeError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ReachAwareEnvelopeError::Serialization(
                "capability consumption is not an object".to_string(),
            )
        })?;
        object.remove("authenticationTag");
        serde_json::to_vec(&value)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachAwareEnvelopeError {
    InvalidSchemaVersion,
    InvalidOperation,
    MissingRequiredField(&'static str),
    InvalidJournalBinding,
    InvalidCapability,
    CapabilityUnavailable,
    Authentication(String),
    AuthenticationFailed,
    FingerprintMismatch,
    Serialization(String),
    UnsafeRoot(PathBuf),
}

impl fmt::Display for ReachAwareEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaVersion => {
                formatter.write_str("reach-aware schema version is unsupported")
            }
            Self::InvalidOperation => formatter.write_str("reach-aware operation is invalid"),
            Self::MissingRequiredField(field) => {
                write!(formatter, "reach-aware envelope is missing {field}")
            }
            Self::InvalidJournalBinding => {
                formatter.write_str("reach-aware journal owner or revision is invalid")
            }
            Self::InvalidCapability => {
                formatter.write_str("reach-aware transfer capability is invalid")
            }
            Self::CapabilityUnavailable => formatter
                .write_str("reach-aware transfer capability is expired or already consumed"),
            Self::Authentication(error) => {
                write!(formatter, "reach-aware authentication failed: {error}")
            }
            Self::AuthenticationFailed => formatter.write_str("reach-aware authentication failed"),
            Self::FingerprintMismatch => {
                formatter.write_str("reach-aware envelope fingerprint mismatch")
            }
            Self::Serialization(error) => {
                write!(formatter, "reach-aware serialization failed: {error}")
            }
            Self::UnsafeRoot(path) => {
                write!(formatter, "reach-aware root is unsafe: {}", path.display())
            }
        }
    }
}

impl std::error::Error for ReachAwareEnvelopeError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReachAwareControlOperationEnvelope {
    pub schema_version: u32,
    pub family: ReachAwareOperationFamily,
    pub family_schema_version: u32,
    pub operation_id: String,
    pub operation_kind: String,
    pub plan_fingerprint: String,
    pub context: ControlResolvedContext,
    pub connection_boundary: ConnectionBoundary,
    pub provider_reach: ProviderReach,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider: Option<SelectedProviderAuthority>,
    pub provider_coverage: ProviderReachCoverage,
    pub expected_lifecycle: ProviderReachLifecycle,
    pub lifecycle: ProviderReachLifecycle,
    pub activation: EffectActivation,
    pub roots: ReachAwareRootBinding,
    pub audience: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub owner: OwnerGeneration,
    pub revision: StateRevision,
    pub payload_reference: ReachAwarePayloadReference,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_state: Vec<ReachAwarePriorState>,
    pub principal: ReachAwarePrincipal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_capability: Option<ReachAwareTransferCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<ReachAwareRecoveryEvidence>,
    pub envelope_fingerprint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authentication_tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authority_key_id: String,
}

/// Fail-closed constructor for durable schema-v2 records.  Every field that
/// affects authority, reach, persistence, or family interpretation must be
/// supplied explicitly before an envelope can be fingerprinted or persisted.
#[derive(Debug, Default)]
pub struct ReachAwareControlOperationEnvelopeBuilder {
    family: Option<ReachAwareOperationFamily>,
    family_schema_version: Option<u32>,
    operation_id: Option<String>,
    operation_kind: Option<String>,
    plan_fingerprint: Option<String>,
    context: Option<ControlResolvedContext>,
    connection_boundary: Option<ConnectionBoundary>,
    provider_reach: Option<ProviderReach>,
    selected_provider: Option<SelectedProviderAuthority>,
    provider_coverage: Option<ProviderReachCoverage>,
    expected_lifecycle: Option<ProviderReachLifecycle>,
    lifecycle: Option<ProviderReachLifecycle>,
    activation: Option<EffectActivation>,
    roots: Option<ReachAwareRootBinding>,
    audience: Option<String>,
    issued_at_unix: Option<i64>,
    expires_at_unix: Option<i64>,
    owner: Option<OwnerGeneration>,
    revision: Option<StateRevision>,
    payload_reference: Option<ReachAwarePayloadReference>,
    prior_state: Vec<ReachAwarePriorState>,
    principal: Option<ReachAwarePrincipal>,
    transfer_capability: Option<ReachAwareTransferCapability>,
    recovery: Option<ReachAwareRecoveryEvidence>,
}

impl ReachAwareControlOperationEnvelopeBuilder {
    #[must_use]
    pub fn family(mut self, family: ReachAwareOperationFamily, schema_version: u32) -> Self {
        self.family = Some(family);
        self.family_schema_version = Some(schema_version);
        self
    }

    #[must_use]
    pub fn operation(
        mut self,
        operation_id: impl Into<String>,
        operation_kind: impl Into<String>,
        plan_fingerprint: impl Into<String>,
    ) -> Self {
        self.operation_id = Some(operation_id.into());
        self.operation_kind = Some(operation_kind.into());
        self.plan_fingerprint = Some(plan_fingerprint.into());
        self
    }

    #[must_use]
    pub fn context(mut self, context: ControlResolvedContext) -> Self {
        self.context = Some(context);
        self
    }

    #[must_use]
    pub fn reach(
        mut self,
        boundary: ConnectionBoundary,
        provider_reach: ProviderReach,
        selected_provider: Option<SelectedProviderAuthority>,
        coverage: ProviderReachCoverage,
    ) -> Self {
        self.connection_boundary = Some(boundary);
        self.provider_reach = Some(provider_reach);
        self.selected_provider = selected_provider;
        self.provider_coverage = Some(coverage);
        self
    }

    #[must_use]
    pub fn lifecycle(
        mut self,
        expected: ProviderReachLifecycle,
        lifecycle: ProviderReachLifecycle,
        activation: EffectActivation,
    ) -> Self {
        self.expected_lifecycle = Some(expected);
        self.lifecycle = Some(lifecycle);
        self.activation = Some(activation);
        self
    }

    #[must_use]
    pub fn trusted_roots(mut self, roots: ReachAwareRootBinding) -> Self {
        self.roots = Some(roots);
        self
    }

    #[must_use]
    pub fn authority(
        mut self,
        principal: ReachAwarePrincipal,
        audience: impl Into<String>,
        issued_at_unix: i64,
        expires_at_unix: i64,
    ) -> Self {
        self.principal = Some(principal);
        self.audience = Some(audience.into());
        self.issued_at_unix = Some(issued_at_unix);
        self.expires_at_unix = Some(expires_at_unix);
        self
    }

    #[must_use]
    pub fn journal_binding(mut self, owner: OwnerGeneration, revision: StateRevision) -> Self {
        self.owner = Some(owner);
        self.revision = Some(revision);
        self
    }

    #[must_use]
    pub fn payload_reference(mut self, payload: ReachAwarePayloadReference) -> Self {
        self.payload_reference = Some(payload);
        self
    }

    #[must_use]
    pub fn prior_state(mut self, prior_state: Vec<ReachAwarePriorState>) -> Self {
        self.prior_state = prior_state;
        self
    }

    #[must_use]
    pub fn transfer_capability(mut self, capability: Option<ReachAwareTransferCapability>) -> Self {
        self.transfer_capability = capability;
        self
    }

    #[must_use]
    pub fn recovery(mut self, recovery: Option<ReachAwareRecoveryEvidence>) -> Self {
        self.recovery = recovery;
        self
    }

    pub fn build(self) -> Result<ReachAwareControlOperationEnvelope, ReachAwareEnvelopeError> {
        let envelope = ReachAwareControlOperationEnvelope {
            schema_version: REACH_AWARE_CONTROL_OPERATION_SCHEMA_VERSION,
            family: self
                .family
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("family"))?,
            family_schema_version: self.family_schema_version.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("family schema version"),
            )?,
            operation_id: self.operation_id.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("operation id"),
            )?,
            operation_kind: self.operation_kind.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("operation kind"),
            )?,
            plan_fingerprint: self.plan_fingerprint.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("plan fingerprint"),
            )?,
            context: self
                .context
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("context"))?,
            connection_boundary: self.connection_boundary.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("connection boundary"),
            )?,
            provider_reach: self.provider_reach.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("provider reach"),
            )?,
            selected_provider: self.selected_provider,
            provider_coverage: self.provider_coverage.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("provider coverage"),
            )?,
            expected_lifecycle: self.expected_lifecycle.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("expected lifecycle"),
            )?,
            lifecycle: self
                .lifecycle
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("lifecycle"))?,
            activation: self
                .activation
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("activation"))?,
            roots: self
                .roots
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField(
                    "trusted roots",
                ))?,
            audience: self
                .audience
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("audience"))?,
            issued_at_unix: self
                .issued_at_unix
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("issued at"))?,
            expires_at_unix: self
                .expires_at_unix
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("expires at"))?,
            owner: self
                .owner
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField(
                    "journal owner",
                ))?,
            revision: self
                .revision
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField(
                    "journal revision",
                ))?,
            payload_reference: self.payload_reference.ok_or(
                ReachAwareEnvelopeError::MissingRequiredField("family payload reference"),
            )?,
            prior_state: self.prior_state,
            principal: self
                .principal
                .ok_or(ReachAwareEnvelopeError::MissingRequiredField("principal"))?,
            transfer_capability: self.transfer_capability,
            recovery: self.recovery,
            envelope_fingerprint: String::new(),
            authentication_tag: String::new(),
            authority_key_id: String::new(),
        };
        envelope.validate_complete()?;
        let mut envelope = envelope;
        envelope.envelope_fingerprint = envelope.compute_fingerprint()?;
        Ok(envelope)
    }
}

pub type ControlOperationEnvelopeV2 = ReachAwareControlOperationEnvelope;

impl ReachAwareControlOperationEnvelope {
    #[must_use]
    pub fn builder() -> ReachAwareControlOperationEnvelopeBuilder {
        ReachAwareControlOperationEnvelopeBuilder::default()
    }

    pub fn fingerprint(&self) -> Result<String, ReachAwareEnvelopeError> {
        self.compute_fingerprint()
    }

    pub fn verify(&self) -> Result<(), ReachAwareEnvelopeError> {
        if self.schema_version != REACH_AWARE_CONTROL_OPERATION_SCHEMA_VERSION {
            return Err(ReachAwareEnvelopeError::InvalidSchemaVersion);
        }
        self.validate_complete()?;
        if self.envelope_fingerprint != self.compute_fingerprint()? {
            return Err(ReachAwareEnvelopeError::FingerprintMismatch);
        }
        Ok(())
    }

    pub fn seal(
        &mut self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        self.verify()?;
        self.authority_key_id = authority_key.key_id();
        self.authentication_tag = authority_key
            .authenticate_reach_aware(&self.signing_payload()?)
            .map_err(ReachAwareEnvelopeError::Authentication)?;
        Ok(())
    }

    pub fn verify_authenticated(
        &self,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), ReachAwareEnvelopeError> {
        self.verify()?;
        self.principal.verify(authority_key)?;
        if self.authority_key_id != authority_key.key_id() || self.authentication_tag.is_empty() {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        authority_key
            .verify_reach_aware(&self.signing_payload()?, &self.authentication_tag)
            .map_err(|_| ReachAwareEnvelopeError::AuthenticationFailed)?;
        if let Some(capability) = &self.transfer_capability {
            capability.verify_authenticated(authority_key)?;
            if capability.operation_id != self.operation_id || capability.audience != self.audience
            {
                return Err(ReachAwareEnvelopeError::InvalidCapability);
            }
        }
        Ok(())
    }

    /// Return whether the envelope's persisted authority window has expired.
    ///
    /// The journal is the source of truth for an attached operation.  Callers
    /// that are reattaching an interrupted operation must use this value rather
    /// than a newly supplied handoff timestamp, otherwise a caller could extend
    /// an expired write authority simply by rebuilding the envelope.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// Compare the immutable authority binding of two envelopes.
    ///
    /// Lifecycle and recovery evidence are intentionally excluded because they
    /// are durable operation progress, not caller authority.  The journal
    /// owner/revision binding is also excluded: the revision advances whenever
    /// progress is checkpointed.  Every operation, scope, root, timestamp,
    /// principal, payload and capability field remains bound and must match.
    #[must_use]
    pub fn same_authority_binding(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.family == other.family
            && self.family_schema_version == other.family_schema_version
            && self.operation_id == other.operation_id
            && self.operation_kind == other.operation_kind
            && self.plan_fingerprint == other.plan_fingerprint
            && self.context == other.context
            && self.connection_boundary == other.connection_boundary
            && self.provider_reach == other.provider_reach
            && self.selected_provider == other.selected_provider
            && self.provider_coverage == other.provider_coverage
            && self.expected_lifecycle == other.expected_lifecycle
            && self.activation == other.activation
            && self.roots == other.roots
            && self.audience == other.audience
            && self.issued_at_unix == other.issued_at_unix
            && self.expires_at_unix == other.expires_at_unix
            && self.payload_reference == other.payload_reference
            && self.prior_state == other.prior_state
            && self.principal == other.principal
            && self.transfer_capability == other.transfer_capability
    }

    #[must_use]
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        redacted.roots = self.roots.redacted();
        redacted.prior_state.iter_mut().for_each(|entry| {
            entry.target_id = redact_path(&entry.target_id);
        });
        if let Some(capability) = redacted.transfer_capability.as_mut() {
            capability.authentication_tag.clear();
        }
        redacted.authentication_tag.clear();
        redacted.envelope_fingerprint = redacted.compute_fingerprint().unwrap_or_default();
        redacted
    }

    fn compute_fingerprint(&self) -> Result<String, ReachAwareEnvelopeError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ReachAwareEnvelopeError::Serialization("envelope is not an object".to_string())
        })?;
        object.remove("envelopeFingerprint");
        object.remove("authenticationTag");
        object.remove("authorityKeyId");
        Ok(crate::encode_lower_hex(&Sha256::digest(
            serde_json::to_vec(&value)
                .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))?,
        )))
    }

    fn signing_payload(&self) -> Result<Vec<u8>, ReachAwareEnvelopeError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ReachAwareEnvelopeError::Serialization("envelope is not an object".to_string())
        })?;
        object.remove("authenticationTag");
        serde_json::to_vec(&value)
            .map_err(|error| ReachAwareEnvelopeError::Serialization(error.to_string()))
    }

    fn validate_complete(&self) -> Result<(), ReachAwareEnvelopeError> {
        validate_safe_text(&self.operation_id, "operation id")?;
        validate_safe_text(&self.operation_kind, "operation kind")?;
        validate_safe_text(&self.plan_fingerprint, "plan fingerprint")?;
        validate_safe_text(&self.context.repository_key, "repository key")?;
        validate_safe_text(&self.context.workspace_key, "workspace key")?;
        if self.family_schema_version == 0
            || self.payload_reference.schema_version == 0
            || self.payload_reference.family != self.family
        {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        validate_safe_text(&self.audience, "audience")?;
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        self.roots.verify()?;
        if self.principal.session_id.is_empty()
            || self.principal.connection_scope_id.is_empty()
            || self.principal.connection_boundary != self.connection_boundary
            || self.principal.authority_key_id.is_empty()
            || self.principal.authentication_tag.is_empty()
        {
            return Err(ReachAwareEnvelopeError::AuthenticationFailed);
        }
        if self.owner.owner_id.is_empty()
            || self.owner.generation == 0
            || self.revision.sequence == 0
            || self.revision.fingerprint.is_empty()
        {
            return Err(ReachAwareEnvelopeError::InvalidJournalBinding);
        }
        validate_safe_text(&self.payload_reference.reference, "payload reference")?;
        validate_safe_text(&self.payload_reference.payload_digest, "payload digest")?;
        let normalized_coverage =
            ProviderReachCoverage::new(self.provider_coverage.entries.clone());
        if normalized_coverage != self.provider_coverage {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        if self.family != ReachAwareOperationFamily::Profile
            && let Some(selected_provider) = self.provider_reach.provider()
            && (self.roots.provider_roots.is_empty()
                || !self.roots.provider_roots.iter().any(|root| {
                    root.provider == selected_provider && root.scope == ReachAwareRootScope::Primary
                })
                || self
                    .roots
                    .provider_roots
                    .iter()
                    .any(|root| root.provider != selected_provider)
                || self
                    .provider_coverage
                    .included()
                    .any(|entry| entry.provider != selected_provider))
        {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        if let Some(boundary_provider) = self.connection_boundary.provider()
            && (self.provider_reach == ProviderReach::All
                || self.provider_reach.provider() != Some(boundary_provider))
        {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        if let Some(selected) = self.selected_provider
            && Some(selected.provider) != self.provider_reach.provider()
        {
            return Err(ReachAwareEnvelopeError::InvalidOperation);
        }
        if let Some(capability) = &self.transfer_capability
            && (capability.consumed
                || capability.audience != self.audience
                || capability.operation_id != self.operation_id
                || capability.issued_at_unix < self.issued_at_unix
                || capability.expires_at_unix > self.expires_at_unix
                || capability.expires_at_unix <= capability.issued_at_unix
                || capability.scope_digest.is_empty()
                || capability.principal_session_id.is_empty()
                || capability.principal_scope_id.is_empty()
                || capability.authority_key_id.is_empty()
                || capability.authentication_tag.is_empty())
        {
            return Err(ReachAwareEnvelopeError::InvalidCapability);
        }
        Ok(())
    }
}

fn canonical_root(path: &Path) -> Result<String, ReachAwareEnvelopeError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ReachAwareEnvelopeError::UnsafeRoot(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() {
        return Err(ReachAwareEnvelopeError::UnsafeRoot(path.to_path_buf()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ReachAwareEnvelopeError::UnsafeRoot(path.to_path_buf()))?;
    if !canonical.is_absolute() {
        return Err(ReachAwareEnvelopeError::UnsafeRoot(canonical));
    }
    Ok(canonical.to_string_lossy().into_owned())
}

fn redact_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    format!(
        "<private:{}>",
        &crate::encode_lower_hex(&Sha256::digest(path.as_bytes()))[..16]
    )
}

fn validate_safe_text(value: &str, _label: &str) -> Result<(), ReachAwareEnvelopeError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ReachAwareEnvelopeError::InvalidOperation);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct DurableControlJournal {
    store: TransitionJournalStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableControlTerminalStatus {
    Applied,
    NoOp,
}

impl DurableControlTerminalStatus {
    const fn terminal_code(self) -> &'static str {
        match self {
            Self::Applied => "control-result-applied",
            Self::NoOp => "control-result-no-op",
        }
    }

    fn from_terminal_code(code: Option<&str>) -> Option<Self> {
        match code {
            Some("control-result-applied") => Some(Self::Applied),
            Some("control-result-no-op") => Some(Self::NoOp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableControlTerminal {
    pub(crate) operation_id: String,
    pub(crate) operation_kind: String,
    pub(crate) effect_graph_digest: String,
    pub(crate) status: DurableControlTerminalStatus,
}

#[derive(Debug)]
pub(crate) enum DurableControlStart {
    Apply(Box<DurableControlHandle>),
    Cached(DurableControlTerminal),
}

impl DurableControlJournal {
    #[must_use]
    pub(crate) fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            store: TransitionJournalStore::new(app_state_root),
        }
    }

    pub(crate) fn begin(
        &self,
        plan: &TransitionPlan,
        authorization: &ControlAuthorization,
        _actor_id: &str,
    ) -> Result<DurableControlStart, DurableControlError> {
        if authorization.operation_id() != plan.operation_id {
            return Err(DurableControlError::AuthorizationDecisionConflict);
        }
        let owner_digest = crate::encode_lower_hex(&Sha256::digest(plan.operation_id.as_bytes()));
        let owner = OwnerGeneration::new(format!("control-{}", &owner_digest[..32]), 1)?;
        let mut handle = self.store.create_or_attach(plan, owner)?;
        let resumed = handle.journal.lifecycle == TransitionLifecycle::Applying;
        match &handle.journal.authorization_decision_digest {
            Some(existing) if existing != authorization.decision_digest() && resumed => {
                let decisions_to_append = usize::from(
                    handle.journal.authorization_decision_history.last() != Some(existing),
                ) + 1;
                if handle
                    .journal
                    .authorization_decision_history
                    .len()
                    .saturating_add(decisions_to_append)
                    > MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES
                {
                    handle.journal.terminal_code = Some("approval-refresh-limit".to_string());
                    handle.journal.record(
                        TransitionLifecycle::NeedsRepair,
                        "approval-refresh-limit",
                        None,
                    )?;
                    self.store.save(&mut handle)?;
                    return Err(DurableControlError::RecoveryRequired(
                        handle.journal.operation_id.clone(),
                    ));
                }
                if handle.journal.authorization_decision_history.last() != Some(existing) {
                    handle
                        .journal
                        .authorization_decision_history
                        .push(existing.clone());
                }
                handle
                    .journal
                    .authorization_decision_history
                    .push(authorization.decision_digest().to_string());
                handle.journal.authorization_decision_digest =
                    Some(authorization.decision_digest().to_string());
                handle
                    .journal
                    .record(TransitionLifecycle::Applying, "approval-refreshed", None)?;
                self.store.save(&mut handle)?;
            }
            Some(existing) if existing != authorization.decision_digest() => {
                return Err(DurableControlError::AuthorizationDecisionConflict);
            }
            Some(_) => {}
            None if handle.journal.lifecycle.is_terminal() => {
                return Err(DurableControlError::TerminalOutcomeUnavailable(
                    handle.journal.operation_id.clone(),
                ));
            }
            None => {
                handle.journal.authorization_decision_digest =
                    Some(authorization.decision_digest().to_string());
                handle
                    .journal
                    .authorization_decision_history
                    .push(authorization.decision_digest().to_string());
                handle
                    .journal
                    .record(TransitionLifecycle::Approved, "approval-recorded", None)?;
                self.store.save(&mut handle)?;
            }
        }
        match handle.journal.lifecycle {
            TransitionLifecycle::Committed => {
                let status = DurableControlTerminalStatus::from_terminal_code(
                    handle.journal.terminal_code.as_deref(),
                )
                .ok_or_else(|| {
                    DurableControlError::TerminalOutcomeUnavailable(
                        handle.journal.operation_id.clone(),
                    )
                })?;
                return Ok(DurableControlStart::Cached(DurableControlTerminal {
                    operation_id: handle.journal.operation_id,
                    operation_kind: handle.journal.operation_kind,
                    effect_graph_digest: handle.journal.effect_graph_digest,
                    status,
                }));
            }
            TransitionLifecycle::RolledBack => {
                return Err(DurableControlError::RolledBackOperation(
                    handle.journal.operation_id.clone(),
                ));
            }
            TransitionLifecycle::NeedsRepair => {
                return Err(DurableControlError::RecoveryRequired(
                    handle.journal.operation_id.clone(),
                ));
            }
            _ => {}
        }
        if let Some(blocking) = self.store.blocking_operation_for(plan)? {
            return Err(DurableControlError::RecoveryRequired(blocking));
        }
        if handle.journal.lifecycle != TransitionLifecycle::Applying {
            handle
                .journal
                .record(TransitionLifecycle::Applying, "control-applying", None)?;
            self.store.save(&mut handle)?;
        }
        Ok(DurableControlStart::Apply(Box::new(DurableControlHandle {
            store: self.store.clone(),
            handle,
            resumed,
        })))
    }
}

#[derive(Debug)]
pub(crate) struct DurableControlHandle {
    store: TransitionJournalStore,
    handle: JournalHandle,
    resumed: bool,
}

impl DurableControlHandle {
    pub(crate) const fn is_resumed(&self) -> bool {
        self.resumed
    }

    pub(crate) fn commit_with_terminal_status(
        mut self,
        status: DurableControlTerminalStatus,
    ) -> Result<(), DurableControlError> {
        self.commit_inner(status)
    }

    fn commit_inner(
        &mut self,
        status: DurableControlTerminalStatus,
    ) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(status.terminal_code().to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::Committed, "control-committed", None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }

    pub(crate) fn abort(mut self, code: &'static str) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(code.to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::RolledBack, code, None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }

    pub(crate) fn needs_repair(mut self, code: &'static str) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(code.to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::NeedsRepair, code, None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DurableControlError {
    Journal(JournalError),
    State(crate::state::atomic_json::StateError),
    AuthorizationDecisionConflict,
    RecoveryRequired(String),
    RolledBackOperation(String),
    TerminalOutcomeUnavailable(String),
    TerminalOperation(String),
}

impl From<JournalError> for DurableControlError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<crate::state::atomic_json::StateError> for DurableControlError {
    fn from(error: crate::state::atomic_json::StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for DurableControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::AuthorizationDecisionConflict => {
                formatter.write_str("control operation is bound to another approval decision")
            }
            Self::RecoveryRequired(operation_id) => {
                write!(formatter, "control recovery required for {operation_id}")
            }
            Self::RolledBackOperation(operation_id) => {
                write!(
                    formatter,
                    "control operation was rolled back: {operation_id}"
                )
            }
            Self::TerminalOutcomeUnavailable(operation_id) => {
                write!(
                    formatter,
                    "control operation terminal outcome is unavailable: {operation_id}"
                )
            }
            Self::TerminalOperation(operation_id) => {
                write!(
                    formatter,
                    "control operation is already terminal: {operation_id}"
                )
            }
        }
    }
}

impl std::error::Error for DurableControlError {}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        approval::{
            ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
            CONTROL_APPROVAL_AUDIENCE, CONTROL_APPROVAL_ISSUER, authorize_control,
        },
        state::atomic_json::OwnerGeneration,
        transitions::{
            EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
            TransitionEffectKind, TransitionJournalStore, TransitionKind,
        },
    };

    use super::*;

    #[test]
    fn exact_applied_and_no_op_retries_return_cached_terminal_status() {
        for (suffix, status) in [
            ("applied", DurableControlTerminalStatus::Applied),
            ("no-op", DurableControlTerminalStatus::NoOp),
        ] {
            let temp = TempDir::new().expect("temporary state root");
            let root = temp.path().canonicalize().expect("canonical state root");
            let plan = plan(&format!("operation-{suffix}"), "resource", 'b');
            let authorization = authorization(&root, &plan, suffix);
            let journal = DurableControlJournal::new(&root);

            let DurableControlStart::Apply(handle) = journal
                .begin(&plan, &authorization, "first-actor")
                .expect("begin operation")
            else {
                panic!("new operation must be active");
            };
            handle
                .commit_with_terminal_status(status)
                .expect("commit operation");

            let DurableControlStart::Cached(cached) = journal
                .begin(&plan, &authorization, "retry-actor")
                .expect("attach exact retry")
            else {
                panic!("exact retry must return cached terminal status");
            };
            assert_eq!(cached.operation_id, plan.operation_id);
            assert_eq!(cached.operation_kind, plan.kind.as_str());
            assert_eq!(cached.effect_graph_digest, plan.effect_graph_digest);
            assert_eq!(cached.status, status);
        }
    }

    #[test]
    fn terminal_retry_rejects_mismatched_operation_identity() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let original = plan("operation-mismatch", "resource", 'b');
        let original_authorization = authorization(&root, &original, "original");
        let journal = DurableControlJournal::new(&root);
        let DurableControlStart::Apply(handle) = journal
            .begin(&original, &original_authorization, "first-actor")
            .expect("begin original operation")
        else {
            panic!("new operation must be active");
        };
        handle
            .commit_with_terminal_status(DurableControlTerminalStatus::Applied)
            .expect("commit original operation");

        let mismatched = plan("operation-mismatch", "other-resource", 'c');
        let mismatched_authorization = authorization(&root, &mismatched, "mismatched");
        assert!(matches!(
            journal.begin(&mismatched, &mismatched_authorization, "retry-actor"),
            Err(DurableControlError::Journal(
                JournalError::OperationConflict
            ))
        ));
    }

    #[test]
    fn resumed_operation_preserves_approval_decision_history() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let plan = plan("operation-resume-approval", "resource", 'b');
        let first_authorization = authorization(&root, &plan, "first");
        let first_digest = first_authorization.decision_digest().to_string();
        let journal = DurableControlJournal::new(&root);

        let DurableControlStart::Apply(first) = journal
            .begin(&plan, &first_authorization, "first-actor")
            .expect("begin operation")
        else {
            panic!("new operation must be active");
        };
        drop(first);

        let second_authorization = authorization(&root, &plan, "second");
        let second_digest = second_authorization.decision_digest().to_string();
        let DurableControlStart::Apply(resumed) = journal
            .begin(&plan, &second_authorization, "second-actor")
            .expect("resume operation")
        else {
            panic!("interrupted operation must resume");
        };
        assert!(resumed.is_resumed());
        drop(resumed);

        let stored = TransitionJournalStore::new(&root)
            .list()
            .expect("transition journals")
            .into_iter()
            .find(|journal| journal.operation_id == plan.operation_id)
            .expect("resumed journal");
        assert_eq!(
            stored.authorization_decision_history,
            vec![first_digest, second_digest.clone()]
        );
        assert_eq!(
            stored.authorization_decision_digest.as_deref(),
            Some(second_digest.as_str())
        );
        assert!(
            stored
                .audit
                .iter()
                .any(|event| event.code == "approval-refreshed")
        );
    }

    #[test]
    fn resumed_operation_bounds_approval_decision_history() {
        const MAX_REFRESH_HISTORY: usize = 32;

        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let plan = plan("operation-resume-approval-limit", "resource", 'b');
        let journal = DurableControlJournal::new(&root);

        for index in 0..MAX_REFRESH_HISTORY {
            let authorization = authorization(&root, &plan, &format!("refresh-limit-{index}"));
            let DurableControlStart::Apply(handle) = journal
                .begin(&plan, &authorization, "retry-actor")
                .expect("approval history has bounded capacity")
            else {
                panic!("interrupted operation must remain resumable within its history bound");
            };
            drop(handle);
        }

        let overflow = authorization(&root, &plan, "refresh-limit-overflow");
        assert!(matches!(
            journal.begin(&plan, &overflow, "overflow-actor"),
            Err(DurableControlError::RecoveryRequired(operation_id))
                if operation_id == plan.operation_id
        ));
        let stored = TransitionJournalStore::new(&root)
            .list()
            .expect("transition journals")
            .into_iter()
            .find(|candidate| candidate.operation_id == plan.operation_id)
            .expect("bounded journal");
        assert_eq!(
            stored.authorization_decision_history.len(),
            MAX_REFRESH_HISTORY
        );
        assert_eq!(stored.lifecycle, TransitionLifecycle::NeedsRepair);
        assert_eq!(
            stored.terminal_code.as_deref(),
            Some("approval-refresh-limit")
        );
    }

    #[test]
    fn rolled_back_and_needs_repair_operations_are_not_replayed() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let journal = DurableControlJournal::new(&root);

        let rolled_back = plan("operation-rolled-back", "rolled-back-resource", 'b');
        let rolled_back_authorization = authorization(&root, &rolled_back, "rolled-back");
        let DurableControlStart::Apply(handle) = journal
            .begin(&rolled_back, &rolled_back_authorization, "first-actor")
            .expect("begin rolled-back operation")
        else {
            panic!("new operation must be active");
        };
        handle.abort("control-apply-aborted").expect("roll back");
        assert!(matches!(
            journal.begin(&rolled_back, &rolled_back_authorization, "retry-actor"),
            Err(DurableControlError::RolledBackOperation(operation_id))
                if operation_id == rolled_back.operation_id
        ));

        let needs_repair = plan("operation-needs-repair", "repair-resource", 'c');
        let needs_repair_authorization = authorization(&root, &needs_repair, "needs-repair");
        let DurableControlStart::Apply(handle) = journal
            .begin(&needs_repair, &needs_repair_authorization, "first-actor")
            .expect("begin needs-repair operation")
        else {
            panic!("new operation must be active");
        };
        handle
            .needs_repair("control-partial-apply")
            .expect("mark repair required");
        assert!(matches!(
            journal.begin(&needs_repair, &needs_repair_authorization, "retry-actor"),
            Err(DurableControlError::RecoveryRequired(operation_id))
                if operation_id == needs_repair.operation_id
        ));
    }

    fn plan(operation_id: &str, resource_id: &str, post_digest: char) -> TransitionPlan {
        TransitionPlan::new(
            operation_id,
            TransitionKind::ApplyProfile,
            TransitionContext {
                repository_key: "repository".to_string(),
                workspace_key: "workspace".to_string(),
                session_id: None,
                profile_digest: None,
            },
            vec![TransitionEffect {
                effect_id: "effect".to_string(),
                kind: TransitionEffectKind::PublishView,
                resource_id: resource_id.to_string(),
                target_type: "profile-policy".to_string(),
                summary: "Apply reviewed policy".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::Live,
                expected_pre_fingerprint: Some("a".repeat(64)),
                expected_post_fingerprint: Some(post_digest.to_string().repeat(64)),
                provider_views: Vec::new(),
            }],
        )
        .expect("valid transition plan")
    }

    fn authorization(
        app_state_root: &std::path::Path,
        plan: &TransitionPlan,
        suffix: &str,
    ) -> ControlAuthorization {
        let expectation =
            plan.approval_expectation(CONTROL_APPROVAL_ISSUER, CONTROL_APPROVAL_AUDIENCE);
        let key = ApprovalKey::new([0x41; 32]);
        let issuer = ApprovalIssuer::new(
            ApprovalKey::new([0x41; 32]),
            CONTROL_APPROVAL_ISSUER,
            CONTROL_APPROVAL_AUDIENCE,
        )
        .expect("approval issuer");
        let receipt = issuer
            .issue(ApprovalReceiptClaims {
                version: 1,
                receipt_id: format!("receipt-{suffix}"),
                nonce: format!("nonce-{suffix}"),
                issuer: String::new(),
                audience: String::new(),
                operation_id: expectation.operation_id.clone(),
                operation_kind: expectation.operation_kind.clone(),
                effect_graph_digest: expectation.effect_graph_digest.clone(),
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
                resources: expectation.resources.clone(),
                issued_at_unix: 100,
                expires_at_unix: 200,
            })
            .expect("issue approval");
        authorize_control(
            app_state_root,
            &receipt,
            &ApprovalVerifier::new(key),
            &expectation,
            150,
            OwnerGeneration::new("approval-test", 1).expect("approval owner"),
        )
        .expect("authorize control")
    }
}
