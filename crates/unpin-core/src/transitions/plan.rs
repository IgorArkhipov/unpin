use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{ApprovalExpectation, ApprovalResourceBinding},
    providers::ProviderId,
};

pub const TRANSITION_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionKind {
    ApplyProfile,
    ApplyCapabilityPolicy,
    GatewayWorkflow,
    SessionEnd,
    AdoptCapability,
    RestoreNative,
    DetachGateway,
    TrustHook,
    Recover,
    NativeToggle,
    BulkToggle,
    InventoryGroupApply,
}

impl TransitionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplyProfile => "apply-profile",
            Self::ApplyCapabilityPolicy => "apply-capability-policy",
            Self::GatewayWorkflow => "gateway-workflow",
            Self::SessionEnd => "session-end",
            Self::AdoptCapability => "adopt-capability",
            Self::RestoreNative => "restore-native",
            Self::DetachGateway => "detach-gateway",
            Self::TrustHook => "trust-hook",
            Self::Recover => "recover",
            Self::NativeToggle => "native-toggle",
            Self::BulkToggle => "bulk-toggle",
            Self::InventoryGroupApply => "inventory-group-apply",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionContext {
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionEffectKind {
    PublishView,
    WithdrawView,
    ReplaceProviderConfig,
    CopyCanonicalContent,
    RestoreView,
    InstallBridge,
    DetachBridge,
    RecordTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectAuthority {
    UserManaged,
    ProviderManaged,
    AdministratorManaged,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectActivation {
    Live,
    ReloadRequired,
    RestartRequired,
    NextSessionOnly,
}

impl EffectActivation {
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Live => 0,
            Self::ReloadRequired => 1,
            Self::RestartRequired => 2,
            Self::NextSessionOnly => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionEffect {
    pub effect_id: String,
    pub kind: TransitionEffectKind,
    pub resource_id: String,
    pub target_type: String,
    pub summary: String,
    pub authority: EffectAuthority,
    pub activation: EffectActivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pre_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_post_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_views: Vec<ProviderId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionPlan {
    pub schema_version: u32,
    pub operation_id: String,
    pub kind: TransitionKind,
    pub context: TransitionContext,
    pub effects: Vec<TransitionEffect>,
    pub effect_graph_digest: String,
}

impl TransitionPlan {
    pub fn new(
        operation_id: impl Into<String>,
        kind: TransitionKind,
        context: TransitionContext,
        effects: Vec<TransitionEffect>,
    ) -> Result<Self, TransitionPlanError> {
        let mut plan = Self {
            schema_version: TRANSITION_PLAN_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            kind,
            context,
            effects,
            effect_graph_digest: String::new(),
        };
        plan.validate_shape()?;
        plan.effect_graph_digest = plan.calculate_digest()?;
        Ok(plan)
    }

    pub fn verify(&self) -> Result<(), TransitionPlanError> {
        self.validate_shape()?;
        let actual = self.calculate_digest()?;
        if actual == self.effect_graph_digest {
            Ok(())
        } else {
            Err(TransitionPlanError::DigestMismatch {
                expected: self.effect_graph_digest.clone(),
                actual,
            })
        }
    }

    #[must_use]
    pub fn resource_bindings(&self) -> Vec<ApprovalResourceBinding> {
        let mut resources = self
            .effects
            .iter()
            .map(|effect| ApprovalResourceBinding {
                resource_id: effect.resource_id.clone(),
                pre_state_fingerprint: effect.expected_pre_fingerprint.clone(),
            })
            .collect::<Vec<_>>();
        resources.sort();
        resources
    }

    #[must_use]
    pub fn provider_fan_out(&self) -> BTreeSet<ProviderId> {
        self.effects
            .iter()
            .flat_map(|effect| effect.provider_views.iter().copied())
            .collect()
    }

    #[must_use]
    pub fn approval_expectation(
        &self,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> ApprovalExpectation {
        ApprovalExpectation {
            issuer: issuer.into(),
            audience: audience.into(),
            operation_id: self.operation_id.clone(),
            operation_kind: self.kind.as_str().to_string(),
            effect_graph_digest: self.effect_graph_digest.clone(),
            repository_key: self.context.repository_key.clone(),
            workspace_key: self.context.workspace_key.clone(),
            session_id: self.context.session_id.clone(),
            profile_digest: self.context.profile_digest.clone(),
            resources: self.resource_bindings(),
        }
    }

    fn validate_shape(&self) -> Result<(), TransitionPlanError> {
        if self.schema_version != TRANSITION_PLAN_SCHEMA_VERSION {
            return Err(TransitionPlanError::UnsupportedVersion(self.schema_version));
        }
        validate_identifier("operation id", &self.operation_id)?;
        validate_identifier("repository key", &self.context.repository_key)?;
        validate_identifier("workspace key", &self.context.workspace_key)?;
        if let Some(session_id) = &self.context.session_id {
            validate_identifier("session id", session_id)?;
        }
        if let Some(profile_digest) = &self.context.profile_digest {
            validate_digest("profile", profile_digest)?;
        }
        if self.effects.is_empty() {
            return Err(TransitionPlanError::EmptyEffects);
        }
        let mut effect_ids = BTreeSet::new();
        let mut resource_ids = BTreeSet::new();
        for effect in &self.effects {
            validate_identifier("effect id", &effect.effect_id)?;
            validate_identifier("resource id", &effect.resource_id)?;
            validate_identifier("target type", &effect.target_type)?;
            if effect.summary.trim().is_empty()
                || effect.summary.len() > 1024
                || effect.summary.chars().any(char::is_control)
            {
                return Err(TransitionPlanError::InvalidSummary);
            }
            if effect.authority != EffectAuthority::UserManaged {
                return Err(TransitionPlanError::ImmutableAuthority {
                    effect_id: effect.effect_id.clone(),
                    authority: effect.authority,
                });
            }
            if !effect_ids.insert(effect.effect_id.clone()) {
                return Err(TransitionPlanError::DuplicateEffect(
                    effect.effect_id.clone(),
                ));
            }
            if !resource_ids.insert(effect.resource_id.clone()) {
                return Err(TransitionPlanError::DuplicateResource(
                    effect.resource_id.clone(),
                ));
            }
            if let Some(fingerprint) = &effect.expected_pre_fingerprint {
                validate_digest("pre-state", fingerprint)?;
            }
            if let Some(fingerprint) = &effect.expected_post_fingerprint {
                validate_digest("post-state", fingerprint)?;
            }
            if effect.expected_pre_fingerprint == effect.expected_post_fingerprint {
                return Err(TransitionPlanError::NoStateChange {
                    effect_id: effect.effect_id.clone(),
                });
            }
            effect.provider_views.windows(2).try_for_each(|pair| {
                if pair[0] < pair[1] {
                    Ok(())
                } else {
                    Err(TransitionPlanError::NonCanonicalProviderViews {
                        effect_id: effect.effect_id.clone(),
                    })
                }
            })?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, TransitionPlanError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DigestBody<'a> {
            schema_version: u32,
            operation_id: &'a str,
            kind: TransitionKind,
            context: &'a TransitionContext,
            effects: &'a [TransitionEffect],
        }
        let bytes = serde_json::to_vec(&DigestBody {
            schema_version: self.schema_version,
            operation_id: &self.operation_id,
            kind: self.kind,
            context: &self.context,
            effects: &self.effects,
        })
        .map_err(|error| TransitionPlanError::Serialization(error.to_string()))?;
        Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
    }
}

fn validate_identifier(label: &'static str, value: &str) -> Result<(), TransitionPlanError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err(TransitionPlanError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn validate_digest(label: &'static str, value: &str) -> Result<(), TransitionPlanError> {
    if crate::is_lower_hex_digest(value) {
        Ok(())
    } else {
        Err(TransitionPlanError::InvalidDigest(label))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionPlanError {
    UnsupportedVersion(u32),
    InvalidIdentifier(&'static str),
    InvalidDigest(&'static str),
    EmptyEffects,
    DuplicateEffect(String),
    DuplicateResource(String),
    InvalidSummary,
    NoStateChange {
        effect_id: String,
    },
    ImmutableAuthority {
        effect_id: String,
        authority: EffectAuthority,
    },
    NonCanonicalProviderViews {
        effect_id: String,
    },
    Serialization(String),
    DigestMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for TransitionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported transition plan version: {version}")
            }
            Self::InvalidIdentifier(label) => write!(formatter, "invalid {label}"),
            Self::InvalidDigest(label) => write!(formatter, "invalid {label} digest"),
            Self::EmptyEffects => formatter.write_str("transition plan has no effects"),
            Self::DuplicateEffect(effect_id) => {
                write!(formatter, "duplicate transition effect: {effect_id}")
            }
            Self::DuplicateResource(resource_id) => {
                write!(formatter, "duplicate transition resource: {resource_id}")
            }
            Self::InvalidSummary => formatter.write_str("transition effect summary is invalid"),
            Self::NoStateChange { effect_id } => {
                write!(
                    formatter,
                    "transition effect does not change state: {effect_id}"
                )
            }
            Self::ImmutableAuthority {
                effect_id,
                authority,
            } => write!(
                formatter,
                "transition effect {effect_id} cannot mutate {authority:?} capability"
            ),
            Self::NonCanonicalProviderViews { effect_id } => {
                write!(
                    formatter,
                    "transition effect provider views are not canonical: {effect_id}"
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "transition plan serialization failed: {message}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "transition plan digest mismatch: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for TransitionPlanError {}
