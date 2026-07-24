use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    discovery::{DiscoveryLayer, DiscoveryMutability},
    providers::ProviderId,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn new(value: impl Into<String>) -> Result<Self, CatalogModelError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > 256
            || value.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || matches!(character, '/' | '\\')
            })
        {
            return Err(CatalogModelError::InvalidCapabilityId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    Skill,
    McpServer,
    McpTool,
    Plugin,
    Agent,
    Hook,
    Setting,
}

impl CapabilityKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::McpServer => "mcp-server",
            Self::McpTool => "mcp-tool",
            Self::Plugin => "plugin",
            Self::Agent => "agent",
            Self::Hook => "hook",
            Self::Setting => "setting",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityScope {
    Global,
    Repository,
}

impl From<DiscoveryLayer> for CapabilityScope {
    fn from(layer: DiscoveryLayer) -> Self {
        match layer {
            DiscoveryLayer::Global => Self::Global,
            DiscoveryLayer::Project => Self::Repository,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityOwnership {
    User,
    ProviderManaged,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityMutability {
    ReadWrite,
    ReadOnly,
    Unsupported,
}

impl From<DiscoveryMutability> for CapabilityMutability {
    fn from(value: DiscoveryMutability) -> Self {
        match value {
            DiscoveryMutability::ReadWrite => Self::ReadWrite,
            DiscoveryMutability::ReadOnly => Self::ReadOnly,
            DiscoveryMutability::Unsupported => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalOrigin {
    /// Stable local identity. This is not an executable or credential reference.
    pub canonical_key: String,
    pub source_path: String,
    pub state_path: String,
    pub scope: CapabilityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderView {
    pub provider: ProviderId,
    pub discovery_id: String,
    pub layer: DiscoveryLayer,
    pub enabled: bool,
    pub mutability: CapabilityMutability,
    pub source_path: String,
    pub state_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityLifecycle {
    pub cataloged: bool,
    pub installed: bool,
    pub active: bool,
    pub exposed: bool,
    pub loaded: bool,
    pub connected: bool,
}

impl CapabilityLifecycle {
    #[must_use]
    pub const fn discovered(enabled: bool) -> Self {
        Self {
            cataloged: true,
            installed: true,
            active: enabled,
            exposed: enabled,
            loaded: false,
            connected: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityStateEvidence {
    pub observation: String,
    pub observed_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityTrustRequirements {
    pub executable_review: bool,
    pub network_review: bool,
    pub credential_authorization: bool,
}

impl CapabilityTrustRequirements {
    #[must_use]
    pub const fn requires_local_review(&self) -> bool {
        self.executable_review || self.network_review || self.credential_authorization
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolNamespace {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContributionControl {
    Independent,
    Atomic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContributionEdge {
    pub capability_id: CapabilityId,
    pub control: ContributionControl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogRecord {
    pub id: CapabilityId,
    pub kind: CapabilityKind,
    pub display_name: String,
    pub origin: CanonicalOrigin,
    pub ownership: CapabilityOwnership,
    pub fingerprint: String,
    pub lifecycle: CapabilityLifecycle,
    pub state_evidence: CapabilityStateEvidence,
    pub trust_requirements: CapabilityTrustRequirements,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_views: Vec<ProviderView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<CapabilityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ContributionEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contributed_by: Option<CapabilityId>,
    #[serde(default)]
    pub atomic_unknown_contributions: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_namespace: Option<ToolNamespace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_conflict_key: Option<String>,
}

impl CatalogRecord {
    #[must_use]
    pub fn provider_fan_out(&self) -> usize {
        self.provider_views.len()
    }

    #[must_use]
    pub fn supports_provider(&self, provider: ProviderId) -> bool {
        self.provider_views
            .iter()
            .any(|view| view.provider == provider)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogWarningCode {
    InvalidManifest,
    OversizedManifest,
    UnknownDynamicContributions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogWarning {
    pub capability_id: CapabilityId,
    pub code: CatalogWarningCode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalog {
    pub records: BTreeMap<CapabilityId, CatalogRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<CatalogWarning>,
}

impl Catalog {
    pub fn from_records(
        records: impl IntoIterator<Item = CatalogRecord>,
    ) -> Result<Self, CatalogModelError> {
        let mut catalog = Self::default();
        for record in records {
            catalog.insert(record)?;
        }
        Ok(catalog)
    }

    pub fn insert(&mut self, record: CatalogRecord) -> Result<(), CatalogModelError> {
        let id = record.id.clone();
        if self.records.insert(id.clone(), record).is_some() {
            return Err(CatalogModelError::DuplicateCapability(id));
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &CapabilityId) -> Option<&CatalogRecord> {
        self.records.get(id)
    }

    #[must_use]
    pub fn find_provider_view(
        &self,
        provider: ProviderId,
        discovery_id: &str,
    ) -> Option<&CatalogRecord> {
        self.records.values().find(|record| {
            record
                .provider_views
                .iter()
                .any(|view| view.provider == provider && view.discovery_id == discovery_id)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogModelError {
    InvalidCapabilityId(String),
    DuplicateCapability(CapabilityId),
}

impl fmt::Display for CatalogModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapabilityId(value) => {
                write!(formatter, "invalid capability id: {value:?}")
            }
            Self::DuplicateCapability(id) => write!(formatter, "duplicate capability id: {id}"),
        }
    }
}

impl std::error::Error for CatalogModelError {}
