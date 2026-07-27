use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::UnpinConfig,
    discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryRoots, ProviderId},
    encode_lower_hex, is_lower_hex_digest,
    state::workspace::{WorkspaceIdentity, resolve_workspace_identity},
};

pub const GROUP_DEFINITION_SCHEMA_VERSION: u8 = 1;
pub const MAX_GROUP_DEFINITION_BYTES: usize = 256 * 1024;
pub const MAX_GROUP_MEMBERS: usize = 256;
pub const MAX_GROUP_MEMBER_ID_BYTES: usize = 2_048;
pub const MAX_GROUP_NAME_BYTES: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupScope {
    Personal,
    Repository,
}

impl GroupScope {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Repository => "repository",
        }
    }
}

impl fmt::Display for GroupScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for GroupScope {
    type Err = GroupValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "personal" => Ok(Self::Personal),
            "repository" => Ok(Self::Repository),
            _ => Err(GroupValidationError::InvalidScope(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupMemberIdentity {
    pub provider: ProviderId,
    pub kind: DiscoveryKind,
    pub category: DiscoveryCategory,
    pub layer: DiscoveryLayer,
    pub id: String,
}

impl GroupMemberIdentity {
    pub fn new(
        provider: ProviderId,
        kind: DiscoveryKind,
        category: DiscoveryCategory,
        layer: DiscoveryLayer,
        id: impl Into<String>,
    ) -> Result<Self, GroupValidationError> {
        let identity = Self {
            provider,
            kind,
            category,
            layer,
            id: id.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), GroupValidationError> {
        if self.id.is_empty()
            || self.id.len() > MAX_GROUP_MEMBER_ID_BYTES
            || self.id.chars().any(char::is_control)
        {
            return Err(GroupValidationError::InvalidMemberId {
                id: self.id.clone(),
                maximum: MAX_GROUP_MEMBER_ID_BYTES,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.provider.as_str(),
            self.layer.as_str(),
            self.kind.as_str(),
            self.category.as_str(),
            self.id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupDefinitionV1 {
    pub schema_version: u8,
    pub name: String,
    pub members: Vec<GroupMemberIdentity>,
}

impl GroupDefinitionV1 {
    pub fn new(
        name: impl Into<String>,
        members: Vec<GroupMemberIdentity>,
    ) -> Result<Self, GroupValidationError> {
        let mut definition = Self {
            schema_version: GROUP_DEFINITION_SCHEMA_VERSION,
            name: name.into(),
            members,
        };
        definition.canonicalize_and_validate()?;
        Ok(definition)
    }

    pub fn canonicalize_and_validate(&mut self) -> Result<(), GroupValidationError> {
        valid_group_name(&self.name)?;
        if self.schema_version != GROUP_DEFINITION_SCHEMA_VERSION {
            return Err(GroupValidationError::UnsupportedSchema {
                actual: self.schema_version,
                expected: GROUP_DEFINITION_SCHEMA_VERSION,
            });
        }
        if self.members.is_empty() {
            return Err(GroupValidationError::EmptyMembers);
        }
        if self.members.len() > MAX_GROUP_MEMBERS {
            return Err(GroupValidationError::TooManyMembers {
                actual: self.members.len(),
                maximum: MAX_GROUP_MEMBERS,
            });
        }
        for member in &self.members {
            member.validate()?;
        }
        self.members.sort();
        let original_len = self.members.len();
        self.members.dedup();
        if self.members.len() != original_len {
            return Err(GroupValidationError::DuplicateMembers);
        }
        let serialized = serde_json::to_vec(self)
            .map_err(|error| GroupValidationError::Serialization(error.to_string()))?;
        if serialized.len() > MAX_GROUP_DEFINITION_BYTES {
            return Err(GroupValidationError::DefinitionTooLarge {
                actual: serialized.len(),
                maximum: MAX_GROUP_DEFINITION_BYTES,
            });
        }
        Ok(())
    }

    pub fn revision(
        &self,
        binding: &GroupContextBinding,
    ) -> Result<GroupRevision, GroupValidationError> {
        let mut canonical = self.clone();
        canonical.canonicalize_and_validate()?;
        let bytes = serde_json::to_vec(&(canonical, binding))
            .map_err(|error| GroupValidationError::Serialization(error.to_string()))?;
        Ok(GroupRevision::from_bytes(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupRevision(String);

impl GroupRevision {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(encode_lower_hex(&Sha256::digest(bytes)))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, GroupValidationError> {
        let value = value.into();
        if !is_lower_hex_digest(&value) {
            return Err(GroupValidationError::InvalidRevision(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum GroupContextBinding {
    Global,
    Repository {
        repository_key: String,
    },
    Workspace {
        repository_key: String,
        workspace_key: String,
    },
}

#[derive(Debug, Clone)]
pub struct GroupAccessContext {
    app_state_root: PathBuf,
    workspace: WorkspaceIdentity,
    workspace_physical_identity: PhysicalDirectoryIdentity,
    discovery_roots: DiscoveryRoots,
    provider_scope: Option<ProviderId>,
    allowed_layers: BTreeSet<DiscoveryLayer>,
}

impl GroupAccessContext {
    pub fn from_config(
        config: &UnpinConfig,
        roots: &DiscoveryRoots,
        provider_scope: Option<ProviderId>,
        allowed_layers: Option<BTreeSet<DiscoveryLayer>>,
    ) -> Result<Self, GroupAccessContextError> {
        Self::from_runtime(
            &config.app_state_root,
            &config.project_root,
            roots,
            provider_scope,
            allowed_layers,
        )
    }

    pub fn from_runtime(
        app_state_root: impl AsRef<Path>,
        project_root: impl AsRef<Path>,
        roots: &DiscoveryRoots,
        provider_scope: Option<ProviderId>,
        allowed_layers: Option<BTreeSet<DiscoveryLayer>>,
    ) -> Result<Self, GroupAccessContextError> {
        let workspace = resolve_workspace_identity(project_root.as_ref())
            .map_err(GroupAccessContextError::Workspace)?;
        let app_state_root =
            canonical_or_absolute(app_state_root.as_ref()).map_err(GroupAccessContextError::Io)?;
        let configured_project =
            canonical_or_absolute(project_root.as_ref()).map_err(GroupAccessContextError::Io)?;
        if configured_project != workspace.canonical_root {
            return Err(GroupAccessContextError::ProjectRootMismatch);
        }
        let workspace_physical_identity =
            PhysicalDirectoryIdentity::read(&workspace.canonical_root)
                .map_err(GroupAccessContextError::Io)?;
        let allowed_layers = allowed_layers
            .unwrap_or_else(|| BTreeSet::from([DiscoveryLayer::Global, DiscoveryLayer::Project]));
        if allowed_layers.is_empty() {
            return Err(GroupAccessContextError::NoAllowedLayers);
        }
        Ok(Self {
            app_state_root,
            workspace,
            workspace_physical_identity,
            discovery_roots: roots.clone(),
            provider_scope,
            allowed_layers,
        })
    }

    #[must_use]
    pub fn app_state_root(&self) -> &Path {
        &self.app_state_root
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace.canonical_root
    }

    #[must_use]
    pub fn repository_key(&self) -> &str {
        &self.workspace.repository_key
    }

    #[must_use]
    pub fn workspace_key(&self) -> &str {
        &self.workspace.workspace_key
    }

    pub(crate) fn workspace_incarnation_matches(&self) -> Result<bool, std::io::Error> {
        PhysicalDirectoryIdentity::read(self.workspace_root())
            .map(|current| current == self.workspace_physical_identity)
    }

    #[must_use]
    pub fn discovery_roots(&self) -> &DiscoveryRoots {
        &self.discovery_roots
    }

    #[must_use]
    pub fn provider_scope(&self) -> Option<ProviderId> {
        self.provider_scope
    }

    #[must_use]
    pub fn allowed_layers(&self) -> &BTreeSet<DiscoveryLayer> {
        &self.allowed_layers
    }

    #[must_use]
    pub fn binding_for_personal(&self, definition: &GroupDefinitionV1) -> GroupContextBinding {
        self.binding_for(definition, GroupScope::Personal)
    }

    #[must_use]
    pub fn binding_for_repository(&self, definition: &GroupDefinitionV1) -> GroupContextBinding {
        self.binding_for(definition, GroupScope::Repository)
    }

    fn binding_for(
        &self,
        definition: &GroupDefinitionV1,
        scope: GroupScope,
    ) -> GroupContextBinding {
        if definition
            .members
            .iter()
            .any(|member| member.layer == DiscoveryLayer::Project)
        {
            GroupContextBinding::Workspace {
                repository_key: self.workspace.repository_key.clone(),
                workspace_key: self.workspace.workspace_key.clone(),
            }
        } else {
            match scope {
                GroupScope::Personal => GroupContextBinding::Global,
                GroupScope::Repository => GroupContextBinding::Repository {
                    repository_key: self.workspace.repository_key.clone(),
                },
            }
        }
    }

    #[must_use]
    pub fn is_binding_compatible(&self, binding: &GroupContextBinding) -> bool {
        match binding {
            GroupContextBinding::Global => true,
            GroupContextBinding::Repository { repository_key } => {
                repository_key == &self.workspace.repository_key
            }
            GroupContextBinding::Workspace {
                repository_key,
                workspace_key,
            } => {
                repository_key == &self.workspace.repository_key
                    && workspace_key == &self.workspace.workspace_key
            }
        }
    }

    #[must_use]
    pub fn admits_member(&self, member: &GroupMemberIdentity) -> bool {
        self.provider_scope
            .is_none_or(|provider| provider == member.provider)
            && self.allowed_layers.contains(&member.layer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalDirectoryIdentity {
    #[cfg(windows)]
    windows: crate::fs_support::WindowsFileIdentity,
    #[cfg(not(windows))]
    first: u64,
    #[cfg(not(windows))]
    second: u64,
}

impl PhysicalDirectoryIdentity {
    fn read(path: &Path) -> Result<Self, std::io::Error> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::other(
                "workspace root is not a physical directory",
            ));
        }
        #[cfg(windows)]
        {
            crate::fs_support::windows_path_identity(path).map(|windows| Self { windows })
        }
        #[cfg(not(windows))]
        {
            physical_directory_identity(&metadata)
        }
    }
}

#[cfg(unix)]
fn physical_directory_identity(
    metadata: &std::fs::Metadata,
) -> Result<PhysicalDirectoryIdentity, std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    Ok(PhysicalDirectoryIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

#[cfg(not(any(unix, windows)))]
fn physical_directory_identity(
    metadata: &std::fs::Metadata,
) -> Result<PhysicalDirectoryIdentity, std::io::Error> {
    use std::time::UNIX_EPOCH;

    let created = metadata
        .created()?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            std::io::Error::other("workspace root creation time predates the Unix epoch")
        })?;
    Ok(PhysicalDirectoryIdentity {
        first: created.as_secs(),
        second: u64::from(created.subsec_nanos()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRecord {
    pub scope: GroupScope,
    pub qualified_name: String,
    pub definition: GroupDefinitionV1,
    pub binding: GroupContextBinding,
    pub revision: GroupRevision,
}

impl GroupRecord {
    pub fn new(
        scope: GroupScope,
        definition: GroupDefinitionV1,
        binding: GroupContextBinding,
    ) -> Result<Self, GroupValidationError> {
        let revision = definition.revision(&binding)?;
        let qualified_name = format!("{}:{}", scope.as_str(), definition.name);
        Ok(Self {
            scope,
            qualified_name,
            definition,
            binding,
            revision,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GroupScope>,
    pub name: String,
}

impl GroupRef {
    pub fn unqualified(name: impl Into<String>) -> Result<Self, GroupValidationError> {
        let name = name.into();
        valid_group_name(&name)?;
        Ok(Self { scope: None, name })
    }

    pub fn qualified(
        scope: GroupScope,
        name: impl Into<String>,
    ) -> Result<Self, GroupValidationError> {
        let name = name.into();
        valid_group_name(&name)?;
        Ok(Self {
            scope: Some(scope),
            name,
        })
    }

    pub fn parse(value: &str) -> Result<Self, GroupValidationError> {
        match value.split_once(':') {
            Some((scope, name)) => Self::qualified(GroupScope::from_str(scope)?, name),
            None => Self::unqualified(value),
        }
    }
}

#[derive(Debug)]
pub enum GroupAccessContextError {
    Workspace(crate::state::workspace::WorkspaceIdentityError),
    Io(std::io::Error),
    ProjectRootMismatch,
    NoAllowedLayers,
}

impl fmt::Display for GroupAccessContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "group access context I/O failed: {error}"),
            Self::ProjectRootMismatch => {
                formatter.write_str("trusted project root does not match workspace identity")
            }
            Self::NoAllowedLayers => {
                formatter.write_str("group access context must allow at least one layer")
            }
        }
    }
}

impl std::error::Error for GroupAccessContextError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupValidationError {
    InvalidName(String),
    InvalidScope(String),
    UnsupportedSchema { actual: u8, expected: u8 },
    EmptyMembers,
    TooManyMembers { actual: usize, maximum: usize },
    InvalidMemberId { id: String, maximum: usize },
    DuplicateMembers,
    DefinitionTooLarge { actual: usize, maximum: usize },
    InvalidRevision(String),
    Serialization(String),
}

impl fmt::Display for GroupValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(formatter, "invalid group name: {name:?}"),
            Self::InvalidScope(scope) => write!(formatter, "invalid group scope: {scope:?}"),
            Self::UnsupportedSchema { actual, expected } => {
                write!(
                    formatter,
                    "unsupported group schema {actual}; expected {expected}"
                )
            }
            Self::EmptyMembers => formatter.write_str("group must contain at least one member"),
            Self::TooManyMembers { actual, maximum } => {
                write!(
                    formatter,
                    "group has {actual} members; maximum is {maximum}"
                )
            }
            Self::InvalidMemberId { id, maximum } => {
                write!(
                    formatter,
                    "invalid group member id {id:?}; maximum is {maximum} bytes"
                )
            }
            Self::DuplicateMembers => formatter.write_str("group contains duplicate members"),
            Self::DefinitionTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "group definition is {actual} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidRevision(revision) => {
                write!(formatter, "invalid group revision: {revision:?}")
            }
            Self::Serialization(error) => write!(formatter, "group serialization failed: {error}"),
        }
    }
}

impl std::error::Error for GroupValidationError {}

pub fn valid_group_name(name: &str) -> Result<(), GroupValidationError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_GROUP_NAME_BYTES
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(GroupValidationError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn canonical_or_absolute(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.exists() {
        path.canonicalize()
    } else if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir().map(|cwd| cwd.join(path))
    }
}
