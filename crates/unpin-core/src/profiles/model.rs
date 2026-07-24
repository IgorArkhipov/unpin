use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    catalog::{
        CapabilityId, CapabilityTrustRequirements, Catalog, CatalogRecord, ContributionControl,
        ToolNamespace, stable_hash,
    },
    providers::ProviderId,
};

pub const PROFILE_DEFINITION_VERSION: u32 = 1;
pub const COMPILED_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROFILE_DEFINITION_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDefinition {
    pub version: u32,
    pub id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<CapabilityId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_members: BTreeMap<ProviderId, Vec<CapabilityId>>,
}

impl ProfileDefinition {
    pub fn from_json(raw: &str) -> Result<Self, ProfileValidationError> {
        if raw.len() > MAX_PROFILE_DEFINITION_BYTES {
            return Err(ProfileValidationError::DefinitionTooLarge {
                actual: raw.len(),
                maximum: MAX_PROFILE_DEFINITION_BYTES,
            });
        }
        let value: Value =
            serde_json::from_str(raw).map_err(|error| ProfileValidationError::InvalidJson {
                message: error.to_string(),
            })?;
        reject_non_exportable_fields(&value)?;
        serde_json::from_value(value).map_err(|error| ProfileValidationError::InvalidJson {
            message: error.to_string(),
        })
    }

    pub fn to_export_json(&self) -> Result<String, ProfileValidationError> {
        validate_definition_shape(self)?;
        let value =
            serde_json::to_value(self).map_err(|error| ProfileValidationError::Serialization {
                message: error.to_string(),
            })?;
        reject_non_exportable_fields(&value)?;
        serde_json::to_string_pretty(&value).map_err(|error| {
            ProfileValidationError::Serialization {
                message: error.to_string(),
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileSourceScope {
    Global,
    Repository,
    Workspace,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProfileOrigin {
    pub scope: ProfileSourceScope,
    pub definition_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberSelectionKind {
    Generic,
    ProviderSpecific,
    AtomicContribution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProfileMember {
    pub capability_id: CapabilityId,
    pub capability_fingerprint: String,
    pub catalog_origin_key: String,
    pub providers: BTreeSet<ProviderId>,
    pub selection_kind: MemberSelectionKind,
    pub trust_requirements: CapabilityTrustRequirements,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contributed_by: Option<CapabilityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProfileRevision {
    pub schema_version: u32,
    pub profile_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub origin: CompiledProfileOrigin,
    pub digest: String,
    pub members: Vec<CompiledProfileMember>,
    pub requires_local_review: bool,
}

impl CompiledProfileRevision {
    pub fn verify_digest(&self) -> Result<(), ProfileValidationError> {
        let actual = compiled_digest(
            self.schema_version,
            &self.profile_id,
            &self.display_name,
            self.description.as_deref(),
            &self.origin,
            &self.members,
            self.requires_local_review,
        )?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(ProfileValidationError::DigestMismatch {
                expected: self.digest.clone(),
                actual,
            })
        }
    }

    #[must_use]
    pub fn supports_provider(&self, provider: ProviderId) -> bool {
        self.members
            .iter()
            .any(|member| member.providers.contains(&provider))
    }

    pub fn members_for_provider(
        &self,
        provider: ProviderId,
    ) -> impl Iterator<Item = &CompiledProfileMember> {
        self.members
            .iter()
            .filter(move |member| member.providers.contains(&provider))
    }

    #[must_use]
    pub fn selects(&self, capability_id: &CapabilityId, provider: ProviderId) -> bool {
        self.members_for_provider(provider)
            .any(|member| &member.capability_id == capability_id)
    }
}

#[derive(Debug, Clone, Default)]
struct MembershipIntent {
    generic: bool,
    providers: BTreeSet<ProviderId>,
    atomic_parent: Option<CapabilityId>,
}

pub fn compile_profile(
    definition: &ProfileDefinition,
    catalog: &Catalog,
    source_scope: ProfileSourceScope,
) -> Result<CompiledProfileRevision, ProfileValidationError> {
    validate_definition_shape(definition)?;
    let normalized = normalized_definition(definition);
    let definition_digest = stable_hash(&serde_json::to_vec(&normalized).map_err(|error| {
        ProfileValidationError::Serialization {
            message: error.to_string(),
        }
    })?);
    let origin = CompiledProfileOrigin {
        scope: source_scope,
        definition_digest,
    };

    let mut intents = BTreeMap::<CapabilityId, MembershipIntent>::new();
    for capability_id in &definition.members {
        validate_capability_id(capability_id)?;
        let intent = intents.entry(capability_id.clone()).or_default();
        if intent.generic || !intent.providers.is_empty() {
            return Err(ProfileValidationError::DuplicateMember {
                capability_id: capability_id.clone(),
            });
        }
        intent.generic = true;
    }
    for (provider, capability_ids) in &definition.provider_members {
        let mut provider_seen = BTreeSet::new();
        for capability_id in capability_ids {
            validate_capability_id(capability_id)?;
            if !provider_seen.insert(capability_id.clone()) {
                return Err(ProfileValidationError::DuplicateMember {
                    capability_id: capability_id.clone(),
                });
            }
            let intent = intents.entry(capability_id.clone()).or_default();
            if intent.generic || !intent.providers.insert(*provider) {
                return Err(ProfileValidationError::DuplicateMember {
                    capability_id: capability_id.clone(),
                });
            }
        }
    }

    for capability_id in intents.keys() {
        if catalog.get(capability_id).is_none() {
            return Err(ProfileValidationError::MissingCapability {
                capability_id: capability_id.clone(),
            });
        }
    }
    expand_and_validate_atomic_contributions(&mut intents, catalog)?;

    let selected = intents.keys().cloned().collect::<BTreeSet<_>>();
    let mut resolved_providers = BTreeMap::<CapabilityId, BTreeSet<ProviderId>>::new();
    for (capability_id, intent) in &intents {
        let record = catalog
            .get(capability_id)
            .expect("selected catalog capability was validated");
        resolved_providers.insert(
            capability_id.clone(),
            resolve_member_providers(capability_id, intent, record)?,
        );
    }
    for capability_id in &selected {
        let record = catalog
            .get(capability_id)
            .expect("selected catalog capability was validated");
        for dependency in &record.dependencies {
            if !selected.contains(dependency) {
                return Err(ProfileValidationError::MissingDependency {
                    capability_id: capability_id.clone(),
                    dependency_id: dependency.clone(),
                });
            }
            let capability_providers = &resolved_providers[capability_id];
            let dependency_providers = &resolved_providers[dependency];
            if let Some(provider) = capability_providers
                .iter()
                .find(|provider| !dependency_providers.contains(provider))
            {
                return Err(ProfileValidationError::DependencyProviderMismatch {
                    capability_id: capability_id.clone(),
                    dependency_id: dependency.clone(),
                    provider: *provider,
                });
            }
        }
    }

    let mut members = Vec::new();
    for (capability_id, intent) in &intents {
        let record = catalog
            .get(capability_id)
            .expect("selected catalog capability was validated");
        let providers = resolved_providers[capability_id].clone();
        members.push(CompiledProfileMember {
            capability_id: capability_id.clone(),
            capability_fingerprint: record.fingerprint.clone(),
            catalog_origin_key: record.origin.canonical_key.clone(),
            providers,
            selection_kind: if intent.atomic_parent.is_some() {
                MemberSelectionKind::AtomicContribution
            } else if intent.generic {
                MemberSelectionKind::Generic
            } else {
                MemberSelectionKind::ProviderSpecific
            },
            trust_requirements: record.trust_requirements.clone(),
            contributed_by: intent.atomic_parent.clone(),
        });
    }
    validate_namespaces(&members, catalog)?;
    validate_hook_conflicts(&members, catalog)?;
    let requires_local_review = members
        .iter()
        .any(|member| member.trust_requirements.requires_local_review());
    let digest = compiled_digest(
        COMPILED_PROFILE_SCHEMA_VERSION,
        &normalized.id,
        &normalized.display_name,
        normalized.description.as_deref(),
        &origin,
        &members,
        requires_local_review,
    )?;

    Ok(CompiledProfileRevision {
        schema_version: COMPILED_PROFILE_SCHEMA_VERSION,
        profile_id: normalized.id,
        display_name: normalized.display_name,
        description: normalized.description,
        origin,
        digest,
        members,
        requires_local_review,
    })
}

fn validate_definition_shape(definition: &ProfileDefinition) -> Result<(), ProfileValidationError> {
    if definition.version != PROFILE_DEFINITION_VERSION {
        return Err(ProfileValidationError::UnsupportedVersion {
            version: definition.version,
        });
    }
    if !valid_profile_id(&definition.id) {
        return Err(ProfileValidationError::InvalidProfileId {
            profile_id: definition.id.clone(),
        });
    }
    if definition.display_name.trim().is_empty()
        || definition.display_name.chars().any(char::is_control)
    {
        return Err(ProfileValidationError::InvalidDisplayName);
    }
    if definition
        .description
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control) || looks_machine_path(value))
    {
        return Err(ProfileValidationError::NonExportableValue {
            field: "description".to_string(),
        });
    }
    for capability_id in definition.members.iter().chain(
        definition
            .provider_members
            .values()
            .flat_map(|members| members.iter()),
    ) {
        validate_capability_id(capability_id)?;
    }
    Ok(())
}

pub(crate) fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !matches!(value, "." | "..")
}

fn validate_capability_id(id: &CapabilityId) -> Result<(), ProfileValidationError> {
    if CapabilityId::new(id.as_str()).is_err() {
        Err(ProfileValidationError::InvalidCapabilityId {
            capability_id: id.clone(),
        })
    } else {
        Ok(())
    }
}

fn normalized_definition(definition: &ProfileDefinition) -> ProfileDefinition {
    let mut normalized = definition.clone();
    normalized.members.sort();
    for members in normalized.provider_members.values_mut() {
        members.sort();
    }
    normalized
}

fn expand_and_validate_atomic_contributions(
    intents: &mut BTreeMap<CapabilityId, MembershipIntent>,
    catalog: &Catalog,
) -> Result<(), ProfileValidationError> {
    loop {
        let mut pending = BTreeMap::<CapabilityId, MembershipIntent>::new();
        for parent in catalog.records.values() {
            let atomic_children = parent
                .contributions
                .iter()
                .filter(|edge| edge.control == ContributionControl::Atomic)
                .map(|edge| edge.capability_id.clone())
                .collect::<Vec<_>>();
            if atomic_children.is_empty() {
                continue;
            }
            let Some(parent_intent) = intents.get(&parent.id).cloned() else {
                if let Some(child) = atomic_children
                    .iter()
                    .find(|child| intents.contains_key(*child))
                {
                    return Err(ProfileValidationError::AtomicContributionSplit {
                        parent_id: parent.id.clone(),
                        capability_id: child.clone(),
                    });
                }
                continue;
            };
            for child in atomic_children {
                if let Some(child_intent) = intents.get(&child) {
                    if child_intent.atomic_parent.as_ref() != Some(&parent.id)
                        || child_intent.generic != parent_intent.generic
                        || child_intent.providers != parent_intent.providers
                    {
                        return Err(ProfileValidationError::AtomicContributionSplit {
                            parent_id: parent.id.clone(),
                            capability_id: child,
                        });
                    }
                    continue;
                }
                let requested = MembershipIntent {
                    generic: parent_intent.generic,
                    providers: parent_intent.providers.clone(),
                    atomic_parent: Some(parent.id.clone()),
                };
                if let Some(existing) = pending.insert(child.clone(), requested)
                    && existing.atomic_parent.as_ref() != Some(&parent.id)
                {
                    return Err(ProfileValidationError::AtomicContributionSplit {
                        parent_id: parent.id.clone(),
                        capability_id: child,
                    });
                }
            }
        }
        if pending.is_empty() {
            break;
        }
        intents.extend(pending);
    }
    Ok(())
}

fn resolve_member_providers(
    capability_id: &CapabilityId,
    intent: &MembershipIntent,
    record: &CatalogRecord,
) -> Result<BTreeSet<ProviderId>, ProfileValidationError> {
    let providers = if intent.generic {
        record
            .provider_views
            .iter()
            .map(|view| view.provider)
            .collect::<BTreeSet<_>>()
    } else {
        intent.providers.clone()
    };
    if providers.is_empty() {
        return Err(ProfileValidationError::NoProviderViews {
            capability_id: capability_id.clone(),
        });
    }
    for provider in &providers {
        if !record.supports_provider(*provider) {
            return Err(ProfileValidationError::IncompatibleProviderMapping {
                capability_id: capability_id.clone(),
                provider: *provider,
            });
        }
    }
    Ok(providers)
}

fn validate_namespaces(
    members: &[CompiledProfileMember],
    catalog: &Catalog,
) -> Result<(), ProfileValidationError> {
    let mut names = BTreeMap::<(ProviderId, ToolNamespace), CapabilityId>::new();
    for member in members {
        let record = catalog
            .get(&member.capability_id)
            .expect("compiled member exists in catalog");
        let Some(namespace) = &record.tool_namespace else {
            continue;
        };
        for provider in &member.providers {
            let key = (*provider, namespace.clone());
            if let Some(existing) = names.insert(key, member.capability_id.clone())
                && existing != member.capability_id
            {
                return Err(ProfileValidationError::AmbiguousToolNamespace {
                    provider: *provider,
                    namespace: namespace.clone(),
                    first: existing,
                    second: member.capability_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_hook_conflicts(
    members: &[CompiledProfileMember],
    catalog: &Catalog,
) -> Result<(), ProfileValidationError> {
    let mut policies = BTreeMap::<(ProviderId, String), CapabilityId>::new();
    for member in members {
        let record = catalog
            .get(&member.capability_id)
            .expect("compiled member exists in catalog");
        let Some(conflict_key) = &record.hook_conflict_key else {
            continue;
        };
        for provider in &member.providers {
            let key = (*provider, conflict_key.clone());
            if let Some(existing) = policies.insert(key, member.capability_id.clone())
                && existing != member.capability_id
            {
                return Err(ProfileValidationError::ConflictingHookPolicy {
                    provider: *provider,
                    conflict_key: conflict_key.clone(),
                    first: existing,
                    second: member.capability_id.clone(),
                });
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompiledDigestBody<'a> {
    schema_version: u32,
    profile_id: &'a str,
    display_name: &'a str,
    description: Option<&'a str>,
    origin: &'a CompiledProfileOrigin,
    members: &'a [CompiledProfileMember],
    requires_local_review: bool,
}

fn compiled_digest(
    schema_version: u32,
    profile_id: &str,
    display_name: &str,
    description: Option<&str>,
    origin: &CompiledProfileOrigin,
    members: &[CompiledProfileMember],
    requires_local_review: bool,
) -> Result<String, ProfileValidationError> {
    let body = CompiledDigestBody {
        schema_version,
        profile_id,
        display_name,
        description,
        origin,
        members,
        requires_local_review,
    };
    let bytes =
        serde_json::to_vec(&body).map_err(|error| ProfileValidationError::Serialization {
            message: error.to_string(),
        })?;
    Ok(stable_hash(&bytes))
}

fn reject_non_exportable_fields(value: &Value) -> Result<(), ProfileValidationError> {
    fn visit(value: &Value, field: &str) -> Result<(), ProfileValidationError> {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let normalized = key
                        .chars()
                        .filter(|character| character.is_ascii_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect::<String>();
                    if [
                        "credential",
                        "secret",
                        "password",
                        "token",
                        "keychain",
                        "trust",
                        "backup",
                        "runtime",
                        "lease",
                        "sourcepath",
                        "statepath",
                        "originalpath",
                    ]
                    .iter()
                    .any(|forbidden| normalized.contains(forbidden))
                    {
                        return Err(ProfileValidationError::NonExportableField {
                            field: key.clone(),
                        });
                    }
                    visit(value, key)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, field)?;
                }
            }
            Value::String(value) if looks_machine_path(value) => {
                return Err(ProfileValidationError::NonExportableValue {
                    field: field.to_string(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    visit(value, "root")
}

fn looks_machine_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || value.starts_with("file://")
        || value.starts_with("\\\\")
        || (value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileValidationError {
    DefinitionTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidJson {
        message: String,
    },
    Serialization {
        message: String,
    },
    UnsupportedVersion {
        version: u32,
    },
    InvalidProfileId {
        profile_id: String,
    },
    InvalidDisplayName,
    InvalidCapabilityId {
        capability_id: CapabilityId,
    },
    DuplicateMember {
        capability_id: CapabilityId,
    },
    MissingCapability {
        capability_id: CapabilityId,
    },
    MissingDependency {
        capability_id: CapabilityId,
        dependency_id: CapabilityId,
    },
    DependencyProviderMismatch {
        capability_id: CapabilityId,
        dependency_id: CapabilityId,
        provider: ProviderId,
    },
    NoProviderViews {
        capability_id: CapabilityId,
    },
    IncompatibleProviderMapping {
        capability_id: CapabilityId,
        provider: ProviderId,
    },
    AtomicContributionSplit {
        parent_id: CapabilityId,
        capability_id: CapabilityId,
    },
    AmbiguousToolNamespace {
        provider: ProviderId,
        namespace: ToolNamespace,
        first: CapabilityId,
        second: CapabilityId,
    },
    ConflictingHookPolicy {
        provider: ProviderId,
        conflict_key: String,
        first: CapabilityId,
        second: CapabilityId,
    },
    NonExportableField {
        field: String,
    },
    NonExportableValue {
        field: String,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ProfileValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitionTooLarge { actual, maximum } => write!(
                formatter,
                "profile definition is too large: {actual} bytes exceeds {maximum}"
            ),
            Self::InvalidJson { message } => write!(formatter, "invalid profile JSON: {message}"),
            Self::Serialization { message } => {
                write!(formatter, "profile serialization failed: {message}")
            }
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported profile version: {version}")
            }
            Self::InvalidProfileId { profile_id } => {
                write!(formatter, "invalid profile id: {profile_id:?}")
            }
            Self::InvalidDisplayName => formatter.write_str("profile display name is invalid"),
            Self::InvalidCapabilityId { capability_id } => {
                write!(formatter, "invalid capability id: {capability_id}")
            }
            Self::DuplicateMember { capability_id } => {
                write!(formatter, "duplicate profile member: {capability_id}")
            }
            Self::MissingCapability { capability_id } => {
                write!(formatter, "profile capability is missing: {capability_id}")
            }
            Self::MissingDependency {
                capability_id,
                dependency_id,
            } => write!(
                formatter,
                "profile capability {capability_id} requires {dependency_id}"
            ),
            Self::DependencyProviderMismatch {
                capability_id,
                dependency_id,
                provider,
            } => write!(
                formatter,
                "profile capability {capability_id} requires {dependency_id} for {}",
                provider.as_str()
            ),
            Self::NoProviderViews { capability_id } => {
                write!(
                    formatter,
                    "capability has no provider views: {capability_id}"
                )
            }
            Self::IncompatibleProviderMapping {
                capability_id,
                provider,
            } => write!(
                formatter,
                "capability {capability_id} has no {} provider view",
                provider.as_str()
            ),
            Self::AtomicContributionSplit {
                parent_id,
                capability_id,
            } => write!(
                formatter,
                "atomic contribution {capability_id} cannot be selected separately from {parent_id}"
            ),
            Self::AmbiguousToolNamespace {
                provider,
                namespace,
                first,
                second,
            } => write!(
                formatter,
                "ambiguous {} tool {}.{} between {first} and {second}",
                provider.as_str(),
                namespace.namespace,
                namespace.name
            ),
            Self::ConflictingHookPolicy {
                provider,
                conflict_key,
                first,
                second,
            } => write!(
                formatter,
                "conflicting {} hook policy {conflict_key} between {first} and {second}",
                provider.as_str()
            ),
            Self::NonExportableField { field } => {
                write!(formatter, "profile field is not exportable: {field}")
            }
            Self::NonExportableValue { field } => {
                write!(formatter, "profile field contains a machine path: {field}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "compiled profile digest mismatch: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for ProfileValidationError {}
