use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    catalog::CapabilityId,
    profiles::{CompiledProfileMember, ProfileSourceScope},
    providers::ProviderId,
};

use super::WorkflowControl;

pub const WORKFLOW_DEFINITION_VERSION: u32 = 1;
pub const COMPILED_WORKFLOW_SCHEMA_VERSION: u32 = 1;
pub const COMPILED_WORKFLOW_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MAX_WORKFLOW_DEFINITION_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowModeDefinition {
    pub name: String,
    pub profile_id: String,
}

impl WorkflowModeDefinition {
    #[must_use]
    pub fn new(name: impl Into<String>, profile_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            profile_id: profile_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinition {
    pub version: u32,
    pub id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub baseline_profile_id: String,
    pub entry_mode: String,
    pub modes: Vec<WorkflowModeDefinition>,
}

impl WorkflowDefinition {
    pub fn from_json(raw: &str) -> Result<Self, WorkflowValidationError> {
        if raw.len() > MAX_WORKFLOW_DEFINITION_BYTES {
            return Err(WorkflowValidationError::DefinitionTooLarge {
                actual: raw.len(),
                maximum: MAX_WORKFLOW_DEFINITION_BYTES,
            });
        }
        let value: Value = serde_json::from_str(raw)
            .map_err(|error| WorkflowValidationError::InvalidJson(error.to_string()))?;
        reject_protected_roots(&value)?;
        let definition: Self = serde_json::from_value(value)
            .map_err(|error| WorkflowValidationError::InvalidJson(error.to_string()))?;
        definition.validate()?;
        Ok(definition)
    }

    pub fn to_export_json(&self) -> Result<String, WorkflowValidationError> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|error| WorkflowValidationError::Serialization(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), WorkflowValidationError> {
        if self.version != WORKFLOW_DEFINITION_VERSION {
            return Err(WorkflowValidationError::UnsupportedVersion(self.version));
        }
        validate_id("workflow", &self.id)?;
        validate_id("baseline profile", &self.baseline_profile_id)?;
        validate_id("entry mode", &self.entry_mode)?;
        if self.display_name.trim().is_empty() || self.display_name.chars().any(char::is_control) {
            return Err(WorkflowValidationError::InvalidDisplayName);
        }
        if self
            .description
            .as_deref()
            .is_some_and(|value| value.chars().any(char::is_control) || looks_machine_path(value))
        {
            return Err(WorkflowValidationError::InvalidDescription);
        }
        if self.modes.is_empty() {
            return Err(WorkflowValidationError::NoModes);
        }
        let mut names = std::collections::BTreeSet::new();
        for mode in &self.modes {
            validate_id("mode", &mode.name)?;
            validate_id("mode profile", &mode.profile_id)?;
            if !names.insert(mode.name.clone()) {
                return Err(WorkflowValidationError::DuplicateMode(mode.name.clone()));
            }
        }
        if !names.contains(&self.entry_mode) {
            return Err(WorkflowValidationError::MissingEntryMode(
                self.entry_mode.clone(),
            ));
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| WorkflowValidationError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_WORKFLOW_DEFINITION_BYTES {
            return Err(WorkflowValidationError::DefinitionTooLarge {
                actual: bytes.len(),
                maximum: MAX_WORKFLOW_DEFINITION_BYTES,
            });
        }
        Ok(())
    }

    pub(crate) fn canonical(&self) -> Self {
        let mut canonical = self.clone();
        canonical
            .modes
            .sort_by(|left, right| left.name.cmp(&right.name));
        canonical
    }

    pub fn definition_digest(&self) -> Result<String, WorkflowValidationError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.canonical())
            .map_err(|error| WorkflowValidationError::Serialization(error.to_string()))?;
        Ok(domain_digest(b"unpin.workflow.definition.v1", &bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledWorkflowProfileRevision {
    pub schema_version: u32,
    pub profile_id: String,
    pub digest: String,
    pub members: Vec<CompiledProfileMember>,
    pub authored_member_count: usize,
}

impl CompiledWorkflowProfileRevision {
    pub(crate) fn compile(
        profile_id: String,
        members: Vec<CompiledProfileMember>,
    ) -> Result<Self, WorkflowValidationError> {
        let authored_member_count = members.len();
        let digest = workflow_profile_digest(
            COMPILED_WORKFLOW_PROFILE_SCHEMA_VERSION,
            &profile_id,
            &members,
            authored_member_count,
        )?;
        Ok(Self {
            schema_version: COMPILED_WORKFLOW_PROFILE_SCHEMA_VERSION,
            profile_id,
            digest,
            members,
            authored_member_count,
        })
    }

    pub fn verify_digest(&self) -> Result<(), WorkflowValidationError> {
        if self.schema_version != COMPILED_WORKFLOW_PROFILE_SCHEMA_VERSION {
            return Err(WorkflowValidationError::UnsupportedCompiledSchema(
                self.schema_version,
            ));
        }
        if self.authored_member_count != self.members.len() {
            return Err(WorkflowValidationError::AuthoredMemberCountMismatch {
                profile_id: self.profile_id.clone(),
                expected: self.members.len(),
                actual: self.authored_member_count,
            });
        }
        if self
            .members
            .windows(2)
            .any(|members| members[0].capability_id.as_str() >= members[1].capability_id.as_str())
        {
            return Err(WorkflowValidationError::UnsortedProfileMembers {
                profile_id: self.profile_id.clone(),
            });
        }
        let actual = workflow_profile_digest(
            self.schema_version,
            &self.profile_id,
            &self.members,
            self.authored_member_count,
        )?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(WorkflowValidationError::DigestMismatch {
                expected: self.digest.clone(),
                actual,
            })
        }
    }

    #[must_use]
    pub fn contains(&self, capability_id: &CapabilityId) -> bool {
        self.members
            .iter()
            .any(|member| &member.capability_id == capability_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledWorkflowMode {
    pub profile_id: String,
    pub profile_digest: String,
    pub effective_profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledWorkflowRevision {
    pub schema_version: u32,
    pub workflow_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub origin: ProfileSourceScope,
    pub definition_digest: String,
    pub provider: ProviderId,
    pub baseline_profile_id: String,
    pub baseline_profile_digest: String,
    pub entry_mode: String,
    pub modes: BTreeMap<String, CompiledWorkflowMode>,
    pub effective_profiles: BTreeMap<String, CompiledWorkflowProfileRevision>,
    pub maximum_envelope: CompiledWorkflowProfileRevision,
    pub capability_lock_digest: String,
    pub catalog_fingerprints: BTreeMap<CapabilityId, String>,
    pub system_controls: Vec<WorkflowControl>,
    pub digest: String,
}

impl CompiledWorkflowRevision {
    pub fn verify_digest(&self) -> Result<(), WorkflowValidationError> {
        if self.schema_version != COMPILED_WORKFLOW_SCHEMA_VERSION {
            return Err(WorkflowValidationError::UnsupportedCompiledSchema(
                self.schema_version,
            ));
        }
        if self.system_controls != WorkflowControl::ALL {
            return Err(WorkflowValidationError::InvalidSystemControls);
        }
        if !self.modes.contains_key(&self.entry_mode) {
            return Err(WorkflowValidationError::MissingEntryMode(
                self.entry_mode.clone(),
            ));
        }
        if !self.modes.keys().eq(self.effective_profiles.keys()) {
            return Err(WorkflowValidationError::ModeProfileKeyMismatch);
        }
        self.maximum_envelope.verify_digest()?;
        for (mode_name, mode) in &self.modes {
            let profile = &self.effective_profiles[mode_name];
            profile.verify_digest()?;
            if mode.effective_profile_digest != profile.digest {
                return Err(WorkflowValidationError::EffectiveProfileDigestMismatch {
                    mode: mode_name.clone(),
                    expected: mode.effective_profile_digest.clone(),
                    actual: profile.digest.clone(),
                });
            }
            for member in &profile.members {
                let Some(maximum_member) = self
                    .maximum_envelope
                    .members
                    .iter()
                    .find(|maximum| maximum.capability_id == member.capability_id)
                else {
                    return Err(WorkflowValidationError::EnvelopeNotSuperset);
                };
                if maximum_member != member {
                    return Err(WorkflowValidationError::ConflictingCapability(
                        member.capability_id.clone(),
                    ));
                }
            }
        }
        let expected_catalog_fingerprints = self
            .maximum_envelope
            .members
            .iter()
            .map(|member| {
                (
                    member.capability_id.clone(),
                    member.capability_fingerprint.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if self.catalog_fingerprints != expected_catalog_fingerprints {
            return Err(WorkflowValidationError::CatalogFingerprintsMismatch);
        }
        let actual = self.computed_digest()?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(WorkflowValidationError::DigestMismatch {
                expected: self.digest.clone(),
                actual,
            })
        }
    }

    pub(crate) fn computed_digest(&self) -> Result<String, WorkflowValidationError> {
        let mut unsigned = self.clone();
        unsigned.digest.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| WorkflowValidationError::Serialization(error.to_string()))?;
        Ok(domain_digest(b"unpin.workflow.compiled.v1", &bytes))
    }
}

fn workflow_profile_digest(
    schema_version: u32,
    profile_id: &str,
    members: &[CompiledProfileMember],
    authored_member_count: usize,
) -> Result<String, WorkflowValidationError> {
    let bytes = serde_json::to_vec(&(schema_version, profile_id, members, authored_member_count))
        .map_err(|error| WorkflowValidationError::Serialization(error.to_string()))?;
    Ok(domain_digest(b"unpin.workflow.profile.v1", &bytes))
}

pub(crate) fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    crate::encode_lower_hex(&hasher.finalize())
}

fn validate_id(label: &'static str, value: &str) -> Result<(), WorkflowValidationError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(WorkflowValidationError::InvalidIdentifier {
            label,
            value: value.to_string(),
        })
    } else {
        Ok(())
    }
}

fn reject_protected_roots(value: &Value) -> Result<(), WorkflowValidationError> {
    const PROTECTED: &[&str] = &[
        "projectroot",
        "appstateroot",
        "cursorroot",
        "discoveryroot",
        "discoveryroots",
        "providermutationroot",
        "providermutationroots",
        "approvalstate",
        "policystate",
        "backuproot",
        "backups",
        "sessionroot",
        "sessions",
        "auditroot",
        "auditstate",
    ];
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let normalized = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if PROTECTED.contains(&normalized.as_str()) {
                    return Err(WorkflowValidationError::ProtectedAuthorityRoot(key.clone()));
                }
                reject_protected_roots(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_protected_roots(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn looks_machine_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("file://")
        || value.starts_with("\\\\")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowValidationError {
    DefinitionTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidJson(String),
    Serialization(String),
    UnsupportedVersion(u32),
    UnsupportedCompiledSchema(u32),
    InvalidIdentifier {
        label: &'static str,
        value: String,
    },
    InvalidDisplayName,
    InvalidDescription,
    NoModes,
    DuplicateMode(String),
    MissingEntryMode(String),
    MissingProfile(String),
    ProfileIdMismatch {
        expected: String,
        actual: String,
    },
    ProfileInvalid {
        profile_id: String,
        message: String,
    },
    LockInvalid(String),
    LockProviderMismatch {
        expected: ProviderId,
        actual: ProviderId,
    },
    MissingCapability(CapabilityId),
    StaleCapability(CapabilityId),
    UnsupportedCapability {
        capability_id: CapabilityId,
        kind: String,
    },
    ConflictingCapability(CapabilityId),
    HardEnabledOutsideEnvelope(CapabilityId),
    EnvelopeNotSuperset,
    InvalidSystemControls,
    ModeProfileKeyMismatch,
    EffectiveProfileDigestMismatch {
        mode: String,
        expected: String,
        actual: String,
    },
    CatalogFingerprintsMismatch,
    UnsortedProfileMembers {
        profile_id: String,
    },
    AuthoredMemberCountMismatch {
        profile_id: String,
        expected: usize,
        actual: usize,
    },
    ProtectedAuthorityRoot(String),
    DigestMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for WorkflowValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitionTooLarge { actual, maximum } => write!(
                formatter,
                "workflow definition is too large: {actual} bytes exceeds {maximum}"
            ),
            Self::InvalidJson(message) => write!(formatter, "invalid workflow JSON: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "workflow serialization failed: {message}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported workflow version: {version}")
            }
            Self::UnsupportedCompiledSchema(version) => {
                write!(formatter, "unsupported compiled workflow schema: {version}")
            }
            Self::InvalidIdentifier { label, value } => {
                write!(formatter, "invalid {label} identifier: {value:?}")
            }
            Self::InvalidDisplayName => formatter.write_str("workflow display name is invalid"),
            Self::InvalidDescription => formatter.write_str("workflow description is invalid"),
            Self::NoModes => formatter.write_str("workflow must define at least one mode"),
            Self::DuplicateMode(mode) => write!(formatter, "duplicate workflow mode: {mode}"),
            Self::MissingEntryMode(mode) => {
                write!(formatter, "workflow entry mode is missing: {mode}")
            }
            Self::MissingProfile(profile) => {
                write!(formatter, "workflow profile is missing: {profile}")
            }
            Self::ProfileIdMismatch { expected, actual } => write!(
                formatter,
                "workflow profile id mismatch: expected {expected}, found {actual}"
            ),
            Self::ProfileInvalid {
                profile_id,
                message,
            } => write!(
                formatter,
                "workflow profile {profile_id} is invalid: {message}"
            ),
            Self::LockInvalid(message) => write!(
                formatter,
                "workflow capability locks are invalid: {message}"
            ),
            Self::LockProviderMismatch { expected, actual } => write!(
                formatter,
                "workflow capability lock provider mismatch: expected {}, found {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::MissingCapability(capability) => {
                write!(formatter, "workflow capability is missing: {capability}")
            }
            Self::StaleCapability(capability) => write!(
                formatter,
                "workflow capability changed since profile compilation: {capability}"
            ),
            Self::UnsupportedCapability {
                capability_id,
                kind,
            } => write!(
                formatter,
                "workflow capability {capability_id} cannot be gateway-routed ({kind})"
            ),
            Self::ConflictingCapability(capability) => write!(
                formatter,
                "workflow capability has conflicting normalized records: {capability}"
            ),
            Self::HardEnabledOutsideEnvelope(capability) => write!(
                formatter,
                "hard-enabled capability is outside the authored workflow envelope: {capability}"
            ),
            Self::EnvelopeNotSuperset => {
                formatter.write_str("workflow maximum envelope is not a superset of every mode")
            }
            Self::InvalidSystemControls => {
                formatter.write_str("compiled workflow controls do not match the typed allowlist")
            }
            Self::ModeProfileKeyMismatch => formatter
                .write_str("compiled workflow mode keys do not match effective profile keys"),
            Self::EffectiveProfileDigestMismatch {
                mode,
                expected,
                actual,
            } => write!(
                formatter,
                "compiled workflow mode {mode} references effective profile {expected}, found {actual}"
            ),
            Self::CatalogFingerprintsMismatch => formatter.write_str(
                "compiled workflow catalog fingerprints do not match the maximum envelope",
            ),
            Self::UnsortedProfileMembers { profile_id } => write!(
                formatter,
                "compiled workflow profile members are not unique and sorted: {profile_id}"
            ),
            Self::AuthoredMemberCountMismatch {
                profile_id,
                expected,
                actual,
            } => write!(
                formatter,
                "compiled workflow profile authored count mismatch for {profile_id}: expected {expected}, found {actual}"
            ),
            Self::ProtectedAuthorityRoot(field) => write!(
                formatter,
                "repository workflow definition cannot select protected authority root: {field}"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "workflow digest mismatch: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for WorkflowValidationError {}
