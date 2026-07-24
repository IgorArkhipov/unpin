use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::catalog::stable_hash;

use super::{GatewayError, UpstreamIdentity, UpstreamToolRegistration};

const MAX_PUBLIC_TOOL_NAME_BYTES: usize = 128;
const RESERVED_TOOL_NAMES: &[&str] = &[
    "unpin_search_skills",
    "unpin_load_skill",
    "unpin_get_session_status",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
    #[serde(skip)]
    registration: Option<UpstreamToolRegistration>,
}

impl ProjectedTool {
    #[must_use]
    pub fn registration_id(&self) -> Option<&str> {
        self.registration
            .as_ref()
            .map(|registration| registration.registration_id.as_str())
    }

    #[must_use]
    pub fn upstream_name(&self) -> Option<&str> {
        self.registration
            .as_ref()
            .map(|registration| registration.descriptor.name.as_str())
    }

    #[must_use]
    pub fn upstream_identity(&self) -> Option<&UpstreamIdentity> {
        self.registration
            .as_ref()
            .map(|registration| &registration.identity)
    }

    #[must_use]
    pub fn credential_key_id(&self) -> Option<&str> {
        self.registration
            .as_ref()
            .and_then(|registration| registration.credential.as_ref())
            .map(|credential| credential.key_id.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, ProjectedTool>,
}

impl ToolRegistry {
    pub(crate) fn compile(
        mut registrations: Vec<UpstreamToolRegistration>,
        maximum_tools: usize,
        maximum_schema_bytes: usize,
        maximum_schema_depth: usize,
        maximum_descriptor_bytes: usize,
    ) -> Result<Self, GatewayError> {
        if registrations.len() > maximum_tools {
            return Err(GatewayError::ToolLimitExceeded);
        }
        registrations.sort_by(|left, right| left.registration_id.cmp(&right.registration_id));
        let mut registration_ids = BTreeSet::new();
        let mut bases = BTreeMap::<String, usize>::new();
        for registration in &registrations {
            registration.verify()?;
            if !registration_ids.insert(registration.registration_id.clone()) {
                return Err(GatewayError::InvalidToolDescriptor);
            }
            validate_descriptor(registration, maximum_schema_bytes, maximum_schema_depth)?;
            let base = truncate_ascii(&tool_name_base(registration), MAX_PUBLIC_TOOL_NAME_BYTES);
            *bases.entry(base).or_default() += 1;
        }

        let mut tools = BTreeMap::new();
        for registration in registrations {
            let raw_base = tool_name_base(&registration);
            let base = truncate_ascii(&raw_base, MAX_PUBLIC_TOOL_NAME_BYTES);
            let collides = bases.get(&base).copied().unwrap_or_default() > 1
                || RESERVED_TOOL_NAMES.contains(&base.as_str());
            let name = if collides {
                suffixed_name(&raw_base, &registration.registration_id)
            } else {
                base
            };
            let descriptor = &registration.descriptor;
            let projected = ProjectedTool {
                name: name.clone(),
                title: descriptor.title.clone(),
                description: descriptor.description.clone(),
                input_schema: descriptor.input_schema.clone(),
                output_schema: descriptor.output_schema.clone(),
                annotations: descriptor.annotations.clone(),
                execution: descriptor.execution.clone(),
                registration: Some(registration),
            };
            if tools.insert(name, projected).is_some() {
                return Err(GatewayError::InvalidToolDescriptor);
            }
        }
        let registry = Self { tools };
        let descriptor_bytes = serde_json::to_vec(&registry.descriptors())
            .map_err(|error| GatewayError::Serialization(error.to_string()))?;
        if descriptor_bytes.len() > maximum_descriptor_bytes {
            return Err(GatewayError::ResponseLimitExceeded);
        }
        Ok(registry)
    }

    #[must_use]
    pub fn descriptors(&self) -> Vec<ProjectedTool> {
        self.tools.values().cloned().collect()
    }

    #[must_use]
    pub fn get(&self, public_name: &str) -> Option<&ProjectedTool> {
        self.tools.get(public_name)
    }

    /// Resolves one profile-selected upstream target without exposing hidden
    /// registrations. Duplicate target aliases are treated as ambiguous.
    #[must_use]
    pub fn resolve_upstream(&self, server_id: &str, tool_name: &str) -> Option<&ProjectedTool> {
        let mut matching = self.tools.values().filter(|projected| {
            projected
                .upstream_identity()
                .is_some_and(|identity| identity.server_id == server_id)
                && projected.upstream_name() == Some(tool_name)
        });
        let resolved = matching.next()?;
        if matching.next().is_some() {
            None
        } else {
            Some(resolved)
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

fn validate_descriptor(
    registration: &UpstreamToolRegistration,
    maximum_schema_bytes: usize,
    maximum_schema_depth: usize,
) -> Result<(), GatewayError> {
    for value in [
        Some(&registration.descriptor.input_schema),
        registration.descriptor.output_schema.as_ref(),
        registration.descriptor.annotations.as_ref(),
        registration.descriptor.execution.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| GatewayError::Serialization(error.to_string()))?;
        if bytes.len() > maximum_schema_bytes
            || !json_shape_within(value, maximum_schema_depth, 4_096)
        {
            return Err(GatewayError::SchemaLimitExceeded);
        }
    }
    validate_annotations(registration.descriptor.annotations.as_ref())?;
    validate_execution(registration.descriptor.execution.as_ref())?;
    Ok(())
}

fn validate_annotations(value: Option<&Value>) -> Result<(), GatewayError> {
    let Some(Value::Object(object)) = value else {
        return if value.is_none() {
            Ok(())
        } else {
            Err(GatewayError::InvalidToolDescriptor)
        };
    };
    for (key, value) in object {
        let valid = match key.as_str() {
            "title" => value
                .as_str()
                .is_some_and(|title| valid_presentation_text(title, 512)),
            "readOnlyHint" | "destructiveHint" | "idempotentHint" | "openWorldHint" => {
                value.is_boolean()
            }
            _ => false,
        };
        if !valid {
            return Err(GatewayError::InvalidToolDescriptor);
        }
    }
    Ok(())
}

fn valid_presentation_text(value: &str, maximum: usize) -> bool {
    value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn validate_execution(value: Option<&Value>) -> Result<(), GatewayError> {
    let Some(Value::Object(object)) = value else {
        return if value.is_none() {
            Ok(())
        } else {
            Err(GatewayError::InvalidToolDescriptor)
        };
    };
    if object.len() > 1
        || object.get("taskSupport").is_some_and(|value| {
            !matches!(value.as_str(), Some("forbidden" | "optional" | "required"))
        })
        || object.keys().any(|key| key != "taskSupport")
    {
        Err(GatewayError::InvalidToolDescriptor)
    } else {
        Ok(())
    }
}

pub(crate) fn json_shape_within(value: &Value, maximum_depth: usize, maximum_nodes: usize) -> bool {
    let mut pending = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > maximum_nodes || depth > maximum_depth {
            return false;
        }
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn tool_name_base(registration: &UpstreamToolRegistration) -> String {
    format!(
        "{}__{}",
        sanitize_name(&registration.identity.server_id),
        sanitize_name(&registration.descriptor.name)
    )
}

fn sanitize_name(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut previous_separator = false;
    for byte in value.bytes() {
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.');
        let next = if allowed { byte as char } else { '_' };
        if next == '_' && previous_separator {
            continue;
        }
        previous_separator = next == '_';
        result.push(next);
    }
    let result = result.trim_matches(['_', '.', '-']);
    if result.is_empty() {
        "tool".to_string()
    } else {
        result.to_string()
    }
}

fn suffixed_name(base: &str, registration_id: &str) -> String {
    let digest = stable_hash(registration_id.as_bytes());
    let suffix = format!("__{}", &digest[..12]);
    let maximum_base = MAX_PUBLIC_TOOL_NAME_BYTES.saturating_sub(suffix.len());
    format!("{}{}", truncate_ascii(base, maximum_base), suffix)
}

fn truncate_ascii(value: &str, maximum: usize) -> String {
    value.bytes().take(maximum).map(char::from).collect()
}
