use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    config::normalize_path,
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryMutability, DiscoveryOutput,
    },
    hooks::HookActionType,
};

pub mod adoption;
pub mod model;
pub mod store;

pub use model::*;

const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const MAX_DECLARED_CONTRIBUTIONS: usize = 512;
const MAX_CONTRIBUTION_NAME_BYTES: usize = 256;

impl Catalog {
    pub fn from_discovery(output: &DiscoveryOutput) -> Result<Self, CatalogModelError> {
        let mut grouped = BTreeMap::<String, Vec<&DiscoveryItem>>::new();
        for item in &output.items {
            grouped.entry(group_key(item)).or_default().push(item);
        }

        let mut catalog = Catalog::default();
        for (key, mut items) in grouped {
            items.sort_by_key(|item| (item.provider, item.id.as_str()));
            catalog.insert(record_from_items(&key, &items)?)?;
        }
        derive_plugin_contributions(&mut catalog);
        Ok(catalog)
    }
}

fn group_key(item: &DiscoveryItem) -> String {
    if item.is_shared_skill_source() {
        format!(
            "shared-skill:{}",
            canonical_origin_path(Path::new(&item.source_path)).display()
        )
    } else {
        format!("{}:{}", item.provider.as_str(), item.id)
    }
}

fn canonical_origin_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| normalize_path(path))
}

fn record_from_items(
    group_key: &str,
    items: &[&DiscoveryItem],
) -> Result<CatalogRecord, CatalogModelError> {
    let first = items[0];
    let kind = capability_kind(first);
    let id = CapabilityId::new(format!(
        "catalog:{}:{}",
        kind.as_str(),
        &stable_hash(group_key.as_bytes())[..24]
    ))?;
    let canonical_path = canonical_origin_path(Path::new(&first.source_path));
    let mut provider_views = Vec::new();
    let mut fingerprints = BTreeSet::new();
    let mut active = false;
    for item in items {
        active |= item.enabled;
        if let Some(fingerprint) = &item.source_fingerprint {
            fingerprints.insert(fingerprint.clone());
        }
        provider_views.push(ProviderView {
            provider: item.provider,
            discovery_id: item.id.clone(),
            layer: item.layer,
            enabled: item.enabled,
            mutability: item.mutability.into(),
            source_path: item.source_path.clone(),
            state_path: item.state_path.clone(),
            source_fingerprint: item.source_fingerprint.clone(),
        });
    }
    provider_views.sort_by(|left, right| {
        (
            left.provider,
            left.layer.as_str(),
            left.discovery_id.as_str(),
        )
            .cmp(&(
                right.provider,
                right.layer.as_str(),
                right.discovery_id.as_str(),
            ))
    });
    let fingerprint_material = format!(
        "{group_key}\n{}\n{}",
        kind.as_str(),
        fingerprints.into_iter().collect::<Vec<_>>().join("\n")
    );
    let ownership = ownership_for(items.iter().map(|item| item.mutability));
    let canonical_key = stable_hash(group_key.as_bytes());
    let tool_namespace = (kind == CapabilityKind::McpTool).then(|| ToolNamespace {
        namespace: first
            .id
            .rsplit_once(':')
            .map(|(namespace, _)| namespace)
            .filter(|namespace| !namespace.is_empty())
            .unwrap_or_else(|| first.provider.as_str())
            .to_string(),
        name: first.display_name.clone(),
    });

    Ok(CatalogRecord {
        id,
        kind,
        display_name: first.display_name.clone(),
        origin: CanonicalOrigin {
            canonical_key,
            source_path: canonical_path.to_string_lossy().into_owned(),
            state_path: first.state_path.clone(),
            scope: if items
                .iter()
                .any(|item| item.layer == crate::discovery::DiscoveryLayer::Global)
            {
                CapabilityScope::Global
            } else {
                CapabilityScope::Repository
            },
            source_fingerprint: first.source_fingerprint.clone(),
        },
        ownership,
        fingerprint: stable_hash(fingerprint_material.as_bytes()),
        lifecycle: CapabilityLifecycle::discovered(active),
        state_evidence: CapabilityStateEvidence {
            observation: "provider-discovery".to_string(),
            observed_enabled: active,
        },
        trust_requirements: trust_for(kind, Some(first)),
        provider_views,
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace,
        hook_conflict_key: first.hook.as_ref().map(|hook| {
            format!(
                "{}:{}:{}",
                first.provider.as_str(),
                hook.native_event,
                hook.matcher
            )
        }),
    })
}

fn capability_kind(item: &DiscoveryItem) -> CapabilityKind {
    match item.kind {
        DiscoveryKind::Skill => CapabilityKind::Skill,
        DiscoveryKind::Mcp if item.category == DiscoveryCategory::Tool => CapabilityKind::McpTool,
        DiscoveryKind::Mcp => CapabilityKind::McpServer,
        DiscoveryKind::Plugin => CapabilityKind::Plugin,
        DiscoveryKind::Agent => CapabilityKind::Agent,
        DiscoveryKind::Hook => CapabilityKind::Hook,
        DiscoveryKind::Setting => CapabilityKind::Setting,
    }
}

fn ownership_for(mutabilities: impl Iterator<Item = DiscoveryMutability>) -> CapabilityOwnership {
    let mut ownership = CapabilityOwnership::External;
    for mutability in mutabilities {
        match mutability {
            DiscoveryMutability::ReadWrite => return CapabilityOwnership::User,
            DiscoveryMutability::ReadOnly => ownership = CapabilityOwnership::ProviderManaged,
            DiscoveryMutability::Unsupported => {}
        }
    }
    ownership
}

fn trust_for(kind: CapabilityKind, item: Option<&DiscoveryItem>) -> CapabilityTrustRequirements {
    match kind {
        CapabilityKind::McpServer => CapabilityTrustRequirements {
            executable_review: true,
            network_review: true,
            credential_authorization: true,
        },
        CapabilityKind::McpTool => CapabilityTrustRequirements {
            executable_review: false,
            network_review: true,
            credential_authorization: true,
        },
        CapabilityKind::Plugin => CapabilityTrustRequirements {
            executable_review: true,
            network_review: true,
            credential_authorization: true,
        },
        CapabilityKind::Hook => {
            let action_type = item
                .and_then(|item| item.hook.as_ref())
                .map_or(HookActionType::Unknown, |hook| hook.action_type);
            CapabilityTrustRequirements {
                executable_review: matches!(
                    action_type,
                    HookActionType::Command
                        | HookActionType::Prompt
                        | HookActionType::Agent
                        | HookActionType::ProviderComponent
                        | HookActionType::Unknown
                ),
                network_review: matches!(
                    action_type,
                    HookActionType::Http | HookActionType::McpTool
                ),
                credential_authorization: action_type == HookActionType::McpTool,
            }
        }
        CapabilityKind::Skill | CapabilityKind::Agent | CapabilityKind::Setting => {
            CapabilityTrustRequirements::default()
        }
    }
}

fn derive_plugin_contributions(catalog: &mut Catalog) {
    let plugin_ids = catalog
        .records
        .values()
        .filter(|record| record.kind == CapabilityKind::Plugin)
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();

    for plugin_id in plugin_ids {
        let Some(plugin) = catalog.records.get(&plugin_id).cloned() else {
            continue;
        };
        let manifest = read_static_manifest(Path::new(&plugin.origin.source_path));
        let declared = match manifest {
            ManifestRead::Declared(declared) => declared,
            ManifestRead::Invalid => {
                mark_unknown_contributions(
                    catalog,
                    &plugin_id,
                    CatalogWarningCode::InvalidManifest,
                );
                continue;
            }
            ManifestRead::Oversized => {
                mark_unknown_contributions(
                    catalog,
                    &plugin_id,
                    CatalogWarningCode::OversizedManifest,
                );
                continue;
            }
            ManifestRead::DynamicOrUnknown => {
                mark_unknown_contributions(
                    catalog,
                    &plugin_id,
                    CatalogWarningCode::UnknownDynamicContributions,
                );
                continue;
            }
        };

        if declared.is_empty() {
            if let Some(parent) = catalog.records.get_mut(&plugin_id) {
                parent.contributions.clear();
                parent.atomic_unknown_contributions = false;
            }
            continue;
        }

        let mut edges = Vec::new();
        for contribution in declared {
            let child = synthetic_contribution(&plugin, contribution);
            let child_id = child.id.clone();
            if !catalog.records.contains_key(&child_id) {
                catalog.records.insert(child_id.clone(), child);
            }
            edges.push(ContributionEdge {
                capability_id: child_id,
                control: ContributionControl::Atomic,
            });
        }
        edges.sort_by(|left, right| left.capability_id.cmp(&right.capability_id));
        edges.dedup_by(|left, right| left.capability_id == right.capability_id);
        if let Some(parent) = catalog.records.get_mut(&plugin_id) {
            parent.contributions = edges;
            parent.atomic_unknown_contributions = false;
        }
    }
}

fn mark_unknown_contributions(
    catalog: &mut Catalog,
    plugin_id: &CapabilityId,
    code: CatalogWarningCode,
) {
    if let Some(parent) = catalog.records.get_mut(plugin_id) {
        parent.atomic_unknown_contributions = true;
    }
    catalog.warnings.push(CatalogWarning {
        capability_id: plugin_id.clone(),
        code,
    });
}

#[derive(Debug)]
struct DeclaredContribution {
    kind: CapabilityKind,
    name: String,
}

enum ManifestRead {
    Declared(Vec<DeclaredContribution>),
    DynamicOrUnknown,
    Invalid,
    Oversized,
}

fn read_static_manifest(path: &Path) -> ManifestRead {
    if path.extension().and_then(|value| value.to_str()) != Some("json") {
        return ManifestRead::DynamicOrUnknown;
    }
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return ManifestRead::DynamicOrUnknown;
    };
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return ManifestRead::DynamicOrUnknown;
    }
    let Ok(mut file) = File::open(path) else {
        return ManifestRead::Invalid;
    };
    let Ok(opened_metadata) = file.metadata() else {
        return ManifestRead::Invalid;
    };
    let Ok(current_path_metadata) = fs::symlink_metadata(path) else {
        return ManifestRead::Invalid;
    };
    if current_path_metadata.file_type().is_symlink() || !current_path_metadata.is_file() {
        return ManifestRead::Invalid;
    }
    match crate::fs_support::path_matches_open_file(path, &file) {
        Ok(true) => {}
        Ok(false) => return ManifestRead::Invalid,
        Err(error) if error.kind() == ErrorKind::Unsupported => {
            return ManifestRead::DynamicOrUnknown;
        }
        Err(_) => return ManifestRead::Invalid,
    }
    if opened_metadata.len() > MAX_MANIFEST_BYTES {
        return ManifestRead::Oversized;
    }
    let mut raw = Vec::new();
    let Ok(_) = file
        .by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
    else {
        return ManifestRead::Invalid;
    };
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return ManifestRead::Oversized;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
        return ManifestRead::Invalid;
    };
    match declared_contributions(&value) {
        Ok(declared) => ManifestRead::Declared(declared),
        Err(()) => ManifestRead::Invalid,
    }
}

fn declared_contributions(value: &Value) -> Result<Vec<DeclaredContribution>, ()> {
    let root = value.get("contributions").unwrap_or(value);
    let mut declared = Vec::new();
    for (key, kind) in [
        ("skills", CapabilityKind::Skill),
        ("mcpServers", CapabilityKind::McpServer),
        ("tools", CapabilityKind::McpTool),
        ("hooks", CapabilityKind::Hook),
    ] {
        let Some(value) = root.get(key) else {
            continue;
        };
        for name in contribution_names(value)? {
            declared.push(DeclaredContribution { kind, name });
            if declared.len() > MAX_DECLARED_CONTRIBUTIONS {
                return Err(());
            }
        }
    }
    declared.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
    declared.dedup_by(|left, right| left.kind == right.kind && left.name == right.name);
    Ok(declared)
}

fn contribution_names(value: &Value) -> Result<Vec<String>, ()> {
    let names = match value {
        Value::Array(values) => values
            .iter()
            .filter_map(|value| {
                value.as_str().map(ToOwned::to_owned).or_else(|| {
                    value
                        .get("id")
                        .or_else(|| value.get("name"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
            })
            .filter(|value| !value.trim().is_empty())
            .collect(),
        Value::Object(values) => values.keys().cloned().collect(),
        Value::String(value) if !value.trim().is_empty() => vec![value.clone()],
        _ => Vec::new(),
    };
    if names.len() > MAX_DECLARED_CONTRIBUTIONS
        || names.iter().any(|name| {
            name.trim().is_empty()
                || name.len() > MAX_CONTRIBUTION_NAME_BYTES
                || name.chars().any(char::is_control)
        })
    {
        Err(())
    } else {
        Ok(names)
    }
}

fn synthetic_contribution(
    plugin: &CatalogRecord,
    contribution: DeclaredContribution,
) -> CatalogRecord {
    let identity = format!(
        "{}#{}:{}",
        plugin.id,
        contribution.kind.as_str(),
        contribution.name
    );
    let id = CapabilityId::new(format!(
        "catalog:{}:{}",
        contribution.kind.as_str(),
        &stable_hash(identity.as_bytes())[..24]
    ))
    .expect("generated catalog id is valid");
    let provider_views = plugin
        .provider_views
        .iter()
        .map(|view| ProviderView {
            provider: view.provider,
            discovery_id: format!(
                "{}#{}:{}",
                view.discovery_id,
                contribution.kind.as_str(),
                contribution.name
            ),
            layer: view.layer,
            enabled: view.enabled,
            mutability: CapabilityMutability::ReadOnly,
            source_path: view.source_path.clone(),
            state_path: view.state_path.clone(),
            source_fingerprint: view.source_fingerprint.clone(),
        })
        .collect();
    let tool_namespace = (contribution.kind == CapabilityKind::McpTool).then(|| ToolNamespace {
        namespace: plugin.id.as_str().to_string(),
        name: contribution.name.clone(),
    });
    let hook_conflict_key =
        (contribution.kind == CapabilityKind::Hook).then(|| contribution.name.clone());

    CatalogRecord {
        id: id.clone(),
        kind: contribution.kind,
        display_name: contribution.name,
        origin: CanonicalOrigin {
            canonical_key: stable_hash(identity.as_bytes()),
            source_path: plugin.origin.source_path.clone(),
            state_path: plugin.origin.state_path.clone(),
            scope: plugin.origin.scope,
            source_fingerprint: plugin.origin.source_fingerprint.clone(),
        },
        ownership: plugin.ownership,
        fingerprint: stable_hash(format!("{}:{}", plugin.fingerprint, id.as_str()).as_bytes()),
        lifecycle: plugin.lifecycle.clone(),
        state_evidence: plugin.state_evidence.clone(),
        trust_requirements: trust_for(contribution.kind, None),
        provider_views,
        dependencies: vec![plugin.id.clone()],
        contributions: Vec::new(),
        contributed_by: Some(plugin.id.clone()),
        atomic_unknown_contributions: false,
        tool_namespace,
        hook_conflict_key,
    }
}

pub(crate) fn stable_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
