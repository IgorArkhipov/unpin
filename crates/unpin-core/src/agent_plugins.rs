use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryWarning, ProviderId, source_fingerprint,
    },
    fs_support::path_matches_open_file,
    groups::GroupMemberIdentity,
};

pub const AGENT_PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
pub const AGENT_PLUGIN_MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";

const MAX_PACKAGE_FILE_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 512;
const MAX_COMPONENT_NAME_BYTES: usize = 256;
const MAX_JSON_DEPTH: usize = 32;
const MAX_PUBLIC_STRING_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPluginComponentKind {
    Skill,
    Mcp,
}

impl AgentPluginComponentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPluginComponentDisposition {
    Available,
    Invalid,
    Unsupported,
    ReadError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPluginState {
    On,
    Off,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentPluginAccess {
    Actionable,
    DiagnosticsOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginSupportRow {
    pub provider: ProviderId,
    pub layer: DiscoveryLayer,
    pub access: AgentPluginAccess,
    pub root_contract: &'static str,
    pub reason: &'static str,
}

pub const AGENT_PLUGIN_SUPPORT: &[AgentPluginSupportRow] = &[
    AgentPluginSupportRow {
        provider: ProviderId::Claude,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Actionable,
        root_contract: "claude_global/plugins/cache/<marketplace>/<plugin>/<version>",
        reason: "standard package metadata can bind to native enabledPlugins state",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Claude,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Actionable,
        root_contract: "claude_global/plugins/cache/<marketplace>/<plugin>/<version>",
        reason: "standard package metadata can bind to project enabledPlugins state",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Codex,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Actionable,
        root_contract: "codex_global/plugins/cache/<marketplace>/<plugin>/<version>",
        reason: "standard package metadata can bind to native plugins.<id>.enabled state",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Codex,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "current Codex plugin installation enablement is user scoped",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Cursor,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "current adapter recognizes provider-specific local plugin manifests only",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Cursor,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "no fixture-backed standard package installation root",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Pi,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "Pi package references do not expose standard package roots",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Pi,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "Pi package references do not expose standard package roots",
    },
    AgentPluginSupportRow {
        provider: ProviderId::OpenCode,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "OpenCode plugin references do not expose standard package roots",
    },
    AgentPluginSupportRow {
        provider: ProviderId::OpenCode,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "OpenCode plugin references do not expose standard package roots",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Zed,
        layer: DiscoveryLayer::Global,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "Zed plugins remain outside Unpin provider scope",
    },
    AgentPluginSupportRow {
        provider: ProviderId::Zed,
        layer: DiscoveryLayer::Project,
        access: AgentPluginAccess::Unsupported,
        root_contract: "none",
        reason: "Zed plugins remain outside Unpin provider scope",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginAuthor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginManifestView {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<AgentPluginAuthor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginComponentView {
    pub kind: AgentPluginComponentKind,
    pub name: String,
    pub disposition: AgentPluginComponentDisposition,
    pub source_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginActivationView {
    pub identity: GroupMemberIdentity,
    pub enabled: bool,
    pub mutability: DiscoveryMutability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginInstance {
    pub instance_id: String,
    pub provider: ProviderId,
    pub layer: DiscoveryLayer,
    pub manifest: AgentPluginManifestView,
    pub state: AgentPluginState,
    pub access: AgentPluginAccess,
    pub components: Vec<AgentPluginComponentView>,
    pub activations: Vec<AgentPluginActivationView>,
    pub projection_fingerprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

impl AgentPluginInstance {
    pub(crate) fn control_activations(&self) -> impl Iterator<Item = &AgentPluginActivationView> {
        self.activations.iter().filter(|activation| {
            self.access != AgentPluginAccess::DiagnosticsOnly
                || activation.mutability != DiscoveryMutability::ReadWrite
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPluginSummary {
    pub logical_id: String,
    pub name: String,
    pub component_signature: String,
    pub projection_fingerprint: String,
    pub state: AgentPluginState,
    pub access: AgentPluginAccess,
    pub instances: Vec<AgentPluginInstance>,
}

impl AgentPluginSummary {
    pub(crate) fn refresh_rollup(&mut self) {
        self.instances.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.layer.cmp(&right.layer))
                .then_with(|| left.instance_id.cmp(&right.instance_id))
        });
        self.state = roll_up_state(self.instances.iter().map(|instance| instance.state));
        self.access = roll_up_access(self.instances.iter().map(|instance| instance.access));
        self.projection_fingerprint = source_fingerprint(
            &self
                .instances
                .iter()
                .map(|instance| instance.projection_fingerprint.as_str())
                .collect::<Vec<_>>()
                .join("\0"),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentAssociationKey(String);

impl ComponentAssociationKey {
    fn new(provider: ProviderId, layer: DiscoveryLayer, package_root_identity: &str) -> Self {
        Self(source_fingerprint(
            format!(
                "{}\0{}\0{}",
                provider.as_str(),
                layer.as_str(),
                package_root_identity
            )
            .as_str(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPluginMetadata {
    pub provider: ProviderId,
    pub layer: DiscoveryLayer,
    pub package_root_identity: String,
    pub native_plugin_id: String,
    pub manifest: AgentPluginManifestView,
    pub manifest_source_fingerprint: String,
    pub components: Vec<AgentPluginComponentView>,
    pub activation_key: Option<ComponentAssociationKey>,
    pub blockers: Vec<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentPluginActivationCandidate {
    pub identity: GroupMemberIdentity,
    pub native_plugin_id: String,
}

pub(crate) fn activation_candidates(
    provider: ProviderId,
    items: &[DiscoveryItem],
) -> Vec<AgentPluginActivationCandidate> {
    items
        .iter()
        .filter(|item| {
            item.provider == provider
                && item.kind == DiscoveryKind::Plugin
                && item.category == DiscoveryCategory::PluginConfig
        })
        .filter_map(|item| {
            GroupMemberIdentity::try_from(item).ok().map(|identity| {
                AgentPluginActivationCandidate {
                    identity,
                    native_plugin_id: item.display_name.clone(),
                }
            })
        })
        .collect()
}

#[derive(Debug)]
struct ParsedPackage {
    package_root_identity: String,
    native_plugin_id: String,
    manifest: AgentPluginManifestView,
    manifest_source_fingerprint: String,
    components: Vec<AgentPluginComponentView>,
    blockers: Vec<String>,
    diagnostics: Vec<String>,
}

pub(crate) fn discover_cached_agent_plugins(
    provider: ProviderId,
    cache_root: &Path,
    activations: &[AgentPluginActivationCandidate],
    metadata: &mut Vec<AgentPluginMetadata>,
    item_keys: &mut BTreeMap<GroupMemberIdentity, ComponentAssociationKey>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> io::Result<()> {
    let packages = match read_cache_packages(provider, cache_root, warnings) {
        Ok(packages) => packages,
        Err(_) => {
            warnings.push(DiscoveryWarning {
                provider,
                layer: Some(DiscoveryLayer::Global),
                code: "agent-plugin-cache-unavailable".to_string(),
                message: "Agent Plugin cache could not be read; package inventory is incomplete."
                    .to_string(),
            });
            return Ok(());
        }
    };
    let mut package_counts = BTreeMap::<String, usize>::new();
    for package in &packages {
        *package_counts
            .entry(package.native_plugin_id.clone())
            .or_default() += 1;
    }
    let mut activations_by_native_id =
        BTreeMap::<String, Vec<&AgentPluginActivationCandidate>>::new();
    for activation in activations {
        activations_by_native_id
            .entry(activation.native_plugin_id.clone())
            .or_default()
            .push(activation);
    }

    for package in packages {
        let matching = activations_by_native_id
            .get(&package.native_plugin_id)
            .cloned()
            .unwrap_or_default();
        let ambiguous_installation = package_counts
            .get(&package.native_plugin_id)
            .copied()
            .unwrap_or_default()
            > 1;
        let layers = matching
            .iter()
            .map(|candidate| candidate.identity.layer)
            .collect::<BTreeSet<_>>();

        if matching.is_empty() || ambiguous_installation {
            let mut blockers = package.blockers.clone();
            blockers.push(if ambiguous_installation {
                "multiple-installed-versions".to_string()
            } else {
                "native-activation-not-found".to_string()
            });
            let diagnostic_layers = if layers.is_empty() {
                BTreeSet::from([DiscoveryLayer::Global])
            } else {
                layers.clone()
            };
            for layer in diagnostic_layers {
                metadata.push(AgentPluginMetadata {
                    provider,
                    layer,
                    package_root_identity: package.package_root_identity.clone(),
                    native_plugin_id: package.native_plugin_id.clone(),
                    manifest: package.manifest.clone(),
                    manifest_source_fingerprint: package.manifest_source_fingerprint.clone(),
                    components: package.components.clone(),
                    activation_key: None,
                    blockers: blockers.clone(),
                    diagnostics: package.diagnostics.clone(),
                });
            }
            continue;
        }

        for layer in layers {
            let activation_key =
                ComponentAssociationKey::new(provider, layer, &package.package_root_identity);
            for candidate in matching
                .iter()
                .filter(|candidate| candidate.identity.layer == layer)
            {
                item_keys.insert(candidate.identity.clone(), activation_key.clone());
            }
            metadata.push(AgentPluginMetadata {
                provider,
                layer,
                package_root_identity: package.package_root_identity.clone(),
                native_plugin_id: package.native_plugin_id.clone(),
                manifest: package.manifest.clone(),
                manifest_source_fingerprint: package.manifest_source_fingerprint.clone(),
                components: package.components.clone(),
                activation_key: Some(activation_key),
                blockers: package.blockers.clone(),
                diagnostics: package.diagnostics.clone(),
            });
        }
    }

    Ok(())
}

pub(crate) fn has_diagnostics_only_writable_activation_anchors(
    package: &AgentPluginSummary,
) -> bool {
    package.instances.iter().any(|instance| {
        instance.access == AgentPluginAccess::DiagnosticsOnly
            && instance
                .activations
                .iter()
                .any(|activation| activation.mutability == DiscoveryMutability::ReadWrite)
    })
}

#[must_use]
pub fn project_agent_plugins(
    items: &[DiscoveryItem],
    metadata: &[AgentPluginMetadata],
    item_keys: &BTreeMap<GroupMemberIdentity, ComponentAssociationKey>,
) -> Vec<AgentPluginSummary> {
    let mut activations =
        BTreeMap::<ComponentAssociationKey, Vec<AgentPluginActivationView>>::new();
    for item in items {
        let Ok(identity) = GroupMemberIdentity::try_from(item) else {
            continue;
        };
        let Some(key) = item_keys.get(&identity) else {
            continue;
        };
        activations
            .entry(key.clone())
            .or_default()
            .push(AgentPluginActivationView {
                identity,
                enabled: item.enabled,
                mutability: item.mutability,
                source_fingerprint: item.source_fingerprint.clone(),
            });
    }

    let mut grouped = BTreeMap::<(String, String, String), Vec<AgentPluginInstance>>::new();
    for package in metadata {
        let mut instance_activations = package
            .activation_key
            .as_ref()
            .and_then(|key| activations.get(key))
            .cloned()
            .unwrap_or_default();
        instance_activations.sort_by(|left, right| left.identity.cmp(&right.identity));

        let state = activation_state(&instance_activations);
        let access = if !instance_activations.is_empty()
            && instance_activations
                .iter()
                .all(|activation| activation.mutability == DiscoveryMutability::ReadWrite)
            && package.blockers.is_empty()
            && package.components.iter().all(|component| {
                component.disposition == AgentPluginComponentDisposition::Available
            }) {
            AgentPluginAccess::Actionable
        } else {
            AgentPluginAccess::DiagnosticsOnly
        };
        let component_signature = component_signature(&package.components);
        let instance_id = format!(
            "agent-plugin-instance:{}:{}:{}",
            package.provider.as_str(),
            package.layer.as_str(),
            digest_fragment(&package.package_root_identity)
        );
        let projection_fingerprint = instance_fingerprint(
            package,
            &component_signature,
            &instance_activations,
            state,
            access,
        );
        let instance = AgentPluginInstance {
            instance_id,
            provider: package.provider,
            layer: package.layer,
            manifest: package.manifest.clone(),
            state,
            access,
            components: package.components.clone(),
            activations: instance_activations,
            projection_fingerprint,
            blockers: package.blockers.clone(),
            diagnostics: package.diagnostics.clone(),
        };
        grouped
            .entry((
                package.manifest.name.clone(),
                component_signature,
                package.native_plugin_id.clone(),
            ))
            .or_default()
            .push(instance);
    }

    let mut summaries = grouped
        .into_iter()
        .map(
            |((name, component_signature, native_plugin_id), instances)| {
                let mut summary = AgentPluginSummary {
                    logical_id: format!(
                        "agent-plugin:{}:{}",
                        name,
                        digest_fragment(&source_fingerprint(&format!(
                            "{component_signature}\0{native_plugin_id}"
                        )))
                    ),
                    name,
                    component_signature,
                    projection_fingerprint: String::new(),
                    state: AgentPluginState::Unknown,
                    access: AgentPluginAccess::DiagnosticsOnly,
                    instances,
                };
                summary.refresh_rollup();
                summary
            },
        )
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.component_signature.cmp(&right.component_signature))
    });
    summaries
}

fn read_cache_packages(
    provider: ProviderId,
    cache_root: &Path,
    warnings: &mut Vec<DiscoveryWarning>,
) -> io::Result<Vec<ParsedPackage>> {
    let Some(metadata) = metadata_if_present(cache_root)? else {
        return Ok(Vec::new());
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_data("package cache root is not a directory"));
    }
    let cache_root = fs::canonicalize(cache_root)?;
    let mut remaining = MAX_PACKAGE_ENTRIES;
    let mut packages = Vec::new();

    let marketplaces = bounded_directories(&cache_root, &cache_root, &mut remaining)?;
    if marketplaces.incomplete {
        push_cache_incomplete_warning(warnings, provider);
    }
    for marketplace in marketplaces.directories {
        let marketplace_name = match safe_file_name(&marketplace) {
            Ok(name) => name,
            Err(_) => {
                push_cache_incomplete_warning(warnings, provider);
                continue;
            }
        };
        let plugins = match bounded_directories(&marketplace, &cache_root, &mut remaining) {
            Ok(plugins) => plugins,
            Err(_) => {
                push_cache_incomplete_warning(warnings, provider);
                continue;
            }
        };
        if plugins.incomplete {
            push_cache_incomplete_warning(warnings, provider);
        }
        for plugin in plugins.directories {
            let plugin_name = match safe_file_name(&plugin) {
                Ok(name) => name,
                Err(_) => {
                    push_cache_incomplete_warning(warnings, provider);
                    continue;
                }
            };
            let versions = match bounded_directories(&plugin, &cache_root, &mut remaining) {
                Ok(versions) => versions,
                Err(_) => {
                    push_cache_incomplete_warning(warnings, provider);
                    continue;
                }
            };
            if versions.incomplete {
                push_cache_incomplete_warning(warnings, provider);
            }
            for version in versions.directories {
                let native_plugin_id = format!("{plugin_name}@{marketplace_name}");
                match parse_package(&version, native_plugin_id.clone()) {
                    Ok(Some(package)) => packages.push(package),
                    Ok(None) => {}
                    Err(error) => warnings.push(DiscoveryWarning {
                        provider,
                        layer: Some(DiscoveryLayer::Global),
                        code: "agent-plugin-invalid".to_string(),
                        message: format!(
                            "Agent Plugin {} was ignored: {}",
                            sanitize_public(&native_plugin_id),
                            sanitize_public(&error.to_string())
                        ),
                    }),
                }
            }
        }
    }
    packages.sort_by(|left, right| {
        left.native_plugin_id
            .cmp(&right.native_plugin_id)
            .then_with(|| left.package_root_identity.cmp(&right.package_root_identity))
    });
    Ok(packages)
}

fn parse_package(root: &Path, native_plugin_id: String) -> io::Result<Option<ParsedPackage>> {
    let manifest_path = root.join("plugin.json");
    let Some(manifest_metadata) = metadata_if_present(&manifest_path)? else {
        return Ok(None);
    };
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        return Err(invalid_data("plugin.json is not a regular file"));
    }
    let manifest_raw = read_bounded_file(&manifest_path, root)?;
    let manifest_value = parse_bounded_json(&manifest_raw)?;
    let (manifest, mut diagnostics) = parse_manifest(&manifest_value)?;
    let mut blockers = Vec::new();
    let manifest_source_fingerprint = source_fingerprint(&manifest_raw);
    let mut components = read_skills(root, &mut blockers)?;
    components.extend(read_mcp(root, &mut blockers)?);
    components.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    let package_root_identity = source_fingerprint(root.to_string_lossy().as_ref());
    Ok(Some(ParsedPackage {
        package_root_identity,
        native_plugin_id,
        manifest,
        manifest_source_fingerprint,
        components,
        blockers,
        diagnostics: {
            diagnostics.sort();
            diagnostics
        },
    }))
}

fn parse_manifest(value: &serde_json::Value) -> io::Result<(AgentPluginManifestView, Vec<String>)> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_data("plugin.json must contain an object"))?;
    let schema = required_string(object, "$schema")?;
    if schema != AGENT_PLUGIN_SCHEMA {
        return Err(invalid_data("unsupported plugin schema"));
    }
    let name = required_string(object, "name")?;
    validate_plugin_name(name)?;

    let permitted = BTreeSet::from([
        "$schema",
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "extensions",
    ]);
    let mut diagnostics = Vec::new();
    if object.keys().any(|key| !permitted.contains(key.as_str())) {
        diagnostics.push("unknown-manifest-fields-ignored".to_string());
    }
    if object
        .get("extensions")
        .is_some_and(|extensions| !extensions.is_object())
    {
        diagnostics.push("invalid-extensions-ignored".to_string());
    }

    let author = object.get("author").map(parse_author).transpose()?;
    let keywords = object
        .get("keywords")
        .map(|value| {
            let values = value
                .as_array()
                .ok_or_else(|| invalid_data("keywords must be an array"))?;
            if values.len() > MAX_PACKAGE_ENTRIES {
                return Err(invalid_data("too many keywords"));
            }
            values
                .iter()
                .map(|keyword| {
                    keyword
                        .as_str()
                        .map(sanitize_public)
                        .ok_or_else(|| invalid_data("keywords entries must be strings"))
                })
                .collect::<io::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok((
        AgentPluginManifestView {
            name: name.to_string(),
            version: optional_string(object, "version")?,
            description: optional_string(object, "description")?,
            author,
            homepage: optional_string(object, "homepage")?,
            repository: optional_string(object, "repository")?,
            license: optional_string(object, "license")?,
            keywords,
        },
        diagnostics,
    ))
}

fn parse_author(value: &serde_json::Value) -> io::Result<AgentPluginAuthor> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_data("author must be an object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "email" | "url"))
    {
        return Err(invalid_data("author contains an unknown field"));
    }
    Ok(AgentPluginAuthor {
        name: optional_string(object, "name")?,
        email: optional_string(object, "email")?,
        url: optional_string(object, "url")?,
    })
}

fn read_skills(
    root: &Path,
    blockers: &mut Vec<String>,
) -> io::Result<Vec<AgentPluginComponentView>> {
    let skills = root.join("skills");
    let metadata = match metadata_if_present(&skills) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return Ok(Vec::new()),
        Err(_) => {
            blockers.push("skills-read-error".to_string());
            return Ok(vec![read_error_component(
                AgentPluginComponentKind::Skill,
                "skills",
                "skills-read-error",
            )]);
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        blockers.push("invalid-skills-location".to_string());
        return Ok(vec![invalid_component(
            AgentPluginComponentKind::Skill,
            "skills",
            "invalid-skills-location",
        )]);
    }
    let skills = fs::canonicalize(skills)?;
    if !skills.starts_with(root) {
        return Err(invalid_data("skills location escapes package root"));
    }
    let mut remaining = MAX_PACKAGE_ENTRIES;
    let mut components = Vec::new();
    let scan = match bounded_directories(&skills, root, &mut remaining) {
        Ok(scan) => scan,
        Err(_) => {
            blockers.push("skills-read-error".to_string());
            return Ok(vec![read_error_component(
                AgentPluginComponentKind::Skill,
                "skills",
                "skills-read-error",
            )]);
        }
    };
    if scan.incomplete {
        blockers.push("skills-read-error".to_string());
        components.push(read_error_component(
            AgentPluginComponentKind::Skill,
            "skills",
            "skills-read-error",
        ));
    }
    for skill in scan.directories {
        let name = match safe_file_name(&skill) {
            Ok(name) => name,
            Err(_) => {
                blockers.push("skills-read-error".to_string());
                components.push(read_error_component(
                    AgentPluginComponentKind::Skill,
                    "skill",
                    "skill-read-error",
                ));
                continue;
            }
        };
        let skill_md = skill.join("SKILL.md");
        match metadata_if_present(&skill_md) {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(_) => {
                blockers.push("skills-read-error".to_string());
                components.push(read_error_component(
                    AgentPluginComponentKind::Skill,
                    &name,
                    "skill-read-error",
                ));
                continue;
            }
        }
        match read_bounded_file(&skill_md, root) {
            Ok(raw) if valid_skill_markdown(&raw, &name) => {
                components.push(AgentPluginComponentView {
                    kind: AgentPluginComponentKind::Skill,
                    name,
                    disposition: AgentPluginComponentDisposition::Available,
                    source_fingerprint: source_fingerprint(&raw),
                    reason: None,
                });
            }
            Ok(_) => components.push(invalid_component(
                AgentPluginComponentKind::Skill,
                &name,
                "invalid-agent-skill",
            )),
            Err(_) => components.push(read_error_component(
                AgentPluginComponentKind::Skill,
                &name,
                "skill-read-error",
            )),
        }
    }
    Ok(components)
}

fn read_mcp(root: &Path, blockers: &mut Vec<String>) -> io::Result<Vec<AgentPluginComponentView>> {
    let path = root.join("mcp.json");
    match metadata_if_present(&path) {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(Vec::new()),
        Err(_) => {
            blockers.push("mcp-read-error".to_string());
            return Ok(vec![read_error_component(
                AgentPluginComponentKind::Mcp,
                "mcp",
                "mcp-read-error",
            )]);
        }
    }
    let raw = match read_bounded_file(&path, root) {
        Ok(raw) => raw,
        Err(_) => {
            blockers.push("mcp-read-error".to_string());
            return Ok(vec![read_error_component(
                AgentPluginComponentKind::Mcp,
                "mcp",
                "mcp-read-error",
            )]);
        }
    };
    let value = match parse_bounded_json(&raw) {
        Ok(value) => value,
        Err(_) => return Ok(invalid_mcp_document(blockers)),
    };
    let Some(object) = value.as_object() else {
        return Ok(invalid_mcp_document(blockers));
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "$schema" | "mcpServers"))
        || object.get("$schema").and_then(serde_json::Value::as_str)
            != Some(AGENT_PLUGIN_MCP_SCHEMA)
    {
        return Ok(invalid_mcp_document(blockers));
    }
    let Some(servers) = object
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(invalid_mcp_document(blockers));
    };
    if servers.len() > MAX_PACKAGE_ENTRIES {
        blockers.push("too-many-mcp-servers".to_string());
        return Ok(vec![invalid_component(
            AgentPluginComponentKind::Mcp,
            "mcp",
            "too-many-mcp-servers",
        )]);
    }
    let mut components = servers
        .iter()
        .map(|(name, server)| {
            if !valid_component_name(name) {
                return invalid_component(
                    AgentPluginComponentKind::Mcp,
                    "invalid-name",
                    "invalid-mcp-server-name",
                );
            }
            let fingerprint = source_fingerprint(
                &serde_json::to_string(server).unwrap_or_else(|_| "null".to_string()),
            );
            if validate_mcp_server(server, root).is_err() {
                AgentPluginComponentView {
                    kind: AgentPluginComponentKind::Mcp,
                    name: name.clone(),
                    disposition: AgentPluginComponentDisposition::Invalid,
                    source_fingerprint: fingerprint,
                    reason: Some("invalid-mcp-server".to_string()),
                }
            } else {
                AgentPluginComponentView {
                    kind: AgentPluginComponentKind::Mcp,
                    name: name.clone(),
                    disposition: AgentPluginComponentDisposition::Available,
                    source_fingerprint: fingerprint,
                    reason: None,
                }
            }
        })
        .collect::<Vec<_>>();
    components.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(components)
}

fn validate_mcp_server(value: &serde_json::Value, root: &Path) -> io::Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_data("MCP server must be an object"))?;
    let transport = required_string(object, "type")?;
    let permitted = match transport {
        "stdio" => ["type", "command", "args", "env", "cwd"].as_slice(),
        "streamable-http" | "sse" => ["type", "url", "headers"].as_slice(),
        _ => return Err(invalid_data("unsupported MCP transport")),
    };
    if object.keys().any(|key| !permitted.contains(&key.as_str())) {
        return Err(invalid_data("MCP server contains an unknown field"));
    }
    match transport {
        "stdio" => {
            let command = required_string(object, "command")?;
            validate_stdio_command(command, root)?;
            if let Some(args) = object.get("args") {
                validate_string_array(args)?;
            }
            if let Some(env) = object.get("env") {
                validate_mcp_env(env)?;
            }
            if let Some(cwd) = object.get("cwd") {
                let cwd = cwd
                    .as_str()
                    .ok_or_else(|| invalid_data("cwd must be a string"))?;
                validate_stdio_cwd(cwd, root)?;
            }
        }
        "streamable-http" | "sse" => {
            let url = required_string(object, "url")?;
            if !valid_remote_mcp_url(url) {
                return Err(invalid_data("invalid remote MCP URL"));
            }
            if let Some(headers) = object.get("headers") {
                validate_string_map(headers)?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_stdio_command(command: &str, root: &Path) -> io::Result<()> {
    if command.chars().any(char::is_control) {
        return Err(invalid_data("invalid stdio command"));
    }
    if let Some(relative) = command.strip_prefix("./") {
        return validate_existing_plugin_path(root, relative, true);
    }
    if command.is_empty()
        || matches!(command, "." | "..")
        || command.contains('/')
        || command.contains('\\')
        || command.contains("${")
    {
        return Err(invalid_data("invalid stdio command"));
    }
    Ok(())
}

fn validate_stdio_cwd(cwd: &str, root: &Path) -> io::Result<()> {
    if cwd.chars().any(char::is_control) {
        return Err(invalid_data("invalid cwd"));
    }
    if let Some(relative) = cwd.strip_prefix("./") {
        return validate_existing_plugin_path(root, relative, false);
    }
    if cwd == "${PLUGIN_ROOT}" {
        return Ok(());
    }
    if let Some(relative) = cwd.strip_prefix("${PLUGIN_ROOT}/") {
        return validate_existing_plugin_path(root, relative, false);
    }
    if cwd == "${PLUGIN_DATA}" {
        return Ok(());
    }
    if let Some(relative) = cwd.strip_prefix("${PLUGIN_DATA}/")
        && valid_relative_path(relative)
    {
        return Ok(());
    }
    Err(invalid_data("invalid cwd"))
}

fn validate_existing_plugin_path(root: &Path, relative: &str, file: bool) -> io::Result<()> {
    if !valid_relative_path(relative) {
        return Err(invalid_data("invalid plugin-relative path"));
    }
    let resolved = fs::canonicalize(root.join(relative))?;
    if !resolved.starts_with(root) {
        return Err(invalid_data("plugin-relative path escapes package root"));
    }
    let metadata = fs::metadata(resolved)?;
    if (file && !metadata.is_file()) || (!file && !metadata.is_dir()) {
        return Err(invalid_data("plugin-relative path has the wrong type"));
    }
    Ok(())
}

fn valid_relative_path(relative: &str) -> bool {
    !relative.is_empty()
        && !relative.contains('\\')
        && !relative.chars().any(char::is_control)
        && relative
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
        && Path::new(relative)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_mcp_env(value: &serde_json::Value) -> io::Result<()> {
    validate_string_map(value)?;
    let values = value
        .as_object()
        .ok_or_else(|| invalid_data("environment must be a string map"))?;
    if values.contains_key("PLUGIN_ROOT") || values.contains_key("PLUGIN_DATA") {
        return Err(invalid_data("reserved plugin environment variable"));
    }
    Ok(())
}

fn valid_remote_mcp_url(url: &str) -> bool {
    if url
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || url.contains('#')
        || url.contains('@')
    {
        return false;
    }
    let Some((scheme, remainder)) = url.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let Some(host) = url_host(&remainder[..authority_end]) else {
        return false;
    };
    if scheme == "https" {
        return true;
    }
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.octets()[0] == 127)
}

fn url_host(authority: &str) -> Option<&str> {
    if authority.is_empty() {
        return None;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        return (!host.is_empty() && valid_url_port(suffix)).then_some(host);
    }
    if authority.contains('[') || authority.contains(']') {
        return None;
    }
    let (host, suffix) = authority
        .rsplit_once(':')
        .map_or((authority, ""), |(host, _)| {
            (host, &authority[host.len()..])
        });
    if host.is_empty()
        || host.contains(':')
        || host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || !valid_url_port(suffix)
    {
        None
    } else {
        Some(host)
    }
}

fn valid_url_port(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

fn validate_string_array(value: &serde_json::Value) -> io::Result<()> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid_data("value must be a string array"))?;
    if values.iter().any(|value| {
        value
            .as_str()
            .is_none_or(|value| value.chars().any(char::is_control))
    }) {
        return Err(invalid_data("value must contain safe strings"));
    }
    Ok(())
}

fn validate_string_map(value: &serde_json::Value) -> io::Result<()> {
    let values = value
        .as_object()
        .ok_or_else(|| invalid_data("value must be a string map"))?;
    if values.iter().any(|(key, value)| {
        key.is_empty()
            || key.chars().any(char::is_control)
            || value
                .as_str()
                .is_none_or(|value| value.chars().any(char::is_control))
    }) {
        return Err(invalid_data("value must contain safe strings"));
    }
    Ok(())
}

struct BoundedDirectoryScan {
    directories: Vec<PathBuf>,
    incomplete: bool,
}

fn bounded_directories(
    directory: &Path,
    root: &Path,
    remaining: &mut usize,
) -> io::Result<BoundedDirectoryScan> {
    let mut directories = Vec::new();
    let mut incomplete = false;
    for entry in fs::read_dir(directory)? {
        if *remaining == 0 {
            incomplete = true;
            break;
        }
        *remaining -= 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            incomplete = true;
            continue;
        }
        let canonical = match fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        if !canonical.starts_with(root) {
            incomplete = true;
            continue;
        }
        directories.push(canonical);
    }
    directories.sort();
    Ok(BoundedDirectoryScan {
        directories,
        incomplete,
    })
}

fn metadata_if_present(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn push_cache_incomplete_warning(warnings: &mut Vec<DiscoveryWarning>, provider: ProviderId) {
    if warnings.iter().any(|warning| {
        warning.provider == provider && warning.code == "agent-plugin-cache-incomplete"
    }) {
        return;
    }
    warnings.push(DiscoveryWarning {
        provider,
        layer: Some(DiscoveryLayer::Global),
        code: "agent-plugin-cache-incomplete".to_string(),
        message: "Agent Plugin cache was only partially readable; package inventory is incomplete."
            .to_string(),
    });
}

fn read_bounded_file(path: &Path, root: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_data("package input is not a regular file"));
    }
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(root) {
        return Err(invalid_data("package input escapes root"));
    }
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_PACKAGE_FILE_BYTES as u64
        || !path_matches_open_file(path, &file)?
    {
        return Err(invalid_data("package input is unsafe or too large"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_PACKAGE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKAGE_FILE_BYTES || !path_matches_open_file(path, &file)? {
        return Err(invalid_data("package input changed or is too large"));
    }
    String::from_utf8(bytes).map_err(|_| invalid_data("package input must be UTF-8"))
}

fn parse_bounded_json(raw: &str) -> io::Result<serde_json::Value> {
    let value = serde_json::from_str(raw).map_err(invalid_data)?;
    if json_depth(&value) > MAX_JSON_DEPTH {
        return Err(invalid_data("JSON nesting limit exceeded"));
    }
    Ok(value)
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(values) => {
            1 + values.iter().map(json_depth).max().unwrap_or_default()
        }
        serde_json::Value::Object(values) => {
            1 + values.values().map(json_depth).max().unwrap_or_default()
        }
        _ => 1,
    }
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> io::Result<&'a str> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_data(format!("{key} must be a non-empty string")))
}

fn optional_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> io::Result<Option<String>> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(sanitize_public)
                .ok_or_else(|| invalid_data(format!("{key} must be a string")))
        })
        .transpose()
}

fn validate_plugin_name(name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    if !(1..=64).contains(&name.chars().count())
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || bytes.iter().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
        })
        || name.contains("--")
        || name.contains("..")
    {
        return Err(invalid_data("invalid Agent Plugin name"));
    }
    Ok(())
}

fn safe_file_name(path: &Path) -> io::Result<String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| valid_component_name(name))
        .ok_or_else(|| invalid_data("unsafe package directory name"))?;
    Ok(name.to_string())
}

fn valid_component_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_COMPONENT_NAME_BYTES
        && !name.chars().any(char::is_control)
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_skill_markdown(raw: &str, directory_name: &str) -> bool {
    let mut lines = raw.lines();
    if lines.next() != Some("---") {
        return false;
    }
    let mut name = None;
    let mut description = None;
    for line in lines.by_ref() {
        if line == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("name:") {
            name = Some(value.trim());
        }
        if let Some(value) = line.strip_prefix("description:") {
            description = Some(value.trim());
        }
    }
    name == Some(directory_name) && description.is_some_and(|value| !value.is_empty())
}

fn invalid_mcp_document(blockers: &mut Vec<String>) -> Vec<AgentPluginComponentView> {
    blockers.push("invalid-mcp-document".to_string());
    vec![invalid_component(
        AgentPluginComponentKind::Mcp,
        "mcp",
        "invalid-mcp-document",
    )]
}

fn invalid_component(
    kind: AgentPluginComponentKind,
    name: &str,
    reason: &str,
) -> AgentPluginComponentView {
    AgentPluginComponentView {
        kind,
        name: sanitize_public(name),
        disposition: AgentPluginComponentDisposition::Invalid,
        source_fingerprint: source_fingerprint(reason),
        reason: Some(reason.to_string()),
    }
}

fn read_error_component(
    kind: AgentPluginComponentKind,
    name: &str,
    reason: &str,
) -> AgentPluginComponentView {
    AgentPluginComponentView {
        kind,
        name: sanitize_public(name),
        disposition: AgentPluginComponentDisposition::ReadError,
        source_fingerprint: source_fingerprint(reason),
        reason: Some(reason.to_string()),
    }
}

fn component_signature(components: &[AgentPluginComponentView]) -> String {
    source_fingerprint(
        &components
            .iter()
            .map(|component| format!("{}\0{}", component.kind.as_str(), component.name))
            .collect::<Vec<_>>()
            .join("\0"),
    )
}

fn instance_fingerprint(
    package: &AgentPluginMetadata,
    component_signature: &str,
    activations: &[AgentPluginActivationView],
    state: AgentPluginState,
    access: AgentPluginAccess,
) -> String {
    let component_state = package
        .components
        .iter()
        .map(|component| {
            format!(
                "{}\0{}\0{:?}\0{}",
                component.kind.as_str(),
                component.name,
                component.disposition,
                component.source_fingerprint
            )
        })
        .collect::<Vec<_>>()
        .join("\0");
    let activation_state = activations
        .iter()
        .map(|activation| {
            format!(
                "{}\0{}\0{:?}\0{}",
                activation.identity.canonical_key(),
                activation.enabled,
                activation.mutability,
                activation
                    .source_fingerprint
                    .as_deref()
                    .unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>()
        .join("\0");
    let diagnostics = package.diagnostics.join("\0");
    let blockers = package.blockers.join("\0");
    source_fingerprint(&format!(
        "{}\0{}\0{}\0{}\0{}\0{:?}\0{:?}\0{}\0{}\0{}\0{}",
        package.provider.as_str(),
        package.layer.as_str(),
        package.package_root_identity,
        package.manifest_source_fingerprint,
        component_signature,
        state,
        access,
        component_state,
        activation_state,
        diagnostics,
        blockers
    ))
}

fn activation_state(activations: &[AgentPluginActivationView]) -> AgentPluginState {
    if activations.is_empty() {
        AgentPluginState::Unknown
    } else if activations.iter().all(|activation| activation.enabled) {
        AgentPluginState::On
    } else if activations.iter().all(|activation| !activation.enabled) {
        AgentPluginState::Off
    } else {
        AgentPluginState::Mixed
    }
}

pub(crate) fn roll_up_state(states: impl Iterator<Item = AgentPluginState>) -> AgentPluginState {
    let states = states.collect::<BTreeSet<_>>();
    if states.len() == 1 {
        states
            .into_iter()
            .next()
            .unwrap_or(AgentPluginState::Unknown)
    } else if states.contains(&AgentPluginState::Unknown) {
        AgentPluginState::Unknown
    } else {
        AgentPluginState::Mixed
    }
}

pub(crate) fn roll_up_access(access: impl Iterator<Item = AgentPluginAccess>) -> AgentPluginAccess {
    let access = access.collect::<BTreeSet<_>>();
    if access.contains(&AgentPluginAccess::Actionable) {
        AgentPluginAccess::Actionable
    } else if access.contains(&AgentPluginAccess::DiagnosticsOnly) {
        AgentPluginAccess::DiagnosticsOnly
    } else {
        AgentPluginAccess::Unsupported
    }
}

fn digest_fragment(value: &str) -> &str {
    value
        .strip_prefix("sha256:")
        .unwrap_or(value)
        .get(..16)
        .unwrap_or(value)
}

fn sanitize_public(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let sanitized = if character.is_control() || character == '\u{1b}' {
            '\u{fffd}'
        } else {
            character
        };
        if output.len() + sanitized.len_utf8() > MAX_PUBLIC_STRING_BYTES {
            break;
        }
        output.push(sanitized);
    }
    output
}

fn invalid_data(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
