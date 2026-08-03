use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, types::Value as SqliteValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::providers::ProviderId;

use crate::{
    config::normalize_path,
    encode_path_segment,
    fs_support::read_optional_string,
    hooks::{HookInventoryMetadata, parse_hook_document},
    pi_packages::{pi_disabled_package_entry, pi_package_extension_state},
    providers::registry::provider_registry,
    toml_syntax::{
        all_table_sections, duplicate_standard_table_names, duplicate_top_level_key_tables,
        find_array_table_sections, find_table_section, malformed_table_header_lines,
        table_child_ids, table_subtree_content,
    },
};

mod project_scopes;
mod providers;

use project_scopes::{
    scan_project_scope_frontier_accumulating_with, scan_project_scope_frontier_with,
};
#[cfg(test)]
use project_scopes::{
    scan_project_scope_frontier_accumulating_with_cancellation,
    scan_project_scope_frontier_with_cancellation,
};
pub(crate) use providers::*;
#[cfg(test)]
use std::sync::atomic::Ordering as AtomicOrdering;

pub type DiscoveryError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryProgressPhase {
    DiscoveringProvider(ProviderId),
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryProgress {
    pub phase: DiscoveryProgressPhase,
    pub completed_providers: usize,
    pub provider_count: usize,
}

#[derive(Debug)]
struct DiscoveryCancelled;

impl std::fmt::Display for DiscoveryCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("discovery cancelled")
    }
}

impl std::error::Error for DiscoveryCancelled {}

const CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX: &str = "claude:project:configured-mcp:@local/";
const CURSOR_GLOBAL_SKILL_ID_PREFIX: &str = "cursor:global:skill:";
const CURSOR_PROJECT_SKILL_ID_PREFIX: &str = "cursor:project:skill:";
const CURSOR_COMPAT_AGENTS_SKILL_NAMESPACE: &str = "@compat/agents/";
const CURSOR_COMPAT_CLAUDE_SKILL_NAMESPACE: &str = "@compat/claude/";
const CURSOR_COMPAT_CODEX_SKILL_NAMESPACE: &str = "@compat/codex/";
const CURSOR_COMPAT_SKILL_NAMESPACES: [&str; 3] = [
    CURSOR_COMPAT_AGENTS_SKILL_NAMESPACE,
    CURSOR_COMPAT_CLAUDE_SKILL_NAMESPACE,
    CURSOR_COMPAT_CODEX_SKILL_NAMESPACE,
];
const PI_GLOBAL_SKILL_ID_PREFIX: &str = "pi:global:skill:";
const PI_PROJECT_SKILL_ID_PREFIX: &str = "pi:project:skill:";
const PI_COMPAT_AGENTS_SKILL_NAMESPACE: &str = "@compat/agents/";
const PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX: &str = "pi:global:plugin-config:package-extensions:";
const PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX: &str = "pi:project:plugin-config:package-extensions:";
const OPENCODE_GLOBAL_SKILL_ID_PREFIX: &str = "opencode:global:skill:";
const OPENCODE_PROJECT_SKILL_ID_PREFIX: &str = "opencode:project:skill:";
const OPENCODE_COMPAT_AGENTS_SKILL_NAMESPACE: &str = "@compat/agents/";
const OPENCODE_COMPAT_CLAUDE_SKILL_NAMESPACE: &str = "@compat/claude/";
const OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "opencode:global:configured-mcp:";
const OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "opencode:project:configured-mcp:";

#[derive(Debug, Clone)]
pub struct DiscoveryRoots {
    pub claude_global: PathBuf,
    pub claude_user_state: PathBuf,
    pub claude_project: PathBuf,
    pub codex_global: PathBuf,
    pub codex_admin: PathBuf,
    pub codex_project: PathBuf,
    pub cursor_global: PathBuf,
    pub cursor_config: PathBuf,
    pub cursor_project: PathBuf,
    pub pi_global: PathBuf,
    pub pi_project: PathBuf,
    pub opencode_global: PathBuf,
    pub opencode_project: PathBuf,
    pub shared_global: PathBuf,
    pub shared_project: PathBuf,
    pub zed_global: PathBuf,
    pub zed_project: PathBuf,
    pub scan_project_scopes: bool,
    pub app_state_root: Option<PathBuf>,
}

impl DiscoveryRoots {
    pub fn fixture_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();

        Self {
            claude_global: root.join("claude").join("global"),
            claude_user_state: root.join("claude").join(".claude.json"),
            claude_project: root.join("claude").join("project"),
            codex_global: root.join("codex").join("global"),
            codex_admin: root.join("codex").join("admin"),
            codex_project: root.join("codex").join("project"),
            cursor_global: root.join("cursor").join("global"),
            cursor_config: root.join("cursor").join("home"),
            cursor_project: root.join("cursor").join("project"),
            pi_global: root.join("pi").join("global"),
            pi_project: root.join("pi").join("project"),
            opencode_global: root.join("opencode").join("global"),
            opencode_project: root.join("opencode").join("project"),
            shared_global: root.join("shared").join("global"),
            shared_project: root.join("shared").join("project"),
            zed_global: root.join("zed").join("global").join(".config").join("zed"),
            zed_project: root.join("zed").join("project"),
            scan_project_scopes: false,
            app_state_root: None,
        }
    }

    pub fn from_locations(
        home_root: impl AsRef<Path>,
        project_root: impl AsRef<Path>,
        cursor_root: impl AsRef<Path>,
    ) -> Self {
        let home_root = home_root.as_ref();
        let project_root = project_root.as_ref();
        let cursor_root = cursor_root.as_ref();

        Self {
            claude_global: home_root.join(".claude"),
            claude_user_state: home_root.join(".claude.json"),
            claude_project: project_root.to_path_buf(),
            codex_global: home_root.join(".codex"),
            codex_admin: PathBuf::from("/etc/codex"),
            codex_project: project_root.to_path_buf(),
            cursor_global: cursor_root.to_path_buf(),
            cursor_config: home_root.join(".cursor"),
            cursor_project: project_root.to_path_buf(),
            pi_global: home_root.join(".pi").join("agent"),
            pi_project: project_root.to_path_buf(),
            opencode_global: home_root.join(".config").join("opencode"),
            opencode_project: project_root.to_path_buf(),
            shared_global: home_root.to_path_buf(),
            shared_project: project_root.to_path_buf(),
            zed_global: home_root.join(".config").join("zed"),
            zed_project: project_root.to_path_buf(),
            scan_project_scopes: true,
            app_state_root: None,
        }
    }

    pub fn with_app_state_root(mut self, app_state_root: impl AsRef<Path>) -> Self {
        let app_state_root = app_state_root.as_ref();
        self.app_state_root =
            Some(fs::canonicalize(app_state_root).unwrap_or_else(|_| app_state_root.to_path_buf()));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryKind {
    Skill,
    Mcp,
    Plugin,
    Agent,
    Hook,
    Setting,
}

impl DiscoveryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Mcp => "mcp",
            Self::Plugin => "plugin",
            Self::Agent => "agent",
            Self::Hook => "hook",
            Self::Setting => "setting",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryCategory {
    Skill,
    ConfiguredMcp,
    Tool,
    Agent,
    Hook,
    ProviderSetting,
    PluginConfig,
    PluginManifest,
}

impl DiscoveryCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::ConfiguredMcp => "configured-mcp",
            Self::Tool => "tool",
            Self::Agent => "agent",
            Self::Hook => "hook",
            Self::ProviderSetting => "provider-setting",
            Self::PluginConfig => "plugin-config",
            Self::PluginManifest => "plugin-manifest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryLayer {
    Global,
    Project,
}

impl DiscoveryLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryMutability {
    ReadWrite,
    ReadOnly,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryItem {
    pub provider: ProviderId,
    pub kind: DiscoveryKind,
    pub category: DiscoveryCategory,
    pub layer: DiscoveryLayer,
    pub id: String,
    pub display_name: String,
    pub enabled: bool,
    pub mutability: DiscoveryMutability,
    pub source_path: String,
    pub state_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<HookInventoryMetadata>,
}

impl DiscoveryItem {
    pub fn is_shared_skill_source(&self) -> bool {
        if self.category != DiscoveryCategory::Skill {
            return false;
        }

        match self.provider {
            ProviderId::Claude | ProviderId::Zed => true,
            ProviderId::Cursor => {
                let id_prefix = match self.layer {
                    DiscoveryLayer::Global => CURSOR_GLOBAL_SKILL_ID_PREFIX,
                    DiscoveryLayer::Project => CURSOR_PROJECT_SKILL_ID_PREFIX,
                };
                self.id.strip_prefix(id_prefix).is_some_and(|id| {
                    CURSOR_COMPAT_SKILL_NAMESPACES
                        .iter()
                        .any(|namespace| id.starts_with(namespace))
                })
            }
            ProviderId::Codex => Path::new(&self.source_path)
                .components()
                .map(|component| component.as_os_str())
                .collect::<Vec<_>>()
                .windows(2)
                .any(|components| components[0] == ".agents" && components[1] == "skills"),
            ProviderId::Pi => {
                let id_prefix = match self.layer {
                    DiscoveryLayer::Global => PI_GLOBAL_SKILL_ID_PREFIX,
                    DiscoveryLayer::Project => PI_PROJECT_SKILL_ID_PREFIX,
                };
                self.id
                    .strip_prefix(id_prefix)
                    .is_some_and(|id| id.starts_with(PI_COMPAT_AGENTS_SKILL_NAMESPACE))
            }
            ProviderId::OpenCode => {
                let id_prefix = match self.layer {
                    DiscoveryLayer::Global => OPENCODE_GLOBAL_SKILL_ID_PREFIX,
                    DiscoveryLayer::Project => OPENCODE_PROJECT_SKILL_ID_PREFIX,
                };
                self.id.strip_prefix(id_prefix).is_some_and(|id| {
                    id.starts_with(OPENCODE_COMPAT_AGENTS_SKILL_NAMESPACE)
                        || id.starts_with(OPENCODE_COMPAT_CLAUDE_SKILL_NAMESPACE)
                })
            }
        }
    }

    #[must_use]
    pub fn uses_codex_skill_config_state(&self) -> bool {
        self.provider == ProviderId::Codex
            && self.category == DiscoveryCategory::Skill
            && Path::new(&self.state_path)
                .file_name()
                .is_some_and(|name| name == "config.toml")
    }

    #[must_use]
    pub fn is_catalog_adoption_candidate(&self) -> bool {
        self.enabled
            && self.mutability == DiscoveryMutability::ReadWrite
            && matches!(
                self.category,
                DiscoveryCategory::Skill | DiscoveryCategory::Agent
            )
            && !self.is_shared_skill_source()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryWarning {
    pub provider: ProviderId,
    pub layer: Option<DiscoveryLayer>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryOutput {
    pub items: Vec<DiscoveryItem>,
    pub warnings: Vec<DiscoveryWarning>,
}

impl DiscoveryOutput {
    pub fn to_catalog(&self) -> Result<crate::catalog::Catalog, crate::catalog::CatalogModelError> {
        crate::catalog::Catalog::from_discovery(self)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpDocument {
    #[serde(default)]
    mcp_servers: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeSettings {
    enable_all_project_mcp_servers: Option<bool>,
    #[serde(default)]
    enabled_mcpjson_servers: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    disabled_mcpjson_servers: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    enabled_plugins: BTreeMap<String, bool>,
    #[serde(default)]
    hooks: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ZedSettings {
    #[serde(default)]
    context_servers: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OpenCodeConfig {
    #[serde(default)]
    mcp: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    plugin: Vec<serde_json::Value>,
}

const CURSOR_WORKSPACE_DISABLED_SERVERS_KEY: &str = "cursor/disabledMcpServers";
const CURSOR_MARKETPLACE_PLUGIN_KEY_PREFIX: &str = "cursor.plugins.installedIds.";

#[derive(Debug, Clone)]
enum CursorWorkspaceState {
    Missing,
    Ok {
        database_path: PathBuf,
        disabled_server_ids: BTreeSet<String>,
    },
}

struct SettingsSource<T> {
    path: PathBuf,
    layer: DiscoveryLayer,
    source_label: &'static str,
    display_name: &'static str,
    document: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredVaultEntry {
    version: u8,
    provider: String,
    kind: String,
    layer: String,
    item_id: String,
    display_name: String,
    original_path: String,
    vaulted_path: String,
    payload_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredOpenCodePluginVaultPayload {
    plugin_id: String,
    original_order: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPiPackageVaultPayload {
    package_source: String,
    original_entry: serde_json::Value,
    original_raw: String,
    disabled_entry_fingerprint: String,
}

pub fn discover_all(roots: &DiscoveryRoots) -> Result<DiscoveryOutput, DiscoveryError> {
    discover_all_with_progress(roots, |_| true)
}

pub fn discover_all_with_progress(
    roots: &DiscoveryRoots,
    mut report_progress: impl FnMut(DiscoveryProgress) -> bool,
) -> Result<DiscoveryOutput, DiscoveryError> {
    let mut state = DiscoveryState::default();
    let descriptors = provider_registry();

    for (completed_providers, descriptor) in descriptors.iter().enumerate() {
        if !report_progress(DiscoveryProgress {
            phase: DiscoveryProgressPhase::DiscoveringProvider(descriptor.id),
            completed_providers,
            provider_count: descriptors.len(),
        }) {
            return Err(DiscoveryCancelled.into());
        }
        (descriptor.discoverer)(roots, &mut state)?;
    }
    if !report_progress(DiscoveryProgress {
        phase: DiscoveryProgressPhase::Finalizing,
        completed_providers: descriptors.len(),
        provider_count: descriptors.len(),
    }) {
        return Err(DiscoveryCancelled.into());
    }
    let DiscoveryState {
        shared_skill_views,
        mut items,
        warnings,
        ..
    } = state;
    project_disabled_shared_skill_views(&shared_skill_views, &mut items);
    sort_items(&mut items);

    Ok(DiscoveryOutput { items, warnings })
}

pub(crate) type ProviderDiscoverer =
    fn(&DiscoveryRoots, &mut DiscoveryState) -> Result<(), DiscoveryError>;

fn read_settings_source<T>(
    path: PathBuf,
    provider: ProviderId,
    layer: DiscoveryLayer,
    source_label: &'static str,
    display_name: &'static str,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<Option<SettingsSource<T>>, DiscoveryError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(document) = read_json_if_exists::<T>(&path, provider, Some(layer), warnings)? else {
        return Ok(None);
    };

    Ok(Some(SettingsSource {
        path,
        layer,
        source_label,
        display_name,
        document,
    }))
}

fn read_json_if_exists<T>(
    path: &Path,
    provider: ProviderId,
    layer: Option<DiscoveryLayer>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<Option<T>, DiscoveryError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(raw) = read_optional_string(path)? else {
        return Ok(None);
    };
    match serde_json::from_str(&raw) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            warnings.push(DiscoveryWarning {
                provider,
                layer,
                code: "json-parse-error".to_string(),
                message: format!("{} is not valid JSON: {error}", path.display()),
            });
            Ok(None)
        }
    }
}

fn read_jsonc_if_exists<T>(
    path: &Path,
    provider: ProviderId,
    layer: Option<DiscoveryLayer>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<Option<T>, DiscoveryError>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(raw) = read_optional_string(path)? else {
        return Ok(None);
    };
    match jsonc_parser::parse_to_serde_value(&raw, &Default::default()) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            warnings.push(DiscoveryWarning {
                provider,
                layer,
                code: "json-parse-error".to_string(),
                message: format!("{} is not valid JSONC: {error}", path.display()),
            });
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SkillDiscoverySpec<'a> {
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &'a str,
    mutability: DiscoveryMutability,
    traversal: ProjectSkillTraversal,
    skill_root_traversal: SkillRootTraversal,
}

#[derive(Debug, Clone, Copy)]
struct SkillItemDiscoverySpec<'a> {
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &'a str,
    mutability: DiscoveryMutability,
}

struct VaultedSkillDiscoverySpec<'a> {
    provider: ProviderId,
    layer: DiscoveryLayer,
    live_ids: &'a BTreeSet<String>,
    allowed_skill_roots: &'a [PathBuf],
    skill_root_traversal: SkillRootTraversal,
}

#[derive(Debug, Clone)]
pub(crate) struct SkillView {
    provider: ProviderId,
    layer: DiscoveryLayer,
    root: PathBuf,
    id_prefix: String,
    skill_root_traversal: SkillRootTraversal,
}

impl SkillView {
    fn new(
        provider: ProviderId,
        layer: DiscoveryLayer,
        root: PathBuf,
        id_prefix: impl Into<String>,
        skill_root_traversal: SkillRootTraversal,
    ) -> Self {
        Self {
            provider,
            layer,
            root,
            id_prefix: id_prefix.into(),
            skill_root_traversal,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SkillRootTraversal {
    Direct,
    Recursive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProjectSkillTraversal {
    Selected,
    Ancestors,
    AncestorsAndDescendants,
    Repository,
}

struct ProjectSkillDiscovery {
    live_ids: BTreeSet<String>,
    skill_roots: Vec<PathBuf>,
    skill_views: Vec<SkillView>,
}

#[derive(Clone)]
struct ProjectSkillScopeRoots {
    roots: BTreeSet<PathBuf>,
    skipped_directories: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectScopeCacheKey {
    project_root: PathBuf,
    repository_root: PathBuf,
    relative_skill_root: PathBuf,
    traversal: ProjectSkillTraversal,
    scan_project_scopes: bool,
}

#[derive(Default)]
pub(crate) struct ProjectScopeCache {
    scopes: BTreeMap<ProjectScopeCacheKey, Arc<ProjectSkillScopeRoots>>,
}

#[derive(Default)]
pub(crate) struct DiscoveryState {
    project_scope_cache: ProjectScopeCache,
    shared_skill_views: Vec<SkillView>,
    items: Vec<DiscoveryItem>,
    warnings: Vec<DiscoveryWarning>,
}

impl ProjectScopeCache {
    fn get_or_discover(
        &mut self,
        project_root: &Path,
        repository_root: &Path,
        relative_skill_root: &Path,
        traversal: ProjectSkillTraversal,
        scan_project_scopes: bool,
        discover: impl FnOnce() -> Result<ProjectSkillScopeRoots, DiscoveryError>,
    ) -> Result<&ProjectSkillScopeRoots, DiscoveryError> {
        let key = ProjectScopeCacheKey {
            project_root: project_root.to_path_buf(),
            repository_root: repository_root.to_path_buf(),
            relative_skill_root: relative_skill_root.to_path_buf(),
            traversal,
            scan_project_scopes,
        };
        let scope_roots = match self.scopes.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Arc::new(discover()?)),
        };
        Ok(Arc::as_ref(scope_roots))
    }
}

fn prepopulate_cursor_repository_scopes(
    roots: &DiscoveryRoots,
    project_scope_cache: &mut ProjectScopeCache,
) -> Result<(), DiscoveryError> {
    let requests = [
        (roots.cursor_project.as_path(), Path::new(".cursor/skills")),
        (roots.shared_project.as_path(), Path::new(".agents/skills")),
        (roots.claude_project.as_path(), Path::new(".claude/skills")),
        (roots.codex_project.as_path(), Path::new(".codex/skills")),
    ];
    prepopulate_repository_project_scopes(project_scope_cache, &requests, roots.scan_project_scopes)
}

fn prepopulate_repository_project_scopes(
    project_scope_cache: &mut ProjectScopeCache,
    requests: &[(&Path, &Path)],
    scan_project_scopes: bool,
) -> Result<(), DiscoveryError> {
    if !scan_project_scopes || requests.is_empty() {
        return Ok(());
    }

    let Some(repository_root) = enclosing_repository_root(requests[0].0) else {
        return Ok(());
    };
    if !requests.iter().all(|(project_root, _)| {
        enclosing_repository_root(project_root).as_ref() == Some(&repository_root)
    }) {
        return Ok(());
    }

    let relative_skill_roots = requests
        .iter()
        .map(|(_, relative_skill_root)| (*relative_skill_root).to_path_buf())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let scope_roots = project_repository_scope_roots(&repository_root, &relative_skill_roots)?
        .into_iter()
        .map(|(relative_skill_root, scope_roots)| (relative_skill_root, Arc::new(scope_roots)))
        .collect::<BTreeMap<_, _>>();

    for (project_root, relative_skill_root) in requests {
        let key = ProjectScopeCacheKey {
            project_root: (*project_root).to_path_buf(),
            repository_root: repository_root.clone(),
            relative_skill_root: (*relative_skill_root).to_path_buf(),
            traversal: ProjectSkillTraversal::Repository,
            scan_project_scopes: true,
        };
        if project_scope_cache.scopes.contains_key(&key) {
            continue;
        }
        let scope_roots = Arc::clone(
            scope_roots
                .get(*relative_skill_root)
                .expect("every requested relative skill root is scanned"),
        );
        project_scope_cache.scopes.insert(key, scope_roots);
    }

    Ok(())
}

fn skill_path_mutability(
    root: &Path,
    skill_file: &Path,
    requested: DiscoveryMutability,
    allow_provider_owned_symlinks: bool,
) -> Result<DiscoveryMutability, DiscoveryError> {
    if requested != DiscoveryMutability::ReadWrite {
        return Ok(requested);
    }
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Ok(DiscoveryMutability::ReadOnly);
    }

    let relative = skill_file.strip_prefix(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            if allow_provider_owned_symlinks
                && (current == skill_file || skill_file.parent() == Some(current.as_path()))
            {
                continue;
            }
            return Ok(DiscoveryMutability::ReadOnly);
        }
    }

    Ok(requested)
}

fn discover_project_skill_dirs(
    project_root: &Path,
    relative_skill_root: &Path,
    spec: SkillDiscoverySpec<'_>,
    scan_project_scopes: bool,
    project_scope_cache: &mut ProjectScopeCache,
    warnings: &mut Vec<DiscoveryWarning>,
    items: &mut Vec<DiscoveryItem>,
) -> Result<ProjectSkillDiscovery, DiscoveryError> {
    let repository_root = scan_project_scopes
        .then(|| enclosing_repository_root(project_root))
        .flatten();
    let scan_project_scopes = repository_root.is_some();
    let repository_root = repository_root.unwrap_or_else(|| project_root.to_path_buf());
    let scope_discovery = project_scope_cache.get_or_discover(
        project_root,
        &repository_root,
        relative_skill_root,
        spec.traversal,
        scan_project_scopes,
        || {
            project_skill_scope_roots(
                project_root,
                &repository_root,
                relative_skill_root,
                spec.traversal,
                scan_project_scopes,
            )
        },
    )?;
    if scope_discovery.skipped_directories > 0 {
        warnings.push(DiscoveryWarning {
            provider: spec.provider,
            layer: Some(spec.layer),
            code: "scope-scan-incomplete".to_string(),
            message: format!(
                "{} project skill scan skipped {} unreadable or vanished directories",
                relative_skill_root.display(),
                scope_discovery.skipped_directories
            ),
        });
    }
    let mut live_ids = BTreeSet::new();
    let mut skill_roots = Vec::with_capacity(scope_discovery.roots.len());
    let mut skill_views = Vec::with_capacity(scope_discovery.roots.len());

    for scope_root in &scope_discovery.roots {
        let relative_scope = scope_root.strip_prefix(&repository_root)?;
        let scoped_prefix = if relative_scope.as_os_str().is_empty() {
            spec.id_prefix.to_string()
        } else {
            format!(
                "{}@scope/{}/",
                spec.id_prefix,
                skill_id_path(relative_scope)
            )
        };
        let skill_root = scope_root.join(relative_skill_root);
        skill_views.push(SkillView::new(
            spec.provider,
            spec.layer,
            skill_root.clone(),
            scoped_prefix.clone(),
            spec.skill_root_traversal,
        ));
        live_ids.extend(match spec.skill_root_traversal {
            SkillRootTraversal::Direct => discover_direct_child_skill_dirs(
                &skill_root,
                spec.provider,
                spec.layer,
                &scoped_prefix,
                spec.mutability,
                items,
            )?,
            SkillRootTraversal::Recursive => discover_recursive_skill_dirs(
                &skill_root,
                spec.provider,
                spec.layer,
                &scoped_prefix,
                spec.mutability,
                items,
                warnings,
            )?,
        });
        skill_roots.push(skill_root);
    }

    Ok(ProjectSkillDiscovery {
        live_ids,
        skill_roots,
        skill_views,
    })
}

fn find_repository_root(project_root: &Path) -> PathBuf {
    enclosing_repository_root(project_root).unwrap_or_else(|| project_root.to_path_buf())
}

fn enclosing_repository_root(project_root: &Path) -> Option<PathBuf> {
    project_root
        .ancestors()
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
}

fn project_skill_scope_roots(
    project_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
    traversal: ProjectSkillTraversal,
    scan_project_scopes: bool,
) -> Result<ProjectSkillScopeRoots, DiscoveryError> {
    if !scan_project_scopes {
        return Ok(ProjectSkillScopeRoots {
            roots: BTreeSet::from([project_root.to_path_buf()]),
            skipped_directories: 0,
        });
    }

    let mut scope_roots = BTreeSet::new();
    let skipped_directories = match traversal {
        ProjectSkillTraversal::Selected => {
            scope_roots.insert(project_root.to_path_buf());
            0
        }
        ProjectSkillTraversal::Ancestors => {
            add_project_ancestors(project_root, repository_root, &mut scope_roots);
            0
        }
        ProjectSkillTraversal::AncestorsAndDescendants => {
            add_project_ancestors(project_root, repository_root, &mut scope_roots);
            add_descendant_skill_scopes(
                project_root,
                repository_root,
                relative_skill_root,
                &mut scope_roots,
            )?
        }
        ProjectSkillTraversal::Repository => add_descendant_skill_scopes(
            repository_root,
            repository_root,
            relative_skill_root,
            &mut scope_roots,
        )?,
    };

    Ok(ProjectSkillScopeRoots {
        roots: scope_roots,
        skipped_directories,
    })
}

fn add_project_ancestors(
    project_root: &Path,
    repository_root: &Path,
    scope_roots: &mut impl Extend<PathBuf>,
) {
    let mut ancestors = Vec::new();
    for ancestor in project_root.ancestors() {
        ancestors.push(ancestor.to_path_buf());
        if ancestor == repository_root {
            break;
        }
    }
    scope_roots.extend(ancestors);
}

const MAX_PROJECT_SCOPE_SCAN_WORKERS: usize = 8;

#[derive(Default)]
struct ProjectScopeScan {
    scope_roots: BTreeSet<PathBuf>,
    skipped_directories: usize,
}

#[derive(Default)]
struct ProjectScopeMultiScan {
    scope_roots: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    skipped_directories: usize,
}

struct ProjectScopeDirectoryScan {
    scope_root: Option<PathBuf>,
    child_directories: Vec<PathBuf>,
    skipped_directories: usize,
}

fn add_descendant_skill_scopes(
    search_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
    scope_roots: &mut BTreeSet<PathBuf>,
) -> Result<usize, DiscoveryError> {
    add_descendant_skill_scopes_with_worker_limit(
        search_root,
        repository_root,
        relative_skill_root,
        scope_roots,
        project_scope_scan_worker_limit(),
    )
}

fn add_descendant_skill_scopes_with_worker_limit(
    search_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
    scope_roots: &mut BTreeSet<PathBuf>,
    worker_limit: usize,
) -> Result<usize, DiscoveryError> {
    if !search_root.is_dir() {
        return Ok(0);
    }

    let worker_limit = worker_limit.max(1);
    let mut scan = ProjectScopeScan::default();
    let mut frontier = vec![search_root.to_path_buf()];
    while frontier.len() < worker_limit {
        let Some(directory) = frontier.pop() else {
            break;
        };
        let directory_scan = scan_project_scope_directory(
            &directory,
            search_root,
            repository_root,
            relative_skill_root,
        )?;
        extend_project_scope_scan(&mut scan, &directory_scan);
        frontier.extend(directory_scan.child_directories);
    }

    for subtree_scan in scan_project_scope_frontier(
        &frontier,
        search_root,
        repository_root,
        relative_skill_root,
        worker_limit,
    )? {
        merge_project_scope_scan(&mut scan, subtree_scan);
    }

    scope_roots.extend(scan.scope_roots);
    Ok(scan.skipped_directories)
}

fn project_scope_scan_worker_limit() -> usize {
    thread::available_parallelism()
        .map_or(1, |count| count.get().min(MAX_PROJECT_SCOPE_SCAN_WORKERS))
}

fn project_repository_scope_roots(
    repository_root: &Path,
    relative_skill_roots: &[PathBuf],
) -> Result<BTreeMap<PathBuf, ProjectSkillScopeRoots>, DiscoveryError> {
    let Some(primary_relative_skill_root) = relative_skill_roots.first() else {
        return Ok(BTreeMap::new());
    };
    let mut scan = ProjectScopeMultiScan::default();
    for relative_skill_root in relative_skill_roots {
        scan.scope_roots
            .entry(relative_skill_root.clone())
            .or_default();
    }
    if !repository_root.is_dir() {
        return Ok(project_skill_scope_roots_from_multi_scan(
            scan,
            relative_skill_roots,
        ));
    }

    let worker_limit = project_scope_scan_worker_limit();
    let mut frontier = vec![repository_root.to_path_buf()];
    while frontier.len() < worker_limit {
        let Some(directory) = frontier.pop() else {
            break;
        };
        let directory_scan = scan_project_scope_directory(
            &directory,
            repository_root,
            repository_root,
            primary_relative_skill_root,
        )?;
        extend_project_scope_multi_scan(
            &mut scan,
            &directory,
            relative_skill_roots,
            &directory_scan,
        );
        frontier.extend(directory_scan.child_directories);
    }

    for subtree_scan in scan_project_scope_frontier_accumulating_with(
        &frontier,
        worker_limit,
        |directory| {
            scan_project_scope_multi_subtree(directory, repository_root, relative_skill_roots)
        },
        merge_project_scope_multi_scan,
    )? {
        merge_project_scope_multi_scan(&mut scan, subtree_scan);
    }

    Ok(project_skill_scope_roots_from_multi_scan(
        scan,
        relative_skill_roots,
    ))
}

fn project_skill_scope_roots_from_multi_scan(
    scan: ProjectScopeMultiScan,
    relative_skill_roots: &[PathBuf],
) -> BTreeMap<PathBuf, ProjectSkillScopeRoots> {
    relative_skill_roots
        .iter()
        .map(|relative_skill_root| {
            (
                relative_skill_root.clone(),
                ProjectSkillScopeRoots {
                    roots: scan
                        .scope_roots
                        .get(relative_skill_root)
                        .cloned()
                        .unwrap_or_default(),
                    skipped_directories: scan.skipped_directories,
                },
            )
        })
        .collect()
}

fn scan_project_scope_multi_subtree(
    start: &Path,
    repository_root: &Path,
    relative_skill_roots: &[PathBuf],
) -> Result<ProjectScopeMultiScan, DiscoveryError> {
    let primary_relative_skill_root = relative_skill_roots
        .first()
        .expect("repository scope scans include a relative skill root");
    let mut scan = ProjectScopeMultiScan::default();
    let mut pending = vec![start.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let directory_scan = scan_project_scope_directory(
            &directory,
            repository_root,
            repository_root,
            primary_relative_skill_root,
        )?;
        extend_project_scope_multi_scan(
            &mut scan,
            &directory,
            relative_skill_roots,
            &directory_scan,
        );
        pending.extend(directory_scan.child_directories);
    }
    Ok(scan)
}

fn extend_project_scope_multi_scan(
    scan: &mut ProjectScopeMultiScan,
    directory: &Path,
    relative_skill_roots: &[PathBuf],
    directory_scan: &ProjectScopeDirectoryScan,
) {
    let Some((primary_relative_skill_root, additional_relative_skill_roots)) =
        relative_skill_roots.split_first()
    else {
        return;
    };
    if directory_scan.scope_root.is_some() {
        scan.scope_roots
            .entry(primary_relative_skill_root.clone())
            .or_default()
            .insert(directory.to_path_buf());
    }
    for relative_skill_root in additional_relative_skill_roots {
        if directory.join(relative_skill_root).is_dir() {
            scan.scope_roots
                .entry(relative_skill_root.clone())
                .or_default()
                .insert(directory.to_path_buf());
        }
    }
    scan.skipped_directories += directory_scan.skipped_directories;
}

fn merge_project_scope_multi_scan(
    scan: &mut ProjectScopeMultiScan,
    subtree_scan: ProjectScopeMultiScan,
) {
    for (relative_skill_root, scope_roots) in subtree_scan.scope_roots {
        scan.scope_roots
            .entry(relative_skill_root)
            .or_default()
            .extend(scope_roots);
    }
    scan.skipped_directories += subtree_scan.skipped_directories;
}

fn scan_project_scope_frontier(
    frontier: &[PathBuf],
    search_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
    worker_limit: usize,
) -> Result<Vec<ProjectScopeScan>, DiscoveryError> {
    scan_project_scope_frontier_with(frontier, worker_limit, |directory| {
        scan_project_scope_subtree(directory, search_root, repository_root, relative_skill_root)
    })
}

fn merge_project_scope_scan(scan: &mut ProjectScopeScan, subtree_scan: ProjectScopeScan) {
    scan.scope_roots.extend(subtree_scan.scope_roots);
    scan.skipped_directories += subtree_scan.skipped_directories;
}

fn scan_project_scope_subtree(
    start: &Path,
    search_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
) -> Result<ProjectScopeScan, DiscoveryError> {
    let mut scan = ProjectScopeScan::default();
    let mut pending = vec![start.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let directory_scan = scan_project_scope_directory(
            &directory,
            search_root,
            repository_root,
            relative_skill_root,
        )?;
        extend_project_scope_scan(&mut scan, &directory_scan);
        pending.extend(directory_scan.child_directories);
    }
    Ok(scan)
}

fn extend_project_scope_scan(
    scan: &mut ProjectScopeScan,
    directory_scan: &ProjectScopeDirectoryScan,
) {
    if let Some(scope_root) = &directory_scan.scope_root {
        scan.scope_roots.insert(scope_root.clone());
    }
    scan.skipped_directories += directory_scan.skipped_directories;
}

fn scan_project_scope_directory(
    directory: &Path,
    search_root: &Path,
    repository_root: &Path,
    relative_skill_root: &Path,
) -> Result<ProjectScopeDirectoryScan, DiscoveryError> {
    if is_inactive_repository_root(repository_root, directory) {
        return Ok(ProjectScopeDirectoryScan {
            scope_root: None,
            child_directories: Vec::new(),
            skipped_directories: 0,
        });
    }
    let scope_root = directory
        .join(relative_skill_root)
        .is_dir()
        .then(|| directory.to_path_buf());
    let read_dir = match fs::read_dir(directory) {
        Ok(read_dir) => read_dir,
        Err(error) if directory != search_root && recoverable_project_scope_scan_error(&error) => {
            return Ok(ProjectScopeDirectoryScan {
                scope_root,
                child_directories: Vec::new(),
                skipped_directories: 1,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let mut skipped_directories = 0;
    let mut entries = Vec::new();
    for entry in read_dir {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) if recoverable_project_scope_scan_error(&error) => {
                skipped_directories += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    entries.sort_by_key(|entry| entry.file_name());

    let mut child_directories = Vec::new();
    for entry in entries.into_iter().rev() {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if recoverable_project_scope_scan_error(&error) => {
                skipped_directories += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if !file_type.is_dir()
            || should_skip_project_scope_dir(&entry.file_name())
            || is_repository_tmp_dir(repository_root, &entry.path())
        {
            continue;
        }
        child_directories.push(entry.path());
    }

    Ok(ProjectScopeDirectoryScan {
        scope_root,
        child_directories,
        skipped_directories,
    })
}

fn recoverable_project_scope_scan_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::NotADirectory
            | std::io::ErrorKind::PermissionDenied
    )
}

fn should_skip_project_scope_dir(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            ".agents"
                | ".claude"
                | ".cursor"
                | ".git"
                | ".hg"
                | ".opencode"
                | ".pi"
                | ".svn"
                | ".worktrees"
                | "fixture"
                | "fixtures"
                | "node_modules"
                | "target"
                | "test"
                | "tests"
        )
    )
}

fn is_inactive_repository_root(active_repository_root: &Path, directory: &Path) -> bool {
    directory != active_repository_root && directory.join(".git").exists()
}

fn is_repository_tmp_dir(repository_root: &Path, directory: &Path) -> bool {
    directory
        .strip_prefix(repository_root)
        .is_ok_and(|relative| relative == Path::new("tmp"))
}

fn skill_id_path(path: &Path) -> String {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .replace('%', "%25")
                .replace('@', "%40")
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn discover_direct_skill_markdown_files(
    root: &Path,
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    mutability: DiscoveryMutability,
    items: &mut Vec<DiscoveryItem>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    if !root.exists() {
        return Ok(live_ids);
    }

    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if !path.is_file()
            || path.extension().and_then(OsStr::to_str) != Some("md")
            || path.file_name() == Some(OsStr::new("SKILL.md"))
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };
        if stem.is_empty() {
            continue;
        }
        let id = format!("{id_prefix}{}", skill_id_path(Path::new(stem)));
        live_ids.insert(id.clone());
        let source_fingerprint = fs::read_to_string(&path)
            .ok()
            .map(|raw| source_fingerprint(&raw));
        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Skill,
            category: DiscoveryCategory::Skill,
            layer,
            id,
            display_name: stem.to_string(),
            enabled: true,
            mutability: skill_path_mutability(root, &path, mutability, true)?,
            source_path: path_string(&path),
            state_path: path_string(&path),
            source_fingerprint,
            hook: None,
        });
    }

    Ok(live_ids)
}

fn discover_direct_child_skill_dirs(
    root: &Path,
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    mutability: DiscoveryMutability,
    items: &mut Vec<DiscoveryItem>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    if !root.exists() {
        return Ok(live_ids);
    }

    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let spec = SkillItemDiscoverySpec {
        provider,
        layer,
        id_prefix,
        mutability,
    };

    for entry in entries {
        let skill_dir = entry.path();
        if !skill_dir.is_dir() {
            continue;
        }
        discover_skill_dir(root, &skill_dir, spec, &mut live_ids, items)?;
    }

    Ok(live_ids)
}

fn discover_recursive_skill_dirs(
    root: &Path,
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    mutability: DiscoveryMutability,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    if !root.exists() {
        return Ok(live_ids);
    }

    let mut pending = vec![root.to_path_buf()];
    let spec = SkillItemDiscoverySpec {
        provider,
        layer,
        id_prefix,
        mutability,
    };
    let mut skipped_directories = 0;
    while let Some(directory) = pending.pop() {
        let read_dir = match fs::read_dir(&directory) {
            Ok(read_dir) => read_dir,
            Err(error) if directory != root && recoverable_project_scope_scan_error(&error) => {
                skipped_directories += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let mut entries = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => entries.push(entry),
                Err(error) if recoverable_project_scope_scan_error(&error) => {
                    skipped_directories += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries.into_iter().rev() {
            let skill_dir = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if recoverable_project_scope_scan_error(&error) => {
                    skipped_directories += 1;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };

            if file_type.is_dir() {
                discover_skill_dir(root, &skill_dir, spec, &mut live_ids, items)?;
                pending.push(skill_dir);
                continue;
            }

            if !file_type.is_symlink() {
                continue;
            }
            match fs::metadata(&skill_dir) {
                Ok(metadata) if metadata.is_dir() => {
                    discover_skill_dir(root, &skill_dir, spec, &mut live_ids, items)?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) if recoverable_project_scope_scan_error(&error) => {
                    skipped_directories += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    if skipped_directories > 0 {
        warnings.push(DiscoveryWarning {
            provider,
            layer: Some(layer),
            code: "scope-scan-incomplete".to_string(),
            message: format!(
                "{} {} recursive skill scan skipped {skipped_directories} unreadable or vanished directories",
                provider.as_str(),
                layer.as_str()
            ),
        });
    }

    Ok(live_ids)
}

fn discover_skill_dir(
    root: &Path,
    skill_dir: &Path,
    spec: SkillItemDiscoverySpec<'_>,
    live_ids: &mut BTreeSet<String>,
    items: &mut Vec<DiscoveryItem>,
) -> Result<(), DiscoveryError> {
    let skill_file = skill_dir.join("SKILL.md");
    if !skill_file.is_file() {
        return Ok(());
    }
    let relative_id = skill_dir.strip_prefix(root)?;
    if relative_id.as_os_str().is_empty() {
        return Ok(());
    }
    let Some(display_name) = skill_dir.file_name() else {
        return Ok(());
    };
    let display_name = display_name.to_string_lossy().to_string();
    if display_name.is_empty() {
        return Ok(());
    }

    let id = format!("{}{}", spec.id_prefix, skill_id_path(relative_id));
    live_ids.insert(id.clone());
    let source_fingerprint = fs::read_to_string(&skill_file)
        .ok()
        .map(|raw| source_fingerprint(&raw));
    let item_mutability = skill_path_mutability(root, &skill_file, spec.mutability, true)?;
    items.push(DiscoveryItem {
        provider: spec.provider,
        kind: DiscoveryKind::Skill,
        category: DiscoveryCategory::Skill,
        layer: spec.layer,
        id,
        display_name,
        enabled: true,
        mutability: item_mutability,
        source_path: path_string(&skill_file),
        state_path: path_string(skill_dir),
        source_fingerprint,
        hook: None,
    });

    Ok(())
}

fn discover_vaulted_skill_items(
    app_state_root: Option<&Path>,
    spec: VaultedSkillDiscoverySpec<'_>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let VaultedSkillDiscoverySpec {
        provider,
        layer,
        live_ids,
        allowed_skill_roots,
        skill_root_traversal,
    } = spec;
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("skill");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = format!("{}:{}:skill:", provider.as_str(), layer.as_str());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "skill",
            "path",
            &expected_id_prefix,
            warnings,
        ) else {
            continue;
        };
        if vault_entry
            .item_id
            .strip_prefix(&expected_id_prefix)
            .is_some_and(|id| id.starts_with("@file/"))
        {
            continue;
        }
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists".to_string())
        } else if !vaulted_skill_belongs_to_roots(
            &vault_entry.original_path,
            allowed_skill_roots,
            skill_root_traversal,
        ) {
            Some("originalPath is outside the discovered skill roots".to_string())
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &entry.path().join("payload"),
        ) {
            Some("vaultedPath does not match the entry payload path".to_string())
        } else if !skill_payload_has_skill(
            Path::new(&vault_entry.vaulted_path),
            Path::new(&vault_entry.original_path),
        ) {
            Some("vaultedPath does not contain SKILL.md".to_string())
        } else {
            None
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
            continue;
        }

        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Skill,
            category: DiscoveryCategory::Skill,
            layer,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: path_string(&Path::new(&vault_entry.original_path).join("SKILL.md")),
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

fn discover_vaulted_skill_file_items(
    app_state_root: Option<&Path>,
    provider: ProviderId,
    layer: DiscoveryLayer,
    live_ids: &BTreeSet<String>,
    allowed_skill_roots: &[PathBuf],
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("skill");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = format!("{}:{}:skill:", provider.as_str(), layer.as_str());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "skill",
            "path",
            &expected_id_prefix,
            warnings,
        ) else {
            continue;
        };
        if !vault_entry
            .item_id
            .strip_prefix(&expected_id_prefix)
            .is_some_and(|id| id.starts_with("@file/"))
        {
            continue;
        }
        let original_path = Path::new(&vault_entry.original_path);
        let expected_vaulted_path = entry.path().join("payload");
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists")
        } else if !allowed_skill_roots
            .iter()
            .any(|root| original_path.parent() == Some(root.as_path()))
        {
            Some("originalPath is outside the discovered file skill roots")
        } else if original_path.extension().and_then(OsStr::to_str) != Some("md") {
            Some("originalPath is not a Markdown skill file")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_vaulted_path,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !Path::new(&vault_entry.vaulted_path).is_file() {
            Some("vaultedPath is not a file")
        } else {
            None
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
            continue;
        }

        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Skill,
            category: DiscoveryCategory::Skill,
            layer,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: vault_entry.original_path,
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

fn project_disabled_shared_skill_views(views: &[SkillView], items: &mut Vec<DiscoveryItem>) {
    let disabled_items = items
        .iter()
        .filter(|item| {
            !item.enabled
                && item.category == DiscoveryCategory::Skill
                && item.is_shared_skill_source()
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut known_ids = items
        .iter()
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();

    for disabled_item in disabled_items {
        let source_path = Path::new(&disabled_item.source_path);
        if source_path.file_name() != Some(OsStr::new("SKILL.md")) {
            continue;
        }
        let Some(skill_dir) = source_path.parent() else {
            continue;
        };

        for view in views {
            if view.layer != disabled_item.layer {
                continue;
            }
            let Ok(relative_id) = skill_dir.strip_prefix(&view.root) else {
                continue;
            };
            let component_count = relative_id.components().count();
            if component_count == 0
                || matches!(view.skill_root_traversal, SkillRootTraversal::Direct)
                    && component_count != 1
            {
                continue;
            }

            let id = format!("{}{}", view.id_prefix, skill_id_path(relative_id));
            if !known_ids.insert(id.clone()) {
                continue;
            }

            items.push(DiscoveryItem {
                provider: view.provider,
                kind: DiscoveryKind::Skill,
                category: DiscoveryCategory::Skill,
                layer: view.layer,
                id,
                display_name: disabled_item.display_name.clone(),
                enabled: false,
                mutability: DiscoveryMutability::ReadWrite,
                source_path: disabled_item.source_path.clone(),
                state_path: disabled_item.state_path.clone(),
                source_fingerprint: None,
                hook: None,
            });
        }
    }
}

fn read_stored_vault_entry(
    entry: &fs::DirEntry,
    provider: ProviderId,
    layer: DiscoveryLayer,
    expected_kind: &str,
    expected_payload_kind: &str,
    expected_id_prefix: &str,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Option<(PathBuf, StoredVaultEntry)> {
    let entry_root = entry.path();
    let entry_path = entry_root.join("entry.json");
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(error) => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_root,
                format!("entry type could not be read: {error}"),
            );
            return None;
        }
    };
    if !file_type.is_dir() {
        push_invalid_vault_entry_warning(
            warnings,
            provider,
            layer,
            &entry_root,
            "vault child must be a directory",
        );
        return None;
    }

    let entry_metadata = match fs::symlink_metadata(&entry_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_path,
                format!("entry metadata could not be read: {error}"),
            );
            return None;
        }
    };
    if entry_metadata.file_type().is_symlink() || !entry_metadata.is_file() {
        push_invalid_vault_entry_warning(
            warnings,
            provider,
            layer,
            &entry_path,
            "entry.json must be a regular file",
        );
        return None;
    }

    let raw = match fs::read_to_string(&entry_path) {
        Ok(raw) => raw,
        Err(error) => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_path,
                format!("entry could not be read: {error}"),
            );
            return None;
        }
    };
    let vault_entry = match serde_json::from_str::<StoredVaultEntry>(&raw) {
        Ok(vault_entry) => vault_entry,
        Err(error) => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_path,
                format!("entry is not valid vault JSON: {error}"),
            );
            return None;
        }
    };
    if vault_entry.version != 1
        || vault_entry.provider != provider.as_str()
        || vault_entry.layer != layer.as_str()
        || vault_entry.kind != expected_kind
        || vault_entry.payload_kind != expected_payload_kind
    {
        push_invalid_vault_entry_warning(
            warnings,
            provider,
            layer,
            &entry_path,
            format!(
                "entry must use version 1, provider {}, layer {}, kind {expected_kind}, and payloadKind {expected_payload_kind}",
                provider.as_str(),
                layer.as_str()
            ),
        );
        return None;
    }

    let expected_entry_name = encode_path_segment(&vault_entry.item_id);
    if !vault_entry
        .item_id
        .strip_prefix(expected_id_prefix)
        .is_some_and(|suffix| !suffix.is_empty())
        || entry.file_name() != OsStr::new(&expected_entry_name)
    {
        push_invalid_vault_entry_warning(
            warnings,
            provider,
            layer,
            &entry_path,
            format!(
                "itemId must start with {expected_id_prefix} and match the vault directory name"
            ),
        );
        return None;
    }

    Some((entry_path, vault_entry))
}

fn vault_payload_path_matches(recorded: &Path, expected: &Path) -> bool {
    if recorded == expected {
        return true;
    }

    let (Some(recorded_parent), Some(expected_parent)) = (recorded.parent(), expected.parent())
    else {
        return false;
    };
    recorded.file_name() == expected.file_name()
        && fs::canonicalize(recorded_parent).ok() == fs::canonicalize(expected_parent).ok()
}

fn push_invalid_vault_entry_warning(
    warnings: &mut Vec<DiscoveryWarning>,
    provider: ProviderId,
    layer: DiscoveryLayer,
    entry_path: &Path,
    reason: impl AsRef<str>,
) {
    warnings.push(DiscoveryWarning {
        provider,
        layer: Some(layer),
        code: "invalid-vault-entry".to_string(),
        message: format!("{}: {}", entry_path.display(), reason.as_ref()),
    });
}

fn vaulted_skill_belongs_to_roots(
    original_path: &str,
    allowed_skill_roots: &[PathBuf],
    skill_root_traversal: SkillRootTraversal,
) -> bool {
    let original_path = Path::new(original_path);
    allowed_skill_roots.iter().any(|skill_root| {
        if matches!(skill_root_traversal, SkillRootTraversal::Direct) {
            return original_path.parent() == Some(skill_root.as_path());
        }

        original_path
            .strip_prefix(skill_root)
            .is_ok_and(|relative| {
                !relative.as_os_str().is_empty()
                    && relative
                        .components()
                        .all(|component| matches!(component, std::path::Component::Normal(_)))
            })
    })
}

pub(crate) fn skill_payload_has_skill(vaulted_path: &Path, original_path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(vaulted_path) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        if !metadata.is_dir() {
            return false;
        }
        let vaulted_skill_file = vaulted_path.join("SKILL.md");
        let Ok(skill_metadata) = fs::symlink_metadata(&vaulted_skill_file) else {
            return false;
        };
        if !skill_metadata.file_type().is_symlink() {
            return skill_metadata.is_file();
        }
        return resolved_symlink_target(&vaulted_skill_file, &original_path.join("SKILL.md"))
            .is_some_and(|target| target.is_file());
    }

    resolved_symlink_target(vaulted_path, original_path)
        .is_some_and(|target| target.join("SKILL.md").is_file())
}

fn resolved_symlink_target(symlink_path: &Path, restored_path: &Path) -> Option<PathBuf> {
    let target = fs::read_link(symlink_path).ok()?;
    if target.is_absolute() {
        return Some(target);
    }

    Some(normalize_path(restored_path.parent()?.join(target)))
}

fn discover_vaulted_cursor_plugin_items(
    app_state_root: Option<&Path>,
    live_ids: &BTreeSet<String>,
    local_plugins_root: &Path,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let vault_root = app_state_root
        .join("vault")
        .join("cursor")
        .join("global")
        .join("plugin");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            ProviderId::Cursor,
            DiscoveryLayer::Global,
            DiscoveryKind::Plugin.as_str(),
            "path",
            "cursor:global:plugin-manifest:local:",
            warnings,
        ) else {
            continue;
        };
        let entry_root = entry.path();
        let expected_vaulted_path = entry_root.join("payload");
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists")
        } else if Path::new(&vault_entry.original_path).parent() != Some(local_plugins_root) {
            Some("originalPath is outside Cursor's local plugin root")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_vaulted_path,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else {
            None
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(
                warnings,
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                &entry_path,
                reason,
            );
            continue;
        }
        let vaulted_plugin_path = Path::new(&vault_entry.vaulted_path);
        let Some(vaulted_manifest_path) = cursor_plugin_manifest_path(vaulted_plugin_path) else {
            push_invalid_vault_entry_warning(
                warnings,
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                &entry_path,
                "vaultedPath does not contain a supported Cursor plugin manifest",
            );
            continue;
        };

        let Some(manifest_relative_path) =
            vaulted_manifest_path.strip_prefix(vaulted_plugin_path).ok()
        else {
            push_invalid_vault_entry_warning(
                warnings,
                ProviderId::Cursor,
                DiscoveryLayer::Global,
                &entry_path,
                "plugin manifest is outside vaultedPath",
            );
            continue;
        };
        items.push(DiscoveryItem {
            provider: ProviderId::Cursor,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginManifest,
            layer: DiscoveryLayer::Global,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: path_string(
                &Path::new(&vault_entry.original_path).join(manifest_relative_path),
            ),
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentFileKind {
    Markdown,
    Toml,
}

fn discover_agent_files(
    root: &Path,
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    allowed_kinds: &[AgentFileKind],
    items: &mut Vec<DiscoveryItem>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    if !root.exists() {
        return Ok(live_ids);
    }

    let mut files = Vec::new();
    collect_agent_files(root, allowed_kinds, &mut files)?;
    files.sort();

    for file_path in files {
        let relative_id = file_stem_relative_id(root, &file_path)?;
        if relative_id.is_empty() {
            continue;
        }

        let display_name = agent_display_name(&file_path, &relative_id)?;
        let id = format!("{id_prefix}{display_name}");
        live_ids.insert(id.clone());
        let source_fingerprint = fs::read_to_string(&file_path)
            .ok()
            .map(|raw| source_fingerprint(&raw));
        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Agent,
            category: DiscoveryCategory::Agent,
            layer,
            id,
            display_name,
            enabled: true,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: path_string(&file_path),
            state_path: path_string(&file_path),
            source_fingerprint,
            hook: None,
        });
    }

    Ok(live_ids)
}

fn discover_vaulted_agent_items(
    app_state_root: Option<&Path>,
    provider: ProviderId,
    layer: DiscoveryLayer,
    live_ids: &BTreeSet<String>,
    allowed_agent_roots: &[PathBuf],
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("agent");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = format!("{}:{}:agent:", provider.as_str(), layer.as_str());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "agent",
            "path",
            &expected_id_prefix,
            warnings,
        ) else {
            continue;
        };
        let original_path = Path::new(&vault_entry.original_path);
        let expected_vaulted_path = entry.path().join("payload");
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists")
        } else if !allowed_agent_roots
            .iter()
            .any(|root| original_path != root && original_path.starts_with(root))
        {
            Some("originalPath is outside the discovered agent roots")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_vaulted_path,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !Path::new(&vault_entry.vaulted_path).is_file() {
            Some("vaultedPath is not a file")
        } else {
            None
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
            continue;
        }

        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Agent,
            category: DiscoveryCategory::Agent,
            layer,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: vault_entry.original_path,
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

struct ConfiguredMcpVaultSpec<'a> {
    provider: ProviderId,
    layer: DiscoveryLayer,
    payload_kind: &'static str,
    live_ids: &'a BTreeSet<String>,
    allowed_state_paths: &'a [PathBuf],
    allowed_item_id_prefix: Option<&'a str>,
}

fn discover_vaulted_configured_mcp_items(
    app_state_root: Option<&Path>,
    spec: ConfiguredMcpVaultSpec<'_>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let ConfiguredMcpVaultSpec {
        provider,
        layer,
        payload_kind,
        live_ids,
        allowed_state_paths,
        allowed_item_id_prefix,
    } = spec;
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("configured-mcp");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = format!("{}:{}:configured-mcp:", provider.as_str(), layer.as_str());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "configured-mcp",
            payload_kind,
            &expected_id_prefix,
            warnings,
        ) else {
            continue;
        };
        if allowed_item_id_prefix.is_some_and(|prefix| !vault_entry.item_id.starts_with(prefix)) {
            continue;
        }
        let payload_name = if payload_kind == "json-payload" {
            "payload.json"
        } else {
            "payload"
        };
        let expected_vaulted_path = entry.path().join(payload_name);
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists")
        } else if !allowed_state_paths
            .iter()
            .any(|path| path == Path::new(&vault_entry.original_path))
        {
            Some("originalPath is outside the discovered provider config paths")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_vaulted_path,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !Path::new(&vault_entry.vaulted_path).is_file() {
            Some("vaultedPath is not a file")
        } else {
            None
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
            continue;
        }

        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Mcp,
            category: DiscoveryCategory::ConfiguredMcp,
            layer,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: vault_entry.original_path,
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

fn discover_vaulted_opencode_plugin_config_items(
    app_state_root: Option<&Path>,
    layer: DiscoveryLayer,
    live_ids: &BTreeSet<String>,
    allowed_state_paths: &[PathBuf],
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let provider = ProviderId::OpenCode;
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("plugin");
    if !vault_root.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = format!("opencode:{}:plugin-config:npm:", layer.as_str());

    for entry in entries {
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "plugin",
            "json-payload",
            &expected_id_prefix,
            warnings,
        ) else {
            continue;
        };
        let expected_vaulted_path = entry.path().join("payload.json");
        let plugin_id = vault_entry
            .item_id
            .strip_prefix(&expected_id_prefix)
            .expect("stored vault id prefix validated");
        let invalid_reason = if live_ids.contains(&vault_entry.item_id) {
            Some("a live item with the same id already exists")
        } else if !allowed_state_paths
            .iter()
            .any(|path| path == Path::new(&vault_entry.original_path))
        {
            Some("originalPath is outside the discovered OpenCode config paths")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_vaulted_path,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !fs::symlink_metadata(&vault_entry.vaulted_path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            Some("vaultedPath is not a regular file")
        } else {
            let payload_matches = fs::read_to_string(&vault_entry.vaulted_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<StoredOpenCodePluginVaultPayload>(&raw).ok())
                .is_some_and(|payload| {
                    payload.plugin_id == plugin_id
                        && payload
                            .original_order
                            .iter()
                            .filter(|current| current.as_str() == plugin_id)
                            .count()
                            == 1
                        && payload.original_order.iter().collect::<BTreeSet<_>>().len()
                            == payload.original_order.len()
                });
            if payload_matches && vault_entry.display_name == plugin_id {
                None
            } else {
                Some("vault payload does not match the OpenCode plugin identity")
            }
        };
        if let Some(reason) = invalid_reason {
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
            continue;
        }

        items.push(DiscoveryItem {
            provider,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginConfig,
            layer,
            id: vault_entry.item_id,
            display_name: vault_entry.display_name,
            enabled: false,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: vault_entry.original_path,
            state_path: path_string(&entry_path),
            source_fingerprint: None,
            hook: None,
        });
    }

    Ok(())
}

fn collect_agent_files(
    root: &Path,
    allowed_kinds: &[AgentFileKind],
    files: &mut Vec<PathBuf>,
) -> Result<(), DiscoveryError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_agent_files(&path, allowed_kinds, files)?;
        } else if let Some(kind) = agent_file_kind(&path)
            && allowed_kinds.contains(&kind)
        {
            files.push(path);
        }
    }

    Ok(())
}

fn agent_file_kind(path: &Path) -> Option<AgentFileKind> {
    match path
        .extension()?
        .to_string_lossy()
        .to_ascii_lowercase()
        .as_str()
    {
        "md" | "markdown" => Some(AgentFileKind::Markdown),
        "toml" => Some(AgentFileKind::Toml),
        _ => None,
    }
}

fn file_stem_relative_id(root: &Path, file_path: &Path) -> Result<String, DiscoveryError> {
    let without_extension = file_path.with_extension("");
    Ok(without_extension
        .strip_prefix(root)?
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn agent_display_name(file_path: &Path, fallback: &str) -> Result<String, DiscoveryError> {
    let raw = fs::read_to_string(file_path)?;
    let parsed = match agent_file_kind(file_path) {
        Some(AgentFileKind::Markdown) => parse_markdown_name(&raw),
        Some(AgentFileKind::Toml) => parse_toml_name(&raw),
        None => None,
    };

    Ok(parsed.unwrap_or_else(|| fallback.to_string()))
}

fn parse_markdown_name(raw: &str) -> Option<String> {
    let frontmatter = raw.strip_prefix("---")?;
    let end_index = frontmatter.find("\n---")?;
    let frontmatter = &frontmatter[..end_index];
    parse_name_line(frontmatter)
}

fn parse_toml_name(raw: &str) -> Option<String> {
    parse_name_line(raw)
}

fn parse_name_line(raw: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = trimmed.strip_prefix("name")?.trim_start();
        let value = value
            .strip_prefix(':')
            .or_else(|| value.strip_prefix('='))?;
        let unquoted = unquote_metadata_value(value);
        if unquoted.is_empty() {
            None
        } else {
            Some(unquoted)
        }
    })
}

fn unquote_metadata_value(value: &str) -> String {
    let trimmed = value.trim();
    let quoted = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        });
    quoted.unwrap_or(trimmed).trim().to_string()
}

fn configured_mcp_item(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id: String,
    display_name: &str,
    enabled: bool,
    source_path: &Path,
    state_path: &Path,
) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind: DiscoveryKind::Mcp,
        category: DiscoveryCategory::ConfiguredMcp,
        layer,
        id,
        display_name: display_name.to_string(),
        enabled,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: path_string(source_path),
        state_path: path_string(state_path),
        source_fingerprint: None,
        hook: None,
    }
}

fn provider_setting_item(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id: String,
    display_name: &str,
    file_path: &Path,
) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind: DiscoveryKind::Setting,
        category: DiscoveryCategory::ProviderSetting,
        layer,
        id,
        display_name: display_name.to_string(),
        enabled: true,
        mutability: DiscoveryMutability::ReadOnly,
        source_path: path_string(file_path),
        state_path: path_string(file_path),
        source_fingerprint: None,
        hook: None,
    }
}

fn plugin_config_item(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id: String,
    display_name: &str,
    enabled: bool,
    file_path: &Path,
) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind: DiscoveryKind::Plugin,
        category: DiscoveryCategory::PluginConfig,
        layer,
        id,
        display_name: display_name.to_string(),
        enabled,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: path_string(file_path),
        state_path: path_string(file_path),
        source_fingerprint: None,
        hook: None,
    }
}

fn claude_plugin_config_items(source: &SettingsSource<ClaudeSettings>) -> Vec<DiscoveryItem> {
    source
        .document
        .enabled_plugins
        .iter()
        .map(|(plugin_id, enabled)| DiscoveryItem {
            provider: ProviderId::Claude,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginConfig,
            layer: source.layer,
            // Keep historical `:tool:` segment as an opaque selector contract.
            id: format!(
                "claude:{}:tool:{}:{}",
                source.layer.as_str(),
                source.source_label,
                plugin_id
            ),
            display_name: plugin_id.to_string(),
            enabled: *enabled,
            mutability: DiscoveryMutability::ReadWrite,
            source_path: path_string(&source.path),
            state_path: path_string(&source.path),
            source_fingerprint: None,
            hook: None,
        })
        .collect()
}

fn claude_hook_items(
    source: &SettingsSource<ClaudeSettings>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Vec<DiscoveryItem> {
    let value = serde_json::json!({ "hooks": &source.document.hooks });
    parsed_hook_items(
        ProviderId::Claude,
        source.layer,
        &format!(
            "claude:{}:hook:{}:",
            source.layer.as_str(),
            source.source_label
        ),
        &value,
        false,
        &source.path,
        warnings,
    )
}

fn discover_setting_files(
    provider: ProviderId,
    layer: DiscoveryLayer,
    specs: &[(PathBuf, &'static str, &'static str)],
    items: &mut Vec<DiscoveryItem>,
) {
    for (path, id, display_name) in specs {
        if path.exists() {
            items.push(provider_setting_item(
                provider,
                layer,
                (*id).to_string(),
                display_name,
                path,
            ));
        }
    }
}

struct JsonHooksSpec {
    provider: ProviderId,
    layer: DiscoveryLayer,
    hook_id_prefix: &'static str,
    setting_id: &'static str,
    setting_display_name: &'static str,
    allow_top_level_events: bool,
}

fn discover_json_hooks_file(
    path: &Path,
    spec: JsonHooksSpec,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(value) =
        read_json_if_exists::<serde_json::Value>(path, spec.provider, Some(spec.layer), warnings)?
    else {
        return Ok(());
    };

    items.push(provider_setting_item(
        spec.provider,
        spec.layer,
        spec.setting_id.to_string(),
        spec.setting_display_name,
        path,
    ));

    items.extend(parsed_hook_items(
        spec.provider,
        spec.layer,
        spec.hook_id_prefix,
        &value,
        spec.allow_top_level_events,
        path,
        warnings,
    ));

    Ok(())
}

fn parsed_hook_items(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    value: &serde_json::Value,
    allow_top_level_events: bool,
    source_path: &Path,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Vec<DiscoveryItem> {
    let parsed = parse_hook_document(provider, layer, id_prefix, value, allow_top_level_events);
    for issue in parsed.issues {
        warnings.push(DiscoveryWarning {
            provider,
            layer: Some(layer),
            code: issue.code.to_string(),
            message: format!(
                "ignored invalid hook definition in {}",
                source_path.display()
            ),
        });
    }
    parsed
        .handlers
        .into_iter()
        .map(|parsed| {
            let handler = parsed.handler;
            DiscoveryItem {
                provider,
                kind: DiscoveryKind::Hook,
                category: DiscoveryCategory::Hook,
                layer,
                id: handler.id().to_string(),
                display_name: parsed.display_name,
                enabled: handler.enabled(),
                mutability: DiscoveryMutability::ReadOnly,
                source_path: path_string(source_path),
                state_path: path_string(source_path),
                source_fingerprint: Some(handler.fingerprint().to_string()),
                hook: Some(handler.inventory()),
            }
        })
        .collect()
}

fn cursor_mcp_server_is_disabled(value: &serde_json::Value) -> bool {
    value.get("disabled").and_then(serde_json::Value::as_bool) == Some(true)
}

fn cursor_workspace_server_is_disabled(
    workspace_state: &CursorWorkspaceState,
    server_id: &str,
) -> bool {
    let CursorWorkspaceState::Ok {
        disabled_server_ids,
        ..
    } = workspace_state
    else {
        return false;
    };

    disabled_server_ids.contains(&cursor_workspace_server_id(server_id))
}

fn cursor_workspace_server_id(server_id: &str) -> String {
    if server_id.starts_with("user-") {
        server_id.to_string()
    } else {
        format!("user-{server_id}")
    }
}

fn load_cursor_workspace_state(
    cursor_root: &Path,
    project_root: &Path,
    warnings: &mut Vec<DiscoveryWarning>,
) -> CursorWorkspaceState {
    let Some(database_path) = find_cursor_workspace_database(cursor_root, project_root) else {
        return CursorWorkspaceState::Missing;
    };

    match read_cursor_workspace_disabled_server_ids(&database_path) {
        Ok(disabled_server_ids) => CursorWorkspaceState::Ok {
            database_path,
            disabled_server_ids,
        },
        Err(reason) => {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Cursor,
                layer: Some(DiscoveryLayer::Global),
                code: "invalid-shape".to_string(),
                message: reason,
            });
            CursorWorkspaceState::Missing
        }
    }
}

fn find_cursor_workspace_database(cursor_root: &Path, project_root: &Path) -> Option<PathBuf> {
    let workspace_storage_root = cursor_root.join("workspaceStorage");
    let entries = fs::read_dir(workspace_storage_root).ok()?;
    let mut entries = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    let project_url = project_file_url(project_root);
    for entry in entries {
        let workspace_root = entry.path();
        let workspace_json_path = workspace_root.join("workspace.json");
        let Ok(raw) = fs::read_to_string(&workspace_json_path) else {
            continue;
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        if document.get("folder").and_then(serde_json::Value::as_str) != Some(project_url.as_str())
        {
            continue;
        }

        let database_path = workspace_root.join("state.vscdb");
        if database_path.exists() {
            return Some(database_path);
        }
    }

    None
}

fn read_cursor_workspace_disabled_server_ids(
    database_path: &Path,
) -> Result<BTreeSet<String>, String> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        format!(
            "invalid Cursor workspace state at {}; could not read {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY}",
            database_path.display()
        )
    })?;
    let mut statement = connection
        .prepare("SELECT value FROM ItemTable WHERE key = ?1")
        .map_err(|_| {
            format!(
                "invalid Cursor workspace state at {}; could not read {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY}",
                database_path.display()
            )
        })?;
    let value = statement
        .query_row([CURSOR_WORKSPACE_DISABLED_SERVERS_KEY], |row| {
            row.get::<_, SqliteValue>(0)
        })
        .optional()
        .map_err(|_| {
            format!(
                "invalid Cursor workspace state at {}; could not read {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY}",
                database_path.display()
            )
        })?;
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };

    let raw_value = sqlite_value_to_string(value).map_err(|_| {
        format!(
            "invalid Cursor workspace state at {}; expected {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} to be a JSON string array",
            database_path.display()
        )
    })?;
    let parsed = serde_json::from_str::<Vec<String>>(&raw_value).map_err(|_| {
        format!(
            "invalid Cursor workspace state at {}; expected {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} to be a JSON string array",
            database_path.display()
        )
    })?;

    Ok(parsed.into_iter().collect())
}

fn sqlite_value_to_string(value: SqliteValue) -> Result<String, ()> {
    match value {
        SqliteValue::Text(value) => Ok(value),
        SqliteValue::Blob(value) => String::from_utf8(value).map_err(|_| ()),
        _ => Err(()),
    }
}

fn project_file_url(project_root: &Path) -> String {
    let mut url = String::from("file://");
    for byte in project_root.to_string_lossy().bytes() {
        if is_file_url_path_byte(byte) {
            url.push(byte as char);
        } else {
            write!(&mut url, "%{byte:02X}").expect("writing to string cannot fail");
        }
    }
    url
}

fn is_file_url_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':')
}

fn codex_inline_hook_items(
    config_path: &Path,
    raw: &str,
    layer: DiscoveryLayer,
    id_scope: &str,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Vec<DiscoveryItem> {
    let value = codex_inline_hook_document(raw);
    parsed_hook_items(
        ProviderId::Codex,
        layer,
        &format!("codex:{}:hook:config-toml:{id_scope}", layer.as_str()),
        &value,
        false,
        config_path,
        warnings,
    )
}

fn codex_inline_hook_document(raw: &str) -> serde_json::Value {
    let mut groups = BTreeMap::<String, String>::new();
    let mut hooks = BTreeMap::<String, Vec<serde_json::Value>>::new();
    for (header, section) in codex_hook_table_sections(raw) {
        let Some(tail) = header.strip_prefix("hooks.") else {
            continue;
        };
        let (event, nested_handler) = tail
            .strip_suffix(".hooks")
            .map_or((tail, false), |event| (event, true));
        if event.is_empty() || event.contains('.') {
            continue;
        }
        let event = unquote_metadata_value(event);
        let matcher = toml_assignment_value(&section, "matcher")
            .and_then(|value| parse_toml_string(value).ok());
        let action_type =
            toml_assignment_value(&section, "type").and_then(|value| parse_toml_string(value).ok());
        let has_command = toml_assignment_value(&section, "command").is_some();
        let has_url = toml_assignment_value(&section, "url").is_some();
        if !nested_handler && action_type.is_none() && !has_command && !has_url {
            if let Some(matcher) = matcher {
                groups.insert(event, matcher);
            }
            continue;
        }

        let mut definition = serde_json::Map::new();
        definition.insert(
            "definitionFingerprint".to_string(),
            serde_json::Value::String(source_fingerprint(&section)),
        );
        if let Some(action_type) = action_type {
            definition.insert("type".to_string(), serde_json::Value::String(action_type));
        }
        if has_command {
            definition.insert("command".to_string(), serde_json::Value::Bool(true));
        }
        if has_url {
            definition.insert("url".to_string(), serde_json::Value::Bool(true));
        }
        if let Some(matcher) = matcher.or_else(|| groups.get(&event).cloned()) {
            definition.insert("matcher".to_string(), serde_json::Value::String(matcher));
        }
        if let Some(timeout) = toml_assignment_value(&section, "timeout")
            .and_then(|value| value.split('#').next())
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            definition.insert("timeout".to_string(), serde_json::Value::from(timeout));
        }
        if let Some(order) = toml_assignment_value(&section, "order")
            .and_then(|value| value.split('#').next())
            .and_then(|value| value.trim().parse::<i64>().ok())
        {
            definition.insert("order".to_string(), serde_json::Value::from(order));
        }
        if let Some(disabled) = toml_assignment_value(&section, "disabled")
            .and_then(|value| parse_toml_bool(value).ok())
        {
            definition.insert("disabled".to_string(), serde_json::Value::Bool(disabled));
        }
        hooks
            .entry(event)
            .or_default()
            .push(serde_json::Value::Object(definition));
    }
    serde_json::json!({ "hooks": hooks })
}

fn codex_hook_table_sections(raw: &str) -> Vec<(String, String)> {
    all_table_sections(raw)
        .into_iter()
        .filter(|(header, _)| header.name.starts_with("hooks."))
        .map(|(header, section)| (header.name, section.content.to_string()))
        .collect()
}

fn discover_cursor_plugin_manifests(
    local_plugins_root: &Path,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let mut live_ids = BTreeSet::new();
    if !local_plugins_root.exists() {
        return Ok(live_ids);
    }

    let mut entries = fs::read_dir(local_plugins_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(manifest_path) = cursor_plugin_manifest_path(&path) else {
            continue;
        };
        let Some(value) = read_json_if_exists::<serde_json::Value>(
            &manifest_path,
            ProviderId::Cursor,
            Some(DiscoveryLayer::Global),
            warnings,
        )?
        else {
            continue;
        };
        if !value.is_object() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Cursor,
                layer: Some(DiscoveryLayer::Global),
                code: "invalid-shape".to_string(),
                message: format!("{} must be a JSON object", manifest_path.display()),
            });
            continue;
        }
        let display_name = value
            .get("displayName")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("name").and_then(serde_json::Value::as_str))
            .map_or_else(
                || entry.file_name().to_string_lossy().into_owned(),
                str::to_string,
            );
        let plugin_id = entry.file_name().to_string_lossy().into_owned();
        let id = format!("cursor:global:plugin-manifest:local:{plugin_id}");
        let source_fingerprint = fs::read_to_string(&manifest_path)
            .ok()
            .map(|raw| source_fingerprint(&raw));
        let mutability = cursor_plugin_path_mutability(local_plugins_root, &manifest_path)?;

        items.push(DiscoveryItem {
            provider: ProviderId::Cursor,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginManifest,
            layer: DiscoveryLayer::Global,
            id: id.clone(),
            display_name,
            enabled: true,
            mutability,
            source_path: path_string(&manifest_path),
            state_path: path_string(&path),
            source_fingerprint,
            hook: None,
        });
        live_ids.insert(id);
    }

    Ok(live_ids)
}

fn discover_cursor_marketplace_plugins(
    cursor_root: &Path,
    project_root: &Path,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) {
    let database_path = cursor_root.join("globalStorage").join("state.vscdb");
    if !database_path.is_file() {
        return;
    }

    let connection = match Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(_) => {
            push_cursor_marketplace_warning(warnings, &database_path, "could not read database");
            return;
        }
    };
    let mut statement = match connection
        .prepare("SELECT key, value FROM ItemTable WHERE key LIKE ?1 ORDER BY key")
    {
        Ok(statement) => statement,
        Err(_) => {
            push_cursor_marketplace_warning(warnings, &database_path, "could not read ItemTable");
            return;
        }
    };
    let key_pattern = format!("{CURSOR_MARKETPLACE_PLUGIN_KEY_PREFIX}%");
    let rows = match statement.query_map([key_pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, SqliteValue>(1)?))
    }) {
        Ok(rows) => rows,
        Err(_) => {
            push_cursor_marketplace_warning(warnings, &database_path, "could not query ItemTable");
            return;
        }
    };

    let mut installs = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for row in rows {
        let Ok((key, value)) = row else {
            push_cursor_marketplace_warning(
                warnings,
                &database_path,
                "could not read ItemTable row",
            );
            continue;
        };
        let Some(context) = key
            .strip_prefix(CURSOR_MARKETPLACE_PLUGIN_KEY_PREFIX)
            .and_then(|suffix| suffix.rsplit_once('|').map(|(_, context)| context))
        else {
            push_cursor_marketplace_warning(warnings, &database_path, "invalid row key");
            continue;
        };
        let Some(layer) = cursor_marketplace_layer(context, project_root) else {
            continue;
        };
        let Ok(raw_value) = sqlite_value_to_string(value) else {
            push_cursor_marketplace_warning(warnings, &database_path, "expected JSON text");
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw_value) else {
            push_cursor_marketplace_warning(warnings, &database_path, "expected JSON array");
            continue;
        };
        let Some(entries) = value.as_array() else {
            push_cursor_marketplace_warning(warnings, &database_path, "expected JSON array");
            continue;
        };

        for entry in entries {
            let Some((plugin_id, sources)) = cursor_marketplace_plugin_entry(entry) else {
                push_cursor_marketplace_warning(
                    warnings,
                    &database_path,
                    "expected numeric plugin id and string sources",
                );
                continue;
            };
            installs
                .entry((layer.as_str().to_string(), plugin_id))
                .or_default()
                .extend(sources);
        }
    }

    for ((layer, plugin_id), sources) in installs {
        let layer = if layer == DiscoveryLayer::Global.as_str() {
            DiscoveryLayer::Global
        } else {
            DiscoveryLayer::Project
        };
        let source_fingerprint = json_value_source_fingerprint(&serde_json::json!({
            "id": plugin_id,
            "sources": sources,
        }));
        items.push(DiscoveryItem {
            provider: ProviderId::Cursor,
            kind: DiscoveryKind::Plugin,
            category: DiscoveryCategory::PluginConfig,
            layer,
            id: format!(
                "cursor:{}:plugin-config:marketplace:{plugin_id}",
                layer.as_str()
            ),
            display_name: format!("Cursor marketplace plugin {plugin_id}"),
            enabled: true,
            mutability: DiscoveryMutability::ReadOnly,
            source_path: path_string(&database_path),
            state_path: path_string(&database_path),
            source_fingerprint: Some(source_fingerprint),
            hook: None,
        });
    }
}

fn cursor_marketplace_layer(context: &str, project_root: &Path) -> Option<DiscoveryLayer> {
    if context == "no-workspace" {
        return Some(DiscoveryLayer::Global);
    }

    (context.trim_end_matches('/') == project_file_url(project_root).trim_end_matches('/'))
        .then_some(DiscoveryLayer::Project)
}

fn cursor_marketplace_plugin_entry(
    value: &serde_json::Value,
) -> Option<(String, BTreeSet<String>)> {
    let object = value.as_object()?;
    let plugin_id = match object.get("id")? {
        serde_json::Value::String(value) => value.parse::<u64>().ok()?,
        serde_json::Value::Number(value) => value.as_u64()?,
        _ => return None,
    }
    .to_string();
    let sources = object
        .get("sources")?
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect::<Option<BTreeSet<_>>>()?
        .into_iter()
        .map(str::to_string)
        .collect();

    Some((plugin_id, sources))
}

fn push_cursor_marketplace_warning(
    warnings: &mut Vec<DiscoveryWarning>,
    database_path: &Path,
    reason: &str,
) {
    warnings.push(DiscoveryWarning {
        provider: ProviderId::Cursor,
        layer: None,
        code: "invalid-shape".to_string(),
        message: format!(
            "invalid Cursor marketplace plugin state at {}; {reason}",
            database_path.display()
        ),
    });
}

fn cursor_plugin_manifest_path(plugin_path: &Path) -> Option<PathBuf> {
    let cursor_manifest = plugin_path.join(".cursor-plugin").join("plugin.json");
    if cursor_manifest.is_file() {
        return Some(cursor_manifest);
    }

    let claude_manifest = plugin_path.join(".claude-plugin").join("plugin.json");
    claude_manifest.is_file().then_some(claude_manifest)
}

fn cursor_plugin_path_mutability(
    local_plugins_root: &Path,
    manifest_path: &Path,
) -> Result<DiscoveryMutability, DiscoveryError> {
    skill_path_mutability(
        local_plugins_root,
        manifest_path,
        DiscoveryMutability::ReadWrite,
        false,
    )
}

fn parse_codex_section_ids(raw: &str, section_prefix: &str) -> Vec<String> {
    table_child_ids(raw, section_prefix)
}

pub(crate) fn source_fingerprint(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

pub(crate) fn json_value_source_fingerprint(value: &serde_json::Value) -> String {
    let raw = serde_json::to_string(value).expect("JSON values serialize deterministically");
    source_fingerprint(&raw)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn sort_items(items: &mut [DiscoveryItem]) {
    items.sort_by(|left, right| {
        provider_rank(left.provider)
            .cmp(&provider_rank(right.provider))
            .then_with(|| layer_rank(left.layer).cmp(&layer_rank(right.layer)))
            .then_with(|| category_rank(left.category).cmp(&category_rank(right.category)))
            .then_with(|| compare_ids(&left.id, &right.id))
    });
}

fn compare_ids(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

fn provider_rank(provider: ProviderId) -> usize {
    ProviderId::ALL
        .iter()
        .position(|candidate| *candidate == provider)
        .expect("provider is registered")
}

fn layer_rank(layer: DiscoveryLayer) -> usize {
    match layer {
        DiscoveryLayer::Global => 0,
        DiscoveryLayer::Project => 1,
    }
}

fn category_rank(category: DiscoveryCategory) -> usize {
    match category {
        DiscoveryCategory::Skill => 0,
        DiscoveryCategory::ConfiguredMcp => 1,
        DiscoveryCategory::Tool => 2,
        DiscoveryCategory::Agent => 3,
        DiscoveryCategory::Hook => 4,
        DiscoveryCategory::ProviderSetting => 5,
        DiscoveryCategory::PluginConfig => 6,
        DiscoveryCategory::PluginManifest => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_workspace_read_does_not_create_missing_database() {
        let temp = tempfile::TempDir::new().expect("temporary Cursor workspace");
        let database_path = temp.path().join("state.vscdb");

        assert!(read_cursor_workspace_disabled_server_ids(&database_path).is_err());
        assert!(!database_path.exists());
    }

    #[test]
    fn non_repository_project_skill_discovery_does_not_scan_descendants() {
        let temp = tempfile::TempDir::new().expect("temporary non-repository project root");
        let project_root = temp.path();
        write_test_file(
            &project_root
                .join("nested")
                .join(".cursor")
                .join("skills")
                .join("unrelated")
                .join("SKILL.md"),
        );
        let mut warnings = Vec::new();
        let mut items = Vec::new();
        let mut project_scope_cache = ProjectScopeCache::default();

        let discovery = discover_project_skill_dirs(
            project_root,
            Path::new(".cursor/skills"),
            SkillDiscoverySpec {
                provider: ProviderId::Cursor,
                layer: DiscoveryLayer::Project,
                id_prefix: CURSOR_PROJECT_SKILL_ID_PREFIX,
                mutability: DiscoveryMutability::ReadWrite,
                traversal: ProjectSkillTraversal::Repository,
                skill_root_traversal: SkillRootTraversal::Recursive,
            },
            true,
            &mut project_scope_cache,
            &mut warnings,
            &mut items,
        )
        .expect("project skill discovery");

        assert!(discovery.live_ids.is_empty());
        assert!(items.is_empty());
        assert!(warnings.is_empty());
        assert_eq!(
            discovery.skill_roots,
            vec![project_root.join(".cursor").join("skills")]
        );
    }

    #[test]
    fn project_scope_cache_reuses_matching_scope_discovery() {
        let project_root = Path::new("/project");
        let relative_skill_root = Path::new(".agents/skills");
        let expected_roots = BTreeSet::from([project_root.to_path_buf()]);
        let mut cache = ProjectScopeCache::default();
        let mut calls = 0;

        let first = cache
            .get_or_discover(
                project_root,
                project_root,
                relative_skill_root,
                ProjectSkillTraversal::Ancestors,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: expected_roots.clone(),
                        skipped_directories: 2,
                    })
                },
            )
            .expect("first cache lookup")
            .clone();
        let second = cache
            .get_or_discover(
                project_root,
                project_root,
                relative_skill_root,
                ProjectSkillTraversal::Ancestors,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("second cache lookup")
            .clone();
        let distinct_relative_root = cache
            .get_or_discover(
                project_root,
                project_root,
                Path::new(".claude/skills"),
                ProjectSkillTraversal::Ancestors,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("distinct cache lookup")
            .clone();

        let distinct_project_root = cache
            .get_or_discover(
                Path::new("/other-project"),
                project_root,
                relative_skill_root,
                ProjectSkillTraversal::Ancestors,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("distinct project root cache lookup")
            .clone();
        let distinct_repository_root = cache
            .get_or_discover(
                project_root,
                Path::new("/other-repository"),
                relative_skill_root,
                ProjectSkillTraversal::Ancestors,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("distinct repository root cache lookup")
            .clone();
        let distinct_traversal = cache
            .get_or_discover(
                project_root,
                project_root,
                relative_skill_root,
                ProjectSkillTraversal::Repository,
                true,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("distinct traversal cache lookup")
            .clone();
        let distinct_scope_scan = cache
            .get_or_discover(
                project_root,
                project_root,
                relative_skill_root,
                ProjectSkillTraversal::Ancestors,
                false,
                || {
                    calls += 1;
                    Ok(ProjectSkillScopeRoots {
                        roots: BTreeSet::new(),
                        skipped_directories: 0,
                    })
                },
            )
            .expect("distinct scope-scan cache lookup")
            .clone();

        assert_eq!(calls, 6);
        assert_eq!(first.roots, expected_roots);
        assert_eq!(second.roots, expected_roots);
        assert_eq!(second.skipped_directories, 2);
        assert!(distinct_relative_root.roots.is_empty());
        assert!(distinct_project_root.roots.is_empty());
        assert!(distinct_repository_root.roots.is_empty());
        assert!(distinct_traversal.roots.is_empty());
        assert!(distinct_scope_scan.roots.is_empty());
    }

    #[test]
    fn repository_scope_prepopulation_caches_cursor_skill_roots() {
        let temporary_root = tempfile::TempDir::new().expect("temporary repository root");
        let repository_root = temporary_root.path().join("repository");
        let project_root = repository_root.join("workspace").join("app");
        write_test_file(&repository_root.join(".git"));
        let relative_skill_roots = [
            Path::new(".cursor/skills"),
            Path::new(".agents/skills"),
            Path::new(".claude/skills"),
            Path::new(".codex/skills"),
        ];
        for (index, relative_skill_root) in relative_skill_roots.iter().enumerate() {
            write_test_file(
                &repository_root
                    .join(format!("package-{index}"))
                    .join(relative_skill_root)
                    .join("example")
                    .join("SKILL.md"),
            );
        }
        let requests = relative_skill_roots
            .iter()
            .map(|relative_skill_root| (project_root.as_path(), *relative_skill_root))
            .collect::<Vec<_>>();
        let mut cache = ProjectScopeCache::default();

        prepopulate_repository_project_scopes(&mut cache, &requests, true)
            .expect("scope prepopulation");

        for (index, relative_skill_root) in relative_skill_roots.iter().enumerate() {
            let scope_roots = cache
                .get_or_discover(
                    &project_root,
                    &repository_root,
                    relative_skill_root,
                    ProjectSkillTraversal::Repository,
                    true,
                    || -> Result<ProjectSkillScopeRoots, DiscoveryError> {
                        panic!("prepopulated scope should be cached")
                    },
                )
                .expect("cached scope roots");
            assert!(
                scope_roots
                    .roots
                    .contains(&repository_root.join(format!("package-{index}")))
            );
        }
    }

    #[test]
    fn cursor_discovery_consumes_prepopulated_repository_scopes() {
        let temporary_root = tempfile::TempDir::new().expect("temporary Cursor repository");
        let repository_root = temporary_root.path().join("repository");
        let project_root = repository_root.join("workspace").join("app");
        let home_root = temporary_root.path().join("home");
        let cursor_root = temporary_root.path().join("cursor");
        fs::create_dir_all(&project_root).expect("create Cursor project root");
        write_test_file(&repository_root.join(".git"));

        let skill_files = [
            repository_root
                .join("cursor-package")
                .join(".cursor/skills/example/SKILL.md"),
            repository_root
                .join("agents-package")
                .join(".agents/skills/example/SKILL.md"),
            repository_root
                .join("claude-package")
                .join(".claude/skills/example/SKILL.md"),
            repository_root
                .join("codex-package")
                .join(".codex/skills/example/SKILL.md"),
        ];
        for skill_file in &skill_files {
            write_test_file(skill_file);
        }

        let roots = DiscoveryRoots::from_locations(&home_root, &project_root, &cursor_root);
        let mut state = DiscoveryState::default();
        discover_cursor(&roots, &mut state).expect("Cursor discovery");

        assert_eq!(
            state.project_scope_cache.scopes.len(),
            4,
            "Cursor should consume the four scopes prepopulated for its repository traversal"
        );
        for skill_file in skill_files {
            assert!(
                state
                    .items
                    .iter()
                    .any(|item| item.source_path == path_string(&skill_file)),
                "Cursor should discover {} through the prepopulated scope",
                skill_file.display()
            );
        }
    }

    #[test]
    fn repository_scope_multi_scan_reuses_duplicate_relative_root_results() {
        let temporary_root = tempfile::TempDir::new().expect("temporary repository root");
        let repository_root = temporary_root.path();
        let skill_root = repository_root.join("package").join(".agents/skills");
        write_test_file(&skill_root.join("example/SKILL.md"));

        let relative_skill_root = PathBuf::from(".agents/skills");
        let scope_roots = project_repository_scope_roots(
            repository_root,
            &[relative_skill_root.clone(), relative_skill_root.clone()],
        )
        .expect("multi-root scope scan");

        assert_eq!(
            scope_roots
                .get(&relative_skill_root)
                .expect("duplicate scope root result")
                .roots,
            BTreeSet::from([repository_root.join("package")])
        );
    }

    #[test]
    fn parallel_project_scope_scan_matches_serial_reference() {
        let temporary_root = tempfile::TempDir::new().expect("temporary repository root");
        let repository_root = temporary_root.path();
        let mut expected = BTreeSet::new();

        for index in 0..16 {
            let scope_root = repository_root
                .join(format!("group-{index:02}"))
                .join("nested");
            write_test_file(
                &scope_root
                    .join(".claude")
                    .join("skills")
                    .join("benchmark")
                    .join("SKILL.md"),
            );
            expected.insert(scope_root);
        }
        write_test_file(
            &repository_root
                .join("node_modules")
                .join("ignored")
                .join(".claude")
                .join("skills")
                .join("benchmark")
                .join("SKILL.md"),
        );
        write_test_file(
            &repository_root
                .join("tmp")
                .join("ignored")
                .join(".claude")
                .join("skills")
                .join("benchmark")
                .join("SKILL.md"),
        );

        let mut serial_scopes = BTreeSet::new();
        let serial_skipped = add_descendant_skill_scopes_with_worker_limit(
            repository_root,
            repository_root,
            Path::new(".claude/skills"),
            &mut serial_scopes,
            1,
        )
        .expect("serial scope scan");
        let mut parallel_scopes = BTreeSet::new();
        let parallel_skipped = add_descendant_skill_scopes_with_worker_limit(
            repository_root,
            repository_root,
            Path::new(".claude/skills"),
            &mut parallel_scopes,
            4,
        )
        .expect("parallel scope scan");

        assert_eq!(serial_scopes, expected);
        assert_eq!(parallel_scopes, serial_scopes);
        assert_eq!(parallel_skipped, serial_skipped);

        let skipped_scope_roots = expected.iter().take(3).cloned().collect::<BTreeSet<_>>();
        let scan_subtree = |directory: &Path| -> Result<ProjectScopeScan, DiscoveryError> {
            let (scope_roots, skipped_directories) = if directory == repository_root {
                (expected.clone(), skipped_scope_roots.len())
            } else {
                (
                    BTreeSet::from([directory.to_path_buf()]),
                    usize::from(skipped_scope_roots.contains(directory)),
                )
            };
            Ok(ProjectScopeScan {
                scope_roots,
                skipped_directories,
            })
        };
        let serial_reference =
            scan_project_scope_frontier_with(&[repository_root.to_path_buf()], 1, scan_subtree)
                .expect("serial reference scan")
                .pop()
                .expect("serial reference result");
        let mut parallel_reference = ProjectScopeScan::default();
        for subtree_scan in scan_project_scope_frontier_with(
            &expected.iter().cloned().collect::<Vec<_>>(),
            4,
            scan_subtree,
        )
        .expect("parallel reference scan")
        {
            merge_project_scope_scan(&mut parallel_reference, subtree_scan);
        }

        assert_eq!(parallel_reference.scope_roots, serial_reference.scope_roots);
        assert_eq!(
            parallel_reference.skipped_directories,
            serial_reference.skipped_directories
        );
        assert_eq!(
            parallel_reference.skipped_directories,
            skipped_scope_roots.len()
        );
    }

    #[test]
    fn project_scope_scan_excludes_test_fixture_and_inactive_worktree_subtrees() {
        let temporary_root = tempfile::TempDir::new().expect("temporary repository root");
        let repository_root = temporary_root.path();
        let live_scope = repository_root.join("packages/live-agent");
        let inactive_worktree_scope = repository_root.join("alternate-worktree");
        let ignored_scopes = [
            repository_root.join(".worktrees/feature-agent"),
            repository_root.join("test/example"),
            repository_root.join("tests/example"),
            repository_root.join("fixture/example"),
            repository_root.join("fixtures/example"),
            repository_root.join("crates/unpin-core/tests/fixtures/example"),
        ];

        write_test_file(&live_scope.join(".claude/skills/review/SKILL.md"));
        write_test_file(&inactive_worktree_scope.join(".git"));
        write_test_file(&inactive_worktree_scope.join(".claude/skills/review/SKILL.md"));
        for scope in ignored_scopes {
            write_test_file(&scope.join(".claude/skills/review/SKILL.md"));
        }

        let mut scope_roots = BTreeSet::new();
        add_descendant_skill_scopes_with_worker_limit(
            repository_root,
            repository_root,
            Path::new(".claude/skills"),
            &mut scope_roots,
            4,
        )
        .expect("project scope scan");

        assert_eq!(scope_roots, BTreeSet::from([live_scope]));
    }

    #[test]
    fn active_worktree_scope_does_not_scan_sibling_worktrees() {
        let temporary_root = tempfile::TempDir::new().expect("temporary checkout root");
        let main_checkout = temporary_root.path().join("main");
        let active_worktree = main_checkout.join(".worktrees/active");
        let sibling_worktree = main_checkout.join(".worktrees/sibling");
        write_test_file(&active_worktree.join(".git"));
        write_test_file(&active_worktree.join(".claude/skills/review/SKILL.md"));
        write_test_file(&sibling_worktree.join(".claude/skills/review/SKILL.md"));

        let scope_roots = project_skill_scope_roots(
            &active_worktree,
            &find_repository_root(&active_worktree),
            Path::new(".claude/skills"),
            ProjectSkillTraversal::Repository,
            true,
        )
        .expect("active worktree scope scan");

        assert_eq!(scope_roots.roots, BTreeSet::from([active_worktree]));
    }

    #[test]
    fn parallel_project_scope_scan_worker_panic_returns_discovery_error() {
        let panic_directory = PathBuf::from("panic");
        let error = match scan_project_scope_frontier_with(
            &[panic_directory.clone(), PathBuf::from("complete")],
            2,
            |directory| -> Result<ProjectScopeScan, DiscoveryError> {
                if directory == panic_directory {
                    panic!("deliberate project scope scan worker panic");
                }
                Ok(ProjectScopeScan::default())
            },
        ) {
            Ok(_) => panic!("worker panic must become a discovery error"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "project scope scan worker panicked: deliberate project scope scan worker panic"
        );
    }

    #[test]
    fn cancelled_project_scope_scan_does_not_start_a_subtree() {
        let cancellation = std::sync::atomic::AtomicBool::new(true);
        let error = match scan_project_scope_frontier_with_cancellation(
            &[PathBuf::from("unstarted")],
            1,
            &cancellation,
            |_| -> Result<ProjectScopeScan, DiscoveryError> {
                panic!("a cancelled scan must not start a subtree")
            },
        ) {
            Ok(_) => panic!("cancelled project scope scan must return an error"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "project scope scan cancelled");
    }

    #[test]
    fn parallel_project_scope_scan_stops_dequeuing_after_worker_error() {
        let failing_directory = PathBuf::from("failing");
        let slow_directory = PathBuf::from("slow");
        let unstarted_directory = PathBuf::from("unstarted");
        let workers_started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unstarted_scans = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deadline =
            std::sync::Arc::new(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let error = match scan_project_scope_frontier_with_cancellation(
            &[
                failing_directory.clone(),
                slow_directory.clone(),
                unstarted_directory.clone(),
            ],
            2,
            &cancellation,
            {
                let workers_started = std::sync::Arc::clone(&workers_started);
                let cancellation = std::sync::Arc::clone(&cancellation);
                let unstarted_scans = std::sync::Arc::clone(&unstarted_scans);
                let deadline = std::sync::Arc::clone(&deadline);
                move |directory| -> Result<ProjectScopeScan, DiscoveryError> {
                    if directory == failing_directory {
                        workers_started.fetch_add(1, AtomicOrdering::Release);
                        while workers_started.load(AtomicOrdering::Acquire) < 2 {
                            assert!(
                                std::time::Instant::now() < *deadline,
                                "two workers must start before the failure is returned"
                            );
                            thread::yield_now();
                        }
                        return Err(std::io::Error::other("synthetic project scan failure").into());
                    }
                    if directory == slow_directory {
                        workers_started.fetch_add(1, AtomicOrdering::Release);
                        while !cancellation.load(AtomicOrdering::Acquire) {
                            assert!(
                                std::time::Instant::now() < *deadline,
                                "a sibling failure must set cancellation"
                            );
                            thread::yield_now();
                        }
                        return Ok(ProjectScopeScan::default());
                    }
                    if directory == unstarted_directory {
                        unstarted_scans.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    Ok(ProjectScopeScan::default())
                }
            },
        ) {
            Ok(_) => panic!("worker failure must stop queued project scans"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "synthetic project scan failure");
        assert_eq!(
            unstarted_scans.load(AtomicOrdering::Relaxed),
            0,
            "no worker should dequeue a new subtree after a sibling fails"
        );
    }

    #[test]
    fn accumulating_project_scope_scan_stops_dequeuing_after_worker_error() {
        let failing_directory = PathBuf::from("failing");
        let slow_directory = PathBuf::from("slow");
        let unstarted_directory = PathBuf::from("unstarted");
        let workers_started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unstarted_scans = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deadline =
            std::sync::Arc::new(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let error = match scan_project_scope_frontier_accumulating_with_cancellation(
            &[
                failing_directory.clone(),
                slow_directory.clone(),
                unstarted_directory.clone(),
            ],
            2,
            &cancellation,
            {
                let workers_started = std::sync::Arc::clone(&workers_started);
                let cancellation = std::sync::Arc::clone(&cancellation);
                let unstarted_scans = std::sync::Arc::clone(&unstarted_scans);
                let deadline = std::sync::Arc::clone(&deadline);
                move |directory| -> Result<usize, DiscoveryError> {
                    if directory == failing_directory {
                        workers_started.fetch_add(1, AtomicOrdering::Release);
                        while workers_started.load(AtomicOrdering::Acquire) < 2 {
                            assert!(
                                std::time::Instant::now() < *deadline,
                                "two workers must start before the failure is returned"
                            );
                            thread::yield_now();
                        }
                        return Err(std::io::Error::other("synthetic project scan failure").into());
                    }
                    if directory == slow_directory {
                        workers_started.fetch_add(1, AtomicOrdering::Release);
                        while !cancellation.load(AtomicOrdering::Acquire) {
                            assert!(
                                std::time::Instant::now() < *deadline,
                                "a sibling failure must set cancellation"
                            );
                            thread::yield_now();
                        }
                        return Ok(1);
                    }
                    if directory == unstarted_directory {
                        unstarted_scans.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                    Ok(1)
                }
            },
            |total, next| *total += next,
        ) {
            Ok(_) => panic!("worker failure must stop queued project scans"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "synthetic project scan failure");
        assert_eq!(
            unstarted_scans.load(AtomicOrdering::Relaxed),
            0,
            "no worker should dequeue a new subtree after a sibling fails"
        );
    }

    #[test]
    fn accumulating_project_scope_scan_with_one_worker_merges_each_subtree() {
        let scans = scan_project_scope_frontier_accumulating_with(
            &[
                PathBuf::from("one"),
                PathBuf::from("two"),
                PathBuf::from("three"),
            ],
            1,
            |_| Ok::<_, DiscoveryError>(1usize),
            |total, next| *total += next,
        )
        .expect("single-worker accumulating project scope scan");

        assert_eq!(scans, vec![3]);
    }

    #[test]
    fn cancelled_accumulating_project_scope_scan_does_not_start_a_subtree() {
        let cancellation = std::sync::atomic::AtomicBool::new(true);
        let error = scan_project_scope_frontier_accumulating_with_cancellation(
            &[PathBuf::from("unstarted")],
            1,
            &cancellation,
            |_| -> Result<usize, DiscoveryError> {
                panic!("a cancelled accumulating scan must not start a subtree")
            },
            |total, next| *total += next,
        )
        .expect_err("cancelled accumulating project scope scan must return an error");

        assert_eq!(error.to_string(), "project scope scan cancelled");
    }

    fn write_test_file(path: &Path) {
        fs::create_dir_all(path.parent().expect("test file parent"))
            .expect("create test file parent");
        fs::write(path, "# Test skill\n").expect("write test skill");
    }
}
