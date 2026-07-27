use std::{
    fmt,
    path::{Component, Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::fs_support::read_optional_string;

pub type ConfigResult<T> = Result<T, ConfigError>;

const CONFIG_SCHEMA_VERSION: u8 = 1;

#[derive(Debug)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnpinConfigOverrides {
    pub app_state_root: Option<PathBuf>,
    pub cursor_root: Option<PathBuf>,
    pub project_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadConfigOptions {
    pub cwd: PathBuf,
    pub home_dir: PathBuf,
    pub overrides: UnpinConfigOverrides,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinConfigPaths {
    pub user_config_path: PathBuf,
    pub project_config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpinConfig {
    pub version: u8,
    pub app_state_root: PathBuf,
    pub cursor_root: PathBuf,
    pub project_root: PathBuf,
    pub config_paths: UnpinConfigPaths,
}

impl UnpinConfig {
    pub fn workspace_identity(
        &self,
    ) -> crate::state::workspace::WorkspaceResult<crate::state::workspace::WorkspaceIdentity> {
        crate::state::workspace::resolve_workspace_identity(&self.project_root)
    }
}

#[derive(Debug, Clone, Default)]
struct UnpinConfigDocument {
    version: Option<u8>,
    app_state_root: Option<PathBuf>,
    cursor_root: Option<PathBuf>,
    project_root: Option<PathBuf>,
}

pub fn expand_home_path(input_path: impl AsRef<Path>, home_dir: impl AsRef<Path>) -> PathBuf {
    let input_path = input_path.as_ref();
    let home_dir = home_dir.as_ref();
    let input = input_path.to_string_lossy();

    if input == "~" {
        return home_dir.to_path_buf();
    }

    if let Some(rest) = input.strip_prefix("~/") {
        return home_dir.join(rest);
    }

    input_path.to_path_buf()
}

pub fn normalize_absolute_path(
    input_path: impl AsRef<Path>,
    cwd: impl AsRef<Path>,
    home_dir: impl AsRef<Path>,
) -> PathBuf {
    let expanded = expand_home_path(input_path, home_dir);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        cwd.as_ref().join(expanded)
    };

    normalize_path(&absolute)
}

pub fn resolve_project_root(
    cwd: impl AsRef<Path>,
    home_dir: impl AsRef<Path>,
    configured_project_root: Option<&Path>,
) -> PathBuf {
    let cwd = cwd.as_ref();
    normalize_absolute_path(configured_project_root.unwrap_or(cwd), cwd, home_dir)
}

pub fn resolve_app_state_root(
    cwd: impl AsRef<Path>,
    home_dir: impl AsRef<Path>,
    configured_app_state_root: Option<&Path>,
) -> PathBuf {
    match configured_app_state_root {
        Some(configured_app_state_root) => {
            normalize_absolute_path(configured_app_state_root, cwd, home_dir)
        }
        None => home_dir.as_ref().join(".config").join("unpin"),
    }
}

pub fn default_cursor_root(home_dir: impl AsRef<Path>) -> ConfigResult<PathBuf> {
    cursor_root_for_os(home_dir.as_ref(), std::env::consts::OS)
}

fn cursor_root_for_os(home_dir: &Path, operating_system: &str) -> ConfigResult<PathBuf> {
    match operating_system {
        "macos" => Ok(home_dir.join("Library/Application Support/Cursor/User")),
        "windows" => Ok(home_dir.join("AppData/Roaming/Cursor/User")),
        "linux" => Ok(home_dir.join(".config/Cursor/User")),
        _ => Err(ConfigError::new(format!(
            "unsupported operating system for Cursor root discovery: {operating_system}; configure cursorRoot or pass --cursor-root explicitly"
        ))),
    }
}

pub fn resolve_cursor_root(
    cwd: impl AsRef<Path>,
    home_dir: impl AsRef<Path>,
    configured_cursor_root: Option<&Path>,
) -> ConfigResult<PathBuf> {
    match configured_cursor_root {
        Some(configured_cursor_root) => Ok(normalize_absolute_path(
            configured_cursor_root,
            cwd,
            home_dir,
        )),
        None => default_cursor_root(home_dir),
    }
}

pub fn get_project_snapshot_key(project_root: impl AsRef<Path>) -> String {
    let resolved = normalize_path(project_root.as_ref());
    let base_name = resolved
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("project");
    let slug = sanitize_project_key_segment(base_name);
    let mut hasher = Sha256::new();
    hasher.update(resolved.to_string_lossy().as_bytes());
    let hash = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    format!("{slug}-{}", &hash[..16])
}

pub fn get_project_snapshots_dir(
    app_state_root: impl AsRef<Path>,
    project_root: impl AsRef<Path>,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("snapshots")
        .join(get_project_snapshot_key(project_root))
}

pub fn get_snapshot_history_dir(
    app_state_root: impl AsRef<Path>,
    project_root: impl AsRef<Path>,
) -> PathBuf {
    get_project_snapshots_dir(app_state_root, project_root).join("history")
}

pub fn get_latest_snapshot_path(
    app_state_root: impl AsRef<Path>,
    project_root: impl AsRef<Path>,
) -> PathBuf {
    get_project_snapshots_dir(app_state_root, project_root).join("latest.json")
}

pub fn get_catalog_dir(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("catalog")
}

pub fn get_catalog_index_path(app_state_root: impl AsRef<Path>) -> PathBuf {
    get_catalog_dir(app_state_root).join("index.json")
}

pub fn get_catalog_object_path(app_state_root: impl AsRef<Path>, digest: &str) -> PathBuf {
    get_catalog_dir(app_state_root)
        .join("objects")
        .join(format!("{}.json", crate::encode_path_segment(digest)))
}

pub fn get_global_profiles_dir(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("profiles")
}

pub fn get_global_profile_definition_path(
    app_state_root: impl AsRef<Path>,
    profile_id: &str,
) -> PathBuf {
    get_global_profiles_dir(app_state_root)
        .join(format!("{}.json", crate::encode_path_segment(profile_id)))
}

pub fn get_profile_revision_path(app_state_root: impl AsRef<Path>, digest: &str) -> PathBuf {
    get_global_profiles_dir(app_state_root)
        .join("revisions")
        .join(format!("{}.json", crate::encode_path_segment(digest)))
}

pub fn get_global_policy_path(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("policy").join("global.json")
}

pub fn get_repository_policy_path(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("policy")
        .join("repositories")
        .join(format!(
            "{}.json",
            crate::encode_path_segment(repository_key)
        ))
}

pub fn get_workspace_policy_state_path(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
    workspace_key: &str,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("policy")
        .join("workspaces")
        .join(crate::encode_path_segment(repository_key))
        .join(format!(
            "{}.json",
            crate::encode_path_segment(workspace_key)
        ))
}

pub fn get_workspace_profiles_dir(workspace_root: impl AsRef<Path>) -> PathBuf {
    workspace_root.as_ref().join(".unpin").join("profiles")
}

pub fn get_workspace_groups_dir(workspace_root: impl AsRef<Path>) -> PathBuf {
    workspace_root.as_ref().join(".unpin").join("groups")
}

pub fn get_workspace_policy_path(workspace_root: impl AsRef<Path>) -> PathBuf {
    workspace_root.as_ref().join(".unpin").join("policy.json")
}

pub fn get_approval_nonce_path(app_state_root: impl AsRef<Path>, nonce_digest: &str) -> PathBuf {
    app_state_root
        .as_ref()
        .join("approvals")
        .join("nonces")
        .join(format!("{}.json", crate::encode_path_segment(nonce_digest)))
}

pub fn get_approval_nonce_ledger_path(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root
        .as_ref()
        .join("approvals")
        .join("nonces.json")
}

pub fn get_approval_nonce_ledger_shard_path(
    app_state_root: impl AsRef<Path>,
    shard: &str,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("approvals")
        .join("nonce-ledgers")
        .join(format!("{}.json", crate::encode_path_segment(shard)))
}

pub fn get_hook_trust_path(app_state_root: impl AsRef<Path>, operation_id: &str) -> PathBuf {
    app_state_root
        .as_ref()
        .join("trust")
        .join("hooks")
        .join(format!("{}.json", crate::encode_path_segment(operation_id)))
}

pub fn get_transition_journal_path(
    app_state_root: impl AsRef<Path>,
    operation_id: &str,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("transactions")
        .join(format!("{}.json", crate::encode_path_segment(operation_id)))
}

pub fn get_transition_lock_dir(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("transactions").join("locks")
}

pub fn get_activation_root(app_state_root: impl AsRef<Path>, repository_key: &str) -> PathBuf {
    app_state_root
        .as_ref()
        .join("activations")
        .join(crate::encode_path_segment(repository_key))
}

pub fn get_session_leases_dir(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("runtime").join("sessions")
}

pub fn get_session_lease_path(app_state_root: impl AsRef<Path>, session_id: &str) -> PathBuf {
    get_session_leases_dir(app_state_root)
        .join(format!("{}.json", crate::encode_path_segment(session_id)))
}

pub fn get_session_registry_lock_path(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root
        .as_ref()
        .join("runtime")
        .join("session-registry")
}

pub fn get_session_transition_admission_lock_path(
    app_state_root: impl AsRef<Path>,
    resource_digest: &str,
) -> PathBuf {
    app_state_root
        .as_ref()
        .join("runtime")
        .join("session-transition-admission")
        .join(resource_digest)
}

pub fn get_gateway_mode_path(app_state_root: impl AsRef<Path>, target_key: &str) -> PathBuf {
    get_gateway_modes_dir(app_state_root)
        .join(format!("{}.json", crate::encode_path_segment(target_key)))
}

pub fn get_gateway_modes_dir(app_state_root: impl AsRef<Path>) -> PathBuf {
    app_state_root.as_ref().join("runtime").join("modes")
}

pub fn get_session_overlay_root(app_state_root: impl AsRef<Path>, session_id: &str) -> PathBuf {
    app_state_root
        .as_ref()
        .join("runtime")
        .join("overlays")
        .join(crate::encode_path_segment(session_id))
}

pub fn load_config(options: LoadConfigOptions) -> ConfigResult<UnpinConfig> {
    let defaults = UnpinConfigDocument {
        version: Some(CONFIG_SCHEMA_VERSION),
        project_root: Some(options.cwd.clone()),
        ..UnpinConfigDocument::default()
    };

    let user_config_path = options
        .home_dir
        .join(".config")
        .join("unpin")
        .join("config.json");
    let user_config = load_optional_config_document(&user_config_path)?;

    let project_config_lookup_root = resolve_project_root(
        &options.cwd,
        &options.home_dir,
        options
            .overrides
            .project_root
            .as_deref()
            .or(user_config.project_root.as_deref())
            .or(defaults.project_root.as_deref()),
    );
    let project_config_path = project_config_lookup_root.join(".unpin.json");
    let project_config = load_optional_config_document(&project_config_path)?;
    for (field, configured) in [
        ("projectRoot", project_config.project_root.is_some()),
        ("appStateRoot", project_config.app_state_root.is_some()),
        ("cursorRoot", project_config.cursor_root.is_some()),
    ] {
        if configured {
            return Err(ConfigError::new(format!(
                "{} {field} is not allowed in project config; configure command roots in {} or pass the corresponding CLI root explicitly",
                project_config_path.display(),
                user_config_path.display()
            )));
        }
    }

    let merged =
        merge_config_documents(&defaults, &user_config, &project_config, &options.overrides);
    let version = merged.version.ok_or_else(|| {
        ConfigError::new("Unpin config schema version is missing after configuration merge")
    })?;

    Ok(UnpinConfig {
        version,
        project_root: resolve_project_root(
            &options.cwd,
            &options.home_dir,
            merged.project_root.as_deref(),
        ),
        app_state_root: resolve_app_state_root(
            &options.cwd,
            &options.home_dir,
            merged.app_state_root.as_deref(),
        ),
        cursor_root: resolve_cursor_root(
            &options.cwd,
            &options.home_dir,
            merged.cursor_root.as_deref(),
        )?,
        config_paths: UnpinConfigPaths {
            user_config_path,
            project_config_path,
        },
    })
}

fn load_optional_config_document(path: &Path) -> ConfigResult<UnpinConfigDocument> {
    let Some(raw) = read_optional_string(path)
        .map_err(|error| ConfigError::new(format!("{}: {error}", path.display())))?
    else {
        return Ok(UnpinConfigDocument::default());
    };
    parse_config_document(&raw, &path.display().to_string())
}

fn parse_config_document(raw: &str, label: &str) -> ConfigResult<UnpinConfigDocument> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|error| ConfigError::new(format!("{label} must be valid JSON: {error}")))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| ConfigError::new(format!("{label} must be a JSON object")))?;

    let version = match object.get("version") {
        Some(value) => {
            let version = value.as_u64().ok_or_else(|| {
                ConfigError::new(format!("{label} version must be the integer 1"))
            })?;
            if version != u64::from(CONFIG_SCHEMA_VERSION) {
                return Err(ConfigError::new(format!(
                    "Unsupported unpin config schema version: {version}"
                )));
            }
            Some(CONFIG_SCHEMA_VERSION)
        }
        None => None,
    };

    Ok(UnpinConfigDocument {
        version,
        project_root: string_path(object.get("projectRoot"), "projectRoot", label)?,
        app_state_root: string_path(object.get("appStateRoot"), "appStateRoot", label)?,
        cursor_root: string_path(object.get("cursorRoot"), "cursorRoot", label)?,
    })
}

fn string_path(value: Option<&Value>, field: &str, label: &str) -> ConfigResult<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }

    let path = value
        .as_str()
        .ok_or_else(|| ConfigError::new(format!("{label} {field} must be a string or null")))?;
    if path.trim().is_empty() {
        return Err(ConfigError::new(format!(
            "{label} {field} must not be empty"
        )));
    }

    Ok(Some(PathBuf::from(path)))
}

fn merge_config_documents(
    defaults: &UnpinConfigDocument,
    user_config: &UnpinConfigDocument,
    project_config: &UnpinConfigDocument,
    overrides: &UnpinConfigOverrides,
) -> UnpinConfigDocument {
    UnpinConfigDocument {
        version: project_config
            .version
            .or(user_config.version)
            .or(defaults.version),
        project_root: overrides
            .project_root
            .clone()
            .or_else(|| user_config.project_root.clone())
            .or_else(|| defaults.project_root.clone()),
        app_state_root: overrides
            .app_state_root
            .clone()
            .or_else(|| user_config.app_state_root.clone())
            .or_else(|| defaults.app_state_root.clone()),
        cursor_root: overrides
            .cursor_root
            .clone()
            .or_else(|| user_config.cursor_root.clone())
            .or_else(|| defaults.cursor_root.clone()),
    }
}

fn sanitize_project_key_segment(input: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;

    for character in input.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }

    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "project".to_string()
    } else {
        slug
    }
}

pub(crate) fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Prefix(value) => normalized.push(value.as_os_str()),
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::cursor_root_for_os;

    #[test]
    fn cursor_root_defaults_follow_supported_host_layouts() {
        let home = Path::new("/home/example");
        assert_eq!(
            cursor_root_for_os(home, "macos").expect("macOS is supported"),
            home.join("Library/Application Support/Cursor/User")
        );
        assert_eq!(
            cursor_root_for_os(home, "linux").expect("Linux is supported"),
            home.join(".config/Cursor/User")
        );
        assert_eq!(
            cursor_root_for_os(home, "windows").expect("Windows is supported"),
            home.join("AppData/Roaming/Cursor/User")
        );
    }

    #[test]
    fn unsupported_cursor_platform_requires_an_explicit_root() {
        let error = cursor_root_for_os(Path::new("/home/example"), "plan9")
            .expect_err("unsupported platform");
        assert!(error.to_string().contains("unsupported operating system"));
        assert!(error.to_string().contains("--cursor-root"));
    }
}
