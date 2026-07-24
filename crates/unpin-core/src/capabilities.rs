use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use serde_json::Value;

pub use crate::providers::registry::{CAPABILITY_ROWS, CapabilityRow};

use crate::{
    discovery::parse_codex_table_header, pi_packages::pi_package_extension_state,
    providers::registry::provider_registry,
};

const CAPABILITY_FIELDS: &[&str] = &[
    "skills",
    "configuredMcps",
    "tools",
    "agents",
    "hooks",
    "providerSettings",
    "pluginConfigs",
    "pluginManifests",
    "pluginGlobalScope",
    "pluginProjectScope",
    "extensions",
];
const CAPABILITY_STATUSES: &[&str] = &[
    "verified",
    "read-only",
    "unsupported",
    "out-of-scope",
    "needs-verification",
    "gateway-only",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityMatrix {
    pub version: u8,
    pub providers: BTreeMap<String, ProviderCapabilities>,
    pub notes: BTreeMap<String, String>,
}

impl CapabilityMatrix {
    pub fn provider_ids(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub skills: String,
    pub configured_mcps: String,
    pub tools: String,
    pub agents: String,
    pub hooks: String,
    pub provider_settings: String,
    pub plugin_configs: String,
    pub plugin_manifests: String,
    pub plugin_global_scope: String,
    pub plugin_project_scope: String,
    pub extensions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityMatrixValidationReport {
    pub issues: Vec<String>,
    pub matrix: Option<CapabilityMatrix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureValidationIssue {
    pub provider_id: String,
    pub relative_path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureValidationReport {
    pub checked_files: Vec<String>,
    pub issues: Vec<FixtureValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityMatrixError {
    message: String,
}

impl fmt::Display for CapabilityMatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CapabilityMatrixError {}

pub fn load_capability_matrix(
    fixtures_root: impl AsRef<Path>,
) -> Result<CapabilityMatrix, CapabilityMatrixError> {
    let report = validate_capability_matrix(fixtures_root);
    match report.matrix {
        Some(matrix) => Ok(matrix),
        None => Err(CapabilityMatrixError {
            message: report.issues.join("; "),
        }),
    }
}

pub fn validate_capability_matrix(
    fixtures_root: impl AsRef<Path>,
) -> CapabilityMatrixValidationReport {
    let matrix_path = fixtures_root.as_ref().join("capability-matrix.json");
    let raw = match fs::read_to_string(&matrix_path) {
        Ok(raw) => raw,
        Err(_) => {
            return CapabilityMatrixValidationReport {
                issues: vec!["capability-matrix.json is missing".to_string()],
                matrix: None,
            };
        }
    };

    validate_capability_matrix_json(&raw, &matrix_path)
}

pub fn validate_provider_fixtures(fixtures_root: impl AsRef<Path>) -> FixtureValidationReport {
    let fixtures_root = fixtures_root.as_ref();
    let mut checked_files = Vec::new();
    let mut issues = Vec::new();

    for fixture in PROVIDER_FIXTURES {
        checked_files.push(fixture.relative_path.to_string());
        let path = fixtures_root.join(fixture.relative_path);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => {
                issues.push(FixtureValidationIssue {
                    provider_id: fixture.provider_id.to_string(),
                    relative_path: fixture.relative_path.to_string(),
                    message: "fixture file is missing".to_string(),
                });
                continue;
            }
        };

        for message in validate_fixture_raw(fixture.validator, &raw) {
            issues.push(FixtureValidationIssue {
                provider_id: fixture.provider_id.to_string(),
                relative_path: fixture.relative_path.to_string(),
                message,
            });
        }
    }

    FixtureValidationReport {
        checked_files,
        issues,
    }
}

fn validate_capability_matrix_json(
    raw: &str,
    _matrix_path: &Path,
) -> CapabilityMatrixValidationReport {
    let parsed: Value = match serde_json::from_str(raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            return CapabilityMatrixValidationReport {
                issues: vec![format!(
                    "capability-matrix.json must be valid JSON: {error}"
                )],
                matrix: None,
            };
        }
    };
    let Some(object) = parsed.as_object() else {
        return CapabilityMatrixValidationReport {
            issues: vec!["capability-matrix.json must be a JSON object".to_string()],
            matrix: None,
        };
    };

    let mut issues = Vec::new();
    if object.get("version").and_then(Value::as_u64) != Some(2) {
        issues.push("capability-matrix.json must use version 2".to_string());
    }

    let providers_value = object.get("providers");
    let notes_value = object.get("notes");
    let providers_object = providers_value.and_then(Value::as_object);
    let notes_object = notes_value.and_then(Value::as_object);

    if providers_object.is_none() {
        issues.push("capability-matrix.json must define providers".to_string());
    }
    if notes_object.is_none() {
        issues.push("capability-matrix.json must define notes".to_string());
    }

    let mut providers = BTreeMap::new();
    let mut notes = BTreeMap::new();

    let mut provider_ids = provider_registry()
        .iter()
        .map(|descriptor| descriptor.id.as_str())
        .collect::<Vec<_>>();
    provider_ids.sort_unstable();

    for provider_id in provider_ids {
        match providers_object.and_then(|providers| providers.get(provider_id)) {
            Some(provider_value) if provider_value.is_object() => {
                if let Some(capabilities) =
                    validate_provider_capabilities(provider_id, provider_value, &mut issues)
                {
                    providers.insert(provider_id.to_string(), capabilities);
                }
            }
            _ => {
                issues.push(format!("capability-matrix.json is missing {provider_id}"));
            }
        }

        match notes_object
            .and_then(|notes| notes.get(provider_id))
            .and_then(Value::as_str)
        {
            Some(note) if !note.is_empty() => {
                notes.insert(provider_id.to_string(), note.to_string());
            }
            _ => {
                issues.push(format!(
                    "capability-matrix.json is missing note for {provider_id}"
                ));
            }
        }
    }

    if issues.is_empty() {
        CapabilityMatrixValidationReport {
            issues,
            matrix: Some(CapabilityMatrix {
                version: 2,
                providers,
                notes,
            }),
        }
    } else {
        CapabilityMatrixValidationReport {
            issues,
            matrix: None,
        }
    }
}

fn validate_provider_capabilities(
    provider_id: &str,
    provider_value: &Value,
    issues: &mut Vec<String>,
) -> Option<ProviderCapabilities> {
    let object = provider_value
        .as_object()
        .expect("provider_value is known object");
    let mut values = BTreeMap::new();
    let mut provider_valid = true;

    for field in CAPABILITY_FIELDS {
        match object.get(*field).and_then(Value::as_str) {
            Some(status) if CAPABILITY_STATUSES.contains(&status) => {
                values.insert(*field, status.to_string());
            }
            Some(_) => {
                provider_valid = false;
                issues.push(format!(
                    "capability-matrix.json has an invalid {provider_id}.{field} value"
                ));
            }
            None => {
                provider_valid = false;
                issues.push(format!(
                    "capability-matrix.json is missing {provider_id}.{field}"
                ));
            }
        }
    }

    if provider_valid {
        Some(ProviderCapabilities {
            skills: values["skills"].clone(),
            configured_mcps: values["configuredMcps"].clone(),
            tools: values["tools"].clone(),
            agents: values["agents"].clone(),
            hooks: values["hooks"].clone(),
            provider_settings: values["providerSettings"].clone(),
            plugin_configs: values["pluginConfigs"].clone(),
            plugin_manifests: values["pluginManifests"].clone(),
            plugin_global_scope: values["pluginGlobalScope"].clone(),
            plugin_project_scope: values["pluginProjectScope"].clone(),
            extensions: values["extensions"].clone(),
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum FixtureValidator {
    ClaudeSettings(&'static str),
    ClaudeUserStateMcp,
    ClaudeProjectMcp,
    CodexConfig,
    SkillMarkdown,
    BundledPluginManifest(&'static str, &'static str),
    BundledPluginMcp(&'static str),
    CursorMcp,
    CursorPluginManifest,
    PiSettings,
    OpenCodeConfig,
    PluginSource,
    ZedSettings(&'static str),
}

struct FixtureSpec {
    provider_id: &'static str,
    relative_path: &'static str,
    validator: FixtureValidator,
}

const PROVIDER_FIXTURES: &[FixtureSpec] = &[
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/.claude.json",
        validator: FixtureValidator::ClaudeUserStateMcp,
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/global/settings.json",
        validator: FixtureValidator::ClaudeSettings("Claude global settings"),
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/global/settings.local.json",
        validator: FixtureValidator::ClaudeSettings("Claude global settings.local.json"),
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/project/.claude/settings.json",
        validator: FixtureValidator::ClaudeSettings("Claude project settings.json"),
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/project/.claude/settings.local.json",
        validator: FixtureValidator::ClaudeSettings("Claude project settings.local.json"),
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/global/skills/example-claude-global-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/project/.claude/skills/example-claude-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/project/.mcp.json",
        validator: FixtureValidator::ClaudeProjectMcp,
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.claude-plugin/plugin.json",
        validator: FixtureValidator::BundledPluginManifest("Claude plugin manifest", "./.mcp.json"),
    },
    FixtureSpec {
        provider_id: "claude",
        relative_path: "claude/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json",
        validator: FixtureValidator::BundledPluginMcp("Claude plugin .mcp.json"),
    },
    FixtureSpec {
        provider_id: "codex",
        relative_path: "codex/global/config.toml",
        validator: FixtureValidator::CodexConfig,
    },
    FixtureSpec {
        provider_id: "codex",
        relative_path: "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.codex-plugin/plugin.json",
        validator: FixtureValidator::BundledPluginManifest("Codex plugin manifest", "./.mcp.json"),
    },
    FixtureSpec {
        provider_id: "codex",
        relative_path: "codex/global/plugins/cache/example-marketplace/connector-kit/1.0.0/.mcp.json",
        validator: FixtureValidator::BundledPluginMcp("Codex plugin .mcp.json"),
    },
    FixtureSpec {
        provider_id: "codex",
        relative_path: "codex/admin/skills/example-codex-admin-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "shared",
        relative_path: "shared/global/.agents/skills/example-shared-global-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "shared",
        relative_path: "shared/project/.agents/skills/example-shared-project-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/home/skills/example-cursor-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/project/.cursor/skills/example-cursor-project-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/home/mcp.json",
        validator: FixtureValidator::CursorMcp,
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/project/.cursor/mcp.json",
        validator: FixtureValidator::CursorMcp,
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/home/plugins/local/example-plugin/.cursor-plugin/plugin.json",
        validator: FixtureValidator::BundledPluginManifest("Cursor plugin manifest", "./mcp.json"),
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/home/plugins/local/example-plugin/mcp.json",
        validator: FixtureValidator::BundledPluginMcp("Cursor plugin mcp.json"),
    },
    FixtureSpec {
        provider_id: "cursor",
        relative_path: "cursor/home/plugins/local/claude-compatible/.claude-plugin/plugin.json",
        validator: FixtureValidator::CursorPluginManifest,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/global/skills/workflows/example-pi-global-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/global/skills/example-pi-file-skill.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/project/.pi/skills/example-pi-project-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/project/.pi/skills/example-pi-project-file-skill.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/global/settings.json",
        validator: FixtureValidator::PiSettings,
    },
    FixtureSpec {
        provider_id: "pi",
        relative_path: "pi/project/.pi/settings.json",
        validator: FixtureValidator::PiSettings,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/global/skills/example-opencode-global-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/global/opencode.jsonc",
        validator: FixtureValidator::OpenCodeConfig,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/project/opencode.json",
        validator: FixtureValidator::OpenCodeConfig,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/global/plugins/example-local.ts",
        validator: FixtureValidator::PluginSource,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/project/.opencode/plugins/example-project.js",
        validator: FixtureValidator::PluginSource,
    },
    FixtureSpec {
        provider_id: "opencode",
        relative_path: "opencode/project/.opencode/skills/example-opencode-project-skill/SKILL.md",
        validator: FixtureValidator::SkillMarkdown,
    },
    FixtureSpec {
        provider_id: "zed",
        relative_path: "zed/global/.config/zed/settings.json",
        validator: FixtureValidator::ZedSettings("Zed global settings.json"),
    },
    FixtureSpec {
        provider_id: "zed",
        relative_path: "zed/project/.zed/settings.json",
        validator: FixtureValidator::ZedSettings("Zed project settings.json"),
    },
];

fn validate_fixture_raw(validator: FixtureValidator, raw: &str) -> Vec<String> {
    match validator {
        FixtureValidator::ClaudeSettings(label) => validate_claude_settings(raw, label),
        FixtureValidator::ClaudeUserStateMcp => validate_claude_user_state(raw),
        FixtureValidator::ClaudeProjectMcp => {
            validate_mcp_servers_object(raw, "Claude project .mcp.json")
        }
        FixtureValidator::CodexConfig => validate_codex_config(raw),
        FixtureValidator::SkillMarkdown => validate_skill_markdown(raw),
        FixtureValidator::BundledPluginManifest(label, mcp_path) => {
            validate_bundled_plugin_manifest(raw, label, mcp_path)
        }
        FixtureValidator::BundledPluginMcp(label) => validate_bundled_plugin_mcp(raw, label),
        FixtureValidator::CursorMcp => validate_cursor_mcp(raw),
        FixtureValidator::CursorPluginManifest => validate_cursor_plugin_manifest(raw),
        FixtureValidator::PiSettings => validate_pi_settings(raw),
        FixtureValidator::OpenCodeConfig => validate_opencode_config(raw),
        FixtureValidator::PluginSource => raw
            .trim()
            .is_empty()
            .then_some("plugin source must not be empty".to_string())
            .into_iter()
            .collect(),
        FixtureValidator::ZedSettings(label) => validate_zed_settings(raw, label),
    }
}

fn validate_claude_settings(raw: &str, label: &str) -> Vec<String> {
    let document = match parse_json_object(raw, label) {
        Ok(document) => document,
        Err(message) => return vec![message],
    };
    let mut issues = Vec::new();

    if let Some(enabled_plugins) = document.get("enabledPlugins") {
        if let Some(plugins) = enabled_plugins.as_object() {
            for (key, value) in plugins {
                if !value.is_boolean() {
                    issues.push(format!("enabledPlugins.{key} must be a boolean"));
                }
            }
        } else {
            issues.push("enabledPlugins must be an object".to_string());
        }
    }

    for field in ["enabledMcpjsonServers", "disabledMcpjsonServers"] {
        if document.get(field).is_some_and(|value| !value.is_object()) {
            issues.push(format!("{field} must be an object"));
        }
    }

    if document
        .get("enableAllProjectMcpServers")
        .is_some_and(|value| !value.is_boolean())
    {
        issues.push("enableAllProjectMcpServers must be a boolean".to_string());
    }

    issues
}

fn validate_mcp_servers_object(raw: &str, label: &str) -> Vec<String> {
    let document = match parse_json_object(raw, label) {
        Ok(document) => document,
        Err(message) => return vec![message],
    };

    if document
        .get("mcpServers")
        .is_some_and(|value| value.is_object())
    {
        Vec::new()
    } else {
        vec!["mcpServers must be an object".to_string()]
    }
}

fn validate_claude_user_state(raw: &str) -> Vec<String> {
    let document = match parse_json_object(raw, "Claude user .claude.json") {
        Ok(document) => document,
        Err(message) => return vec![message],
    };
    let mut issues = Vec::new();
    if !document
        .get("mcpServers")
        .is_some_and(|value| value.is_object())
    {
        issues.push("mcpServers must be an object".to_string());
    }

    let Some(projects) = document.get("projects").and_then(Value::as_object) else {
        issues.push("projects must be an object".to_string());
        return issues;
    };
    let mut has_local_mcp = false;
    for (index, project) in projects.values().enumerate() {
        let Some(project) = project.as_object() else {
            issues.push(format!("projects entry {index} must be an object"));
            continue;
        };
        let Some(servers_value) = project.get("mcpServers") else {
            continue;
        };
        let Some(servers) = servers_value.as_object() else {
            issues.push(format!(
                "projects entry {index} mcpServers must be an object"
            ));
            continue;
        };
        has_local_mcp |= !servers.is_empty();
        for (server_id, value) in servers {
            if !value.is_object() {
                issues.push(format!(
                    "projects entry {index} mcpServers.{server_id} must be an object"
                ));
            }
        }
    }
    if !has_local_mcp {
        issues.push("projects must contain a local mcpServers fixture".to_string());
    }

    issues
}

fn validate_codex_config(raw: &str) -> Vec<String> {
    let mut issues = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("[plugins") && !trimmed.starts_with("[mcp_servers") {
            continue;
        }

        if !valid_codex_section_header(trimmed) {
            issues.push(format!(
                "line {} must use [plugins.<id>] or [mcp_servers.<id>]",
                index + 1
            ));
        }
    }

    issues
}

fn valid_codex_section_header(line: &str) -> bool {
    let Some(header) = parse_codex_table_header(line) else {
        return false;
    };

    ["plugins.", "mcp_servers."].iter().any(|prefix| {
        header
            .strip_prefix(prefix)
            .is_some_and(|path| !path.is_empty() && !path.starts_with('.') && !path.ends_with('.'))
    })
}

fn validate_skill_markdown(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return vec!["SKILL.md must not be empty".to_string()];
    }

    if trimmed.lines().any(|line| {
        line.strip_prefix("# ")
            .is_some_and(|heading| !heading.trim().is_empty())
    }) {
        Vec::new()
    } else {
        vec!["SKILL.md must include a top-level markdown heading".to_string()]
    }
}

fn validate_bundled_plugin_manifest(raw: &str, label: &str, mcp_path: &str) -> Vec<String> {
    let document = match parse_json_object(raw, label) {
        Ok(document) => document,
        Err(message) => return vec![message],
    };
    let mut issues = Vec::new();

    if !document
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        issues.push(format!("{label} must define a non-empty name"));
    }
    if document.get("mcpServers").and_then(Value::as_str) != Some(mcp_path) {
        issues.push(format!("{label} mcpServers must reference {mcp_path}"));
    }

    issues
}

fn validate_bundled_plugin_mcp(raw: &str, label: &str) -> Vec<String> {
    let document = match parse_json_object(raw, label) {
        Ok(document) => document,
        Err(message) => return vec![message],
    };
    let Some(servers) = document.get("mcpServers").and_then(Value::as_object) else {
        return vec![format!("{label} mcpServers must be an object")];
    };
    if servers.is_empty() {
        return vec![format!("{label} mcpServers must not be empty")];
    }

    servers
        .iter()
        .filter_map(|(server_id, value)| {
            let Some(server) = value.as_object() else {
                return Some(format!("{label} mcpServers.{server_id} must be an object"));
            };
            let has_command = server
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty());
            let has_url = server
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty());
            (!has_command && !has_url).then(|| {
                format!("{label} mcpServers.{server_id} must define a non-empty command or url")
            })
        })
        .collect()
}

fn validate_cursor_mcp(raw: &str) -> Vec<String> {
    match parse_json_object(raw, "Cursor mcp.json") {
        Ok(document) => validate_mcp_servers_document(document),
        Err(_) => match parse_json_object(&strip_trailing_commas(raw), "Cursor mcp.json") {
            Ok(document) => validate_mcp_servers_document(document),
            Err(message) => vec![message],
        },
    }
}

fn validate_cursor_plugin_manifest(raw: &str) -> Vec<String> {
    let document = match parse_json_object(raw, "Cursor plugin manifest") {
        Ok(document) => document,
        Err(message) => return vec![message],
    };

    if ["displayName", "name"].iter().any(|field| {
        document
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    }) {
        Vec::new()
    } else {
        vec!["Cursor plugin manifest must define a non-empty displayName or name".to_string()]
    }
}

fn validate_mcp_servers_document(document: serde_json::Map<String, Value>) -> Vec<String> {
    if document
        .get("mcpServers")
        .is_some_and(|value| value.is_object())
    {
        Vec::new()
    } else {
        vec!["mcpServers must be an object".to_string()]
    }
}

fn validate_zed_settings(raw: &str, label: &str) -> Vec<String> {
    let document = match parse_json_object(raw, label) {
        Ok(document) => document,
        Err(message) => return vec![message],
    };

    if document
        .get("context_servers")
        .is_some_and(|value| value.is_object())
    {
        Vec::new()
    } else {
        vec!["context_servers must be an object".to_string()]
    }
}

fn validate_pi_settings(raw: &str) -> Vec<String> {
    let document = match parse_json_object(raw, "Pi settings.json") {
        Ok(document) => document,
        Err(message) => return vec![message],
    };
    let Some(packages) = document.get("packages") else {
        return vec!["packages must be an array".to_string()];
    };
    let Some(packages) = packages.as_array() else {
        return vec!["packages must be an array".to_string()];
    };
    let mut issues = Vec::new();
    let mut sources = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        match pi_package_extension_state(package) {
            Ok((source, _)) if !sources.insert(source) => {
                issues.push(format!("packages[{index}] duplicates source {source}"));
            }
            Ok(_) => {}
            Err(reason) => issues.push(format!("packages[{index}] {reason}")),
        }
    }
    issues
}

fn validate_opencode_config(raw: &str) -> Vec<String> {
    let document = match jsonc_parser::parse_to_serde_value(raw, &Default::default()) {
        Ok(Some(Value::Object(document))) => document,
        Ok(Some(_)) => return vec!["OpenCode config must be a JSON object".to_string()],
        Ok(None) => return vec!["OpenCode config must not be empty".to_string()],
        Err(error) => return vec![format!("OpenCode config is not valid JSONC: {error}")],
    };
    let mut issues = Vec::new();
    match document.get("mcp") {
        Some(Value::Object(servers)) => {
            for (server_id, server) in servers {
                let Some(server) = server.as_object() else {
                    issues.push(format!("mcp.{server_id} must be an object"));
                    continue;
                };
                if server
                    .get("enabled")
                    .is_some_and(|value| !value.is_boolean())
                {
                    issues.push(format!("mcp.{server_id}.enabled must be a boolean"));
                }
            }
        }
        Some(_) => issues.push("mcp must be an object".to_string()),
        None => issues.push("mcp must be an object".to_string()),
    }
    match document.get("plugin") {
        Some(Value::Array(plugins)) => {
            let mut seen = BTreeSet::new();
            for (index, plugin) in plugins.iter().enumerate() {
                let Some(plugin) = plugin.as_str() else {
                    issues.push(format!("plugin[{index}] must be a string"));
                    continue;
                };
                if plugin.is_empty() {
                    issues.push(format!("plugin[{index}] must not be empty"));
                } else if !seen.insert(plugin) {
                    issues.push(format!("plugin[{index}] duplicates {plugin}"));
                }
            }
        }
        Some(_) => issues.push("plugin must be an array".to_string()),
        None => issues.push("plugin must be an array".to_string()),
    }
    issues
}

fn parse_json_object(raw: &str, label: &str) -> Result<serde_json::Map<String, Value>, String> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|error| format!("{label} must be valid JSON: {error}"))?;
    parsed
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn strip_trailing_commas(contents: &str) -> String {
    let mut result = String::new();
    let mut in_string = false;
    let mut escaped = false;
    let chars = contents.chars().collect::<Vec<_>>();
    let mut index = 0;

    while index < chars.len() {
        let character = chars[index];
        if in_string {
            result.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if character == '"' {
            in_string = true;
            result.push(character);
            index += 1;
            continue;
        }

        if character == ',' {
            let mut lookahead = index + 1;
            while lookahead < chars.len() && chars[lookahead].is_whitespace() {
                lookahead += 1;
            }
            if matches!(chars.get(lookahead).copied(), Some('}' | ']')) {
                index += 1;
                continue;
            }
        }

        result.push(character);
        index += 1;
    }

    result
}
