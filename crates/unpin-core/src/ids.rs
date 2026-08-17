//! Shared discovery-item ID prefixes used by inventory and mutation.
//!
//! Discovery constructs these IDs; mutation parses them. Keep both sides on the
//! same literals so a prefix change cannot silently desynchronize plan/apply.

pub(crate) const CLAUDE_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "claude:global:configured-mcp:";
pub(crate) const CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX: &str =
    "claude:project:configured-mcp:@local/";
pub(crate) const CLAUDE_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "claude:project:configured-mcp:";
pub(crate) const CLAUDE_ALL_PROJECT_MCP_SERVERS_ID: &str =
    "claude:project:configured-mcp:all-project-mcp-servers";

pub(crate) const CODEX_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "codex:global:configured-mcp:";
pub(crate) const CODEX_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "codex:project:configured-mcp:";
pub(crate) const CODEX_GLOBAL_PLUGIN_CONFIG_ID_PREFIX: &str = "codex:global:plugin-config:config:";

pub(crate) const CURSOR_GLOBAL_SKILL_ID_PREFIX: &str = "cursor:global:skill:";
pub(crate) const CURSOR_PROJECT_SKILL_ID_PREFIX: &str = "cursor:project:skill:";
pub(crate) const CURSOR_GLOBAL_LOCAL_PLUGIN_ID_PREFIX: &str =
    "cursor:global:plugin-manifest:local:";
pub(crate) const CURSOR_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "cursor:global:configured-mcp:";
pub(crate) const CURSOR_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "cursor:project:configured-mcp:";

pub(crate) const OPENCODE_GLOBAL_SKILL_ID_PREFIX: &str = "opencode:global:skill:";
pub(crate) const OPENCODE_PROJECT_SKILL_ID_PREFIX: &str = "opencode:project:skill:";
pub(crate) const OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "opencode:global:configured-mcp:";
pub(crate) const OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str =
    "opencode:project:configured-mcp:";
pub(crate) const OPENCODE_GLOBAL_PLUGIN_CONFIG_ID_PREFIX: &str =
    "opencode:global:plugin-config:npm:";
pub(crate) const OPENCODE_PROJECT_PLUGIN_CONFIG_ID_PREFIX: &str =
    "opencode:project:plugin-config:npm:";

pub(crate) const PI_GLOBAL_SKILL_ID_PREFIX: &str = "pi:global:skill:";
pub(crate) const PI_PROJECT_SKILL_ID_PREFIX: &str = "pi:project:skill:";
pub(crate) const PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX: &str =
    "pi:global:plugin-config:package-extensions:";
pub(crate) const PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX: &str =
    "pi:project:plugin-config:package-extensions:";

pub(crate) const ZED_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "zed:global:configured-mcp:";
pub(crate) const ZED_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "zed:project:configured-mcp:";
