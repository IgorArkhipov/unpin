use crate::{
    bridges::{HookBridgeDescriptor, hook_bridge_descriptor},
    discovery::{
        ProviderDiscoverer, discover_claude, discover_codex, discover_cursor, discover_opencode,
        discover_pi, discover_zed,
    },
    providers::ProviderId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityRow {
    pub provider_id: &'static str,
    pub provider_name: &'static str,
    pub skills: &'static str,
    pub configured_mcps: &'static str,
    pub tools: &'static str,
    pub agents: &'static str,
    pub hooks: &'static str,
    pub provider_settings: &'static str,
    pub plugin_configs: &'static str,
    pub plugin_manifests: &'static str,
    pub plugin_global_scope: &'static str,
    pub plugin_project_scope: &'static str,
    pub extensions: &'static str,
    pub note: &'static str,
}

#[derive(Clone, Copy)]
pub struct ProviderDescriptor {
    pub id: ProviderId,
    pub capabilities: CapabilityRow,
    pub hook_bridge: HookBridgeDescriptor,
    pub(crate) discoverer: ProviderDiscoverer,
}

impl std::fmt::Debug for ProviderDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDescriptor")
            .field("id", &self.id)
            .field("capabilities", &self.capabilities)
            .field("hook_bridge", &self.hook_bridge)
            .finish_non_exhaustive()
    }
}

const PROVIDERS: [ProviderDescriptor; 6] = [
    ProviderDescriptor {
        id: ProviderId::Claude,
        discoverer: discover_claude,
        hook_bridge: hook_bridge_descriptor(ProviderId::Claude),
        capabilities: CapabilityRow {
            provider_id: "claude",
            provider_name: "Claude Code",
            skills: "verified",
            configured_mcps: "verified",
            tools: "unsupported",
            agents: "verified",
            hooks: "needs-verification",
            provider_settings: "read-only",
            plugin_configs: "verified",
            plugin_manifests: "unsupported",
            plugin_global_scope: "verified",
            plugin_project_scope: "verified",
            extensions: "unsupported",
            note: "Verified Claude toggles cover regular and provider-owned linked global and repository-scoped .claude/skills directories, user- and local-scoped .claude.json MCP entries, project .mcp.json approvals, and user, project, and local enabledPlugins settings. Plugin toggles use native settings references and leave installed plugin bundles on disk. Skill links preserve link identity; symlinked skill roots remain read-only. Hook handlers are inventoried individually and gateway policy is fixture-verified; native dispatcher activation remains pending installed-host verification.",
        },
    },
    ProviderDescriptor {
        id: ProviderId::Codex,
        discoverer: discover_codex,
        hook_bridge: hook_bridge_descriptor(ProviderId::Codex),
        capabilities: CapabilityRow {
            provider_id: "codex",
            provider_name: "Codex",
            skills: "verified",
            configured_mcps: "verified",
            tools: "unsupported",
            agents: "verified",
            hooks: "needs-verification",
            provider_settings: "read-only",
            plugin_configs: "verified",
            plugin_manifests: "unsupported",
            plugin_global_scope: "verified",
            plugin_project_scope: "unsupported",
            extensions: "unsupported",
            note: "Verified Codex shared global and project `.agents/skills` toggles use Unpin-owned vault state with origin-preserving restore and explicit cross-provider impact. Administrator-managed skill toggles use path-specific `[[skills.config]]` enabled state in user config without moving their sources. Plugin toggles use native `plugins.<id>.enabled` state in user config. Current Codex plugin installation and enable state are user-scoped; repository `.codex/config.toml` plugin sections are not a supported host contract. Restart Codex after skill or plugin changes. Configured MCP toggles use native enabled state across user and project config layers. Hook handlers are inventoried individually and gateway policy is fixture-verified; native dispatcher activation remains pending installed-host verification.",
        },
    },
    ProviderDescriptor {
        id: ProviderId::Cursor,
        discoverer: discover_cursor,
        hook_bridge: hook_bridge_descriptor(ProviderId::Cursor),
        capabilities: CapabilityRow {
            provider_id: "cursor",
            provider_name: "Cursor",
            skills: "verified",
            configured_mcps: "verified",
            tools: "unsupported",
            agents: "verified",
            hooks: "needs-verification",
            provider_settings: "read-only",
            plugin_configs: "unsupported",
            plugin_manifests: "verified",
            plugin_global_scope: "verified",
            plugin_project_scope: "read-only",
            extensions: "unsupported",
            note: "Verified Cursor toggles cover recursively nested global and project .cursor/skills directories, compatibility skills from .agents/skills, .claude/skills, and .codex/skills, modern MCP config, and local plugin directories under $HOME/.cursor/plugins/local. Shared-source skill toggles move the source into Unpin-owned state, retain its original path, and explicitly affect every provider loading that path. Provider-owned linked skills preserve link identity. Marketplace user, project, and team installs remain unsupported because Cursor owns them through authenticated backend state rather than a local config toggle. Hook handlers are inventoried individually and gateway policy is fixture-verified; native dispatcher activation remains pending installed-host verification.",
        },
    },
    ProviderDescriptor {
        id: ProviderId::Pi,
        discoverer: discover_pi,
        hook_bridge: hook_bridge_descriptor(ProviderId::Pi),
        capabilities: CapabilityRow {
            provider_id: "pi",
            provider_name: "Pi",
            skills: "needs-verification",
            configured_mcps: "unsupported",
            tools: "unsupported",
            agents: "unsupported",
            hooks: "needs-verification",
            provider_settings: "read-only",
            plugin_configs: "needs-verification",
            plugin_manifests: "unsupported",
            plugin_global_scope: "needs-verification",
            plugin_project_scope: "needs-verification",
            extensions: "needs-verification",
            note: "Docs-backed Pi support inventories native .pi and shared .agents skills across global and project scopes. Directory skills use authenticated Unpin vault toggles with cross-provider fan-out for shared sources. Pi intentionally has no native MCP core; connector support belongs to extensions or packages. Package extension toggles use native packages[].extensions filters, retain package references and other resources, and are fixture-verified pending live-host verification. Unpin-managed tool_call/tool_result bridge asset is integrity-tracked and fixture-verified; host behavior remains pending live verification.",
        },
    },
    ProviderDescriptor {
        id: ProviderId::OpenCode,
        discoverer: discover_opencode,
        hook_bridge: hook_bridge_descriptor(ProviderId::OpenCode),
        capabilities: CapabilityRow {
            provider_id: "opencode",
            provider_name: "OpenCode",
            skills: "needs-verification",
            configured_mcps: "needs-verification",
            tools: "unsupported",
            agents: "unsupported",
            hooks: "needs-verification",
            provider_settings: "read-only",
            plugin_configs: "needs-verification",
            plugin_manifests: "read-only",
            plugin_global_scope: "needs-verification",
            plugin_project_scope: "needs-verification",
            extensions: "unsupported",
            note: "Docs-backed OpenCode support inventories native .opencode skills plus shared .agents and .claude skills across global and project scopes. Directory skills use authenticated Unpin vault toggles with cross-provider fan-out for shared sources. Native JSONC MCP enabled state and config-listed npm plugin reference toggles are fixture-verified and remain pending live-host verification. Plugin toggles preserve JSONC and leave Bun cache files installed. Auto-loaded local plugin files are read-only because OpenCode exposes no local-file disable setting. Unpin-managed tool.execute before/after bridge asset is integrity-tracked and fixture-verified; host behavior remains pending live verification.",
        },
    },
    ProviderDescriptor {
        id: ProviderId::Zed,
        discoverer: discover_zed,
        hook_bridge: hook_bridge_descriptor(ProviderId::Zed),
        capabilities: CapabilityRow {
            provider_id: "zed",
            provider_name: "Zed",
            skills: "verified",
            configured_mcps: "verified",
            tools: "unsupported",
            agents: "unsupported",
            hooks: "gateway-only",
            provider_settings: "read-only",
            plugin_configs: "out-of-scope",
            plugin_manifests: "out-of-scope",
            plugin_global_scope: "out-of-scope",
            plugin_project_scope: "out-of-scope",
            extensions: "unsupported",
            note: "Verified Zed global and project Agent Skills from .agents/skills use Unpin-owned vault state with origin-preserving restore and explicit shared-provider impact; verified settings.json context_servers toggles preserve JSONC comments, trailing commas, and surrounding formatting. Zed plugins are outside Unpin scope; reusable agent instructions use standard Agent Skills. Hooks apply only to MCP calls routed through Unpin gateway; Zed built-in tool lifecycle hooks remain unsupported.",
        },
    },
];

/// Compatibility view used by existing CLI rendering and fixture validation.
/// Values are copied from registry descriptors at compile time, so registry remains authority.
pub const CAPABILITY_ROWS: &[CapabilityRow] = &[
    PROVIDERS[0].capabilities,
    PROVIDERS[1].capabilities,
    PROVIDERS[2].capabilities,
    PROVIDERS[3].capabilities,
    PROVIDERS[4].capabilities,
    PROVIDERS[5].capabilities,
];

#[must_use]
pub fn provider_registry() -> &'static [ProviderDescriptor] {
    &PROVIDERS
}

#[must_use]
pub fn provider_descriptor(provider_id: ProviderId) -> &'static ProviderDescriptor {
    &PROVIDERS[provider_id_index(provider_id)]
}

const fn provider_id_index(provider_id: ProviderId) -> usize {
    match provider_id {
        ProviderId::Claude => 0,
        ProviderId::Codex => 1,
        ProviderId::Cursor => 2,
        ProviderId::Pi => 3,
        ProviderId::OpenCode => 4,
        ProviderId::Zed => 5,
    }
}
