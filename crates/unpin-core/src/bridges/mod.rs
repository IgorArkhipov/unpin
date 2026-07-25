//! Provider hook bridge descriptors and managed asset lifecycle.
//!
//! Native provider configuration remains transition-owned. This module owns
//! only Unpin bridge assets and their integrity state.

mod installer;

pub use installer::*;

use serde::{Deserialize, Serialize};

use crate::providers::ProviderId;

pub const BRIDGE_ASSET_VERSION: u32 = 1;
pub const MANAGED_COMPONENT_REFERENCE: &str = "unpin-hook-bridge-v1";
pub const NATIVE_DISPATCH_REFERENCE: &str = "unpin-native-dispatcher-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookBridgeAdapter {
    NativeDispatcher,
    ManagedExtension,
    ManagedPlugin,
    GatewayOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookCoverageStatus {
    Verified,
    NeedsVerification,
    GatewayOnly,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookBridgeDescriptor {
    pub provider: ProviderId,
    pub adapter: HookBridgeAdapter,
    pub built_in_tools: HookCoverageStatus,
    pub gateway_mcp_tools: HookCoverageStatus,
    pub native_events: &'static [&'static str],
    pub managed_asset_file: Option<&'static str>,
    pub managed_component_reference: &'static str,
    pub native_dispatch_reference: Option<&'static str>,
}

impl HookBridgeDescriptor {
    #[must_use]
    pub const fn has_managed_asset(self) -> bool {
        self.managed_asset_file.is_some()
    }
}

const CLAUDE_EVENTS: &[&str] = &[
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "SessionStart",
    "SessionEnd",
    "PreCompact",
];
const CODEX_EVENTS: &[&str] = &[
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "SessionStart",
    "SessionEnd",
];
const CURSOR_EVENTS: &[&str] = &[
    "beforeShellExecution",
    "preToolUse",
    "postToolUse",
    "afterShellExecution",
    "afterFileEdit",
];
const PI_EVENTS: &[&str] = &["tool_call", "tool_result"];
const OPENCODE_EVENTS: &[&str] = &["tool.execute.before", "tool.execute.after"];

#[must_use]
pub const fn hook_bridge_descriptor(provider: ProviderId) -> HookBridgeDescriptor {
    match provider {
        ProviderId::Claude => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::NativeDispatcher,
            built_in_tools: HookCoverageStatus::NeedsVerification,
            gateway_mcp_tools: HookCoverageStatus::Verified,
            native_events: CLAUDE_EVENTS,
            managed_asset_file: None,
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: Some(NATIVE_DISPATCH_REFERENCE),
        },
        ProviderId::Codex => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::NativeDispatcher,
            built_in_tools: HookCoverageStatus::NeedsVerification,
            gateway_mcp_tools: HookCoverageStatus::Verified,
            native_events: CODEX_EVENTS,
            managed_asset_file: None,
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: Some(NATIVE_DISPATCH_REFERENCE),
        },
        ProviderId::Cursor => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::NativeDispatcher,
            built_in_tools: HookCoverageStatus::NeedsVerification,
            gateway_mcp_tools: HookCoverageStatus::Verified,
            native_events: CURSOR_EVENTS,
            managed_asset_file: None,
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: Some(NATIVE_DISPATCH_REFERENCE),
        },
        ProviderId::Pi => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::ManagedExtension,
            built_in_tools: HookCoverageStatus::NeedsVerification,
            gateway_mcp_tools: HookCoverageStatus::Verified,
            native_events: PI_EVENTS,
            managed_asset_file: Some("unpin-hook-bridge.ts"),
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: None,
        },
        ProviderId::OpenCode => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::ManagedPlugin,
            built_in_tools: HookCoverageStatus::NeedsVerification,
            gateway_mcp_tools: HookCoverageStatus::Verified,
            native_events: OPENCODE_EVENTS,
            managed_asset_file: Some("unpin-hook-bridge.ts"),
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: None,
        },
        ProviderId::Zed => HookBridgeDescriptor {
            provider,
            adapter: HookBridgeAdapter::GatewayOnly,
            built_in_tools: HookCoverageStatus::Unsupported,
            gateway_mcp_tools: HookCoverageStatus::GatewayOnly,
            native_events: &[],
            managed_asset_file: None,
            managed_component_reference: MANAGED_COMPONENT_REFERENCE,
            native_dispatch_reference: None,
        },
    }
}

pub(crate) fn managed_asset(provider: ProviderId) -> Option<&'static str> {
    match provider {
        ProviderId::Pi => Some(include_str!("../../assets/bridges/pi/unpin-hook-bridge.ts")),
        ProviderId::OpenCode => Some(include_str!(
            "../../assets/bridges/opencode/unpin-hook-bridge.ts"
        )),
        ProviderId::Claude | ProviderId::Codex | ProviderId::Cursor | ProviderId::Zed => None,
    }
}
