use crate::discovery::{DiscoveryCategory, DiscoveryMutability};

use super::{
    TogglePlanInput, ToggleResult, apply_claude_all_project_mcp_servers_toggle,
    apply_claude_configured_mcp_toggle, apply_claude_plugin_config_toggle,
    apply_codex_configured_mcp_toggle, apply_codex_plugin_toggle, apply_codex_skill_toggle,
    apply_directory_toggle, apply_json_configured_mcp_toggle, apply_opencode_configured_mcp_toggle,
    apply_opencode_plugin_config_toggle, apply_path_file_toggle, apply_pi_package_extension_toggle,
    apply_zed_configured_mcp_toggle, blocked, is_supported_claude_all_project_mcp_servers,
    is_supported_claude_configured_mcp, is_supported_claude_global_configured_mcp,
    is_supported_claude_local_configured_mcp, is_supported_claude_plugin_config,
    is_supported_codex_configured_mcp, is_supported_codex_plugin,
    is_supported_cursor_configured_mcp, is_supported_cursor_local_plugin,
    is_supported_opencode_configured_mcp, is_supported_opencode_plugin_config,
    is_supported_pi_file_skill, is_supported_pi_package_extension, is_supported_zed_configured_mcp,
    plan_claude_all_project_mcp_servers_toggle, plan_claude_configured_mcp_toggle,
    plan_claude_plugin_config_toggle, plan_codex_configured_mcp_toggle, plan_codex_plugin_toggle,
    plan_codex_skill_toggle, plan_directory_toggle, plan_json_configured_mcp_toggle,
    plan_opencode_configured_mcp_toggle, plan_opencode_plugin_config_toggle, plan_path_file_toggle,
    plan_pi_package_extension_toggle, plan_zed_configured_mcp_toggle,
};

pub(super) fn plan_toggle_dispatch(input: TogglePlanInput) -> ToggleResult {
    if input.item.mutability != DiscoveryMutability::ReadWrite {
        return blocked(input.item, "read-only item cannot be planned for toggle");
    }

    if input.apply && input.backup_authentication_key.is_none() {
        return blocked(
            input.item,
            "backup authentication key is required before apply",
        );
    }

    let backup_authentication_key = input.backup_authentication_key.as_ref();

    if input.item.uses_codex_skill_config_state() {
        if input.apply {
            return apply_codex_skill_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_codex_skill_toggle(input.item);
    }

    if is_supported_pi_file_skill(&input.item) || input.item.category == DiscoveryCategory::Agent {
        if input.apply {
            return apply_path_file_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_path_file_toggle(input.app_state_root, input.item);
    }

    if input.item.category == DiscoveryCategory::Skill
        || is_supported_cursor_local_plugin(&input.item)
    {
        if input.apply {
            return apply_directory_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_directory_toggle(input.app_state_root, input.item);
    }

    if is_supported_claude_plugin_config(&input.item) {
        if input.apply {
            return apply_claude_plugin_config_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_claude_plugin_config_toggle(input.item);
    }

    if is_supported_claude_all_project_mcp_servers(&input.item) {
        if input.apply {
            return apply_claude_all_project_mcp_servers_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_claude_all_project_mcp_servers_toggle(input.item);
    }

    if is_supported_claude_global_configured_mcp(&input.item) {
        if input.apply {
            return apply_json_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_json_configured_mcp_toggle(input.app_state_root, input.item);
    }

    if is_supported_claude_local_configured_mcp(&input.item) {
        if input.apply {
            return apply_json_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_json_configured_mcp_toggle(input.app_state_root, input.item);
    }

    if is_supported_claude_configured_mcp(&input.item) {
        if input.apply {
            return apply_claude_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_claude_configured_mcp_toggle(input.item);
    }

    if is_supported_codex_configured_mcp(&input.item) {
        if input.apply {
            return apply_codex_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_codex_configured_mcp_toggle(input.app_state_root, input.item);
    }

    if is_supported_codex_plugin(&input.item) {
        if input.apply {
            return apply_codex_plugin_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_codex_plugin_toggle(input.item);
    }

    if is_supported_pi_package_extension(&input.item) {
        if input.apply {
            return apply_pi_package_extension_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_pi_package_extension_toggle(input.app_state_root, input.item);
    }

    if is_supported_opencode_plugin_config(&input.item) {
        if input.apply {
            return apply_opencode_plugin_config_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_opencode_plugin_config_toggle(input.app_state_root, input.item);
    }

    if is_supported_cursor_configured_mcp(&input.item) {
        if input.apply {
            return apply_json_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_json_configured_mcp_toggle(input.app_state_root, input.item);
    }

    if is_supported_opencode_configured_mcp(&input.item) {
        if input.apply {
            return apply_opencode_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_opencode_configured_mcp_toggle(input.item);
    }

    if is_supported_zed_configured_mcp(&input.item) {
        if input.apply {
            return apply_zed_configured_mcp_toggle(
                input.app_state_root,
                input.item,
                backup_authentication_key.expect("apply key checked above"),
            );
        }

        return plan_zed_configured_mcp_toggle(input.app_state_root, input.item);
    }

    blocked(
        input.item.clone(),
        format!(
            "unsupported toggle planning for {}",
            input.item.category.as_str()
        ),
    )
}
