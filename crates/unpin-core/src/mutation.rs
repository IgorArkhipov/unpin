use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process,
    time::Duration,
};

use jsonc_parser::{
    CollectOptions, ParseOptions,
    ast::Value as JsoncAstValue,
    common::Ranged,
    cst::{CstInputValue, CstRootNode},
    tokens::Token as JsoncToken,
};
use rusqlite::{
    Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OpenFlags, OptionalExtension,
    TransactionBehavior, types::Value as SqliteValue,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::clock::{current_timestamp, unix_nanos_id};
use crate::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryLayer, DiscoveryMutability, ProviderId,
    claude_local_scope_token, codex_skill_config_enabled, codex_skill_config_path,
    json_value_source_fingerprint, skill_payload_has_skill, source_fingerprint,
};
use crate::encode_path_segment;
use crate::fs_support::read_optional_string;
use crate::pi_packages::{pi_disabled_package_entry, pi_package_extension_state};
use crate::sessions::SessionManager;
use crate::state::atomic_json::OwnerGeneration;
use crate::toml_syntax::{
    duplicate_standard_table_names, duplicate_top_level_key_tables,
    find_array_table_sections as find_toml_array_table_sections,
    find_table_section as find_toml_table_section, malformed_table_header_lines,
    table_subtree_content as toml_table_subtree_content,
};
use crate::transitions::{
    EffectCheckpointStatus, JournalHandle, TransitionConflictChecker, TransitionJournal,
    TransitionJournalStore, TransitionLifecycle, TransitionPlan,
    journal::{JournalError, MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES},
};
use crate::{
    approval::ControlAuthorization, control_operation::ReachAwareControlOperationEnvelopeBuilder,
};

mod restore_control;
pub use restore_control::*;

pub(crate) mod group_control;

mod toggle_control;
pub use toggle_control::*;

mod bulk_control;
pub use bulk_control::*;

mod backup_authentication;

pub use backup_authentication::BackupAuthenticationKey;
use backup_authentication::{verify_backup_authentication, write_authenticated_backup_manifest};

const CODEX_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "codex:global:configured-mcp:";
const CODEX_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "codex:project:configured-mcp:";
const CODEX_GLOBAL_PLUGIN_CONFIG_ID_PREFIX: &str = "codex:global:plugin-config:config:";
const CURSOR_GLOBAL_LOCAL_PLUGIN_ID_PREFIX: &str = "cursor:global:plugin-manifest:local:";
const CURSOR_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "cursor:global:configured-mcp:";
const CURSOR_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "cursor:project:configured-mcp:";
const ZED_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "zed:global:configured-mcp:";
const ZED_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "zed:project:configured-mcp:";
const OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "opencode:global:configured-mcp:";
const OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "opencode:project:configured-mcp:";
const OPENCODE_GLOBAL_PLUGIN_CONFIG_ID_PREFIX: &str = "opencode:global:plugin-config:npm:";
const OPENCODE_PROJECT_PLUGIN_CONFIG_ID_PREFIX: &str = "opencode:project:plugin-config:npm:";
const PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX: &str = "pi:global:plugin-config:package-extensions:";
const PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX: &str = "pi:project:plugin-config:package-extensions:";
const CLAUDE_GLOBAL_CONFIGURED_MCP_ID_PREFIX: &str = "claude:global:configured-mcp:";
const CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX: &str = "claude:project:configured-mcp:@local/";
const CLAUDE_PROJECT_CONFIGURED_MCP_ID_PREFIX: &str = "claude:project:configured-mcp:";
const CLAUDE_ALL_PROJECT_MCP_SERVERS_ID: &str =
    "claude:project:configured-mcp:all-project-mcp-servers";
const CURSOR_WORKSPACE_DISABLED_SERVERS_KEY: &str = "cursor/disabledMcpServers";
const CURSOR_WORKSPACE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const BACKUP_MANIFEST_VERSION: u8 = 3;
const BACKUP_AUTHENTICATION_ALGORITHM: &str = "hmac-sha256-unpin-backup-v1";

pub const CONTROL_PLANE_PROTECTED_REASON: &str = "control-plane-protected";

thread_local! {
    static TRANSITION_BACKUP_ID_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
    static TRANSITION_MUTATION_LOCK_ROOT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone)]
pub struct TogglePlanRequest {
    pub app_state_root: PathBuf,
    pub item: DiscoveryItem,
}

#[derive(Debug, Clone)]
pub(crate) struct TogglePlanInput {
    app_state_root: PathBuf,
    item: DiscoveryItem,
    apply: bool,
    backup_authentication_key: Option<BackupAuthenticationKey>,
    session_authority_key: Option<crate::sessions::SessionAuthorityKey>,
}

#[derive(Debug, Clone)]
pub struct RestoreBackupInput {
    pub app_state_root: PathBuf,
    pub backup_id: String,
    pub backup_authentication_key: Option<BackupAuthenticationKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToggleStatus {
    DryRun,
    Applied,
    Blocked,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreStatus {
    Restored,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToggleResult {
    pub status: ToggleStatus,
    pub selection: DiscoveryItem,
    pub target_enabled: bool,
    pub operations: Vec<MutationOperation>,
    pub affected_targets: Vec<MutationTarget>,
    pub backup_id: Option<String>,
    pub reason: Option<String>,
    pub writes: Option<String>,
    /// Reach-aware projections are additive so legacy mutation callers remain
    /// source-compatible. Native and bulk controllers always populate these
    /// fields; older direct mutation helpers leave them absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_reach: Option<crate::provider_reach::ProviderReach>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<crate::provider_reach::ProviderReachCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationOperation {
    pub operation_type: String,
    pub from_path: Option<String>,
    pub to_path: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationTarget {
    pub target_type: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub status: RestoreStatus,
    pub backup_id: String,
    pub affected_targets: Vec<MutationTarget>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub backup_id: String,
    pub created_at: String,
    pub item_count: usize,
    pub providers: Vec<String>,
    pub layers: Vec<String>,
    pub paths: Vec<String>,
    pub restorable: bool,
    pub authentication: BackupAuthenticationStatus,
    pub selection: DiscoveryItem,
    pub target_enabled: bool,
}

/// A reviewed backup deletion bound to the exact manifest bytes that were shown
/// to the user. Applying a stale plan is rejected rather than deleting a
/// backup that changed after review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDeletionPlan {
    pub backup_id: String,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDeletionResult {
    pub backup_id: String,
    pub deleted_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupAuthenticationStatus {
    Verified,
    LegacyUnauthenticated,
    KeyUnavailable,
    Failed,
}

pub fn plan_toggle(request: TogglePlanRequest) -> ToggleResult {
    plan_toggle_inner(TogglePlanInput {
        app_state_root: request.app_state_root,
        item: request.item,
        apply: false,
        backup_authentication_key: None,
        session_authority_key: None,
    })
}

#[must_use]
pub fn is_control_plane_protected_disable(item: &DiscoveryItem, target_enabled: bool) -> bool {
    if target_enabled
        || item.category != DiscoveryCategory::ConfiguredMcp
        || item.kind != crate::discovery::DiscoveryKind::Mcp
    {
        return false;
    }
    let id_name = item
        .id
        .rsplit(':')
        .next()
        .unwrap_or(item.id.as_str())
        .to_ascii_lowercase();
    let display_name = item.display_name.to_ascii_lowercase();
    id_name == "unpin" || display_name == "unpin"
}

fn plan_toggle_inner(input: TogglePlanInput) -> ToggleResult {
    let apply = input.apply;
    if input.item.mutability == DiscoveryMutability::ReadWrite
        && is_live_provider_config_state_path(&input.item)
        && let Err(reason) = ensure_provider_config_target(Path::new(&input.item.state_path))
    {
        return blocked(input.item, reason);
    }

    let result = plan_toggle_dispatch(input);
    if apply {
        result
    } else {
        validate_mutation_plan_targets(result)
    }
}

fn plan_toggle_dispatch(input: TogglePlanInput) -> ToggleResult {
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

fn is_live_provider_config_state_path(item: &DiscoveryItem) -> bool {
    !item.state_path.ends_with("entry.json")
        && !is_cursor_workspace_state_path(item)
        && (matches!(
            item.category,
            DiscoveryCategory::PluginConfig | DiscoveryCategory::ConfiguredMcp
        ) || item.uses_codex_skill_config_state())
}

fn validate_mutation_plan_targets(plan: ToggleResult) -> ToggleResult {
    match validate_mutation_plan_target_paths(&plan) {
        Ok(()) => plan,
        Err(reason) => blocked_result_from_plan(plan, reason),
    }
}

fn validate_mutation_plan_target_paths(plan: &ToggleResult) -> Result<(), String> {
    for operation in &plan.operations {
        match operation.operation_type.as_str() {
            "replaceFile" | "replaceJsonValue" => {
                let Some(path) = operation.path.as_deref().or(operation.from_path.as_deref())
                else {
                    continue;
                };
                ensure_provider_config_target(Path::new(path))?;
            }
            "renamePath" => {
                for path in [operation.from_path.as_deref(), operation.to_path.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    ensure_target_parent_has_no_symlink_components(Path::new(path))?;
                }
            }
            "replaceSqliteItemTableValue" => {
                if let Some(path) = operation.path.as_deref() {
                    ensure_target_parent_has_no_symlink_components(Path::new(path))?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn ensure_provider_config_target(path: &Path) -> Result<(), String> {
    ensure_target_parent_has_no_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "provider config path is a symlink and will not be mutated: {}",
            path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(format!(
            "provider config path is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "provider config path could not be validated: {}: {error}",
            path.display()
        )),
    }
}

fn ensure_target_parent_has_no_symlink_components(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("mutation target has no parent: {}", path.display()))?;
    let mut current = PathBuf::new();
    let mut missing_ancestor = false;
    for component in parent.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "mutation target path is not normalized: {}",
                    path.display()
                ));
            }
        }
        if missing_ancestor {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata)
                if metadata.file_type().is_symlink() && !allowed_platform_root_alias(&current) =>
            {
                return Err(format!(
                    "mutation target parent contains a symlink: {}",
                    current.display()
                ));
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {}
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "mutation target parent is not a directory: {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing_ancestor = true;
            }
            Err(error) => {
                return Err(format!(
                    "mutation target parent could not be validated: {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn allowed_platform_root_alias(path: &Path) -> bool {
    matches!(path.to_str(), Some("/etc" | "/tmp" | "/var"))
}

#[cfg(not(target_os = "macos"))]
fn allowed_platform_root_alias(_path: &Path) -> bool {
    false
}

fn write_provider_config(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    ensure_provider_config_target(path).map_err(io::Error::other)?;
    fs::write(path, contents)
}

fn rename_mutation_path(from: &Path, to: &Path) -> io::Result<()> {
    ensure_target_parent_has_no_symlink_components(from).map_err(io::Error::other)?;
    ensure_target_parent_has_no_symlink_components(to).map_err(io::Error::other)?;
    fs::rename(from, to)
}

fn apply_authorized_toggle_transaction(
    input: TogglePlanInput,
    transition: &TransitionPlan,
    authorization: &ControlAuthorization,
    reviewed_preview: &ToggleResult,
) -> ToggleResult {
    apply_authorized_toggle_transaction_with_policy(
        input,
        transition,
        authorization,
        reviewed_preview,
        crate::transitions::TransitionRecoveryPolicy::ResumeSafe,
        None,
    )
}

pub(crate) fn apply_authorized_toggle_transaction_reach_aware(
    input: TogglePlanInput,
    transition: &TransitionPlan,
    authorization: &ControlAuthorization,
    reviewed_preview: &ToggleResult,
    envelope_builder: ReachAwareControlOperationEnvelopeBuilder,
) -> ToggleResult {
    apply_authorized_toggle_transaction_with_policy(
        input,
        transition,
        authorization,
        reviewed_preview,
        crate::transitions::TransitionRecoveryPolicy::ResumeSafe,
        Some(envelope_builder),
    )
}

fn apply_authorized_toggle_transaction_with_policy(
    input: TogglePlanInput,
    transition: &TransitionPlan,
    authorization: &ControlAuthorization,
    reviewed_preview: &ToggleResult,
    recovery_policy: crate::transitions::TransitionRecoveryPolicy,
    mut reach_builder: Option<ReachAwareControlOperationEnvelopeBuilder>,
) -> ToggleResult {
    let app_state_root = input.app_state_root.clone();
    let journal_app_state_root = canonical_existing_root(&app_state_root);
    if reviewed_preview.status != ToggleStatus::DryRun {
        return blocked_result_from_plan(
            reviewed_preview.clone(),
            "reviewed native toggle preview is invalid",
        );
    }
    let backup_authentication_key = match input.backup_authentication_key.clone() {
        Some(key) => key,
        None => {
            return blocked_result_from_plan(
                reviewed_preview.clone(),
                "backup authentication key is required before apply",
            );
        }
    };
    let session_authority_key = match input.session_authority_key.clone() {
        Some(key) => key,
        None => {
            return blocked_result_from_plan(
                reviewed_preview.clone(),
                "session authority key is required before apply",
            );
        }
    };
    let reach_authority_key = session_authority_key.clone();
    let session_manager =
        SessionManager::with_authority_key(&journal_app_state_root, session_authority_key);
    let _session_conflict_guard =
        match TransitionConflictChecker::acquire(&session_manager, transition) {
            Ok(guard) => guard,
            Err(conflict) => {
                return blocked_result_from_plan(
                    reviewed_preview.clone(),
                    format!(
                        "native transition blocked by session state: {}",
                        conflict.code()
                    ),
                );
            }
        };
    let owner = match OwnerGeneration::new("native-toggle-control", 1) {
        Ok(owner) => owner,
        Err(error) => {
            return blocked_result_from_plan(reviewed_preview.clone(), error.to_string());
        }
    };
    let mutation_lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked_result_from_plan(reviewed_preview.clone(), reason),
    };
    let store = TransitionJournalStore::new(&journal_app_state_root);
    let mut existing_handle = match store.load(transition, owner.clone()) {
        Ok(handle) if handle.journal.lifecycle.is_terminal() => {
            return cached_native_toggle_result(
                &app_state_root,
                &backup_authentication_key,
                &handle.journal,
                reviewed_preview.clone(),
            );
        }
        Ok(handle) => Some(handle),
        Err(JournalError::JournalDisappeared) => None,
        Err(error) => {
            return blocked_result_from_plan(reviewed_preview.clone(), error.to_string());
        }
    };
    if recovery_policy == crate::transitions::TransitionRecoveryPolicy::NoResumeWrites
        && let Some(handle) = existing_handle.as_mut()
    {
        return mark_native_toggle_needs_repair(
            &store,
            handle,
            reviewed_preview.clone(),
            "no-resume-writes",
            "interrupted inventory group child writes are never resumed; create a fresh group plan after repair",
        );
    }
    if let Some(handle) = existing_handle.as_mut() {
        let backup_root = input
            .app_state_root
            .join("backups")
            .join(&handle.journal.backup_id);
        if backup_root.exists() {
            return mark_native_toggle_needs_repair(
                &store,
                handle,
                reviewed_preview.clone(),
                "legacy-recovery-required",
                "legacy transition backup exists without a committed checkpoint; manual recovery required",
            );
        }
    }

    let mut dry_run = plan_toggle_inner(TogglePlanInput {
        app_state_root: input.app_state_root.clone(),
        item: input.item.clone(),
        apply: false,
        backup_authentication_key: None,
        session_authority_key: None,
    });
    // Reach and coverage are reviewed-plan metadata. Reattach them to the
    // freshly derived native preview before drift comparison; native mutation
    // dispatch itself remains provider-specific and unchanged.
    dry_run.provider_reach = reviewed_preview.provider_reach;
    dry_run.coverage = reviewed_preview.coverage.clone();
    if dry_run.status != ToggleStatus::DryRun {
        if existing_handle.as_ref().is_some_and(|handle| {
            matches!(
                handle.journal.lifecycle,
                TransitionLifecycle::Applying | TransitionLifecycle::Recovering
            )
        }) {
            return mark_native_toggle_needs_repair(
                &store,
                existing_handle.as_mut().expect("checked existing journal"),
                dry_run,
                "legacy-resume-state-diverged",
                "legacy transition resumed from an interrupted apply but current provider state could not be revalidated; manual recovery required",
            );
        }
        return dry_run;
    }
    if dry_run != *reviewed_preview {
        let blocked = blocked_result_from_plan(
            dry_run,
            "reviewed native toggle preview no longer matches current state",
        );
        if existing_handle.as_ref().is_some_and(|handle| {
            matches!(
                handle.journal.lifecycle,
                TransitionLifecycle::Applying | TransitionLifecycle::Recovering
            )
        }) {
            return mark_native_toggle_needs_repair(
                &store,
                existing_handle.as_mut().expect("checked existing journal"),
                blocked,
                "legacy-resume-state-diverged",
                "legacy transition resumed from an interrupted apply but current provider state diverged from the reviewed preview; manual recovery required",
            );
        }
        return blocked;
    }
    let mut handle = match existing_handle {
        Some(handle) => handle,
        None => match store.create_or_attach(transition, owner.clone()) {
            Ok(handle) => handle,
            Err(error) => return blocked_result_from_plan(dry_run, error.to_string()),
        },
    };
    if handle.journal.reach_aware.is_none()
        && let Some(builder) = reach_builder.take()
        && let Err(error) =
            store.attach_reach_aware_builder(&mut handle, builder, &reach_authority_key)
    {
        return blocked_result_from_plan(dry_run, error.to_string());
    }
    if handle.journal.lifecycle.is_terminal() {
        return cached_native_toggle_result(
            &app_state_root,
            &backup_authentication_key,
            &handle.journal,
            dry_run,
        );
    }
    match store.blocking_operation_for(transition) {
        Ok(Some(operation_id)) => {
            return blocked_result_from_plan(
                dry_run,
                format!(
                    "recovery-required: overlapping transition requires recovery: {operation_id}"
                ),
            );
        }
        Ok(None) => {}
        Err(error) => return blocked_result_from_plan(dry_run, error.to_string()),
    }

    let backup_id = handle.journal.backup_id.clone();
    let backup_root = input.app_state_root.join("backups").join(&backup_id);
    if backup_root.exists() {
        return mark_native_toggle_needs_repair(
            &store,
            &mut handle,
            dry_run,
            "legacy-recovery-required",
            "legacy transition backup exists without a committed checkpoint; manual recovery required",
        );
    }
    let decision_digest = authorization.decision_digest();
    match handle.journal.authorization_decision_digest.clone() {
        Some(existing) if existing != decision_digest => {
            let refreshable = matches!(
                handle.journal.lifecycle,
                TransitionLifecycle::Approved
                    | TransitionLifecycle::Locked
                    | TransitionLifecycle::Applying
                    | TransitionLifecycle::Recovering
            ) && handle
                .journal
                .effects
                .iter()
                .all(|effect| effect.status == EffectCheckpointStatus::Pending);
            if !refreshable {
                return blocked_result_from_plan(
                    dry_run,
                    "native toggle is bound to another approval decision",
                );
            }
            let decisions_to_append = usize::from(
                handle.journal.authorization_decision_history.last() != Some(&existing),
            ) + 1;
            if handle
                .journal
                .authorization_decision_history
                .len()
                .saturating_add(decisions_to_append)
                > MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES
            {
                return mark_native_toggle_needs_repair(
                    &store,
                    &mut handle,
                    dry_run,
                    "approval-refresh-limit",
                    "native toggle exceeded its bounded approval refresh history; manual recovery required",
                );
            }
            if handle.journal.authorization_decision_history.last() != Some(&existing) {
                handle.journal.authorization_decision_history.push(existing);
            }
            handle
                .journal
                .authorization_decision_history
                .push(decision_digest.to_string());
            handle.journal.authorization_decision_digest = Some(decision_digest.to_string());
            let lifecycle = handle.journal.lifecycle;
            if let Err(error) = handle
                .journal
                .record(lifecycle, "approval-refreshed", None)
                .and_then(|()| store.save(&mut handle))
            {
                return blocked_result_from_plan(dry_run, error.to_string());
            }
        }
        Some(_) => {}
        None => {
            handle.journal.authorization_decision_digest = Some(decision_digest.to_string());
            handle
                .journal
                .authorization_decision_history
                .push(decision_digest.to_string());
            if let Err(error) = handle
                .journal
                .record(TransitionLifecycle::Approved, "approval-recorded", None)
                .and_then(|()| {
                    handle.journal.record(
                        TransitionLifecycle::Locked,
                        "legacy-mutation-lock-delegated",
                        None,
                    )
                })
                .and_then(|()| store.save(&mut handle))
            {
                return blocked_result_from_plan(dry_run, error.to_string());
            }
        }
    }

    let revalidated = validate_mutation_plan_targets(dry_run.clone());
    if revalidated.status == ToggleStatus::Blocked {
        if matches!(
            handle.journal.lifecycle,
            TransitionLifecycle::Applying | TransitionLifecycle::Recovering
        ) {
            return mark_native_toggle_needs_repair(
                &store,
                &mut handle,
                revalidated,
                "legacy-resume-state-diverged",
                "legacy transition resumed from an interrupted apply but its mutation targets could not be revalidated; manual recovery required",
            );
        }
        return revalidated;
    }

    let retrying_prewrite_attempt = matches!(
        handle.journal.lifecycle,
        TransitionLifecycle::Applying | TransitionLifecycle::Recovering
    ) && handle
        .journal
        .effects
        .iter()
        .all(|effect| effect.status == EffectCheckpointStatus::Pending);
    if !retrying_prewrite_attempt
        && let Err(error) = handle
            .journal
            .record(
                TransitionLifecycle::Applying,
                "legacy-apply-started",
                Some("native-toggle-effect"),
            )
            .and_then(|()| store.save(&mut handle))
    {
        return blocked_result_from_plan(dry_run, error.to_string());
    }

    let applied = with_transition_mutation_lock(&app_state_root, &mutation_lock, || {
        with_transition_backup_id(&backup_id, || plan_toggle_inner(input))
    });
    if applied.status != ToggleStatus::Applied {
        if backup_root.exists() {
            let reason = applied
                .reason
                .clone()
                .unwrap_or_else(|| "native toggle apply failed after backup".to_string());
            return mark_native_toggle_needs_repair(
                &store,
                &mut handle,
                applied,
                "legacy-apply-needs-repair",
                reason,
            );
        }
        if handle.journal.lifecycle != TransitionLifecycle::Recovering {
            let _ = handle.journal.record(
                TransitionLifecycle::Recovering,
                "legacy-apply-blocked",
                Some("native-toggle-effect"),
            );
            let _ = store.save(&mut handle);
        }
        return applied;
    }
    if applied.backup_id.as_deref() != Some(backup_id.as_str()) {
        return mark_native_toggle_needs_repair(
            &store,
            &mut handle,
            applied,
            "unexpected-backup-id",
            "legacy mutation returned an unexpected aggregate backup id",
        );
    }
    let manifest = match (|| -> Result<BackupManifest, String> {
        let mut manifest = load_backup_manifest(
            &app_state_root,
            &backup_id,
            Some(&backup_authentication_key),
        )?;
        let post_state_fingerprint = native_toggle_post_state_fingerprint(&manifest)?;
        manifest
            .authenticity
            .as_mut()
            .ok_or_else(|| "backup authenticity is missing".to_string())?
            .post_state_fingerprint = Some(post_state_fingerprint);
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            &backup_authentication_key,
        )
        .map_err(|error| error.to_string())?;
        Ok(manifest)
    })() {
        Ok(manifest) => manifest,
        Err(reason) => {
            return mark_native_toggle_needs_repair(
                &store,
                &mut handle,
                applied,
                "post-state-evidence-failed",
                format!("native toggle post-state evidence failed: {reason}"),
            );
        }
    };
    let manifest_digest = match serde_json::to_vec(&manifest) {
        Ok(bytes) => transition_digest(&bytes),
        Err(error) => {
            return mark_native_toggle_needs_repair(
                &store,
                &mut handle,
                applied,
                "manifest-evidence-failed",
                error.to_string(),
            );
        }
    };
    handle.journal.backup_manifest_digest = Some(manifest_digest);
    handle.journal.effects[0].status = EffectCheckpointStatus::BackedUp;
    let checkpoint_result = handle
        .journal
        .record(
            TransitionLifecycle::BackedUp,
            "legacy-backup-authenticated",
            None,
        )
        .and_then(|()| {
            handle.journal.record(
                TransitionLifecycle::Applying,
                "legacy-effect-applied",
                Some("native-toggle-effect"),
            )
        })
        .and_then(|()| {
            handle.journal.effects[0].status = EffectCheckpointStatus::Applied;
            handle.journal.terminal_code = Some("committed".to_string());
            handle
                .journal
                .record(TransitionLifecycle::Committed, "committed", None)
        })
        .and_then(|()| store.save(&mut handle));
    if let Err(error) = checkpoint_result {
        return recover_native_toggle_checkpoint_failure(
            &store,
            transition,
            owner,
            &app_state_root,
            &backup_authentication_key,
            applied,
            error.to_string(),
        );
    }
    applied
}

#[allow(clippy::too_many_arguments)]
fn recover_native_toggle_checkpoint_failure(
    store: &TransitionJournalStore,
    transition: &TransitionPlan,
    owner: OwnerGeneration,
    app_state_root: &Path,
    backup_authentication_key: &BackupAuthenticationKey,
    applied: ToggleResult,
    checkpoint_error: String,
) -> ToggleResult {
    let reason = format!(
        "mutation was applied but its transition journal checkpoint failed: {checkpoint_error}"
    );
    let mut durable = match store.load(transition, owner) {
        Ok(durable) => durable,
        Err(reload_error) => {
            return native_toggle_recovery_after_possible_write(
                applied,
                format!("{reason}; durable journal reload failed: {reload_error}"),
            );
        }
    };
    match durable.journal.lifecycle {
        TransitionLifecycle::Committed => {
            let verified = cached_native_toggle_result(
                app_state_root,
                backup_authentication_key,
                &durable.journal,
                applied.clone(),
            );
            if verified.status != ToggleStatus::Applied {
                return with_possible_write_disclosure(verified);
            }
            let mut applied = applied;
            applied.writes = Some(
                "writes were performed; committed checkpoint was verified after durability uncertainty"
                    .to_string(),
            );
            applied
        }
        TransitionLifecycle::NeedsRepair => cached_native_toggle_result(
            app_state_root,
            backup_authentication_key,
            &durable.journal,
            applied,
        ),
        TransitionLifecycle::RolledBack => native_toggle_recovery_after_possible_write(
            applied,
            format!("{reason}; durable journal unexpectedly rolled back"),
        ),
        _ => mark_native_toggle_needs_repair(
            store,
            &mut durable,
            applied,
            "legacy-checkpoint-failed",
            reason,
        ),
    }
}

fn mark_native_toggle_needs_repair(
    store: &TransitionJournalStore,
    handle: &mut JournalHandle,
    mut result: ToggleResult,
    code: &str,
    reason: impl Into<String>,
) -> ToggleResult {
    handle.journal.terminal_code = Some(code.to_string());
    let journal_result = handle
        .journal
        .record(
            TransitionLifecycle::NeedsRepair,
            code,
            Some("native-toggle-effect"),
        )
        .and_then(|()| store.save(handle));
    let mut reason = reason.into();
    if let Err(error) = journal_result {
        reason.push_str(&format!("; recovery journal update failed: {error}"));
    }
    if result.backup_id.is_none() {
        result.backup_id = Some(handle.journal.backup_id.clone());
    }
    native_toggle_recovery_after_possible_write(result, reason)
}

fn native_toggle_recovery_after_possible_write(
    result: ToggleResult,
    reason: impl Into<String>,
) -> ToggleResult {
    with_possible_write_disclosure(native_toggle_recovery_required(result, reason))
}

fn with_possible_write_disclosure(mut result: ToggleResult) -> ToggleResult {
    result.writes =
        Some("writes may already have been performed; manual recovery is required".to_string());
    result
}

#[cfg(test)]
mod checkpoint_recovery_tests {
    use super::*;
    use crate::transitions::{
        EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionKind,
    };

    fn test_transition(operation_id: &str) -> TransitionPlan {
        TransitionPlan::new(
            operation_id,
            TransitionKind::NativeToggle,
            TransitionContext {
                repository_key: "repository".to_string(),
                workspace_key: "workspace".to_string(),
                session_id: None,
                profile_digest: None,
            },
            vec![TransitionEffect {
                effect_id: "native-toggle-effect".to_string(),
                kind: TransitionEffectKind::ReplaceProviderConfig,
                resource_id: format!("native-resource-{operation_id}"),
                target_type: "native-provider-state".to_string(),
                summary: "Test native checkpoint recovery".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::RestartRequired,
                expected_pre_fingerprint: Some("a".repeat(64)),
                expected_post_fingerprint: Some("b".repeat(64)),
                provider_views: vec![ProviderId::Claude],
            }],
        )
        .expect("native transition")
    }

    fn applied_result(root: &Path, backup_id: String) -> ToggleResult {
        ToggleResult {
            status: ToggleStatus::Applied,
            selection: DiscoveryItem {
                provider: ProviderId::Claude,
                kind: crate::discovery::DiscoveryKind::Skill,
                category: DiscoveryCategory::Skill,
                layer: DiscoveryLayer::Project,
                id: "claude:project:skill:test".to_string(),
                display_name: "test".to_string(),
                enabled: true,
                mutability: DiscoveryMutability::ReadWrite,
                source_path: root.join("SKILL.md").to_string_lossy().into_owned(),
                state_path: root.join("skill").to_string_lossy().into_owned(),
                source_fingerprint: None,
                hook: None,
            },
            target_enabled: false,
            operations: Vec::new(),
            affected_targets: Vec::new(),
            backup_id: Some(backup_id),
            reason: None,
            writes: Some("writes were performed".to_string()),
            provider_reach: None,
            coverage: None,
        }
    }

    #[test]
    fn checkpoint_failure_reloads_durable_journal_and_marks_needs_repair() {
        let temp = tempfile::TempDir::new().expect("temporary mutation state");
        let root = fs::canonicalize(temp.path()).expect("canonical mutation state");
        let transition = test_transition("native-toggle-checkpoint-failure");
        let owner = OwnerGeneration::new("native-toggle-control", 1).expect("journal owner");
        let store = TransitionJournalStore::new(&root);
        let mut handle = store
            .create_or_attach(&transition, owner.clone())
            .expect("transition journal");
        handle
            .journal
            .record(
                TransitionLifecycle::Applying,
                "legacy-apply-started",
                Some("native-toggle-effect"),
            )
            .expect("applying checkpoint");
        store.save(&mut handle).expect("save applying journal");
        let applied = applied_result(&root, handle.journal.backup_id.clone());

        let result = recover_native_toggle_checkpoint_failure(
            &store,
            &transition,
            owner.clone(),
            &root,
            &BackupAuthenticationKey::new([0x42; 32]),
            applied,
            "injected checkpoint failure".to_string(),
        );

        assert_eq!(result.status, ToggleStatus::RecoveryRequired);
        assert_eq!(
            result.backup_id.as_deref(),
            Some(handle.journal.backup_id.as_str())
        );
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("recovery-required:"))
        );
        let recovered = store
            .load(&transition, owner)
            .expect("recovered transition journal");
        assert_eq!(
            recovered.journal.lifecycle,
            TransitionLifecycle::NeedsRepair
        );
        assert_eq!(
            recovered.journal.terminal_code.as_deref(),
            Some("legacy-checkpoint-failed")
        );
    }

    #[test]
    fn committed_checkpoint_divergence_preserves_partial_write_disclosure() {
        let temp = tempfile::TempDir::new().expect("temporary mutation state");
        let root = fs::canonicalize(temp.path()).expect("canonical mutation state");
        let transition = test_transition("native-toggle-committed-checkpoint-divergence");
        let owner = OwnerGeneration::new("native-toggle-control", 1).expect("journal owner");
        let store = TransitionJournalStore::new(&root);
        let mut handle = store
            .create_or_attach(&transition, owner.clone())
            .expect("transition journal");
        handle.journal.terminal_code = Some("committed".to_string());
        handle
            .journal
            .record(TransitionLifecycle::Committed, "committed", None)
            .expect("committed checkpoint");
        store.save(&mut handle).expect("save committed journal");
        let applied = applied_result(&root, handle.journal.backup_id.clone());

        let result = recover_native_toggle_checkpoint_failure(
            &store,
            &transition,
            owner,
            &root,
            &BackupAuthenticationKey::new([0x42; 32]),
            applied,
            "injected checkpoint uncertainty".to_string(),
        );

        assert_eq!(result.status, ToggleStatus::RecoveryRequired);
        assert_eq!(
            result.backup_id.as_deref(),
            Some(handle.journal.backup_id.as_str())
        );
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("recovery-required:"))
        );
        assert_eq!(
            result.writes.as_deref(),
            Some("writes may already have been performed; manual recovery is required")
        );
    }
}

fn cached_native_toggle_result(
    app_state_root: &Path,
    backup_authentication_key: &BackupAuthenticationKey,
    journal: &TransitionJournal,
    mut preview: ToggleResult,
) -> ToggleResult {
    preview.backup_id = Some(journal.backup_id.clone());
    match journal.lifecycle {
        TransitionLifecycle::Committed => {}
        TransitionLifecycle::NeedsRepair => {
            return native_toggle_recovery_required(
                preview,
                journal
                    .terminal_code
                    .clone()
                    .unwrap_or_else(|| "native toggle requires recovery".to_string()),
            );
        }
        _ => {
            return blocked_result_from_plan(
                preview,
                journal
                    .terminal_code
                    .clone()
                    .unwrap_or_else(|| "native toggle did not commit".to_string()),
            );
        }
    }
    let manifest = match load_backup_manifest(
        app_state_root,
        &journal.backup_id,
        Some(backup_authentication_key),
    ) {
        Ok(manifest) => manifest,
        Err(error) => {
            return native_toggle_recovery_required(
                preview,
                format!("cached native toggle backup is invalid: {error}"),
            );
        }
    };
    let expected = manifest
        .authenticity
        .as_ref()
        .and_then(|authenticity| authenticity.post_state_fingerprint.as_deref());
    let current = native_toggle_post_state_fingerprint(&manifest);
    if !matches!((expected, current), (Some(expected), Ok(current)) if expected == current) {
        return native_toggle_recovery_required(
            preview,
            "cached native toggle post-state diverged",
        );
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(journal.backup_id.clone()),
        writes: Some("operation was already committed; live post-state verified".to_string()),
        ..preview
    }
}

fn native_toggle_post_state_fingerprint(manifest: &BackupManifest) -> Result<String, String> {
    let mut observed = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let state = match entry.target.target_type.as_str() {
            "path" => match fs::symlink_metadata(&entry.target.path) {
                Ok(_) => {
                    backup_authentication::digest_backup_payload(Path::new(&entry.target.path))
                        .map_err(|error| error.to_string())?
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".to_string(),
                Err(error) => return Err(error.to_string()),
            },
            "sqlite-item" => match fs::symlink_metadata(&entry.target.path) {
                Ok(_) => read_cursor_workspace_disabled_server_ids_raw_optional(Path::new(
                    &entry.target.path,
                ))?
                .map_or_else(
                    || "absent".to_string(),
                    |bytes| format!("sha256:{}", transition_digest(&bytes)),
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".to_string(),
                Err(error) => return Err(error.to_string()),
            },
            target_type => return Err(format!("unsupported mutation target type: {target_type}")),
        };
        observed.push((
            entry.entry_id.clone(),
            entry.target.target_type.clone(),
            entry.target.path.clone(),
            state,
        ));
    }
    observed.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded = serde_json::to_vec(&observed).map_err(|error| error.to_string())?;
    Ok(transition_digest(&encoded))
}

fn native_toggle_recovery_required(
    mut preview: ToggleResult,
    reason: impl Into<String>,
) -> ToggleResult {
    preview.status = ToggleStatus::RecoveryRequired;
    preview.reason = Some(format!("recovery-required: {}", reason.into()));
    preview.writes =
        Some("writes may already have been performed; manual recovery is required".to_string());
    preview
}

fn blocked_result_from_plan(mut plan: ToggleResult, reason: impl Into<String>) -> ToggleResult {
    plan.status = ToggleStatus::Blocked;
    plan.reason = Some(reason.into());
    plan.writes = Some("no additional writes were performed".to_string());
    plan
}

fn canonical_existing_root(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    let mut missing = Vec::new();
    let mut current = path;
    while let Some(name) = current.file_name() {
        missing.push(name.to_os_string());
        let Some(parent) = current.parent() else {
            break;
        };
        if let Ok(mut canonical) = fs::canonicalize(parent) {
            for component in missing.iter().rev() {
                canonical.push(component);
            }
            return canonical;
        }
        current = parent;
    }
    path.to_path_buf()
}

fn transition_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn with_transition_backup_id<T>(backup_id: &str, operation: impl FnOnce() -> T) -> T {
    struct ResetBackupId(Option<String>);
    impl Drop for ResetBackupId {
        fn drop(&mut self) {
            let previous = self.0.take();
            TRANSITION_BACKUP_ID_OVERRIDE.with(|slot| *slot.borrow_mut() = previous);
        }
    }

    let previous = TRANSITION_BACKUP_ID_OVERRIDE.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.replace(backup_id.to_string())
    });
    let _reset = ResetBackupId(previous);
    operation()
}

fn with_transition_mutation_lock<T>(
    app_state_root: &Path,
    lock: &MutationLock,
    operation: impl FnOnce() -> T,
) -> T {
    struct ResetMutationLockRoot(Option<PathBuf>);
    impl Drop for ResetMutationLockRoot {
        fn drop(&mut self) {
            let previous = self.0.take();
            TRANSITION_MUTATION_LOCK_ROOT.with(|slot| *slot.borrow_mut() = previous);
        }
    }

    assert!(
        lock._file.is_some(),
        "only a real mutation lock may delegate nested acquisition"
    );
    let canonical_root = canonical_existing_root(app_state_root);
    let previous = TRANSITION_MUTATION_LOCK_ROOT.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.replace(canonical_root)
    });
    let _reset = ResetMutationLockRoot(previous);
    operation()
}

fn plan_codex_skill_toggle(item: DiscoveryItem) -> ToggleResult {
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = match fs::read_to_string(&item.source_path) {
            Ok(raw) => source_fingerprint(&raw),
            Err(error) => {
                return blocked(
                    item,
                    format!("Codex skill source could not be read: {error}"),
                );
            }
        };
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item.clone(),
                format!(
                    "Codex skill source drifted for {}: discovered {discovered_fingerprint}, current {current_fingerprint}",
                    item.id
                ),
            );
        }
    }

    let config_path = PathBuf::from(&item.state_path);
    let raw = match read_optional_string(&config_path) {
        Ok(Some(raw)) => raw,
        Ok(None) => String::new(),
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {error}"));
        }
    };
    let current_enabled = match codex_skill_config_enabled(&raw, Path::new(&item.source_path)) {
        Ok(enabled) => enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Codex skill state drifted: discovered {discovered_enabled}, current {current_enabled}"
            ),
        );
    }

    let target_enabled = !item.enabled;
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in Codex skills.config. Restart Codex to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![MutationTarget {
            target_type: "statePath".to_string(),
            path: item.state_path.clone(),
        }],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_codex_skill_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_codex_skill_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let config_path = PathBuf::from(&item.state_path);
    let (config_existed, raw) = match read_optional_string(&config_path) {
        Ok(Some(raw)) => (true, raw),
        Ok(None) => (false, String::new()),
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {error}"));
        }
    };
    let rewritten = match set_codex_skill_config_enabled(
        &raw,
        Path::new(&item.source_path),
        plan.target_enabled,
    ) {
        Ok(rewritten) => rewritten,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(&backup_root)?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        let payload = if config_existed {
            fs::create_dir_all(
                backup_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&config_path, &backup_payload)?;
            Some(BackupPayload {
                storage: "path".to_string(),
                path: "entries/entry-1/payload".to_string(),
            })
        } else {
            None
        };
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: config_existed,
                path_kind: config_existed.then(|| "file".to_string()),
                payload,
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_provider_config(&config_path, rewritten)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();

    drop(lock);
    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

pub fn load_backup_summaries(app_state_root: &Path) -> Vec<BackupSummary> {
    load_backup_summaries_authenticated(app_state_root, None)
}

pub fn load_backup_summaries_authenticated(
    app_state_root: &Path,
    backup_authentication_key: Option<&BackupAuthenticationKey>,
) -> Vec<BackupSummary> {
    let backups_root = app_state_root.join("backups");
    let mut backups = Vec::new();

    let Ok(entries) = fs::read_dir(backups_root) else {
        return backups;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let backup_dir_name = entry.file_name();
        let Some(backup_dir_name) = backup_dir_name.to_str() else {
            continue;
        };

        let manifest_path = path.join("manifest.json");
        let Ok(raw) = fs::read_to_string(manifest_path) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<BackupManifest>(&raw) else {
            continue;
        };

        backups.push(backup_summary_from_manifest(
            backup_dir_name,
            &path,
            manifest,
            backup_authentication_key,
        ));
    }

    backups.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.backup_id.cmp(&right.backup_id))
    });
    backups
}

pub fn load_backup_summary_authenticated(
    app_state_root: &Path,
    backup_id: &str,
    backup_authentication_key: Option<&BackupAuthenticationKey>,
) -> Option<BackupSummary> {
    if !valid_backup_id(backup_id) {
        return None;
    }
    let backup_root = app_state_root.join("backups").join(backup_id);
    if !backup_root.is_dir() {
        return None;
    }
    let raw = fs::read_to_string(backup_root.join("manifest.json")).ok()?;
    let manifest = serde_json::from_str::<BackupManifest>(&raw).ok()?;
    Some(backup_summary_from_manifest(
        backup_id,
        &backup_root,
        manifest,
        backup_authentication_key,
    ))
}

/// Prepares deletion of one backup without mutating it.
pub fn plan_backup_deletion(
    app_state_root: &Path,
    backup_id: &str,
) -> Result<BackupDeletionPlan, String> {
    let raw = read_backup_deletion_manifest(app_state_root, backup_id)?;
    Ok(BackupDeletionPlan {
        backup_id: backup_id.to_string(),
        manifest_digest: transition_digest(raw.as_bytes()),
    })
}

/// Removes a backup only when its reviewed manifest is unchanged.
pub fn delete_backup(
    app_state_root: &Path,
    plan: &BackupDeletionPlan,
) -> Result<BackupDeletionResult, String> {
    let lock = acquire_mutation_lock(app_state_root)?;
    let raw = read_backup_deletion_manifest(app_state_root, &plan.backup_id)?;
    if transition_digest(raw.as_bytes()) != plan.manifest_digest {
        return Err("backup changed after deletion was planned; review it again".to_string());
    }

    let deleted_at = current_timestamp()?;
    fs::create_dir_all(app_state_root.join("audit")).map_err(|error| error.to_string())?;
    let requested = BackupDeletionAuditEntry {
        version: 1,
        event: "backup-delete-requested".to_string(),
        created_at: deleted_at.clone(),
        backup_id: plan.backup_id.clone(),
        manifest_digest: plan.manifest_digest.clone(),
    };
    append_audit_entry(app_state_root, &requested).map_err(|error| error.to_string())?;

    let backups_root = app_state_root.join("backups");
    let backup_root = backups_root.join(&plan.backup_id);
    let quarantine_root = backups_root.join(".quarantine");
    fs::create_dir_all(&quarantine_root).map_err(|error| error.to_string())?;
    validate_path_has_no_symlink_components(app_state_root, &quarantine_root)?;
    let quarantine_path = quarantine_root.join(&plan.backup_id);
    if quarantine_path.exists() {
        return Err(format!(
            "backup deletion recovery copy already exists for {}; inspect it before retrying",
            plan.backup_id
        ));
    }
    fs::rename(&backup_root, &quarantine_path).map_err(|error| error.to_string())?;
    if let Err(error) = fs::remove_dir_all(&quarantine_path) {
        let recovery = BackupDeletionAuditEntry {
            event: "backup-delete-recovery-required".to_string(),
            ..requested
        };
        let _ = append_audit_entry(app_state_root, &recovery);
        return Err(format!(
            "backup moved to deletion quarantine but cleanup failed; recovery copy was retained: {error}"
        ));
    }

    let deleted = BackupDeletionAuditEntry {
        event: "backup-deleted".to_string(),
        ..requested
    };
    append_audit_entry(app_state_root, &deleted)
        .map_err(|error| format!("backup was deleted but audit completion failed: {error}"))?;
    drop(lock);

    Ok(BackupDeletionResult {
        backup_id: plan.backup_id.clone(),
        deleted_at,
    })
}

fn read_backup_deletion_manifest(app_state_root: &Path, backup_id: &str) -> Result<String, String> {
    if !valid_backup_id(backup_id) {
        return Err(format!("invalid backup id: {backup_id}"));
    }
    let backup_root = app_state_root.join("backups").join(backup_id);
    validate_path_has_no_symlink_components(app_state_root, &backup_root)?;
    let metadata = fs::symlink_metadata(&backup_root).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "backup directory must be a regular directory: {}",
            backup_root.display()
        ));
    }
    if !directory_tree_is_plain(&backup_root).map_err(|error| error.to_string())? {
        return Err(format!(
            "backup directory contains a symlink or special file: {}",
            backup_root.display()
        ));
    }
    let manifest_path = backup_root.join("manifest.json");
    validate_path_has_no_symlink_components(app_state_root, &manifest_path)?;
    let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "backup manifest must be a regular file: {}",
            manifest_path.display()
        ));
    }
    fs::read_to_string(manifest_path).map_err(|error| error.to_string())
}

/// Establishes trust in one legacy v1 backup by authenticating its current manifest and payloads.
///
/// Callers must review or otherwise trust legacy backup contents before invoking this function.
/// Legacy backups are never authenticated automatically.
pub fn authenticate_legacy_backup(
    app_state_root: &Path,
    backup_id: &str,
    backup_authentication_key: &BackupAuthenticationKey,
) -> Result<(), String> {
    if !valid_backup_id(backup_id) {
        return Err(format!("invalid backup id: {backup_id}"));
    }
    let lock = acquire_mutation_lock(app_state_root)?;
    let backup_root = app_state_root.join("backups").join(backup_id);
    let manifest_path = backup_root.join("manifest.json");
    validate_path_has_no_symlink_components(app_state_root, &manifest_path)?;
    let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "backup manifest must be a regular file: {}",
            manifest_path.display()
        ));
    }
    let raw = fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let mut manifest: BackupManifest =
        serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    validate_backup_manifest_structure(backup_id, &manifest)?;
    if manifest.version != 1 {
        return Err("only legacy v1 backups can be authenticated".to_string());
    }
    validate_backup_payload_evidence(&backup_root, &manifest)?;
    write_authenticated_backup_manifest(&backup_root, &mut manifest, backup_authentication_key)
        .map_err(|error| error.to_string())?;
    drop(lock);
    Ok(())
}

fn backup_summary_from_manifest(
    backup_dir_name: &str,
    backup_root: &Path,
    manifest: BackupManifest,
    backup_authentication_key: Option<&BackupAuthenticationKey>,
) -> BackupSummary {
    let authentication = backup_authentication_status(
        backup_dir_name,
        backup_root,
        &manifest,
        backup_authentication_key,
    );
    let restorable = authentication == BackupAuthenticationStatus::Verified;
    let providers = vec![manifest.selection.provider.as_str().to_string()];
    let layers = vec![manifest.selection.layer.as_str().to_string()];
    let mut paths = manifest
        .affected_targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<Vec<_>>();
    paths.sort();

    BackupSummary {
        // The directory name is the trusted identity for subsequent restore and
        // deletion paths. A malformed manifest remains visible as failed but
        // can never redirect an operation to another backup directory.
        backup_id: backup_dir_name.to_string(),
        created_at: manifest.created_at,
        item_count: manifest.entries.len(),
        providers,
        layers,
        paths,
        restorable,
        authentication,
        selection: manifest.selection,
        target_enabled: manifest.target_enabled,
    }
}

fn backup_authentication_status(
    backup_dir_name: &str,
    backup_root: &Path,
    manifest: &BackupManifest,
    backup_authentication_key: Option<&BackupAuthenticationKey>,
) -> BackupAuthenticationStatus {
    if validate_backup_manifest_structure(backup_dir_name, manifest).is_err()
        || validate_backup_payload_evidence(backup_root, manifest).is_err()
    {
        return BackupAuthenticationStatus::Failed;
    }
    if manifest.version == 1 {
        return BackupAuthenticationStatus::LegacyUnauthenticated;
    }
    let Some(backup_authentication_key) = backup_authentication_key else {
        return BackupAuthenticationStatus::KeyUnavailable;
    };
    if verify_backup_authentication(backup_root, manifest, backup_authentication_key).is_ok() {
        BackupAuthenticationStatus::Verified
    } else {
        BackupAuthenticationStatus::Failed
    }
}

fn validate_backup_manifest_structure(
    backup_dir_name: &str,
    manifest: &BackupManifest,
) -> Result<(), String> {
    if !matches!(manifest.version, 1 | BACKUP_MANIFEST_VERSION) {
        return Err(format!(
            "unsupported backup manifest version: {}",
            manifest.version
        ));
    }
    match (manifest.version, &manifest.authenticity) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err("legacy backup manifest must not declare authenticity".to_string());
        }
        (BACKUP_MANIFEST_VERSION, Some(authenticity)) => {
            validate_backup_authenticity_structure(authenticity, BACKUP_AUTHENTICATION_ALGORITHM)?;
        }
        (BACKUP_MANIFEST_VERSION, None) => {
            return Err("authenticated backup manifest is missing authenticity".to_string());
        }
        _ => unreachable!("manifest version checked above"),
    }
    if !valid_backup_id(&manifest.backup_id) {
        return Err(format!("invalid backup id: {}", manifest.backup_id));
    }
    if manifest.backup_id != backup_dir_name {
        return Err(format!(
            "backup manifest id mismatch: expected {backup_dir_name}, found {}",
            manifest.backup_id
        ));
    }
    if manifest.entries.is_empty() {
        return Err("backup manifest has no entries".to_string());
    }

    let mut entry_ids = BTreeSet::new();
    for entry in &manifest.entries {
        if !valid_backup_entry_id(&entry.entry_id) {
            return Err(format!("invalid backup entry id: {}", entry.entry_id));
        }
        if !entry_ids.insert(entry.entry_id.clone()) {
            return Err(format!("duplicate backup entry id: {}", entry.entry_id));
        }
        if !Path::new(&entry.target.path).is_absolute() {
            return Err(format!(
                "backup entry {} target path must be absolute: {}",
                entry.entry_id, entry.target.path
            ));
        }
        match entry.target.target_type.as_str() {
            "path" => validate_path_backup_entry(entry)?,
            "sqlite-item" => validate_sqlite_backup_entry(entry)?,
            target_type => {
                return Err(format!(
                    "unsupported backup target type for {}: {target_type}",
                    entry.entry_id
                ));
            }
        }
    }

    Ok(())
}

fn validate_backup_authenticity_structure(
    authenticity: &BackupAuthenticity,
    expected_algorithm: &str,
) -> Result<(), String> {
    if authenticity.algorithm != expected_algorithm {
        return Err(format!(
            "unsupported backup authentication algorithm: {}",
            authenticity.algorithm
        ));
    }
    validate_prefixed_hex(&authenticity.key_id, 16, "backup authentication key id")?;
    if decode_hex(&authenticity.tag)?.len() != 32 {
        return Err("backup authentication tag must be 32 bytes".to_string());
    }

    let mut entry_ids = BTreeSet::new();
    for payload_digest in &authenticity.payload_digests {
        if !valid_backup_entry_id(&payload_digest.entry_id) {
            return Err(format!(
                "invalid authenticated backup entry id: {}",
                payload_digest.entry_id
            ));
        }
        if !entry_ids.insert(&payload_digest.entry_id) {
            return Err(format!(
                "duplicate authenticated backup entry id: {}",
                payload_digest.entry_id
            ));
        }
        validate_prefixed_hex(
            &payload_digest.digest,
            64,
            "backup payload authentication digest",
        )?;
    }
    Ok(())
}

fn validate_prefixed_hex(value: &str, hex_length: usize, description: &str) -> Result<(), String> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{description} must use sha256"))?;
    if encoded.len() != hex_length {
        return Err(format!(
            "{description} must contain {hex_length} lowercase hexadecimal characters"
        ));
    }
    decode_hex(encoded)?;
    Ok(())
}

fn validate_path_backup_entry(entry: &BackupEntry) -> Result<(), String> {
    if !entry.existed {
        return validate_absent_backup_entry(entry);
    }
    if !matches!(
        entry.path_kind.as_deref(),
        Some("directory" | "directory-symlink" | "directory-with-symlinks" | "file")
    ) {
        return Err(format!(
            "unsupported backup path kind for {}: {}",
            entry.entry_id,
            entry.path_kind.as_deref().unwrap_or("missing")
        ));
    }

    validate_backup_entry_payload(entry)
}

fn validate_sqlite_backup_entry(entry: &BackupEntry) -> Result<(), String> {
    if !entry.existed {
        return validate_absent_backup_entry(entry);
    }
    if entry.path_kind.is_some() {
        return Err(format!(
            "SQLite backup entry {} must not declare a path kind",
            entry.entry_id
        ));
    }

    validate_backup_entry_payload(entry)
}

fn validate_absent_backup_entry(entry: &BackupEntry) -> Result<(), String> {
    if entry.path_kind.is_some() || entry.payload.is_some() {
        return Err(format!(
            "absent backup entry {} must not declare path kind or payload",
            entry.entry_id
        ));
    }
    Ok(())
}

fn validate_backup_entry_payload(entry: &BackupEntry) -> Result<(), String> {
    let payload = entry
        .payload
        .as_ref()
        .ok_or_else(|| format!("backup entry {} payload is missing", entry.entry_id))?;
    if payload.storage != "path" {
        return Err(format!(
            "unsupported backup payload storage for {}: {}",
            entry.entry_id, payload.storage
        ));
    }
    backup_payload_relative_path(&payload.path)?;
    let expected_path = entry_payload_path(&entry.entry_id);
    if payload.path != expected_path {
        return Err(format!(
            "backup entry {} payload path must be {expected_path}, got {}",
            entry.entry_id, payload.path
        ));
    }

    Ok(())
}

fn validate_backup_payload_evidence(
    backup_root: &Path,
    manifest: &BackupManifest,
) -> Result<(), String> {
    validate_backup_restore_target_allowlist(backup_root, manifest)?;
    for entry in manifest.entries.iter().filter(|entry| entry.existed) {
        let payload = entry
            .payload
            .as_ref()
            .ok_or_else(|| format!("backup entry {} payload is missing", entry.entry_id))?;
        let payload_path = backup_payload_path(backup_root, payload)?;

        match (
            entry.target.target_type.as_str(),
            entry.path_kind.as_deref(),
        ) {
            ("path", Some("file")) | ("sqlite-item", None) => {
                ensure_regular_backup_file_payload(&payload_path)?;
            }
            ("path", Some("directory")) => {
                validate_directory_backup_payload(&payload_path, false)?;
            }
            ("path", Some("directory-with-symlinks")) => {
                validate_directory_backup_payload(&payload_path, true)?;
            }
            ("path", Some("directory-symlink")) => {
                ensure_backup_symlink_payload(&payload_path)?;
            }
            _ => {
                return Err(format!(
                    "backup entry {} has unsupported payload evidence",
                    entry.entry_id
                ));
            }
        }
    }

    Ok(())
}

fn validate_backup_restore_target_allowlist(
    backup_root: &Path,
    manifest: &BackupManifest,
) -> Result<(), String> {
    let backups_root = backup_root
        .parent()
        .filter(|path| path.file_name() == Some(std::ffi::OsStr::new("backups")))
        .ok_or_else(|| "backup root is outside the application backup directory".to_string())?;
    let app_state_root = backups_root
        .parent()
        .ok_or_else(|| "application state root is unavailable".to_string())?;
    let reviewed_paths = manifest
        .affected_targets
        .iter()
        .map(|target| canonical_existing_root(Path::new(&target.path)))
        .collect::<BTreeSet<_>>();
    let vault_root = vault_root_path(app_state_root, &manifest.selection);
    let mut internal_paths = ["entry.json", "payload", "payload.json"]
        .map(|name| canonical_existing_root(&vault_root.join(name)))
        .into_iter()
        .collect::<BTreeSet<_>>();
    let app_vault_root = canonical_existing_root(&app_state_root.join("vault"));
    let selection_state_path = canonical_existing_root(Path::new(&manifest.selection.state_path));
    if selection_state_path.file_name() == Some(std::ffi::OsStr::new("entry.json"))
        && selection_state_path.starts_with(&app_vault_root)
    {
        internal_paths.insert(selection_state_path);
    }

    for entry in &manifest.entries {
        let target = canonical_existing_root(Path::new(&entry.target.path));
        if !reviewed_paths.contains(&target) && !internal_paths.contains(&target) {
            return Err(format!(
                "backup entry {} target is not declared in the restore allowlist",
                entry.entry_id
            ));
        }
    }
    Ok(())
}

fn validate_directory_backup_payload(
    payload_path: &Path,
    allow_symlinks: bool,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(payload_path).map_err(|error| {
        format!(
            "backup directory payload could not be read: {}: {error}",
            payload_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "backup payload must be a directory: {}",
            payload_path.display()
        ));
    }

    for entry in fs::read_dir(payload_path).map_err(|error| {
        format!(
            "backup directory payload could not be read: {}: {error}",
            payload_path.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "backup directory payload could not be read: {}: {error}",
                payload_path.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "backup directory payload could not be read: {}: {error}",
                path.display()
            )
        })?;

        if metadata.file_type().is_symlink() {
            if !allow_symlinks {
                return Err(format!(
                    "backup directory payload contains a symlink: {}",
                    path.display()
                ));
            }
            fs::read_link(&path).map_err(|error| {
                format!(
                    "backup symlink payload could not be read: {}: {error}",
                    path.display()
                )
            })?;
        } else if metadata.is_dir() {
            validate_directory_backup_payload(&path, allow_symlinks)?;
        } else if !metadata.is_file() {
            return Err(format!(
                "backup directory payload contains a special file: {}",
                path.display()
            ));
        }
    }

    Ok(())
}

fn ensure_backup_symlink_payload(payload_path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(payload_path).map_err(|error| {
        format!(
            "backup symlink payload could not be read: {}: {error}",
            payload_path.display()
        )
    })?;
    if !metadata.file_type().is_symlink() {
        return Err(format!(
            "backup payload must be a symlink: {}",
            payload_path.display()
        ));
    }
    fs::read_link(payload_path).map_err(|error| {
        format!(
            "backup symlink payload could not be read: {}: {error}",
            payload_path.display()
        )
    })?;
    Ok(())
}

fn valid_backup_entry_id(entry_id: &str) -> bool {
    let mut chars = entry_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    entry_id.len() <= 128
        && first.is_ascii_alphanumeric()
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '-')
}

pub fn restore_backup(input: RestoreBackupInput) -> RestoreResult {
    if !valid_backup_id(&input.backup_id) {
        return restore_failed(
            input.backup_id.clone(),
            Vec::new(),
            format!("invalid backup id: {}", input.backup_id),
        );
    }

    let lock = match acquire_mutation_lock(&input.app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return restore_failed(input.backup_id, Vec::new(), reason),
    };
    restore_backup_locked(input, &lock)
}

pub(crate) fn restore_backup_locked(
    input: RestoreBackupInput,
    _lock: &MutationLock,
) -> RestoreResult {
    if !valid_backup_id(&input.backup_id) {
        return restore_failed(
            input.backup_id.clone(),
            Vec::new(),
            format!("invalid backup id: {}", input.backup_id),
        );
    }

    let manifest = match load_backup_manifest(
        &input.app_state_root,
        &input.backup_id,
        input.backup_authentication_key.as_ref(),
    ) {
        Ok(manifest) => manifest,
        Err(reason) => return restore_failed(input.backup_id, Vec::new(), reason),
    };

    let restore_result = restore_manifest_transaction(&input.app_state_root, &manifest);

    match restore_result {
        Ok(warning) => RestoreResult {
            status: RestoreStatus::Restored,
            backup_id: input.backup_id,
            affected_targets: manifest.affected_targets,
            reason: warning,
        },
        Err(reason) => restore_failed(input.backup_id, manifest.affected_targets, reason),
    }
}

fn plan_directory_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let target_enabled = !item.enabled;
    let item_noun = directory_item_noun(&item);
    let item_title = directory_item_title(&item);
    let restart_guidance = directory_item_restart_guidance(&item);
    let shared_source_guidance = directory_item_shared_source_guidance(&item);

    let (from_path, to_path, state_path, vault_path_string, summary) = if item.enabled {
        if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
            let current_fingerprint = match fs::read_to_string(&item.source_path) {
                Ok(raw) => source_fingerprint(&raw),
                Err(error) => {
                    let reason = format!(
                        "{item_noun} source could not be read: {}: {error}",
                        item.source_path
                    );
                    return blocked(item, reason);
                }
            };
            if current_fingerprint != discovered_fingerprint {
                let reason = format!(
                    "{item_title} source drifted for {}: discovered {discovered_fingerprint}, current {current_fingerprint}",
                    item.id
                );
                return blocked(item, reason);
            }
        }
        if let Err(reason) =
            validate_cursor_local_plugin_directory(&item, Path::new(&item.state_path))
        {
            return blocked(item, reason);
        }

        let state_path = item.state_path.clone();
        let vault_path_string = path_string(vault_path(&app_state_root, &item));
        let summary = format!(
            "Disable {} by moving its directory into the Unpin vault.{shared_source_guidance}{restart_guidance}",
            item.id,
        );
        (
            state_path.clone(),
            vault_path_string.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    } else {
        let vault_entry = match load_directory_vault_entry(&app_state_root, &item) {
            Ok(vault_entry) => vault_entry,
            Err(reason) => return blocked(item, reason),
        };
        let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
        if !directory_toggle_payload_is_available(
            &item,
            &vault_payload,
            Path::new(&vault_entry.original_path),
        ) {
            return blocked(
                item,
                format!(
                    "vaulted {item_noun} directory not found: {}",
                    vault_payload.display()
                ),
            );
        }
        if let Err(reason) = validate_cursor_local_plugin_directory(&item, &vault_payload) {
            return blocked(item, reason);
        }
        let restore_target = PathBuf::from(&vault_entry.original_path);
        if restore_target.exists() {
            return blocked(
                item,
                format!(
                    "restore target already exists: {}",
                    restore_target.display()
                ),
            );
        }
        let state_path = vault_entry.original_path.clone();
        let vault_path_string = vault_entry.vaulted_path.clone();
        let summary = format!(
            "Enable {} by moving its directory out of the Unpin vault.{shared_source_guidance}{restart_guidance}",
            item.id,
        );
        (
            vault_path_string.clone(),
            state_path.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "renamePath".to_string(),
            from_path: Some(from_path.clone()),
            to_path: Some(to_path.clone()),
            summary,
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_path_string,
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_directory_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_directory_toggle(app_state_root, item, backup_authentication_key);
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_directory_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let source_path = PathBuf::from(&item.state_path);
    let vault_payload = vault_path(&app_state_root, &item);
    let vault_root = vault_root_path(&app_state_root, &item);

    if !source_path.is_dir() {
        let reason = format!(
            "source {} directory not found: {}",
            directory_item_noun(&item),
            item.state_path
        );
        return blocked(item, reason);
    }

    if backup_root.exists() {
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        let backup_path_kind =
            backup_directory_toggle_payload(&item, &source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some(backup_path_kind),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        rename_mutation_path(&source_path, &vault_payload)?;

        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: item.kind.as_str().to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "path".to_string(),
            jsonc_format: None,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_directory_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let item_noun = directory_item_noun(&item);
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let vault_entry = match load_directory_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_directory_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        return plan;
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let restore_target = PathBuf::from(&vault_entry.original_path);
    let vault_root = disabled_directory_vault_root(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !directory_toggle_payload_is_available(
        &item,
        &vault_payload,
        Path::new(&vault_entry.original_path),
    ) {
        return blocked(
            item,
            format!(
                "vaulted {} directory not found: {}",
                item_noun,
                vault_payload.display()
            ),
        );
    }

    if restore_target.exists() {
        return blocked(
            item,
            format!(
                "restore target already exists: {}",
                restore_target.display()
            ),
        );
    }

    if backup_root.exists() {
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        let backup_vault_path_kind =
            backup_directory_toggle_payload(&item, &vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: false,
                    path_kind: None,
                    payload: None,
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some(backup_vault_path_kind),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if let Some(parent) = restore_target.parent() {
            fs::create_dir_all(parent)?;
        }
        rename_mutation_path(&vault_payload, &restore_target)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_path_file_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let noun = path_file_item_noun(&item);
    let title = path_file_item_title(&item);
    let target_enabled = !item.enabled;

    let (from_path, to_path, state_path, vault_path_string, summary) = if item.enabled {
        if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
            let current_fingerprint = match fs::read_to_string(&item.source_path) {
                Ok(raw) => source_fingerprint(&raw),
                Err(error) => {
                    let reason = format!(
                        "{noun} source could not be read: {}: {error}",
                        item.source_path
                    );
                    return blocked(item, reason);
                }
            };
            if current_fingerprint != discovered_fingerprint {
                let reason = format!(
                    "{title} source drifted for {}: discovered {discovered_fingerprint}, current {current_fingerprint}",
                    item.id
                );
                return blocked(item, reason);
            }
        }

        let state_path = item.state_path.clone();
        let vault_path_string = path_string(vault_path(&app_state_root, &item));
        let summary = format!(
            "Disable {} by moving its {noun} file into the Unpin vault.",
            item.id
        );
        (
            state_path.clone(),
            vault_path_string.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    } else {
        let vault_entry = match load_path_file_vault_entry(&app_state_root, &item) {
            Ok(vault_entry) => vault_entry,
            Err(reason) => return blocked(item, reason),
        };
        let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
        if !vault_payload.is_file() {
            return blocked(
                item,
                format!("vaulted {noun} file not found: {}", vault_payload.display()),
            );
        }
        let restore_target = PathBuf::from(&vault_entry.original_path);
        if restore_target.exists() {
            return blocked(
                item,
                format!(
                    "restore target already exists: {}",
                    restore_target.display()
                ),
            );
        }
        let state_path = vault_entry.original_path.clone();
        let vault_path_string = vault_entry.vaulted_path.clone();
        let summary = format!(
            "Enable {} by moving its {noun} file out of the Unpin vault.",
            item.id
        );
        (
            vault_path_string.clone(),
            state_path.clone(),
            state_path,
            vault_path_string,
            summary,
        )
    };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "renamePath".to_string(),
            from_path: Some(from_path),
            to_path: Some(to_path),
            summary,
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_path_string,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root_path(&app_state_root, &item).join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_path_file_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_path_file_toggle(app_state_root, item, backup_authentication_key);
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_path_file_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let source_path = PathBuf::from(&item.state_path);
    let vault_payload = vault_path(&app_state_root, &item);
    let vault_root = vault_root_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!(
            "source {} file not found: {}",
            path_file_item_noun(&item),
            item.state_path
        );
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        rename_mutation_path(&source_path, &vault_payload)?;

        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: item.kind.as_str().to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "path".to_string(),
            jsonc_format: None,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_path_file_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let vault_entry = match load_path_file_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_path_file_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        return plan;
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let restore_target = PathBuf::from(&vault_entry.original_path);
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !vault_payload.is_file() {
        let noun = path_file_item_noun(&item);
        return blocked(
            item,
            format!(
                "vaulted {} file not found: {}",
                noun,
                vault_payload.display()
            ),
        );
    }

    if restore_target.exists() {
        return blocked(
            item,
            format!(
                "restore target already exists: {}",
                restore_target.display()
            ),
        );
    }

    if backup_root.exists() {
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: false,
                    path_kind: None,
                    payload: None,
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if let Some(parent) = restore_target.parent() {
            fs::create_dir_all(parent)?;
        }
        rename_mutation_path(&vault_payload, &restore_target)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_claude_plugin_config_toggle(item: DiscoveryItem) -> ToggleResult {
    let plugin_id = match claude_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id,
        None => return blocked(item, "invalid Claude plugin config item id"),
    };
    let target_enabled = !item.enabled;
    let state_path = item.state_path.clone();
    let current_enabled = match read_claude_enabled_plugin(Path::new(&state_path), &plugin_id) {
        Ok(current_enabled) => current_enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude plugin state drifted for enabledPlugins.{plugin_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceJsonValue".to_string(),
            from_path: Some(state_path.clone()),
            to_path: None,
            summary: format!("Set enabledPlugins.{plugin_id} to {target_enabled}."),
            path: Some(state_path.clone()),
            json_path: Some(vec!["enabledPlugins".to_string(), plugin_id.clone()]),
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("enabledPlugins.{plugin_id}"),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_claude_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plugin_id = match claude_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id,
        None => {
            drop(lock);
            return blocked(item, "invalid Claude plugin config item id");
        }
    };
    let plan = plan_claude_plugin_config_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = set_claude_enabled_plugin(&mut document, &plugin_id, plan.target_enabled) {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Claude settings file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_claude_all_project_mcp_servers_toggle(item: DiscoveryItem) -> ToggleResult {
    let target_enabled = !item.enabled;
    let state_path = item.state_path.clone();
    let current_enabled = match read_claude_all_project_mcp_servers(Path::new(&state_path)) {
        Ok(current_enabled) => current_enabled,
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude all-project MCP state drifted: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceJsonValue".to_string(),
            from_path: Some(state_path.clone()),
            to_path: None,
            summary: format!("Set enableAllProjectMcpServers to {target_enabled}."),
            path: Some(state_path.clone()),
            json_path: Some(vec!["enableAllProjectMcpServers".to_string()]),
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: state_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: "enableAllProjectMcpServers".to_string(),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_claude_all_project_mcp_servers_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_claude_all_project_mcp_servers_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = set_claude_all_project_mcp_servers(&mut document, plan.target_enabled) {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Claude settings file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_claude_configured_mcp_toggle(item: DiscoveryItem) -> ToggleResult {
    let server_id = match claude_project_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Claude configured MCP item id"),
    };
    let settings_path = item.state_path.clone();
    let mcp_path = item.source_path.clone();
    let mcp_document = match read_json_value(Path::new(&mcp_path)) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };
    let payload = match claude_mcp_server_value(&mcp_document, &server_id) {
        Ok(payload) => payload,
        Err(reason) => return blocked(item, reason),
    };

    let current_enabled =
        match read_claude_configured_mcp_enabled(Path::new(&settings_path), &server_id) {
            Ok(current_enabled) => current_enabled,
            Err(reason) => return blocked(item, reason),
        };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Claude configured MCP state drifted for {server_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&payload);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "Claude configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;
    let action = if target_enabled { "Enable" } else { "Disable" };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(settings_path.clone()),
            to_path: None,
            summary: format!(
                "{action} Claude configured MCP {server_id} by rewriting project approval maps."
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: settings_path,
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("enabledMcpjsonServers.{server_id}"),
            },
            MutationTarget {
                target_type: "jsonPath".to_string(),
                path: format!("disabledMcpjsonServers.{server_id}"),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_claude_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match claude_project_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Claude configured MCP item id");
        }
    };
    let plan = plan_claude_configured_mcp_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let mcp_document = match read_json_value(Path::new(&item.source_path)) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let payload = match claude_mcp_server_value(&mcp_document, &server_id) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) =
        set_claude_configured_mcp_approval(&mut document, &server_id, payload, plan.target_enabled)
    {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Claude settings file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_codex_configured_mcp_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Codex configured MCP item id"),
    };

    if item.state_path.ends_with("entry.json") {
        return plan_disabled_codex_configured_mcp_toggle(app_state_root, item, &server_id);
    }

    plan_codex_toml_table_toggle(
        item,
        "mcp_servers",
        &server_id,
        "configured MCP",
        "its Codex mcp_servers section",
        false,
    )
}

fn plan_codex_plugin_toggle(item: DiscoveryItem) -> ToggleResult {
    let plugin_id = match codex_plugin_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid Codex plugin item id"),
    };

    plan_codex_toml_table_toggle(
        item,
        "plugins",
        &plugin_id,
        "plugin",
        "its Codex plugins section",
        true,
    )
}

fn plan_codex_toml_table_toggle(
    item: DiscoveryItem,
    table_prefix: &str,
    table_id: &str,
    item_description: &str,
    summary_location: &str,
    restart_required: bool,
) -> ToggleResult {
    let config_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        return blocked(item, reason);
    }

    let section = match find_toml_table_section(&raw, table_prefix, table_id) {
        Some(section) => section,
        None => {
            return blocked(
                item,
                format!("Codex {item_description} section not found: [{table_prefix}.{table_id}]"),
            );
        }
    };
    let current_enabled = match toml_table_bool(section.content, "enabled") {
        Ok(enabled) => enabled.unwrap_or(true),
        Err(reason) => return blocked(item, reason),
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "Codex {item_description} state drifted for {table_id}: discovered {}, current {current_enabled}",
                discovered_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let Some(current_content) = toml_table_subtree_content(&raw, table_prefix, table_id) else {
            return blocked(
                item,
                format!("Codex {item_description} table subtree is ambiguous for {table_id}"),
            );
        };
        let current_fingerprint = source_fingerprint(&current_content);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "Codex {item_description} source drifted for {table_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;

    let restart_guidance = if restart_required {
        " Restart Codex to load the change."
    } else {
        ""
    };

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in {summary_location}.{restart_guidance}",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![MutationTarget {
            target_type: "statePath".to_string(),
            path: item.state_path.clone(),
        }],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn plan_disabled_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let vault_entry = match load_codex_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let config_path = PathBuf::from(&vault_entry.original_path);
    let raw = match fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        return blocked(item, reason);
    }
    if find_toml_table_section(&raw, "mcp_servers", server_id).is_some() {
        return blocked(
            item,
            format!(
                "live-section-conflict: {server_id} is already present in {}",
                config_path.display()
            ),
        );
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload_raw = match fs::read_to_string(&vault_payload) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(
                item,
                format!(
                    "vault payload could not be read: {}: {error}",
                    vault_payload.display()
                ),
            );
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&payload_raw) {
        return blocked(item, format!("vault payload is ambiguous: {reason}"));
    }
    if find_toml_table_section(&payload_raw, "mcp_servers", server_id).is_none() {
        return blocked(
            item,
            format!("vault payload does not contain [mcp_servers.{server_id}]"),
        );
    }

    let vault_root = vault_root_path(&app_state_root, &item);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: true,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(vault_entry.original_path.clone()),
            to_path: Some(vault_entry.vaulted_path.clone()),
            summary: format!(
                "Enable {} by restoring its vaulted Codex mcp_servers section.",
                item.id
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: vault_entry.original_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_entry.vaulted_path,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if item.state_path.ends_with("entry.json") {
        return apply_disabled_codex_configured_mcp_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Codex configured MCP item id"),
    };

    apply_codex_toml_table_toggle(
        app_state_root,
        item,
        CodexTomlToggleSpec {
            table_prefix: "mcp_servers",
            table_id: &server_id,
            item_description: "configured MCP",
            summary_location: "its Codex mcp_servers section",
            restart_required: false,
        },
        backup_authentication_key,
    )
}

fn apply_codex_plugin_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let plugin_id = match codex_plugin_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid Codex plugin item id"),
    };

    apply_codex_toml_table_toggle(
        app_state_root,
        item,
        CodexTomlToggleSpec {
            table_prefix: "plugins",
            table_id: &plugin_id,
            item_description: "plugin",
            summary_location: "its Codex plugins section",
            restart_required: true,
        },
        backup_authentication_key,
    )
}

struct CodexTomlToggleSpec<'a> {
    table_prefix: &'a str,
    table_id: &'a str,
    item_description: &'a str,
    summary_location: &'a str,
    restart_required: bool,
}

fn apply_codex_toml_table_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    spec: CodexTomlToggleSpec<'_>,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_codex_toml_table_toggle(
        item.clone(),
        spec.table_prefix,
        spec.table_id,
        spec.item_description,
        spec.summary_location,
        spec.restart_required,
    );
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    let rewritten = match set_toml_table_bool(
        &raw,
        spec.table_prefix,
        spec.table_id,
        "enabled",
        plan.target_enabled,
    ) {
        Ok(rewritten) => rewritten,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Codex config file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rewritten)?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_codex_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match codex_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Codex configured MCP item id");
        }
    };
    let plan = plan_codex_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_codex_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(item, format!("Codex config could not be read: {}", error));
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&raw) {
        drop(lock);
        return blocked(item, reason);
    }
    if find_toml_table_section(&raw, "mcp_servers", &server_id).is_some() {
        drop(lock);
        return blocked(
            item,
            format!(
                "live-section-conflict: {server_id} is already present in {}",
                source_path.display()
            ),
        );
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload_raw = match fs::read_to_string(&vault_payload) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "vault payload could not be read: {}: {error}",
                    vault_payload.display()
                ),
            );
        }
    };
    if let Err(reason) = ensure_unique_standard_toml_tables(&payload_raw) {
        drop(lock);
        return blocked(item, format!("vault payload is ambiguous: {reason}"));
    }
    let section = match find_toml_table_section(&payload_raw, "mcp_servers", &server_id) {
        Some(section) => section,
        None => {
            drop(lock);
            return blocked(
                item,
                format!("vault payload does not contain [mcp_servers.{server_id}]"),
            );
        }
    };
    let rewritten = append_toml_table_section(&raw, section.content);

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !source_path.is_file() {
        let reason = format!("Codex config file not found: {}", source_path.display());
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-1/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rewritten)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_json_configured_mcp_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };

    if !item.enabled && item.state_path.ends_with("entry.json") {
        return plan_disabled_json_configured_mcp_vault_toggle(app_state_root, item, &server_id);
    }

    if !item.enabled && is_cursor_workspace_state_path(&item) {
        return plan_cursor_workspace_configured_mcp_toggle(item, &server_id);
    }

    let config_path = PathBuf::from(&item.state_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };

    let server_value = match configured_json_mcp_server_value(&document, &item, &server_id) {
        Ok(server_value) => server_value,
        Err(reason) => return blocked(item, reason),
    };
    let current_enabled = if item.provider == ProviderId::Cursor {
        cursor_mcp_server_enabled_from_value(&server_value)
    } else {
        true
    };
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "{provider_name} configured MCP state drifted for {server_id}: discovered {}, current {}",
                discovered_enabled, current_enabled
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&server_value);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "{provider_name} configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    if !item.enabled {
        if item.provider != ProviderId::Cursor {
            return blocked(item, "disabled JSON MCP item is missing its vault entry");
        }
        if let Err(reason) = cursor_mcp_server_disabled_flag(&document, &server_id) {
            return blocked(item, reason);
        }

        return ToggleResult {
            status: ToggleStatus::DryRun,
            selection: item.clone(),
            target_enabled: true,
            operations: vec![MutationOperation {
                operation_type: "replaceFile".to_string(),
                from_path: Some(item.state_path.clone()),
                to_path: None,
                summary: format!(
                    "Enable {} by removing its Cursor mcpServers disabled flag.",
                    item.id
                ),
                path: None,
                json_path: None,
                value: None,
            }],
            affected_targets: vec![MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            }],
            backup_id: None,
            reason: None,
            writes: Some("no writes were performed".to_string()),
            provider_reach: None,
            coverage: None,
        };
    }

    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = json_configured_mcp_vault_payload_path(&app_state_root, &item);
    let vault_payload_string = path_string(vault_payload);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: false,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: Some(vault_payload_string.clone()),
            summary: format!(
                "Disable {} by removing its {provider_name} mcpServers entry and vaulting it.",
                item.id,
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_payload_string,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn plan_disabled_json_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let provider_name = json_mcp_provider_name(item.provider);
    let vault_entry = match load_json_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let config_path = PathBuf::from(&vault_entry.original_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };
    match configured_json_mcp_server_present(&document, &item, server_id) {
        Ok(true) => {
            return blocked(
                item,
                format!(
                    "live-entry-conflict: {server_id} is already present in {}",
                    config_path.display()
                ),
            );
        }
        Ok(false) => {}
        Err(reason) => return blocked(item, reason),
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload = match read_json_value(&vault_payload) {
        Ok(payload) => payload,
        Err(reason) => return blocked(item, reason),
    };
    if !payload.is_object() {
        let reason = format!(
            "invalid-vault-payload: {} must contain a JSON object for {}",
            vault_payload.display(),
            item.id
        );
        return blocked(item, reason);
    }

    let vault_root = vault_root_path(&app_state_root, &item);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: true,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(vault_entry.original_path.clone()),
            to_path: Some(vault_entry.vaulted_path.clone()),
            summary: format!(
                "Enable {} by restoring its vaulted {provider_name} mcpServers entry.",
                item.id,
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: vault_entry.original_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_entry.vaulted_path,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn plan_cursor_workspace_configured_mcp_toggle(
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let config_path = PathBuf::from(&item.source_path);
    let document = match read_json_value(&config_path) {
        Ok(document) => document,
        Err(reason) => return blocked(item, reason),
    };

    let server_value = match configured_json_mcp_server_value(&document, &item, server_id) {
        Ok(server_value) => server_value,
        Err(reason) => return blocked(item, reason),
    };
    let workspace_path = PathBuf::from(&item.state_path);
    let disabled_server_ids = match read_cursor_workspace_disabled_server_ids(&workspace_path) {
        Ok(disabled_server_ids) => disabled_server_ids,
        Err(reason) => return blocked(item, reason),
    };
    let workspace_server_id = cursor_workspace_server_id(server_id);
    let has_workspace_disabled = disabled_server_ids
        .iter()
        .any(|server_id| server_id == &workspace_server_id);
    let has_json_disabled = server_value.get("disabled").and_then(Value::as_bool) == Some(true);

    if !has_workspace_disabled && !has_json_disabled {
        return blocked(
            item,
            format!(
                "unsupported-live-disabled-entry: {server_id} is not disabled in a writable Cursor state source"
            ),
        );
    }

    let next_disabled_server_ids = disabled_server_ids
        .into_iter()
        .filter(|server_id| server_id != &workspace_server_id)
        .collect::<Vec<_>>();
    let mut operations = Vec::new();
    let mut affected_targets = Vec::new();

    if has_json_disabled {
        operations.push(MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.source_path.clone()),
            to_path: None,
            summary: format!(
                "Enable {} by removing its Cursor mcpServers disabled flag.",
                item.id
            ),
            path: Some(item.source_path.clone()),
            json_path: None,
            value: None,
        });
        affected_targets.push(MutationTarget {
            target_type: "statePath".to_string(),
            path: item.source_path.clone(),
        });
    }

    if has_workspace_disabled {
        operations.push(MutationOperation {
            operation_type: "replaceSqliteItemTableValue".to_string(),
            from_path: None,
            to_path: None,
            summary: format!(
                "Enable {} by removing it from Cursor workspace disabled MCP state.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: None,
            value: Some(Value::Array(
                next_disabled_server_ids
                    .iter()
                    .map(|server_id| Value::String(server_id.clone()))
                    .collect(),
            )),
        });
        affected_targets.push(MutationTarget {
            target_type: "sqlite-item".to_string(),
            path: item.state_path.clone(),
        });
    }

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item,
        target_enabled: true,
        operations,
        affected_targets,
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_json_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        if item.state_path.ends_with("entry.json") {
            return apply_disabled_json_configured_mcp_vault_toggle(
                app_state_root,
                item,
                backup_authentication_key,
            );
        }
        if is_cursor_workspace_state_path(&item) {
            return apply_cursor_workspace_configured_mcp_toggle(
                app_state_root,
                item,
                backup_authentication_key,
            );
        }
        if item.provider != ProviderId::Cursor {
            return blocked(item, "disabled JSON MCP item is missing its vault entry");
        }
        return apply_cursor_configured_mcp_disabled_flag_enable(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let server_value = match remove_configured_json_mcp_server(&mut document, &item, &server_id) {
        Ok(server_value) => server_value,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = json_configured_mcp_vault_payload_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!(
            "{provider_name} MCP config file not found: {}",
            item.state_path
        );
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        write_json_file(&vault_payload, &server_value)?;

        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: vault_kind_segment(&item).to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "json-payload".to_string(),
            jsonc_format: None,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_cursor_workspace_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match cursor_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Cursor configured MCP item id");
        }
    };
    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let source_path = PathBuf::from(&item.source_path);
    let workspace_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let has_json_disabled = cursor_mcp_server_disabled_flag(&document, &server_id).is_ok();
    if has_json_disabled
        && let Err(reason) = remove_cursor_mcp_server_disabled_flag(&mut document, &server_id)
    {
        drop(lock);
        return blocked(item, reason);
    }

    let mut workspace_connection = match open_cursor_workspace_database(
        &workspace_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "begin write transaction for",
    ) {
        Ok(connection) => connection,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let workspace_transaction = match workspace_connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
    {
        Ok(transaction) => transaction,
        Err(error) => {
            let reason =
                cursor_workspace_database_error(&workspace_path, "reserve write access to", &error);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let workspace_raw = match read_cursor_workspace_disabled_server_ids_raw_from_connection(
        &workspace_transaction,
        &workspace_path,
    ) {
        Ok(Some(workspace_raw)) => workspace_raw,
        Ok(None) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(
                item,
                format!(
                    "Cursor workspace state is missing {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} in {}",
                    workspace_path.display()
                ),
            );
        }
        Err(reason) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let disabled_server_ids =
        match parse_cursor_workspace_disabled_server_ids(&workspace_path, &workspace_raw) {
            Ok(disabled_server_ids) => disabled_server_ids,
            Err(reason) => {
                drop(workspace_transaction);
                drop(lock);
                return blocked(item, reason);
            }
        };
    let workspace_server_id = cursor_workspace_server_id(&server_id);
    if !disabled_server_ids
        .iter()
        .any(|server_id| server_id == &workspace_server_id)
    {
        drop(workspace_transaction);
        drop(lock);
        return blocked(
            item,
            format!(
                "Cursor workspace state drifted for {server_id}: {workspace_server_id} is no longer disabled"
            ),
        );
    }
    let next_disabled_server_ids = disabled_server_ids
        .into_iter()
        .filter(|server_id| server_id != &workspace_server_id)
        .collect::<Vec<_>>();
    let next_workspace_raw = match serde_json::to_vec(&next_disabled_server_ids) {
        Ok(raw) => raw,
        Err(error) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, error.to_string());
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => {
            drop(workspace_transaction);
            drop(lock);
            return blocked(item, reason);
        }
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);

    if has_json_disabled && !source_path.is_file() {
        let reason = format!("Cursor mcp.json file not found: {}", source_path.display());
        drop(workspace_transaction);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(workspace_transaction);
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;

        let mut entries = Vec::new();
        let mut next_entry_id = 1usize;

        if has_json_disabled {
            let entry_id = format!("entry-{next_entry_id}");
            next_entry_id += 1;
            let backup_payload = backup_root.join("entries").join(&entry_id).join("payload");
            fs::create_dir_all(
                backup_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&source_path, &backup_payload)?;
            entries.push(BackupEntry {
                entry_id: entry_id.clone(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.source_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: entry_payload_path(&entry_id),
                }),
            });
        }

        let entry_id = format!("entry-{next_entry_id}");
        let backup_payload = backup_root.join("entries").join(&entry_id).join("payload");
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::write(&backup_payload, &workspace_raw)?;
        entries.push(BackupEntry {
            entry_id: entry_id.clone(),
            target: MutationTarget {
                target_type: "sqlite-item".to_string(),
                path: item.state_path.clone(),
            },
            existed: true,
            path_kind: None,
            payload: Some(BackupPayload {
                storage: "path".to_string(),
                path: entry_payload_path(&entry_id),
            }),
        });

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries,
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        if has_json_disabled {
            let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
            write_provider_config(&source_path, format!("{rendered}\n"))?;
        }
        write_cursor_workspace_disabled_server_ids_raw_on_connection(
            &workspace_transaction,
            &workspace_path,
            &next_workspace_raw,
        )
        .map_err(io::Error::other)?;
        workspace_transaction.commit().map_err(|error| {
            io::Error::other(cursor_workspace_database_error(
                &workspace_path,
                "commit write transaction for",
                &error,
            ))
        })?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_json_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let provider_name = json_mcp_provider_name(item.provider);
    let server_id = match json_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(
                item,
                format!("invalid {provider_name} configured MCP item id"),
            );
        }
    };
    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_json_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    match configured_json_mcp_server_present(&document, &item, &server_id) {
        Ok(true) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "live-entry-conflict: {server_id} is already present in {}",
                    source_path.display()
                ),
            );
        }
        Ok(false) => {}
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    }

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let mut payload = match read_json_value(&vault_payload) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if item.provider == ProviderId::Cursor {
        if let Err(reason) = prepare_cursor_mcp_payload(&mut payload, &server_id) {
            drop(lock);
            return blocked(item, reason);
        }
    } else if !payload.is_object() {
        drop(lock);
        return blocked(
            item,
            format!("mcpServers.{server_id} vaulted payload is not an object"),
        );
    }
    if let Err(reason) =
        insert_configured_json_mcp_server(&mut document, &item, &server_id, payload)
    {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !source_path.is_file() {
        let reason = format!(
            "{provider_name} MCP config file not found: {}",
            source_path.display()
        );
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-1/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_cursor_configured_mcp_disabled_flag_enable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_json_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let server_id = match cursor_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Cursor configured MCP item id");
        }
    };

    let source_path = PathBuf::from(&item.state_path);
    let mut document = match read_json_value(&source_path) {
        Ok(document) => document,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if let Err(reason) = remove_cursor_mcp_server_disabled_flag(&mut document, &server_id) {
        drop(lock);
        return blocked(item, reason);
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");

    if !source_path.is_file() {
        let reason = format!("Cursor mcp.json file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        let rendered = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
        write_provider_config(&source_path, format!("{rendered}\n"))?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_opencode_configured_mcp_toggle(item: DiscoveryItem) -> ToggleResult {
    let server_id = match opencode_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid OpenCode configured MCP item id"),
    };
    let config_path = PathBuf::from(&item.state_path);
    let raw = match read_jsonc_raw(&config_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    let server_value = match opencode_mcp_server_value(&raw, &server_id) {
        Ok(value) => value,
        Err(reason) => return blocked(item, reason),
    };
    let current_enabled = server_value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if current_enabled != item.enabled {
        let discovered_enabled = item.enabled;
        return blocked(
            item,
            format!(
                "OpenCode configured MCP state drifted for {server_id}: discovered {discovered_enabled}, current {current_enabled}"
            ),
        );
    }
    if let Some(discovered_fingerprint) = item.source_fingerprint.clone() {
        let current_fingerprint = json_value_source_fingerprint(&server_value);
        if current_fingerprint != discovered_fingerprint {
            return blocked(
                item,
                format!(
                    "OpenCode configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
                ),
            );
        }
    }

    let target_enabled = !item.enabled;
    if let Err(reason) = set_opencode_mcp_enabled_jsonc(&raw, &server_id, target_enabled) {
        return blocked(item, reason);
    }
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: None,
            summary: format!(
                "Set {} enabled = {target_enabled} in OpenCode mcp config. Restart OpenCode to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: Some(vec!["mcp".to_string(), server_id, "enabled".to_string()]),
            value: Some(Value::Bool(target_enabled)),
        }],
        affected_targets: vec![MutationTarget {
            target_type: "statePath".to_string(),
            path: item.state_path.clone(),
        }],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_opencode_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_configured_mcp_toggle(item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let server_id = match opencode_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode configured MCP item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match set_opencode_mcp_enabled_jsonc(&raw, &server_id, plan.target_enabled) {
        Ok(rendered) => rendered,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: plan.target_enabled,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;
        write_provider_config(&source_path, rendered)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: plan.target_enabled,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();
    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_pi_package_extension_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => return blocked(item, "invalid Pi package extension item id"),
    };
    let settings_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&settings_path) {
        Ok(raw) => raw,
        Err(error) => {
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    settings_path.display()
                ),
            );
        }
    };

    let vault = if item.enabled {
        if let Err(reason) =
            prepare_pi_package_disable(&raw, &package_source, item.source_fingerprint.as_deref())
        {
            return blocked(item, reason);
        }
        None
    } else {
        let vault = match load_optional_pi_package_vault(&app_state_root, &item, &package_source) {
            Ok(vault) => vault,
            Err(reason) => return blocked(item, reason),
        };
        if let Err(reason) = prepare_pi_package_enable(
            &raw,
            &package_source,
            item.source_fingerprint.as_deref(),
            vault.as_ref().map(|(_, payload)| payload),
        ) {
            return blocked(item, reason);
        }
        vault
    };

    let target_enabled = !item.enabled;
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    let mut affected_targets = vec![MutationTarget {
        target_type: "statePath".to_string(),
        path: item.state_path.clone(),
    }];
    if item.enabled || vault.is_some() {
        affected_targets.extend([
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: path_string(vault_payload.clone()),
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ]);
    }
    let action = if target_enabled { "Enable" } else { "Disable" };
    let summary = if target_enabled && vault.is_some() {
        format!(
            "{action} {} by restoring its Pi package extension filter while keeping the package installed. Restart Pi to load the change.",
            item.id
        )
    } else if target_enabled {
        format!(
            "{action} {} by removing its empty Pi package extension filter so all package extensions load while keeping the package installed. Restart Pi to load the change.",
            item.id
        )
    } else {
        format!(
            "{action} {} by setting packages[].extensions to an empty array while keeping the package reference and other resources. Restart Pi to load the change.",
            item.id
        )
    };
    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: (item.enabled || vault.is_some()).then(|| path_string(vault_payload)),
            summary,
            path: Some(item.state_path.clone()),
            json_path: Some(vec![
                "packages".to_string(),
                package_source,
                "extensions".to_string(),
            ]),
            value: (!target_enabled).then(|| Value::Array(Vec::new())),
        }],
        affected_targets,
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_pi_package_extension_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if item.enabled {
        apply_pi_package_extension_disable(app_state_root, item, backup_authentication_key)
    } else {
        apply_pi_package_extension_enable(app_state_root, item, backup_authentication_key)
    }
}

fn apply_pi_package_extension_disable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_pi_package_extension_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Pi package extension item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    source_path.display()
                ),
            );
        }
    };
    let rewrite =
        match prepare_pi_package_disable(&raw, &package_source, item.source_fingerprint.as_deref())
        {
            Ok(rewrite) => rewrite,
            Err(reason) => {
                drop(lock);
                return blocked(item, reason);
            }
        };
    let payload = rewrite
        .payload
        .expect("Pi disable rewrite includes vault payload");
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("Pi settings file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries/entry-1/payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }
    match fs::symlink_metadata(&vault_root) {
        Ok(_) => {
            let reason = format!("vault entry already exists: {}", vault_root.display());
            append_pre_mutation_failed_apply_audit_entry(
                &app_state_root,
                &item,
                false,
                &plan.affected_targets,
                &reason,
                &created_at,
            );
            drop(lock);
            return blocked(item, reason);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            drop(lock);
            return blocked(item, error.to_string());
        }
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        write_json_file(&vault_payload, &payload)?;
        write_json_file(
            &vault_root.join("entry.json"),
            &VaultEntry {
                version: 1,
                provider: item.provider.as_str().to_string(),
                kind: vault_kind_segment(&item).to_string(),
                layer: item.layer.as_str().to_string(),
                item_id: item.id.clone(),
                display_name: item.display_name.clone(),
                original_path: item.state_path.clone(),
                vaulted_path: path_string(vault_payload),
                payload_kind: "json-payload".to_string(),
                jsonc_format: None,
            },
        )?;
        write_provider_config(&source_path, rewrite.rendered)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();
    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_pi_package_extension_enable(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_pi_package_extension_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let package_source = match pi_package_extension_source(&item) {
        Some(source) => source.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Pi package extension item id");
        }
    };
    let vault = match load_optional_pi_package_vault(&app_state_root, &item, &package_source) {
        Ok(vault) => vault,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let raw = match fs::read_to_string(&source_path) {
        Ok(raw) => raw,
        Err(error) => {
            drop(lock);
            return blocked(
                item,
                format!(
                    "Pi settings could not be read: {}: {error}",
                    source_path.display()
                ),
            );
        }
    };
    let rewrite = match prepare_pi_package_enable(
        &raw,
        &package_source,
        item.source_fingerprint.as_deref(),
        vault.as_ref().map(|(_, payload)| payload),
    ) {
        Ok(rewrite) => rewrite,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("Pi settings file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries/entry-1/payload");
    let backup_vault_payload = backup_root.join("entries/entry-2/payload");
    let backup_vault_entry = backup_root.join("entries/entry-3/payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut entries = vec![BackupEntry {
            entry_id: "entry-1".to_string(),
            target: MutationTarget {
                target_type: "path".to_string(),
                path: item.state_path.clone(),
            },
            existed: true,
            path_kind: Some("file".to_string()),
            payload: Some(BackupPayload {
                storage: "path".to_string(),
                path: "entries/entry-1/payload".to_string(),
            }),
        }];
        if let Some((vault_entry, _)) = &vault {
            fs::create_dir_all(
                backup_vault_payload
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&vault_entry.vaulted_path, &backup_vault_payload)?;
            fs::create_dir_all(
                backup_vault_entry
                    .parent()
                    .expect("backup payload path has a parent"),
            )?;
            fs::copy(&vault_entry_path, &backup_vault_entry)?;
            entries.extend([
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ]);
        }
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries,
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rewrite.rendered)?;
        if vault.is_some() {
            fs::remove_dir_all(&vault_root)?;
        }
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();
    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
) -> ToggleResult {
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => return blocked(item, "invalid OpenCode npm plugin item id"),
    };

    if !item.enabled {
        let vault_entry = match load_opencode_plugin_config_vault_entry(&app_state_root, &item) {
            Ok(vault_entry) => vault_entry,
            Err(reason) => return blocked(item, reason),
        };
        let source_path = PathBuf::from(&vault_entry.original_path);
        let source_raw = match read_jsonc_raw(&source_path) {
            Ok(raw) => raw,
            Err(reason) => return blocked(item, reason),
        };
        let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
        let payload = match read_opencode_plugin_vault_payload(&vault_payload, &plugin_id) {
            Ok(payload) => payload,
            Err(reason) => return blocked(item, reason),
        };
        if let Err(reason) = prepare_opencode_plugin_restore(
            &source_raw,
            &plugin_id,
            &payload,
            vault_entry.jsonc_format.as_ref(),
        ) {
            return blocked(item, reason);
        }

        let vault_root = vault_root_path(&app_state_root, &item);
        return ToggleResult {
            status: ToggleStatus::DryRun,
            selection: item.clone(),
            target_enabled: true,
            operations: vec![MutationOperation {
                operation_type: "replaceFile".to_string(),
                from_path: Some(vault_entry.original_path.clone()),
                to_path: Some(vault_entry.vaulted_path.clone()),
                summary: format!(
                    "Enable {} by restoring its OpenCode plugin config reference. Restart OpenCode to load the change.",
                    item.id
                ),
                path: Some(vault_entry.original_path.clone()),
                json_path: Some(vec!["plugin".to_string()]),
                value: Some(Value::String(plugin_id)),
            }],
            affected_targets: vec![
                MutationTarget {
                    target_type: "statePath".to_string(),
                    path: vault_entry.original_path,
                },
                MutationTarget {
                    target_type: "vaultPath".to_string(),
                    path: vault_entry.vaulted_path,
                },
                MutationTarget {
                    target_type: "vaultEntry".to_string(),
                    path: path_string(vault_root.join("entry.json")),
                },
            ],
            backup_id: None,
            reason: None,
            writes: Some("no writes were performed".to_string()),
            provider_reach: None,
            coverage: None,
        };
    }

    let source_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    let original_order =
        match opencode_plugin_order_with_vaults(&app_state_root, &item, &source_raw) {
            Ok(original_order) => original_order,
            Err(reason) => return blocked(item, reason),
        };
    if let Err(reason) = prepare_opencode_plugin_removal(
        &source_raw,
        &plugin_id,
        item.source_fingerprint.as_deref(),
        original_order,
    ) {
        return blocked(item, reason);
    }
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: false,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: Some(path_string(vault_payload.clone())),
            summary: format!(
                "Disable {} by removing its OpenCode plugin config reference while retaining installed cache files. Restart OpenCode to load the change.",
                item.id
            ),
            path: Some(item.state_path.clone()),
            json_path: Some(vec!["plugin".to_string()]),
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: path_string(vault_payload),
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_opencode_plugin_config_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_plugin_config_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode npm plugin item id");
        }
    };
    let source_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let original_order =
        match opencode_plugin_order_with_vaults(&app_state_root, &item, &source_raw) {
            Ok(original_order) => original_order,
            Err(reason) => {
                drop(lock);
                return blocked(item, reason);
            }
        };
    let removal = match prepare_opencode_plugin_removal(
        &source_raw,
        &plugin_id,
        item.source_fingerprint.as_deref(),
        original_order,
    ) {
        Ok(removal) => removal,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = vault_root.join("payload.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }
    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        write_json_file(&vault_payload, &removal.payload)?;
        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: vault_kind_segment(&item).to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "json-payload".to_string(),
            jsonc_format: removal.jsonc_format,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;
        write_provider_config(&source_path, &removal.rendered)?;
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();
    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_opencode_plugin_config_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };
    let plan = plan_opencode_plugin_config_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }
    let plugin_id = match opencode_plugin_config_id(&item) {
        Some(plugin_id) => plugin_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid OpenCode npm plugin item id");
        }
    };
    let vault_entry = match load_opencode_plugin_config_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let payload = match read_opencode_plugin_vault_payload(&vault_payload, &plugin_id) {
        Ok(payload) => payload,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match prepare_opencode_plugin_restore(
        &source_raw,
        &plugin_id,
        &payload,
        vault_entry.jsonc_format.as_ref(),
    ) {
        Ok(rendered) => rendered,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    if !source_path.is_file() {
        drop(lock);
        return blocked(
            item,
            format!("OpenCode config file not found: {}", source_path.display()),
        );
    }

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");
    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-1/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, rendered)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }
        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;
        Ok(())
    })();
    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }
    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn plan_zed_configured_mcp_toggle(app_state_root: PathBuf, item: DiscoveryItem) -> ToggleResult {
    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => return blocked(item, "invalid Zed configured MCP item id"),
    };

    if !item.enabled {
        return plan_disabled_zed_configured_mcp_vault_toggle(app_state_root, item, &server_id);
    }

    let settings_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&settings_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    if let Err(reason) = prepare_zed_context_server_removal(
        &source_raw,
        &server_id,
        item.source_fingerprint.as_deref(),
    ) {
        return blocked(item, reason);
    }

    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = zed_configured_mcp_vault_payload_path(&app_state_root, &item);
    let vault_payload_string = path_string(vault_payload);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: false,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(item.state_path.clone()),
            to_path: Some(vault_payload_string.clone()),
            summary: format!(
                "Disable {} by removing its Zed context_servers entry and vaulting it.",
                item.id
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: item.state_path.clone(),
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_payload_string,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn plan_disabled_zed_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    server_id: &str,
) -> ToggleResult {
    let vault_entry = match load_zed_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => return blocked(item, reason),
    };
    let settings_path = PathBuf::from(&vault_entry.original_path);
    let source_raw = match read_jsonc_raw(&settings_path) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let vault_payload_raw = match read_jsonc_raw(&vault_payload) {
        Ok(raw) => raw,
        Err(reason) => return blocked(item, reason),
    };
    if let Err(reason) = prepare_zed_context_server_restore(
        &settings_path,
        &source_raw,
        server_id,
        &vault_payload,
        &vault_payload_raw,
        vault_entry.jsonc_format.as_ref(),
    ) {
        return blocked(item, reason);
    }

    let vault_root = vault_root_path(&app_state_root, &item);

    ToggleResult {
        status: ToggleStatus::DryRun,
        selection: item.clone(),
        target_enabled: true,
        operations: vec![MutationOperation {
            operation_type: "replaceFile".to_string(),
            from_path: Some(vault_entry.original_path.clone()),
            to_path: Some(vault_entry.vaulted_path.clone()),
            summary: format!(
                "Enable {} by restoring its vaulted Zed context_servers entry.",
                item.id
            ),
            path: None,
            json_path: None,
            value: None,
        }],
        affected_targets: vec![
            MutationTarget {
                target_type: "statePath".to_string(),
                path: vault_entry.original_path,
            },
            MutationTarget {
                target_type: "vaultPath".to_string(),
                path: vault_entry.vaulted_path,
            },
            MutationTarget {
                target_type: "vaultEntry".to_string(),
                path: path_string(vault_root.join("entry.json")),
            },
        ],
        backup_id: None,
        reason: None,
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_zed_configured_mcp_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    if !item.enabled {
        return apply_disabled_zed_configured_mcp_vault_toggle(
            app_state_root,
            item,
            backup_authentication_key,
        );
    }

    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let plan = plan_zed_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Zed configured MCP item id");
        }
    };

    let source_path = PathBuf::from(&item.state_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let removal = match prepare_zed_context_server_removal(
        &source_raw,
        &server_id,
        item.source_fingerprint.as_deref(),
    ) {
        Ok(removal) => removal,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = removal.rendered;
    let vaulted_server_raw = removal.value_raw;
    let jsonc_format = removal.format;

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_payload = zed_configured_mcp_vault_payload_path(&app_state_root, &item);

    if !source_path.is_file() {
        let reason = format!("Zed settings file not found: {}", item.state_path);
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    if vault_root.exists() {
        let reason = format!("vault entry already exists: {}", vault_root.display());
        append_pre_mutation_failed_apply_audit_entry(
            &app_state_root,
            &item,
            false,
            &plan.affected_targets,
            &reason,
            &created_at,
        );
        drop(lock);
        return blocked(item, reason);
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: false,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target: MutationTarget {
                    target_type: "path".to_string(),
                    path: item.state_path.clone(),
                },
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        fs::create_dir_all(&vault_root)?;
        fs::write(
            &vault_payload,
            format!("{}\n", vaulted_server_raw.trim_end()),
        )?;

        let entry = VaultEntry {
            version: 1,
            provider: item.provider.as_str().to_string(),
            kind: vault_kind_segment(&item).to_string(),
            layer: item.layer.as_str().to_string(),
            item_id: item.id.clone(),
            display_name: item.display_name.clone(),
            original_path: item.state_path.clone(),
            vaulted_path: path_string(vault_payload),
            payload_kind: "json-payload".to_string(),
            jsonc_format,
        };
        write_json_file(&vault_root.join("entry.json"), &entry)?;

        write_provider_config(&source_path, &rendered)?;

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: false,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn apply_disabled_zed_configured_mcp_vault_toggle(
    app_state_root: PathBuf,
    item: DiscoveryItem,
    backup_authentication_key: &BackupAuthenticationKey,
) -> ToggleResult {
    let lock = match acquire_mutation_lock(&app_state_root) {
        Ok(lock) => lock,
        Err(reason) => return blocked(item, reason),
    };

    let server_id = match zed_configured_mcp_server_id(&item) {
        Some(server_id) => server_id.to_string(),
        None => {
            drop(lock);
            return blocked(item, "invalid Zed configured MCP item id");
        }
    };
    let plan = plan_zed_configured_mcp_toggle(app_state_root.clone(), item.clone());
    if plan.status == ToggleStatus::Blocked {
        drop(lock);
        return plan;
    }

    let vault_entry = match load_zed_configured_mcp_vault_entry(&app_state_root, &item) {
        Ok(vault_entry) => vault_entry,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let source_path = PathBuf::from(&vault_entry.original_path);
    let source_raw = match read_jsonc_raw(&source_path) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };

    let vault_payload = PathBuf::from(&vault_entry.vaulted_path);
    let vaulted_server_raw = match read_jsonc_raw(&vault_payload) {
        Ok(raw) => raw,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };
    let rendered = match prepare_zed_context_server_restore(
        &source_path,
        &source_raw,
        &server_id,
        &vault_payload,
        &vaulted_server_raw,
        vault_entry.jsonc_format.as_ref(),
    ) {
        Ok(rendered) => rendered,
        Err(reason) => {
            drop(lock);
            return blocked(item, reason);
        }
    };

    let (backup_id, created_at) = match current_backup_metadata() {
        Ok(metadata) => metadata,
        Err(reason) => return blocked(item, reason),
    };
    let backup_root = app_state_root.join("backups").join(&backup_id);
    let backup_payload = backup_root.join("entries").join("entry-1").join("payload");
    let backup_vault_payload = backup_root.join("entries").join("entry-2").join("payload");
    let backup_vault_entry = backup_root.join("entries").join("entry-3").join("payload");
    let vault_root = vault_root_path(&app_state_root, &item);
    let vault_entry_path = vault_root.join("entry.json");

    if !source_path.is_file() {
        let reason = format!("Zed settings file not found: {}", source_path.display());
        drop(lock);
        return blocked(item, reason);
    }

    if backup_root.exists() {
        drop(lock);
        return blocked(item, format!("backup already exists: {backup_id}"));
    }

    let apply_result = (|| -> Result<(), io::Error> {
        fs::create_dir_all(app_state_root.join("backups"))?;
        fs::create_dir_all(app_state_root.join("audit"))?;
        fs::create_dir_all(
            backup_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&source_path, &backup_payload)?;
        fs::create_dir_all(
            backup_vault_payload
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_payload, &backup_vault_payload)?;
        fs::create_dir_all(
            backup_vault_entry
                .parent()
                .expect("backup payload path has a parent"),
        )?;
        fs::copy(&vault_entry_path, &backup_vault_entry)?;

        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            authenticity: None,
            backup_id: backup_id.clone(),
            created_at: created_at.clone(),
            selection: item.clone(),
            target_enabled: true,
            affected_targets: plan.affected_targets.clone(),
            entries: vec![
                BackupEntry {
                    entry_id: "entry-1".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.original_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-1/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-2".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: vault_entry.vaulted_path.clone(),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-2/payload".to_string(),
                    }),
                },
                BackupEntry {
                    entry_id: "entry-3".to_string(),
                    target: MutationTarget {
                        target_type: "path".to_string(),
                        path: path_string(vault_entry_path.clone()),
                    },
                    existed: true,
                    path_kind: Some("file".to_string()),
                    payload: Some(BackupPayload {
                        storage: "path".to_string(),
                        path: "entries/entry-3/payload".to_string(),
                    }),
                },
            ],
        };
        write_authenticated_backup_manifest(
            &backup_root,
            &mut manifest,
            backup_authentication_key,
        )?;

        write_provider_config(&source_path, &rendered)?;
        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }

        append_audit_entry(
            &app_state_root,
            &ApplyAuditEntry {
                version: 1,
                event: "apply".to_string(),
                created_at,
                backup_id: backup_id.clone(),
                selection: item.clone(),
                target_enabled: true,
                affected_targets: plan.affected_targets.clone(),
            },
        )?;

        Ok(())
    })();

    drop(lock);

    if let Err(error) = apply_result {
        return apply_failure_result(plan, backup_id, &backup_root, error.to_string());
    }

    ToggleResult {
        status: ToggleStatus::Applied,
        backup_id: Some(backup_id),
        writes: Some("writes were performed".to_string()),
        ..plan
    }
}

fn blocked(item: DiscoveryItem, reason: impl Into<String>) -> ToggleResult {
    ToggleResult {
        target_enabled: item.enabled,
        selection: item,
        status: ToggleStatus::Blocked,
        operations: Vec::new(),
        affected_targets: Vec::new(),
        backup_id: None,
        reason: Some(reason.into()),
        writes: Some("no writes were performed".to_string()),
        provider_reach: None,
        coverage: None,
    }
}

fn apply_failure_result(
    mut plan: ToggleResult,
    backup_id: String,
    backup_root: &Path,
    reason: impl Into<String>,
) -> ToggleResult {
    let reason = reason.into();
    if backup_root.exists() {
        plan.status = ToggleStatus::RecoveryRequired;
        plan.backup_id = Some(backup_id.clone());
        plan.reason = Some(format!(
            "apply failed after backup {backup_id}; recovery-required: {reason}"
        ));
        plan.writes =
            Some("writes may already have been performed; manual recovery is required".to_string());
    } else {
        plan.status = ToggleStatus::Blocked;
        plan.reason = Some(reason);
        plan.writes = Some("no writes were performed".to_string());
    }
    plan
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupManifest {
    version: u8,
    backup_id: String,
    created_at: String,
    selection: DiscoveryItem,
    target_enabled: bool,
    affected_targets: Vec<MutationTarget>,
    entries: Vec<BackupEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authenticity: Option<BackupAuthenticity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupAuthenticity {
    algorithm: String,
    key_id: String,
    payload_digests: Vec<BackupPayloadDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    post_state_fingerprint: Option<String>,
    tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayloadDigest {
    entry_id: String,
    digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupEntry {
    entry_id: String,
    target: MutationTarget,
    existed: bool,
    path_kind: Option<String>,
    payload: Option<BackupPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    storage: String,
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultEntry {
    version: u8,
    provider: String,
    kind: String,
    layer: String,
    item_id: String,
    display_name: String,
    original_path: String,
    vaulted_path: String,
    payload_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jsonc_format: Option<JsoncVaultFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsoncVaultFormat {
    marker: String,
    property_prefix: String,
    property_suffix: String,
}

fn load_path_file_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    load_file_vault_entry(
        app_state_root,
        item,
        item.kind.as_str(),
        "path",
        "payload",
        path_file_item_noun(item),
    )
}

fn load_directory_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    let expected_vault_root = disabled_directory_vault_root(app_state_root, item);
    let expected_entry_path = expected_vault_root.join("entry.json");
    let expected_vaulted_path = expected_vault_root.join("payload");
    let entry_path = expected_entry_path.clone();
    validate_path_has_no_symlink_components(app_state_root, &entry_path)?;
    let raw = fs::read_to_string(&entry_path).map_err(|error| {
        format!(
            "vault entry could not be read: {}: {error}",
            entry_path.display()
        )
    })?;
    let entry: VaultEntry = serde_json::from_str(&raw).map_err(|error| {
        format!(
            "vault entry is not valid JSON: {}: {error}",
            entry_path.display()
        )
    })?;

    let expected_original_path = directory_item_original_path(item);
    let stored_vault_root = app_state_root
        .join("vault")
        .join(&entry.provider)
        .join(&entry.layer)
        .join(&entry.kind)
        .join(encode_path_segment(&entry.item_id));
    let identity_matches = entry.provider == item.provider.as_str() && entry.item_id == item.id;
    let shared_projection_matches = item.category == DiscoveryCategory::Skill
        && item.is_shared_skill_source()
        && entry.kind == item.kind.as_str()
        && entry.layer == item.layer.as_str();
    if entry.version != 1
        || entry_path != expected_entry_path
        || expected_vault_root != stored_vault_root
        || entry.layer != item.layer.as_str()
        || entry.kind != item.kind.as_str()
        || !(identity_matches || shared_projection_matches)
        || entry.payload_kind != "path"
        || Path::new(&entry.vaulted_path) != expected_vaulted_path
        || expected_original_path
            .as_deref()
            .is_none_or(|expected| Path::new(&entry.original_path) != expected)
    {
        return Err(format!(
            "vault entry does not match disabled {}: {}",
            directory_item_noun(item),
            entry_path.display()
        ));
    }

    Ok(entry)
}

fn load_codex_configured_mcp_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    load_file_vault_entry(
        app_state_root,
        item,
        "configured-mcp",
        "text-payload",
        "payload",
        "Codex configured MCP",
    )
}

fn load_json_configured_mcp_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    let item_description = match item.provider {
        ProviderId::Claude => "Claude configured MCP",
        ProviderId::Cursor => "Cursor configured MCP",
        _ => "JSON configured MCP",
    };
    load_file_vault_entry(
        app_state_root,
        item,
        "configured-mcp",
        "json-payload",
        "payload.json",
        item_description,
    )
}

fn load_zed_configured_mcp_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    load_file_vault_entry(
        app_state_root,
        item,
        "configured-mcp",
        "json-payload",
        "payload.json",
        "Zed configured MCP",
    )
}

fn load_opencode_plugin_config_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
) -> Result<VaultEntry, String> {
    load_file_vault_entry(
        app_state_root,
        item,
        "plugin",
        "json-payload",
        "payload.json",
        "OpenCode npm plugin",
    )
}

fn load_file_vault_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
    expected_kind: &str,
    expected_payload_kind: &str,
    expected_payload_name: &str,
    item_description: &str,
) -> Result<VaultEntry, String> {
    let expected_vault_root = vault_root_path(app_state_root, item);
    let expected_entry_path = expected_vault_root.join("entry.json");
    let expected_vaulted_path = expected_vault_root.join(expected_payload_name);
    let entry_path = if item.state_path.ends_with("entry.json") {
        PathBuf::from(&item.state_path)
    } else {
        expected_entry_path.clone()
    };
    validate_path_has_no_symlink_components(app_state_root, &entry_path)?;
    let raw = fs::read_to_string(&entry_path).map_err(|error| {
        format!(
            "vault entry could not be read: {}: {error}",
            entry_path.display()
        )
    })?;
    let entry: VaultEntry = serde_json::from_str(&raw).map_err(|error| {
        format!(
            "vault entry is not valid JSON: {}: {error}",
            entry_path.display()
        )
    })?;

    if entry.version != 1
        || entry_path != expected_entry_path
        || entry.provider != item.provider.as_str()
        || entry.layer != item.layer.as_str()
        || entry.kind != expected_kind
        || entry.item_id != item.id
        || entry.display_name != item.display_name
        || entry.payload_kind != expected_payload_kind
        || Path::new(&entry.original_path) != Path::new(&item.source_path)
        || Path::new(&entry.vaulted_path) != expected_vaulted_path
    {
        return Err(format!(
            "vault entry does not match disabled {item_description}: {}",
            entry_path.display()
        ));
    }

    if fs::symlink_metadata(&expected_vaulted_path).is_ok() {
        validate_path_has_no_symlink_components(app_state_root, &expected_vaulted_path)?;
    }

    Ok(entry)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyAuditEntry {
    version: u8,
    event: String,
    created_at: String,
    backup_id: String,
    selection: DiscoveryItem,
    target_enabled: bool,
    affected_targets: Vec<MutationTarget>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreAuditEntry {
    version: u8,
    event: String,
    created_at: String,
    backup_id: String,
    affected_targets: Vec<MutationTarget>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupDeletionAuditEntry {
    version: u8,
    event: String,
    created_at: String,
    backup_id: String,
    manifest_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FailedApplyAuditEntry {
    version: u8,
    event: String,
    created_at: String,
    selection: DiscoveryItem,
    target_enabled: bool,
    affected_targets: Vec<MutationTarget>,
    reason: String,
    rollback_succeeded: bool,
    rollback_failure: Option<String>,
    backup_deleted: bool,
}

pub(crate) struct MutationLock {
    _file: Option<File>,
}

pub(crate) fn acquire_mutation_lock(app_state_root: &Path) -> Result<MutationLock, String> {
    let canonical_root = canonical_existing_root(app_state_root);
    let delegated = TRANSITION_MUTATION_LOCK_ROOT
        .with(|slot| slot.borrow().as_deref() == Some(canonical_root.as_path()));
    if delegated {
        return Ok(MutationLock { _file: None });
    }

    let acquired_at = current_timestamp()?;
    let lock_dir = app_state_root.join("locks");
    let lock_path = lock_dir.join("mutation.lock");
    fs::create_dir_all(&lock_dir).map_err(|error| error.to_string())?;

    let mut lock_file = open_mutation_lock_file(&lock_path)?;
    lock_file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => lock_contention_reason(&lock_path),
        TryLockError::Error(error) => error.to_string(),
    })?;

    let payload = serde_json::json!({
        "pid": process::id(),
        "acquiredAt": acquired_at,
    });
    lock_file.set_len(0).map_err(|error| error.to_string())?;
    lock_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    writeln!(
        lock_file,
        "{}",
        serde_json::to_string_pretty(&payload).expect("lock json serializes")
    )
    .map_err(|error| error.to_string())?;
    lock_file.flush().map_err(|error| error.to_string())?;

    Ok(MutationLock {
        _file: Some(lock_file),
    })
}

fn open_mutation_lock_file(lock_path: &Path) -> Result<File, String> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|error| error.to_string())?;
            validate_open_mutation_lock_file(lock_path, &file)?;
            Ok(file)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn validate_open_mutation_lock_file(lock_path: &Path, file: &File) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(lock_path).map_err(|error| error.to_string())?;
    let file_metadata = file.metadata().map_err(|error| error.to_string())?;
    if !path_metadata.file_type().is_file() || !file_metadata.file_type().is_file() {
        return Err("mutation lock path is not a regular file".to_string());
    }
    if !crate::fs_support::path_matches_open_file(lock_path, file)
        .map_err(|error| error.to_string())?
    {
        return Err("mutation lock path changed while it was being opened".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod mutation_lock_file_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn rejects_open_file_descriptor_for_a_different_lock_path() {
        let root = TempDir::new().expect("temporary root");
        let opened_path = root.path().join("opened.lock");
        let current_path = root.path().join("current.lock");
        fs::write(&opened_path, "opened").expect("opened lock");
        fs::write(&current_path, "current").expect("current lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(opened_path)
            .expect("open first lock");

        assert_eq!(
            validate_open_mutation_lock_file(&current_path, &file),
            Err("mutation lock path changed while it was being opened".to_string())
        );
    }
}

fn lock_contention_reason(lock_path: &Path) -> String {
    parse_lock_pid(lock_path).map_or_else(
        || "lock-contention: mutation lock is already held".to_string(),
        |owner_pid| format!("lock-contention: mutation lock is already held by pid {owner_pid}"),
    )
}

fn parse_lock_pid(lock_path: &Path) -> Option<u32> {
    let raw = fs::read_to_string(lock_path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let pid = value.get("pid")?.as_u64()?;
    u32::try_from(pid).ok()
}

fn vault_path(app_state_root: &Path, item: &DiscoveryItem) -> PathBuf {
    vault_root_path(app_state_root, item).join("payload")
}

fn json_configured_mcp_vault_payload_path(app_state_root: &Path, item: &DiscoveryItem) -> PathBuf {
    vault_root_path(app_state_root, item).join("payload.json")
}

fn zed_configured_mcp_vault_payload_path(app_state_root: &Path, item: &DiscoveryItem) -> PathBuf {
    vault_root_path(app_state_root, item).join("payload.json")
}

fn vault_root_path(app_state_root: &Path, item: &DiscoveryItem) -> PathBuf {
    app_state_root
        .join("vault")
        .join(item.provider.as_str())
        .join(item.layer.as_str())
        .join(vault_kind_segment(item))
        .join(encode_path_segment(&item.id))
}

fn disabled_directory_vault_root(app_state_root: &Path, item: &DiscoveryItem) -> PathBuf {
    let state_path = Path::new(&item.state_path);
    if state_path.file_name() == Some(std::ffi::OsStr::new("entry.json")) {
        state_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| vault_root_path(app_state_root, item))
    } else {
        vault_root_path(app_state_root, item)
    }
}

fn vault_kind_segment(item: &DiscoveryItem) -> &'static str {
    if item.category == DiscoveryCategory::ConfiguredMcp {
        item.category.as_str()
    } else {
        item.kind.as_str()
    }
}

fn directory_toggle_payload_is_available(
    item: &DiscoveryItem,
    payload_path: &Path,
    original_path: &Path,
) -> bool {
    if item.category == DiscoveryCategory::Skill {
        return skill_payload_has_skill(payload_path, original_path);
    }

    fs::symlink_metadata(payload_path)
        .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir())
}

fn backup_directory_toggle_payload(
    item: &DiscoveryItem,
    source: &Path,
    destination: &Path,
) -> Result<String, io::Error> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        if item.category != DiscoveryCategory::Skill {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory backup source must not be a symlink: {}",
                    source.display()
                ),
            ));
        }
        copy_directory_symlink(source, destination)?;
        return Ok("directory-symlink".to_string());
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "directory backup source must be a directory: {}",
                source.display()
            ),
        ));
    }

    if item.category == DiscoveryCategory::Skill && !directory_tree_is_plain(source)? {
        copy_dir_all_preserving_symlinks(source, destination)?;
        Ok("directory-with-symlinks".to_string())
    } else {
        copy_dir_all(source, destination)?;
        Ok("directory".to_string())
    }
}

fn copy_directory_symlink(source: &Path, destination: &Path) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("backup source is not a symlink: {}", source.display()),
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    create_directory_symlink(&fs::read_link(source)?, destination)
}

fn copy_dir_all_preserving_symlinks(source: &Path, destination: &Path) -> Result<(), io::Error> {
    let source_metadata = fs::symlink_metadata(source)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "directory backup source must be a directory: {}",
                source.display()
            ),
        ));
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            copy_symlink(&source_path, &destination_path)?;
        } else if metadata.is_dir() {
            copy_dir_all_preserving_symlinks(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(source_path, destination_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory backup source contains a special file: {}",
                    source_path.display()
                ),
            ));
        }
    }

    Ok(())
}

fn copy_symlink(source: &Path, destination: &Path) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("backup source is not a symlink: {}", source.display()),
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    create_symlink_like(source, &fs::read_link(source)?, destination)
}

#[cfg(unix)]
fn create_symlink_like(_source: &Path, target: &Path, link: &Path) -> Result<(), io::Error> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink_like(source: &Path, target: &Path, link: &Path) -> Result<(), io::Error> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    if fs::symlink_metadata(source)?.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink_like(_source: &Path, _target: &Path, link: &Path) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "symlink backup is unsupported on this platform: {}",
            link.display()
        ),
    ))
}

#[cfg(unix)]
fn create_directory_symlink(target: &Path, link: &Path) -> Result<(), io::Error> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_directory_symlink(target: &Path, link: &Path) -> Result<(), io::Error> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_directory_symlink(_target: &Path, link: &Path) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "directory symlink backup is unsupported on this platform: {}",
            link.display()
        ),
    ))
}

fn directory_tree_is_plain(path: &Path) -> Result<bool, io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(false);
    }
    if metadata.is_file() {
        return Ok(true);
    }
    if !metadata.is_dir() {
        return Ok(false);
    }

    for entry in fs::read_dir(path)? {
        if !directory_tree_is_plain(&entry?.path())? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), io::Error> {
    let source_metadata = fs::symlink_metadata(source)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "directory backup source must be a plain directory: {}",
                source.display()
            ),
        ));
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory backup source contains a symlink: {}",
                    source_path.display()
                ),
            ));
        }
        if metadata.is_dir() {
            copy_dir_all(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(source_path, destination_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory backup source contains a special file: {}",
                    source_path.display()
                ),
            ));
        }
    }

    Ok(())
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), io::Error> {
    let json = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    fs::write(path, format!("{json}\n"))
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("hex value has an odd length".to_string());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex value contains a non-lowercase-hex character".to_string()),
    }
}

fn entry_payload_path(entry_id: &str) -> String {
    format!("entries/{entry_id}/payload")
}

fn append_audit_entry(path: &Path, entry: &impl Serialize) -> Result<(), io::Error> {
    let audit_path = path.join("audit").join("log.jsonl");
    let json = serde_json::to_string(entry).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;
    writeln!(file, "{json}")
}

fn append_failed_apply_audit_entry(path: &Path, entry: &FailedApplyAuditEntry) {
    if fs::create_dir_all(path.join("audit")).is_ok() {
        let _ = append_audit_entry(path, entry);
    }
}

fn append_pre_mutation_failed_apply_audit_entry(
    app_state_root: &Path,
    item: &DiscoveryItem,
    target_enabled: bool,
    affected_targets: &[MutationTarget],
    reason: &str,
    created_at: &str,
) {
    append_failed_apply_audit_entry(
        app_state_root,
        &FailedApplyAuditEntry {
            version: 1,
            event: "failed-apply".to_string(),
            created_at: created_at.to_string(),
            selection: item.clone(),
            target_enabled,
            affected_targets: affected_targets.to_vec(),
            reason: reason.to_string(),
            rollback_succeeded: true,
            rollback_failure: None,
            backup_deleted: false,
        },
    );
}

fn load_backup_manifest(
    app_state_root: &Path,
    backup_id: &str,
    backup_authentication_key: Option<&BackupAuthenticationKey>,
) -> Result<BackupManifest, String> {
    let backup_root = app_state_root.join("backups").join(backup_id);
    let manifest_path = backup_root.join("manifest.json");

    let raw = read_optional_string(&manifest_path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("backup manifest not found for {backup_id}"))?;
    let manifest: BackupManifest = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    if manifest.backup_id != backup_id {
        return Err(format!(
            "backup manifest id mismatch: expected {backup_id}, found {}",
            manifest.backup_id
        ));
    }
    validate_backup_manifest_structure(backup_id, &manifest)?;
    validate_backup_payload_evidence(&backup_root, &manifest)?;
    if manifest.version == 1 {
        return Err("legacy backup is unauthenticated; restore is blocked".to_string());
    }
    let backup_authentication_key = backup_authentication_key
        .ok_or_else(|| "backup authentication key is required for restore".to_string())?;
    verify_backup_authentication(&backup_root, &manifest, backup_authentication_key)?;

    Ok(manifest)
}

pub(crate) fn authenticated_backup_manifest_digest(
    app_state_root: &Path,
    backup_id: &str,
    backup_authentication_key: &BackupAuthenticationKey,
) -> Result<String, String> {
    let manifest =
        load_backup_manifest(app_state_root, backup_id, Some(backup_authentication_key))?;
    serde_json::to_vec(&manifest)
        .map(|bytes| transition_digest(&bytes))
        .map_err(|error| error.to_string())
}

fn restore_manifest_transaction(
    app_state_root: &Path,
    manifest: &BackupManifest,
) -> Result<Option<String>, String> {
    let created_at = current_timestamp()?;
    let backup_root = app_state_root.join("backups").join(&manifest.backup_id);
    let rollback_root = backup_root.join("rollback");
    validate_restore_manifest_preconditions(manifest)?;
    let audit_target = prepare_restore_audit_target(app_state_root)?;
    let vault_target = (!manifest.target_enabled).then(|| MutationTarget {
        target_type: "path".to_string(),
        path: path_string(vault_root_path(app_state_root, &manifest.selection)),
    });
    let mut rollback_targets = manifest
        .entries
        .iter()
        .map(|entry| entry.target.clone())
        .collect::<Vec<_>>();
    if let Some(vault_target) = &vault_target {
        push_unique_mutation_target(&mut rollback_targets, vault_target.clone());
    }
    push_unique_mutation_target(&mut rollback_targets, audit_target.clone());
    let rollback_entries = capture_restore_rollback_entries(&rollback_targets, &rollback_root)?;
    let mut attempted_targets = Vec::new();

    for entry in manifest.entries.iter().rev() {
        push_unique_mutation_target(&mut attempted_targets, entry.target.clone());
        if let Err(reason) = restore_backup_entry(&backup_root, entry) {
            return Err(rollback_restore_failure(
                reason,
                &rollback_root,
                &rollback_entries,
                &attempted_targets,
            ));
        }
    }

    if let Some(vault_target) = vault_target {
        push_unique_mutation_target(&mut attempted_targets, vault_target);
        if let Err(reason) = remove_restored_vault_entry(app_state_root, manifest) {
            return Err(rollback_restore_failure(
                reason,
                &rollback_root,
                &rollback_entries,
                &attempted_targets,
            ));
        }
    }

    push_unique_mutation_target(&mut attempted_targets, audit_target);
    if let Err(error) = append_audit_entry(
        app_state_root,
        &RestoreAuditEntry {
            version: 1,
            event: "restore".to_string(),
            created_at,
            backup_id: manifest.backup_id.clone(),
            affected_targets: manifest.affected_targets.clone(),
        },
    ) {
        return Err(rollback_restore_failure(
            error.to_string(),
            &rollback_root,
            &rollback_entries,
            &attempted_targets,
        ));
    }

    if rollback_root.exists()
        && let Err(error) = fs::remove_dir_all(&rollback_root)
    {
        return Ok(Some(format!(
            "restore succeeded but temporary rollback snapshots could not be removed: {error}"
        )));
    }
    Ok(None)
}

fn prepare_restore_audit_target(app_state_root: &Path) -> Result<MutationTarget, String> {
    let audit_root = app_state_root.join("audit");
    match fs::symlink_metadata(&audit_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "restore audit root must be a directory: {}",
                audit_root.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&audit_root).map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }

    let audit_log_path = audit_root.join("log.jsonl");
    match fs::symlink_metadata(&audit_log_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "restore audit log must not be a symlink: {}",
                audit_log_path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }

    Ok(MutationTarget {
        target_type: "path".to_string(),
        path: path_string(audit_log_path),
    })
}

fn push_unique_mutation_target(targets: &mut Vec<MutationTarget>, target: MutationTarget) {
    if !targets.contains(&target) {
        targets.push(target);
    }
}

fn rollback_restore_failure(
    reason: String,
    rollback_root: &Path,
    rollback_entries: &[BackupEntry],
    attempted_targets: &[MutationTarget],
) -> String {
    if let Err(rollback_reason) =
        rollback_attempted_targets(rollback_root, rollback_entries, attempted_targets)
    {
        return format!(
            "{reason}; rollback failed: {rollback_reason}; rollback snapshots retained at {}",
            rollback_root.display()
        );
    }
    if rollback_root.exists()
        && let Err(error) = fs::remove_dir_all(rollback_root)
    {
        return format!(
            "{reason}; rollback succeeded but temporary snapshots could not be removed: {error}"
        );
    }
    reason
}

fn validate_restore_manifest_preconditions(manifest: &BackupManifest) -> Result<(), String> {
    if manifest.selection.kind.as_str() != "agent" {
        return Ok(());
    }

    for entry in &manifest.entries {
        if !entry.existed
            || entry.target.target_type != "path"
            || entry.path_kind.as_deref() != Some("file")
        {
            continue;
        }

        let target_path = PathBuf::from(&entry.target.path);
        if target_path.exists() {
            return Err(format!(
                "restore target already exists: {}",
                target_path.display()
            ));
        }
    }

    Ok(())
}

fn capture_restore_rollback_entries(
    targets: &[MutationTarget],
    rollback_root: &Path,
) -> Result<Vec<BackupEntry>, String> {
    if rollback_root.exists() {
        return Err(format!(
            "restore rollback snapshots already exist: {}",
            rollback_root.display()
        ));
    }

    let capture_result = (|| {
        let mut entries = Vec::new();
        for target in targets {
            if entries
                .iter()
                .any(|entry: &BackupEntry| entry.target == *target)
            {
                continue;
            }
            let entry_id = format!("rollback-{}", entries.len() + 1);
            let payload_path = rollback_root
                .join("entries")
                .join(&entry_id)
                .join("payload");
            let (existed, path_kind, payload) = match target.target_type.as_str() {
                "path" => capture_path_restore_rollback(target, &payload_path, &entry_id)?,
                "sqlite-item" => capture_sqlite_restore_rollback(target, &payload_path, &entry_id)?,
                _ => continue,
            };

            entries.push(BackupEntry {
                entry_id,
                target: target.clone(),
                existed,
                path_kind,
                payload,
            });
        }

        Ok(entries)
    })();

    if capture_result.is_err() && rollback_root.exists() {
        fs::remove_dir_all(rollback_root).map_err(|error| error.to_string())?;
    }
    capture_result
}

fn capture_path_restore_rollback(
    target: &MutationTarget,
    payload_path: &Path,
    entry_id: &str,
) -> Result<(bool, Option<String>, Option<BackupPayload>), String> {
    let target_path = PathBuf::from(&target.path);
    let metadata = match fs::symlink_metadata(&target_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((false, None, None));
        }
        Err(error) => return Err(error.to_string()),
    };
    let path_kind = if metadata.file_type().is_symlink() {
        copy_symlink(&target_path, payload_path).map_err(|error| error.to_string())?;
        "symlink"
    } else if metadata.is_dir() {
        if directory_tree_is_plain(&target_path).map_err(|error| error.to_string())? {
            copy_dir_all(&target_path, payload_path).map_err(|error| error.to_string())?;
            "directory"
        } else {
            copy_dir_all_preserving_symlinks(&target_path, payload_path)
                .map_err(|error| error.to_string())?;
            "directory-with-symlinks"
        }
    } else if metadata.is_file() {
        fs::create_dir_all(
            payload_path
                .parent()
                .expect("rollback payload path has a parent"),
        )
        .map_err(|error| error.to_string())?;
        fs::copy(&target_path, payload_path).map_err(|error| error.to_string())?;
        "file"
    } else {
        return Err(format!(
            "restore rollback target is a special file: {}",
            target_path.display()
        ));
    };

    Ok((
        true,
        Some(path_kind.to_string()),
        Some(BackupPayload {
            storage: "path".to_string(),
            path: entry_payload_path(entry_id),
        }),
    ))
}

fn capture_sqlite_restore_rollback(
    target: &MutationTarget,
    payload_path: &Path,
    entry_id: &str,
) -> Result<(bool, Option<String>, Option<BackupPayload>), String> {
    let target_path = PathBuf::from(&target.path);
    let Some(raw) = read_cursor_workspace_disabled_server_ids_raw_optional(&target_path)? else {
        return Ok((false, None, None));
    };

    fs::create_dir_all(
        payload_path
            .parent()
            .expect("rollback payload path has a parent"),
    )
    .map_err(|error| error.to_string())?;
    fs::write(payload_path, raw).map_err(|error| error.to_string())?;
    Ok((
        true,
        None,
        Some(BackupPayload {
            storage: "path".to_string(),
            path: entry_payload_path(entry_id),
        }),
    ))
}

fn rollback_attempted_targets(
    rollback_root: &Path,
    rollback_entries: &[BackupEntry],
    attempted_targets: &[MutationTarget],
) -> Result<(), String> {
    let mut rolled_back_targets = Vec::new();
    for attempted_target in attempted_targets.iter().rev() {
        if rolled_back_targets.contains(attempted_target) {
            continue;
        }
        let Some(entry) = rollback_entries
            .iter()
            .find(|entry| entry.target == *attempted_target)
        else {
            return Err(format!(
                "rollback snapshot is missing for {} {}",
                attempted_target.target_type, attempted_target.path
            ));
        };
        restore_rollback_entry(rollback_root, entry)?;
        rolled_back_targets.push(attempted_target.clone());
    }

    Ok(())
}

fn restore_rollback_entry(rollback_root: &Path, entry: &BackupEntry) -> Result<(), String> {
    if entry.target.target_type == "path" {
        remove_path_if_present(Path::new(&entry.target.path))?;
    }
    restore_backup_entry(rollback_root, entry)
}

fn restore_backup_entry(backup_root: &Path, entry: &BackupEntry) -> Result<(), String> {
    if entry.target.target_type == "sqlite-item" {
        return restore_sqlite_backup_entry(backup_root, entry);
    }

    if entry.target.target_type != "path" {
        return Err(format!(
            "unsupported restore target type: {}",
            entry.target.target_type
        ));
    }

    let target_path = PathBuf::from(&entry.target.path);
    ensure_target_parent_has_no_symlink_components(&target_path)?;
    if !entry.existed {
        remove_path_if_present(&target_path)?;
        return Ok(());
    }

    let payload = entry
        .payload
        .as_ref()
        .ok_or_else(|| "backup entry payload is missing".to_string())?;
    if payload.storage != "path" {
        return Err(format!(
            "unsupported restore payload storage: {}",
            payload.storage
        ));
    }

    let payload_path = backup_payload_path(backup_root, payload)?;

    match entry.path_kind.as_deref() {
        Some("directory") => {
            ensure_restore_target_absent(&target_path)?;

            copy_dir_all(&payload_path, &target_path).map_err(|error| error.to_string())
        }
        Some("directory-symlink") => {
            ensure_restore_target_absent(&target_path)?;
            copy_directory_symlink(&payload_path, &target_path).map_err(|error| error.to_string())
        }
        Some("directory-with-symlinks") => {
            ensure_restore_target_absent(&target_path)?;
            copy_dir_all_preserving_symlinks(&payload_path, &target_path)
                .map_err(|error| error.to_string())
        }
        Some("symlink") => {
            ensure_restore_target_absent(&target_path)?;
            copy_symlink(&payload_path, &target_path).map_err(|error| error.to_string())
        }
        Some("file") => {
            ensure_regular_backup_file_payload(&payload_path)?;
            ensure_restore_file_target_is_not_symlink(&target_path)?;
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::copy(&payload_path, &target_path)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        _ => Err("unsupported restore path kind".to_string()),
    }
}

fn remove_path_if_present(target_path: &Path) -> Result<(), String> {
    ensure_target_parent_has_no_symlink_components(target_path)?;
    match fs::symlink_metadata(target_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(target_path).map_err(|error| error.to_string())
        }
        Ok(_) => fs::remove_file(target_path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_restore_target_absent(target_path: &Path) -> Result<(), String> {
    ensure_target_parent_has_no_symlink_components(target_path)?;
    match fs::symlink_metadata(target_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(_) => Err(format!(
            "restore target already exists: {}",
            target_path.display()
        )),
    }
}

fn ensure_restore_file_target_is_not_symlink(target_path: &Path) -> Result<(), String> {
    ensure_target_parent_has_no_symlink_components(target_path)?;
    match fs::symlink_metadata(target_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "restore target is a symlink: {}",
            target_path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn ensure_regular_backup_file_payload(payload_path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(payload_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!(
            "backup payload must be a regular file: {}",
            payload_path.display()
        )),
        Err(error) => Err(error.to_string()),
    }
}

fn restore_sqlite_backup_entry(backup_root: &Path, entry: &BackupEntry) -> Result<(), String> {
    let target_path = PathBuf::from(&entry.target.path);
    ensure_target_parent_has_no_symlink_components(&target_path)?;
    if !entry.existed {
        return delete_cursor_workspace_disabled_server_ids(&target_path);
    }

    let payload = entry
        .payload
        .as_ref()
        .ok_or_else(|| "backup entry payload is missing".to_string())?;
    if payload.storage != "path" {
        return Err(format!(
            "unsupported restore payload storage: {}",
            payload.storage
        ));
    }

    let payload_path = backup_payload_path(backup_root, payload)?;
    ensure_regular_backup_file_payload(&payload_path)?;
    let payload = fs::read(&payload_path).map_err(|error| error.to_string())?;
    write_cursor_workspace_disabled_server_ids_raw(&target_path, &payload)
}

fn backup_payload_path(backup_root: &Path, payload: &BackupPayload) -> Result<PathBuf, String> {
    let payload_path = backup_root.join(backup_payload_relative_path(&payload.path)?);
    validate_backup_payload_parent(backup_root, &payload_path)?;
    Ok(payload_path)
}

fn validate_backup_payload_parent(backup_root: &Path, payload_path: &Path) -> Result<(), String> {
    let backup_root_metadata = fs::symlink_metadata(backup_root).map_err(|error| {
        format!(
            "backup root could not be validated: {}: {error}",
            backup_root.display()
        )
    })?;
    if backup_root_metadata.file_type().is_symlink() || !backup_root_metadata.is_dir() {
        return Err(format!(
            "backup root must be a directory: {}",
            backup_root.display()
        ));
    }

    let parent = payload_path
        .parent()
        .ok_or_else(|| format!("backup payload has no parent: {}", payload_path.display()))?;
    let relative_parent = parent.strip_prefix(backup_root).map_err(|_| {
        format!(
            "backup payload path is outside backup root: {}",
            payload_path.display()
        )
    })?;
    let mut current = backup_root.to_path_buf();
    for component in relative_parent.components() {
        let Component::Normal(segment) = component else {
            return Err(format!(
                "backup payload path is not normalized: {}",
                payload_path.display()
            ));
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "backup payload path could not be validated: {}: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "backup payload path contains a symlink: {}",
                current.display()
            ));
        }
    }

    Ok(())
}

fn backup_payload_relative_path(payload_path: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(payload_path);
    let mut validated = PathBuf::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(segment) => validated.push(segment),
            _ => return Err(format!("invalid backup payload path: {payload_path}")),
        }
    }

    if validated.as_os_str().is_empty() {
        return Err(format!("invalid backup payload path: {payload_path}"));
    }

    Ok(validated)
}

fn validate_path_has_no_symlink_components(root: &Path, path: &Path) -> Result<(), String> {
    let relative_path = path
        .strip_prefix(root)
        .map_err(|_| format!("vault path is outside Unpin state root: {}", path.display()))?;
    let mut current = root.to_path_buf();
    for component in relative_path.components() {
        let Component::Normal(segment) = component else {
            return Err(format!("vault path is not normalized: {}", path.display()));
        };
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "vault path could not be validated: {}: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "vault path contains a symlink: {}",
                current.display()
            ));
        }
    }

    Ok(())
}

fn remove_restored_vault_entry(
    app_state_root: &Path,
    manifest: &BackupManifest,
) -> Result<(), String> {
    if manifest.target_enabled {
        return Ok(());
    }

    let vault_root = vault_root_path(app_state_root, &manifest.selection);
    if vault_root.exists() {
        fs::remove_dir_all(vault_root).map_err(|error| error.to_string())?;
    }

    Ok(())
}

fn restore_failed(
    backup_id: String,
    affected_targets: Vec<MutationTarget>,
    reason: impl Into<String>,
) -> RestoreResult {
    RestoreResult {
        status: RestoreStatus::Failed,
        backup_id,
        affected_targets,
        reason: Some(reason.into()),
    }
}

fn valid_backup_id(backup_id: &str) -> bool {
    let mut chars = backup_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    backup_id.len() >= 3
        && backup_id.len() <= 128
        && first.is_ascii_alphanumeric()
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn path_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

fn is_supported_codex_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Codex && item.category == DiscoveryCategory::ConfiguredMcp
}

fn is_supported_pi_file_skill(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Pi
        && item.category == DiscoveryCategory::Skill
        && item.id.starts_with(match item.layer {
            DiscoveryLayer::Global => "pi:global:skill:@file/",
            DiscoveryLayer::Project => "pi:project:skill:@file/",
        })
        && Path::new(&item.source_path)
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("md")
}

fn path_file_item_noun(item: &DiscoveryItem) -> &'static str {
    if is_supported_pi_file_skill(item) {
        "skill"
    } else {
        "agent"
    }
}

fn path_file_item_title(item: &DiscoveryItem) -> &'static str {
    if is_supported_pi_file_skill(item) {
        "Skill"
    } else {
        "Agent"
    }
}

fn is_supported_cursor_local_plugin(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Cursor
        && item.layer == DiscoveryLayer::Global
        && item.category == DiscoveryCategory::PluginManifest
        && item
            .id
            .strip_prefix(CURSOR_GLOBAL_LOCAL_PLUGIN_ID_PREFIX)
            .is_some_and(|plugin_id| !plugin_id.is_empty())
}

fn directory_item_noun(item: &DiscoveryItem) -> &'static str {
    if is_supported_cursor_local_plugin(item) {
        "plugin"
    } else {
        "skill"
    }
}

fn directory_item_title(item: &DiscoveryItem) -> &'static str {
    if is_supported_cursor_local_plugin(item) {
        "Cursor local plugin"
    } else {
        "Skill"
    }
}

fn directory_item_original_path(item: &DiscoveryItem) -> Option<PathBuf> {
    let source_path = Path::new(&item.source_path);
    if is_supported_cursor_local_plugin(item) {
        source_path.parent()?.parent().map(Path::to_path_buf)
    } else {
        source_path.parent().map(Path::to_path_buf)
    }
}

fn directory_item_restart_guidance(item: &DiscoveryItem) -> &'static str {
    if is_supported_cursor_local_plugin(item) {
        " Restart Cursor or reload its window to load the change."
    } else {
        ""
    }
}

fn directory_item_shared_source_guidance(item: &DiscoveryItem) -> &'static str {
    if item.is_shared_skill_source() {
        " This changes every provider loading this source path."
    } else {
        ""
    }
}

fn validate_cursor_local_plugin_directory(
    item: &DiscoveryItem,
    plugin_path: &Path,
) -> Result<(), String> {
    if !is_supported_cursor_local_plugin(item) {
        return Ok(());
    }

    match directory_tree_is_plain(plugin_path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "Cursor local plugin directory contains a symlink or special file: {}",
            plugin_path.display()
        )),
        Err(error) => Err(format!(
            "Cursor local plugin directory could not be validated: {}: {error}",
            plugin_path.display()
        )),
    }
}

fn is_supported_codex_plugin(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Codex
        && item.layer == DiscoveryLayer::Global
        && item.category == DiscoveryCategory::PluginConfig
        && codex_plugin_id(item).is_some()
}

fn is_supported_cursor_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Cursor
        && matches!(item.layer, DiscoveryLayer::Global | DiscoveryLayer::Project)
        && item.category == DiscoveryCategory::ConfiguredMcp
        && cursor_configured_mcp_server_id(item).is_some()
}

fn is_supported_claude_global_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Claude
        && item.layer == DiscoveryLayer::Global
        && item.category == DiscoveryCategory::ConfiguredMcp
        && json_configured_mcp_server_id(item).is_some()
}

fn is_supported_claude_local_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Claude
        && item.layer == DiscoveryLayer::Project
        && item.category == DiscoveryCategory::ConfiguredMcp
        && claude_local_configured_mcp_id_parts(item).is_some()
}

fn is_supported_zed_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Zed
        && matches!(item.layer, DiscoveryLayer::Global | DiscoveryLayer::Project)
        && item.category == DiscoveryCategory::ConfiguredMcp
        && zed_configured_mcp_server_id(item).is_some()
}

fn is_supported_opencode_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::OpenCode
        && matches!(item.layer, DiscoveryLayer::Global | DiscoveryLayer::Project)
        && item.category == DiscoveryCategory::ConfiguredMcp
        && opencode_configured_mcp_server_id(item).is_some()
}

fn is_supported_opencode_plugin_config(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::OpenCode
        && matches!(item.layer, DiscoveryLayer::Global | DiscoveryLayer::Project)
        && item.category == DiscoveryCategory::PluginConfig
        && opencode_plugin_config_id(item).is_some()
}

fn is_supported_pi_package_extension(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Pi
        && matches!(item.layer, DiscoveryLayer::Global | DiscoveryLayer::Project)
        && item.category == DiscoveryCategory::PluginConfig
        && pi_package_extension_source(item).is_some()
}

fn pi_package_extension_source(item: &DiscoveryItem) -> Option<&str> {
    let prefix = match item.layer {
        DiscoveryLayer::Global => PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX,
    };
    item.id
        .strip_prefix(prefix)
        .filter(|source| !source.is_empty())
}

fn opencode_plugin_config_id(item: &DiscoveryItem) -> Option<&str> {
    opencode_plugin_config_id_from_id(&item.id, item.layer)
}

fn opencode_plugin_config_id_from_id(id: &str, layer: DiscoveryLayer) -> Option<&str> {
    let prefix = match layer {
        DiscoveryLayer::Global => OPENCODE_GLOBAL_PLUGIN_CONFIG_ID_PREFIX,
        DiscoveryLayer::Project => OPENCODE_PROJECT_PLUGIN_CONFIG_ID_PREFIX,
    };
    id.strip_prefix(prefix)
        .filter(|plugin_id| !plugin_id.is_empty())
}

fn is_supported_claude_configured_mcp(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Claude
        && item.layer == DiscoveryLayer::Project
        && item.category == DiscoveryCategory::ConfiguredMcp
        && !item.id.starts_with(CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX)
        && claude_project_configured_mcp_server_id(item).is_some()
}

fn is_supported_claude_all_project_mcp_servers(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Claude
        && item.layer == DiscoveryLayer::Project
        && item.category == DiscoveryCategory::ConfiguredMcp
        && item.id == CLAUDE_ALL_PROJECT_MCP_SERVERS_ID
}

fn is_supported_claude_plugin_config(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Claude && item.category == DiscoveryCategory::PluginConfig
}

fn claude_project_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    let server_id = item
        .id
        .strip_prefix(CLAUDE_PROJECT_CONFIGURED_MCP_ID_PREFIX)?;
    if server_id.is_empty() || server_id == "all-project-mcp-servers" {
        None
    } else {
        Some(server_id)
    }
}

fn claude_plugin_config_id(item: &DiscoveryItem) -> Option<String> {
    if item.provider != ProviderId::Claude || item.category != DiscoveryCategory::PluginConfig {
        return None;
    }

    // Inventory keeps historical `:tool:` id segment for selector compatibility.
    let prefix = format!("claude:{}:tool:", item.layer.as_str());
    let rest = item.id.strip_prefix(&prefix)?;
    let (_, plugin_id) = rest.split_once(':')?;
    if plugin_id.is_empty() {
        None
    } else {
        Some(plugin_id.to_string())
    }
}

fn read_claude_enabled_plugin(path: &Path, plugin_id: &str) -> Result<bool, String> {
    let document = read_json_value(path)?;
    document
        .get("enabledPlugins")
        .and_then(Value::as_object)
        .and_then(|enabled_plugins| enabled_plugins.get(plugin_id))
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("enabledPlugins.{plugin_id} is missing or not boolean"))
}

fn read_claude_configured_mcp_enabled(path: &Path, server_id: &str) -> Result<bool, String> {
    let document = read_json_value(path)?;
    claude_configured_mcp_enabled(&document, server_id)
}

fn read_claude_all_project_mcp_servers(path: &Path) -> Result<bool, String> {
    let document = read_json_value(path)?;
    document
        .get("enableAllProjectMcpServers")
        .and_then(Value::as_bool)
        .ok_or_else(|| "enableAllProjectMcpServers is missing or not boolean".to_string())
}

fn read_json_value(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("JSON settings could not be read: {}", error))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("JSON settings could not be parsed: {error}"))
}

fn read_jsonc_raw(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| {
        format!(
            "JSONC settings could not be read: {}: {error}",
            path.display()
        )
    })
}

fn parse_jsonc_value(raw: &str) -> Result<Value, String> {
    jsonc_parser::parse_to_serde_value(raw, &Default::default())
        .map_err(|error| format!("JSONC settings could not be parsed: {error}"))
}

fn read_cursor_workspace_disabled_server_ids(database_path: &Path) -> Result<Vec<String>, String> {
    let raw = read_cursor_workspace_disabled_server_ids_raw(database_path)?;
    parse_cursor_workspace_disabled_server_ids(database_path, &raw)
}

fn read_cursor_workspace_disabled_server_ids_raw(database_path: &Path) -> Result<Vec<u8>, String> {
    read_cursor_workspace_disabled_server_ids_raw_optional(database_path)?.ok_or_else(|| {
        format!(
            "Cursor workspace database not found: {}",
            database_path.display()
        )
    })
}

fn read_cursor_workspace_disabled_server_ids_raw_optional(
    database_path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    if !ensure_cursor_workspace_database_target(database_path)? {
        return Ok(None);
    }
    let connection = open_cursor_workspace_database(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "read",
    )?;
    read_cursor_workspace_disabled_server_ids_raw_from_connection(&connection, database_path)
}

fn read_cursor_workspace_disabled_server_ids_raw_from_connection(
    connection: &Connection,
    database_path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    let mut statement = connection
        .prepare("SELECT value FROM ItemTable WHERE key = ?1")
        .map_err(|error| cursor_workspace_database_error(database_path, "read", &error))?;
    let value = statement
        .query_row([CURSOR_WORKSPACE_DISABLED_SERVERS_KEY], |row| {
            row.get::<_, SqliteValue>(0)
        })
        .optional()
        .map_err(|error| cursor_workspace_database_error(database_path, "read", &error))?;
    let Some(value) = value else {
        return Ok(None);
    };

    let raw = sqlite_value_to_bytes(value).ok_or_else(|| {
        format!(
            "invalid Cursor workspace state at {}; expected {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} to be a JSON string array",
            database_path.display()
        )
    })?;
    Ok(Some(raw))
}

fn parse_cursor_workspace_disabled_server_ids(
    database_path: &Path,
    raw: &[u8],
) -> Result<Vec<String>, String> {
    serde_json::from_slice::<Vec<String>>(raw).map_err(|_| {
        format!(
            "invalid Cursor workspace state at {}; expected {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} to be a JSON string array",
            database_path.display()
        )
    })
}

fn write_cursor_workspace_disabled_server_ids_raw(
    database_path: &Path,
    raw: &[u8],
) -> Result<(), String> {
    if !ensure_cursor_workspace_database_target(database_path)? {
        return Err(format!(
            "Cursor workspace database not found: {}",
            database_path.display()
        ));
    }
    let connection = open_cursor_workspace_database(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "write",
    )?;
    write_cursor_workspace_disabled_server_ids_raw_on_connection(&connection, database_path, raw)
}

fn write_cursor_workspace_disabled_server_ids_raw_on_connection(
    connection: &Connection,
    database_path: &Path,
    raw: &[u8],
) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (CURSOR_WORKSPACE_DISABLED_SERVERS_KEY, raw),
        )
        .map_err(|error| cursor_workspace_database_error(database_path, "write", &error))?;
    Ok(())
}

fn delete_cursor_workspace_disabled_server_ids(database_path: &Path) -> Result<(), String> {
    if !ensure_cursor_workspace_database_target(database_path)? {
        return Ok(());
    }
    let connection = open_cursor_workspace_database(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "delete",
    )?;
    connection
        .execute(
            "DELETE FROM ItemTable WHERE key = ?1",
            [CURSOR_WORKSPACE_DISABLED_SERVERS_KEY],
        )
        .map_err(|error| cursor_workspace_database_error(database_path, "delete", &error))?;
    Ok(())
}

fn open_cursor_workspace_database(
    database_path: &Path,
    flags: OpenFlags,
    action: &str,
) -> Result<Connection, String> {
    if !ensure_cursor_workspace_database_target(database_path)? {
        return Err(format!(
            "Cursor workspace database not found: {}",
            database_path.display()
        ));
    }
    let connection = Connection::open_with_flags(database_path, flags)
        .map_err(|error| cursor_workspace_database_error(database_path, action, &error))?;
    connection
        .busy_timeout(CURSOR_WORKSPACE_BUSY_TIMEOUT)
        .map_err(|error| cursor_workspace_database_error(database_path, action, &error))?;
    Ok(connection)
}

fn ensure_cursor_workspace_database_target(database_path: &Path) -> Result<bool, String> {
    ensure_target_parent_has_no_symlink_components(database_path)?;
    match fs::symlink_metadata(database_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "Cursor workspace database path is a symlink and will not be mutated: {}",
            database_path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(format!(
            "Cursor workspace database path is not a regular file: {}",
            database_path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "Cursor workspace database path could not be validated: {}: {error}",
            database_path.display()
        )),
    }
}

fn cursor_workspace_database_error(
    database_path: &Path,
    action: &str,
    error: &SqliteError,
) -> String {
    if matches!(
        error.sqlite_error_code(),
        Some(SqliteErrorCode::DatabaseBusy | SqliteErrorCode::DatabaseLocked)
    ) {
        return format!(
            "cursor-host-busy: close Cursor and retry; could not {action} {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY} in {}",
            database_path.display()
        );
    }

    format!(
        "invalid Cursor workspace state at {}; could not {action} {CURSOR_WORKSPACE_DISABLED_SERVERS_KEY}: {error}",
        database_path.display()
    )
}

fn sqlite_value_to_bytes(value: SqliteValue) -> Option<Vec<u8>> {
    match value {
        SqliteValue::Text(value) => Some(value.into_bytes()),
        SqliteValue::Blob(value) => Some(value),
        _ => None,
    }
}

fn set_claude_enabled_plugin(
    document: &mut Value,
    plugin_id: &str,
    target_enabled: bool,
) -> Result<(), String> {
    let enabled_plugins = document
        .get_mut("enabledPlugins")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "enabledPlugins is missing or not an object".to_string())?;
    let Some(value) = enabled_plugins.get_mut(plugin_id) else {
        return Err(format!("enabledPlugins.{plugin_id} is missing"));
    };
    if !value.is_boolean() {
        return Err(format!("enabledPlugins.{plugin_id} is not boolean"));
    }

    *value = Value::Bool(target_enabled);
    Ok(())
}

fn set_claude_all_project_mcp_servers(
    document: &mut Value,
    target_enabled: bool,
) -> Result<(), String> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| "Claude settings root is not an object".to_string())?;
    let Some(value) = root.get_mut("enableAllProjectMcpServers") else {
        return Err("enableAllProjectMcpServers is missing".to_string());
    };
    if !value.is_boolean() {
        return Err("enableAllProjectMcpServers is not boolean".to_string());
    }

    *value = Value::Bool(target_enabled);
    Ok(())
}

fn claude_mcp_server_value(document: &Value, server_id: &str) -> Result<Value, String> {
    let servers = document
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| "mcpServers is missing or not an object".to_string())?;
    let Some(value) = servers.get(server_id) else {
        return Err(format!("mcpServers.{server_id} is missing"));
    };
    if !value.is_object() {
        return Err(format!("mcpServers.{server_id} is not an object"));
    }

    Ok(value.clone())
}

fn claude_configured_mcp_enabled(document: &Value, server_id: &str) -> Result<bool, String> {
    if let Some(disabled_servers) = optional_json_object(document, "disabledMcpjsonServers")?
        && disabled_servers.contains_key(server_id)
    {
        return Ok(false);
    }

    if let Some(enabled_servers) = optional_json_object(document, "enabledMcpjsonServers")?
        && enabled_servers.contains_key(server_id)
    {
        return Ok(true);
    }

    Ok(true)
}

fn set_claude_configured_mcp_approval(
    document: &mut Value,
    server_id: &str,
    payload: Value,
    target_enabled: bool,
) -> Result<(), String> {
    if !document.is_object() {
        return Err("Claude settings root is not an object".to_string());
    }
    if !payload.is_object() {
        return Err(format!("mcpServers.{server_id} is not an object"));
    }

    if target_enabled {
        ensure_json_object_mut(document, "disabledMcpjsonServers")?.remove(server_id);
        ensure_json_object_mut(document, "enabledMcpjsonServers")?
            .insert(server_id.to_string(), payload);
    } else {
        ensure_json_object_mut(document, "enabledMcpjsonServers")?.remove(server_id);
        ensure_json_object_mut(document, "disabledMcpjsonServers")?
            .insert(server_id.to_string(), payload);
    }

    Ok(())
}

fn optional_json_object<'a>(
    document: &'a Value,
    field: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match document.get(field) {
        Some(value) => value
            .as_object()
            .map(Some)
            .ok_or_else(|| format!("{field} is not an object")),
        None => Ok(None),
    }
}

fn ensure_json_object_mut<'a>(
    document: &'a mut Value,
    field: &str,
) -> Result<&'a mut serde_json::Map<String, Value>, String> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| "Claude settings root is not an object".to_string())?;
    let value = root
        .entry(field.to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    value
        .as_object_mut()
        .ok_or_else(|| format!("{field} is not an object"))
}

fn codex_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    let prefix = match item.layer {
        DiscoveryLayer::Global => CODEX_GLOBAL_CONFIGURED_MCP_ID_PREFIX,
        DiscoveryLayer::Project => CODEX_PROJECT_CONFIGURED_MCP_ID_PREFIX,
    };
    item.id.strip_prefix(prefix)?;
    if item.display_name.is_empty() {
        None
    } else {
        Some(&item.display_name)
    }
}

fn codex_plugin_id(item: &DiscoveryItem) -> Option<&str> {
    item.id.strip_prefix(CODEX_GLOBAL_PLUGIN_CONFIG_ID_PREFIX)?;
    if item.display_name.is_empty() {
        None
    } else {
        Some(&item.display_name)
    }
}

fn cursor_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    let server_id = match item.layer {
        DiscoveryLayer::Global => item
            .id
            .strip_prefix(CURSOR_GLOBAL_CONFIGURED_MCP_ID_PREFIX)?,
        DiscoveryLayer::Project => item
            .id
            .strip_prefix(CURSOR_PROJECT_CONFIGURED_MCP_ID_PREFIX)?,
    };
    if server_id.is_empty() {
        None
    } else {
        Some(server_id)
    }
}

fn json_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    match item.provider {
        ProviderId::Claude if item.layer == DiscoveryLayer::Global => {
            let server_id = item
                .id
                .strip_prefix(CLAUDE_GLOBAL_CONFIGURED_MCP_ID_PREFIX)?;
            (!server_id.is_empty()).then_some(server_id)
        }
        ProviderId::Claude if item.layer == DiscoveryLayer::Project => {
            claude_local_configured_mcp_id_parts(item).map(|(_, server_id)| server_id)
        }
        ProviderId::Cursor => cursor_configured_mcp_server_id(item),
        _ => None,
    }
}

fn claude_local_configured_mcp_id_parts(item: &DiscoveryItem) -> Option<(&str, &str)> {
    let remainder = item
        .id
        .strip_prefix(CLAUDE_LOCAL_CONFIGURED_MCP_ID_PREFIX)?;
    let (scope_token, server_id) = remainder.split_once(':')?;
    if scope_token.len() != 64
        || !scope_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || server_id.is_empty()
    {
        return None;
    }

    Some((scope_token, server_id))
}

fn json_mcp_provider_name(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Claude => "Claude",
        ProviderId::Codex => "Codex",
        ProviderId::Cursor => "Cursor",
        ProviderId::Pi => "Pi",
        ProviderId::OpenCode => "OpenCode",
        ProviderId::Zed => "Zed",
    }
}

fn zed_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    let server_id = match item.layer {
        DiscoveryLayer::Global => item.id.strip_prefix(ZED_GLOBAL_CONFIGURED_MCP_ID_PREFIX)?,
        DiscoveryLayer::Project => item.id.strip_prefix(ZED_PROJECT_CONFIGURED_MCP_ID_PREFIX)?,
    };
    if server_id.is_empty() {
        None
    } else {
        Some(server_id)
    }
}

fn opencode_configured_mcp_server_id(item: &DiscoveryItem) -> Option<&str> {
    let server_id = match item.layer {
        DiscoveryLayer::Global => item
            .id
            .strip_prefix(OPENCODE_GLOBAL_CONFIGURED_MCP_ID_PREFIX)?,
        DiscoveryLayer::Project => item
            .id
            .strip_prefix(OPENCODE_PROJECT_CONFIGURED_MCP_ID_PREFIX)?,
    };
    (!server_id.is_empty()).then_some(server_id)
}

fn is_cursor_workspace_state_path(item: &DiscoveryItem) -> bool {
    item.provider == ProviderId::Cursor
        && item.category == DiscoveryCategory::ConfiguredMcp
        && item.state_path != item.source_path
        && Path::new(&item.state_path)
            .file_name()
            .and_then(|name| name.to_str())
            == Some("state.vscdb")
}

fn cursor_workspace_server_id(server_id: &str) -> String {
    if server_id.starts_with("user-") {
        server_id.to_string()
    } else {
        format!("user-{server_id}")
    }
}

fn configured_json_mcp_servers<'a>(
    document: &'a Value,
    item: &DiscoveryItem,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let Some((scope_token, _)) = claude_local_configured_mcp_id_parts(item) else {
        return document
            .get("mcpServers")
            .and_then(Value::as_object)
            .ok_or_else(|| "mcpServers is missing or not an object".to_string());
    };
    let project_key = claude_local_project_key(document, scope_token)?;
    document
        .get("projects")
        .and_then(Value::as_object)
        .and_then(|projects| projects.get(&project_key))
        .and_then(Value::as_object)
        .and_then(|project| project.get("mcpServers"))
        .and_then(Value::as_object)
        .ok_or_else(|| "Claude local project mcpServers is missing or not an object".to_string())
}

fn configured_json_mcp_servers_mut<'a>(
    document: &'a mut Value,
    item: &DiscoveryItem,
) -> Result<&'a mut serde_json::Map<String, Value>, String> {
    let Some((scope_token, _)) = claude_local_configured_mcp_id_parts(item) else {
        return document
            .get_mut("mcpServers")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "mcpServers is missing or not an object".to_string());
    };
    let project_key = claude_local_project_key(document, scope_token)?;
    document
        .get_mut("projects")
        .and_then(Value::as_object_mut)
        .and_then(|projects| projects.get_mut(&project_key))
        .and_then(Value::as_object_mut)
        .and_then(|project| project.get_mut("mcpServers"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Claude local project mcpServers is missing or not an object".to_string())
}

fn claude_local_project_key(document: &Value, scope_token: &str) -> Result<String, String> {
    let projects = document
        .get("projects")
        .and_then(Value::as_object)
        .ok_or_else(|| "Claude projects is missing or not an object".to_string())?;
    let mut matching_keys = projects
        .keys()
        .filter(|project_key| claude_local_scope_token(project_key) == scope_token);
    let project_key = matching_keys
        .next()
        .ok_or_else(|| format!("Claude local MCP project scope {scope_token} is missing"))?;
    if matching_keys.next().is_some() {
        return Err(format!(
            "Claude local MCP project scope {scope_token} is ambiguous"
        ));
    }

    Ok(project_key.clone())
}

fn configured_json_mcp_server_value(
    document: &Value,
    item: &DiscoveryItem,
    server_id: &str,
) -> Result<Value, String> {
    json_mcp_server_value_from_servers(configured_json_mcp_servers(document, item)?, server_id)
}

fn configured_json_mcp_server_present(
    document: &Value,
    item: &DiscoveryItem,
    server_id: &str,
) -> Result<bool, String> {
    let Some(value) = configured_json_mcp_servers(document, item)?.get(server_id) else {
        return Ok(false);
    };
    if !value.is_object() {
        return Err(format!("mcpServers.{server_id} is not an object"));
    }

    Ok(true)
}

fn json_mcp_server_value(document: &Value, server_id: &str) -> Result<Value, String> {
    let servers = document
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| "mcpServers is missing or not an object".to_string())?;
    json_mcp_server_value_from_servers(servers, server_id)
}

fn json_mcp_server_value_from_servers(
    servers: &serde_json::Map<String, Value>,
    server_id: &str,
) -> Result<Value, String> {
    let Some(value) = servers.get(server_id) else {
        return Err(format!("mcpServers.{server_id} is missing"));
    };
    if !value.is_object() {
        return Err(format!("mcpServers.{server_id} is not an object"));
    }

    Ok(value.clone())
}

fn cursor_mcp_server_disabled_flag(document: &Value, server_id: &str) -> Result<(), String> {
    let value = json_mcp_server_value(document, server_id)?;
    if value.get("disabled").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(format!("mcpServers.{server_id}.disabled is not true"))
    }
}

fn cursor_mcp_server_enabled_from_value(value: &Value) -> bool {
    value.get("disabled").and_then(Value::as_bool) != Some(true)
}

fn remove_configured_json_mcp_server(
    document: &mut Value,
    item: &DiscoveryItem,
    server_id: &str,
) -> Result<Value, String> {
    let servers = configured_json_mcp_servers_mut(document, item)?;
    let Some(value) = servers.get(server_id) else {
        return Err(format!("mcpServers.{server_id} is missing"));
    };
    if !value.is_object() {
        return Err(format!("mcpServers.{server_id} is not an object"));
    }

    Ok(servers
        .remove(server_id)
        .expect("validated JSON MCP server exists"))
}

fn remove_cursor_mcp_server_disabled_flag(
    document: &mut Value,
    server_id: &str,
) -> Result<(), String> {
    let servers = document
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "mcpServers is missing or not an object".to_string())?;
    let Some(value) = servers.get_mut(server_id) else {
        return Err(format!("mcpServers.{server_id} is missing"));
    };
    let Some(server) = value.as_object_mut() else {
        return Err(format!("mcpServers.{server_id} is not an object"));
    };
    if server.get("disabled").and_then(Value::as_bool) != Some(true) {
        return Err(format!("mcpServers.{server_id}.disabled is not true"));
    }

    server.remove("disabled");
    Ok(())
}

fn prepare_cursor_mcp_payload(payload: &mut Value, server_id: &str) -> Result<(), String> {
    let Some(server) = payload.as_object_mut() else {
        return Err(format!(
            "mcpServers.{server_id} vaulted payload is not an object"
        ));
    };
    server.remove("disabled");
    Ok(())
}

fn opencode_mcp_server_value(raw: &str, server_id: &str) -> Result<Value, String> {
    let document = parse_jsonc_value(raw)?;
    let servers = document
        .get("mcp")
        .and_then(Value::as_object)
        .ok_or_else(|| "mcp is missing or not an object".to_string())?;
    let server = servers
        .get(server_id)
        .ok_or_else(|| format!("mcp.{server_id} is missing"))?;
    if !server.is_object() {
        return Err(format!("mcp.{server_id} is not an object"));
    }
    if server
        .get("enabled")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(format!("mcp.{server_id}.enabled is not a boolean"));
    }
    Ok(server.clone())
}

fn set_opencode_mcp_enabled_jsonc(
    raw: &str,
    server_id: &str,
    enabled: bool,
) -> Result<String, String> {
    opencode_mcp_server_value(raw, server_id)?;
    let root = CstRootNode::parse(raw, &ParseOptions::default())
        .map_err(|error| format!("OpenCode JSONC config could not be parsed: {error}"))?;
    let root_object = root
        .object_value()
        .ok_or_else(|| "OpenCode config root is not an object".to_string())?;
    let mcp = root_object
        .object_value("mcp")
        .ok_or_else(|| "mcp is missing or not an object".to_string())?;
    let server = mcp
        .object_value(server_id)
        .ok_or_else(|| format!("mcp.{server_id} is missing or not an object"))?;
    if let Some(property) = server.get("enabled") {
        property.set_value(CstInputValue::Bool(enabled));
    } else {
        server.append("enabled", CstInputValue::Bool(enabled));
    }

    let rendered = root.to_string();
    let rewritten_server = opencode_mcp_server_value(&rendered, server_id)?;
    if rewritten_server.get("enabled").and_then(Value::as_bool) != Some(enabled) {
        return Err(format!(
            "OpenCode JSONC edit did not set mcp.{server_id}.enabled"
        ));
    }
    Ok(rendered)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PiPackageVaultPayload {
    package_source: String,
    original_entry: Value,
    original_raw: String,
    disabled_entry_fingerprint: String,
}

struct PiPackageRewrite {
    rendered: String,
    payload: Option<PiPackageVaultPayload>,
}

fn pi_package_entries(raw: &str) -> Result<Vec<Value>, String> {
    let document = serde_json::from_str::<Value>(raw)
        .map_err(|error| format!("Pi settings are not valid JSON: {error}"))?;
    let packages = document
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "Pi settings packages are missing or not an array".to_string())?;
    let mut sources = BTreeSet::new();
    for package in packages {
        let (source, _) = pi_package_extension_state(package)?;
        if !sources.insert(source.to_string()) {
            return Err(format!(
                "Pi settings contain duplicate package source {source}"
            ));
        }
    }
    Ok(packages.clone())
}

fn pi_package_selection(raw: &str, package_source: &str) -> Result<(Vec<Value>, usize), String> {
    let entries = pi_package_entries(raw)?;
    let index = entries
        .iter()
        .position(|package| {
            pi_package_extension_state(package).is_ok_and(|(source, _)| source == package_source)
        })
        .ok_or_else(|| format!("Pi package source {package_source} is missing"))?;
    Ok((entries, index))
}

fn pi_package_element_range(raw: &str, index: usize) -> Result<(usize, usize), String> {
    let parsed =
        jsonc_parser::parse_to_ast(raw, &CollectOptions::default(), &ParseOptions::default())
            .map_err(|error| format!("Pi settings JSON could not be parsed: {error}"))?;
    let JsoncAstValue::Object(root_object) = parsed
        .value
        .ok_or_else(|| "Pi settings root is missing".to_string())?
    else {
        return Err("Pi settings root is not an object".to_string());
    };
    let packages_property = root_object
        .get("packages")
        .ok_or_else(|| "Pi settings packages are missing".to_string())?;
    let JsoncAstValue::Array(packages) = &packages_property.value else {
        return Err("Pi settings packages are not an array".to_string());
    };
    packages
        .elements
        .get(index)
        .map(|element| {
            let range = element.range();
            (range.start, range.end)
        })
        .ok_or_else(|| "Pi package entry index changed during JSON parsing".to_string())
}

fn replace_pi_package_entry(
    raw: &str,
    index: usize,
    replacement_raw: &str,
    replacement: &Value,
) -> Result<String, String> {
    let parsed_replacement = serde_json::from_str::<Value>(replacement_raw)
        .map_err(|error| format!("Pi package replacement is not valid JSON: {error}"))?;
    if &parsed_replacement != replacement {
        return Err("Pi package replacement raw value does not match payload".to_string());
    }
    let mut expected_entries = pi_package_entries(raw)?;
    let selected = expected_entries
        .get_mut(index)
        .ok_or_else(|| "Pi package entry index is out of bounds".to_string())?;
    selected.clone_from(replacement);
    let (range_start, range_end) = pi_package_element_range(raw, index)?;
    let mut rendered =
        String::with_capacity(raw.len() - (range_end - range_start) + replacement_raw.len());
    rendered.push_str(&raw[..range_start]);
    rendered.push_str(replacement_raw);
    rendered.push_str(&raw[range_end..]);
    if pi_package_entries(&rendered)? != expected_entries {
        return Err("Pi package JSON edit changed entries outside the selection".to_string());
    }
    Ok(rendered)
}

fn validate_pi_package_vault_payload(
    payload: &PiPackageVaultPayload,
    package_source: &str,
) -> Result<(), String> {
    let (source, enabled) = pi_package_extension_state(&payload.original_entry)?;
    let parsed_original = serde_json::from_str::<Value>(&payload.original_raw)
        .map_err(|error| format!("Pi package vault originalRaw is invalid: {error}"))?;
    let expected_disabled = pi_disabled_package_entry(&payload.original_entry)?
        .ok_or_else(|| "Pi package vault original entry was already disabled".to_string())?;
    if source != package_source || payload.package_source != package_source {
        return Err("Pi package vault payload source does not match selection".to_string());
    }
    if !enabled {
        return Err("Pi package vault original entry was not enabled".to_string());
    }
    if parsed_original != payload.original_entry {
        return Err("Pi package vault originalRaw does not match originalEntry".to_string());
    }
    if payload.disabled_entry_fingerprint != json_value_source_fingerprint(&expected_disabled) {
        return Err(
            "Pi package vault disabled fingerprint does not match original entry".to_string(),
        );
    }
    if !payload
        .disabled_entry_fingerprint
        .strip_prefix("sha256:")
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("Pi package vault disabled fingerprint is invalid".to_string());
    }
    Ok(())
}

fn read_pi_package_vault_payload(
    path: &Path,
    package_source: &str,
) -> Result<PiPackageVaultPayload, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "Pi package vault payload could not be read: {}: {error}",
            path.display()
        )
    })?;
    let payload = serde_json::from_str::<PiPackageVaultPayload>(&raw).map_err(|error| {
        format!(
            "Pi package vault payload is invalid: {}: {error}",
            path.display()
        )
    })?;
    validate_pi_package_vault_payload(&payload, package_source)?;
    Ok(payload)
}

fn load_optional_pi_package_vault(
    app_state_root: &Path,
    item: &DiscoveryItem,
    package_source: &str,
) -> Result<Option<(VaultEntry, PiPackageVaultPayload)>, String> {
    let vault_root = vault_root_path(app_state_root, item);
    match fs::symlink_metadata(&vault_root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "Pi package vault metadata could not be read: {}: {error}",
                vault_root.display()
            ));
        }
        Ok(_) => {}
    }
    let entry = load_file_vault_entry(
        app_state_root,
        item,
        "plugin",
        "json-payload",
        "payload.json",
        "Pi package extensions",
    )?;
    let payload_path = PathBuf::from(&entry.vaulted_path);
    let payload = read_pi_package_vault_payload(&payload_path, package_source)?;
    Ok(Some((entry, payload)))
}

fn prepare_pi_package_disable(
    raw: &str,
    package_source: &str,
    discovered_fingerprint: Option<&str>,
) -> Result<PiPackageRewrite, String> {
    let (entries, index) = pi_package_selection(raw, package_source)?;
    let original_entry = entries[index].clone();
    let (_, enabled) = pi_package_extension_state(&original_entry)?;
    if !enabled {
        return Err(format!(
            "Pi package extensions are already disabled for {package_source}"
        ));
    }
    let current_fingerprint = json_value_source_fingerprint(&original_entry);
    if discovered_fingerprint.is_some_and(|fingerprint| fingerprint != current_fingerprint) {
        return Err(format!(
            "Pi package source drifted for {package_source}: discovered {}, current {current_fingerprint}",
            discovered_fingerprint.expect("checked fingerprint")
        ));
    }
    let (range_start, range_end) = pi_package_element_range(raw, index)?;
    let original_raw = raw
        .get(range_start..range_end)
        .ok_or_else(|| "Pi package entry range is invalid".to_string())?
        .to_string();
    let disabled_entry = pi_disabled_package_entry(&original_entry)?.ok_or_else(|| {
        format!("Pi package extensions are already disabled for {package_source}")
    })?;
    let disabled_raw = serde_json::to_string(&disabled_entry)
        .map_err(|error| format!("Pi disabled package could not be encoded: {error}"))?;
    let rendered = replace_pi_package_entry(raw, index, &disabled_raw, &disabled_entry)?;
    let disabled_entry_fingerprint = json_value_source_fingerprint(&disabled_entry);
    Ok(PiPackageRewrite {
        rendered,
        payload: Some(PiPackageVaultPayload {
            package_source: package_source.to_string(),
            original_entry,
            original_raw,
            disabled_entry_fingerprint,
        }),
    })
}

fn prepare_pi_package_enable(
    raw: &str,
    package_source: &str,
    discovered_fingerprint: Option<&str>,
    payload: Option<&PiPackageVaultPayload>,
) -> Result<PiPackageRewrite, String> {
    let (entries, index) = pi_package_selection(raw, package_source)?;
    let current_entry = &entries[index];
    let (_, enabled) = pi_package_extension_state(current_entry)?;
    if enabled {
        return Err(format!(
            "Pi package extensions are already enabled for {package_source}"
        ));
    }
    let current_fingerprint = json_value_source_fingerprint(current_entry);
    if discovered_fingerprint.is_some_and(|fingerprint| fingerprint != current_fingerprint) {
        return Err(format!(
            "Pi package source drifted for {package_source}: discovered {}, current {current_fingerprint}",
            discovered_fingerprint.expect("checked fingerprint")
        ));
    }

    let (replacement, replacement_raw) = if let Some(payload) = payload {
        validate_pi_package_vault_payload(payload, package_source)?;
        if payload.disabled_entry_fingerprint != current_fingerprint {
            return Err(format!(
                "Pi disabled package entry drifted for {package_source}: expected {}, current {current_fingerprint}",
                payload.disabled_entry_fingerprint
            ));
        }
        (payload.original_entry.clone(), payload.original_raw.clone())
    } else {
        let mut replacement = current_entry
            .as_object()
            .cloned()
            .ok_or_else(|| "disabled Pi package entry must be an object".to_string())?;
        replacement.remove("extensions");
        let replacement = Value::Object(replacement);
        if !pi_package_extension_state(&replacement)?.1 {
            return Err("Pi package edit did not enable extensions".to_string());
        }
        let replacement_raw = serde_json::to_string(&replacement)
            .map_err(|error| format!("Pi enabled package could not be encoded: {error}"))?;
        (replacement, replacement_raw)
    };
    let rendered = replace_pi_package_entry(raw, index, &replacement_raw, &replacement)?;
    Ok(PiPackageRewrite {
        rendered,
        payload: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenCodePluginVaultPayload {
    plugin_id: String,
    original_order: Vec<String>,
}

struct OpenCodePluginRemoval {
    rendered: String,
    payload: OpenCodePluginVaultPayload,
    jsonc_format: Option<JsoncVaultFormat>,
}

fn opencode_plugin_ids(raw: &str) -> Result<Vec<String>, String> {
    let document = parse_jsonc_value(raw)?;
    let plugins = document
        .get("plugin")
        .and_then(Value::as_array)
        .ok_or_else(|| "plugin is missing or not an array".to_string())?;
    let plugin_ids = plugins
        .iter()
        .map(|plugin| {
            plugin
                .as_str()
                .filter(|plugin_id| !plugin_id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| "plugin entries must be non-empty strings".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if plugin_ids.iter().collect::<BTreeSet<_>>().len() != plugin_ids.len() {
        return Err("plugin entries must be unique".to_string());
    }
    Ok(plugin_ids)
}

fn validate_opencode_plugin_vault_payload(
    payload: &OpenCodePluginVaultPayload,
    plugin_id: &str,
) -> Result<(), String> {
    if payload.plugin_id != plugin_id
        || payload
            .original_order
            .iter()
            .filter(|current| current.as_str() == plugin_id)
            .count()
            != 1
        || payload.original_order.iter().collect::<BTreeSet<_>>().len()
            != payload.original_order.len()
    {
        return Err("OpenCode npm plugin vault payload does not match selection".to_string());
    }
    Ok(())
}

fn read_opencode_plugin_vault_payload(
    path: &Path,
    plugin_id: &str,
) -> Result<OpenCodePluginVaultPayload, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "OpenCode npm plugin vault payload could not be read: {}: {error}",
            path.display()
        )
    })?;
    let payload = serde_json::from_str::<OpenCodePluginVaultPayload>(&raw).map_err(|error| {
        format!(
            "OpenCode npm plugin vault payload is invalid: {}: {error}",
            path.display()
        )
    })?;
    validate_opencode_plugin_vault_payload(&payload, plugin_id)?;
    Ok(payload)
}

fn merge_opencode_plugin_order(base: &mut Vec<String>, current_ids: &[String]) {
    for (current_index, plugin_id) in current_ids.iter().enumerate() {
        if base.contains(plugin_id) {
            continue;
        }
        let insertion_index = current_ids[..current_index]
            .iter()
            .rev()
            .find_map(|predecessor| {
                base.iter()
                    .position(|current| current == predecessor)
                    .map(|index| index + 1)
            })
            .or_else(|| {
                current_ids[current_index + 1..]
                    .iter()
                    .find_map(|successor| base.iter().position(|current| current == successor))
            })
            .unwrap_or(base.len());
        base.insert(insertion_index, plugin_id.clone());
    }
}

fn opencode_plugin_order_with_vaults(
    app_state_root: &Path,
    item: &DiscoveryItem,
    raw: &str,
) -> Result<Vec<String>, String> {
    let current_ids = opencode_plugin_ids(raw)?;
    let Some(vault_parent) = vault_root_path(app_state_root, item)
        .parent()
        .map(Path::to_path_buf)
    else {
        return Ok(current_ids);
    };
    if !vault_parent.exists() {
        return Ok(current_ids);
    }

    let mut disabled_ids = BTreeSet::new();
    let mut candidate_orders = Vec::new();
    let entries = fs::read_dir(&vault_parent).map_err(|error| {
        format!(
            "OpenCode plugin vault could not be read: {}: {error}",
            vault_parent.display()
        )
    })?;
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("OpenCode plugin vault entry could not be read: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let entry_path = entry.path().join("entry.json");
        let raw_entry = match fs::read_to_string(&entry_path) {
            Ok(raw_entry) => raw_entry,
            Err(_) => continue,
        };
        let vault_entry = match serde_json::from_str::<VaultEntry>(&raw_entry) {
            Ok(vault_entry) => vault_entry,
            Err(_) => continue,
        };
        if Path::new(&vault_entry.original_path) != Path::new(&item.state_path) {
            continue;
        }
        let expected_root = vault_parent.join(encode_path_segment(&vault_entry.item_id));
        let expected_payload = expected_root.join("payload.json");
        if vault_entry.version != 1
            || vault_entry.provider != ProviderId::OpenCode.as_str()
            || vault_entry.layer != item.layer.as_str()
            || vault_entry.kind != "plugin"
            || vault_entry.payload_kind != "json-payload"
            || entry.path() != expected_root
            || Path::new(&vault_entry.vaulted_path) != expected_payload
        {
            return Err(format!(
                "OpenCode plugin vault entry does not match its config: {}",
                entry_path.display()
            ));
        }
        validate_path_has_no_symlink_components(app_state_root, &entry_path)?;
        validate_path_has_no_symlink_components(app_state_root, &expected_payload)?;
        let plugin_id = opencode_plugin_config_id_from_id(&vault_entry.item_id, item.layer)
            .ok_or_else(|| {
                format!(
                    "OpenCode plugin vault item id is invalid: {}",
                    entry_path.display()
                )
            })?;
        if vault_entry.display_name != plugin_id {
            return Err(format!(
                "OpenCode plugin vault display name does not match its item id: {}",
                entry_path.display()
            ));
        }
        let payload = read_opencode_plugin_vault_payload(&expected_payload, plugin_id)?;
        disabled_ids.insert(payload.plugin_id.clone());
        candidate_orders.push(payload.original_order);
    }

    let allowed_ids = current_ids
        .iter()
        .cloned()
        .chain(disabled_ids)
        .collect::<BTreeSet<_>>();
    for candidate_order in &mut candidate_orders {
        candidate_order.retain(|plugin_id| allowed_ids.contains(plugin_id));
    }
    let mut original_order = candidate_orders
        .into_iter()
        .max_by_key(Vec::len)
        .unwrap_or_else(|| current_ids.clone());
    merge_opencode_plugin_order(&mut original_order, &current_ids);
    Ok(original_order)
}

fn prepare_opencode_plugin_removal(
    raw: &str,
    plugin_id: &str,
    discovered_fingerprint: Option<&str>,
    original_order: Vec<String>,
) -> Result<OpenCodePluginRemoval, String> {
    let plugin_ids = opencode_plugin_ids(raw)?;
    let array_index = plugin_ids
        .iter()
        .position(|current| current == plugin_id)
        .ok_or_else(|| format!("OpenCode plugin reference {plugin_id} is missing"))?;
    let selected_value = Value::String(plugin_id.to_string());
    if let Some(discovered_fingerprint) = discovered_fingerprint {
        let current_fingerprint = json_value_source_fingerprint(&selected_value);
        if current_fingerprint != discovered_fingerprint {
            return Err(format!(
                "OpenCode plugin source drifted for {plugin_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
            ));
        }
    }
    if !plugin_ids
        .iter()
        .all(|current| original_order.contains(current))
        || original_order.iter().collect::<BTreeSet<_>>().len() != original_order.len()
        || !original_order.iter().any(|current| current == plugin_id)
    {
        return Err("OpenCode plugin original order is inconsistent with live config".to_string());
    }
    let payload = OpenCodePluginVaultPayload {
        plugin_id: plugin_id.to_string(),
        original_order,
    };

    if serde_json::from_str::<Value>(raw).is_err() {
        let parsed = jsonc_parser::parse_to_ast(
            raw,
            &CollectOptions {
                comments: Default::default(),
                tokens: true,
            },
            &ParseOptions::default(),
        )
        .map_err(|error| format!("OpenCode JSONC config could not be parsed: {error}"))?;
        let JsoncAstValue::Object(root_object) = parsed
            .value
            .ok_or_else(|| "OpenCode config root is missing".to_string())?
        else {
            return Err("OpenCode config root is not an object".to_string());
        };
        let plugin_property = root_object
            .get("plugin")
            .ok_or_else(|| "plugin is missing".to_string())?;
        let JsoncAstValue::Array(plugin_array) = &plugin_property.value else {
            return Err("plugin is not an array".to_string());
        };
        let element = plugin_array
            .elements
            .get(array_index)
            .ok_or_else(|| format!("OpenCode plugin reference {plugin_id} is missing"))?;
        let element_range = element.range();
        let removal_end = parsed
            .tokens
            .as_deref()
            .and_then(|tokens| {
                tokens.iter().find(|token| {
                    token.range.start >= element_range.end
                        && token.range.start < plugin_array.range.end
                })
            })
            .filter(|token| token.token == JsoncToken::Comma)
            .map_or(element_range.end, |token| token.range.end);
        let element_raw = raw
            .get(element_range.start..element_range.end)
            .ok_or_else(|| "OpenCode plugin element range is invalid".to_string())?
            .to_string();
        let element_suffix = raw
            .get(element_range.end..removal_end)
            .ok_or_else(|| "OpenCode plugin element suffix is invalid".to_string())?
            .to_string();
        let mut marker = format!(
            "/* unpin-disabled-plugin:{} */",
            encode_path_segment(plugin_id)
        );
        while raw.contains(&marker) {
            marker.insert(marker.len() - 3, '-');
        }
        let mut rendered =
            String::with_capacity(raw.len() - (removal_end - element_range.start) + marker.len());
        rendered.push_str(&raw[..element_range.start]);
        rendered.push_str(&marker);
        rendered.push_str(&raw[removal_end..]);
        let mut expected_ids = plugin_ids;
        expected_ids.remove(array_index);
        if opencode_plugin_ids(&rendered)? != expected_ids {
            return Err(format!(
                "OpenCode JSONC edit did not remove only plugin reference {plugin_id}"
            ));
        }
        return Ok(OpenCodePluginRemoval {
            rendered,
            payload,
            jsonc_format: Some(JsoncVaultFormat {
                marker,
                property_prefix: element_raw,
                property_suffix: element_suffix,
            }),
        });
    }

    let root = CstRootNode::parse(raw, &ParseOptions::default())
        .map_err(|error| format!("OpenCode JSONC config could not be parsed: {error}"))?;
    let root_object = root
        .object_value()
        .ok_or_else(|| "OpenCode config root is not an object".to_string())?;
    let plugins = root_object
        .array_value("plugin")
        .ok_or_else(|| "plugin is missing or not an array".to_string())?;
    let element = plugins
        .elements()
        .get(array_index)
        .cloned()
        .ok_or_else(|| format!("OpenCode plugin reference {plugin_id} is missing"))?;
    if element
        .as_string_lit()
        .and_then(|literal| literal.decoded_value().ok())
        .as_deref()
        != Some(plugin_id)
    {
        return Err(format!(
            "OpenCode plugin reference {plugin_id} changed during JSON parsing"
        ));
    }
    element.remove();

    let rendered = root.to_string();
    let mut expected_ids = plugin_ids;
    expected_ids.remove(array_index);
    if opencode_plugin_ids(&rendered)? != expected_ids {
        return Err(format!(
            "OpenCode JSON edit did not remove only plugin reference {plugin_id}"
        ));
    }

    Ok(OpenCodePluginRemoval {
        rendered,
        payload,
        jsonc_format: None,
    })
}

fn strict_opencode_plugin_insertion_index(
    current_ids: &[String],
    payload: &OpenCodePluginVaultPayload,
) -> usize {
    let original_index = payload
        .original_order
        .iter()
        .position(|current| current == &payload.plugin_id)
        .expect("validated payload contains selected plugin");
    if let Some(index) = payload.original_order[..original_index]
        .iter()
        .rev()
        .find_map(|predecessor| {
            current_ids
                .iter()
                .position(|current| current == predecessor)
                .map(|index| index + 1)
        })
    {
        return index;
    }
    payload.original_order[original_index + 1..]
        .iter()
        .find_map(|successor| current_ids.iter().position(|current| current == successor))
        .unwrap_or(current_ids.len())
}

fn prepare_opencode_plugin_restore(
    raw: &str,
    plugin_id: &str,
    payload: &OpenCodePluginVaultPayload,
    jsonc_format: Option<&JsoncVaultFormat>,
) -> Result<String, String> {
    validate_opencode_plugin_vault_payload(payload, plugin_id)?;
    let plugin_ids = opencode_plugin_ids(raw)?;
    if plugin_ids.iter().any(|current| current == plugin_id) {
        return Err(format!(
            "live-entry-conflict: OpenCode plugin reference {plugin_id} is already present"
        ));
    }

    if let Some(format) = jsonc_format {
        if format.marker.is_empty() {
            return Err("OpenCode npm plugin JSONC marker is empty".to_string());
        }
        let Some(marker_start) = raw.find(&format.marker) else {
            return Err(format!(
                "OpenCode JSONC disable marker is missing for plugin {plugin_id}"
            ));
        };
        if raw[marker_start + format.marker.len()..].contains(&format.marker) {
            return Err(format!(
                "OpenCode JSONC disable marker is ambiguous for plugin {plugin_id}"
            ));
        }
        let restored_raw = format!("{}{}", format.property_prefix, format.property_suffix);
        if parse_jsonc_value(&format.property_prefix)?.as_str() != Some(plugin_id) {
            return Err("OpenCode npm plugin JSONC vault format changed payload".to_string());
        }
        let mut rendered =
            String::with_capacity(raw.len() - format.marker.len() + restored_raw.len());
        rendered.push_str(&raw[..marker_start]);
        rendered.push_str(&restored_raw);
        rendered.push_str(&raw[marker_start + format.marker.len()..]);
        let restored_ids = opencode_plugin_ids(&rendered)?;
        if restored_ids
            .iter()
            .filter(|current| current.as_str() == plugin_id)
            .count()
            != 1
        {
            return Err(format!(
                "OpenCode JSONC edit did not restore plugin reference {plugin_id}"
            ));
        }
        return Ok(rendered);
    }

    let insertion_index = strict_opencode_plugin_insertion_index(&plugin_ids, payload);
    let root = CstRootNode::parse(raw, &ParseOptions::default())
        .map_err(|error| format!("OpenCode JSON config could not be parsed: {error}"))?;
    let root_object = root
        .object_value()
        .ok_or_else(|| "OpenCode config root is not an object".to_string())?;
    let plugins = root_object
        .array_value("plugin")
        .ok_or_else(|| "plugin is missing or not an array".to_string())?;
    plugins.insert(
        insertion_index,
        CstInputValue::String(plugin_id.to_string()),
    );

    let rendered = root.to_string();
    let mut expected_ids = plugin_ids;
    expected_ids.insert(insertion_index, plugin_id.to_string());
    if opencode_plugin_ids(&rendered)? != expected_ids {
        return Err(format!(
            "OpenCode JSON edit did not restore plugin reference {plugin_id} at its original relative position"
        ));
    }
    Ok(rendered)
}

fn insert_configured_json_mcp_server(
    document: &mut Value,
    item: &DiscoveryItem,
    server_id: &str,
    value: Value,
) -> Result<(), String> {
    if !value.is_object() {
        return Err(format!(
            "mcpServers.{server_id} vaulted payload is not an object"
        ));
    }
    let servers = configured_json_mcp_servers_mut(document, item)?;
    if servers.contains_key(server_id) {
        return Err(format!("mcpServers.{server_id} already exists"));
    }

    servers.insert(server_id.to_string(), value);
    Ok(())
}

fn zed_context_server_value(document: &Value, server_id: &str) -> Result<Value, String> {
    let servers = document
        .get("context_servers")
        .and_then(Value::as_object)
        .ok_or_else(|| "context_servers is missing or not an object".to_string())?;
    let Some(value) = servers.get(server_id) else {
        return Err(format!("context_servers.{server_id} is missing"));
    };
    if !value.is_object() {
        return Err(format!("context_servers.{server_id} is not an object"));
    }

    Ok(value.clone())
}

struct ZedJsoncRemoval {
    rendered: String,
    value_raw: String,
    format: Option<JsoncVaultFormat>,
}

fn prepare_zed_context_server_removal(
    raw: &str,
    server_id: &str,
    discovered_fingerprint: Option<&str>,
) -> Result<ZedJsoncRemoval, String> {
    let document = parse_jsonc_value(raw)?;
    let server_value = zed_context_server_value(&document, server_id)?;
    if let Some(discovered_fingerprint) = discovered_fingerprint {
        let current_fingerprint = json_value_source_fingerprint(&server_value);
        if current_fingerprint != discovered_fingerprint {
            return Err(format!(
                "Zed configured MCP source drifted for {server_id}: discovered {discovered_fingerprint}, current {current_fingerprint}"
            ));
        }
    }

    let removal = remove_zed_context_server_jsonc(raw, server_id)?;
    let vaulted_server_value = parse_jsonc_value(&removal.value_raw)?;
    if !vaulted_server_value.is_object() {
        return Err("Zed context server JSONC value is not an object".to_string());
    }
    if vaulted_server_value != server_value {
        return Err(
            "Zed context server JSONC edit did not preserve the selected server value".to_string(),
        );
    }

    Ok(removal)
}

fn prepare_zed_context_server_restore(
    source_path: &Path,
    source_raw: &str,
    server_id: &str,
    vault_payload_path: &Path,
    vault_payload_raw: &str,
    format: Option<&JsoncVaultFormat>,
) -> Result<String, String> {
    let document = parse_jsonc_value(source_raw)?;
    let context_servers = document
        .get("context_servers")
        .and_then(Value::as_object)
        .ok_or_else(|| "context_servers is missing or not an object".to_string())?;
    if context_servers.contains_key(server_id) {
        return Err(format!(
            "live-entry-conflict: {server_id} is already present in {}",
            source_path.display()
        ));
    }

    let payload = parse_jsonc_value(vault_payload_raw).map_err(|reason| {
        format!(
            "invalid-vault-payload: {}: {reason}",
            vault_payload_path.display()
        )
    })?;
    if !payload.is_object() {
        return Err(format!(
            "invalid-vault-payload: {} must contain a JSON object for context_servers.{server_id}",
            vault_payload_path.display()
        ));
    }

    if let Some(format) = format {
        restore_zed_context_server_jsonc(source_raw, server_id, format, vault_payload_raw, &payload)
    } else {
        insert_zed_context_server_jsonc(source_raw, server_id, vault_payload_raw, &payload)
    }
}

fn remove_zed_context_server_jsonc(raw: &str, server_id: &str) -> Result<ZedJsoncRemoval, String> {
    if serde_json::from_str::<Value>(raw).is_ok() {
        return remove_zed_context_server_strict_json(raw, server_id);
    }

    let parsed = jsonc_parser::parse_to_ast(
        raw,
        &CollectOptions {
            comments: Default::default(),
            tokens: true,
        },
        &ParseOptions::default(),
    )
    .map_err(|error| format!("JSONC settings could not be parsed: {error}"))?;
    let JsoncAstValue::Object(root_object) = parsed
        .value
        .ok_or_else(|| "Zed settings root is missing".to_string())?
    else {
        return Err("Zed settings root is not an object".to_string());
    };
    let context_servers = root_object
        .get_object("context_servers")
        .ok_or_else(|| "context_servers is missing or not an object".to_string())?;
    let property = context_servers
        .get(server_id)
        .ok_or_else(|| format!("context_servers.{server_id} is missing"))?;
    if !matches!(property.value, JsoncAstValue::Object(_)) {
        return Err(format!("context_servers.{server_id} is not an object"));
    }
    let property_start = property.range.start;
    let property_end = property.range.end;
    let removal_end = parsed
        .tokens
        .as_deref()
        .and_then(|tokens| {
            tokens.iter().find(|token| {
                token.range.start >= property_end && token.range.start < context_servers.range.end
            })
        })
        .filter(|token| token.token == JsoncToken::Comma)
        .map_or(property_end, |token| token.range.end);
    let value_range = property.value.range();
    let value_raw = raw
        .get(value_range.start..value_range.end)
        .ok_or_else(|| format!("context_servers.{server_id} value range is invalid"))?
        .to_string();
    let property_prefix = raw
        .get(property_start..value_range.start)
        .ok_or_else(|| format!("context_servers.{server_id} property prefix is invalid"))?
        .to_string();
    let property_suffix = raw
        .get(value_range.end..removal_end)
        .ok_or_else(|| format!("context_servers.{server_id} property suffix is invalid"))?
        .to_string();
    let mut marker = format!("/* unpin-disabled:{} */", encode_path_segment(server_id));
    while raw.contains(&marker) {
        marker.insert(marker.len() - 3, '-');
    }
    let mut rendered =
        String::with_capacity(raw.len() - (removal_end - property_start) + marker.len());
    rendered.push_str(&raw[..property_start]);
    rendered.push_str(&marker);
    rendered.push_str(&raw[removal_end..]);
    let document = parse_jsonc_value(&rendered)?;
    if zed_context_server_value(&document, server_id).is_ok() {
        return Err(format!(
            "context_servers.{server_id} remained after JSONC removal"
        ));
    }

    Ok(ZedJsoncRemoval {
        rendered,
        value_raw,
        format: Some(JsoncVaultFormat {
            marker,
            property_prefix,
            property_suffix,
        }),
    })
}

fn remove_zed_context_server_strict_json(
    raw: &str,
    server_id: &str,
) -> Result<ZedJsoncRemoval, String> {
    let root = CstRootNode::parse(raw, &ParseOptions::default())
        .map_err(|error| format!("JSON settings could not be parsed: {error}"))?;
    let root_object = root
        .object_value()
        .ok_or_else(|| "Zed settings root is not an object".to_string())?;
    let context_servers = root_object
        .object_value("context_servers")
        .ok_or_else(|| "context_servers is missing or not an object".to_string())?;
    let property = context_servers
        .get(server_id)
        .ok_or_else(|| format!("context_servers.{server_id} is missing"))?;
    let value_raw = property
        .value()
        .ok_or_else(|| format!("context_servers.{server_id} has no value"))?
        .to_string();
    property.remove();
    let rendered = root.to_string();
    serde_json::from_str::<Value>(&rendered)
        .map_err(|error| format!("JSON settings edit produced invalid JSON: {error}"))?;

    Ok(ZedJsoncRemoval {
        rendered,
        value_raw,
        format: None,
    })
}

fn restore_zed_context_server_jsonc(
    raw: &str,
    server_id: &str,
    format: &JsoncVaultFormat,
    value_raw: &str,
    expected_value: &Value,
) -> Result<String, String> {
    let Some(marker_start) = raw.find(&format.marker) else {
        return Err(format!(
            "Zed JSONC disable marker is missing for context_servers.{server_id}"
        ));
    };
    if raw[marker_start + format.marker.len()..].contains(&format.marker) {
        return Err(format!(
            "Zed JSONC disable marker is ambiguous for context_servers.{server_id}"
        ));
    }

    let value_raw = value_raw.trim_end();
    let replacement_len =
        format.property_prefix.len() + value_raw.len() + format.property_suffix.len();
    let mut rendered = String::with_capacity(raw.len() - format.marker.len() + replacement_len);
    rendered.push_str(&raw[..marker_start]);
    rendered.push_str(&format.property_prefix);
    rendered.push_str(value_raw);
    rendered.push_str(&format.property_suffix);
    rendered.push_str(&raw[marker_start + format.marker.len()..]);
    let document = parse_jsonc_value(&rendered)?;
    let restored_value = zed_context_server_value(&document, server_id)?;
    if &restored_value != expected_value {
        return Err(format!(
            "context_servers.{server_id} JSONC restoration changed the vaulted value"
        ));
    }

    Ok(rendered)
}

fn insert_zed_context_server_jsonc(
    raw: &str,
    server_id: &str,
    value_raw: &str,
    expected_value: &Value,
) -> Result<String, String> {
    let root = CstRootNode::parse(raw, &ParseOptions::default())
        .map_err(|error| format!("JSONC settings could not be parsed: {error}"))?;
    let root_object = root
        .object_value()
        .ok_or_else(|| "Zed settings root is not an object".to_string())?;
    let context_servers = root_object
        .object_value("context_servers")
        .ok_or_else(|| "context_servers is missing or not an object".to_string())?;
    if context_servers.get(server_id).is_some() {
        return Err(format!("context_servers.{server_id} already exists"));
    }

    let mut placeholder = "__UNPIN_JSONC_PAYLOAD__".to_string();
    while raw.contains(&placeholder) || value_raw.contains(&placeholder) {
        placeholder.push('_');
    }
    context_servers.append(server_id, CstInputValue::String(placeholder.clone()));
    let rendered_with_placeholder = root.to_string();
    let placeholder_start = rendered_with_placeholder
        .find(&placeholder)
        .ok_or_else(|| "inserted Zed JSONC placeholder is missing".to_string())?;
    if rendered_with_placeholder[placeholder_start + placeholder.len()..].contains(&placeholder) {
        return Err("inserted Zed JSONC placeholder is ambiguous".to_string());
    }
    let value_start = placeholder_start
        .checked_sub(1)
        .ok_or_else(|| "inserted Zed JSONC placeholder has no opening quote".to_string())?;
    let value_end = placeholder_start + placeholder.len() + 1;
    let opening_quote = rendered_with_placeholder.as_bytes()[value_start];
    let closing_quote = rendered_with_placeholder
        .as_bytes()
        .get(value_end - 1)
        .copied();
    if !matches!(opening_quote, b'\'' | b'"') || closing_quote != Some(opening_quote) {
        return Err("inserted Zed JSONC placeholder is not a string value".to_string());
    }

    let mut rendered = String::with_capacity(
        rendered_with_placeholder.len() + value_raw.len() - placeholder.len() - 2,
    );
    rendered.push_str(&rendered_with_placeholder[..value_start]);
    rendered.push_str(value_raw.trim());
    rendered.push_str(&rendered_with_placeholder[value_end..]);

    let document = parse_jsonc_value(&rendered)?;
    let inserted_value = zed_context_server_value(&document, server_id)?;
    if &inserted_value != expected_value {
        return Err(format!(
            "context_servers.{server_id} JSONC insertion changed the vaulted value"
        ));
    }

    Ok(rendered)
}

fn set_codex_skill_config_enabled(
    raw: &str,
    skill_path: &Path,
    enabled: bool,
) -> Result<String, String> {
    ensure_unique_standard_toml_tables(raw)?;
    let skill_path_string = path_string(skill_path.to_path_buf());
    let mut matching_sections = Vec::new();
    for section in find_toml_array_table_sections(raw, "skills.config") {
        if codex_skill_config_path(section.content)?.as_deref() == Some(&skill_path_string) {
            matching_sections.push(section);
        }
    }
    if matching_sections.len() > 1 {
        return Err("Codex config contains duplicate skills.config path".to_string());
    }
    if let Some(section) = matching_sections.pop() {
        let rewritten_section = set_toml_section_bool(section.content, "enabled", enabled)?;
        let mut rewritten = String::with_capacity(raw.len() + rewritten_section.len());
        rewritten.push_str(&raw[..section.start]);
        rewritten.push_str(&rewritten_section);
        rewritten.push_str(&raw[section.end..]);
        return Ok(rewritten);
    }

    let rendered_path = serde_json::to_string(&skill_path_string)
        .map_err(|error| format!("Codex skill path could not be encoded: {error}"))?;
    let mut rewritten = raw.to_string();
    if !rewritten.is_empty() && !rewritten.ends_with('\n') {
        rewritten.push('\n');
    }
    if !rewritten.trim().is_empty() && !rewritten.ends_with("\n\n") {
        rewritten.push('\n');
    }
    rewritten.push_str("[[skills.config]]\npath = ");
    rewritten.push_str(&rendered_path);
    rewritten.push_str("\nenabled = ");
    rewritten.push_str(if enabled { "true" } else { "false" });
    rewritten.push('\n');
    Ok(rewritten)
}

fn toml_table_bool(section: &str, key: &str) -> Result<Option<bool>, String> {
    let Some(assignment) = crate::toml_syntax::top_level_assignment(section, key) else {
        return Ok(None);
    };
    match assignment
        .value
        .split('#')
        .next()
        .unwrap_or_default()
        .trim()
    {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        value => Err(format!("{key} must be true or false, got {value}")),
    }
}

fn set_toml_table_bool(
    raw: &str,
    table_prefix: &str,
    table_id: &str,
    key: &str,
    value: bool,
) -> Result<String, String> {
    ensure_unique_standard_toml_tables(raw)?;
    let section = find_toml_table_section(raw, table_prefix, table_id)
        .ok_or_else(|| format!("TOML section not found: [{table_prefix}.{table_id}]"))?;
    let rewritten_section = set_toml_section_bool(section.content, key, value)?;

    let mut rewritten = String::with_capacity(raw.len() + rewritten_section.len());
    rewritten.push_str(&raw[..section.start]);
    rewritten.push_str(&rewritten_section);
    rewritten.push_str(&raw[section.end..]);
    Ok(rewritten)
}

fn ensure_unique_standard_toml_tables(raw: &str) -> Result<(), String> {
    let malformed_table_headers = malformed_table_header_lines(raw);
    if !malformed_table_headers.is_empty() {
        return Err(format!(
            "Codex config contains malformed TOML table headers on lines: {}",
            malformed_table_headers
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let duplicates = duplicate_standard_table_names(raw);
    if !duplicates.is_empty() {
        return Err(format!(
            "Codex config contains duplicate TOML table declarations: {}",
            duplicates.join(", ")
        ));
    }

    let duplicate_enabled_keys = duplicate_top_level_key_tables(raw, "enabled");
    if !duplicate_enabled_keys.is_empty() {
        return Err(format!(
            "Codex config contains duplicate enabled keys in TOML tables: {}",
            duplicate_enabled_keys.join(", ")
        ));
    }

    Ok(())
}

fn set_toml_section_bool(section: &str, key: &str, value: bool) -> Result<String, String> {
    let rendered_value = if value { "true" } else { "false" };
    if let Some(assignment) = crate::toml_syntax::top_level_assignment(section, key) {
        let existing_len = if assignment.value.starts_with("true")
            && valid_toml_bool_tail(&assignment.value[4..])
        {
            4
        } else if assignment.value.starts_with("false")
            && valid_toml_bool_tail(&assignment.value[5..])
        {
            5
        } else {
            return Err(format!(
                "{key} must be true or false, got {}",
                assignment.value
            ));
        };
        let value_end = assignment.value_start + existing_len;
        let mut rewritten = String::with_capacity(section.len());
        rewritten.push_str(&section[..assignment.value_start]);
        rewritten.push_str(rendered_value);
        rewritten.push_str(&section[value_end..]);
        return Ok(rewritten);
    }

    let header_end = section.find('\n').map_or(section.len(), |index| index + 1);
    let newline = if section[..header_end].ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut rewritten = String::with_capacity(section.len() + key.len() + 10);
    rewritten.push_str(&section[..header_end]);
    if !section[..header_end].ends_with('\n') {
        rewritten.push_str(newline);
    }
    rewritten.push_str(key);
    rewritten.push_str(" = ");
    rewritten.push_str(rendered_value);
    rewritten.push_str(newline);
    rewritten.push_str(&section[header_end..]);
    Ok(rewritten)
}

fn valid_toml_bool_tail(tail: &str) -> bool {
    let tail = tail.trim_start();
    tail.is_empty() || tail.starts_with('#')
}

fn append_toml_table_section(raw: &str, section: &str) -> String {
    let trailing_start = raw
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_whitespace())
        .map_or(0, |(index, character)| index + character.len_utf8());
    let (body, trailing) = raw.split_at(trailing_start);
    let newline = if raw.contains("\r\n") || section.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut rewritten = String::with_capacity(raw.len() + section.len() + newline.len() * 2);
    rewritten.push_str(body);
    if !body.is_empty() {
        rewritten.push_str(newline);
        rewritten.push_str(newline);
    }
    rewritten.push_str(section);
    if !section.ends_with('\n') && !trailing.starts_with(['\r', '\n']) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(trailing);
    rewritten
}

fn current_backup_metadata() -> Result<(String, String), String> {
    Ok((current_backup_id()?, current_timestamp()?))
}

fn current_backup_id() -> Result<String, String> {
    if let Some(backup_id) = TRANSITION_BACKUP_ID_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return Ok(backup_id);
    }
    unix_nanos_id("backup")
}
