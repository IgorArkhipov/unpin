use std::{
    fmt,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalResourceBinding, CONTROL_APPROVAL_AUDIENCE,
        CONTROL_APPROVAL_ISSUER, ControlApprovalContext, ControlAuthorization,
        ControlOperationKind,
    },
    control_operation::{
        DurableControlError, DurableControlJournal, DurableControlStart, DurableControlTerminal,
        DurableControlTerminalStatus,
    },
    discovery::ProviderId,
    mutation::{
        BackupAuthenticationKey, BackupAuthenticationStatus, BackupEntry, BackupManifest,
        RestoreBackupInput, RestoreResult, RestoreStatus, acquire_mutation_lock,
        backup_payload_path, load_backup_manifest, load_backup_summary_authenticated,
        read_cursor_workspace_disabled_server_ids_raw_optional, restore_backup_locked,
    },
    sessions::{SessionAuthorityKey, SessionManager},
    transitions::{
        EffectActivation, EffectAuthority, TransitionConflict, TransitionConflictChecker,
        TransitionContext, TransitionEffect, TransitionEffectKind, TransitionKind, TransitionPlan,
        TransitionPlanError,
    },
};

use super::backup_authentication::digest_backup_payload;

pub const RESTORE_CONTROL_PLAN_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreResourceState {
    pub resource_id: String,
    pub path: String,
    pub pre_state_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreControlPlan {
    pub schema_version: u32,
    pub backup_id: String,
    /// The first bundle provider, retained as a representative for existing
    /// callers. `providers` is the complete restore authority coverage.
    pub provider: ProviderId,
    pub providers: Vec<ProviderId>,
    pub repository_key: String,
    pub workspace_key: String,
    pub authentication: BackupAuthenticationStatus,
    pub affected_resources: Vec<RestoreResourceState>,
    pub activation: EffectActivation,
    pub plan_fingerprint: String,
}

impl RestoreControlPlan {
    pub fn verify(&self) -> Result<(), RestoreControlError> {
        if self.schema_version != RESTORE_CONTROL_PLAN_SCHEMA_VERSION {
            return Err(RestoreControlError::InvalidPlan);
        }
        let actual = self.fingerprint()?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(RestoreControlError::PlanFingerprintMismatch)
        }
    }

    pub fn approval_expectation(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<ApprovalExpectation, RestoreControlError> {
        self.verify()?;
        if self.repository_key != context.repository_key()
            || self.workspace_key != context.workspace_key()
        {
            return Err(RestoreControlError::ContextMismatch);
        }
        Ok(ApprovalExpectation {
            issuer: CONTROL_APPROVAL_ISSUER.to_string(),
            audience: CONTROL_APPROVAL_AUDIENCE.to_string(),
            operation_id: format!("restore-backup-{}", self.plan_fingerprint),
            operation_kind: ControlOperationKind::RestoreBackup.as_str().to_string(),
            effect_graph_digest: self.plan_fingerprint.clone(),
            repository_key: self.repository_key.clone(),
            workspace_key: self.workspace_key.clone(),
            session_id: None,
            profile_digest: None,
            resources: self
                .affected_resources
                .iter()
                .map(|resource| ApprovalResourceBinding {
                    resource_id: resource.resource_id.clone(),
                    pre_state_fingerprint: Some(resource.pre_state_fingerprint.clone()),
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RestoreController {
    app_state_root: PathBuf,
    session_authority_key: Option<SessionAuthorityKey>,
    journal: DurableControlJournal,
}

impl RestoreController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            journal: DurableControlJournal::new(&app_state_root),
            app_state_root,
            session_authority_key: None,
        }
    }

    #[must_use]
    pub fn with_session_authority_key(
        app_state_root: impl Into<PathBuf>,
        session_authority_key: SessionAuthorityKey,
    ) -> Self {
        let app_state_root = app_state_root.into();
        Self {
            journal: DurableControlJournal::new(&app_state_root),
            app_state_root,
            session_authority_key: Some(session_authority_key),
        }
    }

    pub fn plan(
        &self,
        backup_id: &str,
        context: &ControlApprovalContext,
        backup_authentication_key: Option<&BackupAuthenticationKey>,
    ) -> Result<RestoreControlPlan, RestoreControlError> {
        let summary = load_backup_summary_authenticated(
            &self.app_state_root,
            backup_id,
            backup_authentication_key,
        )
        .ok_or_else(|| RestoreControlError::BackupNotFound(backup_id.to_string()))?;
        if !summary.restorable || summary.authentication != BackupAuthenticationStatus::Verified {
            return Err(RestoreControlError::BackupNotRestorable(
                backup_id.to_string(),
            ));
        }
        let manifest =
            load_backup_manifest(&self.app_state_root, backup_id, backup_authentication_key)
                .map_err(RestoreControlError::BackupManifest)?;
        let mut affected_resources = manifest
            .entries
            .iter()
            .map(|entry| restore_resource_state(Path::new(&entry.target.path)))
            .collect::<Result<Vec<_>, _>>()?;
        affected_resources.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        affected_resources.dedup_by(|left, right| left.resource_id == right.resource_id);
        let activation = EffectActivation::Live;
        let providers = ProviderId::ALL
            .into_iter()
            .filter(|provider| summary.includes_provider(*provider))
            .collect::<Vec<_>>();
        let mut plan = RestoreControlPlan {
            schema_version: RESTORE_CONTROL_PLAN_SCHEMA_VERSION,
            backup_id: summary.backup_id,
            provider: summary.selection.provider,
            providers,
            repository_key: context.repository_key().to_string(),
            workspace_key: context.workspace_key().to_string(),
            authentication: summary.authentication,
            affected_resources,
            activation,
            plan_fingerprint: String::new(),
        };
        plan.plan_fingerprint = plan.fingerprint()?;
        Ok(plan)
    }

    pub fn apply(
        &self,
        reviewed_plan: &RestoreControlPlan,
        authorization: ControlAuthorization,
        context: &ControlApprovalContext,
        backup_authentication_key: Option<BackupAuthenticationKey>,
    ) -> Result<RestoreResult, RestoreControlError> {
        let expectation = reviewed_plan.approval_expectation(context)?;
        authorization.assert_matches(&expectation)?;
        reviewed_plan.verify()?;
        let transition = reviewed_plan.transition_plan(context)?;
        let session_authority_key = self
            .session_authority_key
            .as_ref()
            .ok_or(RestoreControlError::SessionAuthorityRequired)?;
        let session_manager =
            SessionManager::with_authority_key(&self.app_state_root, session_authority_key.clone());
        let _conflict_guard = session_manager.acquire(&transition)?;
        let mutation_lock = acquire_mutation_lock(&self.app_state_root)
            .map_err(RestoreControlError::MutationLock)?;
        let journal = match self
            .journal
            .begin(&transition, &authorization, "unpin-restore")?
        {
            DurableControlStart::Apply(journal) => journal,
            DurableControlStart::Cached(terminal) => {
                return self.cached_restore_result(
                    reviewed_plan,
                    backup_authentication_key.as_ref(),
                    &terminal,
                );
            }
        };
        if journal.is_resumed() {
            let manifest = load_backup_manifest(
                &self.app_state_root,
                &reviewed_plan.backup_id,
                backup_authentication_key.as_ref(),
            )
            .map_err(RestoreControlError::BackupManifest)?;
            let backup_root = self
                .app_state_root
                .join("backups")
                .join(&manifest.backup_id);
            match restored_targets_match(&backup_root, &manifest) {
                Ok(true) => {
                    let result = RestoreResult {
                        status: RestoreStatus::Restored,
                        backup_id: manifest.backup_id.clone(),
                        affected_targets: manifest.affected_targets,
                        reason: None,
                    };
                    journal.commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
                    return Ok(result);
                }
                Ok(false) => {}
                Err(_) => {
                    journal.needs_repair("control-resume-verification-failed")?;
                    return Err(RestoreControlError::Durable(
                        DurableControlError::RecoveryRequired(expectation.operation_id),
                    ));
                }
            }
        }
        let current = match self.plan(
            &reviewed_plan.backup_id,
            context,
            backup_authentication_key.as_ref(),
        ) {
            Ok(current) => current,
            Err(error) => {
                journal.abort("control-plan-invalid")?;
                return Err(error);
            }
        };
        if current.plan_fingerprint != reviewed_plan.plan_fingerprint {
            if journal.is_resumed() {
                journal.needs_repair("control-resume-state-diverged")?;
                return Err(RestoreControlError::Durable(
                    DurableControlError::RecoveryRequired(expectation.operation_id),
                ));
            }
            journal.abort("control-plan-drift")?;
            return Err(RestoreControlError::PlanFingerprintMismatch);
        }
        let result = restore_backup_locked(
            RestoreBackupInput {
                app_state_root: self.app_state_root.clone(),
                backup_id: current.backup_id,
                backup_authentication_key,
            },
            &mutation_lock,
        );
        if result.status == RestoreStatus::Restored {
            journal.commit_with_terminal_status(DurableControlTerminalStatus::Applied)?;
        } else {
            journal.needs_repair("restore-failed")?;
        }
        Ok(result)
    }

    fn cached_restore_result(
        &self,
        reviewed_plan: &RestoreControlPlan,
        backup_authentication_key: Option<&BackupAuthenticationKey>,
        terminal: &DurableControlTerminal,
    ) -> Result<RestoreResult, RestoreControlError> {
        if terminal.status != DurableControlTerminalStatus::Applied {
            return Err(RestoreControlError::Durable(
                DurableControlError::RecoveryRequired(terminal.operation_id.clone()),
            ));
        }
        let manifest = load_backup_manifest(
            &self.app_state_root,
            &reviewed_plan.backup_id,
            backup_authentication_key,
        )
        .map_err(|_| {
            RestoreControlError::Durable(DurableControlError::RecoveryRequired(
                terminal.operation_id.clone(),
            ))
        })?;
        let backup_root = self
            .app_state_root
            .join("backups")
            .join(&manifest.backup_id);
        match restored_targets_match(&backup_root, &manifest) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                return Err(RestoreControlError::Durable(
                    DurableControlError::RecoveryRequired(terminal.operation_id.clone()),
                ));
            }
        }
        Ok(RestoreResult {
            status: RestoreStatus::Restored,
            backup_id: manifest.backup_id.clone(),
            affected_targets: manifest.affected_targets,
            reason: None,
        })
    }
}

fn restored_targets_match(backup_root: &Path, manifest: &BackupManifest) -> Result<bool, String> {
    for entry in &manifest.entries {
        let matches = match entry.target.target_type.as_str() {
            "path" => restored_path_matches(manifest, entry)?,
            "sqlite-item" => restored_sqlite_item_matches(backup_root, entry)?,
            target_type => return Err(format!("unsupported restore target type: {target_type}")),
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

fn restored_path_matches(manifest: &BackupManifest, entry: &BackupEntry) -> Result<bool, String> {
    let target = Path::new(&entry.target.path);
    if !entry.existed {
        return match fs::symlink_metadata(target) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.to_string()),
        };
    }
    let expected = manifest
        .authenticity
        .as_ref()
        .and_then(|authenticity| {
            authenticity
                .payload_digests
                .iter()
                .find(|digest| digest.entry_id == entry.entry_id)
        })
        .ok_or_else(|| {
            format!(
                "authenticated payload digest missing for {}",
                entry.entry_id
            )
        })?;
    let actual = digest_backup_payload(target).map_err(|error| error.to_string())?;
    Ok(actual == expected.digest)
}

fn restored_sqlite_item_matches(backup_root: &Path, entry: &BackupEntry) -> Result<bool, String> {
    let target = Path::new(&entry.target.path);
    let current = match fs::symlink_metadata(target) {
        Ok(_) => read_cursor_workspace_disabled_server_ids_raw_optional(target)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    if !entry.existed {
        return Ok(current.is_none());
    }
    let payload = entry
        .payload
        .as_ref()
        .ok_or_else(|| format!("backup payload missing for {}", entry.entry_id))?;
    let expected =
        fs::read(backup_payload_path(backup_root, payload)?).map_err(|error| error.to_string())?;
    Ok(current.as_deref() == Some(expected.as_slice()))
}

impl RestoreControlPlan {
    fn transition_plan(
        &self,
        context: &ControlApprovalContext,
    ) -> Result<TransitionPlan, RestoreControlError> {
        let expectation = self.approval_expectation(context)?;
        let effects = self
            .affected_resources
            .iter()
            .enumerate()
            .map(|(index, resource)| TransitionEffect {
                effect_id: format!("restore-effect-{index}"),
                kind: TransitionEffectKind::RestoreView,
                resource_id: resource.resource_id.clone(),
                target_type: "restore-target".to_string(),
                summary: "Restore authenticated backup target".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: self.activation,
                expected_pre_fingerprint: Some(resource.pre_state_fingerprint.clone()),
                expected_post_fingerprint: Some(crate::encode_lower_hex(&Sha256::digest(
                    format!("{}:{}", self.backup_id, resource.resource_id).as_bytes(),
                ))),
                provider_views: self.providers.clone(),
            })
            .collect();
        TransitionPlan::new(
            expectation.operation_id,
            TransitionKind::RestoreNative,
            TransitionContext {
                repository_key: self.repository_key.clone(),
                workspace_key: self.workspace_key.clone(),
                session_id: None,
                profile_digest: None,
            },
            effects,
        )
        .map_err(RestoreControlError::TransitionPlan)
    }
}

fn restore_resource_state(path: &Path) -> Result<RestoreResourceState, RestoreControlError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(RestoreControlError::UnsupportedTarget(path.to_path_buf()));
    }
    let rendered = path.to_string_lossy().into_owned();
    let resource_digest = crate::encode_lower_hex(&Sha256::digest(rendered.as_bytes()));
    Ok(RestoreResourceState {
        resource_id: format!("restore-resource-{resource_digest}"),
        path: rendered,
        pre_state_fingerprint: fingerprint_path(path)?,
    })
}

fn fingerprint_path(path: &Path) -> Result<String, RestoreControlError> {
    let mut hasher = Sha256::new();
    hash_path(&mut hasher, path, path)?;
    Ok(crate::encode_lower_hex(&hasher.finalize()))
}

fn hash_path(hasher: &mut Sha256, root: &Path, path: &Path) -> Result<(), RestoreControlError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(b"absent\0");
            return Ok(());
        }
        Err(error) => return Err(RestoreControlError::Io(path.to_path_buf(), error)),
    };
    if metadata.file_type().is_symlink() {
        hasher.update(b"symlink\0");
        let target = fs::read_link(path)
            .map_err(|error| RestoreControlError::Io(path.to_path_buf(), error))?;
        hasher.update(target.to_string_lossy().as_bytes());
        hasher.update([0]);
        return Ok(());
    }
    let relative = path.strip_prefix(root).unwrap_or(path);
    hasher.update(relative.to_string_lossy().as_bytes());
    hasher.update([0]);
    if metadata.is_file() {
        hasher.update(b"file\0");
        let mut file =
            File::open(path).map_err(|error| RestoreControlError::Io(path.to_path_buf(), error))?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| RestoreControlError::Io(path.to_path_buf(), error))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        return Ok(());
    }
    if metadata.is_dir() {
        hasher.update(b"directory\0");
        let mut entries = fs::read_dir(path)
            .map_err(|error| RestoreControlError::Io(path.to_path_buf(), error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RestoreControlError::Io(path.to_path_buf(), error))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            hash_path(hasher, root, &entry.path())?;
        }
        return Ok(());
    }
    Err(RestoreControlError::UnsupportedTarget(path.to_path_buf()))
}

impl RestoreControlPlan {
    fn fingerprint(&self) -> Result<String, RestoreControlError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FingerprintBody<'a> {
            schema_version: u32,
            backup_id: &'a str,
            provider: ProviderId,
            providers: &'a [ProviderId],
            repository_key: &'a str,
            workspace_key: &'a str,
            authentication: BackupAuthenticationStatus,
            affected_resources: &'a [RestoreResourceState],
            activation: EffectActivation,
        }
        let body = FingerprintBody {
            schema_version: self.schema_version,
            backup_id: &self.backup_id,
            provider: self.provider,
            providers: &self.providers,
            repository_key: &self.repository_key,
            workspace_key: &self.workspace_key,
            authentication: self.authentication,
            affected_resources: &self.affected_resources,
            activation: self.activation,
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| RestoreControlError::Serialization(error.to_string()))?;
        Ok(crate::encode_lower_hex(&Sha256::digest(bytes)))
    }
}

#[derive(Debug)]
pub enum RestoreControlError {
    Approval(ApprovalError),
    Durable(DurableControlError),
    TransitionPlan(TransitionPlanError),
    TransitionConflict(TransitionConflict),
    BackupNotFound(String),
    BackupNotRestorable(String),
    BackupManifest(String),
    MutationLock(String),
    SessionAuthorityRequired,
    InvalidPlan,
    ContextMismatch,
    PlanFingerprintMismatch,
    UnsupportedTarget(PathBuf),
    Io(PathBuf, std::io::Error),
    Serialization(String),
}

impl From<ApprovalError> for RestoreControlError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<DurableControlError> for RestoreControlError {
    fn from(error: DurableControlError) -> Self {
        Self::Durable(error)
    }
}

impl From<TransitionConflict> for RestoreControlError {
    fn from(error: TransitionConflict) -> Self {
        Self::TransitionConflict(error)
    }
}

impl fmt::Display for RestoreControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => error.fmt(formatter),
            Self::Durable(error) => error.fmt(formatter),
            Self::TransitionPlan(error) => error.fmt(formatter),
            Self::TransitionConflict(error) => {
                write!(formatter, "restore blocked by {}", error.code())
            }
            Self::BackupNotFound(id) => write!(formatter, "backup not found: {id}"),
            Self::BackupNotRestorable(id) => write!(formatter, "backup is not restorable: {id}"),
            Self::BackupManifest(error) => write!(formatter, "backup manifest is invalid: {error}"),
            Self::MutationLock(error) => write!(formatter, "restore mutation lock: {error}"),
            Self::SessionAuthorityRequired => {
                formatter.write_str("session authority key is required to check restore conflicts")
            }
            Self::InvalidPlan => formatter.write_str("restore plan is invalid"),
            Self::ContextMismatch => {
                formatter.write_str("restore plan context does not match workspace")
            }
            Self::PlanFingerprintMismatch => {
                formatter.write_str("reviewed restore plan no longer matches current state")
            }
            Self::UnsupportedTarget(path) => {
                write!(formatter, "unsupported restore target: {}", path.display())
            }
            Self::Io(path, error) => {
                write!(formatter, "restore target {}: {error}", path.display())
            }
            Self::Serialization(message) => {
                write!(formatter, "restore plan serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for RestoreControlError {}
