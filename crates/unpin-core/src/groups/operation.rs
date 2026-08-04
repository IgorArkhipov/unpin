use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use crate::{
    approval::ApprovalExpectation,
    clock::current_timestamp,
    control_operation::{
        ControlOperationEnvelope, ControlOperationLifecycle, ControlResolvedContext,
    },
    fs_support::read_optional_dir,
    groups::{GroupMemberIdentity, GroupState, GroupTargetState, GroupTogglePlan},
    mutation::{BackupAuthenticationKey, authenticated_backup_manifest_digest},
    provider_reach::{ProviderReach, ProviderReachCoverage, ProviderReachLifecycle},
    providers::ProviderId,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
    transitions::EffectActivation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const GROUP_OPERATION_STATE_SCHEMA_VERSION: u32 = 1;
const GROUP_COHORT_BACKUP_INDEX_SCHEMA_VERSION: u32 = 1;
const GROUP_CONTROL_DETAILS_SCHEMA_VERSION: u8 = 1;
const GROUP_OPERATION_AUTHENTICATION_PURPOSE: &[u8] =
    b"unpin-inventory-group-operation-record-v1\0";
const GROUP_COHORT_INDEX_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-inventory-group-cohort-index-v1\0";

fn default_provider_reach() -> ProviderReach {
    ProviderReach::All
}

fn default_provider_coverage() -> ProviderReachCoverage {
    ProviderReachCoverage::new(Vec::new())
}

fn default_provider_reach_lifecycle() -> ProviderReachLifecycle {
    ProviderReachLifecycle::Applied
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupRecoveryPolicy {
    NoResumeWrites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupOperationLifecycle {
    InProgress,
    Completed,
    Partial,
    Failed,
    RecoveryRequired,
}

impl GroupOperationLifecycle {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::InProgress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupApplyMemberStatus {
    Changed,
    AlreadyCorrect,
    Blocked,
    Missing,
    OutOfProviderReach,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupMemberFailureMode {
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupApplyMemberResult {
    pub identity: GroupMemberIdentity,
    pub status: GroupApplyMemberStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<GroupMemberFailureMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupApplyResult {
    pub operation_id: String,
    pub qualified_name: String,
    pub plan_fingerprint: String,
    pub requested_state: GroupTargetState,
    pub lifecycle: GroupOperationLifecycle,
    #[serde(default = "default_provider_reach")]
    pub provider_reach: ProviderReach,
    #[serde(default = "default_provider_coverage")]
    pub provider_coverage: ProviderReachCoverage,
    #[serde(default = "default_provider_reach_lifecycle")]
    pub provider_reach_lifecycle: ProviderReachLifecycle,
    pub members: Vec<GroupApplyMemberResult>,
    pub backup_ids: Vec<String>,
    pub final_state: GroupState,
    pub observation_fresh: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_reason: Option<String>,
}

impl GroupApplyResult {
    pub fn control_operation_envelope(
        &self,
        expectation: &ApprovalExpectation,
        activation: EffectActivation,
        provider_coverage: Vec<ProviderId>,
    ) -> Result<ControlOperationEnvelope, GroupOperationError> {
        let lifecycle = match self.lifecycle {
            GroupOperationLifecycle::Completed => ControlOperationLifecycle::Applied,
            GroupOperationLifecycle::Partial | GroupOperationLifecycle::Failed => {
                ControlOperationLifecycle::Blocked
            }
            GroupOperationLifecycle::RecoveryRequired => {
                ControlOperationLifecycle::RecoveryRequired
            }
            GroupOperationLifecycle::InProgress => {
                return Err(GroupOperationError::InvalidRecord);
            }
        };
        Ok(ControlOperationEnvelope::new(
            self.operation_id.clone(),
            expectation.operation_kind.clone(),
            self.plan_fingerprint.clone(),
            ControlResolvedContext {
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
            },
            lifecycle,
            activation,
            None,
            false,
            provider_coverage,
            json!({
                "schemaVersion": GROUP_CONTROL_DETAILS_SCHEMA_VERSION,
                "groupStatus": self.lifecycle,
                "result": self,
            }),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupOperationRecord {
    pub schema_version: u8,
    pub operation_id: String,
    pub qualified_name: String,
    pub plan_fingerprint: String,
    pub requested_state: GroupTargetState,
    pub recovery_policy: GroupRecoveryPolicy,
    pub lifecycle: GroupOperationLifecycle,
    pub created_at: String,
    pub updated_at: String,
    pub authorization_decision_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorization_link: Option<GroupOperationAuthorizationLink>,
    #[serde(default)]
    pub provider_writes_started: bool,
    pub repository_key: String,
    pub workspace_key: String,
    pub sealed_plan: GroupTogglePlan,
    #[serde(default = "default_provider_reach")]
    pub provider_reach: ProviderReach,
    #[serde(default = "default_provider_coverage")]
    pub provider_coverage: ProviderReachCoverage,
    #[serde(default = "default_provider_reach_lifecycle")]
    pub provider_reach_lifecycle: ProviderReachLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<GroupApplyResult>,
    pub authentication_key_id: String,
    pub authentication_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupOperationAuthorizationLink {
    pub artifact_digest: String,
    pub nonce_digest: String,
    pub session_id: String,
    pub session_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupOperationPublicRecord {
    pub schema_version: u8,
    pub operation_id: String,
    pub qualified_name: String,
    pub plan_fingerprint: String,
    pub requested_state: GroupTargetState,
    pub recovery_policy: GroupRecoveryPolicy,
    pub lifecycle: GroupOperationLifecycle,
    pub created_at: String,
    pub updated_at: String,
    pub provider_writes_started: bool,
    pub provider_reach: ProviderReach,
    pub provider_coverage: ProviderReachCoverage,
    pub provider_reach_lifecycle: ProviderReachLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<GroupApplyResult>,
}

impl From<&GroupOperationRecord> for GroupOperationPublicRecord {
    fn from(record: &GroupOperationRecord) -> Self {
        Self {
            schema_version: record.schema_version,
            operation_id: record.operation_id.clone(),
            qualified_name: record.qualified_name.clone(),
            plan_fingerprint: record.plan_fingerprint.clone(),
            requested_state: record.requested_state,
            recovery_policy: record.recovery_policy,
            lifecycle: record.lifecycle,
            created_at: record.created_at.clone(),
            updated_at: record.updated_at.clone(),
            provider_writes_started: record.provider_writes_started,
            provider_reach: record.provider_reach,
            provider_coverage: record.provider_coverage.clone(),
            provider_reach_lifecycle: record.provider_reach_lifecycle,
            terminal_result: record.terminal_result.clone(),
        }
    }
}

impl GroupOperationRecord {
    pub(crate) fn in_progress(
        sealed_plan: GroupTogglePlan,
        authorization_decision_digest: String,
        authorization_link: Option<GroupOperationAuthorizationLink>,
        repository_key: String,
        workspace_key: String,
    ) -> Result<Self, GroupOperationError> {
        let timestamp = current_timestamp().map_err(GroupOperationError::Clock)?;
        let operation_id = sealed_plan
            .operation_id
            .clone()
            .ok_or(GroupOperationError::InvalidRecord)?;
        Ok(Self {
            schema_version: 1,
            operation_id,
            qualified_name: sealed_plan.qualified_name.clone(),
            plan_fingerprint: sealed_plan.plan_fingerprint.clone(),
            requested_state: sealed_plan.target,
            recovery_policy: GroupRecoveryPolicy::NoResumeWrites,
            lifecycle: GroupOperationLifecycle::InProgress,
            created_at: timestamp.clone(),
            updated_at: timestamp,
            authorization_decision_digest,
            authorization_link,
            provider_writes_started: false,
            repository_key,
            workspace_key,
            sealed_plan: sealed_plan.clone(),
            provider_reach: sealed_plan.provider_reach,
            provider_coverage: sealed_plan.provider_coverage.clone(),
            provider_reach_lifecycle: sealed_plan.lifecycle,
            terminal_result: None,
            authentication_key_id: String::new(),
            authentication_tag: String::new(),
        })
    }

    pub(crate) fn mark_provider_writes_started(&mut self) -> Result<(), GroupOperationError> {
        if self.lifecycle != GroupOperationLifecycle::InProgress
            || self.terminal_result.is_some()
            || self.provider_writes_started
        {
            return Err(GroupOperationError::InvalidRecord);
        }
        self.provider_writes_started = true;
        self.updated_at = current_timestamp().map_err(GroupOperationError::Clock)?;
        Ok(())
    }

    pub(crate) fn terminalize(
        &mut self,
        result: GroupApplyResult,
    ) -> Result<(), GroupOperationError> {
        if !result.lifecycle.is_terminal()
            || result.operation_id != self.operation_id
            || result.plan_fingerprint != self.plan_fingerprint
            || result.provider_reach != self.provider_reach
            || result.provider_coverage != self.provider_coverage
            || result.provider_reach_lifecycle != self.provider_reach_lifecycle
        {
            return Err(GroupOperationError::InvalidRecord);
        }
        self.lifecycle = result.lifecycle;
        self.updated_at = current_timestamp().map_err(GroupOperationError::Clock)?;
        self.terminal_result = Some(result);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GroupOperationStore {
    app_state_root: PathBuf,
    authentication_key: BackupAuthenticationKey,
}

impl GroupOperationStore {
    pub(crate) fn new(
        app_state_root: PathBuf,
        authentication_key: BackupAuthenticationKey,
    ) -> Self {
        Self {
            app_state_root,
            authentication_key,
        }
    }

    pub(crate) fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<StateSnapshot<GroupOperationRecord>>, GroupOperationError> {
        validate_operation_id(operation_id)?;
        let snapshot = self.store(operation_id).load::<GroupOperationRecord>()?;
        if let Some(snapshot) = &snapshot {
            validate_record(&snapshot.value, operation_id, &self.authentication_key)?;
        }
        Ok(snapshot)
    }

    pub(crate) fn create(
        &self,
        record: &GroupOperationRecord,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, GroupOperationError> {
        let mut record = record.clone();
        sign_record(&mut record, &self.authentication_key)?;
        self.store(&record.operation_id)
            .compare_and_swap(None, owner, &record)
            .map_err(Into::into)
    }

    pub(crate) fn save(
        &self,
        record: &GroupOperationRecord,
        expected: &StateRevision,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, GroupOperationError> {
        let mut record = record.clone();
        sign_record(&mut record, &self.authentication_key)?;
        self.store(&record.operation_id)
            .compare_and_swap(Some(expected), owner, &record)
            .map_err(Into::into)
    }

    pub(crate) fn save_backup_index(
        &self,
        index: &GroupCohortBackupIndexV1,
        owner: OwnerGeneration,
    ) -> Result<(), GroupOperationError> {
        index.verify(&self.authentication_key)?;
        AtomicJsonStore::new(
            operations_root(&self.app_state_root)
                .join(&index.operation_id)
                .join("cohorts")
                .join(format!("{}.json", index.cohort_id)),
            GROUP_COHORT_BACKUP_INDEX_SCHEMA_VERSION,
        )
        .compare_and_swap(None, owner, index)
        .map(|_| ())
        .map_err(Into::into)
    }

    pub(crate) fn load_backup_indexes(
        &self,
        plan: &GroupTogglePlan,
    ) -> Result<Vec<GroupCohortBackupIndexV1>, GroupOperationError> {
        let operation_id = plan
            .operation_id
            .as_deref()
            .ok_or(GroupOperationError::InvalidRecord)?;
        validate_operation_id(operation_id)?;
        let mut indexes = Vec::new();
        for cohort in &plan.cohorts {
            let Some(snapshot) = AtomicJsonStore::new(
                operations_root(&self.app_state_root)
                    .join(operation_id)
                    .join("cohorts")
                    .join(format!("{}.json", cohort.cohort_id)),
                GROUP_COHORT_BACKUP_INDEX_SCHEMA_VERSION,
            )
            .load::<GroupCohortBackupIndexV1>()?
            else {
                continue;
            };
            snapshot.value.verify(&self.authentication_key)?;
            if snapshot.value.operation_id != operation_id
                || snapshot.value.cohort_id != cohort.cohort_id
            {
                return Err(GroupOperationError::InvalidBackupIndex);
            }
            indexes.push(snapshot.value);
        }
        Ok(indexes)
    }

    fn store(&self, operation_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            operation_record_path(&self.app_state_root, operation_id),
            GROUP_OPERATION_STATE_SCHEMA_VERSION,
        )
    }
}

fn operations_root(app_state_root: &Path) -> PathBuf {
    app_state_root.join("groups").join("operations")
}

fn operation_record_path(app_state_root: &Path, operation_id: &str) -> PathBuf {
    operations_root(app_state_root).join(format!("{operation_id}.json"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupOperationInspection {
    pub operation: GroupOperationPublicRecord,
    pub cohort_backup_indexes: Vec<GroupCohortBackupPublicIndex>,
    pub evidence_available: bool,
}

pub fn load_group_operation_inspection(
    app_state_root: impl Into<PathBuf>,
    authentication_key: BackupAuthenticationKey,
    operation_id: &str,
    repository_key: &str,
    workspace_key: &str,
) -> Result<Option<GroupOperationInspection>, GroupOperationError> {
    let app_state_root = app_state_root.into();
    let store = GroupOperationStore::new(app_state_root.clone(), authentication_key.clone());
    let Some(snapshot) = store.load(operation_id)? else {
        return Ok(None);
    };
    let record = snapshot.value;
    if record.repository_key != repository_key || record.workspace_key != workspace_key {
        return Err(GroupOperationError::ContextMismatch);
    }
    let (backup_indexes, indexes_available) = match store.load_backup_indexes(&record.sealed_plan) {
        Ok(indexes) => (indexes, true),
        // Do not hide a durable operation because its index cannot be read.
        // A write that lacks authenticated evidence is explicitly unsafe to
        // retry, so the public projection below marks it recovery-required.
        Err(_) => (Vec::new(), false),
    };
    let manifests_available = indexes_available
        && backup_indexes.iter().all(|index| {
            index.backup_ids.iter().all(|backup_id| {
                authenticated_backup_manifest_digest(
                    &app_state_root,
                    backup_id,
                    &authentication_key,
                )
                .is_ok()
            })
        });
    let evidence_available = manifests_available
        && if let Some(result) = record.terminal_result.as_ref() {
            backup_indexes_cover_result(result, &backup_indexes)
        } else {
            !record.provider_writes_started || !backup_indexes.is_empty()
        };
    let cohort_backup_indexes = backup_indexes
        .iter()
        .map(GroupCohortBackupPublicIndex::from)
        .collect();
    let mut operation = GroupOperationPublicRecord::from(&record);
    if record.provider_writes_started && !evidence_available {
        operation.lifecycle = GroupOperationLifecycle::RecoveryRequired;
        if let Some(result) = &mut operation.terminal_result {
            result.lifecycle = GroupOperationLifecycle::RecoveryRequired;
            result.final_state = GroupState::Mixed;
            result.observation_fresh = false;
            result.observation_reason =
                Some("observation-stale: authenticated backup evidence is unavailable".to_string());
            for member in &mut result.members {
                if member.status == GroupApplyMemberStatus::Changed || member.backup_id.is_some() {
                    member.status = GroupApplyMemberStatus::Failed;
                    member.failure_mode = Some(GroupMemberFailureMode::RecoveryRequired);
                    member.reason = Some(
                        "recovery-required: authenticated backup evidence is unavailable"
                            .to_string(),
                    );
                }
            }
        }
    }
    Ok(Some(GroupOperationInspection {
        operation,
        cohort_backup_indexes,
        evidence_available,
    }))
}

/// List authenticated group-operation evidence for one exact workspace.
///
/// Discovery of operation ids remains inside the core boundary: callers never
/// construct a filesystem path from a desktop-client supplied identifier.
pub fn list_group_operation_inspections(
    app_state_root: impl Into<PathBuf>,
    authentication_key: BackupAuthenticationKey,
    repository_key: &str,
    workspace_key: &str,
) -> Result<Vec<GroupOperationInspection>, GroupOperationError> {
    let app_state_root = app_state_root.into();
    let Some(entries) = read_optional_dir(&operations_root(&app_state_root))
        .map_err(|error| GroupOperationError::Io(error.to_string()))?
    else {
        return Ok(Vec::new());
    };
    let mut operation_ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| GroupOperationError::Io(error.to_string()))?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(operation_id) = file_name.strip_suffix(".json") else {
            continue;
        };
        validate_operation_id(operation_id)?;
        operation_ids.push(operation_id.to_string());
    }
    let mut inspections = Vec::new();
    for operation_id in operation_ids {
        match load_group_operation_inspection(
            app_state_root.clone(),
            authentication_key.clone(),
            &operation_id,
            repository_key,
            workspace_key,
        ) {
            Ok(Some(inspection)) => inspections.push(inspection),
            Ok(None) | Err(GroupOperationError::ContextMismatch) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(inspections)
}

fn backup_indexes_cover_result(
    result: &GroupApplyResult,
    indexes: &[GroupCohortBackupIndexV1],
) -> bool {
    let indexed_backup_ids = indexes
        .iter()
        .flat_map(|index| index.backup_ids.iter())
        .collect::<BTreeSet<_>>();
    if result
        .backup_ids
        .iter()
        .any(|backup_id| !indexed_backup_ids.contains(backup_id))
    {
        return false;
    }
    result.members.iter().all(|member| {
        if member.status != GroupApplyMemberStatus::Changed && member.backup_id.is_none() {
            return true;
        }
        indexes
            .iter()
            .flat_map(|index| &index.coverage)
            .any(|coverage| {
                coverage.member_identities.contains(&member.identity)
                    && member
                        .backup_id
                        .as_ref()
                        .is_none_or(|backup_id| coverage.backup_id == *backup_id)
            })
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCohortBackupIndexV1 {
    pub schema_version: u8,
    pub operation_id: String,
    pub cohort_id: String,
    pub member_identities: Vec<GroupMemberIdentity>,
    pub resource_ids: Vec<String>,
    pub backup_ids: Vec<String>,
    pub coverage: Vec<GroupCohortBackupCoverageV1>,
    pub authentication_key_id: String,
    pub integrity_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCohortBackupCoverageV1 {
    pub backup_id: String,
    pub member_identities: Vec<GroupMemberIdentity>,
    pub resource_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCohortBackupPublicIndex {
    pub schema_version: u8,
    pub operation_id: String,
    pub cohort_id: String,
    pub member_identities: Vec<GroupMemberIdentity>,
    pub resource_ids: Vec<String>,
    pub backup_ids: Vec<String>,
    pub coverage: Vec<GroupCohortBackupCoverageV1>,
}

impl From<&GroupCohortBackupIndexV1> for GroupCohortBackupPublicIndex {
    fn from(index: &GroupCohortBackupIndexV1) -> Self {
        Self {
            schema_version: index.schema_version,
            operation_id: index.operation_id.clone(),
            cohort_id: index.cohort_id.clone(),
            member_identities: index.member_identities.clone(),
            resource_ids: index.resource_ids.clone(),
            backup_ids: index.backup_ids.clone(),
            coverage: index.coverage.clone(),
        }
    }
}

impl GroupCohortBackupIndexV1 {
    pub fn new(
        operation_id: impl Into<String>,
        cohort_id: impl Into<String>,
        mut member_identities: Vec<GroupMemberIdentity>,
        mut resource_ids: Vec<String>,
        mut coverage: Vec<GroupCohortBackupCoverageV1>,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<Self, GroupOperationError> {
        member_identities.sort();
        member_identities.dedup();
        resource_ids.sort();
        resource_ids.dedup();
        for item in &mut coverage {
            item.member_identities.sort();
            item.member_identities.dedup();
            item.resource_ids.sort();
            item.resource_ids.dedup();
        }
        coverage.sort_by(|left, right| left.backup_id.cmp(&right.backup_id));
        let backup_ids = coverage
            .iter()
            .map(|item| item.backup_id.clone())
            .collect::<Vec<_>>();
        let mut index = Self {
            schema_version: 1,
            operation_id: operation_id.into(),
            cohort_id: cohort_id.into(),
            member_identities,
            resource_ids,
            backup_ids,
            coverage,
            authentication_key_id: authentication_key.key_id(),
            integrity_digest: String::new(),
        };
        index.integrity_digest = index.expected_digest(authentication_key)?;
        index.verify(authentication_key)?;
        Ok(index)
    }

    pub fn verify(
        &self,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<(), GroupOperationError> {
        validate_operation_id(&self.operation_id)?;
        if self.schema_version != 1
            || !valid_cohort_id(&self.cohort_id)
            || self.member_identities.is_empty()
            || self.resource_ids.is_empty()
            || self.coverage.is_empty()
            || self.backup_ids.is_empty()
            || self.authentication_key_id != authentication_key.key_id()
        {
            return Err(GroupOperationError::InvalidBackupIndex);
        }
        let members = self.member_identities.iter().collect::<BTreeSet<_>>();
        let resources = self.resource_ids.iter().collect::<BTreeSet<_>>();
        let mut previous_backup_id = None;
        for item in &self.coverage {
            if item.backup_id.is_empty()
                || item.member_identities.is_empty()
                || item.resource_ids.is_empty()
                || item
                    .member_identities
                    .iter()
                    .any(|identity| !members.contains(identity))
                || item
                    .resource_ids
                    .iter()
                    .any(|resource_id| !resources.contains(resource_id))
                || previous_backup_id.is_some_and(|previous| previous >= item.backup_id.as_str())
            {
                return Err(GroupOperationError::InvalidBackupIndex);
            }
            previous_backup_id = Some(item.backup_id.as_str());
        }
        if self.backup_ids
            != self
                .coverage
                .iter()
                .map(|item| item.backup_id.clone())
                .collect::<Vec<_>>()
        {
            return Err(GroupOperationError::InvalidBackupIndex);
        }
        let mut unsigned = self.clone();
        let tag = std::mem::take(&mut unsigned.integrity_digest);
        let bytes = serde_json::to_vec(&unsigned).map_err(GroupOperationError::Json)?;
        authentication_key
            .verify_purpose(GROUP_COHORT_INDEX_AUTHENTICATION_PURPOSE, &bytes, &tag)
            .map_err(|_| GroupOperationError::AuthenticationFailed)?;
        Ok(())
    }

    fn expected_digest(
        &self,
        authentication_key: &BackupAuthenticationKey,
    ) -> Result<String, GroupOperationError> {
        let mut unsigned = self.clone();
        unsigned.integrity_digest.clear();
        let bytes = serde_json::to_vec(&unsigned).map_err(GroupOperationError::Json)?;
        authentication_key
            .authenticate_purpose(GROUP_COHORT_INDEX_AUTHENTICATION_PURPOSE, &bytes)
            .map_err(GroupOperationError::Authentication)
    }
}

fn validate_record(
    record: &GroupOperationRecord,
    operation_id: &str,
    authentication_key: &BackupAuthenticationKey,
) -> Result<(), GroupOperationError> {
    validate_operation_id(operation_id)?;
    if record.schema_version != 1
        || record.operation_id != operation_id
        || record.plan_fingerprint.len() != 64
        || record.authorization_decision_digest.len() != 64
        || record.repository_key.is_empty()
        || record.workspace_key.is_empty()
        || record.authentication_key_id != authentication_key.key_id()
        || record.sealed_plan.operation_id.as_deref() != Some(operation_id)
        || record.sealed_plan.plan_fingerprint != record.plan_fingerprint
        || record.provider_reach != record.sealed_plan.provider_reach
        || record.provider_coverage != record.sealed_plan.provider_coverage
        || record.recovery_policy != GroupRecoveryPolicy::NoResumeWrites
        || record.lifecycle.is_terminal() != record.terminal_result.is_some()
        || record.authorization_link.as_ref().is_some_and(|link| {
            link.artifact_digest.len() != 64
                || !crate::is_lower_hex_digest(&link.artifact_digest)
                || link.nonce_digest.len() != 64
                || !crate::is_lower_hex_digest(&link.nonce_digest)
                || link.session_id.is_empty()
                || link.session_id.len() > 256
                || link.session_id.chars().any(char::is_control)
        })
    {
        return Err(GroupOperationError::InvalidRecord);
    }
    record
        .sealed_plan
        .verify()
        .map_err(|_| GroupOperationError::InvalidRecord)?;
    let mut unsigned = record.clone();
    let tag = std::mem::take(&mut unsigned.authentication_tag);
    let bytes = serde_json::to_vec(&unsigned).map_err(GroupOperationError::Json)?;
    authentication_key
        .verify_purpose(GROUP_OPERATION_AUTHENTICATION_PURPOSE, &bytes, &tag)
        .map_err(|_| GroupOperationError::AuthenticationFailed)?;
    Ok(())
}

fn sign_record(
    record: &mut GroupOperationRecord,
    authentication_key: &BackupAuthenticationKey,
) -> Result<(), GroupOperationError> {
    record.authentication_key_id = authentication_key.key_id();
    record.authentication_tag.clear();
    let bytes = serde_json::to_vec(record).map_err(GroupOperationError::Json)?;
    record.authentication_tag = authentication_key
        .authenticate_purpose(GROUP_OPERATION_AUTHENTICATION_PURPOSE, &bytes)
        .map_err(GroupOperationError::Authentication)?;
    validate_record(record, &record.operation_id, authentication_key)
}

fn validate_operation_id(operation_id: &str) -> Result<(), GroupOperationError> {
    if operation_id.is_empty()
        || operation_id.len() > 256
        || operation_id.chars().any(char::is_control)
        || operation_id.contains('/')
        || operation_id.contains('\\')
        || operation_id == "."
        || operation_id == ".."
    {
        return Err(GroupOperationError::InvalidOperationId);
    }
    Ok(())
}

fn valid_cohort_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[derive(Debug)]
pub enum GroupOperationError {
    State(StateError),
    Json(serde_json::Error),
    Io(String),
    Clock(String),
    InvalidOperationId,
    InvalidRecord,
    InvalidBackupIndex,
    ContextMismatch,
    Authentication(String),
    AuthenticationFailed,
}

impl From<StateError> for GroupOperationError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for GroupOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Json(error) => write!(formatter, "group operation JSON failed: {error}"),
            Self::Io(error) => write!(formatter, "group operation I/O failed: {error}"),
            Self::Clock(error) => write!(formatter, "group operation clock failed: {error}"),
            Self::InvalidOperationId => formatter.write_str("invalid group operation id"),
            Self::InvalidRecord => formatter.write_str("invalid group operation record"),
            Self::InvalidBackupIndex => formatter.write_str("invalid group cohort backup index"),
            Self::ContextMismatch => {
                formatter.write_str("group operation belongs to a different workspace context")
            }
            Self::Authentication(_) | Self::AuthenticationFailed => {
                formatter.write_str("group operation authentication failed")
            }
        }
    }
}

impl std::error::Error for GroupOperationError {}
