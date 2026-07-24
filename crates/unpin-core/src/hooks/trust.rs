use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

use crate::{
    approval::{
        ApprovalError, ApprovalReceipt, ApprovalVerifier, NonceConsumption, authorize_control,
    },
    config::get_hook_trust_path,
    hooks::HookInventoryMetadata,
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
};

const HOOK_TRUST_DOCUMENT_SCHEMA_VERSION: u32 = 1;
const LEGACY_HOOK_TRUST_RECORD_VERSION: u32 = 1;
const HOOK_TRUST_RECORD_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookTrustRecord {
    pub version: u32,
    pub provider: ProviderId,
    pub handler_id: String,
    pub handler_fingerprint: String,
    pub invocation_fingerprint: String,
    pub profile_digest: String,
    pub reviewed_at_unix: i64,
    pub decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookTrustStatus {
    pub operation_id: String,
    pub decision_digest: String,
    pub revision: StateRevision,
    pub nonce: NonceConsumption,
}

#[derive(Debug, Clone)]
pub struct HookTrustStore {
    app_state_root: PathBuf,
}

impl HookTrustStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        provider: ProviderId,
        handler_id: &str,
        metadata: &HookInventoryMetadata,
        profile_digest: &str,
        receipt: &ApprovalReceipt,
        verifier: &ApprovalVerifier,
        now_unix: i64,
        owner: OwnerGeneration,
        issuer: &str,
        audience: &str,
        repository_key: &str,
        workspace_key: &str,
        session_id: &str,
    ) -> Result<HookTrustStatus, HookTrustError> {
        let expectation = metadata.trust_approval_expectation(
            provider,
            handler_id,
            profile_digest,
            issuer,
            audience,
            repository_key,
            workspace_key,
            session_id,
        )?;
        let authorization = authorize_control(
            &self.app_state_root,
            receipt,
            verifier,
            &expectation,
            now_unix,
            owner.clone(),
        )?;
        let operation_id = authorization.operation_id().to_string();
        let decision_digest = authorization.decision_digest().to_string();
        let record = HookTrustRecord {
            version: HOOK_TRUST_RECORD_VERSION,
            provider,
            handler_id: handler_id.to_string(),
            handler_fingerprint: metadata.fingerprint.clone(),
            invocation_fingerprint: metadata.invocation_fingerprint.clone(),
            profile_digest: profile_digest.to_string(),
            reviewed_at_unix: receipt.claims.issued_at_unix,
            decision_digest: decision_digest.clone(),
        };
        let store = AtomicJsonStore::new(
            get_hook_trust_path(&self.app_state_root, &operation_id),
            HOOK_TRUST_DOCUMENT_SCHEMA_VERSION,
        );
        let revision = match store.compare_and_swap(None, owner.clone(), &record) {
            Ok(revision) => revision,
            Err(StateError::StaleRevision { .. }) => {
                let existing = store
                    .load::<Value>()?
                    .ok_or(HookTrustError::MissingRecord)?;
                match decode_record(existing.value, &operation_id)? {
                    StoredHookTrustRecord::Legacy => {
                        store.compare_and_swap(Some(&existing.revision), owner, &record)?
                    }
                    StoredHookTrustRecord::Current(existing_record) => {
                        if existing_record != record {
                            return Err(HookTrustError::ConflictingRecord);
                        }
                        existing.revision
                    }
                }
            }
            Err(error) => return Err(error.into()),
        };
        Ok(HookTrustStatus {
            operation_id,
            decision_digest,
            revision,
            nonce: authorization.nonce_consumption(),
        })
    }

    pub fn load(&self, operation_id: &str) -> Result<Option<HookTrustRecord>, HookTrustError> {
        let snapshot = AtomicJsonStore::new(
            get_hook_trust_path(&self.app_state_root, operation_id),
            HOOK_TRUST_DOCUMENT_SCHEMA_VERSION,
        )
        .load::<Value>()?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        match decode_record(snapshot.value, operation_id) {
            Ok(StoredHookTrustRecord::Current(record)) => Ok(Some(record)),
            Ok(StoredHookTrustRecord::Legacy) | Err(HookTrustError::InvalidRecord) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn load_for(
        &self,
        provider: ProviderId,
        handler_id: &str,
        metadata: &HookInventoryMetadata,
        profile_digest: &str,
    ) -> Result<Option<HookTrustRecord>, HookTrustError> {
        let operation_id = metadata.trust_operation_id(provider, handler_id, profile_digest)?;
        if let Some(record) = self.load(&operation_id)? {
            return Ok(Some(record));
        }
        let legacy_operation_id = metadata.legacy_trust_operation_id(provider, profile_digest)?;
        Ok(self.load(&legacy_operation_id)?.filter(|record| {
            record.provider == provider
                && record.handler_id == handler_id
                && record.handler_fingerprint == metadata.fingerprint
                && record.invocation_fingerprint == metadata.invocation_fingerprint
                && record.profile_digest == profile_digest
        }))
    }
}

enum StoredHookTrustRecord {
    Legacy,
    Current(HookTrustRecord),
}

fn decode_record(
    value: Value,
    operation_id: &str,
) -> Result<StoredHookTrustRecord, HookTrustError> {
    let version = value
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(HookTrustError::InvalidRecord)?;
    if version == u64::from(LEGACY_HOOK_TRUST_RECORD_VERSION) {
        return Ok(StoredHookTrustRecord::Legacy);
    }
    if version != u64::from(HOOK_TRUST_RECORD_VERSION) {
        return Err(HookTrustError::InvalidRecord);
    }
    let record = serde_json::from_value::<HookTrustRecord>(value)
        .map_err(|_| HookTrustError::InvalidRecord)?;
    validate_record(&record, operation_id)?;
    Ok(StoredHookTrustRecord::Current(record))
}

fn validate_record(record: &HookTrustRecord, operation_id: &str) -> Result<(), HookTrustError> {
    let expected_operation_id = format!(
        "hook-trust-{}-{}-{}-{}",
        record.provider.as_str(),
        &crate::encode_lower_hex(&sha2::Sha256::digest(record.handler_id.as_bytes()))[..16],
        record.handler_fingerprint,
        record.profile_digest
    );
    let legacy_operation_id = format!(
        "hook-trust-{}-{}-{}",
        record.provider.as_str(),
        record.handler_fingerprint,
        record.profile_digest
    );
    if record.handler_id.trim().is_empty()
        || (operation_id != expected_operation_id && operation_id != legacy_operation_id)
        || !crate::is_lower_hex_digest(&record.handler_fingerprint)
        || !crate::is_lower_hex_digest(&record.invocation_fingerprint)
        || !crate::is_lower_hex_digest(&record.profile_digest)
        || !crate::is_lower_hex_digest(&record.decision_digest)
    {
        return Err(HookTrustError::InvalidRecord);
    }
    Ok(())
}

#[derive(Debug)]
pub enum HookTrustError {
    State(StateError),
    Approval(ApprovalError),
    Model(crate::hooks::HookModelError),
    MissingRecord,
    ConflictingRecord,
    InvalidRecord,
}

impl From<StateError> for HookTrustError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<ApprovalError> for HookTrustError {
    fn from(error: ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<crate::hooks::HookModelError> for HookTrustError {
    fn from(error: crate::hooks::HookModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for HookTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Approval(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
            Self::MissingRecord => formatter.write_str("hook trust record disappeared"),
            Self::ConflictingRecord => {
                formatter.write_str("different hook trust decision already exists")
            }
            Self::InvalidRecord => formatter.write_str("hook trust record is invalid"),
        }
    }
}

impl std::error::Error for HookTrustError {}
