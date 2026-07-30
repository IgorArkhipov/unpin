use std::{collections::BTreeMap, fmt, path::PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    config::{
        get_approval_nonce_ledger_path, get_approval_nonce_ledger_shard_path,
        get_approval_nonce_path,
    },
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateSnapshot},
};

const APPROVAL_RECEIPT_VERSION: u32 = 1;
const APPROVAL_ALGORITHM: &str = "hmac-sha256";
const APPROVAL_KEY_PURPOSE: &[u8] = b"unpin-transition-approval-v1\0";
const NONCE_SCHEMA_VERSION: u32 = 1;
const NONCE_LEDGER_UPDATE_ATTEMPTS: usize = 32;
pub const MAX_APPROVAL_LIFETIME_SECONDS: i64 = 15 * 60;
/// Retains consumed approvals beyond their short receipt lifetime so durable
/// transitions can recover, while a later consumption prunes older evidence.
pub const APPROVAL_NONCE_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Bounds each ledger-shard rewrite cost and fails closed instead of allowing
/// unbounded approval history to exhaust memory or disk.
pub const MAX_APPROVAL_NONCE_LEDGER_ENTRIES: usize = 4_096;
pub const CONTROL_APPROVAL_ISSUER: &str = "unpin-cli-human";
pub const CONTROL_APPROVAL_AUDIENCE: &str = "unpin-core-control";

#[derive(Clone)]
pub struct ApprovalKey([u8; 32]);

impl ApprovalKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApprovalError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ApprovalError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn key_id(&self) -> String {
        format!(
            "sha256:{}",
            &crate::encode_lower_hex(&Sha256::digest(self.0))[..16]
        )
    }
}

impl fmt::Debug for ApprovalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl Drop for ApprovalKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalResourceBinding {
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_state_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalReceiptClaims {
    pub version: u32,
    pub receipt_id: String,
    pub nonce: String,
    pub issuer: String,
    pub audience: String,
    pub operation_id: String,
    pub operation_kind: String,
    pub effect_graph_digest: String,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
    pub resources: Vec<ApprovalResourceBinding>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl ApprovalReceiptClaims {
    pub fn normalize(&mut self) -> Result<(), ApprovalError> {
        validate_identifier("receipt id", &self.receipt_id)?;
        validate_identifier("nonce", &self.nonce)?;
        validate_identifier("issuer", &self.issuer)?;
        validate_identifier("audience", &self.audience)?;
        validate_identifier("operation id", &self.operation_id)?;
        validate_identifier("operation kind", &self.operation_kind)?;
        validate_identifier("repository key", &self.repository_key)?;
        validate_identifier("workspace key", &self.workspace_key)?;
        if let Some(session_id) = &self.session_id {
            validate_identifier("session id", session_id)?;
        }
        validate_digest("effect graph", &self.effect_graph_digest)?;
        if let Some(profile_digest) = &self.profile_digest {
            validate_digest("profile", profile_digest)?;
        }
        if self.version != APPROVAL_RECEIPT_VERSION {
            return Err(ApprovalError::UnsupportedVersion(self.version));
        }
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(ApprovalError::InvalidExpiry);
        }
        if self
            .expires_at_unix
            .checked_sub(self.issued_at_unix)
            .is_none_or(|lifetime| lifetime > MAX_APPROVAL_LIFETIME_SECONDS)
        {
            return Err(ApprovalError::ExpiryTooLong);
        }
        if self.resources.is_empty() {
            return Err(ApprovalError::InvalidResourceBinding);
        }
        for resource in &self.resources {
            validate_identifier("resource id", &resource.resource_id)?;
            if let Some(fingerprint) = &resource.pre_state_fingerprint {
                validate_digest("pre-state", fingerprint)?;
            }
        }
        self.resources.sort();
        if self
            .resources
            .windows(2)
            .any(|pair| pair[0].resource_id == pair[1].resource_id)
        {
            return Err(ApprovalError::DuplicateBinding("resource id"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalReceipt {
    pub claims: ApprovalReceiptClaims,
    pub algorithm: String,
    pub key_id: String,
    pub tag: String,
}

impl ApprovalReceipt {
    #[must_use]
    pub fn decision_digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("approval receipt is serializable");
        crate::encode_lower_hex(&Sha256::digest(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalExpectation {
    pub issuer: String,
    pub audience: String,
    pub operation_id: String,
    pub operation_kind: String,
    pub effect_graph_digest: String,
    pub repository_key: String,
    pub workspace_key: String,
    pub session_id: Option<String>,
    pub profile_digest: Option<String>,
    pub resources: Vec<ApprovalResourceBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOperationKind {
    ProfilePolicy,
    CapabilityPolicy,
    PolicyMaintenance,
    GatewayWorkflow,
    SessionEnd,
    RestoreBackup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlApprovalContext {
    repository_key: String,
    workspace_key: String,
}

impl ControlApprovalContext {
    pub fn new(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
    ) -> Result<Self, ApprovalError> {
        let context = Self {
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
        };
        validate_identifier("repository key", &context.repository_key)?;
        validate_identifier("workspace key", &context.workspace_key)?;
        Ok(context)
    }

    #[must_use]
    pub fn repository_key(&self) -> &str {
        &self.repository_key
    }

    #[must_use]
    pub fn workspace_key(&self) -> &str {
        &self.workspace_key
    }
}

impl ControlOperationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfilePolicy => "profile-policy",
            Self::CapabilityPolicy => "capability-policy",
            Self::PolicyMaintenance => "policy-maintenance",
            Self::GatewayWorkflow => "gateway-workflow",
            Self::SessionEnd => "session-end",
            Self::RestoreBackup => "restore-backup",
        }
    }
}

/// Non-serializable proof that a human-issued receipt matched and consumed a
/// specific control decision. Control apply APIs consume this value so MCP
/// callers cannot manufacture approval from a boolean argument.
#[derive(Debug)]
pub struct ControlAuthorization {
    expectation: ApprovalExpectation,
    operation_id: String,
    decision_digest: String,
    nonce: NonceConsumption,
}

impl ControlAuthorization {
    pub(crate) fn assert_matches(
        &self,
        expectation: &ApprovalExpectation,
    ) -> Result<(), ApprovalError> {
        let mut expectation = expectation.clone();
        expectation.resources.sort();
        if self.expectation == expectation {
            Ok(())
        } else {
            Err(ApprovalError::BindingMismatch)
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    #[must_use]
    pub const fn nonce_consumption(&self) -> NonceConsumption {
        self.nonce
    }

    pub(crate) fn attenuate_for_inventory_group_child(
        &self,
        parent_expectation: &ApprovalExpectation,
        child_expectation: &ApprovalExpectation,
        cohort_id: &str,
        member_plan_fingerprint: &str,
    ) -> Result<Self, ApprovalError> {
        self.assert_matches(parent_expectation)?;
        let mut child_expectation = child_expectation.clone();
        child_expectation.resources.sort();
        if child_expectation.repository_key != parent_expectation.repository_key
            || child_expectation.workspace_key != parent_expectation.workspace_key
            || child_expectation.session_id != parent_expectation.session_id
            || cohort_id.is_empty()
            || cohort_id.len() > 256
            || member_plan_fingerprint.len() != 64
            || !crate::is_lower_hex_digest(member_plan_fingerprint)
        {
            return Err(ApprovalError::BindingMismatch);
        }
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "purpose": "inventory-group-child-capability-v1",
            "parentDecisionDigest": self.decision_digest,
            "parentExpectation": parent_expectation,
            "childExpectation": child_expectation,
            "cohortId": cohort_id,
            "memberPlanFingerprint": member_plan_fingerprint,
        }))
        .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        let decision_digest = crate::encode_lower_hex(&Sha256::digest(payload));
        Ok(Self {
            operation_id: child_expectation.operation_id.clone(),
            expectation: child_expectation,
            decision_digest,
            nonce: self.nonce,
        })
    }

    pub(crate) fn attenuate_for_bulk_child(
        &self,
        parent_expectation: &ApprovalExpectation,
        child_expectation: &ApprovalExpectation,
        parent_plan_fingerprint: &str,
        child_plan_fingerprint: &str,
    ) -> Result<Self, ApprovalError> {
        self.assert_matches(parent_expectation)?;
        let mut child_expectation = child_expectation.clone();
        child_expectation.resources.sort();
        if child_expectation.repository_key != parent_expectation.repository_key
            || child_expectation.workspace_key != parent_expectation.workspace_key
            || child_expectation.session_id != parent_expectation.session_id
            || !crate::is_lower_hex_digest(
                parent_plan_fingerprint
                    .strip_prefix("sha256:")
                    .unwrap_or(parent_plan_fingerprint),
            )
            || !crate::is_lower_hex_digest(child_plan_fingerprint)
        {
            return Err(ApprovalError::BindingMismatch);
        }
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "purpose": "bulk-toggle-child-capability-v1",
            "parentDecisionDigest": self.decision_digest,
            "parentExpectation": parent_expectation,
            "childExpectation": child_expectation,
            "parentPlanFingerprint": parent_plan_fingerprint,
            "childPlanFingerprint": child_plan_fingerprint,
        }))
        .map_err(|error| ApprovalError::Serialization(error.to_string()))?;
        let decision_digest = crate::encode_lower_hex(&Sha256::digest(payload));
        Ok(Self {
            operation_id: child_expectation.operation_id.clone(),
            expectation: child_expectation,
            decision_digest,
            nonce: self.nonce,
        })
    }
}

pub fn authorize_control(
    app_state_root: impl Into<PathBuf>,
    receipt: &ApprovalReceipt,
    verifier: &ApprovalVerifier,
    expectation: &ApprovalExpectation,
    now_unix: i64,
    owner: OwnerGeneration,
) -> Result<ControlAuthorization, ApprovalError> {
    let verified = verifier.verify(receipt, expectation, now_unix)?;
    let nonce =
        ApprovalNonceStore::new(app_state_root).consume_or_attach(&verified, now_unix, owner)?;
    let mut expectation = expectation.clone();
    expectation.resources.sort();
    Ok(ControlAuthorization {
        expectation,
        operation_id: verified.operation_id,
        decision_digest: verified.decision_digest,
        nonce,
    })
}

pub(crate) fn approval_binding_digest(value: &str) -> String {
    crate::encode_lower_hex(&Sha256::digest(value.as_bytes()))
}

pub struct ApprovalIssuer {
    key: ApprovalKey,
    issuer: String,
    audience: String,
}

impl ApprovalIssuer {
    pub fn new(
        key: ApprovalKey,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, ApprovalError> {
        let issuer = issuer.into();
        let audience = audience.into();
        validate_identifier("issuer", &issuer)?;
        validate_identifier("audience", &audience)?;
        Ok(Self {
            key,
            issuer,
            audience,
        })
    }

    pub fn issue(
        &self,
        mut claims: ApprovalReceiptClaims,
    ) -> Result<ApprovalReceipt, ApprovalError> {
        claims.issuer = self.issuer.clone();
        claims.audience = self.audience.clone();
        claims.normalize()?;
        let tag = sign_claims(&self.key, &claims)?;
        Ok(ApprovalReceipt {
            claims,
            algorithm: APPROVAL_ALGORITHM.to_string(),
            key_id: self.key.key_id(),
            tag,
        })
    }
}

pub struct ApprovalVerifier {
    key: ApprovalKey,
}

impl ApprovalVerifier {
    #[must_use]
    pub const fn new(key: ApprovalKey) -> Self {
        Self { key }
    }

    pub fn verify(
        &self,
        receipt: &ApprovalReceipt,
        expectation: &ApprovalExpectation,
        now_unix: i64,
    ) -> Result<VerifiedApproval, ApprovalError> {
        let verified = self.verify_binding(receipt, expectation)?;
        if now_unix < verified.issued_at_unix {
            return Err(ApprovalError::NotYetValid);
        }
        if now_unix >= verified.expires_at_unix {
            return Err(ApprovalError::Expired);
        }
        Ok(verified)
    }

    pub fn verify_binding(
        &self,
        receipt: &ApprovalReceipt,
        expectation: &ApprovalExpectation,
    ) -> Result<VerifiedApproval, ApprovalError> {
        let mut claims = receipt.claims.clone();
        claims.normalize()?;
        if claims != receipt.claims {
            return Err(ApprovalError::NonCanonicalClaims);
        }
        if receipt.algorithm != APPROVAL_ALGORITHM || receipt.key_id != self.key.key_id() {
            return Err(ApprovalError::WrongKeyOrAlgorithm);
        }
        let expected_tag = decode_hex(&receipt.tag)?;
        let message = claims_message(&claims)?;
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.key.0)
            .map_err(|_| ApprovalError::InvalidKeyLength)?;
        mac.update(&message);
        mac.verify_slice(&expected_tag)
            .map_err(|_| ApprovalError::InvalidSignature)?;
        compare_expectation(&claims, expectation)?;
        Ok(VerifiedApproval {
            nonce: claims.nonce,
            operation_id: claims.operation_id,
            decision_digest: receipt.decision_digest(),
            issued_at_unix: claims.issued_at_unix,
            expires_at_unix: claims.expires_at_unix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub(crate) nonce: String,
    pub(crate) operation_id: String,
    pub(crate) decision_digest: String,
    pub(crate) issued_at_unix: i64,
    pub(crate) expires_at_unix: i64,
}

impl VerifiedApproval {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonceConsumption {
    Consumed,
    AttachedToSameOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsumedNonce {
    operation_id: String,
    decision_digest: String,
    consumed_at_unix: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsumedNonceLedger {
    entries: BTreeMap<String, ConsumedNonce>,
}

#[derive(Debug, Clone)]
pub struct ApprovalNonceStore {
    app_state_root: PathBuf,
}

impl ApprovalNonceStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn consume_or_attach(
        &self,
        approval: &VerifiedApproval,
        consumed_at_unix: i64,
        owner: OwnerGeneration,
    ) -> Result<NonceConsumption, ApprovalError> {
        if consumed_at_unix < approval.issued_at_unix {
            return Err(ApprovalError::NotYetValid);
        }
        if consumed_at_unix >= approval.expires_at_unix {
            return Err(ApprovalError::Expired);
        }
        let nonce_digest = crate::encode_lower_hex(&Sha256::digest(approval.nonce.as_bytes()));
        let record = ConsumedNonce {
            operation_id: approval.operation_id.clone(),
            decision_digest: approval.decision_digest.clone(),
            consumed_at_unix,
        };
        let legacy = self.legacy_nonce(&nonce_digest)?;
        let recovery_cutoff = consumed_at_unix.saturating_sub(APPROVAL_NONCE_RETENTION_SECONDS);
        let recovery = self
            .recovery_nonce(&nonce_digest)?
            .filter(|consumed| consumed.consumed_at_unix >= recovery_cutoff);
        let active_cutoff = consumed_at_unix.saturating_sub(MAX_APPROVAL_LIFETIME_SECONDS);
        let active = self
            .active_ledger_nonce(&nonce_digest)?
            .filter(|consumed| consumed.consumed_at_unix > active_cutoff);
        let mut canonical = Some(record);
        for candidate in [
            active,
            recovery.clone(),
            legacy.as_ref().map(|snapshot| snapshot.value.clone()),
        ] {
            canonical = reconcile_consumed_nonce(canonical, candidate)?;
        }
        let record = canonical.expect("new nonce record is always present");
        let mut recovery_entries = BTreeMap::new();
        recovery_entries.insert(nonce_digest.clone(), record.clone());
        self.merge_recovery_entries(&recovery_entries, &owner, recovery_cutoff)?;
        let consumption = self.reserve_active_nonce(
            &nonce_digest,
            &record,
            consumed_at_unix,
            &owner,
            &legacy,
            &recovery,
        )?;
        if let Some(legacy) = &legacy {
            let _ = self
                .legacy_store(&nonce_digest)
                .remove_if_revision(&legacy.revision);
        }
        Ok(consumption)
    }

    fn reserve_active_nonce(
        &self,
        nonce_digest: &str,
        record: &ConsumedNonce,
        consumed_at_unix: i64,
        owner: &OwnerGeneration,
        legacy: &Option<StateSnapshot<ConsumedNonce>>,
        recovery: &Option<ConsumedNonce>,
    ) -> Result<NonceConsumption, ApprovalError> {
        let store = self.active_ledger_store();
        let active_cutoff = consumed_at_unix.saturating_sub(MAX_APPROVAL_LIFETIME_SECONDS);
        let recovery_cutoff = consumed_at_unix.saturating_sub(APPROVAL_NONCE_RETENTION_SECONDS);
        let mut last_stale = None;

        for _ in 0..NONCE_LEDGER_UPDATE_ATTEMPTS {
            let snapshot = store.load::<ConsumedNonceLedger>()?;
            let expected = snapshot.as_ref().map(|snapshot| snapshot.revision.clone());
            let current_owner = snapshot.as_ref().map(|snapshot| snapshot.owner.clone());
            let mut ledger =
                snapshot.map_or_else(ConsumedNonceLedger::default, |value| value.value);
            validate_nonce_ledger(&ledger, None)?;
            let recovery_entries = ledger
                .entries
                .iter()
                .filter(|(_, consumed)| {
                    consumed.consumed_at_unix <= active_cutoff
                        && consumed.consumed_at_unix >= recovery_cutoff
                })
                .map(|(nonce_digest, consumed)| (nonce_digest.clone(), consumed.clone()))
                .collect::<BTreeMap<_, _>>();
            self.merge_recovery_entries(&recovery_entries, owner, recovery_cutoff)?;
            let original_len = ledger.entries.len();
            ledger
                .entries
                .retain(|_, consumed| consumed.consumed_at_unix > active_cutoff);
            let pruned = ledger.entries.len() != original_len;

            let mut existing = None;
            for candidate in [
                ledger.entries.get(nonce_digest).cloned(),
                recovery_entries.get(nonce_digest).cloned(),
                recovery.clone(),
                legacy.as_ref().map(|snapshot| snapshot.value.clone()),
            ] {
                existing = reconcile_consumed_nonce(existing, candidate)?;
            }
            let consumption = match existing {
                Some(existing) if same_nonce_decision(&existing, record) => {
                    if !pruned && ledger.entries.get(nonce_digest) == Some(&existing) {
                        return Ok(NonceConsumption::AttachedToSameOperation);
                    }
                    if !ledger.entries.contains_key(nonce_digest)
                        && ledger.entries.len() >= MAX_APPROVAL_NONCE_LEDGER_ENTRIES
                    {
                        return Err(ApprovalError::NonceLedgerCapacity);
                    }
                    ledger.entries.insert(nonce_digest.to_string(), existing);
                    NonceConsumption::AttachedToSameOperation
                }
                Some(_) => return Err(ApprovalError::Replay),
                None => {
                    if ledger.entries.len() >= MAX_APPROVAL_NONCE_LEDGER_ENTRIES {
                        return Err(ApprovalError::NonceLedgerCapacity);
                    }
                    ledger
                        .entries
                        .insert(nonce_digest.to_string(), record.clone());
                    NonceConsumption::Consumed
                }
            };

            let ledger_owner = nonce_ledger_owner(current_owner.as_ref(), owner)?;
            match store.compare_and_swap(expected.as_ref(), ledger_owner, &ledger) {
                Ok(_) => return Ok(consumption),
                Err(error @ StateError::StaleRevision { .. }) => last_stale = Some(error),
                Err(error) => return Err(error.into()),
            }
        }

        Err(last_stale
            .expect("nonce ledger update attempts record stale state")
            .into())
    }

    pub fn attach_existing(
        &self,
        approval: &VerifiedApproval,
    ) -> Result<NonceConsumption, ApprovalError> {
        let nonce_digest = crate::encode_lower_hex(&Sha256::digest(approval.nonce.as_bytes()));
        let mut existing = None;
        for candidate in [
            self.recovery_nonce(&nonce_digest)?,
            self.active_ledger_nonce(&nonce_digest)?,
            self.legacy_nonce(&nonce_digest)?
                .map(|snapshot| snapshot.value),
        ] {
            existing = reconcile_consumed_nonce(existing, candidate)?;
        }
        let existing = existing.ok_or(ApprovalError::NonceNotConsumed)?;
        if existing.operation_id == approval.operation_id
            && existing.decision_digest == approval.decision_digest
            && existing.consumed_at_unix >= approval.issued_at_unix
            && existing.consumed_at_unix < approval.expires_at_unix
        {
            Ok(NonceConsumption::AttachedToSameOperation)
        } else {
            Err(ApprovalError::Replay)
        }
    }

    fn ledger_store(&self, nonce_digest: &str) -> Result<AtomicJsonStore, ApprovalError> {
        let shard = nonce_ledger_shard(nonce_digest)?;
        Ok(AtomicJsonStore::new(
            get_approval_nonce_ledger_shard_path(&self.app_state_root, shard),
            NONCE_SCHEMA_VERSION,
        ))
    }

    fn active_ledger_store(&self) -> AtomicJsonStore {
        AtomicJsonStore::new(
            get_approval_nonce_ledger_path(&self.app_state_root),
            NONCE_SCHEMA_VERSION,
        )
    }

    fn active_ledger_nonce(
        &self,
        nonce_digest: &str,
    ) -> Result<Option<ConsumedNonce>, ApprovalError> {
        let Some(snapshot) = self.active_ledger_store().load::<ConsumedNonceLedger>()? else {
            return Ok(None);
        };
        validate_nonce_ledger(&snapshot.value, None)?;
        Ok(snapshot.value.entries.get(nonce_digest).cloned())
    }

    fn recovery_nonce(&self, nonce_digest: &str) -> Result<Option<ConsumedNonce>, ApprovalError> {
        let Some(snapshot) = self
            .ledger_store(nonce_digest)?
            .load::<ConsumedNonceLedger>()?
        else {
            return Ok(None);
        };
        validate_nonce_ledger(&snapshot.value, Some(nonce_ledger_shard(nonce_digest)?))?;
        Ok(snapshot.value.entries.get(nonce_digest).cloned())
    }

    fn merge_recovery_entries(
        &self,
        entries: &BTreeMap<String, ConsumedNonce>,
        owner: &OwnerGeneration,
        cutoff: i64,
    ) -> Result<(), ApprovalError> {
        let mut shards = BTreeMap::<String, BTreeMap<String, ConsumedNonce>>::new();
        for (nonce_digest, consumed) in entries {
            shards
                .entry(nonce_ledger_shard(nonce_digest)?.to_string())
                .or_default()
                .insert(nonce_digest.clone(), consumed.clone());
        }
        for entries in shards.values() {
            self.merge_recovery_shard(entries, owner, cutoff)?;
        }
        Ok(())
    }

    fn merge_recovery_shard(
        &self,
        entries: &BTreeMap<String, ConsumedNonce>,
        owner: &OwnerGeneration,
        cutoff: i64,
    ) -> Result<(), ApprovalError> {
        let Some((nonce_digest, _)) = entries.first_key_value() else {
            return Ok(());
        };
        let shard = nonce_ledger_shard(nonce_digest)?;
        let store = self.ledger_store(nonce_digest)?;
        let mut last_stale = None;

        for _ in 0..NONCE_LEDGER_UPDATE_ATTEMPTS {
            let snapshot = store.load::<ConsumedNonceLedger>()?;
            let expected = snapshot.as_ref().map(|snapshot| snapshot.revision.clone());
            let current_owner = snapshot.as_ref().map(|snapshot| snapshot.owner.clone());
            let mut ledger =
                snapshot.map_or_else(ConsumedNonceLedger::default, |value| value.value);
            validate_nonce_ledger(&ledger, Some(shard))?;
            let original_len = ledger.entries.len();
            ledger
                .entries
                .retain(|_, consumed| consumed.consumed_at_unix >= cutoff);
            let mut changed = ledger.entries.len() != original_len;
            for (nonce_digest, consumed) in entries {
                match ledger.entries.get(nonce_digest).cloned() {
                    Some(existing) => {
                        let canonical = reconcile_consumed_nonce(
                            Some(existing.clone()),
                            Some(consumed.clone()),
                        )?
                        .expect("two nonce records reconcile to one record");
                        if canonical != existing {
                            ledger.entries.insert(nonce_digest.clone(), canonical);
                            changed = true;
                        }
                    }
                    None => {
                        if ledger.entries.len() >= MAX_APPROVAL_NONCE_LEDGER_ENTRIES {
                            return Err(ApprovalError::NonceLedgerCapacity);
                        }
                        ledger
                            .entries
                            .insert(nonce_digest.clone(), consumed.clone());
                        changed = true;
                    }
                }
            }
            if !changed {
                return Ok(());
            }

            let ledger_owner = nonce_ledger_owner(current_owner.as_ref(), owner)?;
            match store.compare_and_swap(expected.as_ref(), ledger_owner, &ledger) {
                Ok(_) => return Ok(()),
                Err(error @ StateError::StaleRevision { .. }) => last_stale = Some(error),
                Err(error) => return Err(error.into()),
            }
        }

        Err(last_stale
            .expect("nonce recovery ledger update attempts record stale state")
            .into())
    }

    fn legacy_store(&self, nonce_digest: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            get_approval_nonce_path(&self.app_state_root, nonce_digest),
            NONCE_SCHEMA_VERSION,
        )
    }

    fn legacy_nonce(
        &self,
        nonce_digest: &str,
    ) -> Result<Option<StateSnapshot<ConsumedNonce>>, ApprovalError> {
        self.legacy_store(nonce_digest)
            .load::<ConsumedNonce>()
            .map_err(Into::into)
    }
}

fn same_nonce_decision(left: &ConsumedNonce, right: &ConsumedNonce) -> bool {
    left.operation_id == right.operation_id && left.decision_digest == right.decision_digest
}

fn reconcile_consumed_nonce(
    existing: Option<ConsumedNonce>,
    candidate: Option<ConsumedNonce>,
) -> Result<Option<ConsumedNonce>, ApprovalError> {
    match (existing, candidate) {
        (Some(existing), Some(candidate)) if same_nonce_decision(&existing, &candidate) => {
            if candidate.consumed_at_unix < existing.consumed_at_unix {
                Ok(Some(candidate))
            } else {
                Ok(Some(existing))
            }
        }
        (Some(_), Some(_)) => Err(ApprovalError::Replay),
        (Some(existing), None) => Ok(Some(existing)),
        (None, Some(candidate)) => Ok(Some(candidate)),
        (None, None) => Ok(None),
    }
}

fn nonce_ledger_shard(nonce_digest: &str) -> Result<&str, ApprovalError> {
    if nonce_digest.len() != 64
        || !nonce_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApprovalError::InvalidNonceLedger);
    }
    Ok(&nonce_digest[..2])
}

fn validate_nonce_ledger(
    ledger: &ConsumedNonceLedger,
    expected_shard: Option<&str>,
) -> Result<(), ApprovalError> {
    for nonce_digest in ledger.entries.keys() {
        let shard = nonce_ledger_shard(nonce_digest)?;
        if expected_shard.is_some_and(|expected| expected != shard) {
            return Err(ApprovalError::InvalidNonceLedger);
        }
    }
    Ok(())
}

fn nonce_ledger_owner(
    current: Option<&OwnerGeneration>,
    requested: &OwnerGeneration,
) -> Result<OwnerGeneration, ApprovalError> {
    let generation = current.map_or(requested.generation, |current| {
        if current.owner_id == requested.owner_id {
            requested.generation.max(current.generation)
        } else {
            requested
                .generation
                .max(current.generation.saturating_add(1))
        }
    });
    OwnerGeneration::new(requested.owner_id.clone(), generation).map_err(Into::into)
}

fn sign_claims(key: &ApprovalKey, claims: &ApprovalReceiptClaims) -> Result<String, ApprovalError> {
    let message = claims_message(claims)?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&key.0)
        .map_err(|_| ApprovalError::InvalidKeyLength)?;
    mac.update(&message);
    Ok(crate::encode_lower_hex(&mac.finalize().into_bytes()))
}

fn claims_message(claims: &ApprovalReceiptClaims) -> Result<Vec<u8>, ApprovalError> {
    let mut message = APPROVAL_KEY_PURPOSE.to_vec();
    message.extend(
        serde_json::to_vec(claims)
            .map_err(|error| ApprovalError::Serialization(error.to_string()))?,
    );
    Ok(message)
}

fn compare_expectation(
    claims: &ApprovalReceiptClaims,
    expected: &ApprovalExpectation,
) -> Result<(), ApprovalError> {
    let mut resources = expected.resources.clone();
    resources.sort();
    let matches = claims.issuer == expected.issuer
        && claims.audience == expected.audience
        && claims.operation_id == expected.operation_id
        && claims.operation_kind == expected.operation_kind
        && claims.effect_graph_digest == expected.effect_graph_digest
        && claims.repository_key == expected.repository_key
        && claims.workspace_key == expected.workspace_key
        && claims.session_id == expected.session_id
        && claims.profile_digest == expected.profile_digest
        && claims.resources == resources;
    if matches {
        Ok(())
    } else {
        Err(ApprovalError::BindingMismatch)
    }
}

fn validate_identifier(label: &'static str, value: &str) -> Result<(), ApprovalError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        Err(ApprovalError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn validate_digest(label: &'static str, value: &str) -> Result<(), ApprovalError> {
    if crate::is_lower_hex_digest(value) {
        Ok(())
    } else {
        Err(ApprovalError::InvalidDigest(label))
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ApprovalError> {
    if !value.len().is_multiple_of(2) {
        return Err(ApprovalError::InvalidSignatureEncoding);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, ApprovalError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ApprovalError::InvalidSignatureEncoding),
    }
}

#[derive(Debug)]
pub enum ApprovalError {
    InvalidKeyLength,
    UnsupportedVersion(u32),
    InvalidIdentifier(&'static str),
    InvalidDigest(&'static str),
    InvalidExpiry,
    ExpiryTooLong,
    InvalidResourceBinding,
    DuplicateBinding(&'static str),
    Serialization(String),
    NonCanonicalClaims,
    WrongKeyOrAlgorithm,
    InvalidSignatureEncoding,
    InvalidSignature,
    NotYetValid,
    Expired,
    BindingMismatch,
    Replay,
    NonceStateMissing,
    NonceNotConsumed,
    NonceLedgerCapacity,
    InvalidNonceLedger,
    State(StateError),
}

impl From<StateError> for ApprovalError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength => formatter.write_str("approval key must be exactly 32 bytes"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported approval receipt version: {version}")
            }
            Self::InvalidIdentifier(label) => write!(formatter, "invalid {label}"),
            Self::InvalidDigest(label) => write!(formatter, "invalid {label} digest"),
            Self::InvalidExpiry => formatter.write_str("approval expiry is invalid"),
            Self::ExpiryTooLong => formatter.write_str("approval receipt lifetime is too long"),
            Self::InvalidResourceBinding => {
                formatter.write_str("approval resource bindings are invalid")
            }
            Self::DuplicateBinding(label) => write!(formatter, "duplicate {label}"),
            Self::Serialization(message) => {
                write!(formatter, "approval serialization failed: {message}")
            }
            Self::NonCanonicalClaims => formatter.write_str("approval claims are not canonical"),
            Self::WrongKeyOrAlgorithm => {
                formatter.write_str("approval key or algorithm does not match")
            }
            Self::InvalidSignatureEncoding => {
                formatter.write_str("approval signature encoding is invalid")
            }
            Self::InvalidSignature => formatter.write_str("approval signature is invalid"),
            Self::NotYetValid => formatter.write_str("approval receipt is not yet valid"),
            Self::Expired => formatter.write_str("approval receipt is expired"),
            Self::BindingMismatch => formatter.write_str("approval receipt binding does not match"),
            Self::Replay => formatter.write_str("approval receipt nonce was already consumed"),
            Self::NonceStateMissing => {
                formatter.write_str("approval nonce state disappeared after consumption")
            }
            Self::NonceNotConsumed => formatter.write_str("approval nonce has not been consumed"),
            Self::NonceLedgerCapacity => {
                formatter.write_str("approval nonce ledger reached its safe capacity")
            }
            Self::InvalidNonceLedger => {
                formatter.write_str("approval nonce ledger contains an invalid entry")
            }
            Self::State(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ApprovalError {}
