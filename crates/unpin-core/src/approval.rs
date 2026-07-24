use std::{fmt, path::PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::get_approval_nonce_path,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError},
};

const APPROVAL_RECEIPT_VERSION: u32 = 1;
const APPROVAL_ALGORITHM: &str = "hmac-sha256";
const APPROVAL_KEY_PURPOSE: &[u8] = b"unpin-transition-approval-v1\0";
const NONCE_SCHEMA_VERSION: u32 = 1;
pub const MAX_APPROVAL_LIFETIME_SECONDS: i64 = 15 * 60;
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
        self.0.fill(0);
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
        let store = AtomicJsonStore::new(
            get_approval_nonce_path(&self.app_state_root, &nonce_digest),
            NONCE_SCHEMA_VERSION,
        );
        let record = ConsumedNonce {
            operation_id: approval.operation_id.clone(),
            decision_digest: approval.decision_digest.clone(),
            consumed_at_unix,
        };
        match store.compare_and_swap(None, owner, &record) {
            Ok(_) => Ok(NonceConsumption::Consumed),
            Err(StateError::StaleRevision { .. }) => {
                let existing = store
                    .load::<ConsumedNonce>()?
                    .ok_or(ApprovalError::NonceStateMissing)?;
                if existing.value.operation_id == record.operation_id
                    && existing.value.decision_digest == record.decision_digest
                {
                    Ok(NonceConsumption::AttachedToSameOperation)
                } else {
                    Err(ApprovalError::Replay)
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn attach_existing(
        &self,
        approval: &VerifiedApproval,
    ) -> Result<NonceConsumption, ApprovalError> {
        let nonce_digest = crate::encode_lower_hex(&Sha256::digest(approval.nonce.as_bytes()));
        let store = AtomicJsonStore::new(
            get_approval_nonce_path(&self.app_state_root, &nonce_digest),
            NONCE_SCHEMA_VERSION,
        );
        let existing = store
            .load::<ConsumedNonce>()?
            .ok_or(ApprovalError::NonceNotConsumed)?;
        if existing.value.operation_id == approval.operation_id
            && existing.value.decision_digest == approval.decision_digest
            && existing.value.consumed_at_unix >= approval.issued_at_unix
            && existing.value.consumed_at_unix < approval.expires_at_unix
        {
            Ok(NonceConsumption::AttachedToSameOperation)
        } else {
            Err(ApprovalError::Replay)
        }
    }
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
            Self::State(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ApprovalError {}
