use std::{
    fmt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    approval::ApprovalReceipt,
    groups::{GroupPlanDisposition, GroupPlanMode, GroupTogglePlan},
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateSnapshot},
};

const MCP_GROUP_SESSION_SCHEMA_VERSION: u32 = 1;
const MCP_GROUP_ARTIFACT_SCHEMA_VERSION: u32 = 1;
const MCP_GROUP_CHALLENGE_VERSION: u8 = 1;
const MCP_GROUP_LEASE_LIFETIME_SECONDS: i64 = 120;
const MCP_GROUP_CHALLENGE_LIFETIME_SECONDS: i64 = 5 * 60;
const MAX_CHALLENGE_BYTES: usize = 512 * 1024;
pub const MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES: usize =
    MAX_CHALLENGE_BYTES.saturating_mul(2).saturating_add(80);
const LEASE_PURPOSE: &[u8] = b"unpin-inventory-group-mcp-lease-v1\0";
const CHALLENGE_PURPOSE: &[u8] = b"unpin-inventory-group-mcp-challenge-v1\0";
const ARTIFACT_PURPOSE: &[u8] = b"unpin-inventory-group-approval-artifact-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpGroupSessionBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    pub repository_key: String,
    pub workspace_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpGroupSessionIdentity {
    pub session_id: String,
    pub generation: u64,
    pub binding: McpGroupSessionBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpGroupSessionLeaseRecord {
    schema_version: u8,
    identity: McpGroupSessionIdentity,
    issued_at_unix: i64,
    expires_at_unix: i64,
    authentication_tag: String,
}

impl McpGroupSessionLeaseRecord {
    fn sign(&mut self, key: &SessionAuthorityKey) -> Result<(), GroupSessionError> {
        self.authentication_tag.clear();
        let payload = authenticated_payload(LEASE_PURPOSE, self)?;
        self.authentication_tag = key
            .authenticate_inventory_group(&payload)
            .map_err(GroupSessionError::Authentication)?;
        Ok(())
    }

    fn verify(
        &self,
        identity: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<(), GroupSessionError> {
        if self.schema_version != 1
            || &self.identity != identity
            || self.issued_at_unix > now_unix
            || self.expires_at_unix <= now_unix
            || self.expires_at_unix - self.issued_at_unix > MCP_GROUP_LEASE_LIFETIME_SECONDS
        {
            return Err(GroupSessionError::InvalidLease);
        }
        let mut unsigned = self.clone();
        let tag = std::mem::take(&mut unsigned.authentication_tag);
        let payload = authenticated_payload(LEASE_PURPOSE, &unsigned)?;
        key.verify_inventory_group(&payload, &tag)
            .map_err(|_| GroupSessionError::AuthenticationFailed)
    }
}

#[derive(Debug, Clone)]
pub struct McpGroupSessionLeaseStore {
    app_state_root: PathBuf,
}

impl McpGroupSessionLeaseStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn create(
        &self,
        binding: McpGroupSessionBinding,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<McpGroupSessionIdentity, GroupSessionError> {
        validate_binding(&binding)?;
        let identity = McpGroupSessionIdentity {
            session_id: secure_random_identifier("mcp-group-session", 24)?,
            generation: secure_random_generation()?,
            binding,
        };
        let mut record = McpGroupSessionLeaseRecord {
            schema_version: 1,
            identity: identity.clone(),
            issued_at_unix: now_unix,
            expires_at_unix: checked_expiry(now_unix, MCP_GROUP_LEASE_LIFETIME_SECONDS)?,
            authentication_tag: String::new(),
        };
        record.sign(key)?;
        self.store(&identity.session_id)
            .compare_and_swap(None, owner(&identity)?, &record)?;
        Ok(identity)
    }

    pub fn renew(
        &self,
        identity: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<(), GroupSessionError> {
        let snapshot = self.load_snapshot(identity)?;
        snapshot.value.verify(identity, key, now_unix)?;
        let mut record = snapshot.value;
        record.issued_at_unix = now_unix;
        record.expires_at_unix = checked_expiry(now_unix, MCP_GROUP_LEASE_LIFETIME_SECONDS)?;
        record.sign(key)?;
        self.store(&identity.session_id).compare_and_swap(
            Some(&snapshot.revision),
            owner(identity)?,
            &record,
        )?;
        Ok(())
    }

    pub fn verify(
        &self,
        identity: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<i64, GroupSessionError> {
        let snapshot = self.load_snapshot(identity)?;
        snapshot.value.verify(identity, key, now_unix)?;
        Ok(snapshot.value.expires_at_unix)
    }

    fn load_snapshot(
        &self,
        identity: &McpGroupSessionIdentity,
    ) -> Result<StateSnapshot<McpGroupSessionLeaseRecord>, GroupSessionError> {
        validate_identity(identity)?;
        self.store(&identity.session_id)
            .load::<McpGroupSessionLeaseRecord>()?
            .ok_or(GroupSessionError::LeaseUnavailable)
    }

    fn store(&self, session_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.app_state_root
                .join("groups")
                .join("mcp-sessions")
                .join(format!("{session_id}.json")),
            MCP_GROUP_SESSION_SCHEMA_VERSION,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupApprovalChallengeClaims {
    pub version: u8,
    pub session: McpGroupSessionIdentity,
    pub plan: GroupTogglePlan,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl GroupApprovalChallengeClaims {
    pub fn verify(
        &self,
        expected_session: &McpGroupSessionIdentity,
        lease_expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<(), GroupSessionError> {
        self.plan
            .verify()
            .map_err(|_| GroupSessionError::InvalidChallenge)?;
        if self.version != MCP_GROUP_CHALLENGE_VERSION
            || &self.session != expected_session
            || self.plan.mode != GroupPlanMode::McpHandoff
            || self.plan.disposition != GroupPlanDisposition::Actionable
            || self.issued_at_unix > now_unix
            || self.expires_at_unix <= now_unix
            || self.expires_at_unix > lease_expires_at_unix
            || self.expires_at_unix - self.issued_at_unix > MCP_GROUP_CHALLENGE_LIFETIME_SECONDS
        {
            return Err(GroupSessionError::InvalidChallenge);
        }
        Ok(())
    }
}

pub fn issue_group_approval_challenge(
    plan: GroupTogglePlan,
    session: McpGroupSessionIdentity,
    lease_expires_at_unix: i64,
    key: &SessionAuthorityKey,
    now_unix: i64,
) -> Result<String, GroupSessionError> {
    let expires_at_unix =
        checked_expiry(now_unix, MCP_GROUP_CHALLENGE_LIFETIME_SECONDS)?.min(lease_expires_at_unix);
    let claims = GroupApprovalChallengeClaims {
        version: MCP_GROUP_CHALLENGE_VERSION,
        session,
        plan,
        issued_at_unix: now_unix,
        expires_at_unix,
    };
    claims.verify(&claims.session, lease_expires_at_unix, now_unix)?;
    let payload = serde_json::to_vec(&claims).map_err(GroupSessionError::Json)?;
    if payload.len() > MAX_CHALLENGE_BYTES {
        return Err(GroupSessionError::ChallengeTooLarge);
    }
    let signed_payload = [CHALLENGE_PURPOSE, payload.as_slice()].concat();
    let tag = key
        .authenticate_inventory_group(&signed_payload)
        .map_err(GroupSessionError::Authentication)?;
    Ok(format!("igc1.{}.{}", encode_hex(&payload), tag))
}

pub fn verify_group_approval_challenge(
    token: &str,
    expected_session: &McpGroupSessionIdentity,
    lease_expires_at_unix: i64,
    key: &SessionAuthorityKey,
    now_unix: i64,
) -> Result<GroupApprovalChallengeClaims, GroupSessionError> {
    let claims = authenticate_group_approval_challenge(token, key)?;
    claims.verify(expected_session, lease_expires_at_unix, now_unix)?;
    Ok(claims)
}

pub fn authenticate_group_approval_challenge(
    token: &str,
    key: &SessionAuthorityKey,
) -> Result<GroupApprovalChallengeClaims, GroupSessionError> {
    if token.len() > MAX_GROUP_APPROVAL_CHALLENGE_TEXT_BYTES {
        return Err(GroupSessionError::ChallengeTooLarge);
    }
    let mut parts = token.split('.');
    if parts.next() != Some("igc1") {
        return Err(GroupSessionError::InvalidChallenge);
    }
    let payload = decode_hex(parts.next().ok_or(GroupSessionError::InvalidChallenge)?)?;
    let tag = parts.next().ok_or(GroupSessionError::InvalidChallenge)?;
    if parts.next().is_some() || payload.len() > MAX_CHALLENGE_BYTES {
        return Err(GroupSessionError::InvalidChallenge);
    }
    let signed_payload = [CHALLENGE_PURPOSE, payload.as_slice()].concat();
    key.verify_inventory_group(&signed_payload, tag)
        .map_err(|_| GroupSessionError::AuthenticationFailed)?;
    let claims = serde_json::from_slice::<GroupApprovalChallengeClaims>(&payload)
        .map_err(|_| GroupSessionError::InvalidChallenge)?;
    Ok(claims)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum GroupApprovalArtifactState {
    Ready,
    Consumed,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupApprovalArtifact {
    schema_version: u8,
    pub artifact_id: String,
    pub operation_id: String,
    pub plan_fingerprint: String,
    pub challenge_digest: String,
    pub session: McpGroupSessionIdentity,
    pub receipt: ApprovalReceipt,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    state: GroupApprovalArtifactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision_digest: Option<String>,
    authentication_tag: String,
}

impl fmt::Debug for GroupApprovalArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupApprovalArtifact")
            .field("artifact_id", &"[REDACTED]")
            .field("operation_id", &self.operation_id)
            .field("plan_fingerprint", &self.plan_fingerprint)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl GroupApprovalArtifact {
    fn sign(&mut self, key: &SessionAuthorityKey) -> Result<(), GroupSessionError> {
        self.authentication_tag.clear();
        let payload = authenticated_payload(ARTIFACT_PURPOSE, self)?;
        self.authentication_tag = key
            .authenticate_inventory_group(&payload)
            .map_err(GroupSessionError::Authentication)?;
        Ok(())
    }

    fn verify_authentication(&self, key: &SessionAuthorityKey) -> Result<(), GroupSessionError> {
        let mut unsigned = self.clone();
        let tag = std::mem::take(&mut unsigned.authentication_tag);
        let payload = authenticated_payload(ARTIFACT_PURPOSE, &unsigned)?;
        key.verify_inventory_group(&payload, &tag)
            .map_err(|_| GroupSessionError::AuthenticationFailed)
    }

    fn matches_binding(
        &self,
        artifact_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        challenge: &str,
        session: &McpGroupSessionIdentity,
        now_unix: i64,
    ) -> bool {
        self.schema_version == 1
            && self.artifact_id == artifact_id
            && self.operation_id == operation_id
            && self.plan_fingerprint == plan_fingerprint
            && self.challenge_digest
                == crate::encode_lower_hex(&Sha256::digest(challenge.as_bytes()))
            && &self.session == session
            && self.issued_at_unix <= now_unix
            && self.expires_at_unix > now_unix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedGroupApprovalArtifact {
    pub decision_digest: String,
    pub receipt: ApprovalReceipt,
}

#[derive(Debug, Clone)]
pub struct GroupApprovalArtifactStore {
    app_state_root: PathBuf,
}

impl GroupApprovalArtifactStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        session: McpGroupSessionIdentity,
        plan: &GroupTogglePlan,
        challenge: &str,
        receipt: ApprovalReceipt,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<GroupApprovalArtifact, GroupSessionError> {
        plan.verify()
            .map_err(|_| GroupSessionError::InvalidArtifact)?;
        let operation_id = plan
            .operation_id
            .clone()
            .ok_or(GroupSessionError::InvalidArtifact)?;
        if plan.mode != GroupPlanMode::McpHandoff
            || plan.disposition != GroupPlanDisposition::Actionable
        {
            return Err(GroupSessionError::InvalidArtifact);
        }
        let expires_at_unix = receipt.claims.expires_at_unix;
        if expires_at_unix <= now_unix {
            return Err(GroupSessionError::InvalidArtifact);
        }
        let mut artifact = GroupApprovalArtifact {
            schema_version: 1,
            artifact_id: secure_random_identifier("group-approval", 32)?,
            operation_id,
            plan_fingerprint: plan.plan_fingerprint.clone(),
            challenge_digest: crate::encode_lower_hex(&Sha256::digest(challenge.as_bytes())),
            session,
            receipt,
            issued_at_unix: now_unix,
            expires_at_unix,
            state: GroupApprovalArtifactState::Ready,
            decision_digest: None,
            authentication_tag: String::new(),
        };
        artifact.sign(key)?;
        self.store(&artifact.artifact_id).compare_and_swap(
            None,
            artifact_owner(&artifact.artifact_id)?,
            &artifact,
        )?;
        Ok(artifact)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_ready(
        &self,
        artifact_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        challenge: &str,
        session: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<GroupApprovalArtifact, GroupSessionError> {
        let artifact = self.load_bound(
            artifact_id,
            operation_id,
            plan_fingerprint,
            challenge,
            session,
            key,
            now_unix,
        )?;
        if artifact.state != GroupApprovalArtifactState::Ready {
            return Err(GroupSessionError::ArtifactUnavailable);
        }
        Ok(artifact)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_consumed(
        &self,
        artifact_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        challenge: &str,
        session: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<ConsumedGroupApprovalArtifact, GroupSessionError> {
        let artifact = self.load_bound(
            artifact_id,
            operation_id,
            plan_fingerprint,
            challenge,
            session,
            key,
            now_unix,
        )?;
        if artifact.state != GroupApprovalArtifactState::Consumed {
            return Err(GroupSessionError::ArtifactUnavailable);
        }
        let decision_digest = artifact
            .decision_digest
            .clone()
            .ok_or(GroupSessionError::InvalidArtifact)?;
        Ok(ConsumedGroupApprovalArtifact {
            decision_digest,
            receipt: artifact.receipt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn consume(
        &self,
        artifact_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        challenge: &str,
        session: &McpGroupSessionIdentity,
        decision_digest: &str,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<GroupApprovalArtifact, GroupSessionError> {
        validate_identifier(artifact_id)?;
        let snapshot = self
            .store(artifact_id)
            .load::<GroupApprovalArtifact>()?
            .ok_or(GroupSessionError::ArtifactUnavailable)?;
        let mut artifact = snapshot.value;
        artifact.verify_authentication(key)?;
        if !artifact.matches_binding(
            artifact_id,
            operation_id,
            plan_fingerprint,
            challenge,
            session,
            now_unix,
        ) {
            return Err(GroupSessionError::InvalidArtifact);
        }
        if artifact.state != GroupApprovalArtifactState::Ready {
            return Err(GroupSessionError::ArtifactUnavailable);
        }
        artifact.state = GroupApprovalArtifactState::Consumed;
        artifact.decision_digest = Some(decision_digest.to_string());
        artifact.sign(key)?;
        self.store(artifact_id).compare_and_swap(
            Some(&snapshot.revision),
            artifact_owner(artifact_id)?,
            &artifact,
        )?;
        Ok(artifact)
    }

    #[allow(clippy::too_many_arguments)]
    fn load_bound(
        &self,
        artifact_id: &str,
        operation_id: &str,
        plan_fingerprint: &str,
        challenge: &str,
        session: &McpGroupSessionIdentity,
        key: &SessionAuthorityKey,
        now_unix: i64,
    ) -> Result<GroupApprovalArtifact, GroupSessionError> {
        validate_identifier(artifact_id)?;
        let artifact = self
            .store(artifact_id)
            .load::<GroupApprovalArtifact>()?
            .ok_or(GroupSessionError::ArtifactUnavailable)?
            .value;
        artifact.verify_authentication(key)?;
        if !artifact.matches_binding(
            artifact_id,
            operation_id,
            plan_fingerprint,
            challenge,
            session,
            now_unix,
        ) {
            return Err(GroupSessionError::ArtifactUnavailable);
        }
        Ok(artifact)
    }

    fn store(&self, artifact_id: &str) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.app_state_root
                .join("groups")
                .join("approval-artifacts")
                .join(format!("{artifact_id}.json")),
            MCP_GROUP_ARTIFACT_SCHEMA_VERSION,
        )
    }
}

pub(crate) fn secure_random_identifier(
    prefix: &str,
    entropy_bytes: usize,
) -> Result<String, GroupSessionError> {
    if prefix.is_empty() || !(16..=64).contains(&entropy_bytes) {
        return Err(GroupSessionError::InvalidIdentifier);
    }
    let mut entropy = vec![0_u8; entropy_bytes];
    getrandom::fill(&mut entropy).map_err(|_| GroupSessionError::SecureRandomUnavailable)?;
    Ok(format!("{prefix}-{}", encode_hex(&entropy)))
}

fn secure_random_generation() -> Result<u64, GroupSessionError> {
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|_| GroupSessionError::SecureRandomUnavailable)?;
    Ok(u64::from_le_bytes(entropy).max(1))
}

fn checked_expiry(now_unix: i64, lifetime: i64) -> Result<i64, GroupSessionError> {
    now_unix
        .checked_add(lifetime)
        .ok_or(GroupSessionError::Clock)
}

pub fn current_unix_seconds() -> Result<i64, GroupSessionError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GroupSessionError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| GroupSessionError::Clock)
}

fn authenticated_payload(
    purpose: &[u8],
    value: &impl Serialize,
) -> Result<Vec<u8>, GroupSessionError> {
    let encoded = serde_json::to_vec(value).map_err(GroupSessionError::Json)?;
    Ok([purpose, encoded.as_slice()].concat())
}

fn owner(identity: &McpGroupSessionIdentity) -> Result<OwnerGeneration, GroupSessionError> {
    OwnerGeneration::new(
        format!("mcp-group-session:{}", identity.session_id),
        identity.generation,
    )
    .map_err(|_| GroupSessionError::InvalidIdentifier)
}

fn artifact_owner(artifact_id: &str) -> Result<OwnerGeneration, GroupSessionError> {
    OwnerGeneration::new(format!("group-approval-artifact:{artifact_id}"), 1)
        .map_err(|_| GroupSessionError::InvalidIdentifier)
}

fn validate_binding(binding: &McpGroupSessionBinding) -> Result<(), GroupSessionError> {
    validate_identifier(&binding.repository_key)?;
    validate_identifier(&binding.workspace_key)
}

fn validate_identity(identity: &McpGroupSessionIdentity) -> Result<(), GroupSessionError> {
    validate_identifier(&identity.session_id)?;
    validate_binding(&identity.binding)?;
    if identity.generation == 0 {
        return Err(GroupSessionError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), GroupSessionError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || matches!(value, "." | "..")
    {
        Err(GroupSessionError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    crate::encode_lower_hex(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, GroupSessionError> {
    if !value.len().is_multiple_of(2) {
        return Err(GroupSessionError::InvalidChallenge);
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

fn hex_nibble(byte: u8) -> Result<u8, GroupSessionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GroupSessionError::InvalidChallenge),
    }
}

#[derive(Debug)]
pub enum GroupSessionError {
    State(StateError),
    Json(serde_json::Error),
    Authentication(String),
    AuthenticationFailed,
    InvalidIdentifier,
    InvalidLease,
    LeaseUnavailable,
    InvalidChallenge,
    ChallengeTooLarge,
    InvalidArtifact,
    ArtifactUnavailable,
    SecureRandomUnavailable,
    Clock,
}

impl From<StateError> for GroupSessionError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for GroupSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Json(_) => {
                formatter.write_str("inventory group authorization serialization failed")
            }
            Self::Authentication(_) | Self::AuthenticationFailed => {
                formatter.write_str("inventory group authorization authentication failed")
            }
            Self::InvalidIdentifier => {
                formatter.write_str("inventory group authorization identifier is invalid")
            }
            Self::InvalidLease | Self::LeaseUnavailable => {
                formatter.write_str("approved-group MCP session lease is unavailable")
            }
            Self::InvalidChallenge | Self::ChallengeTooLarge => {
                formatter.write_str("inventory group approval challenge is invalid")
            }
            Self::InvalidArtifact | Self::ArtifactUnavailable => {
                formatter.write_str("inventory group approval artifact is unavailable")
            }
            Self::SecureRandomUnavailable => {
                formatter.write_str("secure random source is unavailable")
            }
            Self::Clock => formatter.write_str("inventory group authorization clock failed"),
        }
    }
}

impl std::error::Error for GroupSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}
