use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    approval::{ApprovalExpectation, ControlAuthorization},
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
    transitions::{
        EffectActivation, JournalError, JournalHandle, TransitionJournalStore, TransitionLifecycle,
        TransitionPlan, journal::MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES,
    },
};

pub const CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOperationLifecycle {
    Planned,
    AwaitingHumanAction,
    Applied,
    NoOp,
    Blocked,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlResolvedContext {
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlHumanAction {
    pub code: String,
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlOperationEnvelope {
    pub schema_version: u32,
    pub operation_id: String,
    pub operation_kind: String,
    pub plan_fingerprint: String,
    pub context: ControlResolvedContext,
    pub lifecycle: ControlOperationLifecycle,
    pub activation: EffectActivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_action: Option<ControlHumanAction>,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_coverage: Vec<ProviderId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

impl ControlOperationEnvelope {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        operation_id: impl Into<String>,
        operation_kind: impl Into<String>,
        plan_fingerprint: impl Into<String>,
        context: ControlResolvedContext,
        lifecycle: ControlOperationLifecycle,
        activation: EffectActivation,
        human_action: Option<ControlHumanAction>,
        retryable: bool,
        mut provider_coverage: Vec<ProviderId>,
        details: Value,
    ) -> Self {
        provider_coverage.sort();
        provider_coverage.dedup();
        Self {
            schema_version: CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            operation_kind: operation_kind.into(),
            plan_fingerprint: plan_fingerprint.into(),
            context,
            lifecycle,
            activation,
            human_action,
            retryable,
            provider_coverage,
            details,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_expectation(
        expectation: &ApprovalExpectation,
        plan_fingerprint: impl Into<String>,
        activation: EffectActivation,
        lifecycle: ControlOperationLifecycle,
        human_action: Option<ControlHumanAction>,
        retryable: bool,
        provider_coverage: Vec<ProviderId>,
        details: Value,
    ) -> Self {
        Self::new(
            expectation.operation_id.clone(),
            expectation.operation_kind.clone(),
            plan_fingerprint,
            ControlResolvedContext {
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
            },
            lifecycle,
            activation,
            human_action,
            retryable,
            provider_coverage,
            details,
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DurableControlJournal {
    store: TransitionJournalStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableControlTerminalStatus {
    Applied,
    NoOp,
}

impl DurableControlTerminalStatus {
    const fn terminal_code(self) -> &'static str {
        match self {
            Self::Applied => "control-result-applied",
            Self::NoOp => "control-result-no-op",
        }
    }

    fn from_terminal_code(code: Option<&str>) -> Option<Self> {
        match code {
            Some("control-result-applied") => Some(Self::Applied),
            Some("control-result-no-op") => Some(Self::NoOp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableControlTerminal {
    pub(crate) operation_id: String,
    pub(crate) operation_kind: String,
    pub(crate) effect_graph_digest: String,
    pub(crate) status: DurableControlTerminalStatus,
}

#[derive(Debug)]
pub(crate) enum DurableControlStart {
    Apply(Box<DurableControlHandle>),
    Cached(DurableControlTerminal),
}

impl DurableControlJournal {
    #[must_use]
    pub(crate) fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            store: TransitionJournalStore::new(app_state_root),
        }
    }

    pub(crate) fn begin(
        &self,
        plan: &TransitionPlan,
        authorization: &ControlAuthorization,
        _actor_id: &str,
    ) -> Result<DurableControlStart, DurableControlError> {
        if authorization.operation_id() != plan.operation_id {
            return Err(DurableControlError::AuthorizationDecisionConflict);
        }
        let owner_digest = crate::encode_lower_hex(&Sha256::digest(plan.operation_id.as_bytes()));
        let owner = OwnerGeneration::new(format!("control-{}", &owner_digest[..32]), 1)?;
        let mut handle = self.store.create_or_attach(plan, owner)?;
        let resumed = handle.journal.lifecycle == TransitionLifecycle::Applying;
        match &handle.journal.authorization_decision_digest {
            Some(existing) if existing != authorization.decision_digest() && resumed => {
                let decisions_to_append = usize::from(
                    handle.journal.authorization_decision_history.last() != Some(existing),
                ) + 1;
                if handle
                    .journal
                    .authorization_decision_history
                    .len()
                    .saturating_add(decisions_to_append)
                    > MAX_AUTHORIZATION_DECISION_HISTORY_ENTRIES
                {
                    handle.journal.terminal_code = Some("approval-refresh-limit".to_string());
                    handle.journal.record(
                        TransitionLifecycle::NeedsRepair,
                        "approval-refresh-limit",
                        None,
                    )?;
                    self.store.save(&mut handle)?;
                    return Err(DurableControlError::RecoveryRequired(
                        handle.journal.operation_id.clone(),
                    ));
                }
                if handle.journal.authorization_decision_history.last() != Some(existing) {
                    handle
                        .journal
                        .authorization_decision_history
                        .push(existing.clone());
                }
                handle
                    .journal
                    .authorization_decision_history
                    .push(authorization.decision_digest().to_string());
                handle.journal.authorization_decision_digest =
                    Some(authorization.decision_digest().to_string());
                handle
                    .journal
                    .record(TransitionLifecycle::Applying, "approval-refreshed", None)?;
                self.store.save(&mut handle)?;
            }
            Some(existing) if existing != authorization.decision_digest() => {
                return Err(DurableControlError::AuthorizationDecisionConflict);
            }
            Some(_) => {}
            None if handle.journal.lifecycle.is_terminal() => {
                return Err(DurableControlError::TerminalOutcomeUnavailable(
                    handle.journal.operation_id.clone(),
                ));
            }
            None => {
                handle.journal.authorization_decision_digest =
                    Some(authorization.decision_digest().to_string());
                handle
                    .journal
                    .authorization_decision_history
                    .push(authorization.decision_digest().to_string());
                handle
                    .journal
                    .record(TransitionLifecycle::Approved, "approval-recorded", None)?;
                self.store.save(&mut handle)?;
            }
        }
        match handle.journal.lifecycle {
            TransitionLifecycle::Committed => {
                let status = DurableControlTerminalStatus::from_terminal_code(
                    handle.journal.terminal_code.as_deref(),
                )
                .ok_or_else(|| {
                    DurableControlError::TerminalOutcomeUnavailable(
                        handle.journal.operation_id.clone(),
                    )
                })?;
                return Ok(DurableControlStart::Cached(DurableControlTerminal {
                    operation_id: handle.journal.operation_id,
                    operation_kind: handle.journal.operation_kind,
                    effect_graph_digest: handle.journal.effect_graph_digest,
                    status,
                }));
            }
            TransitionLifecycle::RolledBack => {
                return Err(DurableControlError::RolledBackOperation(
                    handle.journal.operation_id.clone(),
                ));
            }
            TransitionLifecycle::NeedsRepair => {
                return Err(DurableControlError::RecoveryRequired(
                    handle.journal.operation_id.clone(),
                ));
            }
            _ => {}
        }
        if let Some(blocking) = self.store.blocking_operation_for(plan)? {
            return Err(DurableControlError::RecoveryRequired(blocking));
        }
        if handle.journal.lifecycle != TransitionLifecycle::Applying {
            handle
                .journal
                .record(TransitionLifecycle::Applying, "control-applying", None)?;
            self.store.save(&mut handle)?;
        }
        Ok(DurableControlStart::Apply(Box::new(DurableControlHandle {
            store: self.store.clone(),
            handle,
            resumed,
        })))
    }
}

#[derive(Debug)]
pub(crate) struct DurableControlHandle {
    store: TransitionJournalStore,
    handle: JournalHandle,
    resumed: bool,
}

impl DurableControlHandle {
    pub(crate) const fn is_resumed(&self) -> bool {
        self.resumed
    }

    pub(crate) fn commit_with_terminal_status(
        mut self,
        status: DurableControlTerminalStatus,
    ) -> Result<(), DurableControlError> {
        self.commit_inner(status)
    }

    fn commit_inner(
        &mut self,
        status: DurableControlTerminalStatus,
    ) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(status.terminal_code().to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::Committed, "control-committed", None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }

    pub(crate) fn abort(mut self, code: &'static str) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(code.to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::RolledBack, code, None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }

    pub(crate) fn needs_repair(mut self, code: &'static str) -> Result<(), DurableControlError> {
        self.handle.journal.terminal_code = Some(code.to_string());
        self.handle
            .journal
            .record(TransitionLifecycle::NeedsRepair, code, None)?;
        self.store.save(&mut self.handle)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DurableControlError {
    Journal(JournalError),
    State(crate::state::atomic_json::StateError),
    AuthorizationDecisionConflict,
    RecoveryRequired(String),
    RolledBackOperation(String),
    TerminalOutcomeUnavailable(String),
    TerminalOperation(String),
}

impl From<JournalError> for DurableControlError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<crate::state::atomic_json::StateError> for DurableControlError {
    fn from(error: crate::state::atomic_json::StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for DurableControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::AuthorizationDecisionConflict => {
                formatter.write_str("control operation is bound to another approval decision")
            }
            Self::RecoveryRequired(operation_id) => {
                write!(formatter, "control recovery required for {operation_id}")
            }
            Self::RolledBackOperation(operation_id) => {
                write!(
                    formatter,
                    "control operation was rolled back: {operation_id}"
                )
            }
            Self::TerminalOutcomeUnavailable(operation_id) => {
                write!(
                    formatter,
                    "control operation terminal outcome is unavailable: {operation_id}"
                )
            }
            Self::TerminalOperation(operation_id) => {
                write!(
                    formatter,
                    "control operation is already terminal: {operation_id}"
                )
            }
        }
    }
}

impl std::error::Error for DurableControlError {}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        approval::{
            ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
            CONTROL_APPROVAL_AUDIENCE, CONTROL_APPROVAL_ISSUER, authorize_control,
        },
        state::atomic_json::OwnerGeneration,
        transitions::{
            EffectActivation, EffectAuthority, TransitionContext, TransitionEffect,
            TransitionEffectKind, TransitionJournalStore, TransitionKind,
        },
    };

    use super::*;

    #[test]
    fn exact_applied_and_no_op_retries_return_cached_terminal_status() {
        for (suffix, status) in [
            ("applied", DurableControlTerminalStatus::Applied),
            ("no-op", DurableControlTerminalStatus::NoOp),
        ] {
            let temp = TempDir::new().expect("temporary state root");
            let root = temp.path().canonicalize().expect("canonical state root");
            let plan = plan(&format!("operation-{suffix}"), "resource", 'b');
            let authorization = authorization(&root, &plan, suffix);
            let journal = DurableControlJournal::new(&root);

            let DurableControlStart::Apply(handle) = journal
                .begin(&plan, &authorization, "first-actor")
                .expect("begin operation")
            else {
                panic!("new operation must be active");
            };
            handle
                .commit_with_terminal_status(status)
                .expect("commit operation");

            let DurableControlStart::Cached(cached) = journal
                .begin(&plan, &authorization, "retry-actor")
                .expect("attach exact retry")
            else {
                panic!("exact retry must return cached terminal status");
            };
            assert_eq!(cached.operation_id, plan.operation_id);
            assert_eq!(cached.operation_kind, plan.kind.as_str());
            assert_eq!(cached.effect_graph_digest, plan.effect_graph_digest);
            assert_eq!(cached.status, status);
        }
    }

    #[test]
    fn terminal_retry_rejects_mismatched_operation_identity() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let original = plan("operation-mismatch", "resource", 'b');
        let original_authorization = authorization(&root, &original, "original");
        let journal = DurableControlJournal::new(&root);
        let DurableControlStart::Apply(handle) = journal
            .begin(&original, &original_authorization, "first-actor")
            .expect("begin original operation")
        else {
            panic!("new operation must be active");
        };
        handle
            .commit_with_terminal_status(DurableControlTerminalStatus::Applied)
            .expect("commit original operation");

        let mismatched = plan("operation-mismatch", "other-resource", 'c');
        let mismatched_authorization = authorization(&root, &mismatched, "mismatched");
        assert!(matches!(
            journal.begin(&mismatched, &mismatched_authorization, "retry-actor"),
            Err(DurableControlError::Journal(
                JournalError::OperationConflict
            ))
        ));
    }

    #[test]
    fn resumed_operation_preserves_approval_decision_history() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let plan = plan("operation-resume-approval", "resource", 'b');
        let first_authorization = authorization(&root, &plan, "first");
        let first_digest = first_authorization.decision_digest().to_string();
        let journal = DurableControlJournal::new(&root);

        let DurableControlStart::Apply(first) = journal
            .begin(&plan, &first_authorization, "first-actor")
            .expect("begin operation")
        else {
            panic!("new operation must be active");
        };
        drop(first);

        let second_authorization = authorization(&root, &plan, "second");
        let second_digest = second_authorization.decision_digest().to_string();
        let DurableControlStart::Apply(resumed) = journal
            .begin(&plan, &second_authorization, "second-actor")
            .expect("resume operation")
        else {
            panic!("interrupted operation must resume");
        };
        assert!(resumed.is_resumed());
        drop(resumed);

        let stored = TransitionJournalStore::new(&root)
            .list()
            .expect("transition journals")
            .into_iter()
            .find(|journal| journal.operation_id == plan.operation_id)
            .expect("resumed journal");
        assert_eq!(
            stored.authorization_decision_history,
            vec![first_digest, second_digest.clone()]
        );
        assert_eq!(
            stored.authorization_decision_digest.as_deref(),
            Some(second_digest.as_str())
        );
        assert!(
            stored
                .audit
                .iter()
                .any(|event| event.code == "approval-refreshed")
        );
    }

    #[test]
    fn resumed_operation_bounds_approval_decision_history() {
        const MAX_REFRESH_HISTORY: usize = 32;

        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let plan = plan("operation-resume-approval-limit", "resource", 'b');
        let journal = DurableControlJournal::new(&root);

        for index in 0..MAX_REFRESH_HISTORY {
            let authorization = authorization(&root, &plan, &format!("refresh-limit-{index}"));
            let DurableControlStart::Apply(handle) = journal
                .begin(&plan, &authorization, "retry-actor")
                .expect("approval history has bounded capacity")
            else {
                panic!("interrupted operation must remain resumable within its history bound");
            };
            drop(handle);
        }

        let overflow = authorization(&root, &plan, "refresh-limit-overflow");
        assert!(matches!(
            journal.begin(&plan, &overflow, "overflow-actor"),
            Err(DurableControlError::RecoveryRequired(operation_id))
                if operation_id == plan.operation_id
        ));
        let stored = TransitionJournalStore::new(&root)
            .list()
            .expect("transition journals")
            .into_iter()
            .find(|candidate| candidate.operation_id == plan.operation_id)
            .expect("bounded journal");
        assert_eq!(
            stored.authorization_decision_history.len(),
            MAX_REFRESH_HISTORY
        );
        assert_eq!(stored.lifecycle, TransitionLifecycle::NeedsRepair);
        assert_eq!(
            stored.terminal_code.as_deref(),
            Some("approval-refresh-limit")
        );
    }

    #[test]
    fn rolled_back_and_needs_repair_operations_are_not_replayed() {
        let temp = TempDir::new().expect("temporary state root");
        let root = temp.path().canonicalize().expect("canonical state root");
        let journal = DurableControlJournal::new(&root);

        let rolled_back = plan("operation-rolled-back", "rolled-back-resource", 'b');
        let rolled_back_authorization = authorization(&root, &rolled_back, "rolled-back");
        let DurableControlStart::Apply(handle) = journal
            .begin(&rolled_back, &rolled_back_authorization, "first-actor")
            .expect("begin rolled-back operation")
        else {
            panic!("new operation must be active");
        };
        handle.abort("control-apply-aborted").expect("roll back");
        assert!(matches!(
            journal.begin(&rolled_back, &rolled_back_authorization, "retry-actor"),
            Err(DurableControlError::RolledBackOperation(operation_id))
                if operation_id == rolled_back.operation_id
        ));

        let needs_repair = plan("operation-needs-repair", "repair-resource", 'c');
        let needs_repair_authorization = authorization(&root, &needs_repair, "needs-repair");
        let DurableControlStart::Apply(handle) = journal
            .begin(&needs_repair, &needs_repair_authorization, "first-actor")
            .expect("begin needs-repair operation")
        else {
            panic!("new operation must be active");
        };
        handle
            .needs_repair("control-partial-apply")
            .expect("mark repair required");
        assert!(matches!(
            journal.begin(&needs_repair, &needs_repair_authorization, "retry-actor"),
            Err(DurableControlError::RecoveryRequired(operation_id))
                if operation_id == needs_repair.operation_id
        ));
    }

    fn plan(operation_id: &str, resource_id: &str, post_digest: char) -> TransitionPlan {
        TransitionPlan::new(
            operation_id,
            TransitionKind::ApplyProfile,
            TransitionContext {
                repository_key: "repository".to_string(),
                workspace_key: "workspace".to_string(),
                session_id: None,
                profile_digest: None,
            },
            vec![TransitionEffect {
                effect_id: "effect".to_string(),
                kind: TransitionEffectKind::PublishView,
                resource_id: resource_id.to_string(),
                target_type: "profile-policy".to_string(),
                summary: "Apply reviewed policy".to_string(),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::Live,
                expected_pre_fingerprint: Some("a".repeat(64)),
                expected_post_fingerprint: Some(post_digest.to_string().repeat(64)),
                provider_views: Vec::new(),
            }],
        )
        .expect("valid transition plan")
    }

    fn authorization(
        app_state_root: &std::path::Path,
        plan: &TransitionPlan,
        suffix: &str,
    ) -> ControlAuthorization {
        let expectation =
            plan.approval_expectation(CONTROL_APPROVAL_ISSUER, CONTROL_APPROVAL_AUDIENCE);
        let key = ApprovalKey::new([0x41; 32]);
        let issuer = ApprovalIssuer::new(
            ApprovalKey::new([0x41; 32]),
            CONTROL_APPROVAL_ISSUER,
            CONTROL_APPROVAL_AUDIENCE,
        )
        .expect("approval issuer");
        let receipt = issuer
            .issue(ApprovalReceiptClaims {
                version: 1,
                receipt_id: format!("receipt-{suffix}"),
                nonce: format!("nonce-{suffix}"),
                issuer: String::new(),
                audience: String::new(),
                operation_id: expectation.operation_id.clone(),
                operation_kind: expectation.operation_kind.clone(),
                effect_graph_digest: expectation.effect_graph_digest.clone(),
                repository_key: expectation.repository_key.clone(),
                workspace_key: expectation.workspace_key.clone(),
                session_id: expectation.session_id.clone(),
                profile_digest: expectation.profile_digest.clone(),
                resources: expectation.resources.clone(),
                issued_at_unix: 100,
                expires_at_unix: 200,
            })
            .expect("issue approval");
        authorize_control(
            app_state_root,
            &receipt,
            &ApprovalVerifier::new(key),
            &expectation,
            150,
            OwnerGeneration::new("approval-test", 1).expect("approval owner"),
        )
        .expect("authorize control")
    }
}
