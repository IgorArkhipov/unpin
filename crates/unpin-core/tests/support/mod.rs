use std::path::Path;

use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        ControlApprovalContext, ControlAuthorization, authorize_control,
    },
    state::atomic_json::OwnerGeneration,
};

pub fn control_context(repository_key: &str, workspace_key: &str) -> ControlApprovalContext {
    ControlApprovalContext::new(repository_key, workspace_key).expect("control approval context")
}

pub fn control_authorization(
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    marker: &str,
    now_unix: i64,
) -> ControlAuthorization {
    let key = ApprovalKey::new([0x71; 32]);
    let issuer = ApprovalIssuer::new(
        key.clone(),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer");
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("receipt-{marker}"),
            nonce: format!("nonce-{marker}"),
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
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 60,
        })
        .expect("approval receipt");
    authorize_control(
        app_state_root,
        &receipt,
        &ApprovalVerifier::new(key),
        expectation,
        now_unix,
        OwnerGeneration::new("control-approval-test", 1).unwrap(),
    )
    .expect("control authorization")
}
